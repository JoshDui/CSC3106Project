#!/usr/bin/env python3
"""
Reproducible SSH authentication-log analysis for CSC3106.

Expected usage:

    python analysis.py --input 4_auth.log --output output

If no arguments are provided, the script reads 4_auth.log and writes outputs to
the output directory.
"""

from __future__ import annotations

import argparse
import re
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd


DEFAULT_YEAR = 2026

PRIVILEGED_ACCOUNTS = {"root", "backup", "ops", "admin", "administrator", "sysadmin"}

FAILED_PASSWORD_SUSPICIOUS_THRESHOLD = 10
MAX_AUTH_ATTEMPTS_SUSPICIOUS_THRESHOLD = 5
SUDO_LOOKBACK_MINUTES = 10
PRIORITY_FINDING_USERNAME = "backup"
PRIORITY_FINDING_LOOKBACK_MINUTES = 90
PRIORITY_FINDING_LOOKAHEAD_MINUTES = 150
PRIORITY_FINDING_FAILURE_TYPES = ("failed_password", "max_auth_attempts")
STALE_REPLACED_OUTPUTS = (
    "accepted_after_failures.csv",
    "suspicious_successes.png",
    "figure2_failed_attempts_backup_login.png",
    "attack_stages_over_time.png",
    "event_type_distribution.png",
    "top_source_ips_all_suspicious.csv",
    "sudo_commands.csv",
)

SUDO_HIGH_RISK_KEYWORDS = ("journalctl", "/var/log", "cron", "ssh", "systemctl", "apt")

CSV_COLUMNS = [
    "line_number",
    "raw_line",
    "timestamp_raw",
    "parsed_datetime",
    "host",
    "process",
    "pid",
    "event_type",
    "attack_stage",
    "username",
    "source_ip",
    "source_port",
    "command",
    "is_privileged_account",
    "is_suspicious_source",
    "parse_status",
]

EVENT_STAGE_MAP = {
    "invalid_user": "account_probing",
    "failed_password": "initial_access_attempt",
    "max_auth_attempts": "brute_force_or_password_spraying",
    "preauth_closed": "preauth_interruption",
    "accepted_password": "possible_successful_access",
    "session_opened": "session_activity",
    "session_closed": "session_activity",
    "sudo_command": "post_login_privileged_activity",
    "cron_session": "scheduled_or_background_activity",
    "possible_break_in": "suspicious_connection_warning",
    "other": "other_or_unclassified",
}

EVENT_TYPES = [
    "failed_password",
    "accepted_password",
    "invalid_user",
    "max_auth_attempts",
    "preauth_closed",
    "session_opened",
    "session_closed",
    "sudo_command",
    "cron_session",
    "possible_break_in",
    "other",
]

ATTACK_STAGES = [
    "account_probing",
    "initial_access_attempt",
    "brute_force_or_password_spraying",
    "preauth_interruption",
    "possible_successful_access",
    "session_activity",
    "post_login_privileged_activity",
    "scheduled_or_background_activity",
    "suspicious_connection_warning",
    "other_or_unclassified",
]

# Generic auth.log/syslog envelope. The process may be "sshd[1234]", "CRON[1234]",
# or "sudo" without a PID, so the PID portion is optional.
SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# SSH failure lines can target either a valid account or an "invalid user".
# Both are failed_password events, but the username is still extracted.
FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:(?P<invalid_label>invalid user)\s+)?"
    r"(?P<username>\S+) from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+) ssh2"
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for (?P<username>\S+) from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+) ssh2"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<source_ip>\S+) "
    r"port (?P<source_port>\d+)"
)

MAX_AUTH_ATTEMPTS_RE = re.compile(
    r"maximum authentication attempts exceeded for (?P<username>\S+) "
    r"from (?P<source_ip>\S+) port (?P<source_port>\d+)"
)

# OpenSSH preauth close lines omit the word "from" before the source address.
PREAUTH_CLOSED_RE = re.compile(
    r"Connection closed by authenticating user (?P<username>\S+) "
    r"(?P<source_ip>\S+) port (?P<source_port>\d+) \[preauth\]"
)

SSHD_SESSION_OPENED_RE = re.compile(
    r"pam_unix\(sshd:session\): session opened for user (?P<username>\S+) by "
    r"\(uid=(?P<uid>\d+)\)"
)

SSHD_SESSION_CLOSED_RE = re.compile(
    r"pam_unix\(sshd:session\): session closed for user (?P<username>\S+)"
)

CRON_SESSION_RE = re.compile(
    r"pam_unix\(cron:session\): session (?P<session_action>opened|closed) "
    r"for user (?P<username>\S+)"
)

SUDO_RE = re.compile(
    r"^\s*(?P<username>\S+)\s+:\s+.*?\bCOMMAND=(?P<command>.*)$"
)

# The source IP for these OpenSSH reverse-DNS warnings is usually in brackets.
POSSIBLE_BREAK_IN_RE = re.compile(
    r"(?:\[(?P<bracket_ip>[0-9A-Fa-f:.]+)\]|(?P<plain_ip>\b\d{1,3}(?:\.\d{1,3}){3}\b))"
    r".*POSSIBLE BREAK-IN ATTEMPT!"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse auth.log evidence for SSH attack-lifecycle stages."
    )
    parser.add_argument(
        "--input",
        default="4_auth.log",
        help="Path to raw auth.log-style file. Default: 4_auth.log",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Directory for generated CSV and PNG outputs. Default: output",
    )
    return parser.parse_args()


def parse_syslog_datetime(month: str, day: str, time_value: str) -> datetime | None:
    timestamp = f"{DEFAULT_YEAR} {month} {int(day):02d} {time_value}"
    try:
        return datetime.strptime(timestamp, "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def empty_row(line_number: int, raw_line: str) -> dict[str, object]:
    return {
        "line_number": line_number,
        "raw_line": raw_line.rstrip("\n"),
        "timestamp_raw": "",
        "parsed_datetime": pd.NaT,
        "host": "",
        "process": "",
        "pid": "",
        "event_type": "other",
        "attack_stage": EVENT_STAGE_MAP["other"],
        "username": "",
        "source_ip": "",
        "source_port": "",
        "command": "",
        "is_privileged_account": False,
        "is_suspicious_source": False,
        "parse_status": "unparsed_syslog_envelope",
    }


def apply_match(row: dict[str, object], event_type: str, match: re.Match[str]) -> None:
    row["event_type"] = event_type
    row["attack_stage"] = EVENT_STAGE_MAP[event_type]

    group_dict = match.groupdict()
    username = group_dict.get("username")
    source_ip = group_dict.get("source_ip")
    source_port = group_dict.get("source_port")
    command = group_dict.get("command")

    if username:
        row["username"] = username
    if source_ip:
        row["source_ip"] = source_ip
    if source_port:
        row["source_port"] = source_port
    if command:
        row["command"] = command.strip()


def classify_message(row: dict[str, object], message: str, process: str) -> None:
    if "POSSIBLE BREAK-IN ATTEMPT!" in message:
        match = POSSIBLE_BREAK_IN_RE.search(message)
        row["event_type"] = "possible_break_in"
        row["attack_stage"] = EVENT_STAGE_MAP["possible_break_in"]
        if match:
            row["source_ip"] = match.group("bracket_ip") or match.group("plain_ip") or ""
        return

    if process == "CRON":
        match = CRON_SESSION_RE.search(message)
        if match:
            apply_match(row, "cron_session", match)
            return

    if process == "sudo":
        match = SUDO_RE.search(message)
        if match:
            apply_match(row, "sudo_command", match)
            return

    regex_by_event_type = [
        ("failed_password", FAILED_PASSWORD_RE),
        ("accepted_password", ACCEPTED_PASSWORD_RE),
        ("invalid_user", INVALID_USER_RE),
        ("max_auth_attempts", MAX_AUTH_ATTEMPTS_RE),
        ("preauth_closed", PREAUTH_CLOSED_RE),
        ("session_opened", SSHD_SESSION_OPENED_RE),
        ("session_closed", SSHD_SESSION_CLOSED_RE),
    ]

    for event_type, regex in regex_by_event_type:
        match = regex.search(message)
        if match:
            apply_match(row, event_type, match)
            return


def parse_log_line(line_number: int, raw_line: str) -> dict[str, object]:
    row = empty_row(line_number, raw_line)
    line = raw_line.rstrip("\n")
    match = SYSLOG_RE.match(line)

    if not match:
        return row

    month = match.group("month")
    day = match.group("day")
    time_value = match.group("time")
    parsed_datetime = parse_syslog_datetime(month, day, time_value)
    process = match.group("process") or ""
    message = match.group("message") or ""

    row.update(
        {
            "timestamp_raw": f"{month} {int(day):02d} {time_value}",
            "parsed_datetime": parsed_datetime if parsed_datetime else pd.NaT,
            "host": match.group("host") or "",
            "process": process,
            "pid": match.group("pid") or "",
            "parse_status": "parsed",
        }
    )

    classify_message(row, message, process)

    username = str(row["username"])
    row["is_privileged_account"] = username.lower() in PRIVILEGED_ACCOUNTS

    return row


def read_log(input_path: Path) -> pd.DataFrame:
    rows = []
    with input_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            rows.append(parse_log_line(line_number, raw_line))

    df = pd.DataFrame(rows, columns=CSV_COLUMNS)
    df["parsed_datetime"] = pd.to_datetime(df["parsed_datetime"], errors="coerce")
    return df


def calculate_suspicious_sources(df: pd.DataFrame) -> set[str]:
    source_df = df[df["source_ip"].astype(str) != ""].copy()
    if source_df.empty:
        return set()

    failed_counts = count_by_source(source_df, "failed_password")
    max_auth_counts = count_by_source(source_df, "max_auth_attempts")
    break_in_counts = count_by_source(source_df, "possible_break_in")

    suspicious_sources = set(failed_counts[failed_counts >= FAILED_PASSWORD_SUSPICIOUS_THRESHOLD].index)
    suspicious_sources.update(
        set(max_auth_counts[max_auth_counts >= MAX_AUTH_ATTEMPTS_SUSPICIOUS_THRESHOLD].index)
    )
    suspicious_sources.update(set(break_in_counts[break_in_counts > 0].index))
    return suspicious_sources


def count_by_source(df: pd.DataFrame, event_type: str) -> pd.Series:
    filtered = df[df["event_type"] == event_type]
    if filtered.empty:
        return pd.Series(dtype="int64")
    return filtered.groupby("source_ip").size().sort_values(ascending=False)


def add_suspicious_source_column(df: pd.DataFrame) -> set[str]:
    suspicious_sources = calculate_suspicious_sources(df)
    df["is_suspicious_source"] = df["source_ip"].map(lambda value: value in suspicious_sources)
    return suspicious_sources


def write_csv(df: pd.DataFrame, path: Path) -> None:
    df.to_csv(path, index=False)


def event_type_counts(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["event_type"].value_counts().reindex(EVENT_TYPES, fill_value=0)
    return counts.rename_axis("event_type").reset_index(name="count")


def attack_stage_counts(df: pd.DataFrame) -> pd.DataFrame:
    counts = df["attack_stage"].value_counts().reindex(ATTACK_STAGES, fill_value=0)
    return counts.rename_axis("attack_stage").reset_index(name="count")


def top_source_ips_failed(df: pd.DataFrame) -> pd.DataFrame:
    counts = count_by_source(df, "failed_password")
    return counts.rename_axis("source_ip").reset_index(name="failed_password_count")


def targeted_user_summary(df: pd.DataFrame) -> pd.DataFrame:
    user_df = df[df["username"].astype(str) != ""].copy()
    columns = [
        "username",
        "failed_password_count",
        "invalid_user_count",
        "max_auth_attempts_count",
        "accepted_password_count",
        "sudo_command_count",
        "total_events",
    ]

    if user_df.empty:
        return pd.DataFrame(columns=columns)

    pivot = (
        user_df.pivot_table(
            index="username",
            columns="event_type",
            values="line_number",
            aggfunc="count",
            fill_value=0,
        )
        .rename_axis(None, axis=1)
        .reset_index()
    )

    for event_type in [
        "failed_password",
        "invalid_user",
        "max_auth_attempts",
        "accepted_password",
        "sudo_command",
    ]:
        if event_type not in pivot.columns:
            pivot[event_type] = 0

    total_events = user_df.groupby("username").size().rename("total_events").reset_index()
    summary = pivot.merge(total_events, on="username", how="left")
    summary = summary.rename(
        columns={
            "failed_password": "failed_password_count",
            "invalid_user": "invalid_user_count",
            "max_auth_attempts": "max_auth_attempts_count",
            "accepted_password": "accepted_password_count",
            "sudo_command": "sudo_command_count",
        }
    )

    return summary[columns].sort_values(
        ["failed_password_count", "max_auth_attempts_count", "total_events"],
        ascending=[False, False, False],
    )


def select_priority_backup_login(df: pd.DataFrame) -> pd.Series | None:
    accepted_df = df[
        (df["event_type"] == "accepted_password")
        & (df["username"].str.lower() == PRIORITY_FINDING_USERNAME.lower())
        & (df["source_ip"].astype(str) != "")
        & (df["parsed_datetime"].notna())
    ].copy()

    if accepted_df.empty:
        return None

    scored_rows = []
    failure_df = df[df["event_type"].isin(PRIORITY_FINDING_FAILURE_TYPES)].copy()

    for _, accepted in accepted_df.iterrows():
        accepted_time = accepted["parsed_datetime"]
        source_ip = str(accepted["source_ip"])
        window_start = accepted_time - timedelta(minutes=PRIORITY_FINDING_LOOKBACK_MINUTES)
        window_end = accepted_time + timedelta(minutes=PRIORITY_FINDING_LOOKAHEAD_MINUTES)
        same_source_failures = failure_df[
            (failure_df["source_ip"] == source_ip)
            & (failure_df["parsed_datetime"] >= window_start)
            & (failure_df["parsed_datetime"] <= window_end)
        ]
        backup_failures = same_source_failures[
            same_source_failures["username"].str.lower() == PRIORITY_FINDING_USERNAME.lower()
        ]

        scored = accepted.copy()
        scored["priority_failure_count"] = int(len(same_source_failures))
        scored["priority_backup_failure_count"] = int(len(backup_failures))
        scored_rows.append(scored)

    scored_df = pd.DataFrame(scored_rows)
    scored_df = scored_df.sort_values(
        ["priority_failure_count", "priority_backup_failure_count", "parsed_datetime"],
        ascending=[False, False, True],
    )
    return scored_df.iloc[0]


def priority_backup_login_timeline(df: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "finding_id",
        "sequence_start",
        "sequence_end",
        "successful_login_time",
        "source_ip",
        "successful_username",
        "failed_attempt_count",
        "backup_failed_attempt_count",
        "distinct_usernames_targeted",
        "event_time",
        "event_role",
        "event_type",
        "targeted_username",
        "source_port",
        "command",
        "raw_line",
    ]

    accepted = select_priority_backup_login(df)
    if accepted is None:
        return pd.DataFrame(columns=columns)

    source_ip = str(accepted["source_ip"])
    success_time = accepted["parsed_datetime"]
    window_start = success_time - timedelta(minutes=PRIORITY_FINDING_LOOKBACK_MINUTES)
    window_end = success_time + timedelta(minutes=PRIORITY_FINDING_LOOKAHEAD_MINUTES)

    failed_attempts = df[
        (df["source_ip"] == source_ip)
        & (df["event_type"].isin(PRIORITY_FINDING_FAILURE_TYPES))
        & (df["parsed_datetime"] >= window_start)
        & (df["parsed_datetime"] <= window_end)
    ].copy()

    if failed_attempts.empty:
        sequence_start = success_time
        sequence_end = success_time
    else:
        sequence_start = failed_attempts["parsed_datetime"].min()
        sequence_end = failed_attempts["parsed_datetime"].max()

    selected_events = df[
        (
            (df["source_ip"] == source_ip)
            & (df["event_type"].isin(PRIORITY_FINDING_FAILURE_TYPES))
            & (df["parsed_datetime"] >= sequence_start)
            & (df["parsed_datetime"] <= sequence_end)
        )
        | (df["line_number"] == accepted["line_number"])
    ].copy()

    selected_events = selected_events.sort_values(["parsed_datetime", "line_number"])
    backup_failures = failed_attempts[
        failed_attempts["username"].str.lower() == PRIORITY_FINDING_USERNAME.lower()
    ]
    distinct_usernames = sorted(
        username
        for username in selected_events["username"].dropna().astype(str).unique()
        if username
    )

    records = []
    for _, event in selected_events.iterrows():
        event_time = event["parsed_datetime"]
        if event["line_number"] == accepted["line_number"]:
            event_role = "successful_backup_login"
        else:
            event_role = "failed_attempt"

        records.append(
            {
                "finding_id": "priority_backup_login_sequence",
                "sequence_start": sequence_start.strftime("%Y-%m-%d %H:%M:%S"),
                "sequence_end": sequence_end.strftime("%Y-%m-%d %H:%M:%S"),
                "successful_login_time": success_time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": source_ip,
                "successful_username": str(accepted["username"]),
                "failed_attempt_count": int(len(failed_attempts)),
                "backup_failed_attempt_count": int(len(backup_failures)),
                "distinct_usernames_targeted": ";".join(distinct_usernames),
                "event_time": event_time.strftime("%Y-%m-%d %H:%M:%S")
                if not pd.isna(event_time)
                else "",
                "event_role": event_role,
                "event_type": event["event_type"],
                "targeted_username": event["username"],
                "source_port": event["source_port"],
                "command": event["command"],
                "raw_line": event["raw_line"],
            }
        )

    return pd.DataFrame(records, columns=columns)


def sudo_severity(username: str, command: str) -> str:
    is_privileged = username.lower() in PRIVILEGED_ACCOUNTS
    command_lower = command.lower()
    contains_high_risk_keyword = any(keyword in command_lower for keyword in SUDO_HIGH_RISK_KEYWORDS)

    if is_privileged and contains_high_risk_keyword:
        return "high"
    if is_privileged:
        return "medium"
    return "low"


def find_previous_login_for_sudo(df: pd.DataFrame, sudo_row: pd.Series) -> pd.Series | None:
    sudo_time = sudo_row["parsed_datetime"]
    username = str(sudo_row["username"])

    if pd.isna(sudo_time) or not username:
        return None

    window_start = sudo_time - timedelta(minutes=SUDO_LOOKBACK_MINUTES)
    candidates = df[
        (df["line_number"] < sudo_row["line_number"])
        & (df["username"] == username)
        & (df["event_type"].isin(["accepted_password", "session_opened"]))
        & (df["parsed_datetime"] >= window_start)
        & (df["parsed_datetime"] <= sudo_time)
    ].copy()

    if candidates.empty:
        return None

    candidates = candidates.sort_values(["parsed_datetime", "line_number"], ascending=[False, False])
    return candidates.iloc[0]


def previous_login_source_ip(df: pd.DataFrame, sudo_row: pd.Series, login_row: pd.Series | None) -> str:
    if login_row is not None and str(login_row.get("source_ip", "")):
        return str(login_row["source_ip"])

    sudo_time = sudo_row["parsed_datetime"]
    username = str(sudo_row["username"])
    if pd.isna(sudo_time) or not username:
        return ""

    window_start = sudo_time - timedelta(minutes=SUDO_LOOKBACK_MINUTES)
    accepted_candidates = df[
        (df["line_number"] < sudo_row["line_number"])
        & (df["username"] == username)
        & (df["event_type"] == "accepted_password")
        & (df["parsed_datetime"] >= window_start)
        & (df["parsed_datetime"] <= sudo_time)
    ].copy()

    if accepted_candidates.empty:
        return ""

    accepted_candidates = accepted_candidates.sort_values(
        ["parsed_datetime", "line_number"], ascending=[False, False]
    )
    return str(accepted_candidates.iloc[0]["source_ip"])


def sudo_after_accepted_login(df: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "sudo_time",
        "username",
        "command",
        "previous_login_time",
        "minutes_after_login",
        "previous_login_source_ip",
        "sudo_raw_line",
        "severity",
    ]

    sudo_df = df[df["event_type"] == "sudo_command"].copy()
    records = []

    for _, sudo_row in sudo_df.iterrows():
        sudo_time = sudo_row["parsed_datetime"]
        username = str(sudo_row["username"])
        command = str(sudo_row["command"])
        login_row = find_previous_login_for_sudo(df, sudo_row)

        if login_row is None:
            previous_login_time = ""
            minutes_after_login = ""
        else:
            login_time = login_row["parsed_datetime"]
            previous_login_time = (
                login_time.strftime("%Y-%m-%d %H:%M:%S") if not pd.isna(login_time) else ""
            )
            minutes_after_login = (
                round((sudo_time - login_time).total_seconds() / 60, 2)
                if not pd.isna(sudo_time) and not pd.isna(login_time)
                else ""
            )

        records.append(
            {
                "sudo_time": sudo_time.strftime("%Y-%m-%d %H:%M:%S")
                if not pd.isna(sudo_time)
                else "",
                "username": username,
                "command": command,
                "previous_login_time": previous_login_time,
                "minutes_after_login": minutes_after_login,
                "previous_login_source_ip": previous_login_source_ip(df, sudo_row, login_row),
                "sudo_raw_line": sudo_row["raw_line"],
                "severity": sudo_severity(username, command),
            }
        )

    return pd.DataFrame(records, columns=columns).sort_values(
        ["severity", "sudo_time"],
        ascending=[True, True],
    )


def timestamp_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    columns = [
        "line_number",
        "previous_line_number",
        "previous_datetime",
        "current_datetime",
        "delta_seconds",
        "current_raw_line",
        "previous_raw_line",
    ]
    records = []
    previous_row = None

    for _, current_row in df.iterrows():
        current_datetime = current_row["parsed_datetime"]
        if pd.isna(current_datetime):
            continue

        if previous_row is not None:
            previous_datetime = previous_row["parsed_datetime"]
            if current_datetime < previous_datetime:
                delta_seconds = int((current_datetime - previous_datetime).total_seconds())
                records.append(
                    {
                        "line_number": current_row["line_number"],
                        "previous_line_number": previous_row["line_number"],
                        "previous_datetime": previous_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                        "current_datetime": current_datetime.strftime("%Y-%m-%d %H:%M:%S"),
                        "delta_seconds": delta_seconds,
                        "current_raw_line": current_row["raw_line"],
                        "previous_raw_line": previous_row["raw_line"],
                    }
                )

        previous_row = current_row

    return pd.DataFrame(records, columns=columns)


def save_empty_plot(path: Path, title: str, message: str = "No matching data") -> None:
    plt.figure(figsize=(10, 5))
    plt.title(title)
    plt.text(0.5, 0.5, message, ha="center", va="center", transform=plt.gca().transAxes)
    plt.xticks([])
    plt.yticks([])
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()


def plot_horizontal_bar(
    data: pd.DataFrame,
    label_column: str,
    value_column: str,
    path: Path,
    title: str,
    xlabel: str,
    limit: int = 10,
) -> None:
    plot_df = data[[label_column, value_column]].copy()
    plot_df = plot_df[plot_df[value_column] > 0].head(limit)

    if plot_df.empty:
        save_empty_plot(path, title)
        return

    plot_df = plot_df.sort_values(value_column, ascending=True)
    plt.figure(figsize=(10, 6))
    bars = plt.barh(plot_df[label_column].astype(str), plot_df[value_column])
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(label_column.replace("_", " ").title())
    plt.bar_label(bars, padding=3)
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()


def plot_attack_stages_over_time(
    df: pd.DataFrame,
    path: Path,
    priority_timeline_df: pd.DataFrame | None = None,
    title: str = "Selected Attack Lifecycle Stages Over Time",
) -> None:
    selected_stages = [
        "account_probing",
        "initial_access_attempt",
        "brute_force_or_password_spraying",
        "possible_successful_access",
        "post_login_privileged_activity",
    ]

    stage_df = df[
        df["attack_stage"].isin(selected_stages) & df["parsed_datetime"].notna()
    ].copy()

    if stage_df.empty:
        save_empty_plot(path, title)
        return

    grouped = (
        stage_df.groupby([pd.Grouper(key="parsed_datetime", freq="h"), "attack_stage"])
        .size()
        .unstack(fill_value=0)
    )

    for stage in selected_stages:
        if stage not in grouped.columns:
            grouped[stage] = 0

    grouped = grouped[selected_stages].sort_index()

    plt.figure(figsize=(12, 6))
    for stage in selected_stages:
        plt.plot(grouped.index, grouped[stage], marker="o", linewidth=1.3, markersize=2.5, label=stage)

    if priority_timeline_df is not None and not priority_timeline_df.empty:
        success_time = pd.to_datetime(
            priority_timeline_df["successful_login_time"].iloc[0],
            errors="coerce",
        )
        source_ip = str(priority_timeline_df["source_ip"].iloc[0])
        failed_attempt_count = int(priority_timeline_df["failed_attempt_count"].iloc[0])
        backup_failed_attempt_count = int(priority_timeline_df["backup_failed_attempt_count"].iloc[0])

        if not pd.isna(success_time):
            plt.axvline(
                success_time,
                color="black",
                linestyle="--",
                linewidth=1.8,
                label=f"successful backup login ({source_ip})",
            )
            y_max = max(grouped.max().max(), 1)
            plt.annotate(
                (
                    f"backup login\n{source_ip}\n"
                    f"{failed_attempt_count} failed attempts; "
                    f"{backup_failed_attempt_count} to backup"
                ),
                xy=(success_time, y_max * 0.8),
                xytext=(18, -45),
                textcoords="offset points",
                fontsize=8,
                color="black",
                arrowprops={"arrowstyle": "->", "color": "black", "linewidth": 1},
                bbox={"boxstyle": "round,pad=0.25", "fc": "white", "ec": "black", "alpha": 0.85},
            )

    plt.title(title)
    plt.xlabel("Hour")
    plt.ylabel("Event count")
    plt.legend(loc="upper left", fontsize=8)
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()


def generate_visualisations(
    df: pd.DataFrame,
    output_dir: Path,
    failed_sources_df: pd.DataFrame,
    targeted_users_df: pd.DataFrame,
    priority_timeline_df: pd.DataFrame,
) -> None:
    plot_horizontal_bar(
        failed_sources_df,
        "source_ip",
        "failed_password_count",
        output_dir / "top_source_ips_failed.png",
        "Top 10 Source IPs by Failed Password Events",
        "Failed password count",
    )

    targeted_plot_df = targeted_users_df.copy()
    if not targeted_plot_df.empty:
        targeted_plot_df["failed_plus_max_auth_count"] = (
            targeted_plot_df["failed_password_count"] + targeted_plot_df["max_auth_attempts_count"]
        )
        targeted_plot_df = targeted_plot_df.sort_values(
            "failed_plus_max_auth_count", ascending=False
        )
    else:
        targeted_plot_df["failed_plus_max_auth_count"] = []

    plot_horizontal_bar(
        targeted_plot_df,
        "username",
        "failed_plus_max_auth_count",
        output_dir / "top_targeted_users.png",
        "Top 10 Targeted Usernames by Failed Password and Max Auth Attempts",
        "Failed password + max authentication attempts",
    )

    plot_attack_stages_over_time(
        df,
        output_dir / "figure2_attack_stages_backup_login.png",
        priority_timeline_df,
        "Figure 2: Attack Lifecycle Stages With Successful 'backup' Login Marked",
    )


def remove_stale_replaced_outputs(output_dir: Path) -> None:
    for filename in STALE_REPLACED_OUTPUTS:
        stale_path = output_dir / filename
        if stale_path.exists():
            stale_path.unlink()


def generate_outputs(df: pd.DataFrame, output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    remove_stale_replaced_outputs(output_dir)

    suspicious_sources = add_suspicious_source_column(df)

    event_counts_df = event_type_counts(df)
    attack_counts_df = attack_stage_counts(df)
    failed_sources_df = top_source_ips_failed(df)
    targeted_users_df = targeted_user_summary(df)
    priority_timeline_df = priority_backup_login_timeline(df)
    sudo_after_login_df = sudo_after_accepted_login(df)
    anomalies_df = timestamp_anomalies(df)

    write_csv(df[CSV_COLUMNS], output_dir / "parsed_events.csv")
    write_csv(event_counts_df, output_dir / "event_type_counts.csv")
    write_csv(attack_counts_df, output_dir / "attack_stage_counts.csv")
    write_csv(failed_sources_df, output_dir / "top_source_ips_failed.csv")
    write_csv(targeted_users_df, output_dir / "top_targeted_users.csv")
    write_csv(priority_timeline_df, output_dir / "priority_finding_backup_login_timeline.csv")
    write_csv(sudo_after_login_df, output_dir / "sudo_after_accepted_login.csv")
    write_csv(anomalies_df, output_dir / "timestamp_anomalies.csv")

    generate_visualisations(
        df,
        output_dir,
        failed_sources_df,
        targeted_users_df,
        priority_timeline_df,
    )

    priority_failed_attempt_count = 0
    priority_source_ip = ""
    priority_success_time = ""
    if not priority_timeline_df.empty:
        priority_failed_attempt_count = int(priority_timeline_df["failed_attempt_count"].iloc[0])
        priority_source_ip = str(priority_timeline_df["source_ip"].iloc[0])
        priority_success_time = str(priority_timeline_df["successful_login_time"].iloc[0])

    return {
        "suspicious_source_count": len(suspicious_sources),
        "priority_failed_attempt_count": priority_failed_attempt_count,
        "priority_source_ip": priority_source_ip,
        "priority_success_time": priority_success_time,
        "timestamp_anomaly_count": len(anomalies_df),
    }


def count_event(df: pd.DataFrame, event_type: str) -> int:
    return int((df["event_type"] == event_type).sum())


def print_console_summary(df: pd.DataFrame, output_dir: Path, metrics: dict[str, object]) -> None:
    print("Auth log analysis summary")
    print(f"total lines parsed: {len(df)}")
    print(f"total failed_password events: {count_event(df, 'failed_password')}")
    print(f"total invalid_user events: {count_event(df, 'invalid_user')}")
    print(f"total max_auth_attempts events: {count_event(df, 'max_auth_attempts')}")
    print(f"total accepted_password events: {count_event(df, 'accepted_password')}")
    print(f"total sudo_command events: {count_event(df, 'sudo_command')}")
    print(f"number of suspicious source IPs: {metrics['suspicious_source_count']}")
    print(f"priority finding source IP: {metrics['priority_source_ip'] or 'not found'}")
    print(f"priority finding successful backup login: {metrics['priority_success_time'] or 'not found'}")
    print(f"priority finding failed attempts in timeline: {metrics['priority_failed_attempt_count']}")
    print(f"number of timestamp anomalies: {metrics['timestamp_anomaly_count']}")
    print(f"output folder path: {output_dir.resolve()}")


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output)

    if not input_path.exists():
        raise SystemExit(f"Input log not found: {input_path}")

    df = read_log(input_path)
    metrics = generate_outputs(df, output_dir)
    print_console_summary(df, output_dir, metrics)


if __name__ == "__main__":
    main()


README = """
README - analysis.py

How to run:
    python analysis.py --input 4_auth.log --output output

Defaults:
    If no arguments are supplied, the script reads 4_auth.log and writes all CSV
    and PNG files to output/.

Expected input:
    A Linux auth.log-style text file with syslog timestamps such as:
        Jul 06 03:40:05 backup01 sshd[4207]: Failed password for j.singer from 192.0.2.31 port 60064 ssh2

Generated CSV outputs:
    parsed_events.csv
    event_type_counts.csv
    attack_stage_counts.csv
    top_source_ips_failed.csv
    top_targeted_users.csv
    priority_finding_backup_login_timeline.csv
    sudo_after_accepted_login.csv
    timestamp_anomalies.csv

Generated visual outputs:
    top_source_ips_failed.png
    top_targeted_users.png
    figure2_attack_stages_backup_login.png

Main assumptions:
    - The auth.log timestamps do not include a year, so DEFAULT_YEAR = 2026 is used.
    - Privileged or operational accounts are configured in PRIVILEGED_ACCOUNTS.
    - Suspicious source IPs are calculated from failed_password, max_auth_attempts,
      and possible_break_in evidence using thresholds near the top of the file.
    - priority_finding_backup_login_timeline.csv selects the strongest successful
      backup login sequence by counting failed attempts from the same source IP
      around each successful backup login.
    - figure2_attack_stages_backup_login.png marks the selected successful backup
      login on the lifecycle-stage timeline.
    - sudo_after_accepted_login.csv uses a 10-minute prior window for the same username.

Limitations:
    - The script analyses authentication and post-login evidence only. It cannot prove
      compromise, malware execution, data access, or attacker intent by itself.
    - "Accepted password" means successful authentication was logged; it does not prove
      whether the login was authorised or malicious.
    - Timestamp anomaly detection identifies log-order reversals in file order. It should
      be discussed as a log-ordering or collection limitation, not as proof of tampering.
    - Source IPs in this project may be documentation or simulated ranges; treat them as
      evidence labels unless independently validated.
    - The script supports cautious reporting language such as "possible successful
      compromise", "suspicious authentication sequence", "requires investigation", and
      "visible attack lifecycle stages from auth evidence".
"""
