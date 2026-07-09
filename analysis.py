#!/usr/bin/env python3
"""
CSC3106 mini-project Part 1 analysis scaffold.

Run from the project root with:

    python3 analysis.py --input 4_auth.log --output output
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt


SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Starter scaffold for auth.log analysis.")
    parser.add_argument(
        "--input",
        default="4_auth.log",
        help="Path to assigned auth.log extract. Default: 4_auth.log",
    )
    parser.add_argument(
        "--output",
        default="output",
        help="Directory for generated scaffold artifacts. Default: output",
    )
    return parser.parse_args()


def parse_log_line(line_number: int, raw_line: str) -> dict[str, str | int]:
    """Parse only the generic syslog envelope, not the security event itself."""
    line = raw_line.rstrip("\n")
    match = SYSLOG_RE.match(line)

    if not match:
        return {
            "line_number": line_number,
            "timestamp": "",
            "hour": "",
            "host": "",
            "process": "",
            "pid": "",
            "message": "",
            "raw_line": line,
            "parsed": "no",
        }

    month = match.group("month")
    day = int(match.group("day"))
    time_value = match.group("time")
    hour = time_value.split(":", 1)[0]

    return {
        "line_number": line_number,
        "timestamp": f"{month} {day:02d} {time_value}",
        "hour": f"{month} {day:02d} {hour}:00",
        "host": match.group("host"),
        "process": match.group("process"),
        "pid": match.group("pid") or "",
        "message": match.group("message"),
        "raw_line": line,
        "parsed": "yes",
    }


def read_log(input_path: Path) -> list[dict[str, str | int]]:
    with input_path.open("r", encoding="utf-8", errors="replace") as handle:
        return [parse_log_line(index, line) for index, line in enumerate(handle, start=1)]


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def plot_bar(path: Path, labels: list[str], values: list[int], title: str, ylabel: str) -> None:
    plt.figure(figsize=(10, 6))
    bars = plt.bar(labels, values)
    plt.title(title)
    plt.ylabel(ylabel)
    plt.xticks(rotation=45, ha="right")
    plt.bar_label(bars, padding=3)
    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()


def generate_scaffold_outputs(rows: list[dict[str, str | int]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "line_number",
        "timestamp",
        "hour",
        "host",
        "process",
        "pid",
        "message",
        "raw_line",
        "parsed",
    ]

    write_csv(output_dir / "parsed_log_scaffold.csv", rows, fieldnames)

    parsed_count = sum(1 for row in rows if row["parsed"] == "yes")
    summary_rows = [
        {"metric": "total_lines", "value": len(rows)},
        {"metric": "syslog_envelope_parsed", "value": parsed_count},
        {"metric": "unparsed_lines", "value": len(rows) - parsed_count},
    ]
    write_csv(output_dir / "scaffold_summary.csv", summary_rows, ["metric", "value"])

    process_counts = Counter(str(row["process"]) for row in rows if row["process"])
    process_rows = [
        {"process": process, "line_count": count}
        for process, count in process_counts.most_common()
    ]
    write_csv(output_dir / "lines_by_process.csv", process_rows, ["process", "line_count"])

    hour_counts = Counter(str(row["hour"]) for row in rows if row["hour"])
    hour_rows = [
        {"hour": hour, "line_count": hour_counts[hour]}
        for hour in sorted(hour_counts)
    ]
    write_csv(output_dir / "lines_by_hour.csv", hour_rows, ["hour", "line_count"])

    if process_rows:
        top_processes = process_rows[:10]
        plot_bar(
            output_dir / "placeholder_lines_by_process.png",
            [row["process"] for row in top_processes],
            [int(row["line_count"]) for row in top_processes],
            "Placeholder chart: log lines by process",
            "Line count",
        )

    if hour_rows:
        # Keep the chart simple; this is only an artifact scaffold, not final analysis.
        sample_hours = hour_rows[:24]
        plot_bar(
            output_dir / "placeholder_lines_by_hour.png",
            [row["hour"] for row in sample_hours],
            [int(row["line_count"]) for row in sample_hours],
            "Placeholder chart: first 24 hourly log buckets",
            "Line count",
        )


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output)

    if not input_path.exists():
        raise SystemExit(f"Input log not found: {input_path}")

    rows = read_log(input_path)
    generate_scaffold_outputs(rows, output_dir)

    print(f"Read {len(rows)} lines from {input_path}")
    print(f"Wrote scaffold artifacts to {output_dir}")
    print("No IP, username, or event-type extraction is implemented yet.")


if __name__ == "__main__":
    main()
