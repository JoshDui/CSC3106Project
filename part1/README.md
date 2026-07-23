# CSC3106 Mini-Project — Part 1 Authentication Log Analysis

`analysis.py` performs a reproducible analysis of the assigned SSH authentication
log (`4_auth.log`). It parses the log, classifies authentication events and attack
stages, and writes the summary tables and figures used as evidence in the report.

## Requirements

- Python 3.10 or newer
- `pandas`
- `matplotlib`

```bash
python3 -c "import pandas, matplotlib"
```

## How to run

From this folder (`part1/`), with `4_auth.log` alongside `analysis.py`:

```bash
python3 analysis.py
```

This reads `4_auth.log` and writes all tables and figures to `output/`. The
defaults make it equivalent to:

```bash
python3 analysis.py --input 4_auth.log --output output
```

## Expected input

A Linux `auth.log`-style text file with syslog timestamps, for example:

```
Jul 06 03:40:05 backup01 sshd[4207]: Failed password for j.singer from 192.0.2.31 port 60064 ssh2
```

## Generated outputs

Written to `output/`.

**Tables (CSV)**

| File | Contents |
| ---- | -------- |
| `parsed_events.csv` | Every parsed line: event type, attack stage, username, source IP/port, command |
| `event_type_counts.csv` | Totals per event type |
| `attack_stage_counts.csv` | Totals per attack-lifecycle stage |
| `top_source_ips_failed.csv` | Source IPs ranked by failed authentications |
| `top_targeted_users.csv` | Usernames ranked by failed/invalid attempts |
| `priority_finding_backup_login_timeline.csv` | The strongest suspicious `backup` login sequence |
| `accepted_backup_login_correlations.csv` | Failure-to-success correlation and detection alerts |
| `sudo_after_accepted_login.csv` | `sudo` activity following an accepted login |
| `timestamp_anomalies.csv` | Log-order reversals in file order |

**Figures (PNG)**

- `top_source_ips_failed.png` — required top-source-IPs visualisation
- `top_targeted_users.png`
- `figure2_attack_stages_backup_login.png` — second visualisation

## Key decisions and assumptions

- **Event identification.** SSH outcomes are matched by regex on the message body
  (`failed_password`, `accepted_password`, `invalid_user`, `max_auth_attempts`,
  `sudo_command`, session/cron events). Usernames, source IPs, and ports are
  extracted from these patterns; unmatched lines are retained with a `parse_status`
  flag rather than silently dropped.
- **Year.** Syslog timestamps carry no year, so `DEFAULT_YEAR = 2026` is applied.
- **Privileged accounts.** Configured in `PRIVILEGED_ACCOUNTS`.
- **Suspicious sources.** Ranked from failed-password, max-auth, and break-in
  evidence using thresholds defined near the top of the script.
- **Priority finding.** Selected by counting same-source failures in the 60-minute
  window preceding an accepted `backup` login; post-login failures are reported
  separately.

## Detection rule (baseline-relative)

`accepted_backup_login_correlations.csv` flags an accepted `backup` login when its
preceding-hour, per-source failure count rises far above the **established
per-source baseline**, rather than exceeding a fixed count. The threshold is derived
from the data, tuned by three parameters near the top of the script:

- `DETECTION_BASELINE_PERCENTILE = 95` — robust upper bound of normal behaviour
- `DETECTION_BASELINE_MULTIPLIER = 10` — how far above baseline counts as anomalous
- `DETECTION_ABSOLUTE_FLOOR = 20` — lower bound that suppresses trivial deviations

On this extract the rule flags only `203.0.113.89` (87 preceding-hour failures
against an established-source maximum of 3).

## Limitations

- The script analyses authentication and post-login evidence only; it cannot prove
  compromise, malware execution, data access, or intent by itself.
- An accepted password means authentication succeeded, not that the login was
  authorised or malicious.
- Timestamp anomalies indicate log-ordering or collection issues, not proof of
  tampering.
- Source IPs may be documentation or simulated ranges; treat them as evidence
  labels unless independently validated.
