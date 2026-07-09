# Part 1 Authentication Log Analysis

This folder contains the Python evidence-generation script for CSC3106 Mini-Project Part 1. The script parses the assigned Linux authentication log extract, generates CSV summary tables, and creates visualisations used to support the Part 1 report.

## Security Framing

The analysis focuses on the question:

Which authentication events or patterns in the assigned log extract should be prioritised for investigation or response, and why?

The script treats failed password events, invalid-user attempts, maximum-authentication failures, and pre-authentication connection closures as failed authentication-related events. These are counted separately in the output so the report can avoid treating every event type as the same kind of failed login.

## Requirements

- Python 3
- matplotlib

No network access is required. The script reads the local log file and writes all outputs to the local `output/` folder.

## Input

The default input path is:

```bash
../4_auth.log
```

This matches the assigned authentication log extract for the relevant project groups in the brief.

Syslog timestamps do not include a year. Daily summaries and visualisations therefore use the month and day shown in the raw log, such as `Jul 06`, not a fabricated calendar year.

## How to Run

From this folder:

```bash
python3 analysis.py
```

Optional arguments:

```bash
python3 analysis.py ../4_auth.log --output-dir output
```

## Generated Outputs

The script generates:

- `output/summary_counts.csv`: overall counts used for the report.
- `output/top_source_ips.csv`: source IPs ranked by failed authentication-related events.
- `output/failed_attempts_by_day.csv`: daily failed authentication-related event counts.
- `output/top_targeted_usernames.csv`: usernames ranked by failed authentication-related events.
- `output/top_valid_usernames.csv`: recognised usernames ranked by failed authentication-related events.
- `output/top_invalid_usernames.csv`: invalid usernames ranked by invalid-user-related events.
- `output/event_type_counts.csv`: parsed event categories and counts.
- `output/top_source_ips.png`: required visualisation showing top source IPs by failed authentication-related events.
- `output/failed_attempts_by_day.png`: second visualisation showing when failed authentication-related events peak.

If any log lines do not match the expected syslog format, the script also writes:

- `output/unmatched_lines.csv`

## Parsing Assumptions

- The log uses a standard syslog-like format: month, day, time, hostname, service, optional process ID, and message.
- The raw log does not include a year, so report-facing date labels use only the month and day from the log.
- SSH authentication messages are produced by `sshd`.
- The script extracts usernames, source IP addresses, and ports from recognised SSH patterns.
- Sudo activity is counted when the service is `sudo`.
- CRON and other non-SSH/non-sudo events are retained as parsed events but classified as `other` unless a more specific parser is added.
- Empty lines are ignored.
- Lines that do not match the syslog pattern are counted and optionally written to `unmatched_lines.csv`.

## Limitations

- Counts are event counts, not confirmed unique attacker sessions.
- A failed password, an invalid-user event, and a maximum-authentication event may represent different stages or types of authentication pressure. The report should describe them precisely rather than merging them into a single unsupported claim.
- The script does not prove whether a successful login was authorised or malicious. Successful login counts should be interpreted with caution and, ideally, checked against asset ownership, expected login sources, and user activity records.
- The source IP addresses in this dataset may be documentation/test ranges rather than real public hosts. Do not attempt to scan, contact, or investigate them outside the supplied dataset.
- The script does not perform geolocation, threat intelligence lookup, or live network checks.
