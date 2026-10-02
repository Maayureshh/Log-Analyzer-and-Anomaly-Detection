# Log analyzer

A command line tool that reads web server or SSH logs, flags suspicious activity per source IP, and writes an HTML report. I built it to practice the kind of first-pass triage a SOC analyst does, and to see how well simple rules actually hold up when I measure them.

It only uses the Python standard library, so there is nothing to install.

## What it detects

| Log type | Rule | How it works | MITRE ATT&CK |
|---|---|---|---|
| Web | Brute-force login | N failed logins from one IP inside a sliding time window | T1110.001 |
| Web | Success after failures | A successful login from an IP that already failed several times | T1078 |
| Web | Scanning | Many distinct 404 paths from one IP, or a known scanner tool in the user agent | T1595 |
| Web | Attack payloads | SQL injection, XSS, path traversal and command injection patterns in the URL (decoded first) | T1190 |
| Web | Off-hours login | Successful login between 00:00 and 05:00 | T1078 |
| SSH | Brute force | N failed passwords from one IP inside a time window | T1110.001 |
| SSH | Username enumeration | Many different non-existent usernames from one IP | T1110.003 |
| SSH | Success after failures | Accepted login from an IP with earlier failures | T1078 |

The MITRE mapping is approximate. For example username enumeration sits between discovery and password spraying, and I picked the closest technique.

Each alert gets a severity (critical, high, medium, low) and every IP gets a risk score from the sum of its alert weights, so the report starts with the IPs worth looking at first.

## Usage

Python 3.8 or newer. On Windows use `py` instead of `python` if `python` is not recognised.

```
python generate_sample_logs.py          # makes access.log and ground_truth.json
python analyze.py access.log            # writes report.html
python analyze.py access.log --json alerts.json
python evaluate.py                      # precision / recall against the ground truth
python -m unittest discover -v          # 17 unit tests
```

SSH logs work the same way. They do not contain a year, so pass one:

```
python analyze.py OpenSSH_2k.log --format ssh --year 2017
```

All thresholds can be changed from the command line (`--brute-attempts`, `--brute-window`, `--scan-paths`, `--min-failures`, `--enum-users`, `--night-start`, `--night-end`). Run `python analyze.py -h` for the list.

<!-- Add a screenshot of report.html here: ![report](images/report.png) -->

## Evaluation on simulated logs

`generate_sample_logs.py` builds a day of traffic (about 6,000 requests) with eight attackers and four innocent users who look a bit suspicious (someone who mistyped a password, an uptime monitor, a night-shift employee, a reader searching for "union select tutorial"). Because I know which IPs are malicious, I can count true and false positives.

| Rule | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| brute_force | 2 | 0 | 1 | 1.00 | 0.67 | 0.80 |
| login_success_after_failures | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| scan | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| web_attack | 2 | 1 | 0 | 0.67 | 1.00 | 0.80 |
| off_hours_login | 1 | 1 | 0 | 0.50 | 1.00 | 0.67 |
| **all rules** | 8 | 2 | 1 | 0.80 | 0.89 | 0.84 |

What went wrong:

- **Missed:** a slow brute-force attacker (18 attempts over three hours). The 5 minute window never sees more than one or two attempts at a time. Widening the window to 240 minutes catches it, but a longer window would also mean more chances of flagging normal users in a busy log.
- **False positive:** the blog reader whose search query contained "union select". A pattern match on the URL cannot tell a search term from an attack.
- **False positive:** the night-shift employee. The off-hours rule has no idea who is supposed to be working at night.

I also swept the brute-force threshold. Requiring only 3 failed logins flags the user who mistyped their password (precision drops to 0.67); requiring 60 misses one of the two fast attackers. Anything from 5 to 40 gave the same result on this data. Full tables are in `evaluate.py` output (`evaluation_results.md`).

These numbers come from data I generated myself, with rules I wrote myself, so they are optimistic. They show how the rules behave and where their weak spots are, not how the tool would do on real traffic.

## Limitations

- Rules and fixed thresholds only. Slow attacks and attacks spread over many IPs are not caught.
- Everything is per IP, so a botnet that tries a few passwords from each of many addresses looks harmless.
- Log timestamps are used as written and the timezone is ignored.
- Web login detection looks for POST requests to common login paths with 401/403 for failure and 200/302 for success. Applications that return 200 on a failed login will not be detected correctly.
- The MITRE mapping is a rough label, not a full classification.
- The report escapes everything that comes from the log file, since log lines can contain attacker-controlled text such as `<script>` in a URL.

## Possible next steps

- Compare against a simple statistical baseline (z-score on requests per minute per IP).
- Add IP geolocation and known-bad IP feeds for context.
- Support more formats (nginx error logs, Windows event logs).

## Project layout

```
analyze.py                command line entry point
loganalyzer/parsers.py    Apache/Nginx and OpenSSH parsers
loganalyzer/detectors.py  detection rules, severity, MITRE tags
loganalyzer/report.py     HTML and JSON output
generate_sample_logs.py   simulated log with ground truth
evaluate.py               precision / recall and threshold sweeps
tests/                    unit tests
```

## License

MIT
