"""Command line entry point.

    python analyze.py access.log
    python analyze.py OpenSSH_2k.log --format ssh --year 2015
"""
import argparse
import os

from loganalyzer.parsers import parse_file
from loganalyzer.detectors import Config, run_web, run_ssh, risk_scores
from loganalyzer.report import write_html, write_json


def main():
    ap = argparse.ArgumentParser(description="Detect suspicious activity in web server or SSH logs.")
    ap.add_argument("logfile")
    ap.add_argument("--format", choices=["auto", "web", "ssh"], default="auto")
    ap.add_argument("--year", type=int, help="year to assume for SSH logs (they do not include one)")
    ap.add_argument("--out", default="report.html", help="HTML report path")
    ap.add_argument("--json", dest="json_out", help="also write alerts to this JSON file")
    d = Config()
    ap.add_argument("--brute-attempts", type=int, default=d.brute_attempts)
    ap.add_argument("--brute-window", type=int, default=d.brute_window_min, help="minutes")
    ap.add_argument("--scan-paths", type=int, default=d.scan_distinct_404)
    ap.add_argument("--min-failures", type=int, default=d.min_failures)
    ap.add_argument("--enum-users", type=int, default=d.enum_users)
    ap.add_argument("--night-start", type=int, default=d.night_start)
    ap.add_argument("--night-end", type=int, default=d.night_end)
    a = ap.parse_args()

    cfg = Config(a.brute_attempts, a.brute_window, a.scan_paths, a.min_failures,
                 a.enum_users, a.night_start, a.night_end)
    fmt, events, total, skipped = parse_file(a.logfile, a.format, a.year)
    findings = run_web(events, cfg) if fmt == "web" else run_ssh(events, cfg)

    print(f"Format: {fmt} | lines: {total} | parsed: {len(events)} | skipped: {skipped}")
    print(f"Alerts: {len(findings)} from {len({f.ip for f in findings})} IPs\n")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda f: (order[f.severity], -f.count))[:25]:
        print(f"[{f.severity.upper():8}] {f.ip:16} {f.kind:30} {f.technique_id:10} {f.detail}")
    if len(findings) > 25:
        print(f"... and {len(findings) - 25} more (see the report)")
    print("\nTop risk IPs:", list(risk_scores(findings).items())[:5])

    write_html(a.out, findings, events, fmt, total, skipped, os.path.basename(a.logfile))
    print(f"\nReport written to {a.out}")
    if a.json_out:
        write_json(a.json_out, findings)
        print(f"Alerts written to {a.json_out}")


if __name__ == "__main__":
    main()
