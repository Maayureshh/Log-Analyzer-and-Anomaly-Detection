"""Compares the detector output with ground_truth.json and prints precision / recall,
then repeats the brute-force rule with different thresholds to show the trade-off.

    python generate_sample_logs.py
    python evaluate.py
"""
import json
from dataclasses import replace

from loganalyzer.parsers import parse_file
from loganalyzer.detectors import Config, run_web, web_brute_force

KINDS = ["brute_force", "login_success_after_failures", "scan", "web_attack", "off_hours_login"]


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def load():
    truth = json.load(open("ground_truth.json"))
    expected = {k: {t["ip"] for t in truth if k in t["kinds"]} for k in KINDS}
    _, events, _, _ = parse_file("access.log", "web")
    return truth, expected, events


def main():
    truth, expected, events = load()
    findings = run_web(events, Config())
    detected = {k: {f.ip for f in findings if f.kind == k} for k in KINDS}

    out = ["## Detection results (default thresholds)", "",
           "| Rule | TP | FP | FN | Precision | Recall | F1 |", "|---|---|---|---|---|---|---|"]
    TP = FP = FN = 0
    notes = []
    for k in KINDS:
        tp = len(expected[k] & detected[k]); fp = len(detected[k] - expected[k]); fn = len(expected[k] - detected[k])
        TP += tp; FP += fp; FN += fn
        p, r, f = prf(tp, fp, fn)
        out.append(f"| {k} | {tp} | {fp} | {fn} | {p:.2f} | {r:.2f} | {f:.2f} |")
        for ip in sorted(detected[k] - expected[k]):
            note = next((t["note"] for t in truth if t["ip"] == ip), "not labelled")
            notes.append(f"- False positive ({k}): {ip}, {note}")
        for ip in sorted(expected[k] - detected[k]):
            note = next((t["note"] for t in truth if t["ip"] == ip), "")
            notes.append(f"- Missed ({k}): {ip}, {note}")
    p, r, f = prf(TP, FP, FN)
    out.append(f"| **all rules** | {TP} | {FP} | {FN} | {p:.2f} | {r:.2f} | {f:.2f} |")
    out += ["", "### Where it went wrong", ""] + notes

    base = Config()
    out += ["", "## Brute-force threshold sweep (5 minute window)", "",
            "| Failed logins needed | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"]
    for n in (3, 5, 10, 20, 40, 60):
        d = {f.ip for f in web_brute_force(events, replace(base, brute_attempts=n))}
        e = expected["brute_force"]
        p, r, _ = prf(len(e & d), len(d - e), len(e - d))
        out.append(f"| {n} | {len(e & d)} | {len(d - e)} | {len(e - d)} | {p:.2f} | {r:.2f} |")

    out += ["", "## Brute-force window sweep (10 failed logins needed)", "",
            "| Window (min) | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|"]
    for w in (1, 5, 15, 60, 240):
        d = {f.ip for f in web_brute_force(events, replace(base, brute_window_min=w))}
        e = expected["brute_force"]
        p, r, _ = prf(len(e & d), len(d - e), len(e - d))
        out.append(f"| {w} | {len(e & d)} | {len(d - e)} | {len(e - d)} | {p:.2f} | {r:.2f} |")

    text = "\n".join(out)
    print(text)
    with open("evaluation_results.md", "w") as f:
        f.write(text + "\n")
    print("\nSaved to evaluation_results.md")


if __name__ == "__main__":
    main()
