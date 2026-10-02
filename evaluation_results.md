## Detection results (default thresholds)

| Rule | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| brute_force | 2 | 0 | 1 | 1.00 | 0.67 | 0.80 |
| login_success_after_failures | 1 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| scan | 2 | 0 | 0 | 1.00 | 1.00 | 1.00 |
| web_attack | 2 | 1 | 0 | 0.67 | 1.00 | 0.80 |
| off_hours_login | 1 | 1 | 0 | 0.50 | 1.00 | 0.67 |
| **all rules** | 8 | 2 | 1 | 0.80 | 0.89 | 0.84 |

### Where it went wrong

- Missed (brute_force): 203.0.113.52, slow and low: 18 attempts spread over three hours
- False positive (web_attack): 192.168.1.41, reader of a security blog, searched for 'union select tutorial'
- False positive (off_hours_login): 192.168.1.77, night-shift employee logging in at 4:30 AM

## Brute-force threshold sweep (5 minute window)

| Failed logins needed | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| 3 | 2 | 1 | 1 | 0.67 | 0.67 |
| 5 | 2 | 0 | 1 | 1.00 | 0.67 |
| 10 | 2 | 0 | 1 | 1.00 | 0.67 |
| 20 | 2 | 0 | 1 | 1.00 | 0.67 |
| 40 | 2 | 0 | 1 | 1.00 | 0.67 |
| 60 | 1 | 0 | 2 | 1.00 | 0.33 |

## Brute-force window sweep (10 failed logins needed)

| Window (min) | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| 1 | 2 | 0 | 1 | 1.00 | 0.67 |
| 5 | 2 | 0 | 1 | 1.00 | 0.67 |
| 15 | 2 | 0 | 1 | 1.00 | 0.67 |
| 60 | 2 | 0 | 1 | 1.00 | 0.67 |
| 240 | 3 | 0 | 0 | 1.00 | 1.00 |
