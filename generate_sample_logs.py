"""Builds a sample access log (combined format) and a ground-truth file saying which IPs
are really malicious. The log has normal traffic, eight attackers and a few innocent
users who look a bit suspicious, so the evaluation has something to get wrong.

    python generate_sample_logs.py      ->  access.log, ground_truth.json
"""
import json
import random
from datetime import datetime, timedelta

random.seed(7)
DAY = datetime(2026, 9, 1)
BROWSERS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1"]
PAGES = ["/", "/index.html", "/about", "/products", "/products/12", "/contact", "/blog", "/blog/post-1", "/css/style.css", "/js/app.js"]
MISSING = ["/favicon.ico", "/old-page", "/robots.txt", "/apple-touch-icon.png", "/missing.png"]

lines = []     # (time, text)


def add(ip, t, method, path, status, ua):
    ts = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
    lines.append((t, f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {random.randint(300, 9000)} "-" "{ua}"'))


def at(h, m=0, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


# ---- normal traffic, business hours only
users = [f"192.168.1.{i}" for i in range(100, 160)]
for ip in users:
    ua = random.choice(BROWSERS)
    for _ in range(random.randint(60, 140)):
        t = at(8) + timedelta(seconds=random.randint(0, 12 * 3600))
        r = random.random()
        if r < 0.05:
            add(ip, t, "GET", random.choice(MISSING), 404, ua)
        elif r < 0.08:
            add(ip, t, "POST", "/login", 200, ua)
        else:
            add(ip, t, "GET", random.choice(PAGES), random.choice([200, 200, 200, 304]), ua)

truth = []

# ---- attackers
def attacker(ip, kinds, note):
    truth.append({"ip": ip, "malicious": True, "kinds": kinds, "note": note})

ua = random.choice(BROWSERS)
attacker("203.0.113.50", ["brute_force"], "fast password guessing, 60 attempts in 3 minutes")
for i in range(60):
    add("203.0.113.50", at(11, 0, i * 3), "POST", "/login", 401, ua)

attacker("203.0.113.51", ["brute_force", "login_success_after_failures"], "guessing that eventually works")
for i in range(40):
    add("203.0.113.51", at(14, 0, i * 6), "POST", "/wp-login.php", 401, ua)
add("203.0.113.51", at(14, 4, 30), "POST", "/wp-login.php", 200, ua)

attacker("203.0.113.52", ["brute_force"], "slow and low: 18 attempts spread over three hours")
for i in range(18):
    add("203.0.113.52", at(9, 0) + timedelta(minutes=10 * i), "POST", "/login", 401, ua)

attacker("198.51.100.77", ["scan"], "directory scan with a browser user agent, 80 missing paths")
for i in range(80):
    add("198.51.100.77", at(15, 0, i * 2), "GET", random.choice(["/admin", "/.env", "/phpmyadmin", "/backup.zip", "/config.php", "/.git/config"]) + str(i), 404, ua)

attacker("198.51.100.78", ["scan"], "gobuster user agent, only 15 requests so the 404 count stays low")
for i in range(15):
    add("198.51.100.78", at(16, 0, i * 4), "GET", f"/dir{i}/", 404, "gobuster/3.1.0")

attacker("192.0.2.10", ["web_attack"], "SQL injection attempts")
payloads = ["/products?id=1'%20OR%20'1'='1", "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users",
            "/search?q=1;DROP%20TABLE%20users", "/products?id=1%20AND%20SLEEP(5)", "/item?id=-1%20UNION%20SELECT%20NULL,NULL"]
for i in range(12):
    add("192.0.2.10", at(17, 0, i * 7), "GET", payloads[i % len(payloads)], 200, "python-requests/2.28")

attacker("192.0.2.11", ["web_attack"], "path traversal and XSS")
for i, p in enumerate(["/download?file=../../../../etc/passwd", "/view?page=..%2f..%2fetc%2fpasswd",
                       "/search?q=<script>alert(1)</script>", "/img?src=javascript:alert(1)",
                       "/download?file=....//....//etc/passwd", "/comment?t=<img%20src=x%20onerror=alert(1)>"]):
    add("192.0.2.11", at(18, 0, i * 11), "GET", p, 200, "python-requests/2.28")

attacker("198.18.0.9", ["off_hours_login"], "external IP logging in at 3 AM")
for i in range(3):
    add("198.18.0.9", at(3, 12 + i * 4), "POST", "/login", 200, ua)

# ---- innocent users that look suspicious (ground truth says benign)
def benign(ip, note):
    truth.append({"ip": ip, "malicious": False, "kinds": [], "note": note})

benign("192.168.1.20", "mistyped password three times, then logged in")
for i in range(3):
    add("192.168.1.20", at(10, 0, i * 20), "POST", "/login", 401, BROWSERS[0])
add("192.168.1.20", at(10, 1, 30), "POST", "/login", 200, BROWSERS[0])

benign("192.168.1.30", "uptime monitor that hits 12 old URLs during the day")
for i in range(12):
    add("192.168.1.30", at(8, 0) + timedelta(minutes=50 * i), "GET", f"/old-url-{i}", 404, "UptimeMonitor/1.0")

benign("192.168.1.77", "night-shift employee logging in at 4:30 AM")
add("192.168.1.77", at(4, 30), "POST", "/login", 200, BROWSERS[1])

benign("192.168.1.41", "reader of a security blog, searched for 'union select tutorial'")
add("192.168.1.41", at(13, 20), "GET", "/search?q=sql+union+select+tutorial", 200, BROWSERS[2])

lines.sort(key=lambda x: x[0])
with open("access.log", "w") as f:
    f.write("\n".join(t for _, t in lines) + "\n")
with open("ground_truth.json", "w") as f:
    json.dump(truth, f, indent=2)
print(f"access.log: {len(lines)} lines | ground_truth.json: {len(truth)} labelled IPs")
