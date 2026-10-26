"""Generate synthetic auth.log and access.log files containing a scripted attack scenario.

The scenario (all IPs are from RFC 5737 documentation ranges):

  02:10  203.0.113.45   runs Nikto against the web server, finds an exposed /.env
  02:25  203.0.113.45   sqlmap against /products.php (some 500 errors)
  02:40  203.0.113.45   XSS probes on /search, path traversal on /download.php
  03:05  203.0.113.45   uploads avatar.php and runs commands through it (web shell)
  03:30  198.51.100.23  brute forces SSH, gets in as 'deploy', opens a root shell
  04:00  192.0.2.77     slow password spray across a dozen usernames

Around it runs a day of normal traffic: staff SSH logins, cron, sudo, and site visitors.

Usage: python scripts/generate_samples.py [output_dir]
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

DAY = datetime(2026, 10, 24, tzinfo=timezone.utc)
HOST = "web01"

WEB_ATTACKER = "203.0.113.45"
SSH_ATTACKER = "198.51.100.23"
SPRAYER = "192.0.2.77"

STAFF = {"alice": "10.0.0.12", "bob": "10.0.0.15", "carol": "10.0.0.21"}
BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
PAGES = [
    ("/", 200, 5120), ("/about", 200, 3311), ("/contact", 200, 2874),
    ("/products.php?id=12", 200, 4410), ("/products.php?id=7", 200, 4398),
    ("/search?q=wireless+keyboard", 200, 6021), ("/static/app.css", 200, 18233),
    ("/static/app.js", 200, 40211), ("/img/logo.png", 200, 9022), ("/favicon.ico", 404, 162),
]


class Logs:
    def __init__(self, rng: random.Random):
        self.rng = rng
        self.auth: list[tuple[datetime, str]] = []
        self.web: list[tuple[datetime, str]] = []
        self.pid = 2000

    def _pid(self) -> int:
        self.pid += self.rng.randint(1, 40)
        return self.pid

    def syslog(self, ts: datetime, proc: str, msg: str, pid: bool = True) -> None:
        tag = f"{proc}[{self._pid()}]" if pid else proc
        self.auth.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} {tag}: {msg}"))

    def ssh_fail(self, ts: datetime, user: str, ip: str, invalid: bool = False) -> None:
        who = f"invalid user {user}" if invalid else user
        self.syslog(ts, "sshd", f"Failed password for {who} from {ip} port {self.rng.randint(32768, 60999)} ssh2")

    def ssh_ok(self, ts: datetime, user: str, ip: str, method: str = "publickey") -> None:
        port = self.rng.randint(32768, 60999)
        self.syslog(ts, "sshd", f"Accepted {method} for {user} from {ip} port {port} ssh2")
        self.syslog(ts, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")

    def sudo(self, ts: datetime, user: str, command: str) -> None:
        self.syslog(ts, "sudo", f"   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
                    pid=False)

    def http(self, ts: datetime, ip: str, method: str, path: str, status: int, size: int, ua: str,
             referer: str = "-") -> None:
        self.web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                             f'{status} {size} "{referer}" "{ua}"'))


def background(logs: Logs) -> None:
    rng = logs.rng
    for minute in range(0, 24 * 60, 10):
        logs.syslog(DAY + timedelta(minutes=minute), "CRON",
                    "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")

    for user, ip in STAFF.items():
        start = DAY + timedelta(hours=rng.randint(8, 10), minutes=rng.randint(0, 59))
        if rng.random() < 0.6:  # a mistyped password before getting in is normal
            logs.ssh_fail(start - timedelta(seconds=20), user, ip)
        logs.ssh_ok(start, user, ip, method=rng.choice(["publickey", "password"]))
    logs.sudo(DAY + timedelta(hours=9, minutes=14), "alice", "/usr/bin/systemctl restart nginx")
    logs.sudo(DAY + timedelta(hours=11, minutes=2), "bob", "/usr/bin/apt update")
    logs.sudo(DAY + timedelta(hours=15, minutes=40), "alice", "/bin/bash")

    for _ in range(2400):
        ts = DAY + timedelta(seconds=rng.randint(0, 86399))
        ip = f"198.51.100.{rng.randint(100, 220)}" if rng.random() < 0.5 else f"192.0.2.{rng.randint(10, 60)}"
        path, status, size = rng.choice(PAGES)
        logs.http(ts, ip, "GET", path, status, size + rng.randint(-40, 40) if status == 200 else size,
                  rng.choice(BROWSERS))


def web_attack(logs: Logs) -> None:
    rng = logs.rng
    ip = WEB_ATTACKER
    t = DAY + timedelta(hours=2, minutes=10)
    nikto = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
    wordlist = ["admin", "administrator", "backup", "old", "test", "dev", "phpmyadmin", "cgi-bin/test.cgi",
                "wp-admin", "wp-login.php", "login.php", "manager/html", "console", "debug", "api/v1",
                "includes", "install.php", "setup.php", "uploads/", "tmp", "logs", "db", "sql", "private",
                "server-status", ".git/config", ".svn/entries", "backup.zip", "site-backup.tar.gz",
                "wp-config.php.bak", "config.php.old", "phpinfo.php", "database.sql", ".htpasswd"]
    for word in wordlist:
        t += timedelta(milliseconds=rng.randint(150, 900))
        logs.http(t, ip, "GET", f"/{word}", 404, 162, nikto)
    t += timedelta(seconds=1)
    logs.http(t, ip, "GET", "/.env", 200, 734, nikto)
    logs.http(t + timedelta(seconds=1), ip, "GET", "/uploads/", 403, 199, nikto)

    t = DAY + timedelta(hours=2, minutes=25)
    sqlmap = "sqlmap/1.8.9#stable (https://sqlmap.org)"
    payloads = [
        ("12'", 500), ("12 AND 1=1", 200), ("12' AND '1'='1", 200), ("12' OR '1'='1", 200),
        ("12 UNION ALL SELECT NULL,NULL,NULL-- -", 500),
        ("12 UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables-- -", 200),
        ("12 AND SLEEP(5)", 200), ("12' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -", 500),
        ("12;DROP TABLE users-- -", 500),
    ]
    for payload, status in payloads:
        t += timedelta(seconds=rng.randint(2, 9))
        logs.http(t, ip, "GET", f"/products.php?id={quote(payload)}", status, 4410 if status == 200 else 512, sqlmap)

    t = DAY + timedelta(hours=2, minutes=40)
    firefox = BROWSERS[2]
    for q in ["<script>alert(1)</script>", '"><img src=x onerror=alert(document.cookie)>',
              "javascript:alert(1)"]:
        t += timedelta(seconds=rng.randint(10, 30))
        logs.http(t, ip, "GET", f"/search?q={quote(q)}", 200, 6021, firefox)
    for f, status, size in [("../../../../etc/passwd", 200, 2291), ("..%2f..%2f..%2fetc%2fshadow", 403, 199),
                            ("php://filter/convert.base64-encode/resource=index.php", 200, 7720)]:
        t += timedelta(seconds=rng.randint(10, 30))
        logs.http(t, ip, "GET", f"/download.php?file={quote(f, safe='%')}", status, size, firefox)

    t = DAY + timedelta(hours=3, minutes=5)
    logs.http(t, ip, "POST", "/profile/upload.php", 200, 88, firefox, referer="https://shop.example/profile")
    for cmd in ["id", "whoami", "uname -a", "cat /etc/passwd", "ls -la /var/www/html"]:
        t += timedelta(seconds=rng.randint(4, 20))
        logs.http(t, ip, "GET", f"/uploads/avatar.php?cmd={quote(cmd)}", 200, rng.randint(40, 1900), firefox)


def ssh_bruteforce(logs: Logs) -> None:
    rng = logs.rng
    t = DAY + timedelta(hours=3, minutes=30)
    for i in range(64):
        t += timedelta(seconds=rng.uniform(2.5, 9))
        logs.ssh_fail(t, "root" if i % 3 else "deploy", SSH_ATTACKER)
    t += timedelta(seconds=6)
    logs.ssh_ok(t, "deploy", SSH_ATTACKER, method="password")
    logs.sudo(t + timedelta(minutes=2, seconds=13), "deploy", "/bin/bash")


def password_spray(logs: Logs) -> None:
    rng = logs.rng
    t = DAY + timedelta(hours=4)
    users = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "jenkins",
             "ftpuser", "guest", "support", "alice", "bob"]
    for user in users:
        for _ in range(rng.randint(1, 2)):
            t += timedelta(seconds=rng.randint(35, 55))
            logs.ssh_fail(t, user, SPRAYER, invalid=user not in STAFF)


def main(out_dir: str = "samples") -> None:
    logs = Logs(random.Random(1337))
    background(logs)
    web_attack(logs)
    ssh_bruteforce(logs)
    password_spray(logs)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for name, entries in [("auth.log", logs.auth), ("access.log", logs.web)]:
        entries.sort(key=lambda e: e[0])
        (out / name).write_text("\n".join(line for _, line in entries) + "\n", encoding="utf-8", newline="\n")
        print(f"wrote {out / name} ({len(entries)} lines)")


if __name__ == "__main__":
    main(*sys.argv[1:])
