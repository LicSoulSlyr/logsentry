# LogSentry incident report

| Log | Lines | Parsed events |
|---|---:|---:|
| `samples/auth.log` (auth) | 236 | 88 |
| `samples/access.log` (web) | 2,457 | 2,457 |

## Summary

| Severity | Findings |
|---|---:|
| Critical | 3 |
| High | 5 |
| Medium | 4 |
| Low | 0 |

## Source IPs ranked by risk

| IP | Score | Kill chain (tactics in order seen) | Rules |
|---|---:|---|---|
| `203.0.113.45` | 31 | Reconnaissance → Initial Access → Persistence | WEB-001, WEB-002, WEB-003, WEB-004, WEB-005, WEB-006, WEB-007 |
| `198.51.100.23` | 25 | Credential Access → Initial Access → Privilege Escalation | AUTH-004, SSH-001, SSH-003 |
| `192.0.2.77` | 5 | Credential Access | SSH-002 |
| `local:web01` | 2 | Privilege Escalation | AUTH-004 |

## Findings

### 1. [CRITICAL] WEB-007: Possible web shell command execution

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 03:05:16Z to 2026-10-24 03:05:57Z
- **MITRE ATT&CK:** [T1505.003 Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) (Persistence)
- **Detail:** 5 command request(s) answered with 2xx by /uploads/avatar.php; commands: id, whoami, uname -a, cat /etc/passwd (+1 more).
- **Response:** Isolate the host, preserve the file for analysis, remove it, and audit how it was uploaded. Disable script execution in upload directories.

```text
access.log:352  203.0.113.45 - - [24/Oct/2026:03:05:16 +0000] "GET /uploads/avatar.php?cmd=id HTTP/1.1" 200 403 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:353  203.0.113.45 - - [24/Oct/2026:03:05:24 +0000] "GET /uploads/avatar.php?cmd=whoami HTTP/1.1" 200 747 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:354  203.0.113.45 - - [24/Oct/2026:03:05:31 +0000] "GET /uploads/avatar.php?cmd=uname%20-a HTTP/1.1" 200 447 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:355  203.0.113.45 - - [24/Oct/2026:03:05:42 +0000] "GET /uploads/avatar.php?cmd=cat%20/etc/passwd HTTP/1.1" 200 1038 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:356  203.0.113.45 - - [24/Oct/2026:03:05:57 +0000] "GET /uploads/avatar.php?cmd=ls%20-la%20/var/www/html HTTP/1.1" 200 1324 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
```

### 2. [CRITICAL] SSH-003: Successful SSH login after brute force

- **Source IP:** `198.51.100.23`
- **When:** 2026-10-24 03:36:23Z
- **MITRE ATT&CK:** [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) (Initial Access)
- **Detail:** Account 'deploy' logged in via password on web01 after 64 failed attempts from the same IP.
- **Response:** Treat the account as compromised: disable it, kill its sessions, rotate its credentials, and review what it did after login (sudo, cron, authorized_keys).

```text
auth.log:86  Oct 24 03:36:17 web01 sshd[6689]: Failed password for deploy from 198.51.100.23 port 45791 ssh2
auth.log:87  Oct 24 03:36:23 web01 sshd[6690]: Accepted password for deploy from 198.51.100.23 port 46077 ssh2
```

### 3. [CRITICAL] AUTH-004: Interactive root shell via sudo

- **Source IP:** `198.51.100.23`
- **When:** 2026-10-24 03:38:36Z
- **MITRE ATT&CK:** [T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) (Privilege Escalation)
- **Detail:** 'deploy' opened a root shell (/bin/bash) on web01, 2m 13s after a brute-forced login from 198.51.100.23.
- **Response:** Confirm the user had a reason to open a root shell. Restrict sudoers to specific commands instead of ALL, and log sessions with sudo log_output.

```text
auth.log:87  Oct 24 03:36:23 web01 sshd[6690]: Accepted password for deploy from 198.51.100.23 port 46077 ssh2
auth.log:89  Oct 24 03:38:36 web01 sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
```

### 4. [HIGH] WEB-004: Sensitive file probing

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 02:10:12Z to 2026-10-24 02:10:17Z
- **MITRE ATT&CK:** [T1595.003 Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/) (Reconnaissance)
- **Detail:** 11 probe(s) for sensitive files; served with 200: /.env. Responses: 200 x1, 404 x10.
- **Response:** Deny access to dotfiles and backups at the web server. If any request returned 200, rotate every secret that file contained.

```text
access.log:232  203.0.113.45 - - [24/Oct/2026:02:10:12 +0000] "GET /server-status HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:233  203.0.113.45 - - [24/Oct/2026:02:10:12 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:234  203.0.113.45 - - [24/Oct/2026:02:10:13 +0000] "GET /.svn/entries HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:235  203.0.113.45 - - [24/Oct/2026:02:10:14 +0000] "GET /backup.zip HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:236  203.0.113.45 - - [24/Oct/2026:02:10:14 +0000] "GET /site-backup.tar.gz HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
```

### 5. [HIGH] WEB-001: SQL injection attempt

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 02:25:09Z to 2026-10-24 02:25:47Z
- **MITRE ATT&CK:** [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access)
- **Detail:** 8 SQL injection request(s) to /products.php. Responses: 200 x5, 500 x3.
- **Response:** Check the targeted endpoints for string-built SQL and switch them to parameterized queries. A 500 response suggests the payload reached the database.

```text
access.log:264  203.0.113.45 - - [24/Oct/2026:02:25:09 +0000] "GET /products.php?id=12%20AND%201%3D1 HTTP/1.1" 200 4410 "-" "sqlmap/1.8.9#stable (https://sqlmap.org)"
access.log:265  203.0.113.45 - - [24/Oct/2026:02:25:13 +0000] "GET /products.php?id=12%27%20AND%20%271%27%3D%271 HTTP/1.1" 200 4410 "-" "sqlmap/1.8.9#stable (https://sqlmap.org)"
access.log:266  203.0.113.45 - - [24/Oct/2026:02:25:18 +0000] "GET /products.php?id=12%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 4410 "-" "sqlmap/1.8.9#stable (https://sqlmap.org)"
access.log:267  203.0.113.45 - - [24/Oct/2026:02:25:24 +0000] "GET /products.php?id=12%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL--%20- HTTP/1.1" 500 512 "-" "sqlmap/1.8.9#stable (https://sqlmap.org)"
access.log:268  203.0.113.45 - - [24/Oct/2026:02:25:30 +0000] "GET /products.php?id=12%20UNION%20ALL%20SELECT%20table_name%2CNULL%2CNULL%20FROM%20information_schema.tables--%20- HTTP/1.1" 200 4410 "-" "sqlmap/1.8.9#stable (https://sq...
```

### 6. [HIGH] WEB-003: Path traversal / local file inclusion attempt

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 02:41:26Z to 2026-10-24 02:42:03Z
- **MITRE ATT&CK:** [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access)
- **Detail:** 3 path traversal request(s) to /download.php. Responses: 200 x2, 403 x1.
- **Response:** Make sure file paths from user input are resolved against an allowlist. A 200 response with a large body may mean a file was disclosed.

```text
access.log:302  203.0.113.45 - - [24/Oct/2026:02:41:26 +0000] "GET /download.php?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 200 2291 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:303  203.0.113.45 - - [24/Oct/2026:02:41:52 +0000] "GET /download.php?file=..%2f..%2f..%2fetc%2fshadow HTTP/1.1" 403 199 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:304  203.0.113.45 - - [24/Oct/2026:02:42:03 +0000] "GET /download.php?file=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php HTTP/1.1" 200 7720 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 ...
```

### 7. [HIGH] SSH-001: SSH brute force

- **Source IP:** `198.51.100.23`
- **When:** 2026-10-24 03:30:08Z to 2026-10-24 03:36:17Z
- **MITRE ATT&CK:** [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) (Credential Access)
- **Detail:** Peak of 52 failed logins in 5 min (03:30:08 to 03:35:02); 64 failures in total against 2 account(s).
- **Response:** Block the source IP at the firewall, enable fail2ban or sshd MaxAuthTries, and disable password authentication in favor of SSH keys.

```text
auth.log:23  Oct 24 03:30:08 web01 sshd[5422]: Failed password for deploy from 198.51.100.23 port 45996 ssh2
auth.log:24  Oct 24 03:30:12 web01 sshd[5457]: Failed password for root from 198.51.100.23 port 41126 ssh2
auth.log:25  Oct 24 03:30:16 web01 sshd[5492]: Failed password for root from 198.51.100.23 port 46527 ssh2
auth.log:26  Oct 24 03:30:21 web01 sshd[5508]: Failed password for deploy from 198.51.100.23 port 51214 ssh2
auth.log:27  Oct 24 03:30:24 web01 sshd[5517]: Failed password for root from 198.51.100.23 port 56673 ssh2
```

### 8. [HIGH] SSH-002: SSH password spraying

- **Source IP:** `192.0.2.77`
- **When:** 2026-10-24 04:00:37Z to 2026-10-24 04:11:32Z
- **MITRE ATT&CK:** [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (Credential Access)
- **Detail:** 12 distinct accounts tried: admin, test, oracle, postgres, ubuntu, git (+6 more).
- **Response:** Block the source IP, review which of the targeted accounts exist, and enforce key-only authentication with AllowUsers in sshd_config.

```text
auth.log:93  Oct 24 04:00:37 web01 sshd[6742]: Failed password for invalid user admin from 192.0.2.77 port 48017 ssh2
auth.log:94  Oct 24 04:01:19 web01 sshd[6779]: Failed password for invalid user test from 192.0.2.77 port 56773 ssh2
auth.log:95  Oct 24 04:02:04 web01 sshd[6796]: Failed password for invalid user oracle from 192.0.2.77 port 58398 ssh2
auth.log:96  Oct 24 04:02:41 web01 sshd[6826]: Failed password for invalid user postgres from 192.0.2.77 port 60642 ssh2
auth.log:98  Oct 24 04:04:15 web01 sshd[6844]: Failed password for invalid user ubuntu from 192.0.2.77 port 59622 ssh2
```

### 9. [MEDIUM] WEB-005: Known attack tool user agent

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 02:10:00Z to 2026-10-24 02:25:47Z
- **MITRE ATT&CK:** [T1595.002 Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) (Reconnaissance)
- **Detail:** 45 request(s) identifying as: nikto, sqlmap.
- **Response:** Block or rate-limit the source IP. Scanners usually precede targeted attacks, so correlate this IP with the other findings.

```text
access.log:208  203.0.113.45 - - [24/Oct/2026:02:10:00 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:209  203.0.113.45 - - [24/Oct/2026:02:10:00 +0000] "GET /administrator HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:210  203.0.113.45 - - [24/Oct/2026:02:10:00 +0000] "GET /backup HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:211  203.0.113.45 - - [24/Oct/2026:02:10:01 +0000] "GET /old HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:212  203.0.113.45 - - [24/Oct/2026:02:10:02 +0000] "GET /test HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
```

### 10. [MEDIUM] WEB-006: Directory enumeration (404 burst)

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 02:10:00Z to 2026-10-24 02:10:16Z
- **MITRE ATT&CK:** [T1595.003 Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/) (Reconnaissance)
- **Detail:** Peak of 34 404 responses in 60s; 34 in total.
- **Response:** Rate-limit 404 responses per client and look for any 200 responses from the same IP, which show what the wordlist found.

```text
access.log:208  203.0.113.45 - - [24/Oct/2026:02:10:00 +0000] "GET /admin HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:209  203.0.113.45 - - [24/Oct/2026:02:10:00 +0000] "GET /administrator HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:210  203.0.113.45 - - [24/Oct/2026:02:10:00 +0000] "GET /backup HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:211  203.0.113.45 - - [24/Oct/2026:02:10:01 +0000] "GET /old HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
access.log:212  203.0.113.45 - - [24/Oct/2026:02:10:02 +0000] "GET /test HTTP/1.1" 404 162 "-" "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000462)"
```

### 11. [MEDIUM] WEB-002: Cross-site scripting attempt

- **Source IP:** `203.0.113.45`
- **When:** 2026-10-24 02:40:24Z to 2026-10-24 02:40:56Z
- **MITRE ATT&CK:** [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access)
- **Detail:** 3 XSS request(s) to /search. Responses: 200 x3.
- **Response:** Verify the reflected parameters are output-encoded and set a Content-Security-Policy header that blocks inline scripts.

```text
access.log:296  203.0.113.45 - - [24/Oct/2026:02:40:24 +0000] "GET /search?q=%3Cscript%3Ealert%281%29%3C/script%3E HTTP/1.1" 200 6021 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
access.log:298  203.0.113.45 - - [24/Oct/2026:02:40:44 +0000] "GET /search?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%28document.cookie%29%3E HTTP/1.1" 200 6021 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/13...
access.log:299  203.0.113.45 - - [24/Oct/2026:02:40:56 +0000] "GET /search?q=javascript%3Aalert%281%29 HTTP/1.1" 200 6021 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
```

### 12. [MEDIUM] AUTH-004: Interactive root shell via sudo

- **Source IP:** `local:web01`
- **When:** 2026-10-24 15:40:00Z
- **MITRE ATT&CK:** [T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) (Privilege Escalation)
- **Detail:** 'alice' opened a root shell (/bin/bash) on web01.
- **Response:** Confirm the user had a reason to open a root shell. Restrict sudoers to specific commands instead of ALL, and log sessions with sudo log_output.

```text
auth.log:187  Oct 24 15:40:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
```
