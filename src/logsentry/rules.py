"""Detection rule catalog. Each detector in detectors.py emits findings for one of these rules."""

from .models import Rule

RULES: dict[str, Rule] = {r.id: r for r in [
    Rule(
        id="SSH-001",
        title="SSH brute force",
        mitre_id="T1110.001",
        mitre_name="Brute Force: Password Guessing",
        tactic="Credential Access",
        recommendation="Block the source IP at the firewall, enable fail2ban or sshd MaxAuthTries, "
                       "and disable password authentication in favor of SSH keys.",
    ),
    Rule(
        id="SSH-002",
        title="SSH password spraying",
        mitre_id="T1110.003",
        mitre_name="Brute Force: Password Spraying",
        tactic="Credential Access",
        recommendation="Block the source IP, review which of the targeted accounts exist, "
                       "and enforce key-only authentication with AllowUsers in sshd_config.",
    ),
    Rule(
        id="SSH-003",
        title="Successful SSH login after brute force",
        mitre_id="T1078",
        mitre_name="Valid Accounts",
        tactic="Initial Access",
        recommendation="Treat the account as compromised: disable it, kill its sessions, rotate its "
                       "credentials, and review what it did after login (sudo, cron, authorized_keys).",
    ),
    Rule(
        id="AUTH-004",
        title="Interactive root shell via sudo",
        mitre_id="T1548.003",
        mitre_name="Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        tactic="Privilege Escalation",
        recommendation="Confirm the user had a reason to open a root shell. Restrict sudoers to "
                       "specific commands instead of ALL, and log sessions with sudo log_output.",
    ),
    Rule(
        id="WEB-001",
        title="SQL injection attempt",
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        recommendation="Check the targeted endpoints for string-built SQL and switch them to "
                       "parameterized queries. A 500 response suggests the payload reached the database.",
    ),
    Rule(
        id="WEB-002",
        title="Cross-site scripting attempt",
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        recommendation="Verify the reflected parameters are output-encoded and set a "
                       "Content-Security-Policy header that blocks inline scripts.",
    ),
    Rule(
        id="WEB-003",
        title="Path traversal / local file inclusion attempt",
        mitre_id="T1190",
        mitre_name="Exploit Public-Facing Application",
        tactic="Initial Access",
        recommendation="Make sure file paths from user input are resolved against an allowlist. "
                       "A 200 response with a large body may mean a file was disclosed.",
    ),
    Rule(
        id="WEB-004",
        title="Sensitive file probing",
        mitre_id="T1595.003",
        mitre_name="Active Scanning: Wordlist Scanning",
        tactic="Reconnaissance",
        recommendation="Deny access to dotfiles and backups at the web server. If any request "
                       "returned 200, rotate every secret that file contained.",
    ),
    Rule(
        id="WEB-005",
        title="Known attack tool user agent",
        mitre_id="T1595.002",
        mitre_name="Active Scanning: Vulnerability Scanning",
        tactic="Reconnaissance",
        recommendation="Block or rate-limit the source IP. Scanners usually precede targeted "
                       "attacks, so correlate this IP with the other findings.",
    ),
    Rule(
        id="WEB-006",
        title="Directory enumeration (404 burst)",
        mitre_id="T1595.003",
        mitre_name="Active Scanning: Wordlist Scanning",
        tactic="Reconnaissance",
        recommendation="Rate-limit 404 responses per client and look for any 200 responses from "
                       "the same IP, which show what the wordlist found.",
    ),
    Rule(
        id="WEB-007",
        title="Possible web shell command execution",
        mitre_id="T1505.003",
        mitre_name="Server Software Component: Web Shell",
        tactic="Persistence",
        recommendation="Isolate the host, preserve the file for analysis, remove it, and audit "
                       "how it was uploaded. Disable script execution in upload directories.",
    ),
]}
