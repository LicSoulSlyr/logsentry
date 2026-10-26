from datetime import datetime, timedelta, timezone

import pytest

from logsentry.detectors import Config, _max_in_window, run_all
from logsentry.models import AuthEvent, Severity, WebEvent

T0 = datetime(2026, 10, 24, 3, 0, 0, tzinfo=timezone.utc)
CFG = Config()


def fail(sec, user="root", ip="198.51.100.23"):
    return AuthEvent(timestamp=T0 + timedelta(seconds=sec), action="ssh_failed", host="web01",
                     user=user, src_ip=ip, method="password")


def accept(sec, user="deploy", ip="198.51.100.23"):
    return AuthEvent(timestamp=T0 + timedelta(seconds=sec), action="ssh_accepted", host="web01",
                     user=user, src_ip=ip, method="password")


def sudo(sec, user="deploy", command="/bin/bash"):
    return AuthEvent(timestamp=T0 + timedelta(seconds=sec), action="sudo", host="web01",
                     user=user, target_user="root", command=command)


def req(path, status=200, ip="203.0.113.45", ua="Mozilla/5.0", sec=0):
    return WebEvent(timestamp=T0 + timedelta(seconds=sec), src_ip=ip, method="GET", path=path,
                    status=status, size=100, user_agent=ua)


def rule_ids(findings):
    return sorted(f.rule.id for f in findings)


def test_max_in_window():
    times = [T0 + timedelta(seconds=s) for s in (0, 10, 20, 400, 401, 402, 403)]
    count, start, end = _max_in_window(times, timedelta(seconds=5))
    assert (count, start, end) == (4, 3, 6)


class TestSSH:
    def test_brute_force_detected(self):
        findings = run_all([fail(i * 3) for i in range(12)], [], CFG)
        assert rule_ids(findings) == ["SSH-001"]
        assert findings[0].count == 12

    def test_slow_failures_below_window_threshold_are_not_brute_force(self):
        # 12 failures spread over an hour never put 10 inside a 5 minute window.
        assert run_all([fail(i * 300) for i in range(12)], [], CFG) == []

    def test_a_few_typos_are_not_flagged(self):
        auth = [fail(0, "alice", "10.0.0.12"), fail(20, "alice", "10.0.0.12"), accept(40, "alice", "10.0.0.12")]
        assert run_all(auth, [], CFG) == []

    def test_password_spraying(self):
        users = ["admin", "test", "oracle", "git", "guest", "ubuntu"]
        findings = run_all([fail(i * 60, u, "192.0.2.77") for i, u in enumerate(users)], [], CFG)
        assert rule_ids(findings) == ["SSH-002"]

    def test_login_after_brute_force_is_critical(self):
        auth = [fail(i * 2, "deploy") for i in range(15)] + [accept(40)]
        findings = run_all(auth, [], CFG)
        assert rule_ids(findings) == ["SSH-001", "SSH-003"]
        assert findings[0].rule.id == "SSH-003"
        assert findings[0].severity is Severity.CRITICAL

    def test_login_from_a_different_ip_is_not_correlated(self):
        auth = [fail(i * 2) for i in range(15)] + [accept(40, ip="10.0.0.99")]
        assert rule_ids(run_all(auth, [], CFG)) == ["SSH-001"]

    def test_root_shell_after_compromise_is_critical_and_attributed(self):
        auth = [fail(i * 2, "deploy") for i in range(15)] + [accept(40), sudo(160)]
        shell = next(f for f in run_all(auth, [], CFG) if f.rule.id == "AUTH-004")
        assert shell.severity is Severity.CRITICAL
        assert shell.src_ip == "198.51.100.23"

    def test_root_shell_by_regular_admin_is_medium(self):
        findings = run_all([sudo(0, "alice")], [], CFG)
        assert rule_ids(findings) == ["AUTH-004"]
        assert findings[0].severity is Severity.MEDIUM

    @pytest.mark.parametrize("command", ["/usr/bin/systemctl restart nginx", "/usr/bin/apt update",
                                         "/usr/bin/bashtop"])
    def test_ordinary_sudo_commands_are_ignored(self, command):
        assert run_all([sudo(0, "alice", command)], [], CFG) == []


class TestWeb:
    @pytest.mark.parametrize("path", [
        "/products.php?id=12%20UNION%20ALL%20SELECT%20NULL,NULL--",
        "/products.php?id=12%27%20OR%20%271%27%3D%271",
        "/products.php?id=12+AND+1=1",
        "/item?id=1%20AND%20SLEEP(5)",
        "/item?id=1%2520UNION%2520SELECT%25201",  # double encoded
    ])
    def test_sql_injection(self, path):
        assert rule_ids(run_all([], [req(path)], CFG)) == ["WEB-001"]

    def test_sql_injection_with_server_error_is_high(self):
        findings = run_all([], [req("/p?id=1%27%20OR%20%27a%27%3D%27a", status=500)], CFG)
        assert findings[0].severity is Severity.HIGH

    @pytest.mark.parametrize("path", [
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/search?q=%22%3E%3Cimg%20src=x%20onerror=alert(1)%3E",
    ])
    def test_xss(self, path):
        assert rule_ids(run_all([], [req(path)], CFG)) == ["WEB-002"]

    @pytest.mark.parametrize("path", [
        "/download.php?file=../../../../etc/passwd",
        "/download.php?file=%2e%2e%2f%2e%2e%2fetc%2fshadow",
        "/view?page=php://filter/convert.base64-encode/resource=index.php",
    ])
    def test_path_traversal(self, path):
        assert rule_ids(run_all([], [req(path, status=403)], CFG)) == ["WEB-003"]

    def test_exposed_env_file_is_high(self):
        findings = run_all([], [req("/.env", status=200)], CFG)
        assert rule_ids(findings) == ["WEB-004"]
        assert findings[0].severity is Severity.HIGH

    def test_blocked_env_probe_is_low(self):
        assert run_all([], [req("/.env", status=404)], CFG)[0].severity is Severity.LOW

    def test_scanner_user_agent(self):
        findings = run_all([], [req("/", ua="Mozilla/5.00 (Nikto/2.5.0)")], CFG)
        assert rule_ids(findings) == ["WEB-005"]

    def test_directory_enumeration(self):
        web = [req(f"/word{i}", status=404, sec=i) for i in range(25)]
        assert rule_ids(run_all([], web, CFG)) == ["WEB-006"]

    def test_webshell_success_is_critical_and_not_double_counted(self):
        findings = run_all([], [req("/uploads/a.php?cmd=cat%20/etc/passwd")], CFG)
        assert rule_ids(findings) == ["WEB-007"]
        assert findings[0].severity is Severity.CRITICAL

    def test_webshell_attempt_that_fails_is_medium(self):
        assert run_all([], [req("/uploads/a.php?cmd=id", status=404)], CFG)[0].severity is Severity.MEDIUM

    @pytest.mark.parametrize("path", [
        "/", "/products.php?id=12", "/search?q=wireless+keyboard", "/search?q=rock+%26+roll",
        "/blog/where-or-when", "/index.php?c=home&m=index", "/static/app.js", "/environment",
        "/search?q=select+a+shirt", "/docs/union-select-guide",
    ])
    def test_normal_traffic_is_not_flagged(self, path):
        assert run_all([], [req(path)], CFG) == []


def test_findings_are_sorted_by_severity():
    auth = [fail(i * 2, "deploy") for i in range(15)] + [accept(40)]
    web = [req("/.env", status=404)]
    severities = [f.severity for f in run_all(auth, web, CFG)]
    assert severities == sorted(severities, reverse=True)
