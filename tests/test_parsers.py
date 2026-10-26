from datetime import datetime, timezone

from logsentry.parsers import parse_auth_line, parse_web_line


def utc(*args):
    return datetime(*args, tzinfo=timezone.utc)


class TestAuthParser:
    def test_failed_password(self):
        ev = parse_auth_line(
            "Oct 24 03:30:08 web01 sshd[5422]: Failed password for root from 198.51.100.23 port 45996 ssh2", 2026)
        assert ev.action == "ssh_failed"
        assert ev.user == "root"
        assert ev.src_ip == "198.51.100.23"
        assert ev.timestamp == utc(2026, 10, 24, 3, 30, 8)

    def test_failed_password_invalid_user(self):
        ev = parse_auth_line(
            "Oct 24 04:00:37 web01 sshd[1]: Failed password for invalid user admin from 192.0.2.77 port 1 ssh2", 2026)
        assert ev.action == "ssh_failed"
        assert ev.user == "admin"

    def test_single_digit_day_is_space_padded(self):
        ev = parse_auth_line(
            "Oct  4 09:00:00 web01 sshd[1]: Failed password for bob from 10.0.0.15 port 22 ssh2", 2026)
        assert ev.timestamp == utc(2026, 10, 4, 9, 0, 0)

    def test_accepted_publickey(self):
        ev = parse_auth_line(
            "Oct 24 09:12:44 web01 sshd[1]: Accepted publickey for alice from 10.0.0.12 port 50000 ssh2", 2026)
        assert ev.action == "ssh_accepted"
        assert ev.method == "publickey"
        assert ev.user == "alice"

    def test_iso_timestamp_with_offset_is_converted_to_utc(self):
        ev = parse_auth_line(
            "2026-10-24T05:30:08.123456+02:00 web01 sshd[9]: Failed password for root from 203.0.113.9 port 1 ssh2",
            1999)
        assert ev.timestamp == utc(2026, 10, 24, 3, 30, 8, 123456)

    def test_ipv6_source(self):
        ev = parse_auth_line(
            "Oct 24 03:30:08 web01 sshd[1]: Failed password for root from 2001:db8::5 port 4 ssh2", 2026)
        assert ev.src_ip == "2001:db8::5"

    def test_sudo(self):
        ev = parse_auth_line(
            "Oct 24 03:38:36 web01 sudo:    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
            2026)
        assert ev.action == "sudo"
        assert ev.user == "deploy"
        assert ev.target_user == "root"
        assert ev.command == "/bin/bash"

    def test_irrelevant_lines_are_ignored(self):
        assert parse_auth_line(
            "Oct 24 00:10:00 web01 CRON[2]: pam_unix(cron:session): session opened for user root", 2026) is None
        assert parse_auth_line("garbage that is not syslog", 2026) is None
        assert parse_auth_line("", 2026) is None


class TestWebParser:
    LINE = ('203.0.113.45 - - [24/Oct/2026:02:25:13 +0000] "GET /products.php?id=12 HTTP/1.1" 200 4410 '
            '"-" "sqlmap/1.8.9#stable (https://sqlmap.org)"')

    def test_combined_format(self):
        ev = parse_web_line(self.LINE, "access.log", 7)
        assert ev.src_ip == "203.0.113.45"
        assert ev.method == "GET"
        assert ev.path == "/products.php?id=12"
        assert ev.status == 200
        assert ev.size == 4410
        assert ev.user_agent.startswith("sqlmap")
        assert ev.ref == "access.log:7"

    def test_timezone_offset_is_converted_to_utc(self):
        ev = parse_web_line('192.0.2.1 - - [24/Oct/2026:08:00:00 -0500] "GET / HTTP/1.1" 200 10 "-" "x"')
        assert ev.timestamp == utc(2026, 10, 24, 13, 0, 0)

    def test_common_log_format_without_user_agent(self):
        ev = parse_web_line('192.0.2.1 - frank [24/Oct/2026:08:00:00 +0000] "GET /a HTTP/1.0" 404 -')
        assert ev.status == 404
        assert ev.size == 0
        assert ev.user_agent == ""

    def test_malformed_request_line_keeps_raw_text(self):
        ev = parse_web_line('192.0.2.1 - - [24/Oct/2026:08:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
        assert ev.method == ""
        assert ev.status == 400

    def test_garbage_is_ignored(self):
        assert parse_web_line("not a log line") is None
