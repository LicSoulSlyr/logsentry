"""Parsers for Linux auth logs (sshd, sudo) and web access logs (Apache/Nginx combined)."""

from __future__ import annotations

import gzip
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import AuthEvent, SourceStats, WebEvent

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

_IP = r"[0-9a-fA-F:.]+"

# Classic syslog: "Oct 26 03:14:07 web01 sshd[1234]: message"
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
# RFC 3339 syslog (rsyslog default on newer distros): "2026-10-26T03:14:07.123+00:00 web01 sshd[1234]: message"
_ISO_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w\-/.]+)(?:\[\d+\])?:\s+(?P<msg>.*)$"
)
_SSH_FAILED = re.compile(
    rf"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S*) from (?P<ip>{_IP}) port \d+"
)
_SSH_ACCEPTED = re.compile(
    rf"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>{_IP}) port \d+"
)
_SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.+)$")

_COMBINED = re.compile(
    rf'^(?P<ip>{_IP}) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "[^"]*" "(?P<ua>[^"]*)")?'
)
# "26/Oct/2026:03:15:01 +0000"
_CLF_TS = re.compile(
    r"(?P<day>\d{2})/(?P<mon>[A-Z][a-z]{2})/(?P<year>\d{4}):(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) "
    r"(?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})"
)


def open_log(path: str | Path):
    path = Path(path)
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _syslog_time(mon: str, day: str, clock: str, year: int) -> datetime:
    # Classic syslog has no year or zone; the caller supplies the year and we assume UTC.
    h, m, s = (int(x) for x in clock.split(":"))
    return datetime(year, _MONTHS[mon], int(day), h, m, s, tzinfo=timezone.utc)


def _clf_time(value: str) -> datetime | None:
    m = _CLF_TS.match(value)
    if not m or m["mon"] not in _MONTHS:
        return None
    offset = timedelta(hours=int(m["oh"]), minutes=int(m["om"]))
    if m["sign"] == "-":
        offset = -offset
    local = datetime(int(m["year"]), _MONTHS[m["mon"]], int(m["day"]),
                     int(m["h"]), int(m["m"]), int(m["s"]), tzinfo=timezone(offset))
    return local.astimezone(timezone.utc)


def parse_auth_line(line: str, year: int, source: str = "", line_no: int = 0) -> AuthEvent | None:
    line = line.rstrip("\n")
    if m := _SYSLOG.match(line):
        if m["mon"] not in _MONTHS:
            return None
        ts = _syslog_time(m["mon"], m["day"], m["time"], year)
    elif m := _ISO_SYSLOG.match(line):
        ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00")).astimezone(timezone.utc)
    else:
        return None

    proc, msg, host = m["proc"], m["msg"], m["host"]
    common = dict(timestamp=ts, host=host, source=source, line_no=line_no, raw=line)

    if proc == "sshd":
        if f := _SSH_FAILED.search(msg):
            return AuthEvent(action="ssh_failed", user=f["user"] or "<empty>",
                             src_ip=f["ip"], method=f["method"], **common)
        if a := _SSH_ACCEPTED.search(msg):
            return AuthEvent(action="ssh_accepted", user=a["user"],
                             src_ip=a["ip"], method=a["method"], **common)
    elif proc == "sudo":
        if s := _SUDO.match(msg):
            return AuthEvent(action="sudo", user=s["user"], target_user=s["target"],
                             command=s["cmd"].strip(), **common)
    return None


def parse_web_line(line: str, source: str = "", line_no: int = 0) -> WebEvent | None:
    line = line.rstrip("\n")
    m = _COMBINED.match(line)
    if not m:
        return None
    ts = _clf_time(m["ts"])
    if ts is None:
        return None

    parts = m["request"].split(" ")
    if len(parts) == 3:
        method, path = parts[0], parts[1]
    else:
        # Malformed or binary request lines (common from scanners); keep the raw text as the path.
        method, path = "", m["request"]

    return WebEvent(
        timestamp=ts,
        src_ip=m["ip"],
        method=method,
        path=path,
        status=int(m["status"]),
        size=0 if m["size"] == "-" else int(m["size"]),
        user_agent=m["ua"] or "",
        source=source,
        line_no=line_no,
        raw=line,
    )


def read_auth_log(path: str | Path, year: int) -> tuple[list[AuthEvent], SourceStats]:
    stats = SourceStats(path=str(path), kind="auth")
    events: list[AuthEvent] = []
    name = Path(path).name
    with open_log(path) as fh:
        for no, line in enumerate(fh, start=1):
            stats.lines += 1
            if ev := parse_auth_line(line, year, name, no):
                events.append(ev)
    stats.parsed = len(events)
    return _sorted(events), stats


def read_web_log(path: str | Path) -> tuple[list[WebEvent], SourceStats]:
    stats = SourceStats(path=str(path), kind="web")
    events: list[WebEvent] = []
    name = Path(path).name
    with open_log(path) as fh:
        for no, line in enumerate(fh, start=1):
            stats.lines += 1
            if ev := parse_web_line(line, name, no):
                events.append(ev)
    stats.parsed = len(events)
    return _sorted(events), stats


def _sorted(events: list) -> list:
    return sorted(events, key=lambda e: (e.timestamp, e.line_no))
