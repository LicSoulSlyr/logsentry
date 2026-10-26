"""Detection logic. Each detector takes parsed events and returns findings grouped by source IP."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable, Sequence
from urllib.parse import unquote_plus

from .models import AuthEvent, Finding, Severity, WebEvent
from .rules import RULES


@dataclass(frozen=True)
class Config:
    bruteforce_threshold: int = 10
    bruteforce_window: timedelta = timedelta(minutes=5)
    spray_min_users: int = 5
    enum_404_threshold: int = 20
    enum_window: timedelta = timedelta(minutes=1)
    max_evidence: int = 5


# ---------------------------------------------------------------- helpers

def _max_in_window(times: Sequence[datetime], window: timedelta) -> tuple[int, int, int]:
    """Largest number of sorted timestamps that fit in `window`, with start/end indexes."""
    best = (0, 0, 0)
    start = 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        count = end - start + 1
        if count > best[0]:
            best = (count, start, end)
    return best


def _evidence(events: Iterable[AuthEvent | WebEvent], limit: int) -> list[str]:
    out = []
    for ev in events:
        if len(out) == limit:
            break
        raw = ev.raw if len(ev.raw) <= 220 else ev.raw[:217] + "..."
        out.append(f"{ev.ref}  {raw}")
    return out


def _by_ip(events: Iterable[AuthEvent | WebEvent]) -> dict[str, list]:
    groups: dict[str, list] = defaultdict(list)
    for ev in events:
        groups[ev.src_ip].append(ev)
    return groups


def _decode(path: str) -> str:
    # Attackers double-encode payloads (%252e%252e) to slip past naive filters.
    return unquote_plus(unquote_plus(path)).lower()


def _sample(values: Iterable[str], limit: int = 3) -> str:
    seen = list(dict.fromkeys(values))
    shown = ", ".join(seen[:limit])
    return shown + (f" (+{len(seen) - limit} more)" if len(seen) > limit else "")


# ---------------------------------------------------------------- SSH / auth

def detect_ssh_bruteforce(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    failures = _by_ip(e for e in auth if e.action == "ssh_failed")
    for ip, evs in failures.items():
        peak, i, j = _max_in_window([e.timestamp for e in evs], cfg.bruteforce_window)
        if peak < cfg.bruteforce_threshold:
            continue
        minutes = int(cfg.bruteforce_window.total_seconds() // 60)
        users = {e.user for e in evs}
        findings.append(Finding(
            rule=RULES["SSH-001"],
            severity=Severity.HIGH,
            src_ip=ip,
            first_seen=evs[0].timestamp,
            last_seen=evs[-1].timestamp,
            count=len(evs),
            detail=f"Peak of {peak} failed logins in {minutes} min "
                   f"({evs[i].timestamp:%H:%M:%S} to {evs[j].timestamp:%H:%M:%S}); "
                   f"{len(evs)} failures in total against {len(users)} account(s).",
            evidence=_evidence(evs[i:j + 1], cfg.max_evidence),
        ))
    return findings


def detect_ssh_spraying(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    failures = _by_ip(e for e in auth if e.action == "ssh_failed")
    for ip, evs in failures.items():
        users = list(dict.fromkeys(e.user for e in evs))
        if len(users) < cfg.spray_min_users:
            continue
        # One evidence line per distinct account shows the spray pattern better than repeats.
        firsts = {}
        for e in evs:
            firsts.setdefault(e.user, e)
        findings.append(Finding(
            rule=RULES["SSH-002"],
            severity=Severity.HIGH,
            src_ip=ip,
            first_seen=evs[0].timestamp,
            last_seen=evs[-1].timestamp,
            count=len(evs),
            detail=f"{len(users)} distinct accounts tried: {_sample(users, 6)}.",
            evidence=_evidence(firsts.values(), cfg.max_evidence),
        ))
    return findings


def compromised_logins(auth: list[AuthEvent], cfg: Config) -> list[tuple[AuthEvent, int]]:
    """Accepted logins from an IP that had at least `bruteforce_threshold` failures before it."""
    failed_so_far: dict[str, int] = defaultdict(int)
    hits = []
    for e in auth:
        if e.action == "ssh_failed":
            failed_so_far[e.src_ip] += 1
        elif e.action == "ssh_accepted" and failed_so_far[e.src_ip] >= cfg.bruteforce_threshold:
            hits.append((e, failed_so_far[e.src_ip]))
    return hits


def detect_login_after_bruteforce(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    for login, prior in compromised_logins(auth, cfg):
        last_fail = next(
            (e for e in reversed(auth)
             if e.action == "ssh_failed" and e.src_ip == login.src_ip and e.timestamp <= login.timestamp),
            None,
        )
        findings.append(Finding(
            rule=RULES["SSH-003"],
            severity=Severity.CRITICAL,
            src_ip=login.src_ip,
            first_seen=login.timestamp,
            last_seen=login.timestamp,
            count=1,
            detail=f"Account '{login.user}' logged in via {login.method} on {login.host} "
                   f"after {prior} failed attempts from the same IP.",
            evidence=_evidence([ev for ev in (last_fail, login) if ev], cfg.max_evidence),
        ))
    return findings


_SHELLS = re.compile(r"^(/usr)?/bin/(ba|z|da|k|c)?sh\b|^(/usr)?/bin/su\b")


def detect_sudo_root_shell(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    compromised = {(login.user, login.host): login for login, _ in compromised_logins(auth, cfg)}
    findings = []
    for e in auth:
        if e.action != "sudo" or e.target_user != "root" or not _SHELLS.search(e.command or ""):
            continue
        login = compromised.get((e.user, e.host))
        if login and login.timestamp <= e.timestamp:
            severity = Severity.CRITICAL
            src_ip = login.src_ip
            detail = (f"'{e.user}' opened a root shell ({e.command}) on {e.host}, "
                      f"{_human(e.timestamp - login.timestamp)} after a brute-forced login from {login.src_ip}.")
            evidence = _evidence([login, e], cfg.max_evidence)
        else:
            severity = Severity.MEDIUM
            src_ip = f"local:{e.host}"
            detail = f"'{e.user}' opened a root shell ({e.command}) on {e.host}."
            evidence = _evidence([e], cfg.max_evidence)
        findings.append(Finding(
            rule=RULES["AUTH-004"], severity=severity, src_ip=src_ip,
            first_seen=e.timestamp, last_seen=e.timestamp, count=1,
            detail=detail, evidence=evidence,
        ))
    return findings


def _human(delta: timedelta) -> str:
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    return f"{secs // 3600}h {secs % 3600 // 60}m"


# ---------------------------------------------------------------- web

_SQLI = [re.compile(p) for p in (
    r"union(\s|/\*.*?\*/)+(all(\s|/\*.*?\*/)+)?select",
    r"'\s*(or|and)\s+'?[\w-]+'?\s*(=|like)\s*'?[\w-]+",
    r"\s(or|and)\s+(\d+)\s*=\s*\2\b",
    r"\b(sleep|benchmark|pg_sleep)\s*\(",
    r"\bwaitfor\s+delay\b",
    r"information_schema",
    r"(;|')\s*(drop|insert|update|delete)\s+",
    r"\bextractvalue\s*\(|\bupdatexml\s*\(",
)]
_XSS = [re.compile(p) for p in (
    r"<\s*script",
    r"javascript\s*:",
    r"<\s*(img|svg|iframe|body)[^>]*\bon[a-z]+\s*=",
    r"\bon(error|load|mouseover|focus)\s*=",
    r"document\.cookie",
)]
_TRAVERSAL = [re.compile(p) for p in (
    r"\.\./|\.\.\\",
    r"/etc/(passwd|shadow|hosts)\b",
    r"\b(boot|win)\.ini\b",
    r"php://(filter|input)",
    r"/proc/self/environ",
)]
_SENSITIVE = re.compile(
    r"/\.env(\.|$|\?)|/\.git(/|$)|/\.svn/|/\.htpasswd|/\.aws/|/\.ds_store"
    r"|/wp-config\.php\.(bak|old|save|swp)|/config\.php\.(bak|old)"
    r"|/[\w-]*backup[\w-]*\.(zip|tar|tar\.gz|tgz|sql|gz)$|/[\w-]+\.sql$"
    r"|/phpinfo\.php|/server-status|/actuator/(env|heapdump)"
)
_SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|gobuster|dirbuster|\bdirb\b|wpscan|nuclei|zgrab|feroxbuster"
    r"|\bffuf\b|acunetix|nessus|openvas|whatweb|wfuzz|hydra",
    re.IGNORECASE,
)
_WEBSHELL = re.compile(r"\.(php\d?|phtml|jspx?|aspx?)\?(.*&)?(cmd|exec|command|shell)=", re.IGNORECASE)


def _matching(web: list[WebEvent], predicate: Callable[[WebEvent], bool]) -> dict[str, list[WebEvent]]:
    return _by_ip(e for e in web if predicate(e))


def _status_summary(evs: list[WebEvent]) -> str:
    counts: dict[int, int] = defaultdict(int)
    for e in evs:
        counts[e.status] += 1
    return ", ".join(f"{code} x{n}" for code, n in sorted(counts.items()))


def _web_finding(rule_id: str, ip: str, evs: list[WebEvent], severity: Severity,
                 detail: str, cfg: Config) -> Finding:
    return Finding(
        rule=RULES[rule_id], severity=severity, src_ip=ip,
        first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, count=len(evs),
        detail=detail, evidence=_evidence(evs, cfg.max_evidence),
    )


def _pattern_detector(rule_id: str, patterns: list[re.Pattern],
                      severity_for: Callable[[list[WebEvent]], Severity], label: str):
    def detect(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
        # Web shell commands often contain these payloads (cat /etc/passwd); WEB-007 owns those requests.
        hits = _matching(web, lambda e: not _WEBSHELL.search(e.path)
                         and any(p.search(_decode(e.path)) for p in patterns))
        return [
            _web_finding(
                rule_id, ip, evs, severity_for(evs),
                f"{len(evs)} {label} request(s) to {_sample(e.path.split('?')[0] for e in evs)}. "
                f"Responses: {_status_summary(evs)}.",
                cfg,
            )
            for ip, evs in hits.items()
        ]
    detect.__name__ = f"detect_{rule_id.lower().replace('-', '_')}"
    return detect


def _any_status(evs: list[WebEvent], check: Callable[[int], bool]) -> bool:
    return any(check(e.status) for e in evs)


detect_sqli = _pattern_detector(
    "WEB-001", _SQLI,
    lambda evs: Severity.HIGH if _any_status(evs, lambda s: s >= 500) else Severity.MEDIUM,
    "SQL injection",
)
detect_xss = _pattern_detector("WEB-002", _XSS, lambda evs: Severity.MEDIUM, "XSS")
detect_traversal = _pattern_detector(
    "WEB-003", _TRAVERSAL,
    lambda evs: Severity.HIGH if _any_status(evs, lambda s: s == 200) else Severity.MEDIUM,
    "path traversal",
)


def detect_sensitive_files(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    for ip, evs in _matching(web, lambda e: bool(_SENSITIVE.search(_decode(e.path).split("?")[0]))).items():
        exposed = [e.path for e in evs if e.status == 200]
        if exposed:
            severity = Severity.HIGH
            detail = (f"{len(evs)} probe(s) for sensitive files; served with 200: {_sample(exposed)}. "
                      f"Responses: {_status_summary(evs)}.")
        else:
            severity = Severity.LOW
            detail = (f"{len(evs)} probe(s) for sensitive files ({_sample(e.path for e in evs)}), "
                      f"none served. Responses: {_status_summary(evs)}.")
        findings.append(_web_finding("WEB-004", ip, evs, severity, detail, cfg))
    return findings


def detect_scanner_user_agent(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    for ip, evs in _matching(web, lambda e: bool(_SCANNER_UA.search(e.user_agent))).items():
        tools = _sample(_SCANNER_UA.search(e.user_agent).group(0).lower() for e in evs)
        findings.append(_web_finding(
            "WEB-005", ip, evs, Severity.MEDIUM,
            f"{len(evs)} request(s) identifying as: {tools}.", cfg,
        ))
    return findings


def detect_directory_enumeration(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    for ip, evs in _matching(web, lambda e: e.status == 404).items():
        peak, i, j = _max_in_window([e.timestamp for e in evs], cfg.enum_window)
        if peak < cfg.enum_404_threshold:
            continue
        secs = int(cfg.enum_window.total_seconds())
        findings.append(Finding(
            rule=RULES["WEB-006"], severity=Severity.MEDIUM, src_ip=ip,
            first_seen=evs[0].timestamp, last_seen=evs[-1].timestamp, count=len(evs),
            detail=f"Peak of {peak} 404 responses in {secs}s; {len(evs)} in total.",
            evidence=_evidence(evs[i:j + 1], cfg.max_evidence),
        ))
    return findings


def detect_webshell(auth: list[AuthEvent], web: list[WebEvent], cfg: Config) -> list[Finding]:
    findings = []
    for ip, evs in _matching(web, lambda e: bool(_WEBSHELL.search(e.path))).items():
        ok = [e for e in evs if 200 <= e.status < 300]
        if ok:
            severity = Severity.CRITICAL
            detail = (f"{len(ok)} command request(s) answered with 2xx by "
                      f"{_sample(e.path.split('?')[0] for e in ok)}; commands: "
                      f"{_sample((_decode(e.path).split('=', 1)[-1] for e in ok), 4)}.")
        else:
            severity = Severity.MEDIUM
            detail = f"{len(evs)} web shell style request(s), none succeeded. Responses: {_status_summary(evs)}."
        findings.append(_web_finding("WEB-007", ip, ok or evs, severity, detail, cfg))
    return findings


DETECTORS = [
    detect_ssh_bruteforce,
    detect_ssh_spraying,
    detect_login_after_bruteforce,
    detect_sudo_root_shell,
    detect_sqli,
    detect_xss,
    detect_traversal,
    detect_sensitive_files,
    detect_scanner_user_agent,
    detect_directory_enumeration,
    detect_webshell,
]


def run_all(auth: list[AuthEvent], web: list[WebEvent], cfg: Config | None = None) -> list[Finding]:
    cfg = cfg or Config()
    findings = [f for detector in DETECTORS for f in detector(auth, web, cfg)]
    return sorted(findings, key=lambda f: (-f.severity, f.first_seen, f.rule.id))
