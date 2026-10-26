"""Render scan results as terminal text, JSON, or Markdown."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from . import __version__
from .models import RISK_WEIGHT, Finding, Severity, SourceStats

_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


@dataclass
class IpProfile:
    ip: str
    score: int
    rules: list[str]
    tactics: list[str]
    first_seen: datetime
    last_seen: datetime


def ip_profiles(findings: list[Finding]) -> list[IpProfile]:
    """Aggregate findings per source IP so one attacker's activity across logs reads as one story."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.src_ip].append(f)
    profiles = [
        IpProfile(
            ip=ip,
            score=sum(RISK_WEIGHT[f.severity] for f in fs),
            rules=sorted({f.rule.id for f in fs}),
            tactics=list(dict.fromkeys(f.rule.tactic for f in sorted(fs, key=lambda f: f.first_seen))),
            first_seen=min(f.first_seen for f in fs),
            last_seen=max(f.last_seen for f in fs),
        )
        for ip, fs in grouped.items()
    ]
    return sorted(profiles, key=lambda p: (-p.score, p.first_seen))


def _counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = {s: 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        counts[f.severity] += 1
    return counts


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


def render_text(findings: list[Finding], sources: list[SourceStats], color: bool = True) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines = [c(_BOLD, f"LogSentry {__version__} scan report"), ""]
    for s in sources:
        lines.append(f"  {s.kind:<4} {s.path}  {s.lines:,} lines, {s.parsed:,} parsed events")
    counts = _counts(findings)
    lines += ["", "  Findings: " + ", ".join(f"{n} {s.name.lower()}" for s, n in counts.items()), ""]

    if not findings:
        lines.append("  No suspicious activity matched the detection rules.")
        return "\n".join(lines) + "\n"

    for f in findings:
        tag = c(_COLORS[f.severity], f" {f.severity.name} ")
        lines.append(f"{tag} {c(_BOLD, f.rule.id)}  {f.rule.title}")
        lines.append(f"  Source IP   {f.src_ip}")
        lines.append(f"  When        {_ts(f.first_seen)}" +
                     (f"  ->  {_ts(f.last_seen)}" if f.last_seen != f.first_seen else ""))
        lines.append(f"  MITRE       {f.rule.mitre_id} {f.rule.mitre_name} ({f.rule.tactic})")
        lines.append(f"  Detail      {f.detail}")
        lines.append(f"  Respond     {f.rule.recommendation}")
        lines.append("  Evidence")
        lines += [c(_DIM, f"    {e}") for e in f.evidence]
        lines.append("")

    lines.append(c(_BOLD, "Source IPs ranked by risk"))
    for p in ip_profiles(findings):
        lines.append(f"  {p.ip:<18} score {p.score:>3}   {' > '.join(p.tactics)}   [{', '.join(p.rules)}]")
    return "\n".join(lines) + "\n"


def render_json(findings: list[Finding], sources: list[SourceStats]) -> str:
    doc = {
        "tool": "logsentry",
        "version": __version__,
        "sources": [
            {"path": s.path, "kind": s.kind, "lines": s.lines, "parsed_events": s.parsed}
            for s in sources
        ],
        "summary": {s.name.lower(): n for s, n in _counts(findings).items()},
        "findings": [f.to_dict() for f in findings],
        "ip_ranking": [
            {"ip": p.ip, "score": p.score, "rules": p.rules, "tactics": p.tactics,
             "first_seen": p.first_seen.isoformat(), "last_seen": p.last_seen.isoformat()}
            for p in ip_profiles(findings)
        ],
    }
    return json.dumps(doc, indent=2) + "\n"


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|")


def render_markdown(findings: list[Finding], sources: list[SourceStats]) -> str:
    out = ["# LogSentry incident report", ""]
    out += ["| Log | Lines | Parsed events |", "|---|---:|---:|"]
    out += [f"| `{s.path}` ({s.kind}) | {s.lines:,} | {s.parsed:,} |" for s in sources]
    out += ["", "## Summary", "", "| Severity | Findings |", "|---|---:|"]
    out += [f"| {s.name.title()} | {n} |" for s, n in _counts(findings).items()]

    if not findings:
        out += ["", "No suspicious activity matched the detection rules."]
        return "\n".join(out) + "\n"

    out += ["", "## Source IPs ranked by risk", "",
            "| IP | Score | Kill chain (tactics in order seen) | Rules |", "|---|---:|---|---|"]
    out += [f"| `{p.ip}` | {p.score} | {' → '.join(p.tactics)} | {', '.join(p.rules)} |"
            for p in ip_profiles(findings)]

    out += ["", "## Findings", ""]
    for n, f in enumerate(findings, start=1):
        out += [
            f"### {n}. [{f.severity.name}] {f.rule.id}: {f.rule.title}",
            "",
            f"- **Source IP:** `{f.src_ip}`",
            f"- **When:** {_ts(f.first_seen)}" + (f" to {_ts(f.last_seen)}" if f.last_seen != f.first_seen else ""),
            f"- **MITRE ATT&CK:** [{f.rule.mitre_id} {f.rule.mitre_name}]({f.rule.mitre_url}) ({f.rule.tactic})",
            f"- **Detail:** {_md_escape(f.detail)}",
            f"- **Response:** {f.rule.recommendation}",
            "",
            "```text",
            *f.evidence,
            "```",
            "",
        ]
    return "\n".join(out)
