from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


# Weights used to rank source IPs; a single critical finding should outrank
# a handful of medium ones.
RISK_WEIGHT = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 5,
    Severity.CRITICAL: 10,
}


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    action: str  # ssh_failed | ssh_accepted | sudo
    host: str
    user: str
    src_ip: str | None = None
    method: str | None = None
    target_user: str | None = None
    command: str | None = None
    source: str = ""
    line_no: int = 0
    raw: str = ""

    @property
    def ref(self) -> str:
        return f"{self.source}:{self.line_no}"


@dataclass(frozen=True)
class WebEvent:
    timestamp: datetime
    src_ip: str
    method: str
    path: str
    status: int
    size: int
    user_agent: str
    source: str = ""
    line_no: int = 0
    raw: str = ""

    @property
    def ref(self) -> str:
        return f"{self.source}:{self.line_no}"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    mitre_id: str
    mitre_name: str
    tactic: str
    recommendation: str

    @property
    def mitre_url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.mitre_id.replace(".", "/") + "/"


@dataclass
class Finding:
    rule: Rule
    severity: Severity
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    detail: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity.name,
            "src_ip": self.src_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "count": self.count,
            "detail": self.detail,
            "mitre": {
                "id": self.rule.mitre_id,
                "name": self.rule.mitre_name,
                "tactic": self.rule.tactic,
                "url": self.rule.mitre_url,
            },
            "recommendation": self.rule.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class SourceStats:
    path: str
    kind: str  # auth | web
    lines: int = 0
    parsed: int = 0

    @property
    def skipped(self) -> int:
        return self.lines - self.parsed
