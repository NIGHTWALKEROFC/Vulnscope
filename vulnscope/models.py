import hashlib
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}
STATUSES = ("confirmed", "potential", "version_match", "informational")
CONFIDENCES = ("high", "medium", "low")


@dataclass
class Target:
    kind: str
    value: str
    host: str = ""
    port: Optional[int] = None
    scheme: str = ""


@dataclass
class Finding:
    title: str
    severity: str
    status: str
    target: str
    source: str
    category: str
    confidence: str = "medium"
    rule_id: str = ""
    rule_basis: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cve: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cvss_version: str = ""
    location: str = ""
    notes: str = ""
    known_exploited: bool = False
    timestamp: float = field(default_factory=time.time)
    fingerprint: str = ""

    def __post_init__(self):
        if self.severity not in SEVERITIES:
            self.severity = "unknown"
        if self.status not in STATUSES:
            self.status = "potential"
        if self.confidence not in CONFIDENCES:
            self.confidence = "medium"
        if not self.fingerprint:
            raw = "|".join([self.rule_id or self.title, self.target, self.location, ",".join(sorted(self.cve))])
            self.fingerprint = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:24]

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


def severity_counts(findings):
    counts = {name: 0 for name in SEVERITIES}
    for item in findings:
        sev = item.severity if isinstance(item, Finding) else item.get("severity", "unknown")
        counts[sev if sev in counts else "unknown"] += 1
    return counts
