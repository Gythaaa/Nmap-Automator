"""Typed security findings shared by the analyzer and report generator."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FindingReference:
    """A source that supports or contextualizes a finding."""

    title: str
    url: str
    source: str


@dataclass
class SecurityFinding:
    """A vulnerability candidate, verified NSE result, or exposure observation.

    NVD product/version matches are always represented as ``candidate`` because
    a network banner cannot prove that a vulnerable code path is reachable or
    that a vendor backport is absent.
    """

    finding_id: str
    title: str
    status: str
    severity: str
    confidence: str
    host_ip: str
    hostname: str
    port: int
    protocol: str
    service: str
    product: str
    version: str
    evidence: str
    impact: str
    remediation: str
    source: str
    cve_id: Optional[str] = None
    cwe_ids: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cpe: Optional[str] = None
    kev: bool = False
    references: list[FindingReference] = field(default_factory=list)
    ai_generated: bool = False
    ai_provider: str = ""
    ai_summary: str = ""
    ai_confidence: Optional[float] = None
