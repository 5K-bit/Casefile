"""Plain data types and vocabulary shared across Casefile."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

# A finding is a claim. Its status says how far the evidence has taken it.
STATUS_HYPOTHESIS = "hypothesis"
STATUS_SUPPORTED = "supported"
STATUS_REFUTED = "refuted"
STATUS_INCONCLUSIVE = "inconclusive"
STATUSES = (STATUS_HYPOTHESIS, STATUS_SUPPORTED, STATUS_REFUTED, STATUS_INCONCLUSIVE)

# How a piece of evidence relates to a finding.
ROLE_SUPPORTS = "supports"
ROLE_CONTRADICTS = "contradicts"
ROLE_CONTEXT = "context"
ROLES = (ROLE_SUPPORTS, ROLE_CONTRADICTS, ROLE_CONTEXT)

KIND_NMAP = "nmap"
KIND_LOG = "log"
EVIDENCE_KINDS = (KIND_NMAP, KIND_LOG)


@dataclass(frozen=True)
class ObservationDraft:
    """One parsed fact from an evidence file, before it is stored."""

    kind: str
    subject: str
    summary: str
    ts_us: int | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Evidence:
    id: int
    label: str
    kind: str
    filename: str
    sha256: str
    size: int
    imported_us: int
    note: str


@dataclass(frozen=True)
class Observation:
    id: int
    evidence_id: int
    seq: int
    kind: str
    subject: str
    summary: str
    ts_us: int | None
    data: dict[str, Any]


@dataclass(frozen=True)
class Finding:
    id: int
    title: str
    statement: str
    severity: str
    status: str
    created_us: int
    updated_us: int


@dataclass(frozen=True)
class Link:
    id: int
    finding_id: int
    evidence_id: int
    seq_from: int | None
    seq_to: int | None
    role: str
    note: str


@dataclass(frozen=True)
class Unknown:
    id: int
    finding_id: int | None
    text: str
    resolved: bool
    resolution: str
