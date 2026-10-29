"""Evidence importers. Each turns raw bytes into observations and never trusts its input."""

from __future__ import annotations

from ..model import KIND_LOG, KIND_NMAP, ObservationDraft
from .errors import ImportFailure
from .logs import parse_log
from .nmap import parse_nmap_xml

__all__ = ["ImportFailure", "parse", "parse_log", "parse_nmap_xml"]


def parse(kind: str, content: bytes, *, year: int | None = None) -> list[ObservationDraft]:
    if kind == KIND_NMAP:
        return parse_nmap_xml(content)
    if kind == KIND_LOG:
        return parse_log(content, year=year)
    raise ImportFailure(f"unknown evidence kind {kind!r}")
