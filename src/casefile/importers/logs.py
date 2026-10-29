"""Line-oriented log importer: syslog, ISO-8601-prefixed and Apache/nginx access logs.

Every non-empty line becomes one observation, numbered in order (``seq``); the original
line number is kept in the data. Lines whose time cannot be read are kept without one.
Syslog lines carry no year or zone, so the year is supplied (default: the current year)
and times are taken as UTC; observations from such lines say so.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from ..model import ObservationDraft
from .errors import ImportFailure

MAX_LINES = 500_000
MAX_SUMMARY = 1000

_MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_MONTHS = {name: number for number, name in enumerate(_MONTH_NAMES, 1)}
_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<prog>[\w./@-]+)(?:\[\d+\])?:\s"
)
_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<rest>.*)$"
)
_CLF = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ \[(?P<ts>\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4})\]"
)


class LogError(ImportFailure):
    pass


def _us(moment: datetime) -> int:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return int(moment.timestamp() * 1_000_000)


def parse_log(content: bytes, *, year: int | None = None) -> list[ObservationDraft]:
    if b"\x00" in content:
        raise LogError("this looks like a binary file, not a text log")
    assumed_year = year if year is not None else datetime.now(UTC).year
    drafts: list[ObservationDraft] = []
    for number, raw in enumerate(content.decode("utf-8", errors="replace").splitlines(), 1):
        line = raw.rstrip()
        if not line.strip():
            continue
        if len(drafts) >= MAX_LINES:
            raise LogError(f"more than {MAX_LINES} lines; split the log and import the parts")
        ts, subject, data = _read(line, assumed_year)
        data["line"] = number
        summary = line if len(line) <= MAX_SUMMARY else line[:MAX_SUMMARY] + "…"
        drafts.append(ObservationDraft("log", subject, summary, ts, data))
    if not drafts:
        raise LogError("the log has no lines")
    return drafts


def _read(line: str, year: int) -> tuple[int | None, str, dict[str, object]]:
    match = _SYSLOG.match(line)
    if match and match["mon"] in _MONTHS:
        try:
            moment = datetime.strptime(
                f"{year} {_MONTHS[match['mon']]} {match['day']} {match['time']}",
                "%Y %m %d %H:%M:%S",
            )
        except ValueError:
            return None, f"{match['host']} {match['prog']}", {}
        return (
            _us(moment),
            f"{match['host']} {match['prog']}",
            {"format": "syslog", "year_assumed": year, "zone_assumed": "UTC"},
        )
    match = _CLF.match(line)
    if match:
        try:
            moment = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None, match["ip"], {"format": "access"}
        return _us(moment), match["ip"], {"format": "access"}
    match = _ISO.match(line)
    if match:
        text = match["ts"].replace(" ", "T").replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None, "log", {"format": "iso"}
        return _us(moment), "log", {"format": "iso"}
    return None, "log", {}
