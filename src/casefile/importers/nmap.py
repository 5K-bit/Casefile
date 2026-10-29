"""Nmap XML importer (``nmap -oX``).

The file is untrusted. Python's XML parser expands internal entities, which allows
"billion laughs" memory attacks, so any file that declares entities or an internal DTD
subset is refused. Real Nmap output only carries a bare ``<!DOCTYPE nmaprun>``.

The refusal is made by expat itself (declaration handlers that raise), not by matching
bytes: the same parser that would expand an entity decodes the document first, so
UTF-16 and other encodings, comments and odd whitespace cannot hide a declaration.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # noqa: N817, S405 - input is screened before parsing
from typing import Any, NoReturn
from xml.parsers import expat  # noqa: S407 - used only to screen, with every handler refusing

from ..model import ObservationDraft
from .errors import ImportFailure

MAX_OUTPUT_CHARS = 600


class NmapError(ImportFailure):
    pass


def _epoch_us(value: str | None) -> int | None:
    if value and value.isdigit():
        return int(value) * 1_000_000
    return None


class _Refused(Exception):  # noqa: N818 - internal signal, never escapes this module
    pass


def _screen(content: bytes) -> None:
    """Raise :class:`NmapError` if expat sees an entity, internal subset or external entity.

    Handlers fire at the declaration, before any reference could be expanded, and this pass
    builds no tree, so it is cheap and cannot itself be inflated.
    """

    def refuse(*_args: Any) -> NoReturn:
        raise _Refused

    def doctype(_name: Any, _sysid: Any, _pubid: Any, has_internal: Any) -> int:
        if has_internal:
            raise _Refused
        return 0

    parser = expat.ParserCreate()
    parser.EntityDeclHandler = refuse
    parser.StartDoctypeDeclHandler = doctype
    parser.ExternalEntityRefHandler = refuse
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(content, True)
    except _Refused:
        raise NmapError("refusing XML that declares entities or an internal DTD subset") from None
    except (expat.ExpatError, ValueError, LookupError) as exc:  # unusable encoding
        raise NmapError(f"not valid XML: {exc}") from exc


def _attr(node: ET.Element | None, name: str, default: str = "") -> str:
    return default if node is None else node.get(name, default)


def parse_nmap_xml(content: bytes) -> list[ObservationDraft]:
    _screen(content)
    try:
        root = ET.fromstring(content)  # noqa: S314 - screened above
    except (ET.ParseError, ValueError, LookupError) as exc:
        raise NmapError(f"not valid XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapError(f"not an Nmap XML file (root element is <{root.tag}>)")

    scan_ts = _epoch_us(root.get("start"))
    drafts: list[ObservationDraft] = [
        ObservationDraft(
            kind="scan",
            subject="nmap",
            summary=f"nmap {root.get('version', '?')}: {root.get('args', '')}".strip(),
            ts_us=scan_ts,
            data={"args": root.get("args", ""), "version": root.get("version", "")},
        )
    ]
    for host in root.findall("host"):
        ts = _epoch_us(host.get("starttime")) or scan_ts
        addr = next(
            (a.get("addr", "") for a in host.findall("address") if a.get("addrtype") != "mac"), ""
        )
        if not addr:
            continue
        names = [h.get("name", "") for h in host.findall("hostnames/hostname") if h.get("name")]
        state = _attr(host.find("status"), "state", "unknown")
        label = f" ({', '.join(names)})" if names else ""
        drafts.append(
            ObservationDraft(
                "host",
                addr,
                f"host {addr}{label} is {state}",
                ts,
                {"hostnames": names, "state": state},
            )
        )
        for port in host.findall("ports/port"):
            drafts.extend(_port(addr, port, ts))
        for match in host.findall("os/osmatch"):
            drafts.append(
                ObservationDraft(
                    "os",
                    addr,
                    f"{addr} may be {match.get('name', '?')} ({match.get('accuracy', '?')}%)",
                    ts,
                    {"name": match.get("name", ""), "accuracy": match.get("accuracy", "")},
                )
            )
    return drafts


def _port(addr: str, port: ET.Element, ts: int | None) -> list[ObservationDraft]:
    proto = port.get("protocol", "?")
    number = port.get("portid", "?")
    state = _attr(port.find("state"), "state", "unknown")
    service = port.find("service")
    name = _attr(service, "name")
    product = " ".join(
        part for part in (_attr(service, "product"), _attr(service, "version")) if part
    )
    subject = f"{addr}:{number}/{proto}"
    detail = " ".join(part for part in (state, name, product) if part)
    data: dict[str, Any] = {
        "port": number,
        "protocol": proto,
        "state": state,
        "service": name,
        "product": product,
    }
    out = [ObservationDraft("port", subject, f"{subject} {detail}", ts, data)]
    for script in port.findall("script"):
        text = (script.get("output") or "").strip()
        clipped = text[:MAX_OUTPUT_CHARS] + ("…" if len(text) > MAX_OUTPUT_CHARS else "")
        out.append(
            ObservationDraft(
                "script",
                subject,
                f"{subject} {script.get('id', 'script')}: {' '.join(clipped.split())}",
                ts,
                {"script": script.get("id", "")},
            )
        )
    return out
