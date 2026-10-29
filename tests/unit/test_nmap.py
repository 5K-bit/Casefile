from __future__ import annotations

from pathlib import Path

import pytest

from casefile.importers.nmap import MAX_OUTPUT_CHARS, NmapError, parse_nmap_xml

LAB = Path(__file__).resolve().parents[2] / "examples" / "lab" / "scan-before.xml"


def wrap(body: str, head: str = "") -> bytes:
    root = f'<nmaprun start="1793293200" args="nmap x">{body}</nmaprun>'
    return f'<?xml version="1.0"?>{head}{root}'.encode()


def test_lab_scan_yields_scan_hosts_ports_os_and_scripts() -> None:
    obs = parse_nmap_xml(LAB.read_bytes())
    kinds = [o.kind for o in obs]
    assert kinds == ["scan", "host", "port", "port", "os", "host", "port", "script"]
    ssh = obs[2]
    assert ssh.subject == "10.0.0.5:22/tcp"
    assert ssh.summary == "10.0.0.5:22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.6"
    assert ssh.ts_us == 1_793_293_201 * 1_000_000
    assert obs[3].data["state"] == "closed"
    assert "web01.lab.example" in obs[5].summary


def test_the_bare_doctype_nmap_writes_is_accepted() -> None:
    assert parse_nmap_xml(wrap("", "<!DOCTYPE nmaprun>"))


def test_entity_declarations_are_refused() -> None:
    bomb = (
        b'<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>'
        b"<nmaprun>&b;</nmaprun>"
    )
    with pytest.raises(NmapError, match="entities"):
        parse_nmap_xml(bomb)


def test_internal_dtd_subset_is_refused_even_without_entities() -> None:
    with pytest.raises(NmapError):
        parse_nmap_xml(b"<!DOCTYPE nmaprun [<!ELEMENT x ANY>]><nmaprun/>")


def test_entity_check_is_case_insensitive() -> None:
    with pytest.raises(NmapError):
        parse_nmap_xml(b'<!doctype nmaprun [<!entity a "b">]><nmaprun/>')


BOMB = (
    '<?xml version="1.0" encoding="{enc}"?><!DOCTYPE nmaprun [<!ENTITY a "aaaa">]>'
    '<nmaprun start="1793293200">&a;</nmaprun>'
)


@pytest.mark.parametrize("py_enc", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_entities_are_refused(py_enc: str) -> None:
    # declared "UTF-16" with a BOM, and BOM-less LE/BE that expat sniffs from the first bytes
    with pytest.raises(NmapError, match="entities"):
        parse_nmap_xml(BOMB.format(enc="UTF-16").encode(py_enc))


@pytest.mark.parametrize("declared", ["UTF-16-LE", "UTF-16-BE", "no-such-encoding"])
def test_encodings_expat_cannot_decode_are_an_import_error(declared: str) -> None:
    doc = BOMB.format(enc=declared).encode("utf-16-le")
    with pytest.raises(NmapError):
        parse_nmap_xml(doc)


def test_utf16_with_bom_and_internal_subset_only_is_refused() -> None:
    doc = "<!DOCTYPE nmaprun [<!ELEMENT x ANY>]><nmaprun/>"
    with pytest.raises(NmapError):
        parse_nmap_xml(b"\xff\xfe" + doc.encode("utf-16-le"))


def test_entity_declaration_split_by_comment_or_whitespace_is_refused() -> None:
    for decl in ('<!ENTITY\na "b">', "<!ENTITY%\tp 'x'>", '<!--c--><!ENTITY a "b">'):
        with pytest.raises(NmapError):
            parse_nmap_xml(f"<!DOCTYPE nmaprun [{decl}]><nmaprun/>".encode())


def test_declared_latin1_encoding_with_entities_is_refused() -> None:
    doc = (
        '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE nmaprun [<!ENTITY a "b">]><nmaprun/>'
    )
    with pytest.raises(NmapError):
        parse_nmap_xml(doc.encode("latin-1"))


def test_utf16_nmap_output_without_entities_still_parses() -> None:
    doc = '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE nmaprun><nmaprun start="1"/>'
    assert parse_nmap_xml(doc.encode("utf-16"))[0].kind == "scan"


@pytest.mark.parametrize("content", [b"", b"not xml", b"<nmaprun><host>"])
def test_malformed_xml_is_an_error_not_a_crash(content: bytes) -> None:
    with pytest.raises(NmapError, match="not valid XML"):
        parse_nmap_xml(content)


def test_other_xml_is_refused() -> None:
    with pytest.raises(NmapError, match="not an Nmap XML"):
        parse_nmap_xml(b"<html/>")


def test_host_without_an_address_is_skipped_and_mac_is_not_the_address() -> None:
    body = (
        '<host><status state="up"/></host>'
        '<host><status state="up"/><address addr="AA:BB" addrtype="mac"/>'
        '<address addr="192.0.2.9" addrtype="ipv4"/></host>'
        '<host><status state="up"/><address addr="AA:BB" addrtype="mac"/></host>'
    )
    obs = parse_nmap_xml(wrap(body))
    assert [o.subject for o in obs if o.kind == "host"] == ["192.0.2.9"]


def test_ipv6_and_missing_attributes_do_not_break_parsing() -> None:
    body = (
        '<host><status state="up"/><address addr="2001:db8::1" addrtype="ipv6"/>'
        '<ports><port protocol="udp" portid="53"><state state="open|filtered"/></port>'
        "</ports></host>"
    )
    obs = parse_nmap_xml(wrap(body))
    assert obs[2].subject == "2001:db8::1:53/udp"
    assert obs[2].summary.endswith("open|filtered")


def test_long_script_output_is_clipped_and_whitespace_collapsed() -> None:
    long = "x" * (MAX_OUTPUT_CHARS + 50)
    body = (
        '<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports>'
        f'<port protocol="tcp" portid="80"><state state="open"/><script id="s" output="{long}"/>'
        "</port></ports></host>"
    )
    script = next(o for o in parse_nmap_xml(wrap(body)) if o.kind == "script")
    assert script.summary.endswith("…")
    assert len(script.summary) < MAX_OUTPUT_CHARS + 60


def test_scan_without_a_start_time_has_no_timestamps() -> None:
    obs = parse_nmap_xml(
        b"<nmaprun><host><status state='up'/><address addr='192.0.2.1'/></host></nmaprun>"
    )
    assert all(o.ts_us is None for o in obs)
