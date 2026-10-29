"""Command-line interface. Thin: parsing and printing only."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .importers import ImportFailure, parse
from .model import (
    EVIDENCE_KINDS,
    KIND_LOG,
    KIND_NMAP,
    ROLE_SUPPORTS,
    ROLES,
    SEVERITIES,
    STATUSES,
    Observation,
)
from .report import build_report, render_html, render_json, render_markdown
from .store import MAX_EVIDENCE_BYTES, CaseError, CaseStore
from .timeparse import TimeParseError, iso, parse_time_us

DEFAULT_CASE = "case.casefile"
EXIT_OK, EXIT_ERROR, EXIT_INTEGRITY = 0, 1, 2


def _now_us() -> int:
    return time.time_ns() // 1000


def _ref(text: str, prefix: str) -> int:
    match = re.fullmatch(rf"{prefix}?(\d+)", text.strip(), re.IGNORECASE)
    if not match:
        raise CaseError(f"expected a reference like {prefix}1, got {text!r}")
    return int(match.group(1))


def _range(text: str | None) -> tuple[int | None, int | None]:
    if text is None:
        return None, None
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", text.strip())
    if not match:
        raise CaseError(f"expected a range like 12 or 12-20, got {text!r}")
    first = int(match.group(1))
    return first, int(match.group(2) or first)


def _read_evidence_file(path: str) -> tuple[bytes, str]:
    target = Path(path)
    try:
        info = target.stat()
    except OSError as exc:
        raise CaseError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise CaseError(f"{path} is not a regular file")
    if info.st_size > MAX_EVIDENCE_BYTES:
        raise CaseError(f"{path} is larger than {MAX_EVIDENCE_BYTES // 2**20} MiB")
    try:
        return target.read_bytes(), target.name
    except OSError as exc:
        raise CaseError(f"cannot read {path}: {exc.strerror or exc}") from exc


def _sniff(content: bytes) -> str:
    head = content[:2048].lstrip().lower()
    return KIND_NMAP if head.startswith((b"<?xml", b"<nmaprun")) else KIND_LOG


def _obs_line(o: Observation) -> str:
    stamp = iso(o.ts_us) if o.ts_us is not None else " " * 20
    return f"{o.seq:>6}  {stamp}  {o.summary}"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="casefile", description="Cybersecurity investigation desk. By OBEOS."
    )
    p.add_argument("--version", action="version", version=f"casefile {__version__}")
    p.add_argument(
        "--case",
        default=os.environ.get("CASEFILE_PATH", DEFAULT_CASE),
        help=f"case file (default: $CASEFILE_PATH or ./{DEFAULT_CASE})",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create a new case file")
    s.add_argument("name", help="case name")
    s.add_argument("--analyst", default=None, help="analyst name (default: current user)")

    s = sub.add_parser("import", help="import evidence (Nmap XML or a text log)")
    s.add_argument("file")
    s.add_argument("--kind", choices=("auto", *EVIDENCE_KINDS), default="auto")
    s.add_argument("--label", help="short name used to cite this evidence (default: file name)")
    s.add_argument("--note", default="", help="where it came from, how it was collected")
    s.add_argument("--year", type=int, help="year for syslog lines, which carry none")

    sub.add_parser("evidence", help="list evidence")

    s = sub.add_parser("show", help="print an evidence item's observations")
    s.add_argument("evidence", help="E1 or its label")
    s.add_argument("--lines", help="observation range, e.g. 10-25")
    s.add_argument("--limit", type=int, default=200)

    s = sub.add_parser("search", help="search observations")
    s.add_argument("term")
    s.add_argument("--evidence", help="limit to one evidence item")
    s.add_argument("--since")
    s.add_argument("--until")
    s.add_argument("--limit", type=int, default=100)

    finding = sub.add_parser("finding", help="manage findings").add_subparsers(
        dest="action", required=True
    )
    s = finding.add_parser("add", help="record a finding (starts as a hypothesis)")
    s.add_argument("title")
    s.add_argument("--statement", required=True, help="what happened, in plain words")
    s.add_argument("--severity", choices=SEVERITIES, default="medium")
    finding.add_parser("list", help="list findings")
    s = finding.add_parser("show", help="show one finding with its evidence")
    s.add_argument("finding")
    s = finding.add_parser("status", help="change a finding's status")
    s.add_argument("finding")
    s.add_argument("status", choices=STATUSES)
    s.add_argument("--reason", default="")

    s = sub.add_parser("link", help="attach evidence to a finding")
    s.add_argument("finding")
    s.add_argument("evidence")
    s.add_argument("--lines", help="observation range; omit to cite the whole item")
    s.add_argument("--role", choices=ROLES, default=ROLE_SUPPORTS)
    s.add_argument("--note", default="", help="why this evidence matters")
    s = sub.add_parser("unlink", help="remove a link")
    s.add_argument("link")

    unknown = sub.add_parser("unknown", help="record what is not known").add_subparsers(
        dest="action", required=True
    )
    s = unknown.add_parser("add")
    s.add_argument("text")
    s.add_argument("--finding", help="attach to a finding; omit for a case-wide question")
    s = unknown.add_parser("resolve")
    s.add_argument("unknown")
    s.add_argument("--how", required=True)

    s = sub.add_parser("report", help="write the investigation report")
    s.add_argument("--format", choices=("md", "html", "json"), default="md")
    s.add_argument("--out", help="write to a file instead of standard output")
    s.add_argument("--no-redact", action="store_true", help="quote evidence without redaction")
    s.add_argument("--max-quotes", type=int, default=12, help="quoted lines per evidence link")

    s = sub.add_parser("verify", help="check evidence hashes and the audit chain")
    s.add_argument("--anchor", help="audit head hash recorded earlier")

    sub.add_parser("status", help="case summary and audit head")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except (CaseError, ImportFailure, TimeParseError) as exc:
        print(f"casefile: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


def _run(args: argparse.Namespace) -> int:
    if args.command == "init":
        with CaseStore(args.case, create=True) as store:
            store.init_case(args.name, args.analyst or getpass.getuser())
        print(f"Created {args.case}. It will hold raw evidence; keep it somewhere private.")
        return EXIT_OK
    with CaseStore(args.case) as store:
        return _dispatch(args, store)


def _dispatch(args: argparse.Namespace, store: CaseStore) -> int:
    cmd = args.command
    if cmd == "import":
        content, filename = _read_evidence_file(args.file)
        kind = _sniff(content) if args.kind == "auto" else args.kind
        drafts = parse(kind, content, year=args.year)
        label = args.label or Path(filename).stem
        ev = store.add_evidence(
            label=label,
            kind=kind,
            filename=filename,
            content=content,
            observations=drafts,
            note=args.note,
        )
        print(f"E{ev.id} {ev.label}: {kind}, {len(drafts)} observations, sha256 {ev.sha256[:16]}…")
        return EXIT_OK
    if cmd == "evidence":
        for e in store.list_evidence():
            print(
                f"E{e.id:<3} {e.label:<24} {e.kind:<5} "
                f"{store.count_observations(e.id, None, None):>6} obs  "
                f"{e.sha256[:16]}…  {e.filename}"
            )
        return EXIT_OK
    if cmd == "show":
        ev = store.evidence_by_ref(args.evidence)
        first, last = _range(args.lines)
        for o in store.observations(ev.id, seq_from=first, seq_to=last, limit=args.limit):
            print(_obs_line(o))
        return EXIT_OK
    if cmd == "search":
        now = _now_us()
        ev_id = store.evidence_by_ref(args.evidence).id if args.evidence else None
        hits = store.search(
            args.term,
            evidence_id=ev_id,
            since_us=parse_time_us(args.since, now_us=now) if args.since else None,
            until_us=parse_time_us(args.until, now_us=now) if args.until else None,
            limit=args.limit,
        )
        for o in hits:
            print(f"E{o.evidence_id}:{_obs_line(o).lstrip()}")
        print(f"{len(hits)} match(es)", file=sys.stderr)
        return EXIT_OK
    if cmd == "finding":
        return _finding(args, store)
    if cmd == "link":
        first, last = _range(args.lines)
        link = store.add_link(
            _ref(args.finding, "F"),
            store.evidence_by_ref(args.evidence).id,
            role=args.role,
            seq_from=first,
            seq_to=last,
            note=args.note,
        )
        print(f"L{link.id}: F{link.finding_id} <- E{link.evidence_id} ({link.role})")
        return EXIT_OK
    if cmd == "unlink":
        store.remove_link(_ref(args.link, "L"))
        return EXIT_OK
    if cmd == "unknown":
        if args.action == "add":
            fid = _ref(args.finding, "F") if args.finding else None
            print(f"U{store.add_unknown(args.text, fid).id} recorded")
        else:
            store.resolve_unknown(_ref(args.unknown, "U"), args.how)
        return EXIT_OK
    if cmd == "report":
        report = build_report(
            store,
            generated_us=_now_us(),
            redact=not args.no_redact,
            max_quotes=args.max_quotes,
        )
        text = {"md": render_markdown, "html": render_html, "json": render_json}[args.format](
            report
        )
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8", newline="\n")
            print(f"Wrote {args.out}")
        else:
            sys.stdout.write(text)
        return EXIT_OK if report["integrity"]["ok"] else EXIT_INTEGRITY
    if cmd == "verify":
        result = store.verify(args.anchor)
        print(f"audit entries: {result.audit_rows}\nhead: {result.head}")
        for problem in result.problems:
            print(f"PROBLEM: {problem}")
        print("integrity: OK" if result.ok else "integrity: FAILED")
        return EXIT_OK if result.ok else EXIT_INTEGRITY
    if cmd == "status":
        findings = store.list_findings()
        print(f"case: {store.meta('name')} (analyst {store.meta('analyst')})")
        print(f"evidence: {len(store.list_evidence())}  findings: {len(findings)}")
        for status in STATUSES:
            count = sum(1 for f in findings if f.status == status)
            if count:
                print(f"  {status}: {count}")
        print(f"audit head: {store.head()}")
        return EXIT_OK
    raise CaseError(f"unknown command {cmd!r}")


def _finding(args: argparse.Namespace, store: CaseStore) -> int:
    if args.action == "add":
        f = store.add_finding(args.title, args.statement, args.severity)
        print(f"F{f.id} recorded as a hypothesis")
    elif args.action == "list":
        for f in store.list_findings():
            print(f"F{f.id:<3} {f.severity:<9} {f.status:<12} {f.title}")
    elif args.action == "status":
        f = store.set_status(_ref(args.finding, "F"), args.status, args.reason)
        print(f"F{f.id} is now {f.status}")
    else:
        f = store.finding(_ref(args.finding, "F"))
        print(f"F{f.id} [{f.severity}] {f.status}: {f.title}\n{f.statement}")
        for link in store.links(f.id):
            where = "whole item" if link.seq_from is None else f"{link.seq_from}-{link.seq_to}"
            print(f"  L{link.id} {link.role:<11} E{link.evidence_id} {where}  {link.note}")
        for u in store.unknowns(f.id):
            print(f"  U{u.id} {'resolved' if u.resolved else 'open':<8} {u.text}")
    return EXIT_OK
