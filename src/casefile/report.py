"""Build and render the investigation report.

The report answers three questions for every finding: what happened, what supports the
conclusion, and what remains unknown. Evidence is quoted from the stored observations
(redacted by default); nothing is paraphrased by the tool. Output is a pure function of
the case file and the ``generated_us`` timestamp, so it is reproducible.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from typing import Any

from . import __version__
from .model import (
    ROLE_CONTEXT,
    ROLE_CONTRADICTS,
    ROLE_SUPPORTS,
    SEVERITY_RANK,
    STATUS_HYPOTHESIS,
    STATUS_INCONCLUSIVE,
    STATUS_REFUTED,
    STATUS_SUPPORTED,
    Finding,
    Link,
)
from .redact import Redactor
from .store import CaseStore
from .timeparse import iso

ROLE_TITLES = {
    ROLE_SUPPORTS: "Supporting evidence",
    ROLE_CONTRADICTS: "Contradicting evidence",
    ROLE_CONTEXT: "Context",
}
STATUS_NOTES = {
    STATUS_SUPPORTED: "The evidence below supports this conclusion.",
    STATUS_HYPOTHESIS: "A hypothesis. It is not yet supported by linked evidence.",
    STATUS_INCONCLUSIVE: "The evidence does not settle this either way.",
    STATUS_REFUTED: "The evidence contradicts this claim.",
}


@dataclass(frozen=True)
class Quote:
    seq: int
    ts: str
    subject: str
    text: str


@dataclass(frozen=True)
class EvidenceRef:
    link_id: int
    role: str
    evidence: str
    seq_from: int | None
    seq_to: int | None
    note: str
    total: int
    quotes: list[Quote]


def _quotes(store: CaseStore, link: Link, redactor: Redactor | None, limit: int) -> EvidenceRef:
    ev = store.evidence(link.evidence_id)
    total = store.count_observations(ev.id, link.seq_from, link.seq_to)
    rows = store.observations(ev.id, seq_from=link.seq_from, seq_to=link.seq_to, limit=limit)
    quotes = [
        Quote(
            o.seq,
            iso(o.ts_us) if o.ts_us is not None else "",
            o.subject,
            redactor.redact(o.summary) if redactor else o.summary,
        )
        for o in rows
    ]
    return EvidenceRef(
        link.id,
        link.role,
        f"E{ev.id} {ev.label}",
        link.seq_from,
        link.seq_to,
        link.note,
        total,
        quotes,
    )


def build_report(
    store: CaseStore,
    *,
    generated_us: int,
    redact: bool = True,
    max_quotes: int = 12,
    redactor: Redactor | None = None,
) -> dict[str, Any]:
    """Collect everything the renderers need into plain data."""
    active = (redactor or Redactor()) if redact else None
    verify = store.verify()
    findings = sorted(
        store.list_findings(), key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.id)
    )
    return {
        "tool": f"casefile {__version__}",
        "case": {
            "name": store.meta("name") or "",
            "analyst": store.meta("analyst") or "",
            "generated": iso(generated_us),
            "redacted": redact,
        },
        "integrity": {
            "ok": verify.ok,
            "audit_rows": verify.audit_rows,
            "head": verify.head,
            "problems": verify.problems,
        },
        "findings": [_finding(store, f, active, max_quotes) for f in findings],
        "case_unknowns": [
            {"id": u.id, "text": u.text, "resolved": u.resolved, "resolution": u.resolution}
            for u in store.unknowns(scope="case")
        ],
        "evidence": [
            {
                "ref": f"E{e.id}",
                "label": e.label,
                "kind": e.kind,
                "filename": e.filename,
                "sha256": e.sha256,
                "size": e.size,
                "imported": iso(e.imported_us),
                "observations": store.count_observations(e.id, None, None),
                "note": e.note,
            }
            for e in store.list_evidence()
        ],
    }


def _finding(
    store: CaseStore, finding: Finding, redactor: Redactor | None, max_quotes: int
) -> dict[str, Any]:
    refs = [_quotes(store, link, redactor, max_quotes) for link in store.links(finding.id)]
    by_role = {role: [r for r in refs if r.role == role] for role in ROLE_TITLES}
    return {
        "ref": f"F{finding.id}",
        "title": finding.title,
        "statement": finding.statement,
        "severity": finding.severity,
        "status": finding.status,
        "status_note": STATUS_NOTES[finding.status],
        "counts": {role: len(items) for role, items in by_role.items()},
        "evidence": {
            role: [r.__dict__ | {"quotes": [q.__dict__ for q in r.quotes]} for r in items]
            for role, items in by_role.items()
        },
        "unknowns": [
            {"id": u.id, "text": u.text, "resolved": u.resolved, "resolution": u.resolution}
            for u in store.unknowns(finding.id)
        ],
        "caveats": _caveats(finding, by_role),
    }


def _caveats(finding: Finding, by_role: dict[str, list[EvidenceRef]]) -> list[str]:
    notes: list[str] = []
    if finding.status == STATUS_SUPPORTED and not by_role[ROLE_CONTRADICTS]:
        notes.append("No contradicting evidence has been recorded for this finding.")
    if finding.status == STATUS_REFUTED and not by_role[ROLE_CONTRADICTS]:
        notes.append("Marked refuted, but no contradicting evidence is linked.")
    return notes


# -- rendering -----------------------------------------------------------------


def _range(ref: dict[str, Any]) -> str:
    if ref["seq_from"] is None:
        return "whole item"
    if ref["seq_from"] == ref["seq_to"]:
        return f"observation {ref['seq_from']}"
    return f"observations {ref['seq_from']}-{ref['seq_to']}"


def render_markdown(report: dict[str, Any]) -> str:
    case = report["case"]
    out = [
        f"# Investigation report: {case['name']}",
        "",
        f"Analyst: {case['analyst']} · Generated: {case['generated']} · "
        f"{'Evidence quotes redacted' if case['redacted'] else 'Evidence quotes NOT redacted'}",
        "",
    ]
    integrity = report["integrity"]
    if integrity["ok"]:
        out.append(
            f"Case integrity: verified ({integrity['audit_rows']} audit entries, "
            f"head `{integrity['head'][:16]}`)."
        )
    else:
        out.append("**Case integrity: FAILED. Do not rely on this report.**")
        out.extend(f"- {p}" for p in integrity["problems"])
    out += ["", "## Findings", ""]
    if not report["findings"]:
        out += ["No findings recorded yet.", ""]
    else:
        out += ["| Ref | Severity | Status | Title |", "|---|---|---|---|"]
        out += [
            f"| {f['ref']} | {f['severity']} | {f['status']} | {_md(f['title'])} |"
            for f in report["findings"]
        ]
        out.append("")
    for f in report["findings"]:
        out += [f"## {f['ref']}: {f['title']}", "", f"**{f['severity'].title()}** · {f['status']}"]
        out += ["", f"> {f['status_note']}", "", "### What happened", "", f["statement"], ""]
        for role, title in ROLE_TITLES.items():
            items = f["evidence"][role]
            if not items:
                if role == ROLE_SUPPORTS:
                    out += [f"### {title}", "", "None linked.", ""]
                continue
            out += [f"### {title}", ""]
            for ref in items:
                note = f" — {ref['note']}" if ref["note"] else ""
                out += [f"**{ref['evidence']}**, {_range(ref)}{note}", "", "```text"]
                out += [_quote_line(q) for q in ref["quotes"]]
                if ref["total"] > len(ref["quotes"]):
                    out.append(f"… {ref['total'] - len(ref['quotes'])} more in the evidence")
                out += ["```", ""]
        out += ["### What remains unknown", ""]
        open_items = [u for u in f["unknowns"] if not u["resolved"]]
        done = [u for u in f["unknowns"] if u["resolved"]]
        out += [f"- U{u['id']}: {u['text']}" for u in open_items] or ["Nothing recorded."]
        out += [f"- U{u['id']} (resolved): {u['text']} → {u['resolution']}" for u in done]
        out.append("")
        out += [f"_Note: {c}_" for c in f["caveats"]]
        if f["caveats"]:
            out.append("")
    if report["case_unknowns"]:
        out += ["## Open questions for the whole case", ""]
        out += [
            f"- U{u['id']}{' (resolved)' if u['resolved'] else ''}: {u['text']}"
            for u in report["case_unknowns"]
        ]
        out.append("")
    out += [
        "## Evidence register",
        "",
        "| Ref | Label | Kind | File | Observations | SHA-256 |",
        "|---|---|---|---|---|---|",
    ]
    out += [
        f"| {e['ref']} | {_md(e['label'])} | {e['kind']} | {_md(e['filename'])} | "
        f"{e['observations']} | `{e['sha256']}` |"
        for e in report["evidence"]
    ]
    out += [
        "",
        f"Generated by {report['tool']}. Conclusions are the analyst's; this tool "
        "organises evidence and does not decide what it means.",
        "",
    ]
    return "\n".join(out)


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _quote_line(q: dict[str, Any]) -> str:
    prefix = f"{q['seq']:>4}  "
    stamp = f"{q['ts']}  " if q["ts"] else ""
    return f"{prefix}{stamp}{q['text']}"


_CSS = """
:root{--bg:#fff;--fg:#1b1f2a;--mute:#5b6577;--line:#d9deea;--accent:#6d4fe0;--card:#f6f7fb;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0c1220;--fg:#eef1f8;--mute:#99a7bc;--line:#283345;
--accent:#a78bfa;--card:#131b2d;--bad:#ff8a80}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,sans-serif}
main{max-width:56rem;margin:0 auto;padding:1.5rem 1rem 4rem}
h1{font-size:1.7rem;margin:.2rem 0}h2{margin-top:2.4rem;border-bottom:2px solid var(--accent);
padding-bottom:.2rem}h3{margin:1.4rem 0 .3rem;font-size:1rem;color:var(--mute);
text-transform:uppercase;letter-spacing:.06em}
.meta,.note{color:var(--mute)}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:.8rem 1rem;margin:.6rem 0}.bad{color:var(--bad);font-weight:700}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.7rem;
overflow-x:auto;font-size:.82rem;white-space:pre-wrap;word-break:break-word}
table{border-collapse:collapse;width:100%;font-size:.9rem;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:.35rem .5rem;text-align:left;vertical-align:top}
code{font-size:.8rem;word-break:break-all}
.tag{display:inline-block;border:1px solid var(--accent);color:var(--accent);border-radius:999px;
padding:0 .6rem;font-size:.8rem;margin-right:.4rem}
"""


def render_html(report: dict[str, Any]) -> str:
    e = html.escape
    case = report["case"]
    integrity = report["integrity"]
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        f"<title>Investigation report: {e(case['name'])}</title><style>{_CSS}</style></head>"
        "<body><main>",
        f"<h1>Investigation report: {e(case['name'])}</h1>",
        f"<p class=meta>Analyst: {e(case['analyst'])} · Generated: {e(case['generated'])} · "
        f"{'Evidence quotes redacted' if case['redacted'] else 'Evidence quotes NOT redacted'}</p>",
    ]
    if integrity["ok"]:
        parts.append(
            f"<p class=note>Case integrity: verified ({integrity['audit_rows']} audit entries, "
            f"head <code>{e(integrity['head'][:16])}</code>).</p>"
        )
    else:
        parts.append("<p class=bad>Case integrity: FAILED. Do not rely on this report.</p><ul>")
        parts += [f"<li>{e(p)}</li>" for p in integrity["problems"]]
        parts.append("</ul>")
    parts.append("<h2>Findings</h2>")
    if report["findings"]:
        parts.append("<table><tr><th>Ref<th>Severity<th>Status<th>Title</tr>")
        parts += [
            f"<tr><td>{e(f['ref'])}<td>{e(f['severity'])}<td>{e(f['status'])}<td>{e(f['title'])}"
            for f in report["findings"]
        ]
        parts.append("</table>")
    else:
        parts.append("<p>No findings recorded yet.</p>")
    for f in report["findings"]:
        parts += [
            f"<h2>{e(f['ref'])}: {e(f['title'])}</h2>",
            f"<p><span class=tag>{e(f['severity'])}</span><span class=tag>{e(f['status'])}</span>"
            f"<span class=note>{e(f['status_note'])}</span></p>",
            f"<h3>What happened</h3><p>{e(f['statement'])}</p>",
        ]
        for role, title in ROLE_TITLES.items():
            items = f["evidence"][role]
            if not items and role != ROLE_SUPPORTS:
                continue
            parts.append(f"<h3>{e(title)}</h3>")
            if not items:
                parts.append("<p>None linked.</p>")
            for ref in items:
                note = f" — {e(ref['note'])}" if ref["note"] else ""
                parts.append(
                    f"<div class=card><strong>{e(ref['evidence'])}</strong>, "
                    f"{e(_range(ref))}{note}<pre>"
                    + e("\n".join(_quote_line(q) for q in ref["quotes"]))
                    + (
                        f"\n… {ref['total'] - len(ref['quotes'])} more in the evidence"
                        if ref["total"] > len(ref["quotes"])
                        else ""
                    )
                    + "</pre></div>"
                )
        parts.append("<h3>What remains unknown</h3>")
        if f["unknowns"]:
            parts.append("<ul>")
            for u in f["unknowns"]:
                tail = f" (resolved: {e(u['resolution'])})" if u["resolved"] else ""
                parts.append(f"<li>U{u['id']}: {e(u['text'])}{tail}</li>")
            parts.append("</ul>")
        else:
            parts.append("<p>Nothing recorded.</p>")
        parts += [f"<p class=note><em>Note: {e(c)}</em></p>" for c in f["caveats"]]
    if report["case_unknowns"]:
        parts.append("<h2>Open questions for the whole case</h2><ul>")
        parts += [f"<li>U{u['id']}: {e(u['text'])}</li>" for u in report["case_unknowns"]]
        parts.append("</ul>")
    parts.append(
        "<h2>Evidence register</h2><table><tr><th>Ref<th>Label<th>Kind<th>File"
        "<th>Observations<th>SHA-256</tr>"
    )
    parts += [
        f"<tr><td>{e(x['ref'])}<td>{e(x['label'])}<td>{e(x['kind'])}<td>{e(x['filename'])}"
        f"<td>{x['observations']}<td><code>{e(x['sha256'])}</code>"
        for x in report["evidence"]
    ]
    parts.append(
        f"</table><p class=note>Generated by {e(report['tool'])}. Conclusions are the analyst's; "
        "this tool organises evidence and does not decide what it means.</p></main></body></html>"
    )
    return "".join(parts)


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
