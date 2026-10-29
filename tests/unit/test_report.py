from __future__ import annotations

import json
import os
from pathlib import Path

from casefile.model import ROLE_CONTEXT, ROLE_CONTRADICTS, ROLE_SUPPORTS
from casefile.report import build_report, render_html, render_json, render_markdown
from casefile.store import CaseStore

from ..conftest import drafts

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
GENERATED = 1_793_304_000_000_000


def golden(name: str, actual: str) -> None:
    path = FIXTURES / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.write_text(actual, encoding="utf-8", newline="\n")
    assert actual == path.read_text(encoding="utf-8"), f"{name} differs; rerun with UPDATE_GOLDEN=1"


def populated(store: CaseStore) -> CaseStore:
    ev = store.add_evidence(
        label="auth",
        kind="log",
        filename="auth.log",
        content=b"abc",
        observations=drafts(
            "login ok", "password=hunter2 used", "<script>alert(1)</script>", "d", "e"
        ),
    )
    f1 = store.add_finding("Account misuse", "Someone used the account.", "high")
    store.add_link(f1.id, ev.id, role=ROLE_SUPPORTS, seq_from=1, seq_to=2, note="login and secret")
    store.add_link(f1.id, ev.id, role=ROLE_CONTEXT, seq_from=3, seq_to=3)
    store.set_status(f1.id, "supported")
    store.add_unknown("Who was it?", f1.id)
    done = store.add_unknown("Was the clock right?", f1.id)
    store.resolve_unknown(done.id, "NTP logs agree")
    f2 = store.add_finding("Web compromise", "The web server was hit.", "low")
    store.add_link(f2.id, ev.id, role=ROLE_CONTRADICTS, note="no web requests")
    store.set_status(f2.id, "refuted")
    store.add_finding("Untested idea", "Maybe insiders.", "medium")
    store.add_unknown("Is there a second host?")
    return store


def test_markdown_report_matches_golden(store: CaseStore) -> None:
    report = build_report(populated(store), generated_us=GENERATED)
    golden("report.golden.md", render_markdown(report))


def test_json_report_matches_golden_and_is_valid(store: CaseStore) -> None:
    text = render_json(build_report(populated(store), generated_us=GENERATED))
    assert json.loads(text)["findings"]
    golden("report.golden.json", text)


def test_findings_are_ordered_by_severity_then_id(store: CaseStore) -> None:
    report = build_report(populated(store), generated_us=GENERATED)
    assert [f["ref"] for f in report["findings"]] == ["F1", "F3", "F2"]


def test_secrets_are_redacted_in_quotes_by_default(store: CaseStore) -> None:
    populated(store)
    default = render_markdown(build_report(store, generated_us=GENERATED))
    assert "hunter2" not in default and "[REDACTED]" in default
    raw = render_markdown(build_report(store, generated_us=GENERATED, redact=False))
    assert "hunter2" in raw and "NOT redacted" in raw


def test_html_escapes_untrusted_evidence_and_text(store: CaseStore) -> None:
    populated(store)
    store.add_finding("<img src=x onerror=alert(1)>", "<b>bold</b>", "low")
    page = render_html(build_report(store, generated_us=GENERATED))
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "<img src=x" not in page and "<b>bold</b>" not in page
    assert page.startswith("<!doctype html>") and "viewport" in page


def test_unsupported_and_uncontradicted_findings_are_flagged(store: CaseStore) -> None:
    report = build_report(populated(store), generated_us=GENERATED)
    by_ref = {f["ref"]: f for f in report["findings"]}
    assert "No contradicting evidence" in by_ref["F1"]["caveats"][0]
    assert "not yet supported" in by_ref["F3"]["status_note"]
    md = render_markdown(report)
    assert "None linked." in md  # F2 and F3 have no supporting evidence


def test_a_refuted_finding_without_contradiction_is_called_out(store: CaseStore) -> None:
    f = store.add_finding("t", "s", "low")
    store.set_status(f.id, "refuted")
    report = build_report(store, generated_us=GENERATED)
    assert "no contradicting evidence is linked" in report["findings"][0]["caveats"][0]


def test_long_evidence_ranges_are_truncated_with_a_count(store: CaseStore) -> None:
    ev = store.add_evidence(
        label="big", kind="log", filename="big", content=b"x", observations=drafts(*["l"] * 30)
    )
    f = store.add_finding("t", "s", "low")
    store.add_link(f.id, ev.id, role=ROLE_SUPPORTS, seq_from=1, seq_to=30)
    md = render_markdown(build_report(store, generated_us=GENERATED, max_quotes=5))
    assert "… 25 more in the evidence" in md
    page = render_html(build_report(store, generated_us=GENERATED, max_quotes=5))
    assert "25 more in the evidence" in page


def test_integrity_failure_is_stated_loudly(store: CaseStore) -> None:
    import sqlite3

    populated(store)
    conn = sqlite3.connect(store.path)
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit SET detail = '{}' WHERE id = 2")
    conn.commit()
    conn.close()
    report = build_report(store, generated_us=GENERATED)
    assert not report["integrity"]["ok"]
    assert "FAILED. Do not rely on this report" in render_markdown(report)
    assert "FAILED. Do not rely on this report" in render_html(report)


def test_empty_case_renders(store: CaseStore) -> None:
    report = build_report(store, generated_us=GENERATED)
    assert "No findings recorded yet." in render_markdown(report)
    assert "No findings recorded yet." in render_html(report)
