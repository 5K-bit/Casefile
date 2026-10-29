from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path

import pytest

from casefile.model import ROLE_CONTEXT, ROLE_SUPPORTS
from casefile.store import CaseError, CaseStore

from ..conftest import drafts, make_clock


def add_ev(store: CaseStore, label: str = "log1", n: int = 5):  # type: ignore[no-untyped-def]
    return store.add_evidence(
        label=label,
        kind="log",
        filename=f"{label}.log",
        content=b"\n".join(f"line {i}".encode() for i in range(n)),
        observations=drafts(*[f"line {i}" for i in range(1, n + 1)]),
    )


def raw(store: CaseStore) -> sqlite3.Connection:
    return sqlite3.connect(store.path)


def test_create_refuses_to_overwrite_and_open_requires_a_file(tmp_path: Path) -> None:
    path = tmp_path / "c.casefile"
    CaseStore(path, create=True).close()
    with pytest.raises(CaseError, match="already exists"):
        CaseStore(path, create=True)
    with pytest.raises(CaseError, match="casefile init"):
        CaseStore(tmp_path / "missing.casefile")


def test_non_database_and_wrong_schema_are_refused(tmp_path: Path) -> None:
    junk = tmp_path / "junk"
    junk.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(CaseError):
        CaseStore(junk)
    other = tmp_path / "other.db"
    conn = sqlite3.connect(other)
    conn.execute("PRAGMA user_version = 99")
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    with pytest.raises(CaseError, match="schema version 99"):
        CaseStore(other)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_case_file_and_sidecars_are_owner_only(store: CaseStore) -> None:
    add_ev(store)
    for suffix in ("", "-wal", "-shm"):
        p = Path(store.path + suffix)
        if p.exists():
            assert stat.S_IMODE(p.stat().st_mode) & 0o077 == 0, p.name


def test_evidence_round_trip_keeps_original_bytes_and_hash(store: CaseStore) -> None:
    ev = add_ev(store)
    assert store.evidence_content(ev.id) == b"line 0\nline 1\nline 2\nline 3\nline 4"
    assert len(ev.sha256) == 64
    assert store.evidence_by_ref("E1").id == ev.id
    assert store.evidence_by_ref("log1").id == ev.id
    with pytest.raises(CaseError):
        store.evidence_by_ref("nope")
    with pytest.raises(CaseError):
        store.evidence(99)


def test_duplicate_labels_are_refused_and_leave_no_trace(store: CaseStore) -> None:
    add_ev(store)
    rows = len(store.audit_rows())
    with pytest.raises(CaseError, match="already exists"):
        add_ev(store)
    assert len(store.list_evidence()) == 1 and len(store.audit_rows()) == rows


def test_evidence_and_observations_are_immutable(store: CaseStore) -> None:
    add_ev(store)
    conn = raw(store)
    for sql in (
        "UPDATE evidence SET content = x'00'",
        "DELETE FROM evidence",
        "UPDATE observations SET summary = 'x'",
        "DELETE FROM observations",
        "UPDATE audit SET action = 'x'",
        "DELETE FROM audit",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="immutable|append-only"):
            conn.execute(sql)
    conn.close()


def test_failed_import_rolls_back_completely(store: CaseStore) -> None:
    bad = drafts("a", "b")
    with pytest.raises(CaseError):
        store.add_evidence(
            label="x", kind="log", filename="x", content=b"x" * 3, observations=bad, note="ok"
        )
        store.add_evidence(label="x", kind="log", filename="x", content=b"y", observations=bad)
    assert len(store.list_evidence()) == 1


def test_finding_validation(store: CaseStore) -> None:
    with pytest.raises(CaseError, match="severity"):
        store.add_finding("t", "s", "catastrophic")
    with pytest.raises(CaseError, match="title"):
        store.add_finding(" ", "s", "low")
    with pytest.raises(CaseError, match="F9"):
        store.finding(9)
    f = store.add_finding(" Title ", " what ", "high")
    assert (f.title, f.statement, f.status) == ("Title", "what", "hypothesis")


def test_supported_requires_supporting_evidence(store: CaseStore) -> None:
    ev = add_ev(store)
    f = store.add_finding("t", "s", "high")
    with pytest.raises(CaseError, match="no supporting evidence"):
        store.set_status(f.id, "supported")
    store.add_link(f.id, ev.id, role=ROLE_CONTEXT)
    with pytest.raises(CaseError, match="no supporting evidence"):
        store.set_status(f.id, "supported")
    store.add_link(f.id, ev.id, role=ROLE_SUPPORTS, seq_from=1, seq_to=2)
    assert store.set_status(f.id, "supported", "why").status == "supported"
    with pytest.raises(CaseError, match="status must be"):
        store.set_status(f.id, "proven")


def test_the_last_support_cannot_be_removed_from_a_supported_finding(store: CaseStore) -> None:
    ev = add_ev(store)
    f = store.add_finding("t", "s", "high")
    ctx = store.add_link(f.id, ev.id, role=ROLE_CONTEXT)
    sup = store.add_link(f.id, ev.id, role=ROLE_SUPPORTS)
    store.set_status(f.id, "supported")
    store.remove_link(ctx.id)  # context can go
    with pytest.raises(CaseError, match="last support"):
        store.remove_link(sup.id)
    store.set_status(f.id, "inconclusive")
    store.remove_link(sup.id)
    assert store.links(f.id) == []
    with pytest.raises(CaseError, match="L99"):
        store.remove_link(99)


def test_link_ranges_are_validated_against_real_observations(store: CaseStore) -> None:
    ev = add_ev(store, n=5)
    f = store.add_finding("t", "s", "low")
    with pytest.raises(CaseError, match="both ends"):
        store.add_link(f.id, ev.id, role=ROLE_SUPPORTS, seq_from=1)
    with pytest.raises(CaseError, match="range must be"):
        store.add_link(f.id, ev.id, role=ROLE_SUPPORTS, seq_from=3, seq_to=2)
    with pytest.raises(CaseError, match="only 2 of the 3"):
        store.add_link(f.id, ev.id, role=ROLE_SUPPORTS, seq_from=4, seq_to=6)
    with pytest.raises(CaseError, match="role must be"):
        store.add_link(f.id, ev.id, role="proves")
    with pytest.raises(CaseError):
        store.add_link(99, ev.id, role=ROLE_SUPPORTS)
    assert store.add_link(f.id, ev.id, role=ROLE_SUPPORTS, seq_from=4, seq_to=5).seq_to == 5


def test_observation_queries_and_search_escape_wildcards(store: CaseStore) -> None:
    ev = store.add_evidence(
        label="l",
        kind="log",
        filename="l",
        content=b"x",
        observations=drafts("100% done", "a_b", "plain", "A_B upper"),
    )
    assert [o.seq for o in store.observations(ev.id, seq_from=2, seq_to=3)] == [2, 3]
    assert [o.seq for o in store.observations(ev.id, limit=1)] == [1]
    assert [o.seq for o in store.search("100%")] == [1]
    assert [o.seq for o in store.search("a_b")] == [2, 4]  # case-insensitive, _ is literal
    assert store.search("plain", evidence_id=ev.id + 1) == []
    base = 1_793_300_000_000_000
    assert [o.seq for o in store.search("a", since_us=base + 2, until_us=base + 3)] == [3, 4]


def test_unknowns_can_be_case_wide_or_per_finding_and_resolved(store: CaseStore) -> None:
    f = store.add_finding("t", "s", "low")
    a = store.add_unknown("per finding", f.id)
    store.add_unknown("case wide")
    assert [u.text for u in store.unknowns(f.id)] == ["per finding"]
    assert [u.text for u in store.unknowns(scope="case")] == ["case wide"]
    store.resolve_unknown(a.id, "checked the host")
    assert store.unknowns(f.id)[0].resolved
    with pytest.raises(CaseError, match="unknown"):
        store.add_unknown("  ")
    with pytest.raises(CaseError, match="how it was resolved"):
        store.resolve_unknown(a.id, "")
    with pytest.raises(CaseError, match="U99"):
        store.resolve_unknown(99, "x")
    with pytest.raises(CaseError):
        store.add_unknown("x", 99)


def test_verify_passes_on_a_clean_case(store: CaseStore) -> None:
    add_ev(store)
    f = store.add_finding("t", "s", "low")
    store.add_link(f.id, 1, role=ROLE_SUPPORTS)
    result = store.verify()
    assert result.ok and result.audit_rows == 4 and result.head == store.head()


def _break(store: CaseStore, *statements: str) -> sqlite3.Connection:
    conn = raw(store)
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("DROP TRIGGER audit_no_delete")
    conn.execute("DROP TRIGGER evidence_no_update")
    for s in statements:
        conn.execute(s)
    conn.commit()
    return conn


def test_verify_detects_an_edited_audit_row(store: CaseStore) -> None:
    add_ev(store)
    _break(store, "UPDATE audit SET detail = '{}' WHERE id = 2").close()
    result = store.verify()
    assert not result.ok and any("row 2 was altered" in p for p in result.problems)


def test_verify_detects_a_deleted_middle_row(store: CaseStore) -> None:
    add_ev(store)
    store.add_finding("t", "s", "low")
    _break(store, "DELETE FROM audit WHERE id = 2").close()
    problems = store.verify().problems
    assert any("row 2 is missing" in p for p in problems)
    assert any("does not follow" in p for p in problems)


def test_verify_detects_tampered_evidence_even_if_the_hash_column_is_rewritten(
    store: CaseStore,
) -> None:
    ev = add_ev(store)
    import hashlib

    new = b"forged"
    digest = hashlib.sha256(new).hexdigest()
    _break(
        store,
        f"UPDATE evidence SET content = x'{new.hex()}', sha256 = '{digest}' WHERE id = {ev.id}",
    ).close()
    problems = store.verify().problems
    assert any("differs from the audit record" in p for p in problems)


def test_verify_detects_changed_content_with_the_original_hash(store: CaseStore) -> None:
    ev = add_ev(store)
    _break(store, f"UPDATE evidence SET content = x'00' WHERE id = {ev.id}").close()
    assert any("does not match its stored hash" in p for p in store.verify().problems)


def test_an_external_anchor_catches_removed_trailing_rows(store: CaseStore) -> None:
    add_ev(store)
    store.add_finding("one", "s", "low")
    store.add_finding("two", "s", "low")
    anchor = store.head()
    assert store.verify(anchor).ok
    # An attacker who truncates the log and also removes what it described: the chain and the
    # replay are both internally consistent, so only the external anchor can see it.
    conn = _break(store, f"DELETE FROM audit WHERE id = {len(store.audit_rows())}")
    conn.execute("DELETE FROM findings WHERE id = 2")
    conn.commit()
    conn.close()
    assert store.verify().ok
    result = store.verify(anchor)
    assert not result.ok and any("anchor" in p for p in result.problems)


def test_truncating_the_log_alone_is_caught_without_an_anchor(store: CaseStore) -> None:
    add_ev(store)
    store.add_finding("one", "s", "low")
    conn = _break(store, f"DELETE FROM audit WHERE id = {len(store.audit_rows())}")
    conn.close()
    assert any(
        "F1 is in the case but not in the audit history" in p for p in store.verify().problems
    )


def test_a_deleted_evidence_row_is_reported(store: CaseStore) -> None:
    ev = add_ev(store)
    conn = _break(store)
    conn.execute("DROP TRIGGER evidence_no_delete")
    conn.execute("DROP TRIGGER obs_no_delete")
    conn.execute(f"DELETE FROM observations WHERE evidence_id = {ev.id}")
    conn.execute(f"DELETE FROM evidence WHERE id = {ev.id}")
    conn.commit()
    conn.close()
    assert any("no longer in the case" in p for p in store.verify().problems)


def _supported_case(store: CaseStore) -> int:
    add_ev(store)
    f = store.add_finding("Brute force", "Many failures then a success", "high")
    store.add_link(f.id, 1, role=ROLE_SUPPORTS, seq_from=1, seq_to=2, note="the burst")
    store.set_status(f.id, "supported", "reviewed")
    store.add_unknown("Was the account reused?", f.id)
    store.add_unknown("Is there a second host?")
    assert store.verify().ok
    return f.id


def test_direct_edit_of_a_finding_statement_fails_verify(store: CaseStore) -> None:
    fid = _supported_case(store)
    anchor = store.head()
    raw_conn = raw(store)
    raw_conn.execute("UPDATE findings SET statement = 'Nothing happened' WHERE id = ?", (fid,))
    raw_conn.commit()
    raw_conn.close()
    result = store.verify(anchor)
    assert not result.ok and any(f"F{fid}" in p and "statement" in p for p in result.problems)


@pytest.mark.parametrize(
    ("column", "value"),
    [("title", "'Renamed'"), ("severity", "'low'"), ("status", "'refuted'")],
)
def test_direct_edit_of_any_finding_field_fails_verify(
    store: CaseStore, column: str, value: str
) -> None:
    fid = _supported_case(store)
    conn = raw(store)
    conn.execute(f"UPDATE findings SET {column} = {value} WHERE id = {fid}")
    conn.commit()
    conn.close()
    assert any(column in p for p in store.verify().problems)


def test_marking_supported_without_evidence_by_direct_edit_fails_verify(store: CaseStore) -> None:
    add_ev(store)
    f = store.add_finding("t", "claim", "low")
    conn = raw(store)
    conn.execute("UPDATE findings SET status = 'supported' WHERE id = ?", (f.id,))
    conn.commit()
    conn.close()
    problems = store.verify(store.head()).problems
    assert any("status" in p for p in problems)


def test_injected_finding_link_and_unknown_fail_verify(store: CaseStore) -> None:
    _supported_case(store)
    conn = raw(store)
    conn.execute(
        "INSERT INTO findings (title,statement,severity,status,created_us,updated_us) "
        "VALUES ('x','y','low','supported',1,1)"
    )
    conn.execute("INSERT INTO links (finding_id,evidence_id,role,note) VALUES (1,1,'supports','')")
    conn.execute("INSERT INTO unknowns (finding_id,text) VALUES (NULL,'smuggled')")
    conn.commit()
    conn.close()
    problems = " | ".join(store.verify().problems)
    assert "F2" in problems and "L2" in problems and "U3" in problems


def test_deleted_or_edited_link_and_unknown_fail_verify(store: CaseStore) -> None:
    _supported_case(store)
    conn = raw(store)
    conn.execute("UPDATE links SET seq_to = 5, note = 'forged' WHERE id = 1")
    conn.execute("UPDATE unknowns SET resolved = 1, resolution = 'nope' WHERE id = 1")
    conn.execute("DELETE FROM unknowns WHERE id = 2")
    conn.commit()
    conn.close()
    problems = " | ".join(store.verify().problems)
    assert "L1" in problems and "U1" in problems and "U2" in problems


def test_deleted_finding_fails_verify(store: CaseStore) -> None:
    fid = _supported_case(store)
    conn = raw(store)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("DELETE FROM unknowns WHERE finding_id = ?", (fid,))
    conn.execute("DELETE FROM links WHERE finding_id = ?", (fid,))
    conn.execute("DELETE FROM findings WHERE id = ?", (fid,))
    conn.commit()
    conn.close()
    assert any(f"F{fid}" in p for p in store.verify().problems)


def test_edited_case_metadata_and_evidence_labels_fail_verify(store: CaseStore) -> None:
    _supported_case(store)
    conn = _break(store, "UPDATE meta SET value = 'someone else' WHERE key = 'analyst'")
    conn.execute("UPDATE evidence SET label = 'renamed', filename = 'x' WHERE id = 1")
    conn.commit()
    conn.close()
    problems = " | ".join(store.verify().problems)
    assert "analyst" in problems and "E1" in problems and "label" in problems


def test_legitimate_history_replays_cleanly(store: CaseStore) -> None:
    fid = _supported_case(store)
    store.add_link(fid, 1, role=ROLE_CONTEXT, note="extra")
    store.remove_link(2)
    store.set_status(fid, "refuted", "new evidence")
    store.resolve_unknown(1, "no")
    assert store.verify(store.head()).ok


def test_clock_is_injected_and_monotonic(tmp_path: Path) -> None:
    with CaseStore(tmp_path / "c", create=True, clock=make_clock()) as s:
        s.init_case("n", "a")
        s.add_finding("t", "s", "low")
        times = [r[1] for r in s.audit_rows()]
        assert times == sorted(times) and len(set(times)) == len(times)
