"""SQLite case file: immutable evidence, mutable findings, a hash-chained audit log.

Design notes (see docs/adr/0001-single-file-case-with-audit-chain.md):

* A case is one SQLite file. Evidence bytes are stored inside it, with their SHA-256,
  so the case is self-contained and every conclusion can be re-checked against the
  original material.
* ``evidence`` and ``observations`` are immutable: triggers reject UPDATE and DELETE.
* Findings, links and unknowns can change, but every change is recorded in ``audit``,
  an append-only log where ``hash = SHA-256(prev_hash || fields)``. Editing or removing
  an audit row, or altering stored evidence, is found by :meth:`CaseStore.verify`.
  This is tamper *evidence*, not tamper proofing: someone with write access to the file
  can rebuild the chain. Record the head hash elsewhere (``casefile status``) to detect that.
* A finding cannot be marked ``supported`` without at least one supporting link.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any

from .model import (
    ROLE_SUPPORTS,
    ROLES,
    SEVERITIES,
    STATUS_HYPOTHESIS,
    STATUS_SUPPORTED,
    STATUSES,
    Evidence,
    Finding,
    Link,
    Observation,
    ObservationDraft,
    Unknown,
)

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE evidence (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    label       TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    filename    TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    size        INTEGER NOT NULL,
    imported_us INTEGER NOT NULL,
    note        TEXT NOT NULL,
    content     BLOB NOT NULL
);
CREATE TABLE observations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    seq         INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    subject     TEXT NOT NULL,
    summary     TEXT NOT NULL,
    ts_us       INTEGER,
    data        TEXT NOT NULL,
    UNIQUE (evidence_id, seq)
);
CREATE INDEX idx_obs_subject ON observations (subject);
CREATE INDEX idx_obs_ts ON observations (ts_us);
CREATE TABLE findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    title      TEXT NOT NULL,
    statement  TEXT NOT NULL,
    severity   TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_us INTEGER NOT NULL,
    updated_us INTEGER NOT NULL
);
CREATE TABLE links (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL REFERENCES findings(id),
    evidence_id INTEGER NOT NULL REFERENCES evidence(id),
    seq_from    INTEGER,
    seq_to      INTEGER,
    role        TEXT NOT NULL,
    note        TEXT NOT NULL
);
CREATE TABLE unknowns (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER REFERENCES findings(id),
    text       TEXT NOT NULL,
    resolved   INTEGER NOT NULL DEFAULT 0,
    resolution TEXT NOT NULL DEFAULT ''
);
CREATE TABLE audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_us     INTEGER NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
CREATE TRIGGER evidence_no_update BEFORE UPDATE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is immutable'); END;
CREATE TRIGGER evidence_no_delete BEFORE DELETE ON evidence
BEGIN SELECT RAISE(ABORT, 'evidence is immutable'); END;
CREATE TRIGGER obs_no_update BEFORE UPDATE ON observations
BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END;
CREATE TRIGGER obs_no_delete BEFORE DELETE ON observations
BEGIN SELECT RAISE(ABORT, 'observations are immutable'); END;
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
"""


class CaseError(Exception):
    """A user-facing problem: bad input, missing case, refused operation."""


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    audit_rows: int
    head: str
    problems: list[str] = field(default_factory=list)


def _hash(prev: str, ts_us: int, action: str, detail: str) -> str:
    material = json.dumps([ts_us, action, detail], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(f"{prev}\n{material}".encode("ascii")).hexdigest()


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _create_owner_only(path: str) -> None:
    """Create the case file with mode 0600 before SQLite opens it (POSIX).

    A case file holds raw evidence. SQLite creates its -wal/-shm sidecars with the main
    file's permissions, so the main file must already be restricted. On Windows, access
    follows the folder ACL.
    """
    if os.name != "posix" or os.path.exists(path):
        return
    with contextlib.suppress(OSError):  # connect() below reports the real problem
        os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))


class CaseStore:
    def __init__(
        self,
        path: str | Path,
        *,
        create: bool = False,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.path = str(path)
        self._clock = clock or (lambda: time.time_ns() // 1000)
        exists = os.path.exists(self.path)
        if create and exists and os.path.getsize(self.path) > 0:
            raise CaseError(f"{self.path} already exists; refusing to overwrite a case")
        if not create and not exists:
            raise CaseError(f"no case file at {self.path}; run `casefile init` first")
        if create:
            _create_owner_only(self.path)
        try:
            self._conn = sqlite3.connect(self.path, isolation_level=None)
        except sqlite3.Error as exc:
            raise CaseError(f"cannot open {self.path}: {exc}") from exc
        try:
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._conn.execute("PRAGMA journal_mode = WAL")
            if create:
                self._conn.executescript(_SCHEMA)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            else:
                version = self._conn.execute("PRAGMA user_version").fetchone()[0]
                if version != SCHEMA_VERSION:
                    raise CaseError(
                        f"{self.path} has schema version {version}; this Casefile reads "
                        f"version {SCHEMA_VERSION}"
                    )
        except (sqlite3.Error, CaseError) as exc:
            self._conn.close()
            if isinstance(exc, CaseError):
                raise
            raise CaseError(f"{self.path} is not a usable case file: {exc}") from exc

    # -- lifecycle -------------------------------------------------------------

    def __enter__(self) -> CaseStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield self._conn
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        self._conn.execute("COMMIT")

    def _audit(self, conn: sqlite3.Connection, action: str, detail: dict[str, Any]) -> None:
        row = conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = row[0] if row else GENESIS_HASH
        ts = self._clock()
        text = _canonical(detail)
        conn.execute(
            "INSERT INTO audit (ts_us, action, detail, prev_hash, hash) VALUES (?,?,?,?,?)",
            (ts, action, text, prev, _hash(prev, ts, action, text)),
        )

    # -- case ------------------------------------------------------------------

    def init_case(self, name: str, analyst: str) -> None:
        with self._tx() as conn:
            conn.execute("INSERT INTO meta VALUES ('name', ?)", (name,))
            conn.execute("INSERT INTO meta VALUES ('analyst', ?)", (analyst,))
            conn.execute("INSERT INTO meta VALUES ('created_us', ?)", (str(self._clock()),))
            self._audit(conn, "case.created", {"name": name, "analyst": analyst})

    def meta(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    # -- evidence --------------------------------------------------------------

    def add_evidence(
        self,
        *,
        label: str,
        kind: str,
        filename: str,
        content: bytes,
        observations: Sequence[ObservationDraft],
        note: str = "",
    ) -> Evidence:
        """Store the original bytes and the facts parsed from them in one transaction."""
        if len(content) > MAX_EVIDENCE_BYTES:
            raise CaseError(f"{filename} is larger than {MAX_EVIDENCE_BYTES // 2**20} MiB")
        sha = hashlib.sha256(content).hexdigest()
        now = self._clock()
        try:
            with self._tx() as conn:
                cur = conn.execute(
                    "INSERT INTO evidence (label, kind, filename, sha256, size, imported_us, "
                    "note, content) VALUES (?,?,?,?,?,?,?,?)",
                    (label, kind, filename, sha, len(content), now, note, content),
                )
                evidence_id = int(cur.lastrowid or 0)
                conn.executemany(
                    "INSERT INTO observations (evidence_id, seq, kind, subject, summary, ts_us, "
                    "data) VALUES (?,?,?,?,?,?,?)",
                    [
                        (
                            evidence_id,
                            seq,
                            o.kind,
                            o.subject,
                            o.summary,
                            o.ts_us,
                            _canonical(o.data),
                        )
                        for seq, o in enumerate(observations, start=1)
                    ],
                )
                self._audit(
                    conn,
                    "evidence.imported",
                    {
                        "id": evidence_id,
                        "label": label,
                        "kind": kind,
                        "filename": filename,
                        "sha256": sha,
                        "size": len(content),
                        "observations": len(observations),
                    },
                )
        except sqlite3.IntegrityError as exc:
            raise CaseError(f"an evidence item labelled {label!r} already exists") from exc
        return self.evidence(evidence_id)

    def evidence(self, evidence_id: int) -> Evidence:
        row = self._conn.execute(
            "SELECT id,label,kind,filename,sha256,size,imported_us,note FROM evidence WHERE id=?",
            (evidence_id,),
        ).fetchone()
        if row is None:
            raise CaseError(f"no evidence E{evidence_id}")
        return Evidence(*row)

    def evidence_by_ref(self, ref: str) -> Evidence:
        """Resolve ``E3`` or a label."""
        text = ref.strip()
        if len(text) > 1 and text[0] in "Ee" and text[1:].isdigit():
            return self.evidence(int(text[1:]))
        row = self._conn.execute("SELECT id FROM evidence WHERE label = ?", (text,)).fetchone()
        if row is None:
            raise CaseError(f"no evidence {ref!r}; list them with `casefile evidence`")
        return self.evidence(int(row[0]))

    def list_evidence(self) -> list[Evidence]:
        rows = self._conn.execute(
            "SELECT id,label,kind,filename,sha256,size,imported_us,note FROM evidence ORDER BY id"
        ).fetchall()
        return [Evidence(*r) for r in rows]

    def evidence_content(self, evidence_id: int) -> bytes:
        row = self._conn.execute(
            "SELECT content FROM evidence WHERE id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise CaseError(f"no evidence E{evidence_id}")
        return bytes(row[0])

    # -- observations ----------------------------------------------------------

    _OBS_COLS = "id,evidence_id,seq,kind,subject,summary,ts_us,data"

    @staticmethod
    def _obs(row: Sequence[Any]) -> Observation:
        return Observation(
            row[0], row[1], row[2], row[3], row[4], row[5], row[6], json.loads(row[7])
        )

    def observations(
        self,
        evidence_id: int,
        *,
        seq_from: int | None = None,
        seq_to: int | None = None,
        limit: int | None = None,
    ) -> list[Observation]:
        sql = f"SELECT {self._OBS_COLS} FROM observations WHERE evidence_id = ?"  # noqa: S608
        args: list[Any] = [evidence_id]
        if seq_from is not None:
            sql += " AND seq >= ?"
            args.append(seq_from)
        if seq_to is not None:
            sql += " AND seq <= ?"
            args.append(seq_to)
        sql += " ORDER BY seq"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(limit)
        return [self._obs(r) for r in self._conn.execute(sql, args)]

    def count_observations(self, evidence_id: int, seq_from: int | None, seq_to: int | None) -> int:
        sql = "SELECT COUNT(*) FROM observations WHERE evidence_id = ?"
        args: list[Any] = [evidence_id]
        if seq_from is not None:
            sql += " AND seq >= ?"
            args.append(seq_from)
        if seq_to is not None:
            sql += " AND seq <= ?"
            args.append(seq_to)
        return int(self._conn.execute(sql, args).fetchone()[0])

    def search(
        self,
        term: str,
        *,
        evidence_id: int | None = None,
        since_us: int | None = None,
        until_us: int | None = None,
        limit: int = 200,
    ) -> list[Observation]:
        """Case-insensitive substring search over subject and summary."""
        like = f"%{_like_escape(term)}%"
        sql = (
            f"SELECT {self._OBS_COLS} FROM observations "  # noqa: S608
            "WHERE (subject LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\')"
        )
        args: list[Any] = [like, like]
        if evidence_id is not None:
            sql += " AND evidence_id = ?"
            args.append(evidence_id)
        if since_us is not None:
            sql += " AND ts_us >= ?"
            args.append(since_us)
        if until_us is not None:
            sql += " AND ts_us <= ?"
            args.append(until_us)
        sql += " ORDER BY evidence_id, seq LIMIT ?"
        args.append(limit)
        return [self._obs(r) for r in self._conn.execute(sql, args)]

    # -- findings --------------------------------------------------------------

    def add_finding(self, title: str, statement: str, severity: str) -> Finding:
        if severity not in SEVERITIES:
            raise CaseError(f"severity must be one of {', '.join(SEVERITIES)}")
        if not title.strip() or not statement.strip():
            raise CaseError("a finding needs a title and a statement of what happened")
        now = self._clock()
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO findings (title, statement, severity, status, created_us, "
                "updated_us) VALUES (?,?,?,?,?,?)",
                (title.strip(), statement.strip(), severity, STATUS_HYPOTHESIS, now, now),
            )
            fid = int(cur.lastrowid or 0)
            self._audit(
                conn,
                "finding.added",
                {"id": fid, "title": title.strip(), "severity": severity},
            )
        return self.finding(fid)

    def finding(self, finding_id: int) -> Finding:
        row = self._conn.execute(
            "SELECT id,title,statement,severity,status,created_us,updated_us FROM findings "
            "WHERE id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            raise CaseError(f"no finding F{finding_id}")
        return Finding(*row)

    def list_findings(self) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT id,title,statement,severity,status,created_us,updated_us FROM findings "
            "ORDER BY id"
        ).fetchall()
        return [Finding(*r) for r in rows]

    def set_status(self, finding_id: int, status: str, reason: str = "") -> Finding:
        if status not in STATUSES:
            raise CaseError(f"status must be one of {', '.join(STATUSES)}")
        current = self.finding(finding_id)
        if status == STATUS_SUPPORTED and not any(
            link.role == ROLE_SUPPORTS for link in self.links(finding_id)
        ):
            raise CaseError(
                f"F{finding_id} has no supporting evidence; link some with "
                f"`casefile link F{finding_id} <evidence> --role supports` first"
            )
        with self._tx() as conn:
            conn.execute(
                "UPDATE findings SET status = ?, updated_us = ? WHERE id = ?",
                (status, self._clock(), finding_id),
            )
            self._audit(
                conn,
                "finding.status",
                {"id": finding_id, "from": current.status, "to": status, "reason": reason},
            )
        return self.finding(finding_id)

    # -- links -----------------------------------------------------------------

    def add_link(
        self,
        finding_id: int,
        evidence_id: int,
        *,
        role: str,
        seq_from: int | None = None,
        seq_to: int | None = None,
        note: str = "",
    ) -> Link:
        if role not in ROLES:
            raise CaseError(f"role must be one of {', '.join(ROLES)}")
        self.finding(finding_id)
        self.evidence(evidence_id)
        if (seq_from is None) != (seq_to is None):
            raise CaseError("give both ends of a range, or neither")
        if seq_from is not None and seq_to is not None:
            if seq_from < 1 or seq_to < seq_from:
                raise CaseError("a range must be 1 or higher and end at or after its start")
            found = self.count_observations(evidence_id, seq_from, seq_to)
            if found != seq_to - seq_from + 1:
                raise CaseError(
                    f"E{evidence_id} has only {found} of the {seq_to - seq_from + 1} "
                    f"observations in {seq_from}-{seq_to}"
                )
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO links (finding_id, evidence_id, seq_from, seq_to, role, note) "
                "VALUES (?,?,?,?,?,?)",
                (finding_id, evidence_id, seq_from, seq_to, role, note),
            )
            lid = int(cur.lastrowid or 0)
            conn.execute(
                "UPDATE findings SET updated_us = ? WHERE id = ?", (self._clock(), finding_id)
            )
            self._audit(
                conn,
                "link.added",
                {
                    "id": lid,
                    "finding": finding_id,
                    "evidence": evidence_id,
                    "from": seq_from,
                    "to": seq_to,
                    "role": role,
                },
            )
        return Link(lid, finding_id, evidence_id, seq_from, seq_to, role, note)

    def links(self, finding_id: int) -> list[Link]:
        rows = self._conn.execute(
            "SELECT id,finding_id,evidence_id,seq_from,seq_to,role,note FROM links "
            "WHERE finding_id = ? ORDER BY id",
            (finding_id,),
        ).fetchall()
        return [Link(*r) for r in rows]

    def remove_link(self, link_id: int) -> None:
        row = self._conn.execute(
            "SELECT finding_id, role FROM links WHERE id = ?", (link_id,)
        ).fetchone()
        if row is None:
            raise CaseError(f"no link L{link_id}")
        finding = self.finding(int(row[0]))
        remaining_support = (
            self._conn.execute(
                "SELECT COUNT(*) FROM links WHERE finding_id = ? AND role = ? AND id != ?",
                (finding.id, ROLE_SUPPORTS, link_id),
            ).fetchone()[0]
            if row[1] == ROLE_SUPPORTS
            else 1
        )
        if finding.status == STATUS_SUPPORTED and remaining_support == 0:
            raise CaseError(
                f"L{link_id} is the last support for F{finding.id}, which is marked supported; "
                f"change its status first"
            )
        with self._tx() as conn:
            conn.execute("DELETE FROM links WHERE id = ?", (link_id,))
            self._audit(conn, "link.removed", {"id": link_id, "finding": finding.id})

    # -- unknowns --------------------------------------------------------------

    def add_unknown(self, text: str, finding_id: int | None = None) -> Unknown:
        if not text.strip():
            raise CaseError("describe what is unknown")
        if finding_id is not None:
            self.finding(finding_id)
        with self._tx() as conn:
            cur = conn.execute(
                "INSERT INTO unknowns (finding_id, text) VALUES (?, ?)", (finding_id, text.strip())
            )
            uid = int(cur.lastrowid or 0)
            self._audit(conn, "unknown.added", {"id": uid, "finding": finding_id})
        return Unknown(uid, finding_id, text.strip(), False, "")

    def resolve_unknown(self, unknown_id: int, resolution: str) -> None:
        if not resolution.strip():
            raise CaseError("say how it was resolved")
        with self._tx() as conn:
            cur = conn.execute(
                "UPDATE unknowns SET resolved = 1, resolution = ? WHERE id = ?",
                (resolution.strip(), unknown_id),
            )
            if cur.rowcount == 0:
                raise CaseError(f"no unknown U{unknown_id}")
            self._audit(conn, "unknown.resolved", {"id": unknown_id})

    def unknowns(self, finding_id: int | None = None, *, scope: str = "finding") -> list[Unknown]:
        """``scope='finding'`` returns one finding's unknowns; ``'case'`` those with none."""
        if scope == "case":
            rows = self._conn.execute(
                "SELECT id,finding_id,text,resolved,resolution FROM unknowns "
                "WHERE finding_id IS NULL ORDER BY id"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT id,finding_id,text,resolved,resolution FROM unknowns "
                "WHERE finding_id = ? ORDER BY id",
                (finding_id,),
            ).fetchall()
        return [Unknown(r[0], r[1], r[2], bool(r[3]), r[4]) for r in rows]

    # -- audit and verification ------------------------------------------------

    def audit_rows(self) -> list[tuple[int, int, str, str, str]]:
        rows = self._conn.execute("SELECT id,ts_us,action,detail,hash FROM audit ORDER BY id")
        return [(r[0], r[1], r[2], r[3], r[4]) for r in rows]

    def head(self) -> str:
        row = self._conn.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS_HASH

    def verify(self, expected_head: str | None = None) -> VerifyResult:
        problems: list[str] = []
        prev = GENESIS_HASH
        expected_id = 1
        imported: dict[int, str] = {}
        count = 0
        for rid, ts, action, detail, prev_hash, digest in self._conn.execute(
            "SELECT id,ts_us,action,detail,prev_hash,hash FROM audit ORDER BY id"
        ).fetchall():
            count += 1
            if rid != expected_id:
                problems.append(f"audit row {expected_id} is missing (found {rid})")
                expected_id = rid
            expected_id += 1
            if prev_hash != prev:
                problems.append(f"audit row {rid} does not follow the previous row")
            if _hash(prev_hash, ts, action, detail) != digest:
                problems.append(f"audit row {rid} was altered")
            prev = digest
            if action == "evidence.imported":
                try:
                    info = json.loads(detail)
                    imported[int(info["id"])] = str(info["sha256"])
                except (ValueError, KeyError, TypeError):
                    problems.append(f"audit row {rid} has an unreadable import record")
        if expected_head is not None and expected_head != prev:
            problems.append(
                "the audit head does not match the recorded anchor "
                "(trailing rows were removed, or the case was changed since)"
            )
        for ev in self.list_evidence():
            actual = hashlib.sha256(self.evidence_content(ev.id)).hexdigest()
            if actual != ev.sha256:
                problems.append(f"E{ev.id} ({ev.label}): content does not match its stored hash")
            if imported.get(ev.id) != ev.sha256:
                problems.append(f"E{ev.id} ({ev.label}): hash differs from the audit record")
        for missing in set(imported) - {e.id for e in self.list_evidence()}:
            problems.append(f"E{missing} was imported but is no longer in the case")
        return VerifyResult(not problems, count, prev, problems)


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
