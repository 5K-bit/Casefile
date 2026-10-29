# ADR 0001: One SQLite file per case, with a hash-chained audit log

Status: accepted

## Context

An investigation needs its evidence, parsed facts, conclusions and history to travel together, and to be checkable later. Analysts work offline and on their own machines.

## Decision

A case is one SQLite file holding the original evidence bytes, the parsed observations, the findings and an audit log. Evidence and observations are immutable (triggers). Every change is appended to an audit log where each row's hash covers the previous row's. The evidence hash is recorded in the audit log at import.

## Consequences

- A case can be copied, archived or handed over as a single file, and `verify` works anywhere.
- Edits to evidence or history are detectable. This is tamper evidence only; an anchor stored elsewhere extends it to truncation.
- The case is larger than its inputs (about four times the raw log, see `docs/evidence/scale.txt`) because observations repeat the text for searching.
- Unredacted evidence lives in the file, so the file must be kept private.
