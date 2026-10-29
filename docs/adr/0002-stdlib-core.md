# ADR 0002: Standard-library core

Status: accepted

## Context

Investigation tools run on locked-down or offline machines, and every dependency is attack surface and install friction.

## Decision

The runtime has no third-party dependencies: `sqlite3`, `xml.etree`, `argparse`, `hashlib`. Development tools (pytest, ruff, mypy) are in the `dev` extra.

## Consequences

- `pip install .` works offline once the wheel is available.
- XML parsing uses the standard library, so hostile XML is screened before it is parsed (ADR 0003 covers the policy).
- Search is a substring scan, not full-text search. This is fast enough at the sizes measured and keeps the schema simple.
