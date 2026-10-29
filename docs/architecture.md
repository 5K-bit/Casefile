# Architecture

Casefile has three layers: **importers** that turn raw files into observations, a **store** that keeps evidence, findings and an audit trail in one SQLite file, and a **report** that reads the store. The CLI is a thin shell over them.

```
 Nmap XML ──┐
 text logs ─┴─► importers ─► observations ─► CaseStore (one SQLite file)
   hostile       refuse or      parsed facts     evidence (raw bytes + SHA-256, immutable)
   input         parse          with times       observations (immutable)
                                                 findings · links · unknowns (mutable, audited)
                                                 audit (append-only, hash-chained)
                                                      │
                          show · search · finding · link · unknown
                          report ──► Markdown / HTML / JSON
                          verify ──► recompute hashes and the chain, replay the log against the tables
```

## Modules

| Module | Responsibility |
|---|---|
| `importers/nmap.py` | Parse `nmap -oX`: scan, hosts, ports and services, OS guesses, script output. Refuses entity declarations and internal DTD subsets. |
| `importers/logs.py` | Parse syslog, ISO-8601-prefixed and access-log lines; one observation per non-empty line. |
| `store.py` | Schema, immutability triggers, audit chain, evidence/finding/link/unknown operations, search, `verify`. |
| `report.py` | Build the report data, then render Markdown, HTML and JSON. Pure function of the case and a timestamp. |
| `redact.py` | Pattern-based secret redaction for quoted evidence in reports. |
| `cli.py` | Argument parsing and printing only. |

The core has no third-party dependencies.

## Data model

| Table | Mutable? | Meaning |
|---|---|---|
| `evidence` | no | One imported file: label, kind, name, SHA-256, size, import time, the original bytes. |
| `observations` | no | Facts parsed from evidence, numbered `seq` within it, with a time when known. |
| `findings` | yes, audited | A claim: title, statement, severity, status. |
| `links` | yes, audited | Ties a finding to an evidence item or a range of its observations, as `supports`, `contradicts` or `context`. |
| `unknowns` | yes, audited | What is not known: per finding, or case-wide. Can be resolved with an explanation. |
| `audit` | append-only | Every change, chained: `hash = SHA-256(prev_hash ‖ time ‖ action ‖ detail)`. |

Evidence import is one transaction: original bytes, parsed observations and the audit entry commit together or not at all.

## How a conclusion is kept honest

- A finding starts as a `hypothesis`.
- `supported` needs at least one `supports` link, and the last supporting link of a supported finding cannot be removed until the status changes.
- Links name real observations: a range must exist in the evidence.
- The report quotes the linked observations verbatim (redacted), shows contradicting evidence next to supporting evidence, flags a supported finding with no contradicting evidence recorded, and lists what remains unknown.

## Time

Each observation carries a time only when its source has one. Syslog lines have no year or zone, so the importer takes the year you give (`--year`, default the current year) and assumes UTC; those observations record that in their data. Access-log and ISO times keep their own offset and are shown in UTC. Times come from the source system's clock, which may be wrong; record that as an unknown when it matters.

## Writing an importer

An importer is a function `bytes -> list[ObservationDraft]` that raises `ImportFailure` for input it will not accept.

```python
from casefile.importers.errors import ImportFailure
from casefile.model import ObservationDraft


def parse_hosts_file(content: bytes) -> list[ObservationDraft]:
    if b"\x00" in content:
        raise ImportFailure("binary file")
    drafts = []
    for line in content.decode("utf-8", errors="replace").splitlines():
        parts = line.split("#")[0].split()
        if len(parts) >= 2:
            drafts.append(
                ObservationDraft("hosts", parts[0], line.strip(), None, {"names": parts[1:]})
            )
    return drafts
```

Register the kind in `model.py` and `importers/__init__.py`, then add tests: a normal file, an empty one, a hostile one (huge, binary, malformed) and a timestamp case.
