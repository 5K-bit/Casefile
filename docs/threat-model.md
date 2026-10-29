# Threat model

Casefile is a local tool that reads evidence files and writes one case file. This document lists what it protects, what it treats as hostile, and what remains your responsibility. Each mitigation points at the test that exercises it.

## Assets

1. **Integrity of the evidence and the analysis.** A conclusion is only as good as the record behind it.
2. **Confidentiality of evidence.** Logs and scans contain credentials, hostnames and personal data.
3. **Availability of the analyst's machine.** A crafted file must not hang or exhaust it.
4. **Honesty of the report.** It should not state more than the evidence supports.

## Trust boundaries

| Boundary | Trusted | Untrusted |
|---|---|---|
| Imported files | Nothing they contain | Size, encoding, structure, XML features, content |
| The case file | The Casefile process | Other local users; anyone with file access (tamper evidence only) |
| Reports | Casefile's escaping | Every string that came from evidence or analyst input |

## Threats and mitigations

| # | Threat | Mitigation | Evidence | Residual risk |
|---|---|---|---|---|
| 1 | Crafted Nmap XML exhausts memory with entity expansion | Expat itself refuses entity declarations, internal DTD subsets and external entity references in a handler-only pass before the tree is built, so the encoding (UTF-16 included) cannot hide them; the bare `<!DOCTYPE nmaprun>` real Nmap writes is accepted | `tests/unit/test_nmap.py` (entity, case-insensitive, internal subset, bare DOCTYPE, UTF-16 and Latin-1 documents, undecodable encodings), `tests/integration/test_cli.py::test_entity_bomb_is_refused_end_to_end` | Standard-library XML parsing is not hardened against every exotic input. A very large well-formed file is bounded only by the 256 MiB evidence cap and available memory. |
| 2 | A binary, oversized or malformed log stalls or crashes the importer | NUL bytes refused; invalid UTF-8 replaced, not raised; 500,000-line cap; summaries clipped at 1,000 characters; impossible dates keep the line without a time | `tests/unit/test_logs.py`, `test_cli.py::test_bad_inputs_are_reported_not_raised` | The whole file is read into memory before parsing. |
| 3 | Evidence, findings history or the audit log is altered after the fact | Evidence and observations are immutable (triggers); SHA-256 per evidence item recorded in the audit chain; every change is chained with its complete values; `verify` recomputes the chain and the evidence hashes, then replays the log and compares the rebuilt findings, links, unknowns and case metadata with the live tables; `--anchor` detects removed trailing entries | `tests/unit/test_store.py` (edited and deleted audit rows, forged evidence with rewritten hash column, deleted evidence, truncated tail with and without anchor, and direct edits, injections and deletions of findings, links, unknowns and metadata) | Tamper **evidence**, not proofing. Finding `updated_us` timestamps and the parsed `observations` rows are protected by triggers but not replayed against the audit log (observations can be re-derived from the hashed evidence bytes). Someone with write access can drop the triggers and rebuild the chain; the anchor must be stored elsewhere. |
| 4 | A secret in evidence is shared through a report | Quotes are redacted by default; `--no-redact` is explicit and the report says so | `tests/unit/test_report.py::test_secrets_are_redacted_in_quotes_by_default`, `test_timeparse_redact.py` | Redaction is pattern-based; the case file itself stores evidence unredacted by design. |
| 5 | Script injection through a report | All dynamic text is HTML-escaped; the page is self-contained (no scripts, links or external resources) | `test_report.py::test_html_escapes_untrusted_evidence_and_text` | Markdown output is plain text and is not sanitised for renderers that run embedded HTML. |
| 6 | Another local user reads the case file | Created owner-only (mode 0600) before SQLite opens it, so the -wal/-shm files inherit it | `test_store.py::test_case_file_and_sidecars_are_owner_only` | POSIX only. On Windows, access follows the folder ACL. |
| 7 | A finding is declared proven without evidence | `supported` is refused without a supporting link; the last support cannot be removed from a supported finding; link ranges must name real observations; reports flag a supported finding with no contradicting evidence | `test_store.py` (support gate, last-support gate, range validation), `test_report.py` (caveats) | The tool cannot judge whether evidence really supports a claim. |
| 8 | Wrong or ambiguous times mislead the timeline | Times only where the source has them; syslog year and zone assumptions are recorded per observation; the report shows source times in UTC | `test_logs.py` (year, zone, invalid dates) | A source clock can be wrong; record it as an unknown. |
| 9 | A path argument reads or overwrites something unintended | Evidence files must be regular files; `init` refuses to overwrite an existing case; `report --out` writes only the path you name | `test_cli.py` (directory, missing file, overwrite) | `report --out` will overwrite a file you name. |
| 10 | Accidental network egress | The code makes no network calls and has no telemetry | Code review of `src/` (no network module imported); stdlib-only core | Not enforced by a test. |

## Out of scope for v0.1

- Chain of custody before import. Casefile proves what was imported and that it has not changed since, not that the file was genuine when you received it.
- A hostile local administrator or kernel.
- Multi-analyst access control, signing, or remote storage. A case is one file you control.
- Authorisation. You are responsible for only importing evidence you may analyse.
