# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `verify` now binds the analysis to the audit history. Audit records carry the complete finding, link, unknown and case-metadata values, and `verify` replays them and compares the result with the live tables, so a finding edited, injected, deleted or marked `supported` by direct database access fails verification. Evidence label, kind, filename, size and note are checked against the import record too. Case files created before this change do not verify; they were never released.
- Nmap XML entity and internal-DTD refusal is now enforced by the XML parser (expat) instead of a byte-pattern screen, so UTF-16 and other encodings can no longer hide a declaration. Encodings expat cannot decode are an import error, not a crash.
- The release workflow now runs the full CI suite on the tagged commit, requires the commit to be on `main`, builds and `twine check`s the distributions, installs only the built wheel into a clean environment, runs the lab investigation and the test suite against it, and only then publishes.

## [0.1.0] - 2026-10-29

First working version.

### Added

- Single-file case store: unaltered evidence with SHA-256, immutable parsed observations, a hash-chained audit log, and `casefile verify` with an external anchor.
- Importers for Nmap XML (hosts, ports and services, OS guesses, script output) and text logs (syslog, ISO-8601-prefixed, Apache/nginx access). Nmap files that declare entities or an internal DTD are refused.
- Findings with a status (`hypothesis`, `supported`, `refuted`, `inconclusive`), evidence links with a role (`supports`, `contradicts`, `context`) and optional observation ranges, and recorded unknowns. A finding cannot be marked `supported` without supporting evidence.
- Investigation report in Markdown, HTML and JSON: what happened, supporting and contradicting evidence quoted from the case, what remains unknown, an evidence register with hashes. Quotes are redacted by default.
- CLI: `init`, `import`, `evidence`, `show`, `search`, `finding`, `link`, `unlink`, `unknown`, `report`, `verify`, `status`.
