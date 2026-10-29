# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-29

First working version.

### Added

- Single-file case store: unaltered evidence with SHA-256, immutable parsed observations, a hash-chained audit log, and `casefile verify` with an external anchor.
- Importers for Nmap XML (hosts, ports and services, OS guesses, script output) and text logs (syslog, ISO-8601-prefixed, Apache/nginx access). Nmap files that declare entities or an internal DTD are refused.
- Findings with a status (`hypothesis`, `supported`, `refuted`, `inconclusive`), evidence links with a role (`supports`, `contradicts`, `context`) and optional observation ranges, and recorded unknowns. A finding cannot be marked `supported` without supporting evidence.
- Investigation report in Markdown, HTML and JSON: what happened, supporting and contradicting evidence quoted from the case, what remains unknown, an evidence register with hashes. Quotes are redacted by default.
- CLI: `init`, `import`, `evidence`, `show`, `search`, `finding`, `link`, `unlink`, `unknown`, `report`, `verify`, `status`.
