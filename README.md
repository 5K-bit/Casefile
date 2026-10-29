<div align="center">

<img src="assets/brand/github-banner.svg" alt="Casefile — Cybersecurity investigation desk" width="1200">

**Cybersecurity investigation desk. What happened, what supports the conclusion, and what is still unknown.**

[![CI](https://img.shields.io/github/actions/workflow/status/5K-bit/casefile/ci.yml?branch=main&style=for-the-badge&label=CI&labelColor=150f2b&color=a78bfa)](https://github.com/5K-bit/casefile/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-c4b5fd?style=for-the-badge&logo=python&logoColor=white&labelColor=150f2b)
![Dependencies](https://img.shields.io/badge/runtime%20dependencies-none-a78bfa?style=for-the-badge&labelColor=150f2b)
![Local first](https://img.shields.io/badge/local--first-no%20telemetry-a99fd1?style=for-the-badge&labelColor=150f2b)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-8fb4c4?style=for-the-badge&labelColor=150f2b)](LICENSE)

</div>

[Quick start](#quick-start) · [Demonstration](#demonstration) · [Tests](#tests-and-evidence) · [Limitations](#limitations)

---

## Overview

Casefile turns lab evidence into an investigation. You import **Nmap XML scans and text logs**, record **findings**, attach the exact evidence that **supports, contradicts or gives context** to each one, write down **what remains unknown**, and export a report anyone can check against the original files.

It answers three questions for every conclusion: **what happened, what supports it, and what is not known.**

Part of the OBEOS projects, and it works completely on its own. No server, no account, no network access; one SQLite file holds the case.

> **Authorised work only.** Casefile organises evidence you are entitled to analyse. It does not scan anything. Evidence is stored unaltered, so a case file contains whatever the logs contained (including secrets). Keep it private; reports redact quoted evidence by default. See [Limitations](#limitations).

## Demonstration

This is a real run on synthetic lab data (documentation-range addresses; the scan and logs in [`examples/lab`](examples/lab) are hand-written, not captured from a real network). An SSH password-guessing run ends in a login on `jump01`. The analyst records two findings; one is confirmed by the evidence and one is refuted by it. (Excerpt; full transcript in [docs/evidence](docs/evidence/).)

```text
$ casefile import examples/lab/auth.log --label jump01-auth --year 2026
E2 jump01-auth: log, 31 observations, sha256 ac5d0227c2543e7f…
$ casefile search "Accepted password"
E2:27  2026-10-29T18:15:05Z  Oct 29 18:15:05 jump01 sshd[2230]: Accepted password for admin from 203.0.113.50 port 40031 ssh2
$ casefile link F1 jump01-auth --lines 3-26 --note "24 failed attempts, one source"
$ casefile finding status F2 refuted --reason "attacker never touched the web server"
```

The report ([HTML](docs/evidence/acceptance-report.html) · [Markdown](docs/evidence/acceptance-report.md)) quotes the evidence it cites, keeps the contradicted claim visible, and ends each finding with what nobody knows yet:

```text
## F1: jump01 was brute-forced and an account was compromised
High · supported

### Supporting evidence
E1 scan-before, observation 3 — SSH is exposed on jump01
   3  2026-10-29T17:00:01Z  10.0.0.5:22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.6
E2 jump01-auth, observations 3-26 — 24 failed attempts, one source
   3  2026-10-29T18:14:02Z  Oct 29 18:14:02 jump01 sshd[2201]: Failed password for root from 203.0.113.50 …
   … 12 more in the evidence

### What remains unknown
- U1: How did the attacker get the admin password: guessed or reused?
- U2: What was done during the 42-second session beyond one sudo command?

## F2: web01 was the entry point
Medium · refuted
### Contradicting evidence
E3 web01-access, whole item — no request from 203.0.113.50 appears in the web log
```

Casefile refuses to mark a finding `supported` until some evidence supports it, and it flags a supported finding that has no contradicting evidence recorded. It does not decide what the evidence means; you do.

Reproduce it (after `pip install .`): `python examples/acceptance.py --out /tmp/evidence`.

## Quick start

**Requirements:** Python 3.11 or newer.

```bash
git clone https://github.com/5K-bit/casefile && cd casefile
pip install .                      # no other dependencies
casefile init "Case name"          # creates ./case.casefile
casefile import scan.xml           # Nmap XML (nmap -oX) or a text log; the kind is detected
casefile import auth.log --year 2026
```

Investigate:

```bash
casefile evidence                                   # what is in the case
casefile search "Failed password" --evidence auth   # find observations (E2:27 means evidence 2, observation 27)
casefile show auth --lines 20-40                    # read a stretch of an item

casefile finding add "SSH was brute-forced" --statement "24 failures from one address, then a login." --severity high
casefile link F1 auth --lines 3-26 --note "24 failed attempts"          # supports, by default
casefile link F2 web-access --role contradicts --note "no requests from the attacker"
casefile finding status F1 supported --reason "failures then success from one source"
casefile unknown add "Was the password guessed or reused?" --finding F1
```

Export and check:

```bash
casefile report --format html --out report.html     # also: md (default), json
casefile verify                                     # evidence hashes and audit chain; exit code 2 on failure
casefile status                                     # includes the audit head to record elsewhere
```

| Command | Purpose |
|---|---|
| `init NAME [--analyst]` | Create the case file (refuses to overwrite one) |
| `import FILE [--kind --label --note --year]` | Add evidence; nothing is stored if parsing fails |
| `evidence` / `show E [--lines]` / `search TERM [--evidence --since --until]` | Read evidence |
| `finding add/list/show/status` | Record and update claims |
| `link F E [--lines --role --note]` / `unlink L` | Tie evidence to a finding as `supports`, `contradicts` or `context` |
| `unknown add [--finding]` / `unknown resolve U --how` | Record what is not known |
| `report [--format --out --no-redact --max-quotes]` | Investigation report |
| `verify [--anchor HASH]` | Recompute hashes and the audit chain, and replay it against findings, links and unknowns |
| `status` | Counts and audit head |

`--case PATH` (or `$CASEFILE_PATH`) selects the case file; the default is `./case.casefile`. Exit codes: 0 ok, 1 error, 2 integrity failure.

## What it imports

- **Nmap XML** (`nmap -oX`): the scan, hosts, ports with services and versions, OS guesses and script output. XML that declares entities or an internal DTD is refused.
- **Text logs**: syslog, ISO-8601-prefixed lines and Apache/nginx access logs. Each non-empty line is an observation with its time when one can be read. Syslog has no year or zone, so the year is yours to give and times are taken as UTC.

## Architecture

```
Nmap XML ──┐
text logs ─┴─► importers ─► observations ─► CaseStore (one SQLite file)
 hostile        refuse or                     evidence (raw bytes + SHA-256, immutable)
 input          parse                         observations (immutable)
                                              findings · links · unknowns (audited)
                                              audit (append-only, hash-chained)
                                                   ├─► show · search
                                                   ├─► report ─► Markdown / HTML / JSON
                                                   └─► verify
```

Details: [docs/architecture.md](docs/architecture.md) · [threat model](docs/threat-model.md) · decisions in [docs/adr/](docs/adr/).

## Tests and evidence

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && mypy
python -m pytest --cov
```

The last recorded run (Linux, Python 3.13) is in [docs/evidence/test-run.txt](docs/evidence/test-run.txt). What each claim rests on:

| Claim | Evidence |
|---|---|
| Nmap hosts, ports, services, OS and scripts are parsed | [`tests/unit/test_nmap.py`](tests/unit/test_nmap.py) |
| Entity-expansion and DTD tricks in Nmap XML are refused; the DOCTYPE real Nmap writes is accepted | `test_nmap.py`, [`test_cli.py`](tests/integration/test_cli.py) |
| Syslog, ISO and access-log lines are parsed; binary, empty, oversized and malformed input is handled | [`tests/unit/test_logs.py`](tests/unit/test_logs.py) |
| Evidence and observations cannot be updated or deleted; edits to the audit log, forged evidence, removed rows and direct edits to findings, links or unknowns are detected | [`tests/unit/test_store.py`](tests/unit/test_store.py) |
| A finding cannot be marked supported without supporting evidence; links must name real observations | `test_store.py` |
| Reports match golden files; secrets are redacted by default; untrusted text is HTML-escaped | [`tests/unit/test_report.py`](tests/unit/test_report.py) with [golden files](tests/fixtures/) |
| The lab investigation produces the expected report end to end | [`tests/integration/test_acceptance.py`](tests/integration/test_acceptance.py), [evidence](docs/evidence/) |
| CLI behaviour and exit codes (0 ok, 1 error, 2 integrity) | [`tests/integration/test_cli.py`](tests/integration/test_cli.py) |
| 200,000 log lines import in a few seconds | [docs/evidence/scale.txt](docs/evidence/scale.txt) (one machine, one run) |

## Limitations

Casefile does not claim more than it has shown:

- **It does not run scans or decide anything.** It organises evidence you collected. Whether evidence supports a conclusion is your judgement; the tool only refuses a `supported` status with nothing behind it.
- **Tested on hand-written samples, not a corpus.** The importers are tested against synthetic Nmap XML and logs and hostile inputs. Real-world Nmap output (many hosts, unusual scans) and production logs may expose gaps. Send a sanitised sample if one fails.
- **Evidence is stored unredacted.** Redaction applies to report quotes only, and it is pattern-based and best-effort. Read a report before sharing it. The case file is created owner-only on POSIX; on Windows it follows the folder ACL.
- **Tamper evidence, not tamper proofing.** `verify` catches edits to evidence, findings, links, unknowns and history. Someone with write access can rebuild the chain, and removed trailing entries are only caught if you recorded the audit head elsewhere (`status`, then `verify --anchor`).
- **Whole files are read into memory.** Evidence is capped at 256 MiB and logs at 500,000 lines. Case files are about four times the size of the log they hold. Search is a substring scan, with no full-text index.
- **Times come from the source.** Syslog needs a year you supply and is assumed to be UTC. A source clock can be wrong.
- **Two input types only.** No PCAP, Sentinel, Zeek, JSON-log or Windows event log import yet; those are roadmap items.
- **Not yet verified on Windows by hand.** CI runs the tests on Windows. Nothing has been checked against a real Windows workflow.

## Roadmap

- [x] Nmap XML and text-log import, findings with linked evidence, unknowns, hash-chained audit, report export
- [ ] Run on GitHub CI (Linux and Windows) and confirm the matrix is green
- [ ] Import Sentinel scan results (optional OBEOS integration)
- [ ] JSON-lines and Windows Event Log importers
- [ ] Timeline view across evidence; case-wide search with time windows
- [ ] Sign a case with a key you hold; export a case without evidence bytes for sharing

## Development practice

AI tools assist with implementation, debugging, tests and documentation in this project.
Louis Boddie owns direction and acceptance decisions; the linked tests and [evidence](docs/evidence/) document what is verified.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE) © 5K-bit
