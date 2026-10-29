# Security Policy

## Intended use

Casefile organises evidence for investigations you are **authorised to conduct**: scans and logs from systems you own or have written permission to assess. It reads the files you import and stores them in a local SQLite case file. It makes no network connections and sends nothing anywhere.

## What Casefile protects, and what it does not

- **A case file holds raw evidence.** Imported files are stored unaltered, because altering evidence defeats its purpose. That means passwords, tokens and personal data in a log are in the case file. Keep it private (it is created owner-only on POSIX; on Windows access follows the folder ACL) and treat it like the logs themselves.
- **Reports are redacted by default.** Quoted evidence passes through pattern-based redaction. It is best-effort: a secret in an unrecognised format will be quoted. Read a report before you share it, and use `--no-redact` only for private copies.
- **Imported files are hostile input.** Nmap XML that declares entities or an internal DTD is refused by the XML parser itself, whatever the encoding (entity-expansion attacks), binary logs are refused, sizes and line counts are capped, and report HTML is escaped.
- **Tamper evidence, not tamper proofing.** Evidence hashes and a hash-chained audit log make edits to evidence, findings history or the audit log detectable with `casefile verify`. Someone with write access to the file can rebuild the chain. Record the audit head (`casefile status`) elsewhere and pass it to `casefile verify --anchor` to also detect removed trailing entries.
- **Casefile does not decide what evidence means.** It will not let you mark a finding `supported` without a supporting link, but it cannot tell whether your reading of the evidence is right.

The full analysis is in [docs/threat-model.md](docs/threat-model.md).

## Reporting a vulnerability

If you find a way to make a crafted Nmap or log file crash or stall Casefile or exhaust memory, inject script into a report, make `verify` pass on altered evidence, findings, links, unknowns or history, or leak secrets that redaction should have removed from a report, please report it privately through GitHub's **Security → Report a vulnerability** on this repository rather than a public issue.

Include the Casefile version (`casefile --version`), your OS and Python version, and the smallest input that reproduces it. Use synthetic data only; never attach real case files. Expect an initial response within a few days.
