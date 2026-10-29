# Contributing

Thanks for your interest in Casefile.

## Ways to help

- Report bugs, especially real-world Nmap XML or log formats that import wrongly (send a **sanitised** sample).
- Add an importer (see [docs/architecture.md](docs/architecture.md#writing-an-importer)).
- Improve report output, redaction patterns or docs.

## Development

```bash
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check .
mypy
python -m pytest --cov                            # must pass before you open a PR
python examples/acceptance.py --out /tmp/evidence # the lab investigation end to end
```

## Guidelines

- The core uses only the Python standard library.
- No network calls. Casefile reads files and writes a case file.
- Importers treat every file as hostile: size limits, no `eval`, refuse anything that can expand or execute, never read a file the user did not name.
- Evidence is stored unaltered and is immutable. Redaction applies only to what leaves the case in a report.
- Changing a report format? Regenerate the golden files with `UPDATE_GOLDEN=1 python -m pytest tests/unit/test_report.py` and review the diff.
- Test data must be synthetic: documentation address ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and made-up hosts. Never commit real evidence.
- Do not add claims (performance, platform support, security) that a test or recorded evidence does not back up.
- Use clear commit messages and keep pull requests focused.
