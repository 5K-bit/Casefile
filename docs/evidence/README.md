# Evidence

Everything in this folder was produced by running the code in this repository. Nothing is hand-edited.

| File | What it shows | How to reproduce |
|---|---|---|
| `acceptance-transcript.txt` | Every command of the lab investigation and its output | `python examples/acceptance.py --out docs/evidence` |
| `acceptance-report.md`, `.html` | The report that investigation produced | same command |
| `acceptance.casefile` | The case file from that run. Open it with any SQLite tool, or run `casefile --case docs/evidence/acceptance.casefile verify` | same command |
| `test-run.txt` | Full verbose test run with the coverage table | `python -m pytest -o addopts="" -v --cov --cov-report=term-missing` |
| `scale.txt` | Import, search and verify timings on a synthetic 200,000-line log | `python examples/scale.py --lines 200000 --out docs/evidence/scale.txt` |

## How to read the acceptance run

The inputs in `examples/lab/` are **synthetic**: documentation-range addresses and made-up hosts. The scan file is hand-written in Nmap's XML format (Nmap was not run to produce it), and the logs are hand-written in syslog and access-log format. The scenario: an SSH password-guessing run against `jump01` ends in a successful login. Two findings are recorded. One turns out to be supported (the SSH brute force) and one is refuted by the web server's log. Three unknowns are recorded, including whether the compromised host's clock is right.

The report's generation time is fixed so the output is reproducible. The audit entries in the transcript use the real clock, so the head hash differs on every run.

## What this evidence does not show

- Behaviour on real Nmap output from many hosts or unusual scan types, or on real production logs. The importers are tested against hand-written samples and hostile inputs, not a corpus.
- That the analysis in the lab is *correct*. It shows the tool carrying a conclusion, its evidence and its unknowns into a report, not that the conclusion is true.
- Behaviour on Windows locally. CI runs the tests on Windows; see the Actions tab.
- Memory use. The import reads the whole file; the scale run measured time and size only.
