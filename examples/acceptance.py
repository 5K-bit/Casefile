"""Run the lab investigation end to end and write the evidence files.

The inputs in ``examples/lab`` are synthetic (documentation-range addresses). The
scenario: an SSH password-guessing run against ``jump01`` ends in a successful login.
An analyst imports a scan and two logs, records two findings (one turns out to be
wrong), links evidence, records what is unknown, and exports a report.

    python examples/acceptance.py --out docs/evidence
"""

from __future__ import annotations

import argparse
import contextlib
import io
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from casefile.cli import main  # noqa: E402

LAB = ROOT / "examples" / "lab"
GENERATED_US = 1793304000 * 1_000_000  # fixed, so the report is reproducible

STEPS: list[list[str]] = [
    ["init", "Lab incident: jump01", "--analyst", "5K"],
    ["import", "{lab}/scan-before.xml", "--label", "scan-before", "--note", "nmap -sV, 17:00 UTC"],
    ["import", "{lab}/auth.log", "--label", "jump01-auth", "--year", "2026"],
    ["import", "{lab}/web-access.log", "--label", "web01-access", "--year", "2026"],
    ["search", "Failed password", "--evidence", "jump01-auth", "--limit", "3"],
    ["search", "Accepted password"],
    [
        "finding",
        "add",
        "jump01 was brute-forced and an account was compromised",
        "--statement",
        "203.0.113.50 made 24 failed SSH password attempts against jump01 in about 50 "
        "seconds, then logged in as admin with a password.",
        "--severity",
        "high",
    ],
    [
        "finding",
        "add",
        "web01 was the entry point",
        "--statement",
        "The attacker got in through the web server on 10.0.0.9.",
        "--severity",
        "medium",
    ],
    ["link", "F1", "scan-before", "--lines", "3", "--note", "SSH is exposed on jump01"],
    ["link", "F1", "jump01-auth", "--lines", "3-26", "--note", "24 failed attempts, one source"],
    ["link", "F1", "jump01-auth", "--lines", "27-28", "--note", "then a successful login"],
    [
        "link",
        "F2",
        "scan-before",
        "--lines",
        "6-8",
        "--role",
        "context",
        "--note",
        "port 80 is open",
    ],
    [
        "link",
        "F2",
        "web01-access",
        "--role",
        "contradicts",
        "--note",
        "no request from 203.0.113.50 appears in the web log",
    ],
    ["finding", "status", "F1", "supported", "--reason", "failures then success from one source"],
    ["finding", "status", "F2", "refuted", "--reason", "attacker never touched the web server"],
    [
        "unknown",
        "add",
        "How did the attacker get the admin password: guessed or reused?",
        "--finding",
        "F1",
    ],
    [
        "unknown",
        "add",
        "What was done during the 42-second session beyond one sudo command?",
        "--finding",
        "F1",
    ],
    ["unknown", "add", "Is the clock on jump01 correct? All times come from its own log."],
    ["finding", "list"],
    ["verify"],
]


@dataclass
class Result:
    workdir: Path
    case_path: Path
    transcript: str
    markdown: str
    html: str


def _run(argv: list[str]) -> tuple[int, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue() + err.getvalue()


def run_scenario(workdir: Path) -> Result:
    case = workdir / "lab.casefile"
    lines: list[str] = []
    for step in STEPS:
        argv = [a.replace("{lab}", str(LAB)) for a in step]
        shown = " ".join(f'"{a}"' if " " in a else a for a in step).replace("{lab}", "examples/lab")
        code, text = _run(["--case", str(case), *argv])
        lines.append(f"$ casefile {shown}")
        lines.extend(text.replace(str(workdir), ".").rstrip().splitlines())
        if code != 0:
            raise SystemExit(f"step failed ({code}): {shown}\n{text}")
    from casefile.report import build_report, render_html, render_markdown
    from casefile.store import CaseStore

    # A fixed clock makes the report text reproducible; the real run used the live clock.
    with CaseStore(case) as store:
        report = build_report(store, generated_us=GENERATED_US)
    md, page = render_markdown(report), render_html(report)
    return Result(workdir, case, "\n".join(lines) + "\n", md, page)


def main_cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        result = run_scenario(Path(tmp))
        (args.out / "acceptance-transcript.txt").write_text(result.transcript, encoding="utf-8")
        (args.out / "acceptance-report.md").write_text(result.markdown, encoding="utf-8")
        (args.out / "acceptance-report.html").write_text(result.html, encoding="utf-8")
        shutil.copy(result.case_path, args.out / "acceptance.casefile")
    print(f"wrote evidence to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
