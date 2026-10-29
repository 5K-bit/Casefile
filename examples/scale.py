"""Measure import, a full-scan search and verification on a synthetic syslog.

python examples/scale.py --lines 200000 --out docs/evidence/scale.txt
"""

from __future__ import annotations

import argparse
import contextlib
import io
import platform
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from casefile.cli import main  # noqa: E402


def quiet(*argv: str) -> float:
    start = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        main(list(argv))
    return time.perf_counter() - start


def run(lines: int) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        log, case = Path(tmp, "big.log"), Path(tmp, "big.casefile")
        log.write_text(
            "\n".join(
                f"Oct 29 18:{(i // 60) % 60:02d}:{i % 60:02d} host sshd[{i}]: "
                f"Failed password for u{i % 50} from 203.0.113.{i % 250} port {i % 60000} ssh2"
                for i in range(lines)
            ),
            encoding="utf-8",
        )
        base = ["--case", str(case)]
        quiet(*base, "init", "scale")
        t_import = quiet(*base, "import", str(log), "--year", "2026")
        t_search = quiet(*base, "search", "no-such-text-anywhere", "--limit", "1")
        t_verify = quiet(*base, "verify")
        return [
            f"python {platform.python_version()} on {platform.system()} {platform.machine()}",
            f"lines imported:          {lines:,}",
            f"log file:                {log.stat().st_size / 1e6:.1f} MB",
            f"case file:               {case.stat().st_size / 1e6:.1f} MB",
            f"import:                  {t_import:.1f} s",
            f"search (full scan, 0 hits): {t_search:.2f} s",
            f"verify:                  {t_verify:.2f} s",
        ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lines", type=int, default=200_000)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = "\n".join(run(args.lines)) + "\n"
    print(report, end="")
    if args.out:
        args.out.write_text(report, encoding="utf-8")
