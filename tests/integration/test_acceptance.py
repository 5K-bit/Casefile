"""The lab investigation, end to end through the real command line."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ACCEPTANCE = Path(__file__).resolve().parents[2] / "examples" / "acceptance.py"


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("acceptance", ACCEPTANCE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["acceptance"] = module
    spec.loader.exec_module(module)
    return module.run_scenario(tmp_path_factory.mktemp("acceptance"))


def test_the_supported_finding_cites_scan_and_log_evidence(result) -> None:  # type: ignore[no-untyped-def]
    md = result.markdown
    f1 = md.split("## F1:")[1].split("## F2:")[0]
    assert "supported" in f1
    assert "E1 scan-before" in f1 and "E2 jump01-auth" in f1
    assert "10.0.0.5:22/tcp open ssh OpenSSH" in f1
    assert "Accepted password for admin from 203.0.113.50" in f1
    assert "… 12 more in the evidence" in f1  # 24 failures, 12 quoted


def test_the_wrong_hypothesis_ends_up_refuted_by_evidence(result) -> None:  # type: ignore[no-untyped-def]
    f2 = result.markdown.split("## F2:")[1].split("## Open questions")[0]
    assert "refuted" in f2 and "### Contradicting evidence" in f2
    assert "E3 web01-access" in f2 and "None linked." in f2


def test_unknowns_are_reported_and_not_hidden(result) -> None:  # type: ignore[no-untyped-def]
    md = result.markdown
    assert "guessed or reused?" in md and "42-second session" in md
    assert "Is the clock on jump01 correct?" in md


def test_integrity_verifies_and_evidence_is_registered_with_hashes(result) -> None:  # type: ignore[no-untyped-def]
    assert "Case integrity: verified" in result.markdown
    assert result.markdown.count("`") >= 6 and "| E3 | web01-access | log |" in result.markdown
    assert "integrity: OK" in result.transcript


def test_transcript_never_leaks_the_scratch_directory(result) -> None:  # type: ignore[no-untyped-def]
    assert str(result.workdir) not in result.transcript
