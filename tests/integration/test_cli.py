from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from casefile.cli import main

LAB = Path(__file__).resolve().parents[2] / "examples" / "lab"


@pytest.fixture
def case(tmp_path: Path) -> str:
    path = str(tmp_path / "c.casefile")
    assert main(["--case", path, "init", "Case", "--analyst", "me"]) == 0
    return path


def run(case: str, *argv: str) -> int:
    return main(["--case", case, *argv])


def test_version_and_missing_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0 and "casefile" in capsys.readouterr().out
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_commands_need_an_existing_case(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--case", str(tmp_path / "none"), "status"]) == 1
    assert "casefile init" in capsys.readouterr().err


def test_init_refuses_to_overwrite(case: str, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(case, "init", "Again") == 1
    assert "already exists" in capsys.readouterr().err


def test_import_sniffs_kind_and_prints_summary(
    case: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(case, "import", str(LAB / "scan-before.xml")) == 0
    assert run(case, "import", str(LAB / "auth.log"), "--year", "2026") == 0
    out = capsys.readouterr().out
    assert "E1 scan-before: nmap, 8 observations" in out
    assert "E2 auth: log, 31 observations" in out
    assert run(case, "evidence") == 0


def test_duplicate_label_error_is_clear(case: str, capsys: pytest.CaptureFixture[str]) -> None:
    run(case, "import", str(LAB / "auth.log"))
    capsys.readouterr()
    assert run(case, "import", str(LAB / "auth.log")) == 1
    assert "already exists" in capsys.readouterr().err
    assert run(case, "import", str(LAB / "auth.log"), "--label", "second") == 0


@pytest.mark.parametrize("kind", ["nmap", "log"])
def test_bad_inputs_are_reported_not_raised(
    case: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], kind: str
) -> None:
    bad = tmp_path / "bad"
    bad.write_bytes(b"\x00\x01binary")
    assert run(case, "import", str(bad), "--kind", kind) == 1
    assert capsys.readouterr().err.startswith("casefile: ")
    assert run(case, "import", str(tmp_path)) == 1  # a directory
    assert "not a regular file" in capsys.readouterr().err
    assert run(case, "import", str(tmp_path / "missing")) == 1


def test_entity_bomb_is_refused_end_to_end(
    case: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bomb = tmp_path / "bomb.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><nmaprun>&a;</nmaprun>')
    assert run(case, "import", str(bomb)) == 1
    assert "entities" in capsys.readouterr().err
    assert run(case, "evidence") == 0
    assert capsys.readouterr().out == ""


def test_show_and_search(case: str, capsys: pytest.CaptureFixture[str]) -> None:
    run(case, "import", str(LAB / "auth.log"), "--year", "2026", "--label", "auth")
    capsys.readouterr()
    assert run(case, "show", "auth", "--lines", "27-28") == 0
    shown = capsys.readouterr().out
    assert "Accepted password for admin" in shown and shown.count("\n") == 2
    assert run(case, "search", "failed password", "--since", "2026-10-29T18:14:10Z") == 0
    captured = capsys.readouterr()
    assert "E1:" in captured.out and "match(es)" in captured.err
    assert run(case, "search", "x", "--evidence", "E9") == 1


def test_finding_flow_and_reference_parsing(case: str, capsys: pytest.CaptureFixture[str]) -> None:
    run(case, "import", str(LAB / "auth.log"), "--label", "auth")
    assert run(case, "finding", "add", "T", "--statement", "S", "--severity", "high") == 0
    assert run(case, "finding", "status", "F1", "supported") == 1  # no support yet
    assert "no supporting evidence" in capsys.readouterr().err
    assert run(case, "link", "1", "auth", "--lines", "3-4", "--note", "n") == 0  # bare number ok
    assert run(case, "link", "F1", "auth", "--lines", "oops") == 1
    assert run(case, "link", "Fx", "auth") == 1
    assert run(case, "finding", "status", "f1", "supported", "--reason", "r") == 0
    assert run(case, "unknown", "add", "Q?", "--finding", "F1") == 0
    assert run(case, "unknown", "add", "Case-wide") == 0
    assert run(case, "unknown", "resolve", "U1", "--how", "found it") == 0
    capsys.readouterr()
    assert run(case, "finding", "show", "F1") == 0
    out = capsys.readouterr().out
    assert "L1 supports" in out and "U1 resolved" in out
    assert run(case, "finding", "list") == 0
    assert run(case, "unlink", "L1") == 1  # last support of a supported finding
    assert run(case, "status") == 0
    assert "supported: 1" in capsys.readouterr().out


def test_report_formats_and_output_file(
    case: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    run(case, "import", str(LAB / "auth.log"), "--label", "auth")
    run(case, "finding", "add", "T", "--statement", "S")
    capsys.readouterr()
    assert run(case, "report") == 0
    assert capsys.readouterr().out.startswith("# Investigation report")
    for fmt, marker in (
        ("html", "<!doctype html>"),
        ("json", '"findings"'),
        ("md", "# Investigation"),
    ):
        out = tmp_path / f"r.{fmt}"
        assert run(case, "report", "--format", fmt, "--out", str(out)) == 0
        assert marker in out.read_text(encoding="utf-8")


def test_verify_exit_codes_and_report_exit_code_on_tampering(
    case: str, capsys: pytest.CaptureFixture[str]
) -> None:
    run(case, "import", str(LAB / "auth.log"), "--label", "auth")
    assert run(case, "verify") == 0
    head = next(
        line.split()[1] for line in capsys.readouterr().out.splitlines() if line.startswith("head:")
    )
    assert run(case, "verify", "--anchor", head) == 0
    assert run(case, "verify", "--anchor", "0" * 64) == 2
    conn = sqlite3.connect(case)
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit SET action = 'x' WHERE id = 1")
    conn.commit()
    conn.close()
    capsys.readouterr()
    assert run(case, "verify") == 2
    assert "integrity: FAILED" in capsys.readouterr().out
    assert run(case, "report") == 2


def test_environment_variable_selects_the_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "env.casefile"
    monkeypatch.setenv("CASEFILE_PATH", str(path))
    assert main(["init", "Env case"]) == 0 and path.exists()
    assert main(["status"]) == 0
