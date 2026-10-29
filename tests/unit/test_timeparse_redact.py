from __future__ import annotations

import subprocess
import sys

import pytest

from casefile.redact import REDACTED, Redactor
from casefile.timeparse import TimeParseError, iso, parse_duration_us, parse_time_us

NOW = 1_793_300_000_000_000


def test_time_forms() -> None:
    assert parse_time_us("now", now_us=NOW) == NOW
    assert parse_time_us("2h", now_us=NOW) == NOW - 7_200_000_000
    assert parse_time_us("1793300000", now_us=NOW) == NOW
    assert parse_time_us("2026-10-29T18:53:20Z", now_us=NOW) == NOW
    assert parse_time_us("2026-10-29T18:53:20", now_us=NOW) == NOW
    assert parse_duration_us("30m") == 1_800_000_000
    assert iso(NOW) == "2026-10-29T18:53:20Z"
    assert iso(NOW + 5_000, precision="milliseconds").endswith(".005Z")


@pytest.mark.parametrize("bad", ["yesterday", "5x", ""])
def test_bad_times_are_clear_errors(bad: str) -> None:
    with pytest.raises(TimeParseError):
        parse_time_us(bad, now_us=NOW)
    with pytest.raises(TimeParseError):
        parse_duration_us(bad)


def test_redaction_patterns() -> None:
    r = Redactor(extra_patterns=[r"badge-\d+"])
    cases = {
        'password="hunter2"': f'password="{REDACTED}"',
        "key AKIAABCDEFGHIJKLMNOP end": f"key {REDACTED} end",
        "https://user:pw@host/x": f"https://{REDACTED}@host/x",
        "id badge-4411": f"id {REDACTED}",
        f"token={REDACTED}": f"token={REDACTED}",
    }
    for text, expected in cases.items():
        assert r.redact(text) == expected
    assert "abcdefgh12345678" not in r.redact("Authorization: Bearer abcdefgh12345678")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
    assert "abc" not in r.redact(pem)
    assert r.redact("nothing secret here") == "nothing secret here"


def test_python_dash_m_runs_the_cli() -> None:
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "casefile", "--version"], capture_output=True, text=True, check=True
    )
    assert out.stdout.startswith("casefile ")
