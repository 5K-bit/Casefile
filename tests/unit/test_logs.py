from __future__ import annotations

import pytest

from casefile.importers.logs import MAX_LINES, MAX_SUMMARY, LogError, parse_log
from casefile.timeparse import iso


def one(line: str, year: int = 2026):  # type: ignore[no-untyped-def]
    return parse_log(line.encode(), year=year)[0]


def test_syslog_line_gets_time_host_and_program() -> None:
    o = one("Oct 29 18:14:02 jump01 sshd[2201]: Failed password for root from 1.2.3.4")
    assert iso(o.ts_us or 0) == "2026-10-29T18:14:02Z"
    assert o.subject == "jump01 sshd"
    assert o.data["year_assumed"] == 2026 and o.data["zone_assumed"] == "UTC"


def test_syslog_single_digit_day() -> None:
    assert iso(one("Oct  3 01:02:03 h p: x").ts_us or 0) == "2026-10-03T01:02:03Z"


def test_impossible_syslog_date_keeps_the_line_without_a_time() -> None:
    o = one("Feb 30 01:02:03 h p: x")
    assert o.ts_us is None and o.subject == "h p"


def test_access_log_line_uses_client_address_and_zone() -> None:
    o = one('198.51.100.7 - - [29/Oct/2026:18:11:40 +0200] "GET / HTTP/1.1" 200 1')
    assert o.subject == "198.51.100.7"
    assert iso(o.ts_us or 0) == "2026-10-29T16:11:40Z"


def test_iso_prefixed_lines_with_and_without_zone() -> None:
    assert iso(one("2026-10-29T18:00:00Z service started").ts_us or 0) == "2026-10-29T18:00:00Z"
    assert iso(one("2026-10-29 18:00:00 service started").ts_us or 0) == "2026-10-29T18:00:00Z"
    assert iso(one("2026-10-29T18:00:00+02:00 x").ts_us or 0) == "2026-10-29T16:00:00Z"


def test_invalid_iso_and_clf_times_are_kept_without_a_time() -> None:
    assert one("2026-13-45T99:99:99Z x").ts_us is None
    assert one('1.2.3.4 - - [31/Feb/2026:00:00:00 +0000] "x"').ts_us is None


def test_unrecognised_lines_are_kept_as_is() -> None:
    o = one("just some text")
    assert (o.ts_us, o.subject, o.summary) == (None, "log", "just some text")


def test_blank_lines_are_skipped_but_original_line_numbers_are_kept() -> None:
    obs = parse_log(b"a\n\n  \nb\n")
    assert [o.summary for o in obs] == ["a", "b"]
    assert [o.data["line"] for o in obs] == [1, 4]


def test_crlf_and_invalid_utf8_do_not_fail() -> None:
    obs = parse_log(b"one\r\ntwo \xff\xfe bytes\r\n")
    assert len(obs) == 2 and "\r" not in obs[0].summary


def test_very_long_lines_are_clipped_in_the_summary_only() -> None:
    o = one("x" * (MAX_SUMMARY + 500))
    assert len(o.summary) == MAX_SUMMARY + 1 and o.summary.endswith("…")


def test_binary_empty_and_oversized_logs_are_refused() -> None:
    with pytest.raises(LogError, match="binary"):
        parse_log(b"abc\x00def")
    with pytest.raises(LogError, match="no lines"):
        parse_log(b"\n\n")
    with pytest.raises(LogError, match="more than"):
        parse_log(b"x\n" * (MAX_LINES + 1))


def test_year_defaults_to_the_current_year() -> None:
    o = parse_log(b"Jan  1 00:00:00 h p: x")[0]
    assert (o.ts_us or 0) > 0
