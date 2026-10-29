from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path

import pytest

from casefile.model import ObservationDraft
from casefile.store import CaseStore


def make_clock(start: int = 1_793_300_000_000_000, step: int = 1_000_000) -> Callable[[], int]:
    counter = itertools.count(start, step)
    return lambda: next(counter)


@pytest.fixture
def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    with CaseStore(tmp_path / "t.casefile", create=True, clock=make_clock()) as s:
        s.init_case("Test case", "tester")
        yield s


def drafts(*lines: str) -> list[ObservationDraft]:
    return [
        ObservationDraft("log", "log", line, 1_793_300_000_000_000 + i)
        for i, line in enumerate(lines)
    ]
