"""Tests for the repetition runner.

The repetition count is the evidence that both policies are stable rather than
coincidental, so the reported numbers — and the guard against a nonsensical
count — are asserted here.
"""

from __future__ import annotations

import pytest

from data_segregation_lab.batch import count_outcomes, main


def test_every_vulnerable_run_leaks_and_no_protected_run_does() -> None:
    assert count_outcomes(10) == (10, 0)


def test_each_repetition_uses_fresh_state() -> None:
    """Otherwise a single leaked run could carry into later iterations."""
    assert count_outcomes(1) == (1, 0)
    assert count_outcomes(3) == (3, 0)


def test_main_reports_both_policies(capsys: pytest.CaptureFixture[str]) -> None:
    main(["--repetitions", "4"])
    output = capsys.readouterr().out
    assert "Vulnerable path leaks: 4/4" in output
    assert "Protected path leaks:  0/4" in output
    assert "SYNTHETIC DATA ONLY" in output


def test_main_rejects_a_repetition_count_below_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit):
        main(["--repetitions", "0"])
    assert "at least 1" in capsys.readouterr().err
