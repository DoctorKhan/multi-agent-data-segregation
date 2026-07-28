"""Tests for backend selection — the control that keeps the lab offline.

The lab must never reach the network, spend credits, or read a real API key
unless the operator asks for it explicitly. That promise lives entirely in
``select_backend``, so it is asserted here rather than assumed from the CI
environment.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from data_segregation_lab.backends import DeterministicLLM, OpenRouterLLM
from data_segregation_lab.cli import main, main_ogi, select_backend


@pytest.fixture(autouse=True)
def isolate_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Run from a directory with no .env.openrouter and no inherited key."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


def test_no_arguments_selects_the_offline_backend() -> None:
    backend, notice = select_backend([])
    assert isinstance(backend, DeterministicLLM)
    assert "offline" in notice.lower()


def test_network_mode_requires_an_explicit_flag() -> None:
    """Anything other than the exact opt-in flag must refuse to run."""
    for arguments in (["--openrouter", "extra"], ["-o"], ["--online"], ["oops"]):
        with pytest.raises(SystemExit) as excinfo:
            select_backend(arguments)
        assert "Usage" in str(excinfo.value)


def test_network_mode_without_a_key_fails_closed() -> None:
    with pytest.raises(SystemExit) as excinfo:
        select_backend(["--openrouter"])
    assert "OPENROUTER_API_KEY" in str(excinfo.value)


def test_network_mode_with_a_key_warns_about_charges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key-not-real")
    backend, notice = select_backend(["--openrouter"])
    assert isinstance(backend, OpenRouterLLM)
    assert "charges" in notice.lower()


def test_demo_entry_point_reports_both_sides_of_the_contract(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["segregation-demo"])
    main()
    output = capsys.readouterr().out
    assert "ALLOWED / LEAKED" in output
    assert "BLOCKED / SAFE" in output


def test_ogi_entry_point_blocks_the_unverified_recipient(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.argv", ["segregation-demo-ogi"])
    main_ogi()
    output = capsys.readouterr().out
    assert "BLOCKED / SAFE" in output
    assert "lineage" in output.lower()
