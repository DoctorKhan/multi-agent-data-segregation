"""Tests for the fixture that becomes the published GitHub Pages demo.

The browser renders this data verbatim, so a wrong outcome here is a wrong
security claim in public. The fixture is also the only artifact the deploy
workflow ships, which makes staleness a correctness problem, not housekeeping.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from data_segregation_lab.backends import DeterministicLLM, LLMBackend
from data_segregation_lab.prompts import Hardening
from data_segregation_lab.web_payload import (
    FIXTURE_PATH,
    build_payload,
    main,
    render_payload,
)

ALLOWED_HIGHLIGHTS = {"danger", "safe", "neutral"}


Fixture = dict[str, Any]


def _scenarios() -> list[Fixture]:
    return cast(list[Fixture], build_payload()["scenarios"])


def _by_number(number: int) -> Fixture:
    return next(item for item in _scenarios() if item["number"] == number)


def _steps(scenario: Fixture) -> list[Fixture]:
    steps = cast(list[Fixture], scenario["steps"])
    assert steps
    return steps


def _boundary(number: int) -> Fixture:
    """The enforcement step, wherever it sits — audit steps may follow it."""
    return next(
        step for step in _steps(_by_number(number)) if step["id"] == "boundary"
    )


# ---- structure the renderer depends on ----


def test_payload_covers_every_scenario_the_cli_demonstrates() -> None:
    assert [item["number"] for item in _scenarios()] == [1, 2, 3, 4]


def test_every_step_carries_the_fields_the_renderer_reads() -> None:
    for scenario in _scenarios():
        for step in _steps(scenario):
            assert step["id"] and step["title"]
            assert isinstance(step["body"], str)
            assert step["highlight"] in ALLOWED_HIGHLIGHTS


def test_every_scenario_walks_to_an_enforcement_decision() -> None:
    """Only audit evidence may follow the boundary; nothing re-decides after it."""
    for scenario in _scenarios():
        ids = [step["id"] for step in _steps(scenario)]
        assert "boundary" in ids
        assert set(ids[ids.index("boundary") + 1 :]) <= {"lineage"}


# ---- the security claims the page makes ----


def test_only_the_vulnerable_scenario_is_labelled_as_leaked() -> None:
    leaked = [s["number"] for s in _scenarios() if s["outcome_kind"] == "leaked"]
    assert leaked == [1]


def test_vulnerable_boundary_shows_the_allow_and_the_returned_value() -> None:
    boundary = _boundary(1)
    assert "ALLOW" in boundary["body"]
    assert "42" in boundary["body"]
    assert boundary["highlight"] == "danger"


@pytest.mark.parametrize("number", [2, 3, 4])
def test_protected_scenarios_show_a_block_at_the_boundary(number: int) -> None:
    scenario = _by_number(number)
    boundary = _boundary(number)
    assert "BLOCK" in boundary["body"]
    assert boundary["highlight"] == "safe"
    assert scenario["outcome"] == "BLOCKED / SAFE"


def test_injection_scenario_surfaces_the_injected_tool_call() -> None:
    """A scenario that never displayed the injection would demonstrate nothing."""
    peer = next(step for step in _steps(_by_number(3)) if step["id"] == "peer-model")
    assert "[tool]" in str(peer["code"])


def test_ogi_scenario_names_the_recipient_that_triggered_the_block() -> None:
    boundary = _boundary(4)
    assert "attacker@protonmail.com" in boundary["body"]
    assert "lineage" in str(boundary["body"]).lower()


# ---- untrusted text must not reach the browser unescaped ----


class ControlCharacterBackend:
    """Emit a terminal escape sequence ahead of otherwise normal output."""

    def __init__(self, delegate: LLMBackend) -> None:
        self._delegate = delegate

    def complete(
        self, role: str, prompt: str, *, hardening: Hardening = "naive"
    ) -> str:
        output = self._delegate.complete(role, prompt, hardening=hardening)
        return "\x1b[2J" + output if role == "client_a" else output


def test_control_characters_never_reach_the_fixture() -> None:
    payload = build_payload(ControlCharacterBackend(DeterministicLLM()))
    serialized = json.dumps(payload)
    assert "\\u001b" not in serialized
    assert "\\\\x1b[2J" in serialized


# ---- serialization and the staleness gate ----


def test_render_payload_is_byte_stable_across_runs() -> None:
    """The staleness check compares bytes, so any instability would flake CI."""
    assert render_payload() == render_payload()


def test_committed_fixture_matches_the_generator() -> None:
    committed = Path(FIXTURE_PATH).read_text(encoding="utf-8")
    assert committed == render_payload(), "run `just export-demo` and commit the result"


def test_check_mode_rejects_a_stale_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stale = tmp_path / "scenarios.json"
    stale.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv", ["segregation-export-demo", "--check", "--output", str(stale)]
    )
    with pytest.raises(SystemExit) as excinfo:
        main()
    assert "stale" in str(excinfo.value)


def test_check_mode_rejects_a_missing_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "absent.json"
    monkeypatch.setattr(
        "sys.argv", ["segregation-export-demo", "--check", "--output", str(missing)]
    )
    with pytest.raises(SystemExit):
        main()


def test_write_then_check_round_trips(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "nested" / "scenarios.json"
    monkeypatch.setattr(
        "sys.argv", ["segregation-export-demo", "--output", str(target)]
    )
    main()
    assert target.exists()

    monkeypatch.setattr(
        "sys.argv", ["segregation-export-demo", "--check", "--output", str(target)]
    )
    main()  # must not raise now that the fixture is current


def test_ogi_scenario_publishes_the_provenance_chain() -> None:
    """A blocked write must leave a visible audit trail, not just a denial."""
    lineage = next(
        step for step in _steps(_by_number(4)) if step["id"] == "lineage"
    )
    assert "ANOMALY" in cast(str, lineage["code"])
