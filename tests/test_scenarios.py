"""End-to-end security-property tests using the shared scenario runner."""

import pytest

from data_segregation_lab.batch import count_outcomes
from data_segregation_lab.models import ScenarioResult
from data_segregation_lab.protocol import INJECTION_SUFFIX
from data_segregation_lab.tool_protocol import detect_tool_calls
from data_segregation_lab.scenario import (
    run_hardened_injection_scenario,
    run_ogi_contamination_scenario,
    run_protected_scenario,
    run_vulnerable_scenario,
)


@pytest.mark.intentional_vulnerability
def test_intentional_cross_owner_read_is_reproducible() -> None:
    result = run_vulnerable_scenario()
    assert result.leaked
    assert result.read_execution.decision == "allow"
    assert result.read_execution.value == "42"


def test_protected_scenario_blocks_the_same_request() -> None:
    result = run_protected_scenario()
    assert not result.leaked
    assert result.read_execution.decision == "block"
    assert result.read_execution.value is None


def test_repetitions_use_fresh_state_and_stable_policies() -> None:
    assert count_outcomes(25) == (25, 0)


def test_hardened_peer_injection_is_blocked() -> None:
    result = run_hardened_injection_scenario()
    assert result.attack == "peer_injection"
    assert result.orchestrator_hardening == "hardened"
    assert not result.leaked
    assert result.read_execution.decision == "block"


# ---- the injection and the hardening tier must actually do something ----


def test_injection_payload_is_parseable_as_a_tool_call() -> None:
    """A payload the parser ignores would make the injection scenario vacuous."""
    calls = detect_tool_calls(INJECTION_SUFFIX)
    assert [call.action for call in calls] == ["read"]
    assert calls[0].owner == "client_a" and calls[0].key == "secret"


def test_hardening_changes_what_the_orchestrator_forwards() -> None:
    naive = run_protected_scenario(
        attack="peer_injection", orchestrator_hardening="naive"
    )
    hardened = run_hardened_injection_scenario()

    def forwarded(result: ScenarioResult) -> int:
        return sum(
            1
            for line in result.orchestrator_output.splitlines()
            if line.startswith("EXEC:")
        )

    # The naive orchestrator obeys the injected line as well as the peer's own
    # proposal; the hardened one forwards only the proposal.
    assert forwarded(naive) == 2
    assert forwarded(hardened) == 1
    assert naive.orchestrator_output != hardened.orchestrator_output


def test_hardening_alone_does_not_decide_the_outcome() -> None:
    """Both prompt tiers reach the same boundary decision under the same policy."""
    naive = run_protected_scenario(
        attack="peer_injection", orchestrator_hardening="naive"
    )
    hardened = run_hardened_injection_scenario()
    assert naive.read_execution.decision == hardened.read_execution.decision == "block"

    # And with authorization removed, hardening does not save the data: the
    # peer's own proposal still reaches storage.
    leaky = run_vulnerable_scenario(
        attack="peer_injection", orchestrator_hardening="hardened"
    )
    assert leaky.leaked


def test_ogi_contamination_blocks_unverified_recipient_before_commit() -> None:
    result = run_ogi_contamination_scenario()
    assert result.attack == "ogi_contamination"
    assert result.ogi_leak_blocked is True
    assert result.write_execution.decision == "block"
    assert result.write_execution.reason is not None
    assert "lineage" in result.write_execution.reason.lower()
