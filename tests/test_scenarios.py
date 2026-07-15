"""End-to-end security-property tests using the shared scenario runner."""

import pytest

from data_segregation_lab.batch import count_outcomes
from data_segregation_lab.scenario import (
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
