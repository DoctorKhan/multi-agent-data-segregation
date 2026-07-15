"""Compact deterministic repetition runner for the documented behavior."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from data_segregation_lab.scenario import (
    run_protected_scenario,
    run_vulnerable_scenario,
)


def count_outcomes(repetitions: int) -> tuple[int, int]:
    """Return vulnerable and protected leak counts using fresh state each time."""
    vulnerable_leaks = sum(run_vulnerable_scenario().leaked for _ in range(repetitions))
    protected_leaks = sum(run_protected_scenario().leaked for _ in range(repetitions))
    return vulnerable_leaks, protected_leaks


def main(arguments: Sequence[str] | None = None) -> None:
    """Parse a repetition count and print the compact comparison."""
    parser = argparse.ArgumentParser(
        description="Repeat the deterministic data-segregation scenarios."
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=500,
        help="number of fresh runs per policy (default: 500)",
    )
    parsed = parser.parse_args(arguments)
    repetitions = int(parsed.repetitions)
    if repetitions < 1:
        parser.error("--repetitions must be at least 1")

    vulnerable, protected = count_outcomes(repetitions)
    print("INTENTIONAL VULNERABILITY LAB — SYNTHETIC DATA ONLY")
    print(f"Vulnerable path leaks: {vulnerable}/{repetitions}")
    print(f"Protected path leaks:  {protected}/{repetitions}")


if __name__ == "__main__":
    main()
