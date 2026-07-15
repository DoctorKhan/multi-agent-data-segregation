"""Command-line entry point for the narrated two-scenario demonstration."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from data_segregation_lab.backends import DeterministicLLM, LLMBackend, OpenRouterLLM
from data_segregation_lab.presentation import DemoPresenter
from data_segregation_lab.scenario import (
    run_protected_scenario,
    run_vulnerable_scenario,
)


def _select_backend(arguments: Sequence[str]) -> tuple[LLMBackend, str]:
    """Choose offline mode by default and require an explicit network flag."""
    if not arguments:
        return DeterministicLLM(), "Deterministic offline mode — synthetic data only."
    if list(arguments) != ["--openrouter"]:
        raise SystemExit("Usage: segregation-demo [--openrouter]")

    from dotenv import load_dotenv

    load_dotenv(".env.openrouter", override=False)
    if not os.environ.get("OPENROUTER_API_KEY"):
        raise SystemExit(
            "--openrouter requires OPENROUTER_API_KEY in the environment or "
            ".env.openrouter"
        )
    return OpenRouterLLM(), "OPENROUTER MODE — network calls and charges are enabled."


def main() -> None:
    """Run both policies through the shared runner, then present the results."""
    backend, notice = _select_backend(sys.argv[1:])
    vulnerable = run_vulnerable_scenario(backend)
    protected = run_protected_scenario(backend)
    presenter = DemoPresenter(
        use_color=sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )
    print(presenter.render(vulnerable, protected, mode_notice=notice))


if __name__ == "__main__":
    main()
