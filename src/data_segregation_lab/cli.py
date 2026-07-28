"""Command-line entry point for the narrated security demonstration."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from data_segregation_lab.backends import DeterministicLLM, LLMBackend, OpenRouterLLM
from data_segregation_lab.presentation import DemoPresenter
from data_segregation_lab.scenario import (
    run_hardened_injection_scenario,
    run_ogi_contamination_scenario,
    run_protected_scenario,
    run_vulnerable_scenario,
)


def select_backend(arguments: Sequence[str]) -> tuple[LLMBackend, str]:
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
    """Run all policies through the shared runner, then present the results."""
    backend, notice = select_backend(sys.argv[1:])
    vulnerable = run_vulnerable_scenario(backend)
    protected = run_protected_scenario(backend)
    hardened_injection = run_hardened_injection_scenario(backend)
    # Counterfactual: same injection, same executor, only the prompt tier differs.
    # Without it the demo asserts that hardening helps instead of measuring it.
    naive_injection = run_protected_scenario(
        backend,
        attack="peer_injection",
        orchestrator_hardening="naive",
    )
    presenter = DemoPresenter(
        use_color=sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )
    print(
        presenter.render(
            vulnerable,
            protected,
            hardened_injection,
            mode_notice=notice,
            naive_injection=naive_injection,
        )
    )


def main_ogi() -> None:
    """Run the OGI provenance + outbound validation scenario."""
    backend, notice = select_backend(sys.argv[1:])
    ogi = run_ogi_contamination_scenario(backend)
    presenter = DemoPresenter(
        use_color=sys.stdout.isatty() and "NO_COLOR" not in os.environ
    )
    header = [
        "╭" + "─" * 71 + "╮",
        "│  OGI SHARED MEMORY — OUTBOUND VALIDATION".ljust(72) + "│",
        "│  Hash-linked provenance + executor-side recipient checks.".ljust(72) + "│",
        "╰" + "─" * 71 + "╯",
        "",
        presenter.style(notice, "1;33"),
    ]
    print("\n".join(header) + presenter.render_ogi_scenario(ogi))


if __name__ == "__main__":
    main()
