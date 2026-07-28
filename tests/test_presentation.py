"""Tests for rendering untrusted model output safely."""

from data_segregation_lab.backends import LLMBackend
from data_segregation_lab.executors import VulnerableToolExecutor
from data_segregation_lab.ownership import IntelligenceRegistry
from data_segregation_lab.presentation import (
    WIDTH,
    DemoPresenter,
    escape_terminal_controls,
)
from data_segregation_lab.prompts import Hardening
from data_segregation_lab.scenario import ScenarioRunner
from data_segregation_lab.storage import InMemoryStore


class ControlCharacterBackend:
    """Delegate normal behavior but inject a terminal-clear escape sequence."""

    def __init__(self, delegate: LLMBackend) -> None:
        self._delegate = delegate

    def complete(
        self,
        role: str,
        prompt: str,
        *,
        hardening: Hardening = "naive",
    ) -> str:
        output = self._delegate.complete(role, prompt, hardening=hardening)
        del hardening
        # Inject into prose only, leaving the following tool line executable.
        return "\x1b[2J" + output if role == "client_a" else output


def test_control_characters_are_escaped() -> None:
    assert escape_terminal_controls("safe\x1b[2Jtext") == "safe\\x1b[2Jtext"


def test_presenter_renders_results_without_raw_terminal_controls() -> None:
    from data_segregation_lab.backends import DeterministicLLM

    store = InMemoryStore()
    result = ScenarioRunner(
        ControlCharacterBackend(DeterministicLLM()),
        store,
        VulnerableToolExecutor(store),
        IntelligenceRegistry(),
    ).run()
    rendered = DemoPresenter(use_color=False).render_scenario(1, result)
    assert "\\x1b[2J" in rendered
    assert "\x1b" not in rendered
    assert "ALLOW" in rendered


def _render_full_demo(*, with_counterfactual: bool = True) -> str:
    from data_segregation_lab.backends import DeterministicLLM
    from data_segregation_lab.scenario import (
        run_hardened_injection_scenario,
        run_protected_scenario,
        run_vulnerable_scenario,
    )

    backend = DeterministicLLM()
    naive_injection = (
        run_protected_scenario(
            backend, attack="peer_injection", orchestrator_hardening="naive"
        )
        if with_counterfactual
        else None
    )
    return DemoPresenter(use_color=False).render(
        run_vulnerable_scenario(backend),
        run_protected_scenario(backend),
        run_hardened_injection_scenario(backend),
        mode_notice="test mode",
        naive_injection=naive_injection,
    )


def test_summary_explains_each_scenario_decision() -> None:
    rendered = _render_full_demo()
    summary = rendered.split("SUMMARY", 1)[1]

    assert summary.count("Executor policy:") == 3
    assert "none — the owner field in model text is trusted" in summary
    assert "requester must equal target owner" in summary
    assert "cross-owner read (confused deputy)" in summary
    assert "peer-message instruction injection" in summary
    assert "naive prompt" in summary
    assert "hardened prompt" in summary
    # The leak and both blocks are each explained, not just tabulated.
    assert "ALLOW — returned '42'" in summary
    assert summary.count("Decision:        BLOCK") == 2
    assert summary.count("Why:") == 3
    assert "WHAT CHANGED" in summary


def test_summary_lines_stay_within_the_rendered_width() -> None:
    for line in _render_full_demo().split("SUMMARY", 1)[1].splitlines():
        assert len(line) <= WIDTH, line


def test_what_changed_reports_the_measured_counterfactual() -> None:
    """The hardening claim must be measured against a naive run, not asserted."""
    changed = _render_full_demo().split("WHAT CHANGED", 1)[1]
    assert "naive=2, hardened=1" in changed
    assert "BLOCK (naive) / BLOCK (hardened)" in changed


def test_counterfactual_claims_are_omitted_when_not_measured() -> None:
    changed = _render_full_demo(with_counterfactual=False).split("WHAT CHANGED", 1)[1]
    assert "naive=" not in changed
    assert "hardening dropped" not in changed


def test_ogi_scenario_render_shows_the_blocked_recipient() -> None:
    from data_segregation_lab.scenario import run_ogi_contamination_scenario

    rendered = DemoPresenter(use_color=False).render_ogi_scenario(
        run_ogi_contamination_scenario()
    )
    assert "OGI SHARED MEMORY" in rendered
    assert "BLOCK" in rendered
    assert "attacker@protonmail.com" in rendered
    assert "BLOCKED / SAFE" in rendered
    # The committed profile address is the legitimate `to`; the block must not
    # be attributed to it.
    assert "not in verified lineage sarah.jennings@private-domain.com" in rendered


def test_ogi_scenario_render_escapes_untrusted_transcripts() -> None:
    from data_segregation_lab.backends import DeterministicLLM
    from data_segregation_lab.scenario import run_ogi_contamination_scenario

    rendered = DemoPresenter(use_color=False).render_ogi_scenario(
        run_ogi_contamination_scenario(ControlCharacterBackend(DeterministicLLM()))
    )
    assert "\x1b" not in rendered


def test_style_is_a_no_op_without_color() -> None:
    assert DemoPresenter(use_color=False).style("text", "1;31") == "text"
    assert "\033[1;31m" in DemoPresenter(use_color=True).style("text", "1;31")
