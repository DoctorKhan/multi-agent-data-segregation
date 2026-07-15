"""Tests for rendering untrusted model output safely."""

from data_segregation_lab.backends import LLMBackend
from data_segregation_lab.executors import VulnerableToolExecutor
from data_segregation_lab.presentation import DemoPresenter, escape_terminal_controls
from data_segregation_lab.scenario import ScenarioRunner
from data_segregation_lab.storage import InMemoryStore


class ControlCharacterBackend:
    """Delegate normal behavior but inject a terminal-clear escape sequence."""

    def __init__(self, delegate: LLMBackend) -> None:
        self._delegate = delegate

    def complete(self, role: str, prompt: str) -> str:
        output = self._delegate.complete(role, prompt)
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
    ).run()
    rendered = DemoPresenter(use_color=False).render_scenario(1, result)
    assert "\\x1b[2J" in rendered
    assert "\x1b" not in rendered
    assert "ALLOW" in rendered
