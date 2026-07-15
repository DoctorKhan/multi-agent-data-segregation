"""Terminal-safe rendering for structured scenario results."""

from __future__ import annotations

from data_segregation_lab.models import ScenarioResult, ToolCall, ToolExecution

WIDTH = 72


def escape_terminal_controls(text: str) -> str:
    """Escape control characters so model output cannot manipulate a terminal."""
    return "".join(
        character
        if character in {"\n", "\t"} or character.isprintable()
        else character.encode("unicode_escape").decode("ascii")
        for character in text
    )


def _format_tool_call(call: ToolCall) -> str:
    # Parsed fields are still derived from model text, so they need the same
    # terminal treatment as the raw transcript.
    owner = escape_terminal_controls(call.owner)
    key = escape_terminal_controls(call.key)
    fields = f'owner="{owner}", key="{key}"'
    if call.value is not None:
        value = escape_terminal_controls(call.value)
        fields += f', value="{value}"'
    return f"{call.action}({fields})"


class DemoPresenter:
    """Build readable output while keeping all scenario behavior elsewhere."""

    def __init__(self, *, use_color: bool) -> None:
        self._use_color = use_color

    def _style(self, text: str, code: str) -> str:
        if not self._use_color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def _transcript(self, actor: str, text: str) -> list[str]:
        safe_text = escape_terminal_controls(text or "<empty>")
        return [
            f"   {actor} output",
            *(f"     │ {line}" for line in safe_text.rstrip().splitlines()),
        ]

    def _execution_details(self, execution: ToolExecution) -> list[str]:
        if execution.call is None:
            return ["   Decision:          NO DECISION"]
        lines = [f"   Tool call:         {_format_tool_call(execution.call)}"]
        if execution.decision == "block":
            lines.extend(
                [
                    "   Decision:          BLOCK",
                    "",
                    self._style(
                        "   ✓ SAFE — unauthorized data never leaves the store",
                        "1;32",
                    ),
                ]
            )
        elif execution.value is not None:
            lines.extend(
                [
                    "   Decision:          ALLOW",
                    f"   Returned:          {execution.value!r}",
                    "",
                    self._style(
                        "   ✗ LEAK — Client B received Client A's private data",
                        "1;31",
                    ),
                ]
            )
        else:
            lines.append(f"   Decision:          {execution.decision.upper()}")
        return lines

    def render_scenario(self, number: int, result: ScenarioResult) -> str:
        """Render one result without re-running any business logic."""
        protected = result.mode == "protected"
        title = "PROTECTED" if protected else "INTENTIONALLY VULNERABLE"
        subtitle = (
            "Requester-scoped authorization runs before storage access."
            if protected
            else "The executor trusts the owner supplied by untrusted model text."
        )
        policy = "requester must equal target owner" if protected else "none (unsafe)"
        write_call = result.write_execution.call
        lines = [
            "",
            self._style(f"SCENARIO {number} OF 2  ·  {title}", "1;35"),
            subtitle,
            "─" * WIDTH,
            "",
            "1. Client A stores synthetic private data",
            f"   Message:           {result.client_a_message.sender} → orchestrator",
            f"   Request:           {result.client_a_message.content}",
            *self._transcript("client_a", result.client_a_output),
        ]
        if write_call is not None:
            lines.append(f"   Executed:          {_format_tool_call(write_call)}")
        lines.extend(
            [
                f"   Memory:            client_a / secret = {result.stored_value!r}",
                "",
                "2. Client B requests Client A's secret",
                f"   Message:           {result.client_b_message.sender} → orchestrator",
                f"   Requester:         {result.requester}",
                f"   Request:           {result.client_b_message.content}",
                *self._transcript("client_b", result.client_b_output),
                *self._transcript("orchestrator", result.orchestrator_output),
                "",
                "3. The request reaches the enforcement boundary",
                f"   Policy:            {policy}",
                *self._execution_details(result.read_execution),
            ]
        )
        return "\n".join(lines)

    def render(
        self,
        vulnerable: ScenarioResult,
        protected: ScenarioResult,
        *,
        mode_notice: str,
    ) -> str:
        """Render the complete two-scenario comparison."""
        vulnerable_outcome = "ALLOWED / LEAKED" if vulnerable.leaked else "NO LEAK"
        protected_outcome = (
            "BLOCKED / SAFE"
            if protected.read_execution.decision == "block"
            else "UNEXPECTED"
        )
        lines = [
            "╭" + "─" * (WIDTH - 2) + "╮",
            "│  MULTI-AGENT DATA SEGREGATION".ljust(WIDTH - 1) + "│",
            "│  Same request. Different enforcement boundary.".ljust(WIDTH - 1) + "│",
            "╰" + "─" * (WIDTH - 2) + "╯",
            "",
            self._style(mode_notice, "1;33"),
            self.render_scenario(1, vulnerable),
            self.render_scenario(2, protected),
            "",
            self._style("COMPARISON", "1;36"),
            "─" * WIDTH,
            f"   {'Configuration':<28} Decision / outcome",
            f"   {'Intentionally vulnerable':<28} {vulnerable_outcome}",
            f"   {'Protected':<28} {protected_outcome}",
            "",
            "Authorization must happen before the storage operation.",
        ]
        return "\n".join(lines)
