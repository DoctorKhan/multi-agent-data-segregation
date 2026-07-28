"""Escaping and formatting shared by every presenter.

Model output reaches a terminal and a browser. Both need the same control
character treatment and the same tool-call rendering, so it lives here once —
two copies of an escaping routine is one copy that eventually stops matching.
"""

from __future__ import annotations

from data_segregation_lab.models import ToolCall


def escape_terminal_controls(text: str) -> str:
    """Escape control characters so model output cannot manipulate a terminal."""
    return "".join(
        character
        if character in {"\n", "\t"} or character.isprintable()
        else character.encode("unicode_escape").decode("ascii")
        for character in text
    )


def format_tool_call(call: ToolCall) -> str:
    """Render a parsed call with every field escaped.

    Parsed fields are still derived from model text, so they need the same
    treatment as the raw transcript.
    """
    owner = escape_terminal_controls(call.owner)
    key = escape_terminal_controls(call.key)
    fields = f'owner="{owner}", key="{key}"'
    if call.value is not None:
        fields += f', value="{escape_terminal_controls(call.value)}"'
    return f"{call.action}({fields})"


def transcript_lines(actor: str, text: str) -> list[str]:
    """Split escaped model output into attributable lines."""
    safe = escape_terminal_controls(text).strip() or "<empty>"
    return safe.splitlines()
