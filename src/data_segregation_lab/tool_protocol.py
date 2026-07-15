"""Fail-closed parser for the lab's intentionally tiny text tool protocol."""

from __future__ import annotations

from typing import cast

from data_segregation_lab.models import ToolAction, ToolCall


class ToolCallParseError(ValueError):
    """Raised internally when a tool line is ambiguous or incomplete."""


def _parse_arguments(parts: list[str]) -> dict[str, str]:
    """Parse unquoted ``name=value`` tokens and reject duplicate names."""
    arguments: dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            raise ToolCallParseError(f"Missing '=' in tool argument: {part}")
        name, value = part.split("=", 1)
        if not name or not value:
            raise ToolCallParseError("Tool argument names and values cannot be empty")
        if name in arguments:
            raise ToolCallParseError(f"Duplicate tool argument: {name}")
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        arguments[name] = value
    return arguments


def _parse_tool_line(line: str) -> ToolCall:
    """Parse one normalized ``[tool]`` line with action-specific fields."""
    parts = line.split()
    if len(parts) < 4:
        raise ToolCallParseError("Tool call is incomplete")

    raw_action = parts[1]
    if raw_action not in {"read", "write"}:
        raise ToolCallParseError(f"Unsupported tool action: {raw_action}")
    action = cast(ToolAction, raw_action)
    arguments = _parse_arguments(parts[2:])

    expected = {"owner", "key", "value"} if action == "write" else {"owner", "key"}
    if arguments.keys() != expected:
        raise ToolCallParseError(
            f"{action} requires exactly these arguments: {sorted(expected)}"
        )

    return ToolCall(
        action=action,
        owner=arguments["owner"],
        key=arguments["key"],
        value=arguments.get("value"),
    )


def detect_tool_calls(text: str) -> list[ToolCall]:
    """Extract valid tool calls while ignoring prose and malformed proposals."""
    calls: list[ToolCall] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("EXEC:"):
            line = line.removeprefix("EXEC:").strip()
        if not line.startswith("[tool]"):
            continue
        try:
            calls.append(_parse_tool_line(line))
        except ToolCallParseError:
            # Model text is untrusted. Invalid operations never reach storage.
            continue
    return calls
