"""Tests for the fail-closed text tool parser."""

from data_segregation_lab.models import ToolCall
from data_segregation_lab.tool_protocol import detect_tool_calls


def test_parses_read_write_and_forwarded_calls() -> None:
    text = "\n".join(
        [
            "[tool] write owner=client_a key=secret value=42",
            "EXEC:[tool] read owner=client_a key=secret",
        ]
    )
    assert detect_tool_calls(text) == [
        ToolCall("write", "client_a", "secret", "42"),
        ToolCall("read", "client_a", "secret"),
    ]


def test_ignores_prose() -> None:
    assert detect_tool_calls("hello\nnot a tool call") == []


def test_rejects_unsupported_or_ambiguous_calls() -> None:
    text = "\n".join(
        [
            "[tool] delete owner=client_a key=secret",
            "[tool] read owner=client_a owner=client_b key=secret",
            "[tool] read owner=client_a key=secret extra=true",
            "[tool] write owner=client_a key=secret",
        ]
    )
    assert detect_tool_calls(text) == []
