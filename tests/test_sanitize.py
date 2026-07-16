"""Tests for the output sanitization boundary."""

from data_segregation_lab.models import ToolCall
from data_segregation_lab.protocol import PARTICIPANTS
from data_segregation_lab.tool_protocol import sanitize_tool_call


def test_sanitize_rejects_unknown_owner() -> None:
    call = ToolCall("read", "evil_tenant", "secret")
    assert sanitize_tool_call(call, PARTICIPANTS) is None


def test_sanitize_rejects_malformed_key() -> None:
    call = ToolCall("read", "client_a", "../secret")
    assert sanitize_tool_call(call, PARTICIPANTS) is None


def test_sanitize_bounds_write_value() -> None:
    call = ToolCall("write", "client_a", "secret", "x" * 500)
    sanitized = sanitize_tool_call(call, PARTICIPANTS)
    assert sanitized is not None
    assert sanitized.value is not None
    assert len(sanitized.value) == 256


def test_sanitize_accepts_valid_read() -> None:
    call = ToolCall("read", "client_a", "secret")
    sanitized = sanitize_tool_call(call, PARTICIPANTS)
    assert sanitized == ToolCall("read", "client_a", "secret", None)
