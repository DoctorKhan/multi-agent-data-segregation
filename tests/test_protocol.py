"""Tests for the inter-agent communication protocol helpers."""

from data_segregation_lab.models import AgentMessage
from data_segregation_lab.protocol import (
    INJECTION_SUFFIX,
    bound_message_content,
    format_messages_for_context,
)


def test_bound_message_content_truncates_long_bodies() -> None:
    assert len(bound_message_content("x" * 600)) == 512


def test_format_messages_for_context_labels_untrusted_bodies() -> None:
    rendered = format_messages_for_context(
        [AgentMessage("client_b", "orchestrator", "hello" + INJECTION_SUFFIX)]
    )
    assert "UNTRUSTED DATA" in rendered
    assert "from=client_b" in rendered
    assert "[SYSTEM OVERRIDE]" in rendered
