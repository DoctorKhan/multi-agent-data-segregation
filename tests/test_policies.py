"""Unit tests for the side-effect-free authorization core."""

from data_segregation_lab.models import ToolCall
from data_segregation_lab.policies import (
    PolicyDecision,
    allow_model_selected_owner,
    authorize_owner_scope,
    authorize_recipient_lineage,
    first_block,
    recipients_requiring_validation,
)


def test_intentionally_vulnerable_policy_accepts_cross_owner_call() -> None:
    call = ToolCall("read", "client_a", "secret")
    assert allow_model_selected_owner("client_b", call).allowed


def test_owner_policy_is_a_pure_decision_over_identity_and_call() -> None:
    call = ToolCall("write", "client_a", "secret", "42")
    assert authorize_owner_scope("client_a", call).allowed
    assert authorize_owner_scope("client_b", call).outcome == "block"
    assert call == ToolCall("write", "client_a", "secret", "42")


def test_ordinary_write_requires_no_recipient_validation() -> None:
    call = ToolCall("write", "client_a", "notes", "quarterly review")
    assert recipients_requiring_validation(call) is None


def test_delivery_key_without_recipient_is_distinct_from_ordinary_write() -> None:
    call = ToolCall("write", "client_a", "send_report", "quarterly review")
    assert recipients_requiring_validation(call) == ()


def test_recipient_detection_follows_payload_instead_of_key_name() -> None:
    call = ToolCall(
        "write",
        "client_a",
        "harmless_note",
        '{"to":"sarah@client.com","bcc":"attacker@evil.com"}',
    )
    assert recipients_requiring_validation(call) == (
        "sarah@client.com",
        "attacker@evil.com",
    )


def test_profile_write_is_not_treated_as_an_outbound_action() -> None:
    call = ToolCall(
        "write",
        "client_a",
        "client_profile",
        '{"client_email":"sarah@client.com"}',
    )
    assert recipients_requiring_validation(call) is None


def test_lineage_verification_is_converted_without_side_effects() -> None:
    assert authorize_recipient_lineage((True, None)).allowed
    blocked = authorize_recipient_lineage((False, "unverified recipient"))
    assert blocked == PolicyDecision("block", "unverified recipient")


def test_policy_composition_returns_first_denial() -> None:
    first = PolicyDecision("block", "ownership")
    second = PolicyDecision("block", "lineage")
    assert first_block([PolicyDecision("allow"), first, second]) is first
    assert first_block([PolicyDecision("allow")]).allowed
