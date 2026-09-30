"""Pure authorization policies for untrusted tool proposals.

These functions inspect immutable inputs and return decisions without touching
storage or provenance state. Executors own the ordered effects that follow an
allowed decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Literal

from data_segregation_lab.models import ToolCall
from data_segregation_lab.ogi import extract_recipients

PolicyOutcome = Literal["allow", "block"]
RecipientVerification = tuple[bool, str | None]

# The key that carries a tenant's verified identity, which outbound calls are
# validated against. It is lineage material, not an outbound action itself.
PROFILE_KEY = "client_profile"

# Keys whose names imply delivery. Untrusted model text chooses the key, so this
# pattern only widens validation — it is never the sole gate. Any payload with a
# recipient is validated regardless of what the key is called.
OUTBOUND_KEY_PATTERN = re.compile(
    r"email|mail|send|notify|forward|webhook|deliver", re.IGNORECASE
)


@dataclass(frozen=True)
class PolicyDecision:
    """An immutable result from policy evaluation."""

    outcome: PolicyOutcome
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"


ALLOW = PolicyDecision("allow")


def allow_model_selected_owner(requester: str, call: ToolCall) -> PolicyDecision:
    """INTENTIONALLY VULNERABLE: accept the owner selected by model output."""
    del requester, call
    return ALLOW


def authorize_owner_scope(requester: str, call: ToolCall) -> PolicyDecision:
    """Allow only operations targeting the authenticated requester's namespace."""
    if requester != call.owner:
        return PolicyDecision("block")
    return ALLOW


def is_profile_key(key: str) -> bool:
    """True for any spelling of the profile key.

    OGI chains are case-insensitive, so ``Client_Profile`` rewrites the same
    lineage as ``client_profile`` and must be governed the same way.
    """
    return key.casefold() == PROFILE_KEY


def authorize_profile_change(has_committed_profile: bool) -> PolicyDecision:
    """Require out-of-band approval before a committed profile changes.

    The profile is the address every outbound action is checked against, so a
    hijacked agent that could rewrite it would re-point all later deliveries.
    The first profile is allowed as onboarding; every change after that waits
    for a human, never the model.
    """
    if has_committed_profile:
        return PolicyDecision("block", "profile change requires step-up approval")
    return ALLOW


def recipients_requiring_validation(call: ToolCall) -> tuple[str, ...] | None:
    """Return outbound recipients, or None when the call is not outbound.

    An empty tuple means the key looks delivery-shaped but the payload carries
    no verifiable recipient. Keeping that distinct from None preserves
    fail-closed evaluation.
    """
    if call.action != "write" or is_profile_key(call.key):
        return None

    recipients = tuple(extract_recipients(call.value or ""))
    looks_outbound = OUTBOUND_KEY_PATTERN.search(call.key) is not None
    if not recipients and not looks_outbound:
        return None
    return recipients


def authorize_recipient_lineage(
    verification: RecipientVerification,
) -> PolicyDecision:
    """Convert a read-only lineage verification result into a policy decision."""
    allowed, reason = verification
    if allowed:
        return ALLOW
    return PolicyDecision("block", reason or "lineage violation")


def first_block(decisions: Iterable[PolicyDecision]) -> PolicyDecision:
    """Compose policies by returning the first denial, otherwise allow."""
    return next((decision for decision in decisions if not decision.allowed), ALLOW)
