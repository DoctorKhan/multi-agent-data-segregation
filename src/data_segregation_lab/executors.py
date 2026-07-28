"""Contrasting tool-enforcement boundaries used by the demonstration."""

from __future__ import annotations

import re
from typing import Protocol

from data_segregation_lab.models import ScenarioMode, ToolCall, ToolExecution
from data_segregation_lab.ogi import OGIClient, extract_recipients
from data_segregation_lab.storage import Store

# The key that carries a tenant's verified identity, which outbound calls are
# validated against. It is lineage material, not an outbound action itself.
PROFILE_KEY = "client_profile"

# Keys whose names imply delivery. Untrusted model text chooses the key, so this
# pattern only widens validation — it is never the sole gate. Any payload with a
# recipient is validated regardless of what the key is called.
OUTBOUND_KEY_PATTERN = re.compile(
    r"email|mail|send|notify|forward|webhook|deliver", re.IGNORECASE
)


class ToolExecutor(Protocol):
    """Policy-aware boundary between untrusted tool calls and storage."""

    mode: ScenarioMode

    def execute(self, requester: str, call: ToolCall) -> ToolExecution: ...


class VulnerableToolExecutor:
    """INTENTIONALLY VULNERABLE: trusts the owner supplied by model text.

    This implementation exists only to reproduce the documented flaw. It
    ignores ``requester`` and therefore permits cross-owner reads and writes.
    """

    mode: ScenarioMode = "vulnerable"

    def __init__(self, store: Store) -> None:
        self._store = store

    def execute(self, requester: str, call: ToolCall) -> ToolExecution:
        """Execute against ``call.owner`` without authenticating that claim."""
        del requester  # Deliberate evidence of the missing identity check.
        if call.action == "write":
            self._store.write(call.owner, call.key, call.value or "")
            return ToolExecution(decision="allow", call=call)
        return ToolExecution(
            decision="allow",
            call=call,
            value=self._store.read(call.owner, call.key),
        )


class OwnerScopedToolExecutor:
    """Enforce owner-scoped authorization before every storage operation."""

    mode: ScenarioMode = "protected"

    def __init__(self, store: Store) -> None:
        self._store = store

    def execute(self, requester: str, call: ToolCall) -> ToolExecution:
        """Default-deny any operation outside the requester's namespace."""
        if requester != call.owner:
            return ToolExecution(decision="block", call=call)
        if call.action == "write":
            self._store.write(call.owner, call.key, call.value or "")
            return ToolExecution(decision="allow", call=call)
        return ToolExecution(
            decision="allow",
            call=call,
            value=self._store.read(call.owner, call.key),
        )


class OGIProvenanceExecutor:
    """Protected executor that commits writes through OGI first.

    Reads are allowed only from committed OGI entries; cross-owner reads and
    writes default-deny. Contaminated payloads are flagged as anomalies so
    audit trails can isolate the blast radius.

    Outbound writes are validated by payload shape rather than by key name: any
    write carrying a recipient must match the tenant's committed profile, and a
    delivery-shaped key with no verifiable recipient is denied. Renaming the key
    therefore does not bypass validation.

    Known limitation: a write to ``PROFILE_KEY`` establishes the address that
    later outbound calls are checked against, so a hijacked agent acting as its
    own tenant can still re-point its profile. That rewrite is owner-scoped and
    left in the append-only lineage, but it is not itself re-verified here.
    """

    mode: ScenarioMode = "protected"

    def __init__(self, store: Store, client: OGIClient) -> None:
        self._store = store
        self._client = client

    def _allowed_target(self, requester: str, target_owner: str) -> bool:
        return requester == target_owner

    def execute(self, requester: str, call: ToolCall) -> ToolExecution:
        if not self._allowed_target(requester, call.owner):
            return ToolExecution(decision="block", call=call)

        if call.action == "write":
            reason = self._outbound_violation(call)
            if reason is not None:
                self._client.anomaly(call.owner, call.key, reason)
                return ToolExecution(decision="block", call=call, reason=reason)

            self._client.propose(call.owner, call.key, call.value or "")
            self._client.commit(call.owner, call.key)
            self._store.write(call.owner, call.key, call.value or "")
            return ToolExecution(decision="allow", call=call)

        value = self._client.read(call.owner, call.key)
        if value is None:
            return ToolExecution(decision="block", call=call)
        return ToolExecution(
            decision="allow",
            call=call,
            value=self._store.read(call.owner, call.key),
        )

    def _outbound_violation(self, call: ToolCall) -> str | None:
        """Return why an outbound write must be denied, or None to proceed."""
        if call.key == PROFILE_KEY:
            return None

        recipients = extract_recipients(call.value or "")
        looks_outbound = OUTBOUND_KEY_PATTERN.search(call.key) is not None
        if not recipients and not looks_outbound:
            return None

        allowed, reason = self._client.verify_recipients(recipients, call.owner)
        if allowed:
            return None
        return reason or "lineage violation"
