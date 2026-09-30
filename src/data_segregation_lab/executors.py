"""Contrasting tool-enforcement boundaries used by the demonstration."""

from __future__ import annotations

from typing import Protocol

from data_segregation_lab.models import ScenarioMode, ToolCall, ToolExecution
from data_segregation_lab.ogi import OGIClient
from data_segregation_lab.policies import (
    PROFILE_KEY,
    PolicyDecision,
    allow_model_selected_owner,
    authorize_owner_scope,
    authorize_profile_change,
    authorize_recipient_lineage,
    is_profile_key,
    recipients_requiring_validation,
)
from data_segregation_lab.storage import Store


def _blocked(call: ToolCall, decision: PolicyDecision) -> ToolExecution:
    """Translate a pure policy denial into the executor's public result."""
    return ToolExecution(decision="block", call=call, reason=decision.reason)


def _execute_store(store: Store, call: ToolCall) -> ToolExecution:
    """Imperative shell for an already-authorized storage operation."""
    if call.action == "write":
        store.write(call.owner, call.key, call.value or "")
        return ToolExecution(decision="allow", call=call)
    return ToolExecution(
        decision="allow",
        call=call,
        value=store.read(call.owner, call.key),
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
        decision = allow_model_selected_owner(requester, call)
        if not decision.allowed:
            return _blocked(call, decision)
        return _execute_store(self._store, call)


class OwnerScopedToolExecutor:
    """Enforce owner-scoped authorization before every storage operation."""

    mode: ScenarioMode = "protected"

    def __init__(self, store: Store) -> None:
        self._store = store

    def execute(self, requester: str, call: ToolCall) -> ToolExecution:
        """Default-deny any operation outside the requester's namespace."""
        decision = authorize_owner_scope(requester, call)
        if not decision.allowed:
            return _blocked(call, decision)
        return _execute_store(self._store, call)


class OGIProvenanceExecutor:
    """Protected executor that commits writes through OGI first.

    Reads are allowed only from committed OGI entries; cross-owner reads and
    writes default-deny. Contaminated payloads are flagged as anomalies so
    audit trails can isolate the blast radius.

    Outbound writes are validated by payload shape rather than by key name: any
    write carrying a recipient must match the tenant's committed profile, and a
    delivery-shaped key with no verifiable recipient is denied. Renaming the key
    therefore does not bypass validation.

    The profile (``PROFILE_KEY``, any spelling) sets the address outbound
    calls are checked against, so changing a committed profile is a step-up
    action: the write is held as pending and blocked, and only
    :meth:`approve_profile_change` commits it. That method is the out-of-band
    path — a human confirming through a channel the agent cannot reach — and
    no tool call can invoke it. The first profile is allowed as onboarding;
    securing onboarding itself is out of scope for this lab.
    """

    mode: ScenarioMode = "protected"

    def __init__(self, store: Store, client: OGIClient) -> None:
        self._store = store
        self._client = client
        self._pending_profiles: dict[str, str] = {}

    def pending_profile(self, owner: str) -> str | None:
        """The profile change awaiting approval for ``owner``, if any."""
        return self._pending_profiles.get(owner)

    def approve_profile_change(self, owner: str) -> ToolExecution:
        """Commit a pending profile change after out-of-band approval.

        Call this only from the trusted approval channel, never from model
        output. The approved value is exactly the one that was held.
        """
        value = self._pending_profiles.pop(owner, None)
        call = ToolCall("write", owner, PROFILE_KEY, value)
        if value is None:
            return ToolExecution(
                decision="block", call=call, reason="no pending profile change"
            )
        self._commit_write(call)
        return ToolExecution(decision="allow", call=call)

    def _commit_write(self, call: ToolCall) -> None:
        self._client.propose(call.owner, call.key, call.value or "")
        self._client.commit(call.owner, call.key)
        self._store.write(call.owner, call.key, call.value or "")

    def execute(self, requester: str, call: ToolCall) -> ToolExecution:
        ownership = authorize_owner_scope(requester, call)
        if not ownership.allowed:
            return _blocked(call, ownership)

        if call.action == "write":
            if is_profile_key(call.key):
                committed = self._client.committed_entry(call.owner, PROFILE_KEY)
                step_up = authorize_profile_change(committed is not None)
                if not step_up.allowed:
                    self._pending_profiles[call.owner] = call.value or ""
                    return _blocked(call, step_up)

            recipients = recipients_requiring_validation(call)
            if recipients is not None:
                verification = self._client.verify_recipients(recipients, call.owner)
                lineage = authorize_recipient_lineage(verification)
                if not lineage.allowed:
                    reason = lineage.reason or "lineage violation"
                    self._client.anomaly(call.owner, call.key, reason)
                    return _blocked(call, lineage)

            self._commit_write(call)
            return ToolExecution(decision="allow", call=call)

        value = self._client.read(call.owner, call.key)
        if value is None:
            return ToolExecution(decision="block", call=call)
        return ToolExecution(
            decision="allow",
            call=call,
            value=self._store.read(call.owner, call.key),
        )
