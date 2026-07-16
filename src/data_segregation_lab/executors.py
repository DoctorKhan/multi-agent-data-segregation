"""Contrasting tool-enforcement boundaries used by the demonstration."""

from __future__ import annotations

from typing import Protocol

from data_segregation_lab.models import ScenarioMode, ToolCall, ToolExecution
from data_segregation_lab.ogi import OGIClient
from data_segregation_lab.storage import Store


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
            if call.key == "email_action" and call.value is not None:
                allowed, reason = self._client.verify_email_recipient(
                    self._extract_recipient(call.value),
                    call.owner,
                )
                if not allowed:
                    self._client.anomaly(call.owner, call.key, reason or "lineage violation")
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

    @staticmethod
    def _extract_recipient(payload: str) -> str:
        import json
        try:
            data = json.loads(payload)
            return str(data.get("to") or data.get("client_email") or "")
        except Exception:
            return ""
