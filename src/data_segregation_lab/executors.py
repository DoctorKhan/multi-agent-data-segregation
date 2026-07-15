"""Contrasting tool-enforcement boundaries used by the demonstration."""

from __future__ import annotations

from typing import Protocol

from data_segregation_lab.models import ScenarioMode, ToolCall, ToolExecution
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
