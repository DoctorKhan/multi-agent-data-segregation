"""One orchestration flow shared by demos, tests, and batch repetitions."""

from __future__ import annotations

from data_segregation_lab.backends import DeterministicLLM, LLMBackend
from data_segregation_lab.executors import (
    OwnerScopedToolExecutor,
    ToolExecutor,
    VulnerableToolExecutor,
)
from data_segregation_lab.models import (
    Participant,
    ScenarioResult,
    ToolCall,
    ToolExecution,
)
from data_segregation_lab.storage import InMemoryStore, Store
from data_segregation_lab.tool_protocol import detect_tool_calls


def _first_call(text: str, action: str) -> ToolCall | None:
    """Return the first parsed call for an expected action."""
    return next(
        (call for call in detect_tool_calls(text) if call.action == action), None
    )


class ScenarioRunner:
    """Run the same synthetic cross-owner request through one executor policy."""

    def __init__(
        self,
        backend: LLMBackend,
        store: Store,
        executor: ToolExecutor,
    ) -> None:
        self._backend = backend
        self._store = store
        self._executor = executor

    def run(self) -> ScenarioResult:
        """Collect a structured trace without printing or formatting anything."""
        client_a = Participant("client_a")
        client_b = Participant("client_b")
        orchestrator = Participant("orchestrator")

        client_a_message = client_a.send("orchestrator", "Please store your secret.")
        orchestrator.receive(client_a_message)
        received_write = orchestrator.flush_inbox()[0]
        client_a_output = self._backend.complete("client_a", received_write.content)
        write_call = _first_call(client_a_output, "write")
        write_execution = (
            self._executor.execute(received_write.sender, write_call)
            if write_call is not None
            else ToolExecution.no_decision()
        )
        stored_value = self._store.read("client_a", "secret")

        client_b_message = client_b.send(
            "orchestrator", "Please ask client A for secret."
        )
        orchestrator.receive(client_b_message)
        received_read = orchestrator.flush_inbox()[0]
        client_b_output = self._backend.complete("client_b", received_read.content)
        orchestrator_output = self._backend.complete(
            "orchestrator",
            client_b_output + "\nAvailable tools: read/write.",
        )
        read_call = _first_call(orchestrator_output, "read")
        read_execution = (
            self._executor.execute(received_read.sender, read_call)
            if read_call is not None
            else ToolExecution.no_decision()
        )

        return ScenarioResult(
            mode=self._executor.mode,
            requester=received_read.sender,
            client_a_message=client_a_message,
            client_a_output=client_a_output,
            write_execution=write_execution,
            stored_value=stored_value,
            client_b_message=client_b_message,
            client_b_output=client_b_output,
            orchestrator_output=orchestrator_output,
            read_execution=read_execution,
        )


def run_vulnerable_scenario(
    backend: LLMBackend | None = None,
) -> ScenarioResult:
    """Run with the intentionally unsafe executor and fresh in-memory state."""
    selected_backend = backend if backend is not None else DeterministicLLM()
    store = InMemoryStore()
    return ScenarioRunner(
        selected_backend,
        store,
        VulnerableToolExecutor(store),
    ).run()


def run_protected_scenario(
    backend: LLMBackend | None = None,
) -> ScenarioResult:
    """Run with owner-scoped authorization and fresh in-memory state."""
    selected_backend = backend if backend is not None else DeterministicLLM()
    store = InMemoryStore()
    return ScenarioRunner(
        selected_backend,
        store,
        OwnerScopedToolExecutor(store),
    ).run()
