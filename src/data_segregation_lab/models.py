"""Small, dependency-free data structures shared across the lab."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ToolAction = Literal["read", "write"]
Decision = Literal["allow", "block", "no_decision"]
ScenarioMode = Literal["vulnerable", "protected"]


@dataclass(frozen=True)
class ToolCall:
    """A parsed storage operation proposed by untrusted model output."""

    action: ToolAction
    owner: str
    key: str
    value: str | None = None


@dataclass(frozen=True)
class AgentMessage:
    """A message whose sender is assigned by the simulation, not the model."""

    sender: str
    recipient: str
    content: str


@dataclass
class Participant:
    """A trusted identity and inbox used to make message routing explicit."""

    name: str
    inbox: list[AgentMessage] = field(default_factory=lambda: list[AgentMessage]())

    def send(self, recipient: str, content: str) -> AgentMessage:
        """Create a message with this participant as its trusted sender."""
        return AgentMessage(self.name, recipient, content.strip())

    def receive(self, message: AgentMessage) -> None:
        """Queue a message for synchronous processing by the scenario runner."""
        self.inbox.append(message)

    def flush_inbox(self) -> list[AgentMessage]:
        """Return queued messages once, then empty the inbox."""
        messages = list(self.inbox)
        self.inbox.clear()
        return messages


@dataclass(frozen=True)
class ToolExecution:
    """The policy decision and result for one proposed tool call."""

    decision: Decision
    call: ToolCall | None = None
    value: str | None = None

    @classmethod
    def no_decision(cls) -> ToolExecution:
        """Represent model output that contained no executable call."""
        return cls(decision="no_decision")


@dataclass(frozen=True)
class ScenarioResult:
    """Structured evidence from one scenario, independent of terminal output."""

    mode: ScenarioMode
    requester: str
    client_a_message: AgentMessage
    client_a_output: str
    write_execution: ToolExecution
    stored_value: str | None
    client_b_message: AgentMessage
    client_b_output: str
    orchestrator_output: str
    read_execution: ToolExecution

    @property
    def leaked(self) -> bool:
        """Return whether another owner's value reached the requester."""
        call = self.read_execution.call
        return (
            self.read_execution.decision == "allow"
            and self.read_execution.value is not None
            and call is not None
            and self.requester != call.owner
        )
