"""Direct tests of the deliberately contrasting enforcement policies."""

from data_segregation_lab.executors import (
    OwnerScopedToolExecutor,
    VulnerableToolExecutor,
)
from data_segregation_lab.models import ToolCall
from data_segregation_lab.storage import InMemoryStore


def test_vulnerable_executor_trusts_claimed_owner() -> None:
    store = InMemoryStore()
    store.write("client_a", "secret", "42")
    execution = VulnerableToolExecutor(store).execute(
        "client_b", ToolCall("read", "client_a", "secret")
    )
    assert execution.decision == "allow"
    assert execution.value == "42"


def test_owner_scoped_executor_blocks_cross_owner_read_before_storage() -> None:
    store = InMemoryStore()
    store.write("client_a", "secret", "42")
    execution = OwnerScopedToolExecutor(store).execute(
        "client_b", ToolCall("read", "client_a", "secret")
    )
    assert execution.decision == "block"
    assert execution.value is None


def test_owner_scoped_executor_blocks_cross_owner_write() -> None:
    store = InMemoryStore()
    execution = OwnerScopedToolExecutor(store).execute(
        "client_b", ToolCall("write", "client_a", "secret", "tampered")
    )
    assert execution.decision == "block"
    assert store.read("client_a", "secret") is None
