"""Unit and integration tests for the OGI shared memory layer."""

from __future__ import annotations

import json

from data_segregation_lab.cli import _select_backend
from data_segregation_lab.executors import OGIProvenanceExecutor
from data_segregation_lab.models import ToolCall
from data_segregation_lab.ogi import OGIClient, OGIMemoryEntry
from data_segregation_lab.scenario import run_ogi_contamination_scenario
from data_segregation_lab.storage import InMemoryStore


backend, _ = _select_backend([])


def _entry(client: OGIClient, owner: str, key: str) -> OGIMemoryEntry | None:
    head = client._head(owner, key)
    return client._entries.get(head)


# ---- OGI client behavior ----


def test_propose_then_commit_creates_committed_entry() -> None:
    client = OGIClient()
    entry, _ = client.propose("client_a", "client_profile", "draft_v1")
    assert _entry(client, "client_a", "client_profile").state == "proposed"
    committed = client.commit("client_a", "client_profile")
    assert committed is not None
    assert committed.state == "committed"
    assert committed.prev_hash != entry.prev_hash
    assert committed.value == "draft_v1"


def test_committed_read_returns_value() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", "draft_v1")
    client.commit("client_a", "client_profile")
    assert client.read("client_a", "client_profile") == "draft_v1"


def test_anomaly_replaces_committed() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", "draft_v1")
    client.commit("client_a", "client_profile")
    client.anomaly("client_a", "client_profile", "contaminated")
    assert client.read("client_a", "client_profile") is None
    assert _entry(client, "client_a", "client_profile").state == "anomaly"


def test_cross_owner_isolation() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", "draft_v1")
    client.commit("client_a", "client_profile")
    assert client.read("client_b", "client_profile") is None


def test_anomaly_exposes_reason() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", "draft_v1")
    client.commit("client_a", "client_profile")
    client.anomaly("client_a", "client_profile", "lineage violation")
    entry = _entry(client, "client_a", "client_profile")
    assert entry is not None and entry.reason == "lineage violation"


def test_verify_replay_detects_tampered_hash() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", "draft_v1")
    client.commit("client_a", "client_profile")
    assert not client.verify_replay("0000000000000000000000000000000000000000000000000000000000000000")


def test_verify_email_recipient_allows_verified_recipient() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", json.dumps({"client_email": "sarah@client.com", "portfolio_value": "$4.25M"}))
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_email_recipient("sarah@client.com", "client_a")
    assert allowed is True
    assert reason is None


def test_verify_email_recipient_blocks_unverified_recipient() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", json.dumps({"client_email": "sarah@client.com", "portfolio_value": "$4.25M"}))
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_email_recipient("attacker@protonmail.com", "client_a")
    assert allowed is False
    assert reason is not None
    assert "attacker@protonmail.com" in reason


def test_verify_email_recipient_blocks_when_no_profile() -> None:
    client = OGIClient()
    allowed, reason = client.verify_email_recipient("sarah@client.com", "client_a")
    assert allowed is False
    assert reason == "no verified client profile committed"


# ---- OGI executor behavior ----


def test_ogi_executor_blocks_cross_owner_write() -> None:
    store = InMemoryStore()
    client = OGIClient()
    executor = OGIProvenanceExecutor(store, client)
    execution = executor.execute(
        "client_b", ToolCall("write", "client_a", "email_action", json.dumps({"to": "x", "bcc": "y"})),
    )
    assert execution.decision == "block"


def test_ogi_executor_allows_committed_value_read() -> None:
    store = InMemoryStore()
    client = OGIClient()
    client.propose("client_a", "api_key", "secret")
    client.commit("client_a", "api_key")
    store.write("client_a", "api_key", "secret")
    executor = OGIProvenanceExecutor(store, client)
    execution = executor.execute("client_a", ToolCall("read", "client_a", "api_key"))
    assert execution.decision == "allow"
    assert execution.value == "secret"


def test_ogi_executor_flags_contaminated_email_as_anomaly() -> None:
    store = InMemoryStore()
    client = OGIClient()
    client.propose("client_a", "client_profile", json.dumps({"client_email": "sarah@client.com"}))
    client.commit("client_a", "client_profile")
    executor = OGIProvenanceExecutor(store, client)
    execution = executor.execute(
        "client_a",
        ToolCall("write", "client_a", "email_action", json.dumps({"to": "client-a@example.com", "bcc": "attacker@protonmail.com"})),
    )
    assert execution.decision == "block"
    reason = execution.reason or ""
    assert "lineage" in reason.lower()
    assert _entry(client, "client_a", "email_action").state == "anomaly"


def test_ogi_protected_path_blocks_prompt_injection_into_bcc() -> None:
    result = run_ogi_contamination_scenario(backend)
    assert result.attack == "ogi_contamination"
    assert result.ogi_leak_blocked is True
    assert result.write_execution.decision == "block"
