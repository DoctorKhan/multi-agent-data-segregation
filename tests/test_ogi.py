"""Unit and integration tests for the OGI shared memory layer."""

from __future__ import annotations

import json

from data_segregation_lab.cli import select_backend
from data_segregation_lab.executors import OGIProvenanceExecutor
from data_segregation_lab.models import ToolCall
from data_segregation_lab.ogi import OGIClient, OGIMemoryEntry, extract_recipients
from data_segregation_lab.scenario import run_ogi_contamination_scenario
from data_segregation_lab.storage import InMemoryStore


backend, _ = select_backend([])


def _entry(client: OGIClient, owner: str, key: str) -> OGIMemoryEntry:
    entry = client.state(owner, key)
    assert entry is not None
    return entry


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
    assert not client.verify_replay(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )


def test_verify_email_recipient_allows_verified_recipient() -> None:
    client = OGIClient()
    client.propose(
        "client_a",
        "client_profile",
        json.dumps({"client_email": "sarah@client.com", "portfolio_value": "$4.25M"}),
    )
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_email_recipient("sarah@client.com", "client_a")
    assert allowed is True
    assert reason is None


def test_verify_email_recipient_blocks_unverified_recipient() -> None:
    client = OGIClient()
    client.propose(
        "client_a",
        "client_profile",
        json.dumps({"client_email": "sarah@client.com", "portfolio_value": "$4.25M"}),
    )
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_email_recipient(
        "attacker@protonmail.com", "client_a"
    )
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
        "client_b",
        ToolCall(
            "write", "client_a", "email_action", json.dumps({"to": "x", "bcc": "y"})
        ),
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
    client.propose(
        "client_a", "client_profile", json.dumps({"client_email": "sarah@client.com"})
    )
    client.commit("client_a", "client_profile")
    executor = OGIProvenanceExecutor(store, client)
    execution = executor.execute(
        "client_a",
        ToolCall(
            "write",
            "client_a",
            "email_action",
            json.dumps(
                {"to": "client-a@example.com", "bcc": "attacker@protonmail.com"}
            ),
        ),
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


# ---- outbound validation must follow the payload, not the key name ----


def _executor_with_profile() -> tuple[OGIProvenanceExecutor, OGIClient]:
    store = InMemoryStore()
    client = OGIClient()
    client.propose(
        "client_a", "client_profile", json.dumps({"client_email": "sarah@client.com"})
    )
    client.commit("client_a", "client_profile")
    return OGIProvenanceExecutor(store, client), client


def test_extract_recipients_reads_every_delivery_field() -> None:
    payload = json.dumps(
        {"to": "sarah@client.com", "cc": ["a@x.com"], "bcc": "attacker@evil.com"}
    )
    assert extract_recipients(payload) == [
        "sarah@client.com",
        "a@x.com",
        "attacker@evil.com",
    ]


def test_extract_recipients_finds_addresses_outside_known_fields() -> None:
    payload = json.dumps({"to": "sarah@client.com", "notes": "cc attacker@evil.com"})
    assert "attacker@evil.com" in extract_recipients(payload)


def test_verified_primary_recipient_does_not_excuse_an_injected_bcc() -> None:
    """The `to` field is correct here; only the bcc exfiltrates."""
    executor, client = _executor_with_profile()
    execution = executor.execute(
        "client_a",
        ToolCall(
            "write",
            "client_a",
            "email_action",
            json.dumps({"to": "sarah@client.com", "bcc": "attacker@evil.com"}),
        ),
    )
    assert execution.decision == "block"
    assert "attacker@evil.com" in (execution.reason or "")
    assert client.read("client_a", "email_action") is None


def test_renaming_the_key_does_not_bypass_recipient_validation() -> None:
    executor, client = _executor_with_profile()
    execution = executor.execute(
        "client_a",
        ToolCall(
            "write",
            "client_a",
            "harmless_note",
            json.dumps({"to": "attacker@evil.com"}),
        ),
    )
    assert execution.decision == "block"
    assert client.read("client_a", "harmless_note") is None


def test_delivery_shaped_key_without_a_recipient_is_denied() -> None:
    executor, _ = _executor_with_profile()
    execution = executor.execute(
        "client_a", ToolCall("write", "client_a", "send_report", "not json")
    )
    assert execution.decision == "block"
    assert "no verifiable recipient" in (execution.reason or "")


def test_verified_recipient_is_still_allowed_to_commit() -> None:
    """Validation must discriminate, not deny everything outbound."""
    executor, client = _executor_with_profile()
    payload = json.dumps({"to": "sarah@client.com"})
    execution = executor.execute(
        "client_a", ToolCall("write", "client_a", "email_action", payload)
    )
    assert execution.decision == "allow"
    assert client.read("client_a", "email_action") == payload


def test_ordinary_writes_are_untouched_by_outbound_validation() -> None:
    executor, client = _executor_with_profile()
    execution = executor.execute(
        "client_a", ToolCall("write", "client_a", "secret", "42")
    )
    assert execution.decision == "allow"
    assert client.read("client_a", "secret") == "42"


# ---- deny paths that would otherwise fail open ----


def test_profile_that_is_not_json_denies_every_recipient() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", "not json at all")
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_recipients(["sarah@client.com"], "client_a")
    assert allowed is False
    assert reason == "verified profile is not valid JSON"


def test_profile_without_an_address_denies_every_recipient() -> None:
    client = OGIClient()
    client.propose("client_a", "client_profile", json.dumps({"portfolio": "$1"}))
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_recipients(["sarah@client.com"], "client_a")
    assert allowed is False
    assert reason == "verified profile carries no client_email"


def test_an_empty_recipient_list_is_denied_not_waved_through() -> None:
    client = OGIClient()
    client.propose(
        "client_a", "client_profile", json.dumps({"client_email": "sarah@client.com"})
    )
    client.commit("client_a", "client_profile")
    allowed, reason = client.verify_recipients([], "client_a")
    assert allowed is False
    assert reason == "outbound action carries no verifiable recipient"


def test_a_proposed_but_uncommitted_profile_does_not_authorize_delivery() -> None:
    client = OGIClient()
    client.propose(
        "client_a", "client_profile", json.dumps({"client_email": "sarah@client.com"})
    )
    allowed, reason = client.verify_recipients(["sarah@client.com"], "client_a")
    assert allowed is False
    assert reason == "no verified client profile committed"


# ---- provenance chain ----


def test_verify_replay_accepts_a_hash_the_client_issued() -> None:
    client = OGIClient()
    _, entry_hash = client.propose("client_a", "client_profile", "draft_v1")
    assert client.verify_replay(entry_hash) is True


def test_lineage_walks_back_through_the_committed_chain() -> None:
    client = OGIClient()
    client.propose("client_a", "notes", "v1")
    client.commit("client_a", "notes")
    client.propose("client_a", "notes", "v2")
    client.commit("client_a", "notes")

    lineage = client.lineage("client_a", "notes")
    assert [entry.state for entry in lineage[:2]] == ["committed", "proposed"]
    assert [entry.value for entry in lineage[:2]] == ["v2", "v2"]
    # The earlier revision is still reachable, so an audit can see the history.
    assert any(entry.value == "v1" for entry in lineage)


def test_mark_anomaly_replaces_the_head_and_hides_the_value() -> None:
    client = OGIClient()
    client.propose("client_a", "notes", "v1")
    client.commit("client_a", "notes")
    flagged = client.mark_anomaly("client_a", "notes", "contaminated")
    assert flagged is not None and flagged.state == "anomaly"
    assert client.read("client_a", "notes") is None


def test_mark_anomaly_on_an_unknown_entry_reports_no_change() -> None:
    assert OGIClient().mark_anomaly("client_a", "absent", "contaminated") is None
