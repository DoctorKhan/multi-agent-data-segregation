"""Unit tests for process-local namespaced storage."""

from __future__ import annotations

import threading

from data_segregation_lab.storage import InMemoryStore


def test_write_then_read_returns_value() -> None:
    store = InMemoryStore()
    store.write("client_a", "secret", "42")
    assert store.read("client_a", "secret") == "42"


def test_missing_key_returns_none() -> None:
    assert InMemoryStore().read("client_a", "missing") is None


def test_values_are_namespaced_by_owner() -> None:
    store = InMemoryStore()
    store.write("client_a", "secret", "42")
    store.write("client_b", "secret", "7")
    assert store.read("client_a", "secret") == "42"
    assert store.read("client_b", "secret") == "7"


def test_tuple_keys_prevent_delimiter_collisions() -> None:
    """Owner/key pairs remain distinct even when either contains a colon."""
    store = InMemoryStore()
    store.write("client:a", "secret", "first")
    store.write("client", "a:secret", "second")
    assert store.read("client:a", "secret") == "first"
    assert store.read("client", "a:secret") == "second"


def test_concurrent_reads_and_writes_do_not_raise() -> None:
    store = InMemoryStore()
    errors: list[Exception] = []

    def writer() -> None:
        for value in range(500):
            store.write("client_a", "secret", str(value))

    def reader() -> None:
        for _ in range(500):
            try:
                store.read("client_a", "secret")
            except Exception as exc:  # pragma: no cover - defensive capture
                errors.append(exc)

    threads = [threading.Thread(target=task) for task in (writer, reader) * 2]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
