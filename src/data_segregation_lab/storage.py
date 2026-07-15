"""Storage interfaces and the process-local implementation used by the lab."""

from __future__ import annotations

import threading
from typing import Protocol


class Store(Protocol):
    """Storage contract expected by tool executors."""

    def write(self, owner: str, key: str, value: str) -> None: ...

    def read(self, owner: str, key: str) -> str | None: ...

    def snapshot(self) -> dict[tuple[str, str], str]: ...


class InMemoryStore:
    """Thread-safe namespaced storage with no built-in authorization.

    A tuple is used as the internal key so delimiter characters in an owner or
    logical key cannot create collisions. Authorization intentionally belongs
    to the executor, which has access to the trusted requester identity.
    """

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _storage_key(owner: str, key: str) -> tuple[str, str]:
        """Normalize owner lookup while preserving the logical key exactly."""
        return owner.casefold(), key

    def write(self, owner: str, key: str, value: str) -> None:
        """Store a value in the claimed owner's namespace."""
        with self._lock:
            self._data[self._storage_key(owner, key)] = value

    def read(self, owner: str, key: str) -> str | None:
        """Read from a claimed namespace; the caller must authorize first."""
        with self._lock:
            return self._data.get(self._storage_key(owner, key))

    def snapshot(self) -> dict[tuple[str, str], str]:
        """Return a copy so diagnostics cannot mutate internal state."""
        with self._lock:
            return dict(self._data)
