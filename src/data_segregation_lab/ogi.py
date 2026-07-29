"""Shared memory (OGI-style) with append-only provenance chain."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal, cast


State = Literal["proposed", "committed", "anomaly"]

# Fields that can carry an outbound recipient. `to` alone is not enough: bcc is
# the field an injected instruction actually uses to exfiltrate.
RECIPIENT_FIELDS = ("to", "cc", "bcc", "reply_to", "recipients")

DEFAULT_PROFILE_KEY = "client_profile"

_EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def extract_recipients(payload: str) -> list[str]:
    """Collect every address an outbound payload could deliver to.

    Known recipient fields are read structurally, then the whole payload is
    swept for address-shaped text so a recipient hidden in an unexpected field
    still reaches validation. Order is preserved and duplicates removed.
    """
    found: list[str] = []
    try:
        data = json.loads(payload)
    except Exception:
        data = None

    if isinstance(data, dict):
        fields = cast(dict[str, object], data)
        for field in RECIPIENT_FIELDS:
            value: object = fields.get(field)
            if isinstance(value, str):
                found.append(value.strip())
            elif isinstance(value, list):
                entries = cast(list[object], value)
                found.extend(str(item).strip() for item in entries)

    found.extend(_EMAIL_PATTERN.findall(payload))

    seen: set[str] = set()
    recipients: list[str] = []
    for candidate in found:
        if candidate and candidate not in seen:
            seen.add(candidate)
            recipients.append(candidate)
    return recipients


@dataclass(frozen=True)
class OGIMemoryEntry:
    owner: str
    key: str
    value: str
    prev_hash: str
    state: State
    reason: str | None = None


def _sha256(*parts: str) -> str:
    payload = "\x00".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def entry_hash(entry: OGIMemoryEntry) -> str:
    """Address one chain entry.

    Every field that distinguishes an entry is hashed as its own NUL-separated
    part, including ``state``. Packing the state into the value instead (say,
    ``value + ":committed"``) would let a value ending in that literal collide
    with a genuinely committed entry, which is exactly the ambiguity an
    append-only chain exists to rule out.
    """
    return _sha256(
        entry.owner,
        entry.key,
        entry.value,
        entry.prev_hash,
        entry.state,
        entry.reason or "",
    )


class OGIClient:
    """Append-only shared memory with proposal / commit / anomaly flow.

    Executors should never write directly to raw storage when OGI is in use.
    They propose, optionally commit or mark anomaly, and read committed
    entries only so untrusted agents do not ingest unverified data.

    Thread safety: every public method holds ``_lock`` for the whole
    read-modify-write, not merely for the dict mutation. Reading the chain head
    outside the lock would let two concurrent proposals observe the same
    predecessor and both append, forking the one structure whose purpose is
    being unforkable.
    """

    def __init__(self) -> None:
        self._entries: dict[str, OGIMemoryEntry] = {}
        self._index: dict[tuple[str, str], str] = {}
        # Reentrant so a public method can call another without deadlocking.
        self._lock = threading.RLock()

    # -- internals: callers must already hold the lock ----------------------

    def _head(self, owner: str, key: str) -> str:
        return self._index.get((owner.casefold(), key.casefold()), "")

    def _lookup(self, owner: str, key: str) -> OGIMemoryEntry | None:
        return self._entries.get(self._head(owner, key))

    def _append(self, entry: OGIMemoryEntry) -> str:
        """Record an entry and make it the head of its (owner, key) chain."""
        digest = entry_hash(entry)
        self._entries[digest] = entry
        self._index[(entry.owner.casefold(), entry.key.casefold())] = digest
        return digest

    # -- chain operations ---------------------------------------------------

    def propose(self, owner: str, key: str, value: str) -> tuple[OGIMemoryEntry, str]:
        with self._lock:
            entry = OGIMemoryEntry(
                owner=owner,
                key=key,
                value=value,
                prev_hash=self._head(owner, key),
                state="proposed",
            )
            return entry, self._append(entry)

    def commit(self, owner: str, key: str) -> OGIMemoryEntry | None:
        with self._lock:
            proposed_hash = self._head(owner, key)
            proposed = self._entries.get(proposed_hash)
            if proposed is None or proposed.state != "proposed":
                return None
            committed = OGIMemoryEntry(
                owner=proposed.owner,
                key=proposed.key,
                value=proposed.value,
                prev_hash=proposed_hash,
                state="committed",
            )
            self._append(committed)
            return committed

    def anomaly(
        self,
        owner: str,
        key: str,
        reason: str,
        *,
        create_if_missing: bool = True,
    ) -> OGIMemoryEntry | None:
        """Flag a chain as contaminated, hiding its value from readers.

        With no live entry to flag, ``create_if_missing`` decides between
        recording the rejection anyway (the executor's case — a blocked write
        must leave a trace) and reporting that there was nothing to change.
        """
        with self._lock:
            current = self._lookup(owner, key)
            live = current is not None and current.state in {"proposed", "committed"}
            if not live and not create_if_missing:
                return None

            flagged = OGIMemoryEntry(
                owner=current.owner if live and current else owner,
                key=current.key if live and current else key,
                value=current.value if live and current else "",
                prev_hash=self._head(owner, key),
                state="anomaly",
                reason=reason,
            )
            self._append(flagged)
            return flagged

    # -- reads --------------------------------------------------------------

    def state(self, owner: str, key: str) -> OGIMemoryEntry | None:
        """Public fallback so scenario code can inspect OGI state."""
        with self._lock:
            return self._lookup(owner, key)

    def read(self, owner: str, key: str) -> str | None:
        entry = self.committed_entry(owner, key)
        return entry.value if entry is not None else None

    def committed_entry(self, owner: str, key: str) -> OGIMemoryEntry | None:
        with self._lock:
            entry = self._lookup(owner, key)
        if entry is None or entry.state != "committed":
            return None
        return entry

    def verify_replay(self, claimed_hash: str) -> bool:
        """True when this client actually issued the claimed entry hash."""
        with self._lock:
            return claimed_hash in self._entries

    def lineage(self, owner: str, key: str) -> list[OGIMemoryEntry]:
        """Walk head to root, newest first, stopping on a cycle or dead link."""
        out: list[OGIMemoryEntry] = []
        with self._lock:
            head = self._head(owner, key)
            seen: set[str] = set()
            while head and head not in seen:
                seen.add(head)
                entry = self._entries.get(head)
                if entry is None:
                    break
                out.append(entry)
                head = entry.prev_hash
        return out

    # -- outbound validation ------------------------------------------------

    def verified_email(
        self,
        owner: str,
        client_profile_key: str = DEFAULT_PROFILE_KEY,
    ) -> tuple[str | None, str | None]:
        """Return the committed client address, or why it is unavailable."""
        entry = self.committed_entry(owner, client_profile_key)
        if entry is None:
            return None, "no verified client profile committed"
        try:
            data = json.loads(entry.value)
        except Exception:
            return None, "verified profile is not valid JSON"
        address = str(data.get("client_email") or "")
        if not address:
            return None, "verified profile carries no client_email"
        return address, None

    def verify_recipients(
        self,
        proposed_recipients: Sequence[str],
        owner: str,
        client_profile_key: str = DEFAULT_PROFILE_KEY,
    ) -> tuple[bool, str | None]:
        """Default-deny lineage check across every proposed recipient."""
        address, failure = self.verified_email(owner, client_profile_key)
        if address is None:
            return False, failure
        if not proposed_recipients:
            return False, "outbound action carries no verifiable recipient"
        unverified = [
            recipient for recipient in proposed_recipients if recipient != address
        ]
        if unverified:
            return False, (
                f"recipients {', '.join(unverified)} not in verified lineage {address}"
            )
        return True, None

    def verify_email_recipient(
        self,
        proposed_recipient: str,
        owner: str,
        client_profile_key: str = DEFAULT_PROFILE_KEY,
    ) -> tuple[bool, str | None]:
        """Single-recipient convenience wrapper over :meth:`verify_recipients`."""
        return self.verify_recipients(
            [proposed_recipient] if proposed_recipient else [],
            owner,
            client_profile_key,
        )
