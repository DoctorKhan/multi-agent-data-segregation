"""Shared memory (OGI-style) with append-only provenance chain."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Literal, cast


State = Literal["proposed", "committed", "anomaly"]

# Fields that can carry an outbound recipient. `to` alone is not enough: bcc is
# the field an injected instruction actually uses to exfiltrate.
RECIPIENT_FIELDS = ("to", "cc", "bcc", "reply_to", "recipients")

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


class _ChainMaterial:
    def hash(self, owner: str, key: str, value: str, prev_hash: str) -> str:
        return _sha256(owner, key, value, prev_hash)


class OGIClient:
    """Append-only shared memory with proposal / commit / anomaly flow.

    Executors should never write directly to raw storage when OGI is in use.
    They propose, optionally commit or mark anomaly, and read committed
    entries only so untrusted agents do not ingest unverified data.
    """

    def __init__(self) -> None:
        self._material = _ChainMaterial()
        self._entries: dict[str, OGIMemoryEntry] = {}
        self._index: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def _head(self, owner: str, key: str) -> str:
        return self._index.get((owner.casefold(), key.casefold()), "")

    def _lookup(self, owner: str, key: str) -> OGIMemoryEntry | None:
        head = self._head(owner, key)
        with self._lock:
            return self._entries.get(head)

    def propose(self, owner: str, key: str, value: str) -> tuple[OGIMemoryEntry, str]:
        prior = self._head(owner, key)
        entry_hash = self._material.hash(owner, key, value, prior)
        entry = OGIMemoryEntry(
            owner=owner,
            key=key,
            value=value,
            prev_hash=prior,
            state="proposed",
        )
        with self._lock:
            self._entries[entry_hash] = entry
            self._index[(owner.casefold(), key.casefold())] = entry_hash
        return entry, entry_hash

    def commit(self, owner: str, key: str) -> OGIMemoryEntry | None:
        proposed_hash = self._head(owner, key)
        with self._lock:
            proposed = self._entries.get(proposed_hash)
            if proposed is None or proposed.state != "proposed":
                return None
            committed_hash = _sha256(
                proposed.owner,
                proposed.key,
                proposed.value + ":committed",
                proposed_hash,
            )
            committed = OGIMemoryEntry(
                owner=proposed.owner,
                key=proposed.key,
                value=proposed.value,
                prev_hash=proposed_hash,
                state="committed",
            )
            self._entries[committed_hash] = committed
            self._index[(proposed.owner.casefold(), proposed.key.casefold())] = (
                committed_hash
            )
            return committed

    def anomaly(self, owner: str, key: str, reason: str) -> OGIMemoryEntry | None:
        current = self._lookup(owner, key)
        with self._lock:
            if current is None or current.state not in {"proposed", "committed"}:
                proposed_hash = self._material.hash(owner, key, "", "")
                flagged_hash = _sha256(owner, key, f"anomaly:{reason}", proposed_hash)
                flagged = OGIMemoryEntry(
                    owner=owner,
                    key=key,
                    value="",
                    prev_hash=proposed_hash,
                    state="anomaly",
                    reason=reason,
                )
                self._entries[flagged_hash] = flagged
                self._index[(owner.casefold(), key.casefold())] = flagged_hash
                return flagged
            flagged_hash = _sha256(
                current.owner, current.key, f"anomaly:{reason}", current.prev_hash
            )
            flagged = OGIMemoryEntry(
                owner=current.owner,
                key=current.key,
                value=current.value,
                prev_hash=current.prev_hash,
                state="anomaly",
                reason=reason,
            )
            self._entries[flagged_hash] = flagged
            self._index[(current.owner.casefold(), current.key.casefold())] = (
                flagged_hash
            )
            return flagged

    def state(self, owner: str, key: str) -> OGIMemoryEntry | None:
        """Public fallback so scenario code can inspect OGI state."""
        return self._lookup(owner, key)

    def read(self, owner: str, key: str) -> str | None:
        entry = self.state(owner, key)
        if entry is None or entry.state != "committed":
            return None
        return entry.value

    def committed_entry(self, owner: str, key: str) -> OGIMemoryEntry | None:
        entry = self.state(owner, key)
        if entry is None or entry.state != "committed":
            return None
        return entry

    def verify_replay(self, claimed_hash: str) -> bool:
        with self._lock:
            return claimed_hash in self._entries

    def lineage(self, owner: str, key: str) -> list[OGIMemoryEntry]:
        out: list[OGIMemoryEntry] = []
        head = self._head(owner, key)
        with self._lock:
            seen: set[str] = set()
            while head:
                if head in seen:
                    break
                seen.add(head)
                entry = self._entries.get(head)
                if entry is None:
                    break
                out.append(entry)
                head = entry.prev_hash
        return out

    def verified_email(
        self,
        owner: str,
        client_profile_key: str = "client_profile",
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
        proposed_recipients: list[str],
        owner: str,
        client_profile_key: str = "client_profile",
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
        client_profile_key: str = "client_profile",
    ) -> tuple[bool, str | None]:
        """Single-recipient convenience wrapper over :meth:`verify_recipients`."""
        return self.verify_recipients(
            [proposed_recipient] if proposed_recipient else [],
            owner,
            client_profile_key,
        )

    def mark_anomaly(self, owner: str, key: str, reason: str) -> OGIMemoryEntry | None:
        head = self._head(owner, key)
        with self._lock:
            current = self._entries.get(head)
            if current is None or current.state not in {"proposed", "committed"}:
                return None
            flagged_hash = _sha256(
                current.owner, current.key, f"anomaly:{reason}", current.prev_hash
            )
            flagged = OGIMemoryEntry(
                owner=current.owner,
                key=current.key,
                value=current.value,
                prev_hash=current.prev_hash,
                state="anomaly",
                reason=reason,
            )
            self._entries[flagged_hash] = flagged
            self._index[(current.owner.casefold(), current.key.casefold())] = (
                flagged_hash
            )
            return self._entries[flagged_hash]
