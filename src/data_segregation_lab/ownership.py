"""Intelligence ownership registry for synthetic tenant data."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Classification = Literal["client_financial", "advisor_notes", "operational"]


@dataclass(frozen=True)
class OwnedRecord:
    """One namespaced value and who may access it."""

    owner: str
    key: str
    classification: Classification


@dataclass
class IntelligenceRegistry:
    """Maps stored keys to ownership and sensitivity — authorization stays in executors."""

    _records: dict[tuple[str, str], OwnedRecord] = field(
        default_factory=lambda: dict[tuple[str, str], OwnedRecord]()
    )

    def register(
        self,
        owner: str,
        key: str,
        *,
        classification: Classification = "client_financial",
    ) -> OwnedRecord:
        """Declare that ``owner`` holds ``key`` with a given sensitivity."""
        record = OwnedRecord(owner, key, classification)
        self._records[(owner.casefold(), key)] = record
        return record

    def lookup(self, owner: str, key: str) -> OwnedRecord | None:
        """Return ownership metadata for a namespace, if registered."""
        return self._records.get((owner.casefold(), key))

    def owners(self) -> frozenset[str]:
        """Return every owner that has registered intelligence."""
        return frozenset(record.owner for record in self._records.values())
