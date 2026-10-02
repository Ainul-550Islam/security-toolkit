"""Storage contracts.

Deliberately narrow. The legacy ``python/store.py`` remains the production
persistence layer for existing phases; this interface exists so foundation
components (health, registry, config) can depend on a CONTRACT rather than on
a concrete database, and so a future adapter can wrap ``store.Database``
without either side importing the other.

No SQL, no schema and no connection handling live here.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ReadOnlyStore(Protocol):
    """Query-only access."""

    def get(self, collection: str, key: str) -> Mapping[str, Any] | None:
        """Return one record, or None. Must not raise for a missing key."""
        ...

    def list(
        self, collection: str, *, limit: int = 100, offset: int = 0
    ) -> Sequence[Mapping[str, Any]]:
        """Return a bounded page of records. ``limit`` is always enforced."""
        ...


@runtime_checkable
class KeyValueStore(ReadOnlyStore, Protocol):
    """Read/write access."""

    def put(self, collection: str, key: str, value: Mapping[str, Any]) -> None:
        """Insert or replace a record."""
        ...

    def delete(self, collection: str, key: str) -> bool:
        """Remove a record; True when something was removed."""
        ...


@runtime_checkable
class HealthCheckable(Protocol):
    """A dependency that can report whether it is reachable."""

    def ping(self) -> bool:
        """True when reachable. Must not raise."""
        ...


class InMemoryStore:
    """Non-durable reference implementation.

    Used by tests and by components that need a store-shaped dependency
    without a database. It is explicitly NOT a production store: nothing is
    persisted and nothing survives the process.
    """

    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, Any]]] = {}

    def get(self, collection: str, key: str) -> Mapping[str, Any] | None:
        return self._data.get(collection, {}).get(key)

    def list(
        self, collection: str, *, limit: int = 100, offset: int = 0
    ) -> Sequence[Mapping[str, Any]]:
        bounded = max(0, min(int(limit), 1000))
        items = list(self._data.get(collection, {}).values())
        return items[max(0, int(offset)):max(0, int(offset)) + bounded]

    def put(self, collection: str, key: str, value: Mapping[str, Any]) -> None:
        self._data.setdefault(collection, {})[key] = dict(value)

    def delete(self, collection: str, key: str) -> bool:
        return self._data.get(collection, {}).pop(key, None) is not None

    def ping(self) -> bool:
        return True

    def collections(self) -> Iterator[str]:
        return iter(sorted(self._data))


__all__ = ["ReadOnlyStore", "KeyValueStore", "HealthCheckable", "InMemoryStore"]
