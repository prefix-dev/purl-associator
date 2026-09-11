"""Dependency-free cache policy for the automatic PURL mapper."""

from __future__ import annotations

from typing import Protocol


class CachedAutomapEntry(Protocol):
    version: str
    build: str
    note: str | None
    download_count: int | None


def has_recorded_fetch_error(entry: CachedAutomapEntry) -> bool:
    """Return whether an entry records a failed processing attempt."""
    return isinstance(entry.note, str) and entry.note.strip().lower().startswith(
        "fetch error:"
    )


def preserved_download_count(
    entry: CachedAutomapEntry | None,
    *,
    name: str,
    fallback: dict[str, int],
) -> int | None:
    """Keep hydrated counts independent from recipe-fetch cache decisions."""
    return entry.download_count if entry is not None else fallback.get(name)


def can_reuse_cached_entry(
    entry: CachedAutomapEntry | None,
    *,
    version: str,
    build: str,
    force: bool,
) -> bool:
    """Reuse only an unchanged successful entry when refresh is not forced."""
    return bool(
        not force
        and entry is not None
        and entry.version == version
        and entry.build == build
        and not has_recorded_fetch_error(entry)
    )
