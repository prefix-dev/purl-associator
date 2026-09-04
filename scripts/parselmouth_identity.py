"""Identity policy for distributions reported by Parselmouth."""

from __future__ import annotations

from collections.abc import Iterable


def artifact_identity_pairs(
    pairs: Iterable[tuple[str, str]], *, normalized_conda_name: str
) -> list[tuple[str, str]]:
    """Keep unambiguous or package-correlated artifact distributions."""
    candidates = list(pairs)
    if len(candidates) <= 1:
        return candidates

    return [(purl, name) for purl, name in candidates if name == normalized_conda_name]
