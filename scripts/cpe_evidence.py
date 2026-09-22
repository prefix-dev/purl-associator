"""Dependency-light evidence loading for CPE candidate discovery.

This module intentionally uses only the Python standard library so merge-contract
tests can run in the repository's lite environment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OSV_PURL_TYPES = frozenset(
    {"pypi", "npm", "cargo", "gem", "maven", "golang", "cran", "bioconductor"}
)

# ---------- inputs ----------


@dataclass(frozen=True)
class ReviewedCpeSet:
    """The effective reviewed CPE replacement for one conda package."""

    cpes: tuple[str, ...]
    source: str
    reviewer: str | None
    reviewed_at: str | None


def _timestamp_key(value: object, fallback: str) -> tuple[datetime, str]:
    """Sort reviewed layers by UTC instant, then filename as merge_mappings does."""
    if not isinstance(value, str):
        return datetime.min.replace(tzinfo=UTC), fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=UTC), fallback
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC), fallback


def _reviewed_layers(manual: Path, contrib_dir: Path) -> list[tuple[dict, str, bool]]:
    """Load reviewed layers in the same oldest-to-newest order as merge."""
    layers: list[tuple[dict, str, bool]] = []
    if manual.exists():
        try:
            data = json.loads(manual.read_text())
        except json.JSONDecodeError:
            data = {}
        layers.append((data, manual.name, True))

    contributions: list[tuple[tuple[datetime, str], dict, str]] = []
    if contrib_dir.exists():
        for path in sorted(contrib_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text())
            except json.JSONDecodeError:
                continue
            contributions.append(
                (_timestamp_key(data.get("timestamp"), path.name), data, path.name)
            )
    contributions.sort(key=lambda item: item[0])
    layers.extend((data, filename, False) for _key, data, filename in contributions)
    return layers


def _load_effective_cpes(manual: Path, contrib_dir: Path) -> dict[str, ReviewedCpeSet]:
    """Load effective reviewed CPE replacements, including explicit clears."""
    effective: dict[str, ReviewedCpeSet] = {}
    for data, filename, is_manual in _reviewed_layers(manual, contrib_dir):
        for name, entry in (data.get("packages") or {}).items():
            if not isinstance(entry, dict) or "cpes" not in entry:
                continue
            raw_cpes = entry.get("cpes")
            if not isinstance(raw_cpes, list):
                continue
            cpes = tuple(cpe for cpe in raw_cpes if isinstance(cpe, str))
            reviewer = entry.get("approved_by") if is_manual else data.get("author")
            reviewed_at = (
                entry.get("approved_at") if is_manual else data.get("timestamp")
            )
            effective[name] = ReviewedCpeSet(
                cpes=cpes,
                source=filename,
                reviewer=reviewer if isinstance(reviewer, str) else None,
                reviewed_at=reviewed_at if isinstance(reviewed_at, str) else None,
            )
    return effective


def _load_existing_cpes(manual: Path, contrib_dir: Path) -> set[str]:
    """Names whose effective reviewed CPE replacement is non-empty."""
    return {
        name
        for name, reviewed in _load_effective_cpes(manual, contrib_dir).items()
        if reviewed.cpes
    }


@dataclass(frozen=True)
class AutoEntry:
    purl: str | None
    purl_type: str | None
    namespace: str | None
    pkg_name: str | None
    summary: str | None
    download_count: int  # 0 when missing; used for top-N ranking
    version: str | None = None
    source_url: str | None = None
    unmapped: bool = False
    # ``alternative_purls`` entries flattened to their ``type`` strings. Used
    # to detect packages that already have an OSV-mappable identity even when
    # their primary PURL is github/generic.
    alternative_purl_types: tuple[str, ...] = ()

    @property
    def github_owner_repo(self) -> str | None:
        """``owner/repo`` if the PURL is a ``pkg:github`` entry, else None."""
        if (
            self.purl_type == "github"
            and isinstance(self.namespace, str)
            and isinstance(self.pkg_name, str)
        ):
            return f"{self.namespace}/{self.pkg_name}"
        return None

    @property
    def has_osv_alternative(self) -> bool:
        """True if any alternative PURL is in an OSV-indexed ecosystem.

        Such packages do not need CPE discovery here because downstream CVE
        tooling can use the PURL identity first.
        """
        return any(t in OSV_PURL_TYPES for t in self.alternative_purl_types)


_PURL_FIELDS = ("purl", "type", "namespace", "pkg_name")
_PRIMARY_REVIEW_FIELDS = (*_PURL_FIELDS, "unmapped", "status")


def _reviews_primary(override: dict) -> bool:
    return any(
        key in override and override[key] is not None for key in _PRIMARY_REVIEW_FIELDS
    )


def _extract_alt_types(entry: dict) -> tuple[str, ...]:
    """Pull the ``type`` field out of each entry in ``alternative_purls``.
    Handles both the auto.json shape ([{purl, type, namespace, ...}, ...])
    and the simpler review-side shape ([purl-string, ...]) by parsing the
    type prefix when needed."""
    out: list[str] = []
    alts = entry.get("alternative_purls")
    if not isinstance(alts, list):
        return ()
    for a in alts:
        if isinstance(a, dict):
            t = a.get("type")
            if isinstance(t, str) and t:
                out.append(t)
                continue
            # Fall through to parsing the purl string if type missing.
            purl = a.get("purl")
        elif isinstance(a, str):
            purl = a
        else:
            continue
        if isinstance(purl, str) and purl.startswith("pkg:"):
            head, _, _ = purl[4:].partition("/")
            if head:
                out.append(head)
    return tuple(out)


def _overlay_purl(base: AutoEntry, override: dict) -> AutoEntry:
    """Return a new AutoEntry with PURL-related fields replaced where the
    override provides them. Mirrors ``merge_mappings``' replace-on-present
    semantics for the PURL layer.

    ``alternative_purls`` follows the same replace-on-present rule the
    merge layer uses (see ``merge_mappings._reviewed_mapping_patch``): a
    contribution that explicitly provides an alternative_purls list
    replaces the base; absent means inherit. An empty list explicitly
    clears the alternatives."""
    reviews_primary = _reviews_primary(override)
    if not reviews_primary and "alternative_purls" not in override:
        return base
    if "alternative_purls" in override and override["alternative_purls"] is not None:
        alt_types = _extract_alt_types(override)
    else:
        alt_types = base.alternative_purl_types
    unmapped = override.get("unmapped") is True if reviews_primary else base.unmapped
    if unmapped:
        purl = purl_type = namespace = pkg_name = None
        alt_types = ()
    else:
        purl = override["purl"] if override.get("purl") is not None else base.purl
        purl_type = (
            override["type"] if override.get("type") is not None else base.purl_type
        )
        namespace = (
            override["namespace"]
            if override.get("namespace") is not None
            else base.namespace
        )
        pkg_name = (
            override["pkg_name"]
            if override.get("pkg_name") is not None
            else base.pkg_name
        )
    return AutoEntry(
        purl=purl,
        purl_type=purl_type,
        namespace=namespace,
        pkg_name=pkg_name,
        summary=base.summary,  # human reviews never change conda evidence
        download_count=base.download_count,
        version=base.version,
        source_url=base.source_url,
        unmapped=unmapped,
        alternative_purl_types=alt_types,
    )


def _load_effective_mappings(
    auto: Path, manual: Path, contrib_dir: Path
) -> dict[str, AutoEntry]:
    """Return the merged ``{name: AutoEntry}`` view that ``merge_mappings``
    would produce for the PURL fields.

    Layered, newest wins: ``auto.json`` → ``manual.json`` → ``contributions``
    (sorted by ``timestamp`` then filename). We only need the PURL portion
    here — the ``cpes`` overrides are handled separately by
    :func:`_load_existing_cpes`."""
    out: dict[str, AutoEntry] = {}

    # Layer 1: auto.json — also carries the ``download_count`` we rank by
    # and the ``alternative_purls`` we check for OSV-mappable fallbacks.
    # Intentionally unwrapped: a corrupt auto.json is a hard failure because
    # ranking depends entirely on it. Reviewed layers below tolerate broken
    # JSON because losing one contribution shouldn't break a discovery run.
    if auto.exists():
        data = json.loads(auto.read_text())
        for name, entry in (data.get("packages") or {}).items():
            if not isinstance(entry, dict):
                continue
            dc = entry.get("download_count")
            out[name] = AutoEntry(
                purl=entry.get("purl"),
                purl_type=entry.get("type"),
                namespace=entry.get("namespace"),
                pkg_name=entry.get("pkg_name"),
                summary=entry.get("summary"),
                download_count=dc if isinstance(dc, int) else 0,
                version=entry.get("version"),
                source_url=entry.get("source_url"),
                unmapped=entry.get("unmapped") is True,
                alternative_purl_types=_extract_alt_types(entry),
            )

    blank = AutoEntry(
        purl=None,
        purl_type=None,
        namespace=None,
        pkg_name=None,
        summary=None,
        download_count=0,
        version=None,
        source_url=None,
        unmapped=False,
        alternative_purl_types=(),
    )

    # Layers 2 and 3: manual first, then contributions oldest → newest by
    # timezone-aware UTC instant and filename, matching merge_mappings.
    for reviewed, _filename, _is_manual in _reviewed_layers(manual, contrib_dir):
        for name, override in (reviewed.get("packages") or {}).items():
            if not isinstance(override, dict):
                continue
            out[name] = _overlay_purl(out.get(name, blank), override)

    return out


# ---------- candidate selection ----------


def _anchor_dict(name: str, reviewed: ReviewedCpeSet) -> dict[str, Any]:
    return {
        "package": name,
        "cpes": list(reviewed.cpes),
        "source": reviewed.source,
        "reviewer": reviewed.reviewer,
        "reviewed_at": reviewed.reviewed_at,
    }


def _shared_source_evidence(
    entries: dict[str, AutoEntry],
    reviewed_cpes: dict[str, ReviewedCpeSet],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    """Return review proposals and conflicts keyed by identity-less target name.

    Source and version equality is deliberately literal: mirrors, scheme changes,
    and inferred feedstock relationships are not silently treated as equivalent.
    """
    groups: dict[tuple[str, str], list[str]] = {}
    for name, entry in entries.items():
        if not entry.source_url or not entry.version:
            continue
        groups.setdefault((entry.source_url, entry.version), []).append(name)

    reviews: dict[str, list[dict[str, Any]]] = {}
    conflicts: dict[str, dict[str, Any]] = {}
    for (source_url, version), names in groups.items():
        anchors = [
            (name, reviewed_cpes[name])
            for name in sorted(names)
            if name in reviewed_cpes and reviewed_cpes[name].cpes
        ]
        if not anchors:
            continue
        distinct_sets = {frozenset(reviewed.cpes) for _name, reviewed in anchors}
        anchor_payload = [_anchor_dict(name, reviewed) for name, reviewed in anchors]
        targets = [
            name
            for name in sorted(names)
            if name not in reviewed_cpes or not reviewed_cpes[name].cpes
        ]
        if len(distinct_sets) != 1:
            evidence = {
                "reason": "reviewed_shared_source_conflict",
                "shared_source_url": source_url,
                "shared_version": version,
                "anchors": anchor_payload,
            }
            for name in targets:
                conflicts[name] = evidence
            continue

        consensus = anchors[0][1].cpes
        evidence = {
            "cpes": list(consensus),
            "reason": "reviewed_shared_source",
            "shared_source_url": source_url,
            "shared_version": version,
            "anchors": anchor_payload,
            "requires_review": True,
        }
        for name in targets:
            reviews[name] = [evidence]
    return reviews, conflicts


def _is_cpe_candidate(name: str, entry: AutoEntry | None) -> bool:
    """A package is a CPE candidate when no existing PURL identity is in an
    OSV-indexed package ecosystem.

    Both the primary PURL and the ``alternative_purls`` list count. A package
    qualifies only when:
      * no primary PURL, or primary PURL is non-OSV (github, generic, …)
      * AND no alternative_purls entry is OSV-mappable
      * AND not a conda-build internal feedstock
    """
    # Skip conda-build internal feedstocks.
    if name.startswith("_") or name.startswith("python_abi"):
        return False
    if entry is None:
        return True
    if entry.unmapped:
        return False
    if entry.purl_type in OSV_PURL_TYPES:
        return False
    # Even if the primary PURL is github/generic, an OSV-mappable alternative
    # means downstream tooling already has an ecosystem identity to try first.
    if entry.has_osv_alternative:
        return False
    return True
