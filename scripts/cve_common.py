"""Shared helpers for reading the OSV-record CVE files.

Every advisory stored under ``mappings/cves/`` is a verbatim OSV record; the
conda-forge match (and, after the merge, the resolved VEX review) lives under
``database_specific["conda-forge"]``. These accessors centralise that layout
so :mod:`scripts.merge_cves` and :mod:`scripts.cve_summary` stay in sync.
"""

from __future__ import annotations

CONDA_DB_KEY = "conda-forge"

# CVSS_V4 is the most expressive, then V3, then V2.
_SEVERITY_RANK = {"CVSS_V4": 4, "CVSS_V3": 3, "CVSS_V2": 2}


def conda_block(advisory: dict) -> dict:
    """The ``database_specific["conda-forge"]`` block, or ``{}`` if absent."""
    db = advisory.get("database_specific")
    if not isinstance(db, dict):
        return {}
    block = db.get(CONDA_DB_KEY)
    return block if isinstance(block, dict) else {}


def affected_versions(advisory: dict) -> list[str]:
    """Conda-forge versions the advisory applies to (post-merge: VEX-adjusted)."""
    versions = conda_block(advisory).get("affected_versions")
    return versions if isinstance(versions, list) else []


def cve_ids(advisory: dict) -> list[str]:
    """CVE ids drawn from the OSV record's id + aliases."""
    ids = {advisory.get("id") or ""}
    ids.update(a for a in (advisory.get("aliases") or []) if isinstance(a, str))
    return sorted(i for i in ids if i.startswith("CVE-"))


def primary_id(advisory: dict) -> str:
    """Prefer a human-friendly CVE id; fall back to the native OSV id."""
    cves = cve_ids(advisory)
    return cves[0] if cves else (advisory.get("id") or "?")


def osv_url(advisory: dict) -> str:
    return f"https://osv.dev/vulnerability/{advisory.get('id')}"


def best_severity(advisory: dict) -> dict | None:
    """The most expressive CVSS entry from the OSV ``severity`` array."""
    severity = advisory.get("severity")
    if not isinstance(severity, list):
        return None
    return max(
        (s for s in severity if isinstance(s, dict)),
        key=lambda s: _SEVERITY_RANK.get(s.get("type", ""), 0),
        default=None,
    )


def parse_conda_purl(purl: str) -> tuple[str, str | None] | None:
    """Split a ``pkg:conda/<name>[@<version>]?...`` PURL into ``(name, version)``.

    Returns ``None`` for anything that is not a conda PURL. ``version`` is
    ``None`` for a package-level reference (no ``@version`` segment)."""
    if not isinstance(purl, str) or not purl.startswith("pkg:conda/"):
        return None
    body = purl[len("pkg:conda/") :].split("?", 1)[0].split("#", 1)[0]
    name, sep, version = body.partition("@")
    if not name:
        return None
    return (name, version if sep and version else None)
