"""Prototype: pull NVD CVEs for every CPE-keyed conda package and emit
``mappings/cves/<pkg>.json`` files in the same shape :mod:`scripts.cve_match`
writes for OSV-sourced advisories.

Reads each package's ``cpes`` field from ``web/public/mappings.json`` (which
``scripts.merge_mappings`` produces from the ``cpes`` overrides in
``mappings/manual.json``). Resolves CVEs against the local NVD feed cache
(:mod:`scripts.nvd_fetch`) — one bulk download per day, then in-memory
``(part, vendor, product)`` lookups for every CPE prefix. When a package
carries multiple CPE aliases (NVD sometimes splits the same product across
several vendor names — e.g. ``gnu:ncurses`` for older records,
``invisible-island:ncurses`` for new ones) the results are unioned and
deduped by CVE id.

Synthesizes an OSV-shaped record per CVE so the existing web UI displays
them identically to OSV-sourced files. ``affected[].package.ecosystem`` is
set to ``"GIT"`` (OSV's allowlisted slot for source-coordinate records);
the real CPE coordinates live in ``database_specific.nvd``.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import typer
from rattler.version import Version
from rich.console import Console

from scripts.cve_common import conda_purl
from scripts.cve_match import (
    _affects_future_version,
    _aggregate_conda_versions,
    _gather_records,
    _safe_version,
    version_in_affected_entry,
)
from scripts.nvd_fetch import NvdIndex, fetch_index
from scripts.osv_fetch import Advisory

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = ROOT / "mappings" / "cves"
DEFAULT_MAPPINGS = ROOT / "web" / "public" / "mappings.json"


def _load_cpe_mappings(mappings_path: Path) -> dict[str, list[str]]:
    """Read ``cpes: [...]`` from every package entry in the merged mappings.

    The CPE list comes from ``mappings/manual.json`` overrides (or
    ``contributions/*.json``) and is passed through verbatim by
    ``scripts.merge_mappings``. Packages without a ``cpes`` list are skipped.
    """
    if not mappings_path.exists():
        raise typer.BadParameter(
            f"Mappings file not found: {mappings_path}. "
            "Run `pixi run python -m scripts.merge_mappings` first."
        )
    payload = json.loads(mappings_path.read_text())
    pkgs = payload.get("packages")
    if not isinstance(pkgs, dict):
        raise typer.BadParameter(f"Unexpected mappings shape in {mappings_path}")
    out: dict[str, list[str]] = {}
    for name, entry in pkgs.items():
        cpes = entry.get("cpes") if isinstance(entry, dict) else None
        if isinstance(cpes, list):
            valid = [c for c in cpes if isinstance(c, str) and c.startswith("cpe:2.3:")]
            if valid:
                out[name] = valid
    return out


# ---------- NVD → OSV synthesis ----------


def _summary(desc: str) -> str:
    # Take the first sentence; if there's no period, cap at 200 chars.
    m = re.match(r"(.{0,200}?[.!?])\s", desc)
    return (m.group(1) if m else desc[:200]).strip()


def _english_description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and isinstance(d.get("value"), str):
            return d["value"]
    return ""


def _normalize_timestamp(ts: object) -> str | None:
    """OSV schema requires ``...Z`` UTC marker; NVD emits naïve ISO strings.

    Appends ``Z`` if missing. Returns ``None`` for non-string inputs."""
    if not isinstance(ts, str) or not ts:
        return None
    return ts if ts.endswith("Z") else ts + "Z"


_CVSS_VERSIONS = [
    ("cvssMetricV40", "CVSS_V4"),
    ("cvssMetricV31", "CVSS_V3"),
    ("cvssMetricV30", "CVSS_V3"),
    ("cvssMetricV2", "CVSS_V2"),
]


def _severity(cve: dict) -> list[dict]:
    metrics = cve.get("metrics") or {}
    out: list[dict] = []
    seen_types: set[str] = set()
    for key, osv_type in _CVSS_VERSIONS:
        for entry in metrics.get(key) or []:
            vector = (entry.get("cvssData") or {}).get("vectorString")
            if isinstance(vector, str) and osv_type not in seen_types:
                out.append({"type": osv_type, "score": vector})
                seen_types.add(osv_type)
                break
    return out


def _references(cve: dict) -> list[dict]:
    return [
        {"type": "WEB", "url": r["url"]}
        for r in (cve.get("references") or [])
        if isinstance(r, dict) and isinstance(r.get("url"), str)
    ]


def _affected_from_cpe_matches(cpe_matches: list[dict]) -> tuple[list[str], list[dict]]:
    """Convert NVD ``cpeMatch`` entries into OSV ``versions`` + ``ranges``.

    NVD encodes the affected version in two distinct ways:

    1. **Pinned in the CPE string** itself (``cpe:2.3:a:gnu:ncurses:6.0:*:...``).
       The match applies to that exact version only. We collect these into
       OSV's ``versions`` exact-list.
    2. **Range qualifiers as siblings** of ``criteria``: ``versionStartIncluding``,
       ``versionStartExcluding``, ``versionEndIncluding``, ``versionEndExcluding``.
       Paired with a wildcarded CPE (``ncurses:*:*:...``). We emit one OSV
       range per cpeMatch.

    Mapping for case 2:
    * ``versionStartIncluding`` → ``introduced``
    * ``versionEndExcluding`` → ``fixed`` (semantics match exactly)
    * ``versionEndIncluding`` → ``last_affected``
    * ``versionStartExcluding`` — no exact OSV equivalent. Emitted as
      ``introduced`` with slight over-reporting at the lower edge (the
      version immediately above the excluded one will be falsely flagged).
      Rare in practice.

    A cpeMatch with neither a pinned version nor any range qualifier means
    "all versions of this product" — emitted as an open-ended range
    ``{"introduced": "0"}``.
    """
    pinned: list[str] = []
    ranges: list[dict] = []
    for cm in cpe_matches:
        if not cm.get("vulnerable", True):
            continue
        criteria = cm.get("criteria") or ""
        parts = criteria.split(":")
        cpe_version = parts[5] if len(parts) >= 6 else "*"
        has_range_qualifier = any(
            cm.get(k)
            for k in (
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
            )
        )
        # Case 1: version pinned in the CPE itself, no qualifier siblings.
        if cpe_version not in ("*", "-") and not has_range_qualifier:
            if cpe_version not in pinned:
                pinned.append(cpe_version)
            continue
        # Case 2: range qualifier siblings (CPE version is usually "*").
        if has_range_qualifier:
            events: list[dict] = []
            start = cm.get("versionStartIncluding") or cm.get("versionStartExcluding")
            events.append({"introduced": start or "0"})
            if end := cm.get("versionEndExcluding"):
                events.append({"fixed": end})
            elif end := cm.get("versionEndIncluding"):
                events.append({"last_affected": end})
            ranges.append({"type": "ECOSYSTEM", "events": events})
            continue
        # Case 3: wildcard CPE, no qualifiers — "all versions affected".
        ranges.append({"type": "ECOSYSTEM", "events": [{"introduced": "0"}]})
    return pinned, ranges


def _collect_cpe_matches(cve: dict, products: set[str]) -> list[dict]:
    """Pull every ``cpeMatch`` entry whose ``criteria`` targets one of our
    products (the ``product`` segment of the CPE, e.g. ``ncurses``).

    Multiple products are accepted because a single conda package can map to
    several CPE prefixes — e.g. ncurses is split across ``gnu:ncurses`` and
    the typo ``invisible-island:ncurse``. Defensive against multi-product
    CVEs: a CVE that affects both ncurses and some other library carries
    cpeMatches for both, and we only want the relevant ones."""
    out: list[dict] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                criteria = cm.get("criteria")
                if not isinstance(criteria, str):
                    continue
                cm_parts = criteria.split(":")
                if len(cm_parts) >= 5 and cm_parts[4] in products:
                    out.append(cm)
    return out


def _synthesize_osv_record(
    cve: dict, *, cpes: list[str], conda_name: str
) -> dict | None:
    """Build an OSV-shaped record from one NVD CVE entry.

    ``cpes`` is the full list of CPE prefixes a package maps to. The
    synthesizer pulls every cpeMatch whose product matches any prefix in
    the list and folds them into a single OSV record. Returns ``None`` if
    no cpeMatch targets any of the requested products (shouldn't happen
    given the virtualMatchString filter, but defensive)."""
    products: set[str] = set()
    primary_vendor: str | None = None
    primary_product: str | None = None
    for cpe in cpes:
        parts = cpe.split(":")
        if len(parts) >= 5:
            products.add(parts[4])
            if primary_product is None:
                primary_vendor = parts[3]
                primary_product = parts[4]
    if not products or primary_product is None:
        return None

    cpe_matches = _collect_cpe_matches(cve, products)
    if not cpe_matches:
        return None

    pinned_versions, ranges = _affected_from_cpe_matches(cpe_matches)
    if not pinned_versions and not ranges:
        return None

    desc = _english_description(cve)
    affected_entry: dict = {
        "package": {
            # OSV schema's ecosystem field requires a value from a fixed
            # allowlist. CPE-sourced records have no real OSV ecosystem;
            # ``GIT`` is the closest neutral choice (it's the bucket OSV
            # uses for source-coordinate records). The actual CPE
            # coordinates live in ``database_specific.nvd.cpes``.
            "ecosystem": "GIT",
            "name": primary_product,
            "purl": f"pkg:generic/{primary_vendor}/{primary_product}",
        },
    }
    # OSV semantics: when ``versions`` is present, it's an exhaustive list
    # and ``ranges`` is ignored. Only emit ``versions`` when we have no
    # range qualifiers; otherwise emit ``ranges`` (the more expressive form).
    if ranges:
        affected_entry["ranges"] = ranges
    else:
        affected_entry["versions"] = pinned_versions

    record = {
        "schema_version": "1.6.0",
        "id": cve["id"],
        "published": _normalize_timestamp(cve.get("published")),
        "modified": _normalize_timestamp(cve.get("lastModified")),
        "aliases": [],
        "summary": _summary(desc) if desc else cve["id"],
        "details": desc,
        "affected": [affected_entry],
        "references": _references(cve),
        "severity": _severity(cve),
    }
    return record


# ---------- conda-version intersection ----------


def _matched_versions(record: dict, versions: list) -> list[str]:
    """Which conda-forge versions fall inside the synthesized record's
    affected[] ranges. Reuses ``version_in_affected_entry`` from cve_match."""
    affected = record["affected"][0]
    hits: list[str] = []
    for v in versions:
        try:
            if version_in_affected_entry(v.parsed, affected):
                hits.append(v.version)
        except Exception:
            continue
    return hits


def _attach_conda_block(
    record: dict,
    *,
    conda_name: str,
    matched_versions: list[str],
    conda_versions_total: int,
    latest_version: Version | None,
    cpes: list[str],
    matched_via: list[str],
    generated_at: str,
) -> None:
    """Attach the conda-forge + nvd database_specific blocks.

    ``cpes`` is the full list of CPE prefixes the package is mapped to.
    ``matched_via`` is the subset whose NVD query actually returned this
    advisory — useful for diagnosing which alias provided the coverage."""
    # Reusing cve_match's _affects_future_version requires an Advisory
    # dataclass instance — synthesize a minimal one.
    adv = Advisory(
        id=record["id"],
        ecosystem="CPE",
        name=record["affected"][0]["package"]["name"],
        aliases=[],
        summary=record.get("summary"),
        details=record.get("details"),
        published=record.get("published"),
        modified=record.get("modified"),
        severity=record.get("severity") or [],
        references=record.get("references") or [],
        raw_affected=record["affected"][0],
        raw=record,
    )
    record["database_specific"] = {
        "conda-forge": {
            "package": conda_name,
            "purl": conda_purl(conda_name),
            "source_purls": [record["affected"][0]["package"]["purl"]],
            "affected_versions": matched_versions,
            "conda_versions_total": conda_versions_total,
            "affects_future": _affects_future_version(adv, latest_version),
            "derived_by": "purl-associator/scripts.nvd_prototype",
            "generated_at": generated_at,
        },
        "nvd": {
            "cpes": cpes,
            "matched_via": matched_via,
            "source": "nvd-rest-api",
        },
    }


# ---------- main ----------


@app.command()
def main(
    mappings: Path = typer.Option(
        DEFAULT_MAPPINGS, help="Merged mappings.json produced by scripts.merge_mappings"
    ),
    out_dir: Path = typer.Option(DEFAULT_OUT_DIR, help="Per-package CVE output dir"),
    only: str | None = typer.Option(
        None,
        help="Comma-separated conda names to process (default: every package with a cpes list)",
    ),
    nvd_cache: Path = typer.Option(
        Path("./nvd_cache"), help="Where the NVD feed cache lives"
    ),
    force_nvd: bool = typer.Option(False, help="Force re-download of NVD feeds"),
    nvd_max_age_hours: float = typer.Option(
        2.0, help="Re-download the NVD modified feed if older than this"
    ),
) -> None:
    """Fetch NVD CVEs for each CPE-mapped conda package and emit JSON files."""
    cpe_mappings = _load_cpe_mappings(mappings)
    if only:
        wanted = {n.strip() for n in only.split(",") if n.strip()}
        cpe_mappings = {k: v for k, v in cpe_mappings.items() if k in wanted}
    if not cpe_mappings:
        console.log("[yellow]No packages with a cpes list — nothing to do.[/]")
        return
    asyncio.run(
        _async_main(
            out_dir=out_dir,
            cpe_mappings=cpe_mappings,
            nvd_cache=nvd_cache,
            force_nvd=force_nvd,
            nvd_max_age_hours=nvd_max_age_hours,
        )
    )


async def _async_main(
    *,
    out_dir: Path,
    cpe_mappings: dict[str, list[str]],
    nvd_cache: Path,
    force_nvd: bool,
    nvd_max_age_hours: float,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")

    # Build the NVD index once, then look up by CPE prefix per package.
    # This collapses what used to be ``sum(len(cpes) for cpes in cpe_mappings.values())``
    # HTTP calls into a single bulk feed sync.
    console.log("Refreshing NVD feed cache…")
    index = await fetch_index(
        cache_dir=nvd_cache,
        force=force_nvd,
        max_modified_age_hours=nvd_max_age_hours,
    )
    console.log(
        f"NVD index: [bold]{index.total_cves():,}[/] CVEs across "
        f"{len(index.feeds)} feed file(s)."
    )

    names = list(cpe_mappings.keys())
    records_by_name = await _gather_records(
        channel="conda-forge", platforms=["linux-64", "noarch"], names=names
    )

    for conda_name, cpes in cpe_mappings.items():
        # Look up each CPE prefix and union the results. The same CVE can be
        # returned by multiple prefixes (e.g. CVE-2023-29491 surfaces under
        # both gnu:ncurses and invisible-island:ncurses if NVD has both
        # vendor tags) — dedupe by CVE id.
        cve_by_id: dict[str, dict] = {}
        matched_via_by_id: dict[str, list[str]] = {}
        for cpe in cpes:
            cves = index.for_cpe(cpe)
            console.log(f"{conda_name}: NVD index returned {len(cves)} CVEs for {cpe}")
            for cve in cves:
                cid = cve.get("id")
                if not isinstance(cid, str):
                    continue
                cve_by_id.setdefault(cid, cve)
                matched_via_by_id.setdefault(cid, []).append(cpe)

        if not cve_by_id:
            console.log(f"[yellow]{conda_name}: no CVEs returned, skipping[/]")
            continue

        repo_records = records_by_name.get(conda_name) or []
        versions = _aggregate_conda_versions(repo_records)
        if not versions:
            console.log(f"[yellow]{conda_name}: no conda-forge versions found, skipping[/]")
            continue
        latest_parsed = versions[-1].parsed

        advisories: list[dict] = []
        for cid, cve in cve_by_id.items():
            record = _synthesize_osv_record(cve, cpes=cpes, conda_name=conda_name)
            if record is None:
                continue
            matched = _matched_versions(record, versions)
            _attach_conda_block(
                record,
                conda_name=conda_name,
                matched_versions=matched,
                conda_versions_total=len(versions),
                latest_version=latest_parsed,
                cpes=cpes,
                matched_via=matched_via_by_id[cid],
                generated_at=generated_at,
            )
            advisories.append(record)

        # Same sort order cve_match uses: hits first.
        advisories.sort(
            key=lambda r: not r["database_specific"]["conda-forge"]["affected_versions"]
        )

        payload = {
            "schema_version": 1,
            "package": conda_name,
            "purls": cpes,  # the source CPE coordinates; not real PURLs
            "generated_at": generated_at,
            "conda_versions_total": len(versions),
            "latest_version": versions[-1].version,
            "advisories": advisories,
        }
        target = out_dir / f"{conda_name}.json"
        target.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")
        hit_count = sum(
            1 for a in advisories if a["database_specific"]["conda-forge"]["affected_versions"]
        )
        console.log(
            f"[green]{conda_name}[/]: wrote {target.relative_to(ROOT)} "
            f"({len(advisories)} advisories, {hit_count} with conda-version hits)"
        )


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)
