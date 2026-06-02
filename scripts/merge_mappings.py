"""Merge auto.json + manual.json + contributions/*.json into the single
payload the frontend consumes.

**Layering, oldest → newest (newer wins):**

1. ``mappings/auto.json`` — automap output.
2. ``mappings/manual.json`` — legacy human-curated overrides (single file).
3. ``mappings/contributions/*.json`` — per-PR contribution files, sorted by
   ``timestamp`` (or filename if absent). Each PR drops one new file with a
   unique name, so concurrent PRs never conflict on disk; the merge below
   resolves them in chronological order.

Output: ``web/public/mappings.json`` for backwards compatibility, plus the split
payload ``web/public/mappings-index.json`` and sharded
``web/public/mapping_packages/*.json`` detail files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL = ROOT / "mappings" / "manual.json"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_DOWNLOADS = ROOT / "mappings" / "top_downloads.json"
DEFAULT_OUT = ROOT / "web" / "public" / "mappings.json"
DEFAULT_INDEX_OUT = ROOT / "web" / "public" / "mappings-index.json"
DEFAULT_DETAIL_DIR = ROOT / "web" / "public" / "mapping_packages"


def _load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return default


def _load_downloads(path: Path) -> dict[str, int]:
    """Return ``{name: total_count}`` from ``mappings/top_downloads.json``.

    The file is produced by ``scripts.top_downloads`` and tracks prefix.dev
    download counts. Missing file → empty mapping, so the merge stays usable
    on fresh checkouts.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    out: dict[str, int] = {}
    for row in data.get("packages") or []:
        name = row.get("name")
        count = row.get("total_count")
        if isinstance(name, str) and isinstance(count, int):
            out[name] = count
    return out


def _load_contributions(directory: Path) -> list[dict]:
    if not directory.exists():
        return []
    entries: list[dict] = []
    for f in sorted(directory.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        data.setdefault("_filename", f.name)
        # Fall back to filename for sort key if timestamp is missing/invalid.
        if not isinstance(data.get("timestamp"), str):
            data["timestamp"] = f.stem
        entries.append(data)
    entries.sort(key=lambda d: (d.get("timestamp") or "", d.get("_filename")))
    return entries


REVIEWED_MAPPING_FIELDS = (
    "purl",
    "type",
    "namespace",
    "pkg_name",
    "alternative_purls",
    "cpes",
    "unmapped",
    "note",
    "status",
)


def _auto_snapshot(auto_entry: dict) -> dict:
    """Return the preserved automatic guess shown as secondary UI context."""
    return {
        "purl": auto_entry.get("purl"),
        "type": auto_entry.get("type"),
        "namespace": auto_entry.get("namespace"),
        "pkg_name": auto_entry.get("pkg_name"),
        "confidence": auto_entry.get("confidence", 0.0),
        "sources": auto_entry.get("sources", []),
        "alternative_purls": auto_entry.get("alternative_purls"),
    }


def _reviewed_mapping_patch(override: dict) -> dict:
    """Return fields that a human review layer owns.

    ``alternative_purls`` is intentionally replace-all when present. This is the
    core #66 invariant: if a reviewer removes an auto-suggested PURL, the latest
    reviewed list (even ``[]``) must replace the auto list rather than be merged
    with it. Omitted fields keep the previous layer for backwards compatibility.
    """
    patch: dict = {}
    for key in REVIEWED_MAPPING_FIELDS:
        if key in override and override[key] is not None:
            patch[key] = override[key]
    patch.setdefault("status", "verified")
    return patch


def _apply_reviewed_override(
    merged: dict[str, dict],
    auto_packages: dict[str, dict],
    name: str,
    override: dict,
    attribution: dict,
) -> None:
    base = merged.get(name, {"name": name})
    merged[name] = {
        **base,
        **_reviewed_mapping_patch(override),
        "source": "manual",
        **attribution,
    }
    if name in auto_packages:
        merged[name]["auto"] = _auto_snapshot(auto_packages[name])


def _index_package(name: str, entry: dict, detail_path: str) -> dict:
    out = {
        "name": name,
        "version": entry.get("version"),
        "purl": entry.get("purl"),
        "type": entry.get("type"),
        "namespace": entry.get("namespace"),
        "pkg_name": entry.get("pkg_name"),
        "status": entry.get("status"),
        "download_count": entry.get("download_count"),
        "detail_path": detail_path,
    }
    for key in ("alternative_purls", "unmapped", "cpes"):
        if key in entry and entry.get(key) is not None:
            out[key] = entry.get(key)
    deep = entry.get("deep_inspection")
    if isinstance(deep, dict):
        out["deep_inspection"] = {"candidate": bool(deep.get("candidate"))}
    return out


def _write_split_payload(payload: dict, index_out: Path, detail_dir: Path) -> None:
    detail_dir.mkdir(parents=True, exist_ok=True)
    for stale in detail_dir.glob("*.json"):
        stale.unlink()

    index_packages: dict[str, dict] = {}
    shards: dict[str, dict[str, dict]] = {}
    for name, entry in sorted((payload.get("packages") or {}).items()):
        shard = hashlib.sha256(name.encode()).hexdigest()[:2]
        detail_path = f"mapping_packages/{shard}.json"
        detail = {**entry, "name": name}
        shards.setdefault(shard, {})[name] = detail
        index_packages[name] = _index_package(name, entry, detail_path)

    for shard, packages in sorted(shards.items()):
        shard_payload = {"schema_version": 1, "packages": packages}
        (detail_dir / f"{shard}.json").write_text(
            json.dumps(shard_payload, separators=(",", ":")) + "\n"
        )

    index_payload = {
        **{k: v for k, v in payload.items() if k != "packages"},
        "schema_version": 2,
        "packages": index_packages,
    }
    index_out.parent.mkdir(parents=True, exist_ok=True)
    index_out.write_text(json.dumps(index_payload, separators=(",", ":")) + "\n")


def main(
    auto: Path = DEFAULT_AUTO,
    manual: Path = DEFAULT_MANUAL,
    contributions: Path = DEFAULT_CONTRIB_DIR,
    downloads: Path = DEFAULT_DOWNLOADS,
    out: Path = DEFAULT_OUT,
    index_out: Path = DEFAULT_INDEX_OUT,
    detail_dir: Path = DEFAULT_DETAIL_DIR,
) -> None:
    auto_data = _load_json(auto, {"packages": {}})
    manual_data = _load_json(manual, {"packages": {}})
    contrib_files = _load_contributions(contributions)
    downloads_by_name = _load_downloads(downloads)

    merged: dict[str, dict] = {}

    # Layer 1: auto.
    for name, entry in auto_data.get("packages", {}).items():
        status = "auto-verified" if entry.get("auto_verified") else "auto-unverified"
        merged[name] = {**entry, "status": status, "source": "auto"}

    # Layer 2: manual.json (legacy single-file overrides).
    legacy_attribution = {
        "approved_by": manual_data.get("updated_by"),
        "approved_at": manual_data.get("updated_at"),
    }
    auto_packages = auto_data.get("packages", {})
    for name, override in manual_data.get("packages", {}).items():
        _apply_reviewed_override(
            merged,
            auto_packages,
            name,
            override,
            {k: v for k, v in legacy_attribution.items() if v is not None},
        )

    # Layer 3: contributions, oldest → newest.
    for contrib in contrib_files:
        attribution = {
            "approved_by": contrib.get("author"),
            "approved_at": contrib.get("timestamp"),
        }
        for name, override in (contrib.get("packages") or {}).items():
            _apply_reviewed_override(merged, auto_packages, name, override, attribution)

    # Fallback for entries that don't carry ``download_count`` from auto.json
    # (e.g. manual-only or contribution-only names). Hydration of auto.json
    # is owned by ``scripts.hydrate_downloads``; we don't clobber its values
    # here, even when the name is absent from top_downloads.json.
    for name, entry in merged.items():
        if entry.get("download_count") is None and name in downloads_by_name:
            entry["download_count"] = downloads_by_name[name]

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "auto_generated_at": auto_data.get("generated_at"),
        "manual_updated_at": manual_data.get("updated_at"),
        "contribution_count": len(contrib_files),
        "download_count_source": "prefix.dev (Package.totalCount)"
        if downloads_by_name
        else None,
        "channel": auto_data.get("channel", "conda-forge"),
        "package_count": len(merged),
        "packages": dict(sorted(merged.items())),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    _write_split_payload(payload, index_out, detail_dir)
    print(
        f"Merged auto={len(auto_data.get('packages', {}))} + "
        f"manual={len(manual_data.get('packages', {}))} + "
        f"contributions={len(contrib_files)} → {out}, {index_out}, {detail_dir} "
        f"({len(merged)} packages)"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auto", type=Path, default=DEFAULT_AUTO)
    parser.add_argument("--manual", type=Path, default=DEFAULT_MANUAL)
    parser.add_argument("--contributions", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--downloads", type=Path, default=DEFAULT_DOWNLOADS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--index-out", type=Path, default=DEFAULT_INDEX_OUT)
    parser.add_argument("--detail-dir", type=Path, default=DEFAULT_DETAIL_DIR)
    args = parser.parse_args()
    main(
        args.auto,
        args.manual,
        args.contributions,
        args.downloads,
        args.out,
        args.index_out,
        args.detail_dir,
    )
