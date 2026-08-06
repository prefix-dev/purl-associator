"""Merge reviewed identity mapping layers into the published payloads.

Layering is auto.json, manual.json, then contributions/*.json ordered by their
trusted timestamp and on-disk filename.  Published legacy fields remain
additive-compatible while ``identities`` carries provenance for each identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL = ROOT / "mappings" / "manual.json"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_DOWNLOADS = ROOT / "mappings" / "top_downloads.json"
DEFAULT_OUT = ROOT / "web" / "public" / "mappings.json"
DEFAULT_INDEX_OUT = ROOT / "web" / "public" / "mappings-index.json"
DEFAULT_DETAIL_DIR = ROOT / "web" / "public" / "mapping_packages"

BUNDLE_SCHEMA_VERSION = 2
INDEX_SCHEMA_VERSION = 3
DETAIL_SCHEMA_VERSION = 2
SOURCE_SCHEMA_VERSION = 1
REVIEW_STATUSES = {"auto-unverified", "auto-verified", "verified", "unmapped", "edited"}
PRIMARY_SOURCES = {"auto", "manual"}
ALTERNATIVE_SOURCES = {
    "recipe-source",
    "recipe-deps",
    "recipe-source+recipe-deps",
    "parselmouth-artifact",
}
CPE23_RE = re.compile(r"^cpe:2\.3:[aho*\-]:[^:]+:[^:]+(?::[^:]*){0,10}$")
PURL_RE = re.compile(r"^pkg:[a-z][a-z0-9.+-]*/[^\s?#]+(?:\?[^\s#]+)?(?:#[^\s]+)?$")

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
PRIMARY_REVIEW_FIELDS = ("purl", "type", "namespace", "pkg_name", "unmapped", "status")
_INTERNAL_PRIMARY = "_primary_identity_provenance"


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_number(value: str) -> None:
    raise ValueError(f"non-standard numeric value {value}")


def _load_json(path: Path, default: dict | None = None) -> dict[str, Any]:
    if not path.exists():
        if default is not None:
            return default
        raise ValueError(f"{path}: file does not exist")
    try:
        value = json.loads(
            path.read_text(),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_nonstandard_number,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path}: payload must be an object")
    return value


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a valid timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{label} must be a valid timezone-aware ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone offset")
    return parsed.astimezone(UTC)


def _valid_timestamp(value: Any) -> bool:
    try:
        _parse_timestamp(value, "timestamp")
    except ValueError:
        return False
    return True


def _finite_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def _require_string(value: Any, label: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{label} must be a non-empty string" + (" or null" if nullable else "")
        )


def _validate_purl(value: Any, label: str) -> None:
    _require_string(value, label)
    if not PURL_RE.fullmatch(value):
        raise ValueError(f"{label} is not a valid package URL: {value!r}")


def _validate_cpes(value: Any, label: str) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    seen: set[str] = set()
    for index, cpe in enumerate(value):
        item_label = f"{label}[{index}]"
        _require_string(cpe, item_label)
        if not CPE23_RE.fullmatch(cpe):
            raise ValueError(
                f"{item_label} is not a valid CPE 2.3 vendor/product prefix"
            )
        if cpe in seen:
            raise ValueError(f"{item_label} duplicates {cpe!r}")
        seen.add(cpe)


def _validate_alternatives(value: Any, label: str, primary: Any) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array")
    seen: set[str] = set()
    for index, alternative in enumerate(value):
        item_label = f"{label}[{index}]"
        if isinstance(alternative, str):
            purl = alternative
            _validate_purl(purl, item_label)
        elif isinstance(alternative, dict):
            allowed = {"purl", "type", "namespace", "pkg_name", "confidence", "source"}
            extras = set(alternative) - allowed
            missing = allowed - set(alternative)
            if extras or missing:
                raise ValueError(
                    f"{item_label} detailed alternative fields must be exactly {sorted(allowed)}; "
                    f"missing={sorted(missing)}, forbidden={sorted(extras)}"
                )
            purl = alternative["purl"]
            _validate_purl(purl, f"{item_label}.purl")
            _require_string(alternative["type"], f"{item_label}.type")
            _require_string(
                alternative["namespace"], f"{item_label}.namespace", nullable=True
            )
            _require_string(alternative["pkg_name"], f"{item_label}.pkg_name")
            confidence = alternative["confidence"]
            if not _finite_number(confidence):
                raise ValueError(f"{item_label}.confidence must be a finite number")
            if alternative["source"] not in ALTERNATIVE_SOURCES:
                raise ValueError(
                    f"{item_label}.source is unsupported: {alternative['source']!r}"
                )
        else:
            raise ValueError(f"{item_label} must be a PURL string or detailed object")
        if purl in seen:
            raise ValueError(f"{item_label} duplicates {purl!r}")
        if purl == primary:
            raise ValueError(f"{item_label} duplicates the primary PURL")
        seen.add(purl)


def _validate_package_entry(entry: Any, label: str, *, auto: bool) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"{label} must be an object")
    if _INTERNAL_PRIMARY in entry or "_filename" in entry:
        raise ValueError(f"{label} uses a reserved internal field")
    purl = entry.get("purl")
    if purl is not None:
        _validate_purl(purl, f"{label}.purl")
    for key in ("type", "namespace", "pkg_name"):
        if key in entry:
            _require_string(entry[key], f"{label}.{key}", nullable=True)
    if "alternative_purls" in entry and entry["alternative_purls"] is not None:
        _validate_alternatives(
            entry["alternative_purls"], f"{label}.alternative_purls", purl
        )
    if "cpes" in entry and entry["cpes"] is not None:
        _validate_cpes(entry["cpes"], f"{label}.cpes")
    if "unmapped" in entry and not isinstance(entry["unmapped"], bool):
        raise ValueError(f"{label}.unmapped must be a boolean")
    if "status" in entry and entry["status"] not in REVIEW_STATUSES:
        raise ValueError(f"{label}.status is unsupported: {entry['status']!r}")
    if entry.get("status") == "unmapped" and entry.get("unmapped") is not True:
        raise ValueError(f"{label}.status unmapped requires unmapped: true")
    if "approved_by" in entry:
        _require_string(entry["approved_by"], f"{label}.approved_by")
    if "approved_at" in entry and not _valid_timestamp(entry["approved_at"]):
        raise ValueError(f"{label}.approved_at must be a valid ISO-8601 timestamp")
    if auto:
        confidence = entry.get("confidence")
        if not _finite_number(confidence):
            raise ValueError(f"{label}.confidence must be a finite number")
        sources = entry.get("sources")
        if not isinstance(sources, list) or any(
            not isinstance(source, str) or not source for source in sources
        ):
            raise ValueError(f"{label}.sources must be an array of non-empty strings")


def _validate_source_payload(
    payload: dict[str, Any], label: str, *, kind: str
) -> dict[str, dict]:
    if payload.get("schema_version") != SOURCE_SCHEMA_VERSION:
        raise ValueError(
            f"{label}: unsupported schema_version {payload.get('schema_version')!r}; "
            f"supported version is {SOURCE_SCHEMA_VERSION}"
        )
    if "_filename" in payload:
        raise ValueError(
            f"{label}: _filename is reserved and cannot control merge ordering"
        )
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise ValueError(f"{label}: packages must be an object")
    for name, entry in packages.items():
        _require_string(name, f"{label}: package identifier")
        _validate_package_entry(entry, f"{label}:{name}", auto=kind == "auto")
    if kind == "manual":
        attribution = {
            "approved_by": payload.get("updated_by"),
            "approved_at": payload.get("updated_at"),
        }
        for name, entry in packages.items():
            if _reviews_primary(entry):
                _effective_attribution(entry, attribution, f"{label}:{name}")
    if kind == "contribution":
        _require_string(payload.get("author"), f"{label}.author")
        if not _valid_timestamp(payload.get("timestamp")):
            raise ValueError(f"{label}.timestamp must be a valid ISO-8601 timestamp")
    return packages


def _load_downloads(path: Path) -> dict[str, int]:
    if not path.exists():
        return {}
    data = _load_json(path)
    rows = data.get("packages")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: packages must be an array")
    out: dict[str, int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{path}: packages[{index}] must be an object")
        name, count = row.get("name"), row.get("total_count")
        _require_string(name, f"{path}: packages[{index}].name")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(
                f"{path}: packages[{index}].total_count must be a non-negative integer"
            )
        if name in out:
            raise ValueError(f"{path}: duplicate package identifier {name!r}")
        out[name] = count
    return out


def _load_contributions(directory: Path) -> list[tuple[dict[str, Any], str]]:
    if not directory.exists():
        return []
    entries: list[tuple[dict[str, Any], str]] = []
    for path in sorted(directory.glob("*.json")):
        data = _load_json(path)
        _validate_source_payload(data, str(path), kind="contribution")
        entries.append((data, path.name))
    entries.sort(
        key=lambda item: (
            _parse_timestamp(item[0]["timestamp"], f"{directory / item[1]}.timestamp"),
            item[1],
        )
    )
    return entries


def _auto_snapshot(auto_entry: dict) -> dict:
    return {
        "purl": auto_entry.get("purl"),
        "type": auto_entry.get("type"),
        "namespace": auto_entry.get("namespace"),
        "pkg_name": auto_entry.get("pkg_name"),
        "confidence": auto_entry.get("confidence", 0.0),
        "sources": auto_entry.get("sources", []),
        "alternative_purls": auto_entry.get("alternative_purls"),
    }


def _reviews_primary(override: dict) -> bool:
    return any(
        key in override and override[key] is not None for key in PRIMARY_REVIEW_FIELDS
    )


def _prune_colliding_alternatives(
    alternatives: list, primary: Any, *, label: str
) -> list:
    """Drop alternatives that collide with the primary PURL or with each other.

    Reviewed layers overlay field by field, so an override that promotes a PURL
    the base layer already carried as an alternative inherits that alternative
    untouched.  Per-file validation only ever sees one layer, so the collision
    first exists in the merged record — dropping it here keeps a routine automap
    demotion from failing ``scripts/validate.py`` and stalling the pipeline.
    """
    kept: list[Any] = []
    seen: set[str] = set()
    for alternative in alternatives:
        purl = alternative if isinstance(alternative, str) else alternative["purl"]
        if purl == primary:
            print(
                f"{label}: dropping inherited alternative {purl!r} now used as the "
                "primary PURL",
                file=sys.stderr,
            )
            continue
        if purl in seen:
            print(
                f"{label}: dropping duplicate inherited alternative {purl!r}",
                file=sys.stderr,
            )
            continue
        seen.add(purl)
        kept.append(alternative)
    return kept


def _effective_attribution(override: dict, attribution: dict, label: str) -> dict:
    reviewer = override.get("approved_by", attribution.get("approved_by"))
    reviewed_at = override.get("approved_at", attribution.get("approved_at"))
    _require_string(reviewer, f"{label}.approved_by")
    if not _valid_timestamp(reviewed_at):
        raise ValueError(f"{label}.approved_at must be a valid ISO-8601 timestamp")
    return {"approved_by": reviewer, "approved_at": reviewed_at}


def _apply_reviewed_override(
    merged: dict[str, dict],
    auto_packages: dict[str, dict],
    name: str,
    override: dict,
    attribution: dict,
    *,
    label: str,
) -> None:
    base = merged.get(name, {"name": name})
    reviews_primary = _reviews_primary(override)
    patch = {
        key: override[key]
        for key in REVIEWED_MAPPING_FIELDS
        if key in override and override[key] is not None
    }

    # Preserve the legacy package-level merge behavior during the additive
    # window: every reviewed layer marks the package manual/verified and owns
    # legacy attribution, including the 848 CPE-only package overrides.
    legacy_attribution = {
        key: value for key, value in attribution.items() if value is not None
    }
    patch.setdefault("status", "verified")
    result = {**base, **patch, "source": "manual", **legacy_attribution}

    if reviews_primary:
        # Per-package manual attribution owns the new typed identity even when
        # the historical package-level fields omitted it. Contributions carry
        # the same current attribution at file level. Do not rewrite legacy
        # attribution merely to make the additive identity view convenient.
        current_attribution = _effective_attribution(override, attribution, label)
        if override.get("unmapped") is True:
            result.update(
                {
                    "purl": None,
                    "type": None,
                    "namespace": None,
                    "pkg_name": None,
                    "alternative_purls": [],
                    "unmapped": True,
                    "status": "unmapped",
                }
            )
        else:
            result["unmapped"] = False
        result[_INTERNAL_PRIMARY] = {
            "availability": "available",
            "source": "manual",
            "review": {
                "status": result["status"],
                "reviewer": current_attribution["approved_by"],
                "reviewed_at": current_attribution["approved_at"],
            },
        }

    if result.get("alternative_purls"):
        result["alternative_purls"] = _prune_colliding_alternatives(
            result["alternative_purls"], result.get("purl"), label=label
        )

    if name in auto_packages and "auto" not in result:
        result["auto"] = _auto_snapshot(auto_packages[name])
    merged[name] = result


def _identity_records(entry: dict) -> list[dict]:
    identities: list[dict] = []
    if isinstance(entry.get("purl"), str) and not entry.get("unmapped"):
        identities.append(
            {
                "kind": "purl",
                "role": "primary",
                "value": entry["purl"],
                "provenance": entry[_INTERNAL_PRIMARY],
            }
        )
    for alternative in entry.get("alternative_purls") or []:
        if isinstance(alternative, str):
            identity = {
                "kind": "purl",
                "role": "alternative",
                "value": alternative,
                "provenance": {"availability": "unavailable"},
            }
        else:
            identity = {
                "kind": "purl",
                "role": "alternative",
                "value": alternative["purl"],
                "coordinates": {
                    "type": alternative["type"],
                    "namespace": alternative["namespace"],
                    "pkg_name": alternative["pkg_name"],
                },
                "provenance": {
                    "availability": "available",
                    "source": alternative["source"],
                    "confidence": alternative["confidence"],
                },
            }
        identities.append(identity)
    for cpe in entry.get("cpes") or []:
        identities.append(
            {
                "kind": "cpe",
                "role": "associated",
                "value": cpe,
                "provenance": {"availability": "unavailable"},
            }
        )
    return identities


def _with_identities(entry: dict) -> dict:
    result = {key: value for key, value in entry.items() if key != _INTERNAL_PRIMARY}
    result["identities"] = _identity_records(entry)
    return result


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
        "identities": entry.get("identities", []),
    }
    for key in ("alternative_purls", "unmapped", "cpes"):
        if key in entry and entry.get(key) is not None:
            out[key] = entry[key]
    return out


def _write_split_payload(payload: dict, index_out: Path, detail_dir: Path) -> None:
    detail_dir.mkdir(parents=True, exist_ok=True)
    for stale in detail_dir.glob("*.json"):
        stale.unlink()
    index_packages: dict[str, dict] = {}
    shards: dict[str, dict[str, dict]] = {}
    for name, entry in sorted(payload["packages"].items()):
        shard = hashlib.sha256(name.encode()).hexdigest()[:2]
        detail_path = f"mapping_packages/{shard}.json"
        shards.setdefault(shard, {})[name] = {**entry, "name": name}
        index_packages[name] = _index_package(name, entry, detail_path)
    for shard, packages in sorted(shards.items()):
        (detail_dir / f"{shard}.json").write_text(
            json.dumps(
                {"schema_version": DETAIL_SCHEMA_VERSION, "packages": packages},
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
    index_payload = {
        **{key: value for key, value in payload.items() if key != "packages"},
        "schema_version": INDEX_SCHEMA_VERSION,
        "packages": index_packages,
    }
    index_out.parent.mkdir(parents=True, exist_ok=True)
    index_out.write_text(
        json.dumps(index_payload, separators=(",", ":"), allow_nan=False) + "\n"
    )


def _build_published_packages(
    auto_data: dict[str, Any],
    manual_data: dict[str, Any],
    contrib_files: list[tuple[dict[str, Any], str]],
    downloads_by_name: dict[str, int],
    *,
    auto_label: str,
    manual_label: str,
    contributions_label: Path,
) -> dict[str, dict]:
    """Replay the validated source layers into canonical published records."""
    auto_packages = _validate_source_payload(auto_data, auto_label, kind="auto")
    manual_packages = _validate_source_payload(manual_data, manual_label, kind="manual")
    merged: dict[str, dict] = {}
    for name, entry in auto_packages.items():
        status = "auto-verified" if entry.get("auto_verified") else "auto-unverified"
        primary = {
            "availability": "available",
            "source": "auto",
            "confidence": entry["confidence"],
            "sources": entry["sources"],
            "review": {"status": status, "reviewer": None},
        }
        merged[name] = {
            **entry,
            "status": status,
            "source": "auto",
            _INTERNAL_PRIMARY: primary,
        }

    legacy_attribution = {
        "approved_by": manual_data.get("updated_by"),
        "approved_at": manual_data.get("updated_at"),
    }
    for name, override in manual_packages.items():
        _apply_reviewed_override(
            merged,
            auto_packages,
            name,
            override,
            legacy_attribution,
            label=f"{manual_label}:{name}",
        )

    for contribution, filename in contrib_files:
        attribution = {
            "approved_by": contribution["author"],
            "approved_at": contribution["timestamp"],
        }
        for name, override in contribution["packages"].items():
            _apply_reviewed_override(
                merged,
                auto_packages,
                name,
                override,
                attribution,
                label=f"{contributions_label / filename}:{name}",
            )

    for name, entry in merged.items():
        if entry.get("download_count") is None and name in downloads_by_name:
            entry["download_count"] = downloads_by_name[name]
    return {name: _with_identities(entry) for name, entry in merged.items()}


def main(
    auto: Path = DEFAULT_AUTO,
    manual: Path = DEFAULT_MANUAL,
    contributions: Path = DEFAULT_CONTRIB_DIR,
    downloads: Path = DEFAULT_DOWNLOADS,
    out: Path = DEFAULT_OUT,
    index_out: Path = DEFAULT_INDEX_OUT,
    detail_dir: Path = DEFAULT_DETAIL_DIR,
    generated_at: str | None = None,
) -> None:
    auto_data = _load_json(auto)
    manual_data = _load_json(manual)
    contrib_files = _load_contributions(contributions)
    downloads_by_name = _load_downloads(downloads)
    published = _build_published_packages(
        auto_data,
        manual_data,
        contrib_files,
        downloads_by_name,
        auto_label=str(auto),
        manual_label=str(manual),
        contributions_label=contributions,
    )
    auto_packages = auto_data["packages"]
    manual_packages = manual_data["packages"]
    payload = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "generated_at": generated_at or datetime.now(UTC).isoformat(timespec="seconds"),
        "auto_generated_at": auto_data.get("generated_at"),
        "manual_updated_at": manual_data.get("updated_at"),
        "contribution_count": len(contrib_files),
        "download_count_source": "prefix.dev (Package.totalCount)"
        if downloads_by_name
        else None,
        "channel": auto_data.get("channel", "conda-forge"),
        "package_count": len(published),
        "packages": dict(sorted(published.items())),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, allow_nan=False) + "\n")
    _write_split_payload(payload, index_out, detail_dir)
    print(
        f"Merged auto={len(auto_packages)} + manual={len(manual_packages)} + "
        f"contributions={len(contrib_files)} → {out}, {index_out}, {detail_dir} "
        f"({len(published)} packages)"
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
