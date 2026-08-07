"""Validate source and published package identity mapping contracts."""

from __future__ import annotations

import argparse
import math
import sys
from pathlib import Path
from typing import Any

from scripts import merge_mappings

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO_MAPPINGS = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL_MAPPINGS = ROOT / "mappings" / "manual.json"
DEFAULT_MAPPING_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_MAPPINGS_BUNDLE = ROOT / "web" / "public" / "mappings.json"
DEFAULT_MAPPINGS_INDEX = ROOT / "web" / "public" / "mappings-index.json"
DEFAULT_MAPPINGS_DETAIL_DIR = ROOT / "web" / "public" / "mapping_packages"

CPE23_RE = merge_mappings.CPE23_RE
PURL_RE = merge_mappings.PURL_RE
SUPPORTED_BUNDLE_SCHEMAS = {1, 2}
SUPPORTED_INDEX_SCHEMAS = {2, 3}
SUPPORTED_DETAIL_SCHEMAS = {1, 2}
CURRENT_BUNDLE_SCHEMA = 2
CURRENT_INDEX_SCHEMA = 3
CURRENT_DETAIL_SCHEMA = 2
REVIEW_STATUSES = merge_mappings.REVIEW_STATUSES
PRIMARY_SOURCES = merge_mappings.PRIMARY_SOURCES
ALTERNATIVE_SOURCES = merge_mappings.ALTERNATIVE_SOURCES


def _load(path: Path) -> dict[str, Any]:
    return merge_mappings._load_json(path)


def _rel(path: Path) -> Path | str:
    return path.relative_to(ROOT) if path.is_relative_to(ROOT) else path


def _valid_timestamp(value: Any) -> bool:
    return merge_mappings._valid_timestamp(value)


def _purl_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item if isinstance(item, str) else item.get("purl")
        for item in value
        if isinstance(item, (str, dict))
    ]


def _validate_schema_version(
    payload: dict[str, Any], label: str, supported: set[int], errors: list[str]
) -> int | None:
    version = payload.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int):
        errors.append(f"{label}: schema_version must be an integer")
        return None
    if version not in supported:
        errors.append(
            f"{label}: unsupported schema_version {version}; supported versions are {sorted(supported)}"
        )
        return None
    return version


def _validate_cpes(value: Any, label: str, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        errors.append(f"{label}: cpes must be an array")
        return
    seen: set[str] = set()
    for index, cpe in enumerate(value):
        item_label = f"{label}.cpes[{index}]"
        if not isinstance(cpe, str) or not cpe:
            errors.append(f"{item_label}: CPE must be a non-empty string")
        elif not CPE23_RE.fullmatch(cpe):
            errors.append(
                f"{item_label}: {cpe!r} is not a valid CPE 2.3 vendor/product prefix"
            )
        if isinstance(cpe, str) and cpe in seen:
            errors.append(f"{item_label}: duplicate CPE {cpe!r}")
        if isinstance(cpe, str):
            seen.add(cpe)


def _validate_published_confidences(
    entry: dict[str, Any], label: str, errors: list[str]
) -> None:
    if "confidence" in entry and not merge_mappings._finite_number(entry["confidence"]):
        errors.append(f"{label}.confidence: confidence must be a finite number")
    auto = entry.get("auto")
    if auto is not None:
        if not isinstance(auto, dict):
            errors.append(f"{label}.auto: must be an object")
        elif not merge_mappings._finite_number(auto.get("confidence")):
            errors.append(
                f"{label}.auto.confidence: confidence must be a finite number"
            )
    alternatives = entry.get("alternative_purls")
    if isinstance(alternatives, list):
        for index, alternative in enumerate(alternatives):
            if isinstance(alternative, dict) and not merge_mappings._finite_number(
                alternative.get("confidence")
            ):
                errors.append(
                    f"{label}.alternative_purls[{index}].confidence: "
                    "confidence must be a finite number"
                )


def _error_extra_fields(
    value: dict, allowed: set[str], label: str, errors: list[str]
) -> None:
    extras = set(value) - allowed
    if extras:
        errors.append(f"{label}: forbidden fields {sorted(extras)}")


def _validate_identity_contract(
    entry: dict[str, Any], label: str, errors: list[str]
) -> None:
    identities = entry.get("identities")
    if not isinstance(identities, list):
        errors.append(f"{label}: identities must be an array")
        return

    expected: list[dict[str, Any]] = []
    purl = entry.get("purl")
    unmapped = entry.get("unmapped") is True
    if isinstance(purl, str) and not unmapped:
        # The exact primary provenance is checked structurally below; source
        # layer regeneration checks attribution equality against source data.
        expected.append({"kind": "purl", "role": "primary", "value": purl})
    alternatives = entry.get("alternative_purls") or []
    if not isinstance(alternatives, list):
        errors.append(f"{label}: alternative_purls must be an array or null")
        alternatives = []
    for alternative in alternatives:
        value = (
            alternative
            if isinstance(alternative, str)
            else alternative.get("purl")
            if isinstance(alternative, dict)
            else None
        )
        expected.append(
            {
                "kind": "purl",
                "role": "alternative",
                "value": value,
                "source": alternative,
            }
        )
    cpes = entry.get("cpes") or []
    if not isinstance(cpes, list):
        errors.append(f"{label}: cpes must be an array or null")
        cpes = []
    for cpe in cpes:
        expected.append({"kind": "cpe", "role": "associated", "value": cpe})

    seen: set[str] = set()
    actual_summary: list[tuple[Any, Any, Any]] = []
    for index, identity in enumerate(identities):
        identity_label = f"{label}.identities[{index}]"
        if not isinstance(identity, dict):
            errors.append(f"{identity_label}: identity must be an object")
            continue
        kind, role, value = (
            identity.get("kind"),
            identity.get("role"),
            identity.get("value"),
        )
        actual_summary.append((kind, role, value))
        allowed_identity = {"kind", "role", "value", "provenance"}
        if kind == "purl" and role == "alternative":
            allowed_identity.add("coordinates")
        _error_extra_fields(identity, allowed_identity, identity_label, errors)
        if not isinstance(value, str) or not value:
            errors.append(f"{identity_label}: value must be a non-empty string")
        elif kind == "purl" and not PURL_RE.fullmatch(value):
            errors.append(f"{identity_label}: value is not a valid PURL")
        elif kind == "cpe" and not CPE23_RE.fullmatch(value):
            errors.append(f"{identity_label}: value is not a valid CPE")
        if isinstance(value, str):
            if value in seen:
                errors.append(f"{identity_label}: duplicate identity value {value!r}")
            seen.add(value)

        provenance = identity.get("provenance")
        if not isinstance(provenance, dict):
            errors.append(f"{identity_label}: provenance must be an object")
            continue

        if kind == "purl" and role == "primary":
            allowed_provenance = {
                "availability",
                "source",
                "review",
                "confidence",
                "sources",
            }
            _error_extra_fields(
                provenance, allowed_provenance, f"{identity_label}.provenance", errors
            )
            if provenance.get("availability") != "available":
                errors.append(f"{identity_label}: primary provenance must be available")
            source = provenance.get("source")
            if source not in PRIMARY_SOURCES:
                errors.append(
                    f"{identity_label}: unsupported primary source {source!r}"
                )
            review = provenance.get("review")
            if not isinstance(review, dict):
                errors.append(f"{identity_label}: primary review is required")
            else:
                _error_extra_fields(
                    review,
                    {"status", "reviewer", "reviewed_at"},
                    f"{identity_label}.provenance.review",
                    errors,
                )
                status = review.get("status")
                if status not in REVIEW_STATUSES:
                    errors.append(
                        f"{identity_label}: unsupported review status {status!r}"
                    )
                if (
                    "reviewer" not in review
                    or review.get("reviewer") is not None
                    and (
                        not isinstance(review.get("reviewer"), str)
                        or not review.get("reviewer")
                    )
                ):
                    errors.append(
                        f"{identity_label}: reviewer must be a non-empty string or null"
                    )
                if "reviewed_at" in review and not _valid_timestamp(
                    review["reviewed_at"]
                ):
                    errors.append(
                        f"{identity_label}: reviewed_at must be a valid ISO-8601 timestamp"
                    )
                if source == "auto":
                    if status not in {"auto-unverified", "auto-verified"}:
                        errors.append(
                            f"{identity_label}: automatic primary has invalid review status"
                        )
                    if review.get("reviewer") is not None or "reviewed_at" in review:
                        errors.append(
                            f"{identity_label}: automatic primary cannot have human attribution"
                        )
                elif source == "manual":
                    if status not in {"verified", "edited"}:
                        errors.append(
                            f"{identity_label}: manual primary has invalid review status"
                        )
                    if not isinstance(review.get("reviewer"), str) or not review.get(
                        "reviewer"
                    ):
                        errors.append(
                            f"{identity_label}: manual primary reviewer is required"
                        )
                    if not _valid_timestamp(review.get("reviewed_at")):
                        errors.append(
                            f"{identity_label}: manual primary reviewed_at is required"
                        )
            if source == "auto":
                confidence = provenance.get("confidence")
                if (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not math.isfinite(confidence)
                ):
                    errors.append(
                        f"{identity_label}: automatic confidence must be a finite number"
                    )
                sources = provenance.get("sources")
                if not isinstance(sources, list) or any(
                    not isinstance(item, str) or not item for item in sources
                ):
                    errors.append(
                        f"{identity_label}: automatic sources must be an array of non-empty strings"
                    )
            elif "confidence" in provenance or "sources" in provenance:
                errors.append(
                    f"{identity_label}: manual primary cannot carry automatic confidence/sources"
                )

        elif kind == "purl" and role == "alternative":
            alternative_index = (
                len(
                    [
                        x
                        for x in actual_summary
                        if x[0] == "purl" and x[1] == "alternative"
                    ]
                )
                - 1
            )
            source_alternative = (
                alternatives[alternative_index]
                if 0 <= alternative_index < len(alternatives)
                else None
            )
            if isinstance(source_alternative, str):
                if provenance != {"availability": "unavailable"}:
                    errors.append(
                        f"{identity_label}: bare alternative provenance must be exactly unavailable"
                    )
                if "coordinates" in identity:
                    errors.append(
                        f"{identity_label}: bare alternative cannot have coordinates"
                    )
            elif isinstance(source_alternative, dict):
                exact_provenance = {
                    "availability": "available",
                    "source": source_alternative.get("source"),
                    "confidence": source_alternative.get("confidence"),
                }
                exact_coordinates = {
                    key: source_alternative.get(key)
                    for key in ("type", "namespace", "pkg_name")
                }
                if provenance != exact_provenance:
                    errors.append(
                        f"{identity_label}: detailed alternative provenance does not exactly match source"
                    )
                if identity.get("coordinates") != exact_coordinates:
                    errors.append(
                        f"{identity_label}: detailed alternative coordinates do not exactly match source"
                    )
                if provenance.get("source") not in ALTERNATIVE_SOURCES:
                    errors.append(f"{identity_label}: unsupported alternative source")
                confidence = provenance.get("confidence")
                if (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not math.isfinite(confidence)
                ):
                    errors.append(
                        f"{identity_label}: alternative confidence must be a finite number"
                    )
            else:
                errors.append(
                    f"{identity_label}: alternative has no valid legacy source"
                )

        elif kind == "cpe" and role == "associated":
            if set(identity) != {"kind", "role", "value", "provenance"}:
                errors.append(f"{identity_label}: CPE contains forbidden fields")
            if provenance != {"availability": "unavailable"}:
                errors.append(
                    f"{identity_label}: CPE provenance must be exactly unavailable"
                )
        else:
            errors.append(
                f"{identity_label}: unsupported identity kind/role {kind!r}/{role!r}"
            )

    expected_summary = [
        (item["kind"], item["role"], item["value"]) for item in expected
    ]
    if actual_summary != expected_summary:
        errors.append(
            f"{label}: identities do not exactly match ordered legacy identities"
        )
    if isinstance(purl, str) and purl in _purl_list(alternatives):
        errors.append(f"{label}: primary PURL must not appear as an alternative")
    if unmapped:
        if entry.get("status") != "unmapped":
            errors.append(f"{label}: unmapped package status must be unmapped")
        for key in ("purl", "type", "namespace", "pkg_name"):
            if entry.get(key) is not None:
                errors.append(f"{label}: unmapped package must clear {key}")
        if alternatives:
            errors.append(f"{label}: unmapped package must clear alternative_purls")
        if any(
            item[:2] in {("purl", "primary"), ("purl", "alternative")}
            for item in actual_summary
        ):
            errors.append(f"{label}: unmapped package must not publish PURL identities")


def _load_mapping_contributions(
    directory: Path, errors: list[str]
) -> list[dict[str, Any]]:
    try:
        return [data for data, _ in merge_mappings._load_contributions(directory)]
    except ValueError as exc:
        errors.append(str(exc))
        return []


def validate_source_payloads(
    auto_path: Path, manual_path: Path, contrib_dir: Path, errors: list[str]
) -> bool:
    try:
        auto = _load(auto_path)
        manual = _load(manual_path)
        merge_mappings._validate_source_payload(auto, str(_rel(auto_path)), kind="auto")
        merge_mappings._validate_source_payload(
            manual, str(_rel(manual_path)), kind="manual"
        )
        merge_mappings._load_contributions(contrib_dir)
    except ValueError as exc:
        errors.append(str(exc))
    return auto_path.exists() and manual_path.exists()


def validate_source_cpes(
    manual_path: Path, contrib_dir: Path, errors: list[str]
) -> tuple[bool, int]:
    checked = 0
    try:
        manual = _load(manual_path)
        for name, entry in merge_mappings._validate_source_payload(
            manual, str(_rel(manual_path)), kind="manual"
        ).items():
            if entry.get("cpes") is not None:
                checked += 1
        for contribution, _ in merge_mappings._load_contributions(contrib_dir):
            checked += sum(
                entry.get("cpes") is not None
                for entry in contribution["packages"].values()
            )
    except ValueError as exc:
        errors.append(str(exc))
    return manual_path.exists() or contrib_dir.exists(), checked


CANONICAL_MAPPING_FIELDS = (
    "purl",
    "type",
    "namespace",
    "pkg_name",
    "alternative_purls",
    "cpes",
    "unmapped",
    "status",
    "source",
    "approved_by",
    "approved_at",
)
INDEX_CANONICAL_FIELDS = (
    "purl",
    "type",
    "namespace",
    "pkg_name",
    "alternative_purls",
    "cpes",
    "unmapped",
    "status",
)


def replay_source_mappings(
    auto_path: Path,
    manual_path: Path,
    contrib_dir: Path,
    errors: list[str],
) -> dict[str, dict] | None:
    """Reconstruct canonical identities and ownership from source layers."""
    try:
        auto_data = _load(auto_path)
        manual_data = _load(manual_path)
        contributions = merge_mappings._load_contributions(contrib_dir)
        return merge_mappings._build_published_packages(
            auto_data,
            manual_data,
            contributions,
            {},
            auto_label=str(_rel(auto_path)),
            manual_label=str(_rel(manual_path)),
            contributions_label=contrib_dir,
        )
    except ValueError as exc:
        errors.append(str(exc))
        return None


def _canonical_shape(
    entry: dict[str, Any], *, current: bool, index: bool = False
) -> dict[str, Any]:
    fields = INDEX_CANONICAL_FIELDS if index else CANONICAL_MAPPING_FIELDS
    shaped = {
        key: entry[key]
        for key in fields
        if key in entry
        and not (
            index
            and key in {"alternative_purls", "cpes", "unmapped"}
            and entry[key] is None
        )
        and not (not current and key == "unmapped" and entry[key] is False)
    }
    if current and "identities" in entry:
        shaped["identities"] = entry["identities"]
    return shaped


def _compare_to_source(
    actual_packages: dict[str, Any],
    expected_packages: dict[str, dict],
    label: str,
    errors: list[str],
    *,
    current: bool,
    index: bool = False,
) -> None:
    if set(actual_packages) != set(expected_packages):
        errors.append(f"{label}: package set does not match source mapping layers")
    for name in actual_packages.keys() & expected_packages.keys():
        actual = actual_packages[name]
        if not isinstance(actual, dict):
            continue
        actual_shape = _canonical_shape(actual, current=current, index=index)
        expected_shape = _canonical_shape(
            expected_packages[name], current=current, index=index
        )
        if actual_shape != expected_shape:
            errors.append(
                f"{label}:{name}: canonical mapping identities/ownership do not match source layers"
            )


def validate_mapping_alternatives(
    manual_path: Path,
    contrib_dir: Path,
    mappings_path: Path,
    errors: list[str],
    auto_path: Path = DEFAULT_AUTO_MAPPINGS,
    expected_packages: dict[str, dict] | None = None,
) -> bool:
    if not mappings_path.exists():
        errors.append(f"{_rel(mappings_path)}: missing; run mappings:merge first")
        return False
    try:
        merged = _load(mappings_path)
    except ValueError as exc:
        errors.append(str(exc))
        return True
    version = _validate_schema_version(
        merged, str(_rel(mappings_path)), SUPPORTED_BUNDLE_SCHEMAS, errors
    )
    if expected_packages is None:
        expected_packages = replay_source_mappings(
            auto_path, manual_path, contrib_dir, errors
        )

    packages = merged.get("packages")
    if not isinstance(packages, dict):
        errors.append(f"{_rel(mappings_path)}: packages must be an object")
        return True
    if merged.get("package_count") != len(packages):
        errors.append(f"{_rel(mappings_path)}: package_count does not match packages")
    for name, entry in packages.items():
        if not isinstance(name, str) or not name or not isinstance(entry, dict):
            errors.append(
                f"{_rel(mappings_path)}:{name}: invalid package identifier or entry"
            )
            continue
        entry_label = f"{_rel(mappings_path)}:{name}"
        _validate_cpes(entry.get("cpes"), entry_label, errors)
        _validate_published_confidences(entry, entry_label, errors)
        if version == CURRENT_BUNDLE_SCHEMA:
            _validate_identity_contract(entry, f"{_rel(mappings_path)}:{name}", errors)
    if expected_packages is not None and version is not None:
        _compare_to_source(
            packages,
            expected_packages,
            str(_rel(mappings_path)),
            errors,
            current=version == CURRENT_BUNDLE_SCHEMA,
        )
    return True


def _expected_index_entry(
    name: str, detail: dict, detail_path: str, *, current: bool
) -> dict:
    entry = merge_mappings._index_package(name, detail, detail_path)
    if not current:
        entry.pop("identities", None)
    return entry


def validate_split_mappings(
    index_path: Path,
    detail_dir: Path,
    errors: list[str],
    bundle_path: Path | None = None,
    expected_packages: dict[str, dict] | None = None,
) -> bool:
    if not index_path.exists():
        errors.append(f"{_rel(index_path)}: missing; run mappings:merge first")
        return False
    try:
        index = _load(index_path)
        bundle = _load(bundle_path) if bundle_path and bundle_path.exists() else None
    except ValueError as exc:
        errors.append(str(exc))
        return True
    index_version = _validate_schema_version(
        index, str(_rel(index_path)), SUPPORTED_INDEX_SCHEMAS, errors
    )
    index_packages = index.get("packages")
    if not isinstance(index_packages, dict):
        errors.append(f"{_rel(index_path)}: packages must be an object")
        return True
    bundle_packages = bundle.get("packages") if isinstance(bundle, dict) else None
    bundle_version = None
    if bundle is not None:
        bundle_version = _validate_schema_version(
            bundle, str(_rel(bundle_path)), SUPPORTED_BUNDLE_SCHEMAS, errors
        )
        expected_bundle_version = (
            CURRENT_BUNDLE_SCHEMA
            if index_version == CURRENT_INDEX_SCHEMA
            else CURRENT_BUNDLE_SCHEMA - 1
        )
        if bundle_version != expected_bundle_version:
            errors.append(
                "bundle and index schema versions do not form a supported pair"
            )
        if not isinstance(bundle_packages, dict):
            errors.append(f"{_rel(bundle_path)}: packages must be an object")
            bundle_packages = {}
        if set(bundle_packages) != set(index_packages):
            errors.append("bundle and index package sets do not match")
        bundle_header = {
            key: value
            for key, value in bundle.items()
            if key not in {"packages", "schema_version"}
        }
        index_header = {
            key: value
            for key, value in index.items()
            if key not in {"packages", "schema_version"}
        }
        if bundle_header != index_header:
            errors.append("bundle and index metadata do not match")

    referenced: set[Path] = set()
    shard_packages: dict[str, dict] = {}
    for name, index_entry in index_packages.items():
        if not isinstance(index_entry, dict):
            errors.append(f"{_rel(index_path)}:{name}: index entry must be an object")
            continue
        path_value = index_entry.get("detail_path")
        if not isinstance(path_value, str) or not path_value:
            errors.append(f"{_rel(index_path)}:{name}: detail_path is required")
            continue
        referenced.add(index_path.parent / path_value)
    for path in sorted(referenced):
        if not path.exists():
            errors.append(f"{_rel(path)}: referenced shard is missing")
            continue
        try:
            shard = _load(path)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        shard_version = _validate_schema_version(
            shard, str(_rel(path)), SUPPORTED_DETAIL_SCHEMAS, errors
        )
        expected_detail_version = (
            CURRENT_DETAIL_SCHEMA
            if index_version == CURRENT_INDEX_SCHEMA
            else CURRENT_DETAIL_SCHEMA - 1
        )
        if shard_version is not None and shard_version != expected_detail_version:
            errors.append(
                f"{_rel(path)}: index/detail schema versions do not form a supported pair"
            )
        packages = shard.get("packages")
        if not isinstance(packages, dict):
            errors.append(f"{_rel(path)}: packages must be an object")
            continue
        for name, detail in packages.items():
            if name in shard_packages:
                errors.append(f"{_rel(path)}: duplicate sharded package {name!r}")
            elif isinstance(detail, dict):
                shard_packages[name] = detail
            else:
                errors.append(f"{_rel(path)}:{name}: detail entry must be an object")
    if set(shard_packages) != set(index_packages):
        errors.append("index and shard package sets do not match")

    for name, index_entry in index_packages.items():
        detail = shard_packages.get(name)
        if not isinstance(index_entry, dict) or not isinstance(detail, dict):
            continue
        label = f"{_rel(index_path)}:{name}"
        if detail.get("name") != name:
            errors.append(f"{label}: detail name does not match package key")
        if index_version == CURRENT_INDEX_SCHEMA:
            _validate_identity_contract(index_entry, label, errors)
            _validate_identity_contract(detail, f"{label}:detail", errors)
        _validate_cpes(index_entry.get("cpes"), label, errors)
        _validate_cpes(detail.get("cpes"), f"{label}:detail", errors)
        _validate_published_confidences(index_entry, label, errors)
        _validate_published_confidences(detail, f"{label}:detail", errors)
        detail_path = index_entry["detail_path"]
        expected_index = _expected_index_entry(
            name,
            {key: value for key, value in detail.items() if key != "name"},
            detail_path,
            current=index_version == CURRENT_INDEX_SCHEMA,
        )
        if index_entry != expected_index:
            errors.append(
                f"{label}: index entry does not exactly match detail legacy/typed fields"
            )
        if isinstance(bundle_packages, dict) and name in bundle_packages:
            expected_detail = {**bundle_packages[name], "name": name}
            if detail != expected_detail:
                errors.append(
                    f"{label}: detail does not exactly match canonical bundle record"
                )

    if expected_packages is not None and index_version is not None:
        current = index_version == CURRENT_INDEX_SCHEMA
        _compare_to_source(
            index_packages,
            expected_packages,
            str(_rel(index_path)),
            errors,
            current=current,
            index=True,
        )
        _compare_to_source(
            shard_packages,
            expected_packages,
            f"{_rel(detail_dir)} shards",
            errors,
            current=current,
        )

    if detail_dir.exists():
        actual_paths = set(detail_dir.glob("*.json"))
        if actual_paths != referenced:
            errors.append("detail directory contains missing or stale shard files")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auto-mappings", type=Path, default=DEFAULT_AUTO_MAPPINGS)
    parser.add_argument("--manual-mappings", type=Path, default=DEFAULT_MANUAL_MAPPINGS)
    parser.add_argument(
        "--mapping-contributions", type=Path, default=DEFAULT_MAPPING_CONTRIB_DIR
    )
    parser.add_argument("--mappings", type=Path, default=DEFAULT_MAPPINGS_BUNDLE)
    parser.add_argument("--mappings-index", type=Path, default=DEFAULT_MAPPINGS_INDEX)
    parser.add_argument(
        "--mappings-detail-dir", type=Path, default=DEFAULT_MAPPINGS_DETAIL_DIR
    )
    args = parser.parse_args()
    errors: list[str] = []
    validate_source_payloads(
        args.auto_mappings, args.manual_mappings, args.mapping_contributions, errors
    )
    _, checked = validate_source_cpes(
        args.manual_mappings, args.mapping_contributions, errors
    )
    expected_packages = replay_source_mappings(
        args.auto_mappings,
        args.manual_mappings,
        args.mapping_contributions,
        errors,
    )
    validate_mapping_alternatives(
        args.manual_mappings,
        args.mapping_contributions,
        args.mappings,
        errors,
        args.auto_mappings,
        expected_packages,
    )
    validate_split_mappings(
        args.mappings_index,
        args.mappings_detail_dir,
        errors,
        args.mappings,
        expected_packages,
    )
    if errors:
        print(f"✗ {len(errors)} mapping validation error(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        raise SystemExit(1)
    print(
        f"✓ identity mappings valid: source schemas, {checked} CPE mappings, bundle/index/shards, and typed provenance"
    )


if __name__ == "__main__":
    main()
