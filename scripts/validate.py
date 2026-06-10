"""Validate package identity mapping payloads.

This repository owns conda-forge package identity mappings only: PURLs and CPEs.
CVE assignment, VEX review, AI CVE drafts, and SBOM-derived findings are owned by
downstream consumers.

Checks performed:

* ``web/public/mappings.json`` preserves reviewed ``alternative_purls`` lists
  from ``mappings/manual.json`` and ``mappings/contributions/*.json`` exactly.
* ``web/public/mappings-index.json`` references existing shard files under
  ``web/public/mapping_packages/`` and every referenced package appears in its
  shard.
* every CPE value in manual/contribution/generated mapping payloads is a CPE
  2.3 string prefix (``cpe:2.3:<part>:<vendor>:<product>`` or longer).

Run via ``pixi run -e lite mappings:validate``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANUAL_MAPPINGS = ROOT / "mappings" / "manual.json"
DEFAULT_MAPPING_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_MAPPINGS_BUNDLE = ROOT / "web" / "public" / "mappings.json"
DEFAULT_MAPPINGS_INDEX = ROOT / "web" / "public" / "mappings-index.json"
DEFAULT_MAPPINGS_DETAIL_DIR = ROOT / "web" / "public" / "mapping_packages"

CPE23_RE = re.compile(r"^cpe:2\.3:[aho\*\-]:[^:]+:[^:]+(?::[^:]*){0,10}$")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _rel(path: Path) -> Path | str:
    return path.relative_to(ROOT) if path.is_relative_to(ROOT) else path


def _purl_list(value: Any) -> list[str]:
    out: list[str] = []
    for item in value or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and isinstance(item.get("purl"), str):
            out.append(item["purl"])
    return out


def _load_mapping_contributions(
    directory: Path, errors: list[str]
) -> list[dict[str, Any]]:
    if not directory.exists():
        return []
    entries: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{_rel(path)}: invalid JSON: {exc}")
            continue
        data.setdefault("_filename", path.name)
        if not isinstance(data.get("timestamp"), str):
            data["timestamp"] = path.stem
        entries.append(data)
    entries.sort(key=lambda d: (d.get("timestamp") or "", d.get("_filename")))
    return entries


def _validate_cpes(value: Any, label: str, errors: list[str]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        errors.append(f"{label}: cpes must be an array")
        return
    seen: set[str] = set()
    for i, cpe in enumerate(value):
        item_label = f"{label}.cpes[{i}]"
        if not isinstance(cpe, str):
            errors.append(f"{item_label}: CPE must be a string")
            continue
        if cpe in seen:
            errors.append(f"{item_label}: duplicate CPE {cpe!r}")
        seen.add(cpe)
        if not CPE23_RE.match(cpe):
            errors.append(
                f"{item_label}: {cpe!r} is not a valid CPE 2.3 vendor/product prefix"
            )


def validate_source_cpes(
    manual_path: Path,
    contrib_dir: Path,
    errors: list[str],
) -> tuple[bool, int]:
    checked = 0
    if manual_path.exists():
        try:
            manual = _load(manual_path)
        except json.JSONDecodeError as exc:
            errors.append(f"{_rel(manual_path)}: invalid JSON: {exc}")
            manual = {}
        for name, entry in (manual.get("packages") or {}).items():
            if isinstance(entry, dict) and "cpes" in entry:
                checked += 1
                _validate_cpes(entry.get("cpes"), f"{_rel(manual_path)}:{name}", errors)

    for contrib in _load_mapping_contributions(contrib_dir, errors):
        filename = contrib.get("_filename", "<contribution>")
        for name, entry in (contrib.get("packages") or {}).items():
            if isinstance(entry, dict) and "cpes" in entry:
                checked += 1
                _validate_cpes(
                    entry.get("cpes"), f"{_rel(contrib_dir)}/{filename}:{name}", errors
                )
    return manual_path.exists() or contrib_dir.exists(), checked


def validate_mapping_alternatives(
    manual_path: Path,
    contrib_dir: Path,
    mappings_path: Path,
    errors: list[str],
) -> bool:
    """Ensure reviewed alternative removals survive the mappings merge."""
    if not mappings_path.exists():
        errors.append(f"{_rel(mappings_path)}: missing; run mappings:merge first")
        return False
    try:
        merged = _load(mappings_path)
    except json.JSONDecodeError as exc:
        errors.append(f"{_rel(mappings_path)}: invalid JSON: {exc}")
        return True

    expected: dict[str, list[str]] = {}
    if manual_path.exists():
        try:
            manual = _load(manual_path)
        except json.JSONDecodeError:
            manual = {}
        for name, override in (manual.get("packages") or {}).items():
            if isinstance(override, dict) and "alternative_purls" in override:
                expected[name] = _purl_list(override.get("alternative_purls"))

    for contrib in _load_mapping_contributions(contrib_dir, errors):
        for name, override in (contrib.get("packages") or {}).items():
            if isinstance(override, dict) and "alternative_purls" in override:
                expected[name] = _purl_list(override.get("alternative_purls"))

    packages = merged.get("packages") or {}
    if not isinstance(packages, dict):
        errors.append(f"{_rel(mappings_path)}: packages must be an object")
        return True
    for name, entry in packages.items():
        if isinstance(entry, dict) and "cpes" in entry:
            _validate_cpes(entry.get("cpes"), f"{_rel(mappings_path)}:{name}", errors)
    for name, wanted in expected.items():
        got = _purl_list((packages.get(name) or {}).get("alternative_purls"))
        if got != wanted:
            errors.append(
                f"{_rel(mappings_path)}:{name}: alternative_purls merged as "
                f"{got!r}, expected latest reviewed list {wanted!r}"
            )
    return True


def validate_split_mappings(
    index_path: Path, detail_dir: Path, errors: list[str]
) -> bool:
    """Validate mappings-index.json plus sharded package detail files."""
    if not index_path.exists():
        errors.append(f"{_rel(index_path)}: missing; run mappings:merge first")
        return False
    try:
        index = _load(index_path)
    except json.JSONDecodeError as exc:
        errors.append(f"{_rel(index_path)}: invalid JSON: {exc}")
        return True
    packages = index.get("packages")
    if not isinstance(packages, dict):
        errors.append(f"{_rel(index_path)}: packages must be an object")
        return True
    seen_detail_paths: set[str] = set()
    for name, pkg_index in packages.items():
        if not isinstance(pkg_index, dict):
            errors.append(f"{_rel(index_path)}:{name}: index entry must be an object")
            continue
        _validate_cpes(pkg_index.get("cpes"), f"{_rel(index_path)}:{name}", errors)
        detail_path = pkg_index.get("detail_path")
        if not isinstance(detail_path, str):
            errors.append(f"{_rel(index_path)}:{name}: detail_path is required")
            continue
        seen_detail_paths.add(detail_path)
        path = ROOT / "web" / "public" / detail_path
        if not path.exists():
            errors.append(
                f"{_rel(index_path)}:{name}: missing detail file {detail_path}"
            )
            continue
        try:
            detail = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{_rel(path)}: invalid JSON: {exc}")
            continue
        shard_packages = detail.get("packages")
        if not isinstance(shard_packages, dict):
            errors.append(f"{_rel(path)}: packages must be an object")
            continue
        package_detail = shard_packages.get(name)
        if not isinstance(package_detail, dict):
            errors.append(f"{_rel(path)}: missing package {name!r} referenced by index")
            continue
        if package_detail.get("name") != name:
            errors.append(
                f"{_rel(path)}:{name}: detail name {package_detail.get('name')!r}, expected {name!r}"
            )
        _validate_cpes(package_detail.get("cpes"), f"{_rel(path)}:{name}", errors)
        index_cpes = pkg_index.get("cpes") or []
        detail_cpes = package_detail.get("cpes") or []
        if index_cpes != detail_cpes:
            errors.append(
                f"{_rel(index_path)}:{name}: index cpes {index_cpes!r} "
                f"do not match detail cpes {detail_cpes!r}"
            )
    if detail_dir.exists():
        expected = {
            str((ROOT / "web" / "public" / p).resolve()) for p in seen_detail_paths
        }
        for path in detail_dir.glob("*.json"):
            if str(path.resolve()) not in expected:
                errors.append(
                    f"{_rel(path)}: stale detail file not referenced by index"
                )
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mappings", type=Path, default=DEFAULT_MAPPINGS_BUNDLE)
    parser.add_argument("--mappings-index", type=Path, default=DEFAULT_MAPPINGS_INDEX)
    parser.add_argument(
        "--mappings-detail-dir", type=Path, default=DEFAULT_MAPPINGS_DETAIL_DIR
    )
    parser.add_argument(
        "--mapping-contributions", type=Path, default=DEFAULT_MAPPING_CONTRIB_DIR
    )
    parser.add_argument("--manual-mappings", type=Path, default=DEFAULT_MANUAL_MAPPINGS)
    args = parser.parse_args()

    errors: list[str] = []
    _, n_source_cpe = validate_source_cpes(
        args.manual_mappings, args.mapping_contributions, errors
    )
    has_mappings = validate_mapping_alternatives(
        args.manual_mappings, args.mapping_contributions, args.mappings, errors
    )
    has_split_mappings = validate_split_mappings(
        args.mappings_index, args.mappings_detail_dir, errors
    )

    if errors:
        print(f"✗ {len(errors)} mapping validation error(s):", file=sys.stderr)
        for line in errors:
            print(f"  - {line}", file=sys.stderr)
        sys.exit(1)

    print(
        f"✓ identity mappings valid: "
        f"{n_source_cpe} source CPE mapping(s) checked, "
        f"mapping removals {'valid' if has_mappings else 'absent'}, "
        f"split mapping payload {'valid' if has_split_mappings else 'absent'}"
    )


if __name__ == "__main__":
    main()
