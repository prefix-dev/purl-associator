"""Validate the generated CVE data against the published JSON Schemas.

This is the standards-compliance gate. It checks:

* ``mappings/cves/*.json`` — the envelope against
  ``schemas/cve-package.schema.json``, and every advisory inside it against
  ``schemas/osv-schema.json`` (the official OSV schema, vendored from
  ``ossf/osv-schema``). Each advisory must be a valid OSV record.
* ``mappings/cve_contributions/*.json`` — each reviewer contribution against
  ``schemas/openvex-schema.json`` (the official OpenVEX 0.2.0 schema).
* ``web/public/cves.json`` — the legacy merged bundle against
  ``schemas/cves-bundle.schema.json`` plus the OSV schema per advisory.
  Skipped if absent (it is a generated artifact).
* ``web/public/cves-index.json`` and ``web/public/cve_packages/*.json`` — the
  split SPA payload used for fast startup and lazy package detail loading.
* ``web/public/mappings.json`` — manual/contribution PURL alternative lists are
  checked against the merged bundle so reviewed removals cannot be silently
  reintroduced from auto-generated suggestions.

Run standalone or via ``pixi run validate``; exits non-zero on any failure so
the ``cve-refresh`` workflow can block a bad refresh.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schemas"
DEFAULT_CVES_DIR = ROOT / "mappings" / "cves"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"
DEFAULT_BUNDLE = ROOT / "web" / "public" / "cves.json"
DEFAULT_CVES_INDEX = ROOT / "web" / "public" / "cves-index.json"
DEFAULT_CVES_DETAIL_DIR = ROOT / "web" / "public" / "cve_packages"
DEFAULT_MANUAL_MAPPINGS = ROOT / "mappings" / "manual.json"
DEFAULT_MAPPING_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_MAPPINGS_BUNDLE = ROOT / "web" / "public" / "mappings.json"
DEFAULT_QUEUE_DIR = ROOT / "mappings" / "cve_review_queue"
DEFAULT_DRAFTS_DIR = ROOT / "mappings" / "cve_ai_drafts"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _load(SCHEMA_DIR / schema_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _fmt(err) -> str:
    loc = "/".join(str(p) for p in err.absolute_path) or "(root)"
    return f"{loc}: {err.message}"


def _validate_advisories(advisories, osv, label: str, rel, errors: list[str]) -> None:
    for i, advisory in enumerate(advisories or []):
        adv_id = advisory.get("id") if isinstance(advisory, dict) else f"#{i}"
        for err in osv.iter_errors(advisory):
            errors.append(f"{rel} [{label} {adv_id}] {_fmt(err)}")


def validate_cves(cves_dir: Path, errors: list[str]) -> int:
    """Validate every per-package CVE file. Returns the file count checked."""
    envelope = _validator("cve-package.schema.json")
    osv = _validator("osv-schema.json")
    files = sorted(cves_dir.glob("*.json"))
    for path in files:
        rel = path.relative_to(ROOT)
        try:
            data = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: invalid JSON: {exc}")
            continue
        for err in envelope.iter_errors(data):
            errors.append(f"{rel} [envelope] {_fmt(err)}")
        _validate_advisories(data.get("advisories"), osv, "OSV record", rel, errors)
    return len(files)


def validate_contributions(contrib_dir: Path, errors: list[str]) -> int:
    """Validate every OpenVEX contribution document. Returns the count checked."""
    openvex = _validator("openvex-schema.json")
    files = sorted(contrib_dir.glob("*.json"))
    for path in files:
        rel = path.relative_to(ROOT)
        try:
            data = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: invalid JSON: {exc}")
            continue
        for err in openvex.iter_errors(data):
            errors.append(f"{rel} [OpenVEX] {_fmt(err)}")
    return len(files)


def _purl_list(value) -> list[str]:
    out: list[str] = []
    for item in value or []:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and isinstance(item.get("purl"), str):
            out.append(item["purl"])
    return out


def _load_mapping_contributions(directory: Path) -> list[dict]:
    if not directory.exists():
        return []
    entries: list[dict] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = _load(path)
        except json.JSONDecodeError:
            # merge_mappings skips invalid JSON too; schema validation for these
            # files can be added separately when a schema is introduced.
            continue
        data.setdefault("_filename", path.name)
        if not isinstance(data.get("timestamp"), str):
            data["timestamp"] = path.stem
        entries.append(data)
    entries.sort(key=lambda d: (d.get("timestamp") or "", d.get("_filename")))
    return entries


def validate_mapping_alternatives(
    manual_path: Path,
    contrib_dir: Path,
    mappings_path: Path,
    errors: list[str],
) -> bool:
    """Ensure reviewed alternative removals survive the mappings merge."""
    if not mappings_path.exists():
        return False
    try:
        merged = _load(mappings_path)
    except json.JSONDecodeError as exc:
        errors.append(f"{mappings_path.relative_to(ROOT)}: invalid JSON: {exc}")
        return True

    expected: dict[str, list[str]] = {}
    if manual_path.exists():
        try:
            manual = _load(manual_path)
        except json.JSONDecodeError as exc:
            errors.append(f"{manual_path.relative_to(ROOT)}: invalid JSON: {exc}")
            manual = {}
        for name, override in (manual.get("packages") or {}).items():
            if isinstance(override, dict) and "alternative_purls" in override:
                expected[name] = _purl_list(override.get("alternative_purls"))

    for contrib in _load_mapping_contributions(contrib_dir):
        for name, override in (contrib.get("packages") or {}).items():
            if isinstance(override, dict) and "alternative_purls" in override:
                expected[name] = _purl_list(override.get("alternative_purls"))

    packages = merged.get("packages") or {}
    for name, wanted in expected.items():
        got = _purl_list((packages.get(name) or {}).get("alternative_purls"))
        if got != wanted:
            errors.append(
                f"{mappings_path.relative_to(ROOT)}:{name}: alternative_purls "
                f"merged as {got!r}, expected latest reviewed list {wanted!r}"
            )
    return True


def validate_bundle(bundle_path: Path, errors: list[str]) -> bool:
    """Validate the legacy merged cves.json bundle. Returns False if it is absent."""
    if not bundle_path.exists():
        return False
    rel = (
        bundle_path.relative_to(ROOT)
        if bundle_path.is_relative_to(ROOT)
        else bundle_path
    )
    bundle_schema = _validator("cves-bundle.schema.json")
    osv = _validator("osv-schema.json")
    try:
        data = _load(bundle_path)
    except json.JSONDecodeError as exc:
        errors.append(f"{rel}: invalid JSON: {exc}")
        return True
    for err in bundle_schema.iter_errors(data):
        errors.append(f"{rel} [bundle] {_fmt(err)}")
    for name, pkg in (data.get("packages") or {}).items():
        _validate_advisories(
            pkg.get("advisories"), osv, "OSV record", f"{rel}:{name}", errors
        )
    return True


def validate_split_cves(index_path: Path, detail_dir: Path, errors: list[str]) -> bool:
    """Validate cves-index.json plus lazy per-package detail files."""
    if not index_path.exists():
        return False
    rel = index_path.relative_to(ROOT) if index_path.is_relative_to(ROOT) else index_path
    index_schema = _validator("cves-index.schema.json")
    envelope = _validator("cve-package.schema.json")
    osv = _validator("osv-schema.json")
    try:
        index = _load(index_path)
    except json.JSONDecodeError as exc:
        errors.append(f"{rel}: invalid JSON: {exc}")
        return True
    for err in index_schema.iter_errors(index):
        errors.append(f"{rel} [index] {_fmt(err)}")

    packages = index.get("packages") or {}
    seen_detail_paths: set[str] = set()
    for name, pkg_index in packages.items():
        detail_path = pkg_index.get("detail_path") if isinstance(pkg_index, dict) else None
        if not isinstance(detail_path, str):
            continue
        seen_detail_paths.add(detail_path)
        path = ROOT / "web" / "public" / detail_path
        drel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        if not path.exists():
            errors.append(f"{rel}:{name}: missing detail file {detail_path}")
            continue
        try:
            detail = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{drel}: invalid JSON: {exc}")
            continue
        if detail.get("package") != name:
            errors.append(f"{drel}: package {detail.get('package')!r}, expected {name!r}")
        for err in envelope.iter_errors(detail):
            errors.append(f"{drel} [envelope] {_fmt(err)}")
        _validate_advisories(detail.get("advisories"), osv, "OSV record", drel, errors)

    if detail_dir.exists():
        expected = {str((ROOT / "web" / "public" / p).resolve()) for p in seen_detail_paths}
        for path in detail_dir.glob("*.json"):
            if str(path.resolve()) not in expected:
                errors.append(f"{path.relative_to(ROOT)}: stale detail file not referenced by index")
    return True


def validate_review_queue(queue_dir: Path, errors: list[str]) -> int:
    """Validate every AI review queue file. Returns the count checked."""
    if not queue_dir.exists():
        return 0
    schema = _validator("cve-review-queue.schema.json")
    files = sorted(queue_dir.glob("*.json"))
    for path in files:
        rel = path.relative_to(ROOT)
        try:
            data = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: invalid JSON: {exc}")
            continue
        for err in schema.iter_errors(data):
            errors.append(f"{rel} [queue] {_fmt(err)}")
    return len(files)


def validate_ai_drafts(drafts_dir: Path, errors: list[str]) -> int:
    """Validate every AI draft file. Returns the count checked.

    Two-stage: validates the wrapper against ``cve-ai-draft.schema.json``, then
    re-validates the embedded ``openvex`` block against the OpenVEX schema so
    the draft can never carry malformed OpenVEX.
    """
    if not drafts_dir.exists():
        return 0
    wrapper = _validator("cve-ai-draft.schema.json")
    openvex = _validator("openvex-schema.json")
    files = sorted(drafts_dir.glob("*.json"))
    for path in files:
        rel = path.relative_to(ROOT)
        try:
            data = _load(path)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: invalid JSON: {exc}")
            continue
        for err in wrapper.iter_errors(data):
            errors.append(f"{rel} [draft wrapper] {_fmt(err)}")
        embedded = data.get("openvex")
        if isinstance(embedded, dict):
            for err in openvex.iter_errors(embedded):
                errors.append(f"{rel} [embedded OpenVEX] {_fmt(err)}")
    return len(files)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cves-dir", type=Path, default=DEFAULT_CVES_DIR)
    parser.add_argument("--contributions", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    parser.add_argument("--cves-index", type=Path, default=DEFAULT_CVES_INDEX)
    parser.add_argument("--cves-detail-dir", type=Path, default=DEFAULT_CVES_DETAIL_DIR)
    parser.add_argument("--mappings", type=Path, default=DEFAULT_MAPPINGS_BUNDLE)
    parser.add_argument(
        "--mapping-contributions", type=Path, default=DEFAULT_MAPPING_CONTRIB_DIR
    )
    parser.add_argument("--manual-mappings", type=Path, default=DEFAULT_MANUAL_MAPPINGS)
    parser.add_argument("--queue-dir", type=Path, default=DEFAULT_QUEUE_DIR)
    parser.add_argument("--drafts-dir", type=Path, default=DEFAULT_DRAFTS_DIR)
    args = parser.parse_args()

    errors: list[str] = []
    n_cves = validate_cves(args.cves_dir, errors)
    n_contrib = validate_contributions(args.contributions, errors)
    has_bundle = validate_bundle(args.bundle, errors)
    has_split_cves = validate_split_cves(args.cves_index, args.cves_detail_dir, errors)
    has_mappings = validate_mapping_alternatives(
        args.manual_mappings, args.mapping_contributions, args.mappings, errors
    )
    n_queue = validate_review_queue(args.queue_dir, errors)
    n_drafts = validate_ai_drafts(args.drafts_dir, errors)

    if errors:
        print(f"✗ {len(errors)} schema violation(s):", file=sys.stderr)
        for line in errors:
            print(f"  - {line}", file=sys.stderr)
        sys.exit(1)

    print(
        f"✓ {n_cves} per-package CVE file(s) valid (OSV schema + envelope), "
        f"{n_contrib} OpenVEX contribution(s) valid, "
        f"{n_queue} AI review queue file(s) valid, "
        f"{n_drafts} AI draft(s) valid, "
        f"CVE bundle {'valid' if has_bundle else 'absent (skipped)'}, "
        f"split CVE payload {'valid' if has_split_cves else 'absent (skipped)'}, "
        f"mapping removals {'valid' if has_mappings else 'absent (skipped)'}"
    )


if __name__ == "__main__":
    main()
