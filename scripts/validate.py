"""Validate the generated CVE data against the published JSON Schemas.

This is the standards-compliance gate. It checks:

* ``mappings/cves/*.json`` — the envelope against
  ``schemas/cve-package.schema.json``, and every advisory inside it against
  ``schemas/osv-schema.json`` (the official OSV schema, vendored from
  ``ossf/osv-schema``). Each advisory must be a valid OSV record.
* ``mappings/cve_contributions/*.json`` — each reviewer contribution against
  ``schemas/openvex-schema.json`` (the official OpenVEX 0.2.0 schema).
* ``web/public/cves.json`` — the merged bundle against
  ``schemas/cves-bundle.schema.json`` plus the OSV schema per advisory.
  Skipped if absent (it is a generated artifact).

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


def validate_bundle(bundle_path: Path, errors: list[str]) -> bool:
    """Validate the merged cves.json bundle. Returns False if it is absent."""
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cves-dir", type=Path, default=DEFAULT_CVES_DIR)
    parser.add_argument("--contributions", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    args = parser.parse_args()

    errors: list[str] = []
    n_cves = validate_cves(args.cves_dir, errors)
    n_contrib = validate_contributions(args.contributions, errors)
    has_bundle = validate_bundle(args.bundle, errors)

    if errors:
        print(f"✗ {len(errors)} schema violation(s):", file=sys.stderr)
        for line in errors:
            print(f"  - {line}", file=sys.stderr)
        sys.exit(1)

    print(
        f"✓ {n_cves} per-package CVE file(s) valid (OSV schema + envelope), "
        f"{n_contrib} OpenVEX contribution(s) valid, "
        f"bundle {'valid' if has_bundle else 'absent (skipped)'}"
    )


if __name__ == "__main__":
    main()
