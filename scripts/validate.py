"""Validate the generated CVE data against the published JSON Schemas.

This is the standards-compliance gate. It checks:

* ``mappings/cves/*.json`` — the envelope against
  ``schemas/cve-package.schema.json``, and every advisory inside it against
  ``schemas/osv-schema.json`` (the official OSV schema, vendored from
  ``ossf/osv-schema``). Each advisory must be a valid OSV record.

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


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def _validator(schema_name: str) -> Draft202012Validator:
    schema = _load(SCHEMA_DIR / schema_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _fmt(err) -> str:
    loc = "/".join(str(p) for p in err.absolute_path) or "(root)"
    return f"{loc}: {err.message}"


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
        for i, advisory in enumerate(data.get("advisories") or []):
            adv_id = advisory.get("id") if isinstance(advisory, dict) else f"#{i}"
            for err in osv.iter_errors(advisory):
                errors.append(f"{rel} [OSV record {adv_id}] {_fmt(err)}")
    return len(files)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cves-dir", type=Path, default=DEFAULT_CVES_DIR)
    args = parser.parse_args()

    errors: list[str] = []
    n_cves = validate_cves(args.cves_dir, errors)

    if errors:
        print(f"✗ {len(errors)} schema violation(s):", file=sys.stderr)
        for line in errors:
            print(f"  - {line}", file=sys.stderr)
        sys.exit(1)
    print(f"✓ {n_cves} per-package CVE file(s) valid (OSV schema + envelope)")


if __name__ == "__main__":
    main()
