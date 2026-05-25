"""Merge per-package OSV records + OpenVEX reviewer contributions into the
single payload the CVE frontend consumes.

**Layering, oldest → newest (newer wins):**

1. ``mappings/cves/*.json`` — per-package matcher output. Each advisory is an
   OSV record with the conda-forge match under
   ``database_specific["conda-forge"]``.
2. ``mappings/cve_contributions/*.json`` — per-PR **OpenVEX** documents. Each
   statement asserts a VEX status (``affected`` / ``not_affected`` / ``fixed``
   / ``under_investigation``) about one or more conda PURLs. Documents are
   sorted by timestamp so concurrent PRs resolve deterministically.

Output: ``web/public/cves.json``.

A VEX statement is matched to an advisory by its ``vulnerability.name`` (the
OSV id, an alias, or a CVE id). Each statement's products are conda PURLs:

- A **package-level** product (``pkg:conda/<name>?channel=conda-forge``, no
  version) sets the review status/justification for that (package, advisory).
- A **version-pinned** product (``pkg:conda/<name>@<version>?…``) flips that
  single conda version: status ``affected`` adds it to the affected set, any
  other status removes it.

The resolved review is written back under
``database_specific["conda-forge"]["vex"]`` and the affected-version set is
updated in place.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from scripts.cve_common import (
    affected_versions,
    blank_version_overrides,
    conda_block,
    ensure_vex,
    parse_conda_purl,
    set_affected_versions,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CVES_DIR = ROOT / "mappings" / "cves"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"
DEFAULT_OUT = ROOT / "web" / "public" / "cves.json"

SCHEMA_VERSION = 2


def _load_pkg_files(directory: Path) -> dict[str, dict]:
    """Return ``{package_name: envelope}`` for every per-package CVE file."""
    if not directory.exists():
        return {}
    out: dict[str, dict] = {}
    for f in sorted(directory.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        name = data.get("package") or f.stem
        out[name] = data
    return out


def _load_openvex(directory: Path) -> list[dict]:
    """Load every OpenVEX contribution document, sorted oldest → newest.

    Belt-and-braces: documents flagged ``"draft": true`` are skipped. This
    directory is reserved for authoritative human OpenVEX; AI drafts live in
    ``mappings/cve_ai_drafts/`` and must be promoted explicitly. The guard
    here is defensive — it stops a misfiled draft from accidentally affecting
    the published bundle.
    """
    if not directory.exists():
        return []
    docs: list[dict] = []
    for f in sorted(directory.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except json.JSONDecodeError:
            continue
        if data.get("draft") is True:
            continue
        if not isinstance(data.get("statements"), list):
            continue
        data["_filename"] = f.name
        if not isinstance(data.get("timestamp"), str):
            data["timestamp"] = f.stem
        docs.append(data)
    docs.sort(key=lambda d: (d.get("timestamp") or "", d.get("_filename")))
    return docs


def _find_advisory(pkg: dict, vuln_name: str) -> dict | None:
    """Locate the advisory a VEX statement targets, by OSV id or alias."""
    for advisory in pkg.get("advisories") or []:
        if advisory.get("id") == vuln_name:
            return advisory
        if vuln_name in (advisory.get("aliases") or []):
            return advisory
    return None


# VEX status-qualifying fields carried verbatim from the statement onto the
# resolved review. ``justification`` qualifies a not_affected status,
# ``action_statement`` an affected one (both required by the OpenVEX schema).
_VEX_STATUS_FIELDS = (
    "justification",
    "impact_statement",
    "action_statement",
    "status_notes",
)


def _apply_statement(
    advisory: dict,
    version: str | None,
    stmt: dict,
    *,
    author: str,
    timestamp: str,
) -> None:
    """Fold one VEX statement (for one product) into the advisory's review."""
    vex = ensure_vex(advisory)
    vex["author"] = author
    vex["reviewed_at"] = timestamp
    status = stmt.get("status")
    if version is None:
        # Package-level: sets the overall review status. Newer wins, so stale
        # qualifying fields from an earlier statement are cleared first.
        vex["status"] = status
        for field in _VEX_STATUS_FIELDS:
            vex.pop(field, None)
            value = stmt.get(field)
            if value is not None:
                vex[field] = value
        return
    # Version-pinned: flip a single conda version. Last write per version wins.
    overrides = vex.setdefault("version_overrides", blank_version_overrides())
    for key in ("affected", "not_affected"):
        overrides[key] = [v for v in overrides[key] if v != version]
    bucket = "affected" if status == "affected" else "not_affected"
    overrides[bucket].append(version)


def _resolve_contributions(packages: dict[str, dict], docs: list[dict]) -> None:
    """Apply every OpenVEX statement, in chronological order, onto the
    matching advisory."""
    for doc in docs:
        author = doc.get("author") or "unknown"
        doc_ts = doc.get("timestamp") or ""
        for stmt in doc.get("statements") or []:
            if not isinstance(stmt, dict):
                continue
            vuln = stmt.get("vulnerability")
            vuln_name = vuln.get("name") if isinstance(vuln, dict) else None
            if not isinstance(vuln_name, str):
                continue
            timestamp = stmt.get("timestamp") or doc_ts
            for product in stmt.get("products") or []:
                if not isinstance(product, dict):
                    continue
                parsed = parse_conda_purl(product.get("@id") or "")
                if parsed is None:
                    continue
                pkg_name, version = parsed
                pkg = packages.get(pkg_name)
                if pkg is None:
                    continue
                advisory = _find_advisory(pkg, vuln_name)
                if advisory is None:
                    continue
                _apply_statement(
                    advisory, version, stmt, author=author, timestamp=timestamp
                )


def _apply_version_overrides(versions: list[str], overrides: dict) -> list[str]:
    """Remove ``not_affected`` versions, then append ``affected`` ones."""
    out = [v for v in versions if v not in set(overrides.get("not_affected") or [])]
    existing = set(out)
    for v in overrides.get("affected") or []:
        if isinstance(v, str) and v not in existing:
            out.append(v)
            existing.add(v)
    return out


def _finalize_affected(packages: dict[str, dict]) -> None:
    """Fold each advisory's resolved version overrides into affected_versions."""
    for pkg in packages.values():
        for advisory in pkg.get("advisories") or []:
            block = conda_block(advisory)
            vex = block.get("vex")
            if not isinstance(vex, dict):
                continue
            overrides = vex.get("version_overrides")
            if isinstance(overrides, dict) and (
                overrides.get("affected") or overrides.get("not_affected")
            ):
                set_affected_versions(
                    advisory,
                    _apply_version_overrides(affected_versions(advisory), overrides),
                )


def main(
    cves_dir: Path = DEFAULT_CVES_DIR,
    contributions: Path = DEFAULT_CONTRIB_DIR,
    out: Path = DEFAULT_OUT,
) -> None:
    packages = _load_pkg_files(cves_dir)
    docs = _load_openvex(contributions)

    _resolve_contributions(packages, docs)
    _finalize_affected(packages)

    advisory_count = sum(len(p.get("advisories") or []) for p in packages.values())
    affected_version_count = sum(
        len(conda_block(a).get("affected_versions") or [])
        for p in packages.values()
        for a in p.get("advisories") or []
    )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "contribution_count": len(docs),
        "package_count": len(packages),
        "advisory_count": advisory_count,
        "affected_version_count": affected_version_count,
        "packages": dict(sorted(packages.items())),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"Merged cves={len(packages)} packages + "
        f"contributions={len(docs)} OpenVEX doc(s) → {out} "
        f"({advisory_count:,} advisories, "
        f"{affected_version_count:,} affected versions)"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cves-dir", type=Path, default=DEFAULT_CVES_DIR)
    parser.add_argument("--contributions", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    main(args.cves_dir, args.contributions, args.out)
