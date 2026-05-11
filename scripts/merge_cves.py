"""Merge per-package CVE files + reviewer contributions into the single
payload the CVE frontend consumes.

**Layering, oldest → newest (newer wins):**

1. ``mappings/cves/*.json`` — per-package auto-matcher output from
   :mod:`scripts.cve_match`.
2. ``mappings/cve_contributions/*.json`` — per-PR review files, each
   containing a ``reviews`` map keyed by ``conda_name`` then advisory id.
   Sorted by timestamp (or filename if absent) so concurrent PRs resolve
   deterministically.

Output: ``web/public/cves.json``.

A review entry can either:

- Set a status (``confirmed`` / ``rejected`` / ``not-applicable`` /
  ``needs-review``) — purely informational, doesn't change the affected
  version set.
- Provide ``version_overrides`` to flip individual conda versions in or out
  of the affected set:

      {
        "version_overrides": {
          "affected": ["1.21.5"],
          "not_affected": ["1.22.0"]
        }
      }

The merge applies ``not_affected`` first (remove) then ``affected`` (add),
so a later override that re-adds a version wins over an earlier removal.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CVES_DIR = ROOT / "mappings" / "cves"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"
DEFAULT_OUT = ROOT / "web" / "public" / "cves.json"


def _load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return default


def _load_pkg_files(directory: Path) -> dict[str, dict]:
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
        if not isinstance(data.get("timestamp"), str):
            data["timestamp"] = f.stem
        entries.append(data)
    entries.sort(key=lambda d: (d.get("timestamp") or "", d.get("_filename")))
    return entries


def _apply_version_overrides(versions: list[str], overrides: dict) -> list[str]:
    if not isinstance(overrides, dict):
        return versions
    out = list(versions)
    not_affected = overrides.get("not_affected")
    if isinstance(not_affected, list):
        out = [v for v in out if v not in set(not_affected)]
    affected = overrides.get("affected")
    if isinstance(affected, list):
        # Preserve original order where possible — append new versions at
        # the end. The frontend sorts again on display.
        existing = set(out)
        for v in affected:
            if isinstance(v, str) and v not in existing:
                out.append(v)
                existing.add(v)
    return out


def _apply_review(advisory: dict, review: dict, author: str, timestamp: str) -> None:
    """In-place: stamp a review onto an advisory entry."""
    advisory["review"] = {
        "status": review.get("status") or "confirmed",
        "note": review.get("note") or None,
        "reviewer": author,
        "reviewed_at": timestamp,
        "version_overrides": review.get("version_overrides")
        if isinstance(review.get("version_overrides"), dict)
        else None,
    }
    overrides = review.get("version_overrides")
    if isinstance(overrides, dict):
        advisory["affected_conda_versions"] = _apply_version_overrides(
            advisory.get("affected_conda_versions") or [], overrides
        )


def main(
    cves_dir: Path = DEFAULT_CVES_DIR,
    contributions: Path = DEFAULT_CONTRIB_DIR,
    out: Path = DEFAULT_OUT,
) -> None:
    packages = _load_pkg_files(cves_dir)
    contrib_files = _load_contributions(contributions)

    for contrib in contrib_files:
        author = contrib.get("author") or "unknown"
        timestamp = contrib.get("timestamp") or ""
        reviews = contrib.get("reviews") or {}
        if not isinstance(reviews, dict):
            continue
        for pkg_name, pkg_reviews in reviews.items():
            pkg = packages.get(pkg_name)
            if pkg is None or not isinstance(pkg_reviews, dict):
                continue
            for advisory in pkg.get("advisories") or []:
                # Look up by either the OSV id or any of its aliases — that
                # way reviewers can paste a CVE id and still hit the right
                # entry, regardless of which form the matcher stored.
                review = pkg_reviews.get(advisory.get("id"))
                if review is None:
                    for alias in advisory.get("aliases") or []:
                        review = pkg_reviews.get(alias)
                        if review:
                            break
                if review is None:
                    continue
                _apply_review(advisory, review, author, timestamp)

    # Summary counts: top-level stats for the dashboard header.
    pkg_count = len(packages)
    advisory_count = sum(len(p.get("advisories") or []) for p in packages.values())
    affected_version_count = sum(
        len(a.get("affected_conda_versions") or [])
        for p in packages.values()
        for a in p.get("advisories") or []
    )

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "contribution_count": len(contrib_files),
        "package_count": pkg_count,
        "advisory_count": advisory_count,
        "affected_version_count": affected_version_count,
        "packages": dict(sorted(packages.items())),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"Merged cves={pkg_count} packages + contributions={len(contrib_files)} "
        f"→ {out} ({advisory_count:,} advisories, "
        f"{affected_version_count:,} affected versions)"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cves-dir", type=Path, default=DEFAULT_CVES_DIR)
    parser.add_argument("--contributions", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    main(args.cves_dir, args.contributions, args.out)
