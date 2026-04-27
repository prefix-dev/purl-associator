"""Merge auto.json + manual.json + contributions/*.json into the single
payload the frontend consumes.

**Layering, oldest → newest (newer wins):**

1. ``mappings/auto.json`` — automap output.
2. ``mappings/manual.json`` — legacy human-curated overrides (single file).
3. ``mappings/contributions/*.json`` — per-PR contribution files, sorted by
   ``timestamp`` (or filename if absent). Each PR drops one new file with a
   unique name, so concurrent PRs never conflict on disk; the merge below
   resolves them in chronological order.

Output: ``web/public/mappings.json``.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL = ROOT / "mappings" / "manual.json"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_OUT = ROOT / "web" / "public" / "mappings.json"


def _load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return default


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


def _apply_override(merged: dict[str, dict], name: str, override: dict, attribution: dict) -> None:
    base = merged.get(name, {"name": name})
    merged[name] = {
        **base,
        **{k: v for k, v in override.items() if v is not None},
        "status": override.get("status", "verified"),
        "source": "manual",
        **attribution,
    }


def main(
    auto: Path = DEFAULT_AUTO,
    manual: Path = DEFAULT_MANUAL,
    contributions: Path = DEFAULT_CONTRIB_DIR,
    out: Path = DEFAULT_OUT,
) -> None:
    auto_data = _load_json(auto, {"packages": {}})
    manual_data = _load_json(manual, {"packages": {}})
    contrib_files = _load_contributions(contributions)

    merged: dict[str, dict] = {}

    # Layer 1: auto.
    for name, entry in auto_data.get("packages", {}).items():
        merged[name] = {**entry, "status": "auto-unverified", "source": "auto"}

    # Layer 2: manual.json (legacy single-file overrides).
    legacy_attribution = {
        "approved_by": manual_data.get("updated_by"),
        "approved_at": manual_data.get("updated_at"),
    }
    for name, override in manual_data.get("packages", {}).items():
        _apply_override(
            merged,
            name,
            override,
            {k: v for k, v in legacy_attribution.items() if v is not None},
        )
        if name in auto_data.get("packages", {}):
            a = auto_data["packages"][name]
            merged[name]["auto"] = {
                "purl": a.get("purl"),
                "type": a.get("type"),
                "namespace": a.get("namespace"),
                "pkg_name": a.get("pkg_name"),
                "confidence": a.get("confidence", 0.0),
                "sources": a.get("sources", []),
                "alternative_purls": a.get("alternative_purls"),
            }

    # Layer 3: contributions, oldest → newest.
    for contrib in contrib_files:
        attribution = {
            "approved_by": contrib.get("author"),
            "approved_at": contrib.get("timestamp"),
        }
        for name, override in (contrib.get("packages") or {}).items():
            _apply_override(merged, name, override, attribution)
            if name in auto_data.get("packages", {}):
                a = auto_data["packages"][name]
                merged[name]["auto"] = {
                    "purl": a.get("purl"),
                    "type": a.get("type"),
                    "namespace": a.get("namespace"),
                    "pkg_name": a.get("pkg_name"),
                    "confidence": a.get("confidence", 0.0),
                    "sources": a.get("sources", []),
                    "alternative_purls": a.get("alternative_purls"),
                }

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "auto_generated_at": auto_data.get("generated_at"),
        "manual_updated_at": manual_data.get("updated_at"),
        "contribution_count": len(contrib_files),
        "channel": auto_data.get("channel", "conda-forge"),
        "package_count": len(merged),
        "packages": dict(sorted(merged.items())),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"Merged auto={len(auto_data.get('packages', {}))} + "
        f"manual={len(manual_data.get('packages', {}))} + "
        f"contributions={len(contrib_files)} → {out} "
        f"({len(merged)} packages)"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--auto", type=Path, default=DEFAULT_AUTO)
    parser.add_argument("--manual", type=Path, default=DEFAULT_MANUAL)
    parser.add_argument("--contributions", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    main(args.auto, args.manual, args.contributions, args.out)
