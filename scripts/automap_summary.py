"""Produce a Markdown summary of an ``auto.json`` diff.

Used by the ``automap`` workflow to generate a descriptive PR body instead
of a static "review the diff" message. The diff against HEAD is captured in
the workflow before the matcher mutates the file; we read it here and emit
top-of-list highlights in each of these buckets:

* New packages (newly mapped this run)
* Removed packages (no longer in the channel — or no longer mapped)
* Changed primary PURL
* Changed alternative-PURL set
* Bumped version (PURL unchanged, just rebuilt)

For tail entries past the per-bucket cap we collapse to a count line, so a
PR opened against a 25k-package refresh stays under GitHub's body limit.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

# Per-bucket cap. Big enough to be useful in normal nightly runs (~tens of
# packages change), small enough that a worst-case full re-derive PR still
# renders.
PER_BUCKET = 25
SAMPLE_CAP = 10  # how many examples to list per ecosystem in the breakdown


def _load(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text()).get("packages") or {}
    except (json.JSONDecodeError, OSError):
        return {}


def _purl_set(entry: dict) -> tuple[str | None, frozenset[str]]:
    """Return (primary_purl, alternates_as_frozenset). ``None`` primary
    means the entry is unmapped — alternates are still surfaced separately."""
    primary = entry.get("purl") if isinstance(entry.get("purl"), str) else None
    alts = frozenset(
        a["purl"]
        for a in (entry.get("alternative_purls") or [])
        if isinstance(a, dict) and isinstance(a.get("purl"), str)
    )
    return primary, alts


def _code(s: str | None) -> str:
    if s is None:
        return "_unmapped_"
    return f"`{s}`"


def _bullet_list(items: list[str], cap: int = PER_BUCKET) -> list[str]:
    lines = [f"- {x}" for x in items[:cap]]
    extra = len(items) - cap
    if extra > 0:
        lines.append(f"- _… and {extra} more_")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--after", type=Path, required=True)
    parser.add_argument(
        "--workflow-name", default="automap", help="Workflow name for the footer"
    )
    args = parser.parse_args()

    before = _load(args.before)
    after = _load(args.after)

    before_keys = set(before)
    after_keys = set(after)

    new_pkgs = sorted(after_keys - before_keys)
    removed_pkgs = sorted(before_keys - after_keys)

    changed_primary: list[tuple[str, str | None, str | None]] = []
    changed_alts: list[tuple[str, list[str], list[str]]] = []
    bumped_version: list[tuple[str, str, str]] = []

    for name in sorted(after_keys & before_keys):
        b = before[name]
        a = after[name]
        b_primary, b_alts = _purl_set(b)
        a_primary, a_alts = _purl_set(a)

        if b_primary != a_primary:
            changed_primary.append((name, b_primary, a_primary))
        elif b_alts != a_alts:
            removed = sorted(b_alts - a_alts)
            added = sorted(a_alts - b_alts)
            changed_alts.append((name, removed, added))
        elif b.get("version") != a.get("version"):
            bumped_version.append(
                (name, str(b.get("version") or "?"), str(a.get("version") or "?"))
            )

    # Ecosystem breakdown for the new packages — gives a sense of "where the
    # churn is" at a glance.
    eco_new: Counter[str] = Counter()
    for name in new_pkgs:
        eco_new[after[name].get("type") or "unmapped"] += 1

    total_changes = (
        len(new_pkgs)
        + len(removed_pkgs)
        + len(changed_primary)
        + len(changed_alts)
        + len(bumped_version)
    )

    # ---- emit ----
    out: list[str] = []
    if total_changes == 0:
        out.append("No mapping changes detected.")
        print("\n".join(out))
        return

    out.append(
        f"Automated refresh of `mappings/auto.json` from the latest conda-forge "
        f"package metadata. **{total_changes:,}** mapping change"
        f"{'s' if total_changes != 1 else ''} this run."
    )
    out.append("")
    out.append("| bucket | count |")
    out.append("|---|---:|")
    out.append(f"| 🆕 new packages | {len(new_pkgs):,} |")
    out.append(f"| 🗑 removed packages | {len(removed_pkgs):,} |")
    out.append(f"| 🔀 changed primary PURL | {len(changed_primary):,} |")
    out.append(f"| ✎ changed alternates | {len(changed_alts):,} |")
    out.append(f"| ⬆ version bump (PURL unchanged) | {len(bumped_version):,} |")
    out.append("")

    if eco_new:
        breakdown = ", ".join(f"`{eco}` {n}" for eco, n in eco_new.most_common())
        out.append(f"**New-package ecosystems:** {breakdown}")
        out.append("")

    if new_pkgs:
        out.append(f"### 🆕 New packages ({len(new_pkgs):,})")
        out.append("")
        out.extend(
            _bullet_list(
                [
                    f"**{n}** v{after[n].get('version', '?')} → {_code(after[n].get('purl'))}"
                    for n in new_pkgs
                ]
            )
        )
        out.append("")

    if removed_pkgs:
        out.append(f"### 🗑 Removed packages ({len(removed_pkgs):,})")
        out.append("")
        out.extend(
            _bullet_list(
                [f"**{n}** (was {_code(before[n].get('purl'))})" for n in removed_pkgs]
            )
        )
        out.append("")

    if changed_primary:
        out.append(f"### 🔀 Changed primary PURL ({len(changed_primary):,})")
        out.append("")
        out.extend(
            _bullet_list(
                [f"**{n}**: {_code(b)} → {_code(a)}" for n, b, a in changed_primary]
            )
        )
        out.append("")

    if changed_alts:
        out.append(f"### ✎ Changed alternates ({len(changed_alts):,})")
        out.append("")
        rendered: list[str] = []
        for n, removed, added in changed_alts:
            parts = []
            if removed:
                parts.append("−" + ", ".join(_code(p) for p in removed))
            if added:
                parts.append("+" + ", ".join(_code(p) for p in added))
            rendered.append(f"**{n}**: {' '.join(parts)}")
        out.extend(_bullet_list(rendered))
        out.append("")

    if bumped_version:
        out.append(f"### ⬆ Version bump only ({len(bumped_version):,})")
        out.append("")
        rendered = [f"**{n}**: v{old} → v{new}" for n, old, new in bumped_version]
        # Version bumps are typically the largest bucket — cap tighter.
        out.extend(_bullet_list(rendered, cap=SAMPLE_CAP))
        out.append("")

    out.append("---")
    out.append(
        f"This PR is opened by the scheduled `{args.workflow_name}` workflow. "
        "Review the diff for unexpected churn and merge to publish the new mappings."
    )

    print("\n".join(out))


if __name__ == "__main__":
    main()
