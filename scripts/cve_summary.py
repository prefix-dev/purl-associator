"""Produce a Markdown summary of a ``mappings/cves/`` diff.

Used by the ``cve-refresh`` workflow to write a descriptive PR body.
Compares two snapshots of the per-package CVE files and surfaces:

* Packages that gained / lost a CVE file.
* Per-package advisory churn: new advisories, dropped advisories, and
  advisories whose affected-conda-version set changed.

Severity, OSV link, and CVE aliases are pulled into each line so a reviewer
can scan without opening the diff. Long lists collapse to a count tail.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path

PER_BUCKET = 30
ADVISORIES_PER_PKG = 15


def _load_dir(path: Path) -> dict[str, dict]:
    """Return ``{package_name: payload}`` for every ``*.json`` in *path*.
    Missing dir → empty dict (so the very first run, with no baseline,
    treats everything as new)."""
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    for f in sorted(path.glob("*.json")):
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        name = data.get("package") or f.stem
        out[name] = data
    return out


def _advisories_by_id(pkg: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for adv in pkg.get("advisories") or []:
        adv_id = adv.get("id")
        if isinstance(adv_id, str):
            out[adv_id] = adv
    return out


def _severity_str(adv: dict) -> str:
    sev = adv.get("severity")
    if not isinstance(sev, dict):
        return ""
    score = sev.get("score")
    if not isinstance(score, str):
        return ""
    import re

    m = re.search(r"(\d+\.\d+)", score)
    if not m:
        return ""
    v = float(m.group(1))
    if v >= 9.0:
        band = "critical"
    elif v >= 7.0:
        band = "high"
    elif v >= 4.0:
        band = "medium"
    elif v > 0:
        band = "low"
    else:
        return ""
    return f"{v:.1f} {band}"


def _label(adv: dict) -> str:
    primary = adv.get("primary_id") or adv.get("id") or "?"
    cve_ids = adv.get("cve_ids") or []
    sev = _severity_str(adv)
    bits = [f"**{primary}**"]
    osv = adv.get("osv_url")
    if isinstance(osv, str):
        bits[0] = f"**[{primary}]({osv})**"
    if cve_ids and primary not in cve_ids:
        bits.append(f"({', '.join(cve_ids)})")
    if sev:
        bits.append(f"· {sev}")
    return " ".join(bits)


def _format_versions(versions: list[str], cap: int = 8) -> str:
    if not versions:
        return "_(no conda versions)_"
    if len(versions) <= cap:
        return ", ".join(f"`{v}`" for v in versions)
    head = ", ".join(f"`{v}`" for v in versions[:cap])
    return f"{head} _… +{len(versions) - cap} more_"


def _bullet_list(items: list[str], cap: int = PER_BUCKET) -> list[str]:
    lines = [f"- {x}" for x in items[:cap]]
    extra = len(items) - cap
    if extra > 0:
        lines.append(f"- _… and {extra} more_")
    return lines


def _advisory_lines(
    advisories: Iterable[dict], cap: int = ADVISORIES_PER_PKG
) -> list[str]:
    items = list(advisories)
    rendered = [f"  - {_label(a)}" for a in items[:cap]]
    extra = len(items) - cap
    if extra > 0:
        rendered.append(f"  - _… and {extra} more_")
    return rendered


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before-dir", type=Path, required=True)
    parser.add_argument("--after-dir", type=Path, required=True)
    parser.add_argument("--workflow-name", default="cve-refresh")
    args = parser.parse_args()

    before = _load_dir(args.before_dir)
    after = _load_dir(args.after_dir)

    new_pkgs = sorted(set(after) - set(before))
    dropped_pkgs = sorted(set(before) - set(after))
    common = sorted(set(after) & set(before))

    per_pkg_diff: list[
        tuple[str, list[dict], list[dict], list[tuple[dict, int, int]]]
    ] = []
    new_adv_total = 0
    dropped_adv_total = 0
    changed_adv_total = 0

    for pkg_name in common:
        b_adv = _advisories_by_id(before[pkg_name])
        a_adv = _advisories_by_id(after[pkg_name])
        added = [a_adv[i] for i in sorted(set(a_adv) - set(b_adv))]
        dropped = [b_adv[i] for i in sorted(set(b_adv) - set(a_adv))]
        changed: list[tuple[dict, int, int]] = []
        for adv_id in sorted(set(a_adv) & set(b_adv)):
            b_versions = b_adv[adv_id].get("affected_conda_versions") or []
            a_versions = a_adv[adv_id].get("affected_conda_versions") or []
            if set(b_versions) != set(a_versions):
                changed.append((a_adv[adv_id], len(b_versions), len(a_versions)))
        if added or dropped or changed:
            per_pkg_diff.append((pkg_name, added, dropped, changed))
        new_adv_total += len(added)
        dropped_adv_total += len(dropped)
        changed_adv_total += len(changed)

    total_advisory_count = sum(len(p.get("advisories") or []) for p in after.values())
    affected_version_count = sum(
        len(a.get("affected_conda_versions") or [])
        for p in after.values()
        for a in p.get("advisories") or []
    )

    new_pkgs_adv = sum(len(after[n].get("advisories") or []) for n in new_pkgs)

    total_changes = (
        len(new_pkgs)
        + len(dropped_pkgs)
        + new_adv_total
        + dropped_adv_total
        + changed_adv_total
    )

    out: list[str] = []
    if total_changes == 0:
        out.append("No CVE-mapping changes detected.")
        print("\n".join(out))
        return

    out.append(
        f"Automated refresh of `mappings/cves/` from the latest OSV advisories. "
        f"**{total_changes:,}** change{'s' if total_changes != 1 else ''} this run."
    )
    out.append("")
    out.append(
        f"After this run: **{len(after):,}** packages affected · "
        f"**{total_advisory_count:,}** advisories · "
        f"**{affected_version_count:,}** affected-conda-version entries."
    )
    out.append("")
    out.append("| bucket | count |")
    out.append("|---|---:|")
    out.append(f"| 🆕 new packages with advisories | {len(new_pkgs):,} |")
    out.append(f"| 🚮 packages no longer affected | {len(dropped_pkgs):,} |")
    out.append(f"| ➕ new advisories on existing packages | {new_adv_total:,} |")
    out.append(
        f"| ➖ advisories dropped from existing packages | {dropped_adv_total:,} |"
    )
    out.append(
        f"| 🔄 advisories with changed conda-version set | {changed_adv_total:,} |"
    )
    out.append("")

    if new_pkgs:
        out.append(
            f"### 🆕 New packages with advisories ({len(new_pkgs):,}, "
            f"{new_pkgs_adv:,} advisories total)"
        )
        out.append("")
        items: list[str] = []
        for n in new_pkgs:
            pkg = after[n]
            advs = pkg.get("advisories") or []
            purl = (pkg.get("purls") or ["?"])[0]
            items.append(
                f"**{n}** (`{purl}`) — {len(advs)} advisor{'y' if len(advs) == 1 else 'ies'}"
            )
        out.extend(_bullet_list(items))
        out.append("")

    if dropped_pkgs:
        out.append(f"### 🚮 Packages no longer affected ({len(dropped_pkgs):,})")
        out.append("")
        out.extend(_bullet_list(dropped_pkgs))
        out.append("")

    if per_pkg_diff:
        out.append(
            f"### 🔄 Advisory changes on existing packages "
            f"({len(per_pkg_diff):,} package{'s' if len(per_pkg_diff) != 1 else ''})"
        )
        out.append("")
        # Sort packages by total churn so the noisiest end up first.
        per_pkg_diff.sort(key=lambda x: -(len(x[1]) + len(x[2]) + len(x[3])))
        for pkg_name, added, dropped, changed in per_pkg_diff[:PER_BUCKET]:
            out.append(f"**{pkg_name}**")
            if added:
                out.append(f"- ➕ new ({len(added)}):")
                out.extend(_advisory_lines(added))
            if dropped:
                out.append(f"- ➖ removed ({len(dropped)}):")
                out.extend(_advisory_lines(dropped))
            if changed:
                out.append(f"- 🔄 affected-version set changed ({len(changed)}):")
                rendered: list[str] = []
                for adv, b_count, a_count in changed:
                    new_versions = adv.get("affected_conda_versions") or []
                    delta = a_count - b_count
                    sign = "+" if delta >= 0 else ""
                    rendered.append(
                        f"  - {_label(adv)} · {b_count} → {a_count} versions "
                        f"({sign}{delta}): {_format_versions(new_versions)}"
                    )
                tail = ADVISORIES_PER_PKG - len(rendered)
                if tail < 0:
                    out.extend(rendered[:ADVISORIES_PER_PKG])
                    out.append(f"  - _… and {-tail} more_")
                else:
                    out.extend(rendered)
            out.append("")
        extra = len(per_pkg_diff) - PER_BUCKET
        if extra > 0:
            out.append(f"_… and {extra} more packages with advisory changes_")
            out.append("")

    out.append("---")
    out.append(
        f"This PR is opened by the scheduled `{args.workflow_name}` workflow. "
        "Review for new advisories and unexpected version-set changes, then merge."
    )

    print("\n".join(out))


if __name__ == "__main__":
    main()
