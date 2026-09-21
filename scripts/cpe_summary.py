"""Produce a Markdown PR body for a CPE discovery refresh.

Used by the ``cpe_discover`` workflow to open its PR with a description of
*what actually changed this run* instead of a static "review the diff"
message. The headline answers the first question a reviewer asks — how many
CPEs will land on ``mappings.json`` after merge, and for which packages.

The promoted set is reconstructed from the same two inputs ``cpe_promote``
reads — the ``accept`` bucket of the candidates file plus the ``confident``
AI verdicts of the vet file — by calling ``cpe_promote``'s own helpers. That
keeps this summary from ever drifting from what the contribution file
actually ships.

Sections emitted:

* Headline — N packages / M CPEs promoted (or "nothing promoted, audit only").
* ✅ Promoted CPEs — the package → CPE list that will appear after merge.
* Discovery buckets — auto-accept / shared-source review / conflict /
  ambiguous / drop / no-NVD-match counts.
* 🤖 AI vet — confident / uncertain / none counts, plus the ``uncertain``
  verdicts surfaced for a human to lift manually if desired.
* A static pipeline / files / idempotency footer for first-time reviewers.

Usage:

    python -m scripts.cpe_summary \
        --candidates mappings/cpe_candidates/latest.json \
        --vet mappings/cpe_vet/_workflow.json > body.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# Reuse the promote step's bucket-collection logic verbatim so this summary
# can never claim a different promoted set than the contribution file ships.
from scripts.cpe_candidate_contract import (
    collect_accepts as _collect_accepts,
    collect_vet_confident as _collect_vet_confident,
    filter_vet_confident_for_candidates,
    merge_accepts_with_vet as _merge_accepts_with_vet,
)

# Per-bucket cap on listed examples. Promoted sets are tiny in practice
# (auto-accept has historically been 0, confident vet ~1), but cap anyway so a
# pathological run can't blow past GitHub's body limit.
PER_BUCKET = 40

STATIC_FOOTER = """\
---

## Pipeline

1. `scripts.cpe_discover` — scores NVD index lookups against H1–H8
   heuristics, buckets into accept / ambiguous / drop, and separately surfaces
   exact source/version sibling evidence for human review.
2. `scripts.cpe_vet` — Claude Haiku tiebreaker on the ambiguous
   bucket (skipped when `skip_vet=true`). Shared-source reviews are excluded.
3. `scripts.cpe_promote` — writes one contribution file unioning
   heuristic accepts + confident AI verdicts. Shared-source reviews are never
   promoted automatically.

## Files in this PR

- `mappings/contributions/*--cpe-pipeline--*.json` — shipping
  payload; the CPEs that will appear on `mappings.json` after merge.
- `mappings/cpe_candidates/latest.json` — rolling audit of every
  candidate seen, including drops, with per-heuristic scores.
- `mappings/cpe_vet/_workflow.json` — Haiku verdicts for the
  ambiguous bucket (when AI vet ran).

Review the contribution file first; the audit files exist for
reference but don't directly change behaviour. Shared-source candidates require
a separate human-reviewed mapping contribution.

Re-running discover is naturally idempotent — already-CPE'd packages
are skipped by `_load_existing_cpes` before NVD is even queried, so
this PR won't propose duplicates on subsequent runs."""


def _load(path: Path | None) -> dict:
    if path is None or not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _bullet_list(items: list[str], cap: int = PER_BUCKET) -> list[str]:
    lines = [f"- {x}" for x in items[:cap]]
    extra = len(items) - cap
    if extra > 0:
        lines.append(f"- _… and {extra} more_")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidates",
        type=Path,
        required=True,
        help="Candidates file written by cpe_discover (mappings/cpe_candidates/latest.json)",
    )
    parser.add_argument(
        "--vet",
        type=Path,
        default=None,
        help="Vet file written by cpe_vet this run; omit when the AI step was skipped",
    )
    args = parser.parse_args()

    candidates = _load(args.candidates)
    vet = _load(args.vet)

    accepts = _collect_accepts(candidates)
    raw_vet_confident = _collect_vet_confident(vet)
    vet_confident = filter_vet_confident_for_candidates(candidates, raw_vet_confident)
    held_vet_confident = len(raw_vet_confident) - len(vet_confident)
    promoted = _merge_accepts_with_vet(accepts, vet_confident)

    pkg_count = len(promoted)
    cpe_count = sum(len(v) for v in promoted.values())

    out: list[str] = []
    out.append(
        "Automated discovery + AI vet of CPE coordinates for top-downloaded "
        "conda-forge packages that lack OSV-mappable PURLs."
    )
    out.append("")

    # ---- headline: the net effect after merge ----
    if pkg_count:
        out.append(
            f"**{pkg_count} package{'s' if pkg_count != 1 else ''} / "
            f"{cpe_count} CPE{'s' if cpe_count != 1 else ''}** will be added to "
            "`mappings.json` after merge."
        )
    else:
        out.append(
            "**No new CPEs promoted this run** — only audit files "
            "(`cpe_candidates` / `cpe_vet`) changed."
        )
    out.append("")

    # ---- promoted CPEs ----
    if promoted:
        out.append(f"### ✅ Promoted CPEs ({pkg_count})")
        out.append("")
        rendered = [
            f"**{name}** → {', '.join(f'`{c}`' for c in cpes)}"
            for name, cpes in sorted(promoted.items())
        ]
        out.extend(_bullet_list(rendered))
        out.append("")

    # ---- discovery buckets ----
    hs = candidates.get("heuristics_summary") or {}
    if candidates:
        top_considered = candidates.get("top_considered", "?")
        scope = "all packages" if top_considered == 0 else f"top {top_considered}"
        out.append(
            f"### Discovery ({scope}, "
            f"{candidates.get('candidates_processed', '?')} candidates processed)"
        )
        out.append("")
        out.append("| bucket | count |")
        out.append("|---|---:|")
        out.append(f"| ✅ auto-accept | {hs.get('auto_accept_total', 0)} |")
        review_groups = hs.get("shared_source_review_groups", 0)
        review_packages = hs.get("shared_source_review_packages", 0)
        review_cpes = hs.get("shared_source_review_cpes", 0)
        review_downloads = hs.get("shared_source_review_downloads", 0)
        out.append(
            f"| 👤 shared-source review required | {review_groups} "
            f"group{'s' if review_groups != 1 else ''} / {review_packages} "
            f"package{'s' if review_packages != 1 else ''} / {review_cpes} "
            f"CPE{'s' if review_cpes != 1 else ''} / "
            f"{review_downloads:,} downloads |"
        )
        conflict_groups = hs.get("shared_source_conflict_groups", 0)
        conflict_packages = hs.get("shared_source_conflict_packages", 0)
        conflict_downloads = hs.get("shared_source_conflict_downloads", 0)
        out.append(
            f"| ⚠️ shared-source conflicts | {conflict_groups} "
            f"group{'s' if conflict_groups != 1 else ''} / {conflict_packages} "
            f"package{'s' if conflict_packages != 1 else ''} / "
            f"{conflict_downloads:,} downloads |"
        )
        out.append(f"| ❓ ambiguous (→ AI vet) | {hs.get('ambiguous_total', 0)} |")
        out.append(f"| 🗑 drop | {hs.get('drop_total', 0)} |")
        out.append(f"| — no NVD match | {hs.get('no_nvd_match', 0)} |")
        out.append("")

        review_rows = [
            pkg
            for pkg in (candidates.get("packages") or [])
            if pkg.get("shared_source_review")
        ]
        if review_rows:
            out.append(
                f"<details><summary>{len(review_rows)} shared-source candidate"
                f"{'s' if len(review_rows) != 1 else ''} — human review required, "
                "not shipped</summary>"
            )
            out.append("")
            for pkg in review_rows[:PER_BUCKET]:
                for evidence in pkg.get("shared_source_review") or []:
                    cpes = (
                        ", ".join(f"`{cpe}`" for cpe in (evidence.get("cpes") or []))
                        or "—"
                    )
                    anchors = (
                        ", ".join(
                            f"`{anchor.get('package', '?')}`"
                            for anchor in (evidence.get("anchors") or [])
                        )
                        or "—"
                    )
                    out.append(f"- **{pkg.get('conda_name', '?')}** → {cpes}")
                    out.append(
                        f"  - anchors: {anchors}; exact source/version: "
                        f"`{evidence.get('shared_version', '?')}`"
                    )
            extra = len(review_rows) - PER_BUCKET
            if extra > 0:
                out.append(f"- _… and {extra} more_")
            out.append("")
            out.append("</details>")
            out.append("")

        conflict_rows = [
            pkg
            for pkg in (candidates.get("packages") or [])
            if pkg.get("shared_source_conflict")
        ]
        if conflict_rows:
            out.append(
                f"<details><summary>{len(conflict_rows)} shared-source conflict"
                f"{'s' if len(conflict_rows) != 1 else ''} — no CPE proposed"
                "</summary>"
            )
            out.append("")
            for pkg in conflict_rows[:PER_BUCKET]:
                conflict = pkg["shared_source_conflict"]
                anchors = "; ".join(
                    f"`{anchor.get('package', '?')}` → "
                    + ", ".join(f"`{cpe}`" for cpe in anchor.get("cpes") or [])
                    for anchor in (conflict.get("anchors") or [])
                )
                out.append(f"- **{pkg.get('conda_name', '?')}**: {anchors}")
            extra = len(conflict_rows) - PER_BUCKET
            if extra > 0:
                out.append(f"- _… and {extra} more_")
            out.append("")
            out.append("</details>")
            out.append("")

    # ---- AI vet ----
    if vet:
        vs = vet.get("summary") or {}
        model = vet.get("model", "Claude Haiku")
        out.append(f"### 🤖 AI vet ({model})")
        out.append("")
        out.append("| verdict | packages |")
        out.append("|---|---:|")
        out.append(f"| confident (shipped) | {len(vet_confident)} |")
        if held_vet_confident:
            out.append(
                f"| confident but shared-source-held (not shipped) | "
                f"{held_vet_confident} |"
            )
        out.append(f"| uncertain (held) | {vs.get('uncertain_packages', 0)} |")
        out.append(f"| none (rejected) | {vs.get('none_packages', 0)} |")
        out.append("")

        # Surface uncertain verdicts: cpe_promote drops these, but a human
        # reviewer may want to lift one manually, so list them with reasoning.
        uncertain = [
            v for v in (vet.get("verdicts") or []) if v.get("verdict") == "uncertain"
        ]
        if uncertain:
            out.append(
                f"<details><summary>{len(uncertain)} uncertain verdict"
                f"{'s' if len(uncertain) != 1 else ''} — not shipped, lift "
                "manually if warranted</summary>"
            )
            out.append("")
            for v in uncertain[:PER_BUCKET]:
                name = v.get("conda_name", "?")
                cpes = (
                    ", ".join(f"`{c}`" for c in (v.get("selected_cpes") or [])) or "—"
                )
                reason = (v.get("reasoning") or "").strip()
                out.append(f"- **{name}** → {cpes}")
                if reason:
                    out.append(f"  - {reason}")
            extra = len(uncertain) - PER_BUCKET
            if extra > 0:
                out.append(f"- _… and {extra} more_")
            out.append("")
            out.append("</details>")
            out.append("")

    out.append(STATIC_FOOTER)

    print("\n".join(out))


if __name__ == "__main__":
    main()
