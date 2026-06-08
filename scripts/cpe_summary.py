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
* Discovery buckets — auto-accept / ambiguous / drop / no-NVD-match counts.
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
from scripts.cpe_promote import (
    _collect_accepts,
    _collect_vet_confident,
    _merge_accepts_with_vet,
)

# Per-bucket cap on listed examples. Promoted sets are tiny in practice
# (auto-accept has historically been 0, confident vet ~1), but cap anyway so a
# pathological run can't blow past GitHub's body limit.
PER_BUCKET = 40

STATIC_FOOTER = """\
---

## Pipeline

1. `scripts.cpe_discover` — scores NVD index lookups against H1–H8
   heuristics, buckets into accept / ambiguous / drop.
2. `scripts.cpe_vet` — Claude Haiku tiebreaker on the ambiguous
   bucket (skipped when `skip_vet=true`).
3. `scripts.cpe_promote` — writes one contribution file unioning
   heuristic accepts + confident AI verdicts.

## Files in this PR

- `mappings/contributions/*--cpe-pipeline--*.json` — shipping
  payload; the CPEs that will appear on `mappings.json` after merge.
- `mappings/cpe_candidates/latest.json` — rolling audit of every
  candidate seen, including drops, with per-heuristic scores.
- `mappings/cpe_vet/_workflow.json` — Haiku verdicts for the
  ambiguous bucket (when AI vet ran).

Review the contribution file first; the audit files exist for
reference but don't directly change behaviour.

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
    vet_confident = _collect_vet_confident(vet)
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
        out.append(
            f"### Discovery (top {candidates.get('top_considered', '?')}, "
            f"{candidates.get('candidates_processed', '?')} with an NVD match)"
        )
        out.append("")
        out.append("| bucket | CPEs |")
        out.append("|---|---:|")
        out.append(f"| ✅ auto-accept | {hs.get('auto_accept_total', 0)} |")
        out.append(f"| ❓ ambiguous (→ AI vet) | {hs.get('ambiguous_total', 0)} |")
        out.append(f"| 🗑 drop | {hs.get('drop_total', 0)} |")
        out.append(f"| — no NVD match | {hs.get('no_nvd_match', 0)} |")
        out.append("")

    # ---- AI vet ----
    if vet:
        vs = vet.get("summary") or {}
        model = vet.get("model", "Claude Haiku")
        out.append(f"### 🤖 AI vet ({model})")
        out.append("")
        out.append("| verdict | packages |")
        out.append("|---|---:|")
        out.append(f"| confident (shipped) | {vs.get('confident_packages', 0)} |")
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
