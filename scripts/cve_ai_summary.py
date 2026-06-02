"""Produce a Markdown PR body for the AI CVE review workflow.

Walks ``mappings/cve_ai_drafts/`` (or a subset given by ``--since-ref``) and
emits a maintainer-friendly summary:

* Headline totals (drafts, packages, agree vs disagree splits).
* Compact table — one row per assessment.
* Collapsible ``<details>`` blocks per package with the four-dimension
  reasoning verbatim so reviewers can scan without opening files.

Output goes to stdout by default; pass ``--out PATH`` to write to a file for
``gh pr create --body-file``.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DRAFTS_DIR = ROOT / "mappings" / "cve_ai_drafts"


def _git(*args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=False
    )
    return proc.stdout


def _files_since(ref: str, drafts_dir: Path) -> list[Path]:
    """Files under drafts_dir that differ from ref (added/modified)."""
    rel = drafts_dir.relative_to(ROOT)
    out = _git("diff", "--name-only", ref, "--", str(rel))
    files: list[Path] = []
    for line in out.splitlines():
        p = ROOT / line.strip()
        if p.exists() and p.suffix == ".json":
            files.append(p)
    return sorted(files)


def _all_files(drafts_dir: Path) -> list[Path]:
    if not drafts_dir.exists():
        return []
    return sorted(drafts_dir.glob("*.json"))


def _load_drafts(paths: Iterable[Path]) -> list[dict]:
    out: list[dict] = []
    for p in paths:
        try:
            data = json.loads(p.read_text())
        except json.JSONDecodeError:
            continue
        if data.get("draft") is not True:
            continue
        data["_path"] = str(p.relative_to(ROOT))
        out.append(data)
    return out


def _flatten_assessments(drafts: list[dict]) -> list[dict]:
    """Each row: package, advisory_id, status, agrees, severity_assessment, run_id, path."""
    rows: list[dict] = []
    for d in drafts:
        rid = d.get("run_id") or "?"
        path = d.get("_path") or "?"
        model = d.get("model") or "?"
        for a in (d.get("assessments") or {}).values():
            if not isinstance(a, dict):
                continue
            af = a.get("affected_versions") or {}
            rt = a.get("runtime_applicability") or {}
            sev = a.get("severity_in_conda_context") or {}
            rows.append(
                {
                    "package": a.get("package") or "?",
                    "advisory_id": a.get("advisory_id") or "?",
                    "openvex_status": a.get("openvex_status") or "?",
                    "agrees": af.get("agrees_with_match"),
                    "runtime_applies": rt.get("applies") or "?",
                    "severity_in_conda": sev.get("assessment") or "?",
                    "run_id": rid,
                    "path": path,
                    "model": model,
                    "rationale": a.get("rationale") or "",
                    "notes": a.get("notes") or "",
                    "_a": a,
                }
            )
    rows.sort(key=lambda r: (r["package"], r["advisory_id"]))
    return rows


def _agrees_emoji(v: bool | None) -> str:
    if v is True:
        return "✅"
    if v is False:
        return "⚠️"
    return "❓"


def _status_chip(s: str) -> str:
    return {
        "affected": "🔴 affected",
        "not_affected": "🟢 not_affected",
        "fixed": "🟢 fixed",
        "under_investigation": "🟡 under_investigation",
    }.get(s, f"❔ {s}")


def _emit_header(rows: list[dict], drafts: list[dict]) -> list[str]:
    n_drafts = len(rows)
    pkgs = sorted({r["package"] for r in rows})
    agree = sum(1 for r in rows if r["agrees"] is True)
    disagree = sum(1 for r in rows if r["agrees"] is False)
    unknown = sum(1 for r in rows if r["agrees"] is None)
    statuses: dict[str, int] = {}
    for r in rows:
        statuses[r["openvex_status"]] = statuses.get(r["openvex_status"], 0) + 1
    # If multiple runs landed on the branch with different models, surface
    # all of them — otherwise the header silently quoted whichever happened
    # to be first by sort order.
    models = sorted({d.get("model") or "?" for d in drafts})
    model_str = ", ".join(f"`{m}`" for m in models) if models else "`?`"
    lines = [
        "# AI CVE review drafts",
        "",
        f"**{n_drafts}** draft assessment(s) across **{len(pkgs)}** package(s) "
        f"(model: {model_str}).",
        "",
        f"- ✅ agrees with auto match: **{agree}**",
        f"- ⚠️ disagrees: **{disagree}**",
        f"- ❓ unknown: **{unknown}**",
        "",
        "Status mix: "
        + ", ".join(f"{_status_chip(s)} × {n}" for s, n in sorted(statuses.items())),
        "",
        "> 🤖 These are **drafts**, not authoritative. Promote into "
        "`mappings/cve_contributions/` via the SPA or `pixi run promote-ai-draft` "
        "after review.",
        "",
    ]
    return lines


def _emit_table(rows: list[dict]) -> list[str]:
    lines = [
        "## Summary",
        "",
        "| package | advisory | status | agrees | runtime | severity-in-conda | run |",
        "| --- | --- | --- | :-: | --- | --- | --- |",
    ]
    for r in rows:
        lines.append(
            f"| `{r['package']}` "
            f"| `{r['advisory_id']}` "
            f"| {_status_chip(r['openvex_status'])} "
            f"| {_agrees_emoji(r['agrees'])} "
            f"| {r['runtime_applies']} "
            f"| {r['severity_in_conda']} "
            f"| `{r['run_id']}` |"
        )
    lines.append("")
    return lines


def _emit_details(rows: list[dict]) -> list[str]:
    lines = ["## Per-draft reasoning", ""]
    by_pkg: dict[str, list[dict]] = {}
    for r in rows:
        by_pkg.setdefault(r["package"], []).append(r)
    for pkg, items in sorted(by_pkg.items()):
        lines.append(
            f"<details><summary><code>{pkg}</code> — {len(items)} draft(s)</summary>"
        )
        lines.append("")
        for r in items:
            a = r["_a"]
            af = a.get("affected_versions") or {}
            rt = a.get("runtime_applicability") or {}
            sev = a.get("severity_in_conda_context") or {}
            adds = af.get("suggested_adds") or []
            removes = af.get("suggested_removes") or []
            lines.append(
                f"### `{r['advisory_id']}` — {_status_chip(r['openvex_status'])}"
            )
            lines.append("")
            if r.get("rationale"):
                lines.append("**Why the AI accepts this**")
                lines.append("")
                lines.append("> " + r["rationale"].replace("\n", "\n> "))
                lines.append("")
            lines.append("**affected_versions**")
            lines.append(
                f"- agrees with auto match: {_agrees_emoji(af.get('agrees_with_match'))}"
            )
            if adds:
                lines.append(f"- suggested adds: {', '.join(f'`{v}`' for v in adds)}")
            if removes:
                lines.append(
                    f"- suggested removes: {', '.join(f'`{v}`' for v in removes)}"
                )
            lines.append(f"- reasoning: {af.get('reasoning') or '(none)'}")
            lines.append("")
            lines.append(
                f"**runtime_applicability**: `{rt.get('applies') or '?'}` — "
                f"{rt.get('reasoning') or '(none)'}"
            )
            lines.append("")
            lines.append(
                f"**severity_in_conda_context**: `{sev.get('assessment') or '?'}` — "
                f"{sev.get('reasoning') or '(none)'}"
            )
            lines.append("")
            if r["notes"]:
                lines.append(f"**notes**: {r['notes']}")
                lines.append("")
            if a.get("openvex_justification"):
                lines.append(
                    f"- proposed justification: `{a['openvex_justification']}`"
                )
            if a.get("openvex_action_statement"):
                lines.append(
                    f"- proposed action_statement: {a['openvex_action_statement']}"
                )
            if a.get("openvex_impact_statement"):
                lines.append(
                    f"- proposed impact_statement: {a['openvex_impact_statement']}"
                )
            lines.append(f"- run file: `{r['path']}`")
            lines.append("")
        lines.append("</details>")
        lines.append("")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drafts-dir", type=Path, default=DEFAULT_DRAFTS_DIR)
    parser.add_argument(
        "--since-ref",
        default="",
        help="Only summarise drafts changed vs this git ref (e.g. origin/main).",
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="Write to this path (default: stdout)"
    )
    args = parser.parse_args()

    if args.since_ref:
        paths = _files_since(args.since_ref, args.drafts_dir)
    else:
        paths = _all_files(args.drafts_dir)
    drafts = _load_drafts(paths)
    rows = _flatten_assessments(drafts)

    if not rows:
        body = (
            "# AI CVE review drafts\n\n"
            "(no new drafts in this run — nothing to summarise)\n"
        )
    else:
        body = "\n".join(
            _emit_header(rows, drafts) + _emit_table(rows) + _emit_details(rows)
        )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(body)
    else:
        print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
