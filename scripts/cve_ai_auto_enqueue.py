"""Auto-enqueue high-severity advisories for AI CVE review.

Walks ``mappings/cves/<pkg>.json`` (output of :mod:`scripts.cve_match`) and
emits one ``mappings/cve_review_queue/<ts>--<runid>.json`` file containing
(package, advisory) pairs that:

* are OSV-derived (``database_specific["conda-forge"]["derived_by"]`` ==
  ``"purl-associator/scripts.cve_match"``) — NVD-derived rows are skipped;
* have a CVSS base score (``severity[].score_num``) ≥ ``--min-score``
  (default 9.0, i.e. CVSS Critical);
* hit at least one shipping conda-forge version
  (``database_specific["conda-forge"]["affected_versions"]`` non-empty);
* are not already queued, not already drafted at the same severity, and not
  already covered by a human OpenVEX statement under
  ``mappings/cve_contributions/``.

Results are sorted by score descending and capped at ``--max-auto-enqueue``
(default 100).

Designed to run after :mod:`scripts.cve_match` in the daily refresh workflow.
The emitted queue file rides in the same refresh PR as the per-package CVE
files; the AI runner picks it up on its next scheduled run.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import typer
from rich.console import Console

from scripts.cve_common import best_severity, parse_conda_purl

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CVES_DIR = ROOT / "mappings" / "cves"
DEFAULT_QUEUE_DIR = ROOT / "mappings" / "cve_review_queue"
DEFAULT_DRAFTS_DIR = ROOT / "mappings" / "cve_ai_drafts"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"

DEFAULT_MIN_SCORE = 9.0
DEFAULT_MAX_AUTO_ENQUEUE = 100

# Discriminator: ``cve_match`` writes this string; ``nvd_prototype`` writes
# ``"purl-associator/scripts.nvd_prototype"``. Filtering on this keeps the
# auto-enqueuer OSV-only.
OSV_DERIVED_BY = "purl-associator/scripts.cve_match"

ENQUEUED_BY = "auto-cve-match"
REASON = "auto:severity"


# --------------------------------------------------------------------------- #
# Gates


def _osv_derived(advisory: dict) -> bool:
    db = advisory.get("database_specific")
    if not isinstance(db, dict):
        return False
    cf = db.get("conda-forge")
    if not isinstance(cf, dict):
        return False
    return cf.get("derived_by") == OSV_DERIVED_BY


def _has_active_versions(advisory: dict) -> bool:
    db = advisory.get("database_specific")
    if not isinstance(db, dict):
        return False
    cf = db.get("conda-forge")
    if not isinstance(cf, dict):
        return False
    affected = cf.get("affected_versions")
    return isinstance(affected, list) and len(affected) > 0


def _cvss_score(advisory: dict) -> float | None:
    sev = best_severity(advisory)
    if not isinstance(sev, dict):
        return None
    score = sev.get("score_num")
    if isinstance(score, (int, float)):
        return float(score)
    return None


def _severity_snapshot(advisory: dict) -> dict[str, Any]:
    """Mirror of ``scripts.cve_ai_review._severity_snapshot``.

    Inlined so the auto-enqueuer doesn't pull in the AI runner's
    ``anthropic`` / ``httpx`` module-level imports."""
    best = best_severity(advisory)
    cvss: float | None = None
    if isinstance(best, dict):
        score = best.get("score_num")
        if isinstance(score, (int, float)):
            cvss = float(score)
    raw_level = (advisory.get("database_specific") or {}).get("severity")
    level = raw_level if isinstance(raw_level, str) else None
    return {"cvss": cvss, "level": level}


def _severity_changed(seen: dict, current: dict) -> bool:
    return (seen.get("cvss") != current.get("cvss")) or (
        seen.get("level") != current.get("level")
    )


def _inputs_snapshot(
    auto_entry: dict | None, pkg_file: dict, advisory: dict
) -> dict[str, str]:
    """Mirror of ``scripts.cve_ai_review._inputs_snapshot``.

    Same payload, same hash algorithm. Inlined for the same reason as
    ``_severity_snapshot``: keep the auto-enqueuer free of the AI runner's
    heavyweight module-level imports."""
    cf = (advisory.get("database_specific") or {}).get("conda-forge") or {}
    pkg_part: dict[str, Any] | None
    if auto_entry is None:
        pkg_part = None
    else:
        pkg_part = {
            "summary": auto_entry.get("summary"),
            "type": auto_entry.get("type"),
            "purl": auto_entry.get("purl"),
            "homepage": auto_entry.get("homepage"),
            "source_url": auto_entry.get("source_url"),
            "repo": auto_entry.get("repo"),
            "recipe_url": auto_entry.get("recipe_url"),
            "latest_version": pkg_file.get("latest_version"),
        }
    adv_part = {
        "summary": advisory.get("summary"),
        "details": advisory.get("details"),
        "references": advisory.get("references"),
        "affected": advisory.get("affected"),
        "source_purls": cf.get("source_purls"),
        "affected_versions": cf.get("affected_versions"),
        "affects_future": cf.get("affects_future"),
    }
    blob = json.dumps({"pkg": pkg_part, "adv": adv_part}, sort_keys=True, default=str)
    return {"hash": hashlib.sha256(blob.encode("utf-8")).hexdigest()}


def _inputs_changed(seen: dict, current: dict) -> bool:
    """Missing hash on the draft → treat as match (cutover policy)."""
    seen_hash = (seen or {}).get("hash")
    if not seen_hash:
        return False
    return seen_hash != (current or {}).get("hash")


def _load_auto(auto_path: Path) -> dict[str, dict]:
    """Mirror of ``scripts.cve_ai_review._load_auto``."""
    if not auto_path.exists():
        return {}
    try:
        data = json.loads(auto_path.read_text())
    except json.JSONDecodeError:
        return {}
    return data.get("packages") or {}


# --------------------------------------------------------------------------- #
# Existing-state loaders (mirrors of helpers in cve_ai_review.py; inlined for
# the same reason as _severity_snapshot).


def _load_queued_pairs(queue_dir: Path) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if not queue_dir.exists():
        return pairs
    for path in sorted(queue_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            console.log(f"[yellow]skipping queue file {path.name}: {exc}[/yellow]")
            continue
        for raw in data.get("items") or []:
            if not isinstance(raw, dict):
                continue
            pkg = raw.get("package")
            adv = raw.get("advisory_id")
            if isinstance(pkg, str) and isinstance(adv, str):
                pairs.add((pkg, adv))
    return pairs


def _load_human_covered_pairs(contrib_dir: Path) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if not contrib_dir.exists():
        return pairs
    for path in sorted(contrib_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            console.log(f"[yellow]skipping contribution {path.name}: {exc}[/yellow]")
            continue
        if data.get("draft") is True:
            continue
        for stmt in data.get("statements") or []:
            if not isinstance(stmt, dict):
                continue
            vuln = stmt.get("vulnerability") or {}
            name = vuln.get("name") if isinstance(vuln, dict) else None
            if not isinstance(name, str):
                continue
            for product in stmt.get("products") or []:
                if not isinstance(product, dict):
                    continue
                parsed = parse_conda_purl(product.get("@id") or "")
                if parsed is None:
                    continue
                pairs.add((parsed[0], name))
    return pairs


def _load_latest_drafts(drafts_dir: Path) -> dict[tuple[str, str], dict]:
    latest: dict[tuple[str, str], dict] = {}
    if not drafts_dir.exists():
        return latest
    for path in sorted(drafts_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            console.log(f"[yellow]skipping draft {path.name}: {exc}[/yellow]")
            continue
        ts = data.get("generated_at") or ""
        for key, assessment in (data.get("assessments") or {}).items():
            if not isinstance(assessment, dict):
                continue
            pkg = assessment.get("package")
            adv = assessment.get("advisory_id") or key
            if not isinstance(pkg, str) or not isinstance(adv, str):
                continue
            existing = latest.get((pkg, adv))
            if existing is None or ts > existing.get("_generated_at", ""):
                merged = dict(assessment)
                merged["_generated_at"] = ts
                latest[(pkg, adv)] = merged
    return latest


# --------------------------------------------------------------------------- #
# Candidate iteration


def _iter_candidates(
    cves_dir: Path, *, min_score: float
) -> Iterator[tuple[str, str, dict, dict, float]]:
    """Yield ``(package, advisory_id, advisory_dict, pkg_file_dict, score)``
    for every per-package advisory passing the OSV + active + severity
    gates. ``pkg_file_dict`` is the parsed per-package CVE file, surfaced
    so callers can compute the prompt-inputs fingerprint without re-reading
    the JSON."""
    if not cves_dir.exists():
        return
    for path in sorted(cves_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            console.log(f"[yellow]skipping {path.name}: {exc}[/yellow]")
            continue
        package = data.get("package") or path.stem
        if not isinstance(package, str):
            continue
        for adv in data.get("advisories") or []:
            if not isinstance(adv, dict):
                continue
            if not _osv_derived(adv):
                continue
            if not _has_active_versions(adv):
                continue
            score = _cvss_score(adv)
            if score is None or score < min_score:
                continue
            adv_id = adv.get("id")
            if not isinstance(adv_id, str):
                continue
            yield package, adv_id, adv, data, score


# --------------------------------------------------------------------------- #
# CLI


@app.command()
def main(
    cves_dir: Path = typer.Option(DEFAULT_CVES_DIR, "--cves-dir"),
    queue_dir: Path = typer.Option(DEFAULT_QUEUE_DIR, "--queue-dir"),
    drafts_dir: Path = typer.Option(DEFAULT_DRAFTS_DIR, "--drafts-dir"),
    contributions_dir: Path = typer.Option(DEFAULT_CONTRIB_DIR, "--contributions-dir"),
    auto_path: Path = typer.Option(DEFAULT_AUTO, "--auto"),
    min_score: float = typer.Option(
        float(os.environ.get("CVE_AI_AUTO_ENQUEUE_MIN_SCORE", DEFAULT_MIN_SCORE)),
        "--min-score",
        help="CVSS base score threshold (inclusive). Default 9.0.",
    ),
    max_auto_enqueue: int = typer.Option(
        DEFAULT_MAX_AUTO_ENQUEUE,
        "--max-auto-enqueue",
        help="Maximum number of items emitted per run.",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print what would be enqueued; write nothing."
    ),
) -> None:
    """Emit one queue file with high-severity advisories for AI review."""
    candidates = list(_iter_candidates(cves_dir, min_score=min_score))
    console.log(
        f"Severity/active gates: [bold]{len(candidates):,}[/] candidates "
        f"(min_score={min_score})"
    )

    queued_pairs = _load_queued_pairs(queue_dir)
    human_pairs = _load_human_covered_pairs(contributions_dir)
    latest_drafts = _load_latest_drafts(drafts_dir)
    auto_packages = _load_auto(auto_path)

    selected: list[tuple[str, str, float]] = []
    counts = {"already_queued": 0, "already_human": 0, "already_drafted": 0}
    for package, adv_id, adv, pkg_file, score in candidates:
        key = (package, adv_id)
        if key in queued_pairs:
            counts["already_queued"] += 1
            continue
        if key in human_pairs:
            counts["already_human"] += 1
            continue
        existing = latest_drafts.get(key)
        if existing is not None:
            cur_sev = _severity_snapshot(adv)
            cur_inp = _inputs_snapshot(auto_packages.get(package), pkg_file, adv)
            sev_drift = _severity_changed(existing.get("severity_seen") or {}, cur_sev)
            inp_drift = _inputs_changed(existing.get("inputs_seen") or {}, cur_inp)
            if not sev_drift and not inp_drift:
                counts["already_drafted"] += 1
                continue
        selected.append((package, adv_id, score))

    # Highest CVSS first; ties keep insertion order (stable sort), which is
    # alphabetical by package because glob() is sorted upstream.
    selected.sort(key=lambda t: -t[2])

    if len(selected) > max_auto_enqueue:
        dropped = len(selected) - max_auto_enqueue
        console.log(
            f"[yellow]Capping at --max-auto-enqueue={max_auto_enqueue} "
            f"(dropping {dropped} lower-scored item(s)).[/yellow]"
        )
        selected = selected[:max_auto_enqueue]

    console.log(
        f"To enqueue: [bold]{len(selected):,}[/]  "
        f"skipped: queued={counts['already_queued']}, "
        f"human={counts['already_human']}, "
        f"drafted_no_drift={counts['already_drafted']}"
    )

    if not selected:
        console.log("Nothing to enqueue.")
        return

    items = [
        {"package": pkg, "advisory_id": adv, "reason": REASON}
        for pkg, adv, _ in selected
    ]
    now = datetime.now(UTC)
    payload = {
        "schema_version": 1,
        "enqueued_at": now.isoformat(timespec="seconds"),
        "enqueued_by": ENQUEUED_BY,
        "items": items,
    }

    if dry_run:
        console.log("[yellow]--dry-run: not writing file.[/yellow]")
        console.print_json(json.dumps(payload))
        return

    ts = now.strftime("%Y-%m-%dT%H-%M-%S-%fZ")
    run_id = secrets.token_hex(3)
    queue_dir.mkdir(parents=True, exist_ok=True)
    out = queue_dir / f"{ts}--{run_id}.json"
    out.write_text(json.dumps(payload, indent=2) + "\n")
    try:
        display = out.resolve().relative_to(ROOT)
    except ValueError:
        display = out
    console.log(f"Wrote [bold]{len(items)}[/] item(s) → {display}")


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)
