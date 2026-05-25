"""Compile AI CVE review artefacts into SPA-facing sidecars.

Reads:

- ``mappings/cve_ai_drafts/*.json`` — per-run AI drafts (wrapper + OpenVEX +
  structured assessments).
- ``mappings/cve_review_queue/*.json`` — queue items pending AI processing.
- ``mappings/cve_contributions/*.json`` — human OpenVEX statements
  (precedence — anything they cover is filtered out).

Writes:

- ``web/public/cve_ai_drafts.json`` — newest assessment per
  ``(package, advisory_id)`` for the SPA's 🤖 chip + side panel.
- ``web/public/cve_ai_queue.json`` — pairs queued but not yet drafted
  (and not yet human-reviewed), for the SPA's ⏳ chip.

Neither sidecar is consumed by ``scripts.merge_cves`` — they're SPA-only.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from scripts.cve_common import parse_conda_purl

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DRAFTS_DIR = ROOT / "mappings" / "cve_ai_drafts"
DEFAULT_QUEUE_DIR = ROOT / "mappings" / "cve_review_queue"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"
DEFAULT_DRAFTS_OUT = ROOT / "web" / "public" / "cve_ai_drafts.json"
DEFAULT_QUEUE_OUT = ROOT / "web" / "public" / "cve_ai_queue.json"

SCHEMA_VERSION = 1


def _load_human_covered_pairs(contrib_dir: Path) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    if not contrib_dir.exists():
        return pairs
    for path in sorted(contrib_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
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


def _collect_drafts(drafts_dir: Path) -> dict[str, dict[str, dict]]:
    """{package: {advisory_id: {...newest assessment...}}}."""
    out: dict[str, dict[str, dict]] = {}
    if not drafts_dir.exists():
        return out
    for path in sorted(drafts_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if data.get("draft") is not True:
            continue
        ts = data.get("generated_at") or ""
        model = data.get("model") or ""
        run_id = data.get("run_id") or path.stem
        for assessment in (data.get("assessments") or {}).values():
            if not isinstance(assessment, dict):
                continue
            pkg = assessment.get("package")
            adv = assessment.get("advisory_id")
            if not pkg or not adv:
                continue
            existing = out.setdefault(pkg, {}).get(adv)
            if existing and existing.get("generated_at", "") >= ts:
                continue
            out[pkg][adv] = {
                "model": model,
                "run_id": run_id,
                "generated_at": ts,
                "rationale": assessment.get("rationale"),
                "openvex_status": assessment.get("openvex_status"),
                "openvex_justification": assessment.get("openvex_justification"),
                "openvex_impact_statement": assessment.get("openvex_impact_statement"),
                "openvex_action_statement": assessment.get("openvex_action_statement"),
                "affected_versions": assessment.get("affected_versions"),
                "runtime_applicability": assessment.get("runtime_applicability"),
                "severity_in_conda_context": assessment.get(
                    "severity_in_conda_context"
                ),
                "notes": assessment.get("notes"),
            }
    return out


def _collect_queue(queue_dir: Path) -> dict[str, dict[str, dict]]:
    """{package: {advisory_id: {enqueued_at, enqueued_by}}} — newest per pair."""
    out: dict[str, dict[str, dict]] = {}
    if not queue_dir.exists():
        return out
    for path in sorted(queue_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        ts = data.get("enqueued_at") or ""
        by = data.get("enqueued_by") or "unknown"
        for item in data.get("items") or []:
            if not isinstance(item, dict):
                continue
            pkg = item.get("package")
            adv = item.get("advisory_id")
            if not pkg or not adv:
                continue
            existing = out.setdefault(pkg, {}).get(adv)
            if existing and existing.get("enqueued_at", "") >= ts:
                continue
            out[pkg][adv] = {"enqueued_at": ts, "enqueued_by": by}
    return out


def _filter_covered(
    tree: dict[str, dict[str, dict]],
    covered: set[tuple[str, str]],
) -> dict[str, dict[str, dict]]:
    out: dict[str, dict[str, dict]] = {}
    for pkg, advs in tree.items():
        keep = {adv: v for adv, v in advs.items() if (pkg, adv) not in covered}
        if keep:
            out[pkg] = dict(sorted(keep.items()))
    return dict(sorted(out.items()))


def main(
    drafts_dir: Path = DEFAULT_DRAFTS_DIR,
    queue_dir: Path = DEFAULT_QUEUE_DIR,
    contributions_dir: Path = DEFAULT_CONTRIB_DIR,
    drafts_out: Path = DEFAULT_DRAFTS_OUT,
    queue_out: Path = DEFAULT_QUEUE_OUT,
) -> None:
    covered = _load_human_covered_pairs(contributions_dir)
    drafts = _filter_covered(_collect_drafts(drafts_dir), covered)
    # The queue sidecar additionally hides items that already have a draft.
    drafted_pairs: set[tuple[str, str]] = {
        (pkg, adv) for pkg, advs in drafts.items() for adv in advs
    }
    queue = _filter_covered(_collect_queue(queue_dir), covered | drafted_pairs)

    drafts_out.parent.mkdir(parents=True, exist_ok=True)
    drafts_out.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "drafts": drafts,
                "draft_count": sum(len(v) for v in drafts.values()),
                "package_count": len(drafts),
            },
            indent=2,
        )
        + "\n"
    )

    queue_out.parent.mkdir(parents=True, exist_ok=True)
    queue_out.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "queue": queue,
                "queue_count": sum(len(v) for v in queue.values()),
                "package_count": len(queue),
            },
            indent=2,
        )
        + "\n"
    )

    print(
        f"drafts: {sum(len(v) for v in drafts.values())} pair(s) across "
        f"{len(drafts)} package(s) → {drafts_out}"
    )
    print(
        f"queue:  {sum(len(v) for v in queue.values())} pair(s) across "
        f"{len(queue)} package(s) → {queue_out}"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drafts-dir", type=Path, default=DEFAULT_DRAFTS_DIR)
    parser.add_argument("--queue-dir", type=Path, default=DEFAULT_QUEUE_DIR)
    parser.add_argument("--contributions-dir", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument("--drafts-out", type=Path, default=DEFAULT_DRAFTS_OUT)
    parser.add_argument("--queue-out", type=Path, default=DEFAULT_QUEUE_OUT)
    args = parser.parse_args()
    main(
        args.drafts_dir,
        args.queue_dir,
        args.contributions_dir,
        args.drafts_out,
        args.queue_out,
    )
