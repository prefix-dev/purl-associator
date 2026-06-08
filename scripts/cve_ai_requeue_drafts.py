"""Requeue existing AI CVE drafts for a fresh review run.

Use this after changing ``scripts.cve_ai_review`` prompt semantics. It reads the
newest draft per ``(package, advisory_id)`` from ``mappings/cve_ai_drafts/`` and
writes one queue file under ``mappings/cve_review_queue/``. By default each item
is marked ``force: true``, so the next ``cve-ai-review`` run redrafts the pairs
even when nothing has drifted (pass ``--no-force`` to redraft only on drift).

Examples::

    pixi run cve-ai-requeue-drafts
    pixi run cve-ai-requeue-drafts --status fixed
    pixi run cve-ai-requeue-drafts --package mlflow --advisory GHSA-fmxj-6h9g-6vw3
"""

from __future__ import annotations

import argparse
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

from scripts.cve_common import load_human_covered_pairs, load_latest_drafts

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DRAFTS_DIR = ROOT / "mappings" / "cve_ai_drafts"
DEFAULT_QUEUE_DIR = ROOT / "mappings" / "cve_review_queue"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--drafts-dir", type=Path, default=DEFAULT_DRAFTS_DIR)
    parser.add_argument("--queue-dir", type=Path, default=DEFAULT_QUEUE_DIR)
    parser.add_argument("--contributions-dir", type=Path, default=DEFAULT_CONTRIB_DIR)
    parser.add_argument(
        "--package",
        action="append",
        dest="packages",
        help="Only requeue this package (repeatable)",
    )
    parser.add_argument(
        "--advisory",
        action="append",
        dest="advisories",
        help="Only requeue this advisory id (repeatable)",
    )
    parser.add_argument(
        "--status",
        action="append",
        choices=["affected", "not_affected", "fixed", "under_investigation"],
        help="Only requeue drafts with this AI OpenVEX status (repeatable)",
    )
    parser.add_argument(
        "--reason",
        default="redraft_after_prompt_change",
        help="Queue item reason to write",
    )
    parser.add_argument("--note", default="", help="Optional note on each queue item")
    parser.add_argument(
        "--no-force",
        dest="force",
        action="store_false",
        help="Don't force a re-draft; only redraft on prompt/severity/input drift",
    )
    parser.set_defaults(force=True)
    parser.add_argument(
        "--include-human-reviewed",
        action="store_true",
        help="Also requeue pairs already covered by human OpenVEX contributions",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print payload; do not write"
    )
    args = parser.parse_args()

    packages = set(args.packages or [])
    advisories = set(args.advisories or [])
    statuses = set(args.status or [])
    covered = (
        set()
        if args.include_human_reviewed
        else load_human_covered_pairs(args.contributions_dir)
    )

    items: list[dict[str, object]] = []
    for (pkg, adv), draft in sorted(load_latest_drafts(args.drafts_dir).items()):
        if packages and pkg not in packages:
            continue
        if advisories and adv not in advisories:
            continue
        if statuses and draft.get("openvex_status") not in statuses:
            continue
        if (pkg, adv) in covered:
            continue
        item: dict[str, object] = {
            "package": pkg,
            "advisory_id": adv,
            "reason": args.reason,
        }
        if args.note:
            item["note"] = args.note
        if args.force:
            item["force"] = True
        items.append(item)

    now = datetime.now(UTC)
    payload = {
        "schema_version": 1,
        "enqueued_at": now.isoformat(timespec="seconds"),
        "enqueued_by": "manual-redraft",
        "items": items,
    }

    if args.dry_run:
        print(json.dumps(payload, indent=2))
        return
    if not items:
        print("nothing to requeue")
        return

    args.queue_dir.mkdir(parents=True, exist_ok=True)
    out = (
        args.queue_dir
        / f"{now.strftime('%Y-%m-%dT%H-%M-%S-%fZ')}--redraft-{secrets.token_hex(3)}.json"
    )
    out.write_text(json.dumps(payload, indent=2) + "\n")
    try:
        display = out.resolve().relative_to(ROOT)
    except ValueError:
        display = out
    print(f"requeued {len(items)} AI draft(s) → {display}")


if __name__ == "__main__":
    main()
