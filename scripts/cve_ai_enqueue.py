"""Append one (package, advisory_id) item to the AI review queue.

Local convenience helper. The primary enqueue path is the web UI →
Cloudflare Worker → ``/api/enqueue-cve-review`` endpoint; this script gives
maintainers the same outcome from a terminal without a GitHub round-trip.

Usage::

    pixi run cve-ai-enqueue --package requests --advisory GHSA-9wx4-h78v-vm56

Writes ``mappings/cve_review_queue/<ISO-timestamp>--<runid>.json``. The file
is picked up on the next ``cve-ai-review`` run (CI cron or local).
"""

from __future__ import annotations

import json
import re
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path

import typer

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_QUEUE_DIR = ROOT / "mappings" / "cve_review_queue"
DEFAULT_CVES_DIR = ROOT / "mappings" / "cves"

# Permissive match: GHSA / CVE / OSV / language-specific advisory prefixes.
_ADVISORY_ID_RE = re.compile(
    r"^(GHSA-|CVE-|OSV-|PYSEC-|RUSTSEC-|GO-|MAL-|NPM-|PLDB-|HSEC-|ASB-|ALAS-|RHSA-)"
)


def _advisory_exists(cves_dir: Path, package: str, advisory_id: str) -> bool:
    """Sanity check that the (package, advisory) pair is actually in cves/."""
    path = cves_dir / f"{package}.json"
    if not path.exists():
        return False
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return False
    for adv in data.get("advisories") or []:
        if adv.get("id") == advisory_id:
            return True
        if advisory_id in (adv.get("aliases") or []):
            return True
    return False


def main(
    package: str = typer.Option(..., "--package", help="conda-forge package name"),
    advisory: str = typer.Option(
        ..., "--advisory", help="Advisory id (GHSA-…, CVE-…, etc.)"
    ),
    reason: str = typer.Option(
        "manual", "--reason", help="Why this pair is being queued"
    ),
    note: str = typer.Option("", "--note", help="Optional free-form note"),
    queue_dir: Path = typer.Option(DEFAULT_QUEUE_DIR, "--queue-dir"),
    cves_dir: Path = typer.Option(DEFAULT_CVES_DIR, "--cves-dir"),
    skip_existence_check: bool = typer.Option(
        False,
        "--skip-existence-check",
        help="Skip verifying (package, advisory) exists in mappings/cves/",
    ),
) -> None:
    if not _ADVISORY_ID_RE.match(advisory):
        print(f"error: advisory id {advisory!r} doesn't look like a known prefix")
        sys.exit(2)

    if not skip_existence_check and not _advisory_exists(cves_dir, package, advisory):
        print(
            f"error: ({package}, {advisory}) not found in {cves_dir}. "
            f"Pass --skip-existence-check to override."
        )
        sys.exit(2)

    item: dict[str, str] = {
        "package": package,
        "advisory_id": advisory,
        "reason": reason,
    }
    if note:
        item["note"] = note

    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S-%fZ")
    run_id = secrets.token_hex(3)
    queue_dir.mkdir(parents=True, exist_ok=True)
    out = queue_dir / f"{ts}--{run_id}.json"
    out.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "enqueued_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "enqueued_by": "manual",
                "items": [item],
            },
            indent=2,
        )
        + "\n"
    )
    try:
        display = out.resolve().relative_to(ROOT)
    except ValueError:
        display = out
    print(f"queued {package} / {advisory} → {display}")


if __name__ == "__main__":
    typer.run(main)
