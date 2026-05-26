"""Promote accepted CPE candidates into a contribution file.

Reads a candidates file produced by :mod:`scripts.cpe_discover` (default: the
newest file in ``mappings/cpe_candidates/``), takes every candidate in the
``accept`` bucket, and writes one ``mappings/contributions/<ISO>--cpe-pipeline.json``
file in the same shape human reviewers' contributions take.

The contribution carries only the ``cpes`` field per package — the primary
PURL and the rest of the layered mapping are left to whatever earlier layer
provided them. ``scripts.merge_mappings`` already passes ``cpes`` through
its ``REVIEWED_MAPPING_FIELDS`` allow-list, so no merge-side changes are
needed.

Re-running is safe: the next ``cpe-discover`` pass will see the newly
contributed CPEs via ``_load_existing_cpes`` and skip those packages, so
running ``promote`` twice never produces duplicate contributions.

Useful commands:

    pixi run cpe-promote --dry-run
    pixi run cpe-promote --in mappings/cpe_candidates/<ts>.json
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATES_DIR = ROOT / "mappings" / "cpe_candidates"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_AUTHOR = "cpe-pipeline"
DEFAULT_AUTHOR_NAME = "Automated CPE discovery pipeline"


def _latest_candidates_file(directory: Path) -> Path | None:
    """Return the most recently named candidates file in ``directory``.

    Candidates files are named with an ISO timestamp (``cpe_discover.py``
    writes ``<ts>.json``), so lexicographic sort == chronological."""
    if not directory.exists():
        return None
    files = sorted(directory.glob("*.json"))
    return files[-1] if files else None


def _collect_accepts(payload: dict) -> dict[str, list[str]]:
    """Return ``{conda_name: [cpe, ...]}`` from the ``accept`` bucket only.

    Preserves CPE order as it appears in the candidates file (which is the
    order cpe_discover wrote them in — by descending CVE count after the
    bucketer's sort). Aliases like ``libssh2``'s three CPEs are kept
    together intact."""
    out: dict[str, list[str]] = {}
    for pkg in payload.get("packages") or []:
        name = pkg.get("conda_name")
        if not isinstance(name, str):
            continue
        cpes = [
            entry["cpe"]
            for entry in (pkg.get("accept") or [])
            if isinstance(entry, dict) and isinstance(entry.get("cpe"), str)
        ]
        if cpes:
            out[name] = cpes
    return out


def _build_contribution(
    *,
    accepts: dict[str, list[str]],
    source_file: Path,
    author: str,
    author_name: str,
    timestamp: str,
) -> dict:
    """Build the contribution payload in the shape ``merge_mappings`` reads.

    Per-package entries carry only ``cpes`` — the primary PURL and other
    reviewed fields are left to earlier layers. ``merge_mappings`` will
    union this contribution's ``cpes`` over whatever was previously
    merged, leaving everything else untouched."""
    return {
        "schema_version": 1,
        "title": "Add CPE mappings (automated discovery)",
        "author": author,
        "author_name": author_name,
        "timestamp": timestamp,
        "source": f"scripts.cpe_promote from {source_file.name}",
        "packages": {name: {"cpes": cpes} for name, cpes in sorted(accepts.items())},
    }


def _short_runid() -> str:
    """5-char alphanumeric tag to disambiguate two runs from the same
    second. Matches the layout the AI vet pipeline uses for its own
    output files."""
    return secrets.token_hex(3)[:5]


@app.command()
def main(
    in_: Path | None = typer.Option(
        None,
        "--in",
        help="Candidates file to promote. Defaults to the newest file in "
        f"{DEFAULT_CANDIDATES_DIR.relative_to(ROOT)}/",
    ),
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Output contribution file. Defaults to "
        f"{DEFAULT_CONTRIB_DIR.relative_to(ROOT)}/<ts>--cpe-pipeline--<runid>.json",
    ),
    author: str = typer.Option(
        DEFAULT_AUTHOR, help="GitHub-style handle in the contribution"
    ),
    author_name: str = typer.Option(
        DEFAULT_AUTHOR_NAME, help="Human-readable attribution"
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the contribution payload without writing it",
    ),
) -> None:
    """Promote ``accept``-bucket candidates to a contribution file."""
    candidates_file = in_ or _latest_candidates_file(DEFAULT_CANDIDATES_DIR)
    if candidates_file is None or not candidates_file.exists():
        raise typer.BadParameter(
            "No candidates file found. Run `pixi run cpe-discover` first, "
            "or pass --in <path>."
        )

    payload = json.loads(candidates_file.read_text())
    accepts = _collect_accepts(payload)
    if not accepts:
        console.log(
            f"[yellow]No accept-bucket candidates in {candidates_file.name}; "
            "nothing to promote.[/]"
        )
        return

    cpe_count = sum(len(v) for v in accepts.values())
    console.log(
        f"Promoting [bold]{len(accepts)}[/] packages "
        f"({cpe_count} CPE entries) from {candidates_file.relative_to(ROOT)}"
    )

    timestamp = (
        datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    contribution = _build_contribution(
        accepts=accepts,
        source_file=candidates_file,
        author=author,
        author_name=author_name,
        timestamp=timestamp,
    )

    body = json.dumps(contribution, indent=2) + "\n"

    if dry_run:
        console.log("[bold]--dry-run[/] — would write:")
        # Cap the preview so a 100-package promotion doesn't spam the terminal.
        preview_lines = body.splitlines()
        if len(preview_lines) > 80:
            head = "\n".join(preview_lines[:60])
            tail = "\n".join(preview_lines[-10:])
            console.print(
                f"{head}\n  ... ({len(preview_lines) - 70} lines elided) ...\n{tail}"
            )
        else:
            console.print(body)
        return

    if out is None:
        DEFAULT_CONTRIB_DIR.mkdir(parents=True, exist_ok=True)
        stamp = timestamp.replace(":", "-").replace(".", "-").replace("Z", "Z")
        out = DEFAULT_CONTRIB_DIR / f"{stamp}--{author}--{_short_runid()}.json"
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body)

    try:
        rel = out.relative_to(ROOT)
    except ValueError:
        rel = out
    console.log(f"[green]wrote[/] {rel}")
    for name, cpes in sorted(accepts.items()):
        joined = ", ".join(cpes)
        console.log(f"  {name}: {joined}")


if __name__ == "__main__":
    app()
