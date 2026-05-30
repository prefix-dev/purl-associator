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
DEFAULT_VET_DIR = ROOT / "mappings" / "cpe_vet"
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


def _latest_vet_file(directory: Path) -> Path | None:
    """Return the most recently named vet file (``cpe_vet/<ts>--<id>.json``)."""
    if not directory.exists():
        return None
    files = sorted(directory.glob("*.json"))
    return files[-1] if files else None


def _collect_vet_confident(payload: dict) -> dict[str, list[str]]:
    """Return ``{conda_name: [cpe, ...]}`` for AI verdicts marked ``confident``.

    ``uncertain`` and ``none`` verdicts are intentionally dropped here — the
    promote step ships only what both the heuristic accept bucket OR a
    confident AI verdict endorsed. Uncertain calls stay in the vet file
    for a human to read and lift manually if desired."""
    out: dict[str, list[str]] = {}
    for v in payload.get("verdicts") or []:
        if v.get("verdict") != "confident":
            continue
        name = v.get("conda_name")
        cpes = v.get("selected_cpes") or []
        if not isinstance(name, str) or not cpes:
            continue
        valid = [c for c in cpes if isinstance(c, str) and c.startswith("cpe:2.3:")]
        if valid:
            out[name] = valid
    return out


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


def _merge_accepts_with_vet(
    accepts: dict[str, list[str]], vet_confident: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Union the heuristic accept bucket with confident AI verdicts.

    When the same conda name appears in both (rare — AI vetting only ships
    candidates from the ambiguous bucket, which by definition didn't reach
    accept), CPEs are unioned preserving order: heuristic accepts first,
    then any AI-only additions."""
    merged: dict[str, list[str]] = {name: list(cpes) for name, cpes in accepts.items()}
    for name, cpes in vet_confident.items():
        existing = merged.setdefault(name, [])
        seen = set(existing)
        for c in cpes:
            if c not in seen:
                existing.append(c)
                seen.add(c)
    return merged


def _build_contribution(
    *,
    accepts: dict[str, list[str]],
    source_files: list[Path],
    author: str,
    author_name: str,
    timestamp: str,
) -> dict:
    """Build the contribution payload in the shape ``merge_mappings`` reads.

    Per-package entries carry only ``cpes`` — the primary PURL and other
    reviewed fields are left to earlier layers. ``merge_mappings`` will
    union this contribution's ``cpes`` over whatever was previously
    merged, leaving everything else untouched."""
    sources = ", ".join(s.name for s in source_files)
    return {
        "schema_version": 1,
        "title": "Add CPE mappings (automated discovery)",
        "author": author,
        "author_name": author_name,
        "timestamp": timestamp,
        "source": f"scripts.cpe_promote from {sources}",
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
    vet_file: Path | None = typer.Option(
        None,
        "--vet-file",
        help="AI vet file to merge in. Defaults to the newest file in "
        f"{DEFAULT_VET_DIR.relative_to(ROOT)}/ if any exist; pass an empty "
        "path or use --no-vet to skip.",
    ),
    no_vet: bool = typer.Option(
        False,
        "--no-vet",
        help="Do not merge any AI vet verdicts even if a vet file exists",
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
    candidates_generated_at = payload.get("generated_at")

    # Layer in AI vet verdicts unless suppressed.
    vet_used: Path | None = None
    vet_confident: dict[str, list[str]] = {}
    if not no_vet:
        explicit_vet = vet_file is not None
        vet_used = vet_file or _latest_vet_file(DEFAULT_VET_DIR)
        if vet_used is not None:
            # Resolve to an absolute path so later .relative_to(ROOT) calls
            # never raise on a relative --vet-file argument.
            vet_used = vet_used.resolve()
        if vet_used is not None and vet_used.exists():
            vet_payload = json.loads(vet_used.read_text())
            # Freshness check: ``cpe_vet`` stamps the candidates file's
            # generated_at into ``source_candidates_generated_at``. If that
            # doesn't match the current latest.json, the vet file is left
            # over from a prior discover run and its verdicts may no longer
            # apply (the prior ambiguous set is gone). Refuse to use it
            # unless --vet-file was passed explicitly (an explicit override
            # is treated as "I know what I'm doing").
            vet_source_at = vet_payload.get("source_candidates_generated_at")
            # Three stale cases:
            #   1. Vet file pre-dates this freshness check (no stamp at all).
            #   2. Stamps differ.
            #   3. Candidates file has no generated_at (unexpected; can't verify).
            # Treat any of them as stale unless --vet-file was passed.
            stale = (
                vet_source_at is None
                or candidates_generated_at is None
                or (vet_source_at != candidates_generated_at)
            )
            if stale and not explicit_vet:
                console.log(
                    f"[yellow]Ignoring stale vet file {vet_used.relative_to(ROOT)}: "
                    f"recorded source_candidates_generated_at={vet_source_at!r} "
                    f"!= current candidates generated_at={candidates_generated_at!r}. "
                    f"Pass --vet-file explicitly to override.[/]"
                )
                vet_used = None
            else:
                if stale and explicit_vet:
                    console.log(
                        "[yellow]Vet file is stale relative to current "
                        "candidates, but --vet-file was passed explicitly — "
                        "using it anyway.[/]"
                    )
                vet_confident = _collect_vet_confident(vet_payload)
                if vet_confident:
                    console.log(
                        f"Merging {len(vet_confident)} confident AI verdict(s) "
                        f"from {vet_used.relative_to(ROOT)}"
                    )

    accepts = _merge_accepts_with_vet(accepts, vet_confident)

    if not accepts:
        console.log(
            f"[yellow]No accepts to promote in {candidates_file.name}; "
            "nothing to do.[/]"
        )
        return

    cpe_count = sum(len(v) for v in accepts.values())
    sources_log = candidates_file.relative_to(ROOT)
    if vet_used is not None and vet_confident:
        sources_log = f"{sources_log} + {vet_used.relative_to(ROOT)}"
    console.log(
        f"Promoting [bold]{len(accepts)}[/] packages "
        f"({cpe_count} CPE entries) from {sources_log}"
    )

    timestamp = (
        datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )
    source_files = [candidates_file]
    if vet_used is not None and vet_confident:
        source_files.append(vet_used)
    contribution = _build_contribution(
        accepts=accepts,
        source_files=source_files,
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
