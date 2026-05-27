"""AI-assisted tiebreaker for the ``ambiguous`` bucket of CPE candidates.

Reads the latest ``mappings/cpe_candidates/<ts>.json`` file produced by
:mod:`scripts.cpe_discover`, picks the packages whose ``ambiguous`` bucket
is non-empty, and asks Claude Haiku to choose which (if any) of the
provided candidate CPEs correctly identify the same software the conda
package ships.

Design notes:

* Batched requests (default 15 packages per AI call), mirroring
  :mod:`scripts.ai_vet`. One system prompt amortizes across the batch.
* Structured output via ``output_config.format.json_schema`` — the model
  cannot return free-form text, only a list of verdicts matching the
  schema below.
* Strict no-hallucination rule: the model must pick from the CPE list it
  was given. If none match, ``verdict="none"`` with an empty selection.
* Output goes to ``mappings/cpe_vet/<ts>--<runid>.json``, layout
  parallel to ``mappings/ai_vet/``. :mod:`scripts.cpe_promote` reads
  this directory when promoting (``--vet-file`` overrides).

Run it:

    pixi run cpe-vet --dry-run            # preview prompts, no API call
    pixi run cpe-vet                      # call Haiku, write verdicts
    pixi run cpe-vet --only libpng,libtiff   # just two packages
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anthropic
import typer
from rich.console import Console

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATES_DIR = ROOT / "mappings" / "cpe_candidates"
DEFAULT_OUT_DIR = ROOT / "mappings" / "cpe_vet"

MODEL = "claude-haiku-4-5"
DEFAULT_BATCH_SIZE = 15  # packages per AI request
DEFAULT_CONCURRENCY = 4  # AI requests in flight
SCHEMA_VERSION = 1


SYSTEM_PROMPT = """You vet CPE coordinate candidates for conda-forge packages.

Each candidate is a CPE 2.3 prefix of the form `cpe:2.3:a:<vendor>:<product>` that
NVD has at least one CVE under. The conda package may correspond to one of these
CPEs, several aliases of the same software, or none of them.

For EACH package in the batch, choose which CPE(s) — if any — identify the same
upstream software the conda package ships.

Output a JSON object {"verdicts": [...]} containing one entry per package in the
same order, each with:
- package_name: the conda name (echo it back)
- verdict: "confident" | "uncertain" | "none"
- selected_cpes: array of CPE prefixes you picked (each MUST be one of the
  candidate strings you were given for that package)
- reasoning: 1-2 short sentences explaining the choice

Rules:
1. **Never invent CPEs.** Every entry in `selected_cpes` must be exact-copied
   from the provided candidate list for that package.
2. **Pick aliases together.** NVD sometimes lists the same product under
   multiple vendor names (e.g. `gnu:ncurses` + `invisible-island:ncurses`
   for older + newer records). When candidates are aliases for the same
   software, select ALL of them.
3. **Reject lookalikes.** Some candidate products share a name with the
   conda package but are unrelated (e.g. a CPE for a WordPress plugin named
   "ninja" is NOT the build tool `ninja`). Use the sample CVE descriptions
   and the conda summary to tell them apart.
4. **`none` is fine.** If no candidate matches, return `verdict="none"` with
   `selected_cpes=[]`. Better to skip than to pick wrong.
5. **`uncertain` is for borderline cases** — pick what you'd lean toward
   but flag that the auto-promote step should NOT take it. Humans review
   uncertain verdicts later."""


VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "package_name": {"type": "string"},
                    "verdict": {
                        "type": "string",
                        "enum": ["confident", "uncertain", "none"],
                    },
                    "selected_cpes": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "reasoning": {"type": "string"},
                },
                "required": [
                    "package_name",
                    "verdict",
                    "selected_cpes",
                    "reasoning",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}


# ---------- candidates input ----------


def _latest_candidates_file(directory: Path) -> Path | None:
    if not directory.exists():
        return None
    files = sorted(directory.glob("*.json"))
    return files[-1] if files else None


@dataclass
class AmbiguousPackage:
    """One conda package with its ambiguous-bucket CPE candidates."""

    conda_name: str
    current_purl: str | None
    github_owner_repo: str | None
    candidates: list[dict]  # full candidate dicts from cpe_candidates.json


def _load_ambiguous(payload: dict, only: set[str] | None) -> list[AmbiguousPackage]:
    out: list[AmbiguousPackage] = []
    for pkg in payload.get("packages") or []:
        name = pkg.get("conda_name")
        if not isinstance(name, str):
            continue
        if only is not None and name not in only:
            continue
        ambiguous = pkg.get("ambiguous") or []
        if not ambiguous:
            continue
        out.append(
            AmbiguousPackage(
                conda_name=name,
                current_purl=pkg.get("current_purl"),
                github_owner_repo=pkg.get("github_owner_repo"),
                candidates=ambiguous,
            )
        )
    return out


# ---------- prompt construction ----------


def _format_candidate_block(idx: int, c: dict) -> str:
    """Render one CPE candidate so the model can compare it against the
    conda package context. Heuristic scores are surfaced so the model
    sees what structural signals already fired."""
    scores = c.get("scores") or {}
    fired: list[str] = []
    if scores.get("h2_owner_or_repo_match"):
        fired.append("H2 owner-or-repo-match")
    if scores.get("h4_vendor_eq_product"):
        fired.append("H4 vendor==product")
    if scores.get("h5_trusted_vendor"):
        fired.append("H5 trusted-vendor")
    if scores.get("h6_desc_mentions_name"):
        fired.append("H6 desc-mentions-name")
    if scores.get("h7_cve_count_ok"):
        fired.append("H7 ≥3 CVEs")
    h1 = scores.get("h1_github_url_rate") or 0.0
    if h1 > 0:
        fired.append(f"H1 github-url-rate={h1:.2f}")
    if scores.get("repo_fallback_only"):
        fired.append("repo-fallback-only (weaker — derived from PURL repo name)")
    fired_line = ", ".join(fired) if fired else "(no heuristic fired)"

    samples = c.get("sample_summaries") or []
    sample_lines = (
        "\n".join(f"        - {s}" for s in samples) or "        (no samples)"
    )

    return (
        f"  ({chr(ord('A') + idx)}) {c['cpe']}\n"
        f"      vendor: {c['vendor']}   product: {c['product']}   CVEs: {c['cve_count']}\n"
        f"      heuristics fired: {fired_line}\n"
        f"      sample CVEs:\n{sample_lines}"
    )


def _format_package_block(idx: int, pkg: AmbiguousPackage) -> str:
    cands = "\n".join(
        _format_candidate_block(i, c) for i, c in enumerate(pkg.candidates)
    )
    purl_line = pkg.current_purl or "(none)"
    repo_line = pkg.github_owner_repo or "(none)"
    return (
        f"[{idx}] package_name: {pkg.conda_name}\n"
        f"    current PURL: {purl_line}\n"
        f"    github owner/repo: {repo_line}\n"
        f"    candidates:\n{cands}"
    )


def _build_user_message(chunk: list[AmbiguousPackage]) -> str:
    parts = [f"Vet the following {len(chunk)} package(s):\n"]
    for i, pkg in enumerate(chunk, start=1):
        parts.append(_format_package_block(i, pkg))
        parts.append("")
    return "\n".join(parts)


# ---------- API call ----------


@dataclass
class VetVerdict:
    conda_name: str
    current_purl: str | None
    verdict: str  # "confident" | "uncertain" | "none"
    selected_cpes: list[str]
    candidate_cpes: list[str]  # echo of what we offered, for the audit trail
    reasoning: str
    ai_vetted_at: str
    model: str


def _parse_response(content: list) -> list[dict] | None:
    for block in content:
        if getattr(block, "type", None) == "text":
            try:
                doc = json.loads(block.text)
            except json.JSONDecodeError:
                return None
            return doc.get("verdicts")
    return None


def _validate_selected(
    selected: list, candidate_cpes: list[str], conda_name: str
) -> list[str]:
    """Drop any model-returned CPE that isn't in the candidate list for this
    package. The schema can't enforce subset-of, only string-typed — so we
    police it here. A common Haiku failure mode is to drop a punctuation
    character (``cpe:2.3:a:c-ares:c-ares`` → ``cpe:2.3:a:cares:cares``) and
    that absolutely must not slip into the output."""
    allowed = set(candidate_cpes)
    valid: list[str] = []
    dropped: list[str] = []
    for s in selected:
        if isinstance(s, str) and s in allowed:
            valid.append(s)
        else:
            dropped.append(str(s))
    if dropped:
        console.log(
            f"[yellow]{conda_name}: dropping {len(dropped)} CPE(s) not in candidate list: {dropped}[/]"
        )
    return valid


async def _vet_chunk(
    client: anthropic.AsyncAnthropic,
    sem: asyncio.Semaphore,
    chunk: list[AmbiguousPackage],
) -> list[VetVerdict]:
    user_msg = _build_user_message(chunk)
    async with sem:
        try:
            resp = await client.messages.create(
                model=MODEL,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                output_config={
                    "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}
                },
            )
        except anthropic.APIError as exc:
            console.log(f"[red]API error on chunk of {len(chunk)}: {exc}[/]")
            return []

    verdicts = _parse_response(resp.content)
    if verdicts is None:
        console.log(f"[red]Could not parse response for chunk of {len(chunk)}[/]")
        return []

    if len(verdicts) != len(chunk):
        console.log(
            f"[yellow]chunk size mismatch: sent {len(chunk)}, got {len(verdicts)} — matching by position[/]"
        )

    now = datetime.now(UTC).isoformat(timespec="seconds")
    out: list[VetVerdict] = []
    for pkg, v in zip(chunk, verdicts, strict=False):
        candidate_cpes = [c["cpe"] for c in pkg.candidates]
        selected = _validate_selected(
            v.get("selected_cpes") or [], candidate_cpes, pkg.conda_name
        )
        out.append(
            VetVerdict(
                conda_name=pkg.conda_name,
                current_purl=pkg.current_purl,
                verdict=v.get("verdict", "uncertain"),
                selected_cpes=selected,
                candidate_cpes=candidate_cpes,
                reasoning=v.get("reasoning", ""),
                ai_vetted_at=now,
                model=MODEL,
            )
        )
    return out


# ---------- file IO ----------


def _short_runid() -> str:
    return secrets.token_hex(3)[:5]


def _verdict_to_dict(v: VetVerdict) -> dict:
    return {
        "conda_name": v.conda_name,
        "current_purl": v.current_purl,
        "verdict": v.verdict,
        "selected_cpes": v.selected_cpes,
        "candidate_cpes": v.candidate_cpes,
        "reasoning": v.reasoning,
        "ai_vetted_at": v.ai_vetted_at,
        "model": v.model,
    }


def _summary_counts(verdicts: list[VetVerdict]) -> dict:
    counts = {"confident": 0, "uncertain": 0, "none": 0}
    for v in verdicts:
        counts[v.verdict] = counts.get(v.verdict, 0) + 1
    return {
        "confident_packages": counts["confident"],
        "uncertain_packages": counts["uncertain"],
        "none_packages": counts["none"],
        "selected_cpes_total": sum(
            len(v.selected_cpes) for v in verdicts if v.verdict == "confident"
        ),
    }


# ---------- CLI ----------


@app.command()
def main(
    candidates_file: Path | None = typer.Option(
        None,
        "--in",
        help="Candidates file to vet. Defaults to the newest file in "
        f"{DEFAULT_CANDIDATES_DIR.relative_to(ROOT)}/",
    ),
    out_dir: Path = typer.Option(DEFAULT_OUT_DIR),
    out: Path | None = typer.Option(
        None,
        "--out",
        help="Explicit output path; default <out_dir>/<ts>--<runid>.json",
    ),
    only: str | None = typer.Option(
        None,
        help="Comma-separated conda names to vet (default: every package "
        "with a non-empty ambiguous bucket)",
    ),
    ai_batch_size: int = typer.Option(DEFAULT_BATCH_SIZE),
    concurrency: int = typer.Option(DEFAULT_CONCURRENCY),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the prompts that would be sent without calling the API",
    ),
) -> None:
    """Vet the ambiguous bucket from the latest cpe_discover audit file."""
    candidates_file = candidates_file or _latest_candidates_file(DEFAULT_CANDIDATES_DIR)
    if candidates_file is None or not candidates_file.exists():
        raise typer.BadParameter(
            "No candidates file found. Run `pixi run cpe-discover` first."
        )
    payload = json.loads(candidates_file.read_text())

    only_set = {n.strip() for n in only.split(",") if n.strip()} if only else None
    targets = _load_ambiguous(payload, only_set)
    if not targets:
        console.log("[yellow]No ambiguous candidates to vet — nothing to do.[/]")
        return

    cand_total = sum(len(t.candidates) for t in targets)
    console.log(
        f"Vetting [bold]{len(targets)}[/] packages "
        f"({cand_total} candidate CPEs) from {candidates_file.relative_to(ROOT)}"
    )

    # Slice into batches of ``ai_batch_size``.
    chunks = [
        targets[i : i + ai_batch_size] for i in range(0, len(targets), ai_batch_size)
    ]
    console.log(f"Batched into {len(chunks)} chunk(s) of up to {ai_batch_size}")

    if dry_run:
        for i, chunk in enumerate(chunks, start=1):
            console.print(f"\n[bold cyan]── Chunk {i} ──[/]")
            console.print(_build_user_message(chunk))
        return

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/]")
        sys.exit(2)

    async def _run() -> list[VetVerdict]:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        sem = asyncio.Semaphore(concurrency)
        t0 = time.monotonic()
        results = await asyncio.gather(
            *(_vet_chunk(client, sem, chunk) for chunk in chunks)
        )
        elapsed = time.monotonic() - t0
        console.log(f"AI vet done in {elapsed:.1f}s")
        verdicts: list[VetVerdict] = []
        for r in results:
            verdicts.extend(r)
        return verdicts

    verdicts = asyncio.run(_run())

    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    summary = _summary_counts(verdicts)
    payload_out: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_candidates": str(candidates_file.relative_to(ROOT)),
        "model": MODEL,
        "summary": summary,
        "verdicts": [_verdict_to_dict(v) for v in verdicts],
    }

    if out is None:
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = generated_at.replace(":", "-")
        out = out_dir / f"{stamp}--{_short_runid()}.json"
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload_out, indent=2) + "\n")

    try:
        rel = out.relative_to(ROOT)
    except ValueError:
        rel = out
    console.log(
        f"[green]confident[/]: {summary['confident_packages']} pkgs "
        f"({summary['selected_cpes_total']} CPEs) · "
        f"[yellow]uncertain[/]: {summary['uncertain_packages']} · "
        f"[red]none[/]: {summary['none_packages']}"
    )
    console.log(f"Wrote {rel}")


if __name__ == "__main__":
    app()
