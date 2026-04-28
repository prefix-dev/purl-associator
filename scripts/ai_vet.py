"""AI-assisted pre-vetting of PURL mappings.

Reads ``mappings/auto.json`` and, for each package, asks Claude Haiku to judge
whether the auto-inferred PURL looks right. Results are written to per-run
sidecar files under ``mappings/ai_vet/<ISO-timestamp>--<runid>.json`` (mirrors
the ``mappings/contributions/`` layout — no merge conflicts with automap PRs,
and a clean audit trail of what the model said when).

Two modes:

- ``realtime`` — parallel API calls with bounded concurrency. Latency: minutes.
  Use for ``workflow_dispatch`` runs where a human is waiting.
- ``batches`` — Message Batches API (50% off, async). Latency: up to 24h.
  Use for the scheduled full-channel sweep.

Optimizations:

- Each AI request bundles N packages (default 15). One system prompt instead
  of N — ~30% input-token savings and ~15× fewer round-trips.
- Each entry is enriched with a tiny URL-liveness check against the proposed
  PURL's canonical registry URL so the model can cross-reference its guess.
- ``--commit-every K``: every K AI requests, flush the run file and
  ``git add/commit/push`` so the PR updates incrementally and a workflow
  timeout doesn't lose progress.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anthropic
import httpx
import typer
from rich.console import Console

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_OUT_DIR = ROOT / "mappings" / "ai_vet"

MODEL = "claude-haiku-4-5"
SCHEMA_VERSION = 2  # bumped: per-run files + batched requests

# Concurrency knobs.
REALTIME_CONCURRENCY = 8  # AI requests in flight (each handles AI_BATCH_SIZE packages)
URL_CHECK_CONCURRENCY = 32
URL_CHECK_TIMEOUT = 8.0
DEFAULT_AI_BATCH_SIZE = 15  # packages per AI request
DEFAULT_COMMIT_EVERY = (
    16  # AI requests per git commit (2 rounds of REALTIME_CONCURRENCY=8)
)


SYSTEM_PROMPT = """You vet automatically-inferred PURL mappings for conda-forge packages.

You will receive a numbered list of candidates. For EACH candidate, decide whether
the proposed primary PURL correctly identifies the upstream source of that conda
package, and output a verdict.

Respond with a JSON object {"verdicts": [...]} containing one entry per candidate,
in the same order. Each verdict has:
- package_name: the candidate's conda package name (echo it back so we can match)
- verdict: "agree" | "disagree" | "uncertain"
- suggested_purl: corrected PURL if disagreeing and obvious; null otherwise
- reasoning: 1-2 short sentences

Guidance:
- Conda packages with prefix `r-` typically map to `pkg:cran/<name>` (or
  `pkg:bioconductor/<name>` for Bioconductor packages).
- Conda packages with prefix `bioconductor-` map to `pkg:bioconductor/<name>`.
- Pure-Python packages typically map to `pkg:pypi/<name>`. If a package is
  available on both PyPI and GitHub, prefer PyPI.
- Rust crates → `pkg:cargo/<name>`. Ruby gems → `pkg:gem/<name>`.
- For C/C++ libraries with no language registry, `pkg:github/<owner>/<repo>`
  is acceptable; `pkg:generic/<name>` is a last resort.
- A 404 on the registry-existence check is strong evidence the proposed PURL
  is wrong. A 200 is supportive but not conclusive (name collisions exist).
- The conda summary often makes the right ecosystem obvious; trust it."""


BATCH_VERDICT_SCHEMA = {
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
                        "enum": ["agree", "disagree", "uncertain"],
                    },
                    "suggested_purl": {"type": ["string", "null"]},
                    "reasoning": {"type": "string"},
                },
                "required": [
                    "package_name",
                    "verdict",
                    "suggested_purl",
                    "reasoning",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}


@dataclass
class VetResult:
    package_version: str
    package_build: str
    vetted_at: str
    model: str
    verdict: str
    suggested_purl: str | None
    reasoning: str
    primary_purl: str | None
    primary_purl_status: int | None  # HTTP status of registry-existence check


def _load_auto(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return json.load(fh)


def _read_existing_dir(out_dir: Path) -> dict[str, dict]:
    """Walk every per-run file in out_dir and return the LATEST verdict per
    package, keyed by package name. "Latest" = highest ``vetted_at``."""
    latest: dict[str, dict] = {}
    if not out_dir.exists():
        return latest
    for path in out_dir.glob("*.json"):
        try:
            with path.open() as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            console.log(f"[yellow]Skipping unreadable {path}: {exc}[/yellow]")
            continue
        for name, entry in (doc.get("entries") or {}).items():
            prev = latest.get(name)
            if prev is None or entry.get("vetted_at", "") > prev.get("vetted_at", ""):
                latest[name] = entry
    return latest


def _save_run_file(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _is_fresh(prev: dict, version: str, build: str) -> bool:
    return prev.get("package_version") == version and prev.get("package_build") == build


def _registry_url(purl: str) -> str | None:
    """Best-effort canonical URL to confirm a PURL exists upstream."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    if "/" not in body:
        return None
    type_, rest = body.split("/", 1)
    name = rest.split("?", 1)[0].split("#", 1)[0]
    match type_:
        case "pypi":
            return f"https://pypi.org/pypi/{name}/json"
        case "cargo":
            return f"https://crates.io/api/v1/crates/{name}"
        case "npm":
            return f"https://registry.npmjs.org/{name}"
        case "gem":
            return f"https://rubygems.org/api/v1/gems/{name}.json"
        case "cran":
            return f"https://cran.r-project.org/web/packages/{name}/index.html"
        case "bioconductor":
            return f"https://bioconductor.org/packages/release/bioc/html/{name}.html"
        case "github":
            return f"https://api.github.com/repos/{name}"
        case _:
            return None


async def _check_url(client: httpx.AsyncClient, url: str) -> int | None:
    try:
        resp = await client.get(url, follow_redirects=True, timeout=URL_CHECK_TIMEOUT)
        return resp.status_code
    except httpx.HTTPError:
        return None


def _format_candidate(idx: int, entry: dict, primary_status: int | None) -> str:
    alts = entry.get("alternative_purls") or []
    alt_str = ", ".join(a["purl"] for a in alts) or "(none)"
    status_line = (
        f"HTTP {primary_status}"
        if primary_status is not None
        else "no registry URL / unreachable"
    )
    return (
        f"[{idx}] package_name: {entry['name']} v{entry.get('version', '?')}\n"
        f"    summary: {entry.get('summary') or '(none)'}\n"
        f"    homepage: {entry.get('homepage') or '(none)'}\n"
        f"    source URL: {entry.get('source_url') or '(none)'}\n"
        f"    upstream repo: {entry.get('repo') or '(none)'}\n"
        f"    proposed primary PURL: {entry.get('purl') or '(none)'}\n"
        f"    registry-existence check: {status_line}\n"
        f"    alternatives: {alt_str}"
    )


def _build_batch_message(chunk: list[dict], statuses: dict[str, int | None]) -> str:
    parts = [f"Vet the following {len(chunk)} candidates:\n"]
    for i, entry in enumerate(chunk, start=1):
        parts.append(_format_candidate(i, entry, statuses.get(entry["name"])))
        parts.append("")
    return "\n".join(parts)


def _parse_batch_response(content: list) -> list[dict] | None:
    for block in content:
        if getattr(block, "type", None) == "text":
            try:
                doc = json.loads(block.text)
            except json.JSONDecodeError:
                return None
            return doc.get("verdicts")
    return None


async def _vet_chunk(
    client: anthropic.AsyncAnthropic,
    sem: asyncio.Semaphore,
    chunk: list[dict],
    statuses: dict[str, int | None],
) -> list[tuple[str, VetResult]]:
    user_msg = _build_batch_message(chunk, statuses)
    async with sem:
        try:
            resp = await client.messages.create(
                model=MODEL,
                max_tokens=2048,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                output_config={
                    "format": {"type": "json_schema", "schema": BATCH_VERDICT_SCHEMA}
                },
            )
        except anthropic.APIError as exc:
            console.log(f"[red]API error on chunk of {len(chunk)}: {exc}[/red]")
            return []

    verdicts = _parse_batch_response(resp.content)
    if verdicts is None:
        console.log(f"[red]Could not parse response for chunk of {len(chunk)}[/red]")
        return []

    by_name = {v.get("package_name"): v for v in verdicts}
    now = datetime.now(UTC).isoformat(timespec="seconds")
    out: list[tuple[str, VetResult]] = []
    for entry in chunk:
        name = entry["name"]
        v = by_name.get(name)
        if v is None:
            console.log(f"[yellow]No verdict returned for {name}[/yellow]")
            continue
        out.append(
            (
                name,
                VetResult(
                    package_version=entry.get("version", ""),
                    package_build=entry.get("build", ""),
                    vetted_at=now,
                    model=MODEL,
                    verdict=v["verdict"],
                    suggested_purl=v.get("suggested_purl"),
                    reasoning=v["reasoning"],
                    primary_purl=entry.get("purl"),
                    primary_purl_status=statuses.get(name),
                ),
            )
        )
    return out


def _select_targets(
    auto: dict,
    *,
    only: list[str] | None,
    skip_vetted: bool,
    limit: int | None,
    out_dir: Path,
) -> list[dict]:
    entries = auto["packages"]
    only_set = set(only) if only else None
    latest = _read_existing_dir(out_dir) if skip_vetted else {}
    targets: list[dict] = []
    for name, entry in entries.items():
        if only_set and name not in only_set:
            continue
        if skip_vetted:
            prev = latest.get(name)
            if prev and _is_fresh(
                prev, entry.get("version", ""), entry.get("build", "")
            ):
                continue
        targets.append(entry)
    if limit is not None:
        targets = targets[:limit]
    return targets


def _git(*args: str) -> tuple[int, str]:
    """Run a git command, return (rc, combined-output)."""
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _commit_and_push(run_file: Path, message: str) -> bool:
    """Commit the run file and push. Returns True on success, False on no-op
    or failure (logs the failure)."""
    rc, out = _git("add", str(run_file.relative_to(ROOT)))
    if rc != 0:
        console.log(f"[red]git add failed: {out.strip()}[/red]")
        return False
    rc, out = _git("diff", "--cached", "--quiet")
    if rc == 0:
        # Nothing staged — nothing to commit.
        return False
    rc, out = _git("commit", "-m", message)
    if rc != 0:
        console.log(f"[red]git commit failed: {out.strip()}[/red]")
        return False
    rc, out = _git("push")
    if rc != 0:
        console.log(f"[red]git push failed: {out.strip()}[/red]")
        return False
    return True


async def _prefetch_statuses(targets: list[dict]) -> dict[str, int | None]:
    sem = asyncio.Semaphore(URL_CHECK_CONCURRENCY)
    out: dict[str, int | None] = {}

    async def _one(http: httpx.AsyncClient, entry: dict) -> None:
        purl = entry.get("purl")
        url = _registry_url(purl) if purl else None
        if not url:
            out[entry["name"]] = None
            return
        async with sem:
            out[entry["name"]] = await _check_url(http, url)

    async with httpx.AsyncClient() as http:
        await asyncio.gather(*(_one(http, e) for e in targets))
    return out


async def _run_realtime(
    targets: list[dict],
    run_file: Path,
    *,
    ai_batch_size: int,
    commit_every: int,
) -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/red]")
        sys.exit(2)

    client = anthropic.AsyncAnthropic(api_key=api_key)
    sem = asyncio.Semaphore(REALTIME_CONCURRENCY)

    console.log(f"Pre-flight URL checks for {len(targets)} packages…")
    t0 = time.monotonic()
    statuses = await _prefetch_statuses(targets)
    console.log(f"  done in {time.monotonic() - t0:.1f}s")

    chunks = [
        targets[i : i + ai_batch_size] for i in range(0, len(targets), ai_batch_size)
    ]
    console.log(
        f"Vetting {len(targets)} packages in {len(chunks)} chunks "
        f"(batch_size={ai_batch_size}, concurrency={REALTIME_CONCURRENCY}, "
        f"commit_every={commit_every} chunks)"
    )

    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": MODEL,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "entries": {},
    }

    tasks = [_vet_chunk(client, sem, chunk, statuses) for chunk in chunks]
    chunks_done = 0
    pkgs_done = 0
    flush_lock = asyncio.Lock()

    for coro in asyncio.as_completed(tasks):
        results = await coro
        for name, result in results:
            state["entries"][name] = asdict(result)
        chunks_done += 1
        pkgs_done += len(results)
        console.log(
            f"  chunk {chunks_done}/{len(chunks)} done — "
            f"{pkgs_done}/{len(targets)} packages vetted"
        )

        if commit_every > 0 and chunks_done % commit_every == 0:
            async with flush_lock:
                state["generated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
                _save_run_file(run_file, state)
                msg = f"ai-vet: progress — {pkgs_done}/{len(targets)} packages"
                committed = await asyncio.to_thread(_commit_and_push, run_file, msg)
                if committed:
                    console.log(f"  [green]pushed: {msg}[/green]")

    # Final flush
    state["generated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
    _save_run_file(run_file, state)
    if commit_every > 0:
        msg = f"ai-vet: complete — {pkgs_done}/{len(targets)} packages"
        committed = await asyncio.to_thread(_commit_and_push, run_file, msg)
        if committed:
            console.log(f"  [green]pushed: {msg}[/green]")


def _run_batches(
    targets: list[dict],
    run_file: Path,
    *,
    ai_batch_size: int,
) -> None:
    """Anthropic Message Batches API path — async, 50% off. We still bundle
    multiple packages per request for token efficiency; commit_every is
    ignored because the work happens server-side and we only see results
    once the batch finishes."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/red]")
        sys.exit(2)

    client = anthropic.Anthropic(api_key=api_key)

    console.log(f"Pre-flight URL checks for {len(targets)} packages…")
    statuses: dict[str, int | None] = asyncio.run(_prefetch_statuses(targets))

    chunks = [
        targets[i : i + ai_batch_size] for i in range(0, len(targets), ai_batch_size)
    ]
    console.log(
        f"Submitting {len(chunks)} chunks of up to {ai_batch_size} packages each…"
    )

    requests = []
    for i, chunk in enumerate(chunks):
        user_msg = _build_batch_message(chunk, statuses)
        # custom_id maps back to chunk index. ≤64 chars.
        requests.append(
            {
                "custom_id": f"chunk-{i:06d}",
                "params": {
                    "model": MODEL,
                    "max_tokens": 2048,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_msg}],
                    "output_config": {
                        "format": {
                            "type": "json_schema",
                            "schema": BATCH_VERDICT_SCHEMA,
                        }
                    },
                },
            }
        )

    batch = client.messages.batches.create(requests=requests)
    console.log(f"Batch ID: {batch.id} (status: {batch.processing_status})")

    while True:
        batch = client.messages.batches.retrieve(batch.id)
        if batch.processing_status == "ended":
            break
        rc = batch.request_counts
        console.log(
            f"  status={batch.processing_status} processing={rc.processing} "
            f"succeeded={rc.succeeded} errored={rc.errored}"
        )
        time.sleep(60)

    console.log(
        f"Batch complete: {batch.request_counts.succeeded} succeeded, "
        f"{batch.request_counts.errored} errored"
    )

    state: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "model": MODEL,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "entries": {},
    }

    chunks_by_id = {f"chunk-{i:06d}": chunks[i] for i in range(len(chunks))}
    now = datetime.now(UTC).isoformat(timespec="seconds")
    for result in client.messages.batches.results(batch.id):
        chunk = chunks_by_id.get(result.custom_id)
        if chunk is None:
            console.log(f"[yellow]Unknown custom_id: {result.custom_id}[/yellow]")
            continue
        if result.result.type != "succeeded":
            console.log(f"[red]{result.custom_id}: {result.result.type}[/red]")
            continue
        verdicts = _parse_batch_response(result.result.message.content)
        if verdicts is None:
            console.log(f"[red]Could not parse: {result.custom_id}[/red]")
            continue
        by_name = {v.get("package_name"): v for v in verdicts}
        for entry in chunk:
            name = entry["name"]
            v = by_name.get(name)
            if v is None:
                continue
            state["entries"][name] = asdict(
                VetResult(
                    package_version=entry.get("version", ""),
                    package_build=entry.get("build", ""),
                    vetted_at=now,
                    model=MODEL,
                    verdict=v["verdict"],
                    suggested_purl=v.get("suggested_purl"),
                    reasoning=v["reasoning"],
                    primary_purl=entry.get("purl"),
                    primary_purl_status=statuses.get(name),
                )
            )

    _save_run_file(run_file, state)


def _run_id() -> str:
    # Short stable id like the contributions/ filenames.
    return secrets.token_hex(3)


def _make_run_file(out_dir: Path) -> Path:
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S-%fZ")
    return out_dir / f"{ts}--{_run_id()}.json"


@app.command()
def main(
    auto_path: Path = typer.Option(DEFAULT_AUTO, "--auto", help="Path to auto.json"),
    out_dir: Path = typer.Option(
        DEFAULT_OUT_DIR, "--out-dir", help="Directory for per-run sidecar files"
    ),
    mode: str = typer.Option("realtime", "--mode", help="realtime | batches"),
    limit: int | None = typer.Option(None, "--limit", help="Cap number of packages"),
    only: str = typer.Option("", "--only", help="Comma-separated package names"),
    skip_vetted: bool = typer.Option(
        True,
        "--skip-vetted/--revet",
        help="Skip packages already vetted at the same version+build",
    ),
    ai_batch_size: int = typer.Option(
        DEFAULT_AI_BATCH_SIZE,
        "--ai-batch-size",
        help="Packages per AI request (more = fewer round trips, larger context)",
    ),
    commit_every: int = typer.Option(
        DEFAULT_COMMIT_EVERY,
        "--commit-every",
        help="git commit + push every N AI requests (0 = no commits, write only at end)",
    ),
) -> None:
    if mode not in {"realtime", "batches"}:
        console.print(f"[red]Unknown mode: {mode}[/red]")
        sys.exit(2)
    if ai_batch_size < 1:
        console.print("[red]--ai-batch-size must be >= 1[/red]")
        sys.exit(2)

    auto = _load_auto(auto_path)
    only_list = [n.strip() for n in only.split(",") if n.strip()] if only else None
    targets = _select_targets(
        auto,
        only=only_list,
        skip_vetted=skip_vetted,
        limit=limit,
        out_dir=out_dir,
    )

    console.log(
        f"Selected {len(targets)} packages (mode={mode}, "
        f"skip_vetted={skip_vetted}, limit={limit})"
    )
    if not targets:
        console.log("Nothing to do.")
        return

    run_file = _make_run_file(out_dir)
    console.log(f"Run file: {run_file.relative_to(ROOT)}")

    if mode == "realtime":
        asyncio.run(
            _run_realtime(
                targets,
                run_file,
                ai_batch_size=ai_batch_size,
                commit_every=commit_every,
            )
        )
    else:
        _run_batches(targets, run_file, ai_batch_size=ai_batch_size)
        # Batches mode: write once at end. Optionally commit if requested.
        if commit_every > 0:
            _commit_and_push(
                run_file, f"ai-vet: batch result — {len(targets)} packages"
            )


if __name__ == "__main__":
    app()
