"""AI-assisted pre-vetting of PURL mappings.

Reads ``mappings/auto.json`` and, for each package, asks Claude Haiku to judge
whether the auto-inferred PURL looks right. Results are written to a sidecar
``mappings/ai_vet.json`` (separate file → no merge conflicts with automap PRs).

Two modes:

- ``realtime`` — parallel API calls with a small semaphore. Latency: minutes.
  Use for ``workflow_dispatch`` runs where a human is waiting.
- ``batches`` — Message Batches API (50% off, async). Latency: up to 24h.
  Use for the scheduled full-channel sweep.

Each entry is enriched with a tiny URL-liveness check against the proposed
PURL's canonical registry URL so the model can cross-reference its guess.
"""

from __future__ import annotations

import asyncio
import json
import os
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
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_OUT = ROOT / "mappings" / "ai_vet.json"

MODEL = "claude-haiku-4-5"
SCHEMA_VERSION = 1

# How many real-time API calls in flight at once. Haiku is cheap & fast,
# but stay polite to the rate limiter.
REALTIME_CONCURRENCY = 8
URL_CHECK_CONCURRENCY = 32
URL_CHECK_TIMEOUT = 8.0


SYSTEM_PROMPT = """You vet automatically-inferred PURL mappings for conda-forge packages.

For each candidate, decide whether the proposed primary PURL correctly identifies
the upstream source of this conda package.

Output exactly one of:
- "agree": the primary PURL is correct.
- "disagree": the primary PURL is wrong; supply a corrected PURL if obvious,
  otherwise leave suggested_purl null.
- "uncertain": you cannot judge from the given evidence.

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
- The conda summary often makes the right ecosystem obvious; trust it.

Keep `reasoning` to one or two short sentences."""


VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["agree", "disagree", "uncertain"]},
        "suggested_purl": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
    },
    "required": ["verdict", "suggested_purl", "reasoning"],
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


def _load_existing(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "model": MODEL, "entries": {}}
    with path.open() as fh:
        return json.load(fh)


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _is_fresh(existing: dict, version: str, build: str) -> bool:
    return (
        existing.get("package_version") == version
        and existing.get("package_build") == build
    )


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
            # name is "owner/repo"
            return f"https://api.github.com/repos/{name}"
        case _:
            return None


async def _check_url(client: httpx.AsyncClient, url: str) -> int | None:
    try:
        resp = await client.get(url, follow_redirects=True, timeout=URL_CHECK_TIMEOUT)
        return resp.status_code
    except httpx.HTTPError:
        return None


def _build_user_message(entry: dict, primary_status: int | None) -> str:
    """Render a compact, deterministic blob for the model. No timestamps, no
    nondeterministic dict ordering — keeps the prompt cacheable across runs.
    """
    alts = entry.get("alternative_purls") or []
    alt_lines = [
        f"  - {a['purl']}  (confidence={a.get('confidence', '?')}, source={a.get('source', '?')})"
        for a in alts
    ]
    status_line = (
        f"HTTP {primary_status}"
        if primary_status is not None
        else "no canonical registry URL / unreachable"
    )
    parts = [
        f"conda package: {entry['name']} v{entry.get('version', '?')}",
        f"summary: {entry.get('summary') or '(none)'}",
        f"homepage: {entry.get('homepage') or '(none)'}",
        f"source URL: {entry.get('source_url') or '(none)'}",
        f"upstream repo: {entry.get('repo') or '(none)'}",
        "",
        f"proposed primary PURL: {entry.get('purl') or '(none)'}",
        f"registry-existence check on primary PURL: {status_line}",
        "alternative PURLs from heuristics:",
        *(alt_lines or ["  (none)"]),
    ]
    return "\n".join(parts)


def _parse_response_json(content: list) -> dict | None:
    """Pull the JSON object out of a Claude response.

    With output_config.format=json_schema the response is a single text block
    whose body is the JSON document.
    """
    for block in content:
        if getattr(block, "type", None) == "text":
            try:
                return json.loads(block.text)
            except json.JSONDecodeError:
                return None
    return None


async def _vet_one_realtime(
    client: anthropic.AsyncAnthropic,
    http: httpx.AsyncClient,
    sem_api: asyncio.Semaphore,
    sem_url: asyncio.Semaphore,
    entry: dict,
) -> tuple[str, VetResult] | tuple[str, None]:
    name = entry["name"]
    primary = entry.get("purl")
    canonical = _registry_url(primary) if primary else None

    primary_status: int | None = None
    if canonical:
        async with sem_url:
            primary_status = await _check_url(http, canonical)

    user_msg = _build_user_message(entry, primary_status)

    async with sem_api:
        try:
            resp = await client.messages.create(
                model=MODEL,
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_msg}],
                output_config={
                    "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}
                },
            )
        except anthropic.APIError as exc:
            console.log(f"[red]API error on {name}: {exc}[/red]")
            return name, None

    parsed = _parse_response_json(resp.content)
    if parsed is None:
        console.log(f"[red]Could not parse response for {name}[/red]")
        return name, None

    return name, VetResult(
        package_version=entry.get("version", ""),
        package_build=entry.get("build", ""),
        vetted_at=datetime.now(UTC).isoformat(timespec="seconds"),
        model=MODEL,
        verdict=parsed["verdict"],
        suggested_purl=parsed.get("suggested_purl"),
        reasoning=parsed["reasoning"],
        primary_purl=primary,
        primary_purl_status=primary_status,
    )


def _select_targets(
    auto: dict,
    existing: dict,
    *,
    only: list[str] | None,
    skip_vetted: bool,
    limit: int | None,
) -> list[dict]:
    entries = auto["packages"]
    targets: list[dict] = []
    only_set = set(only) if only else None
    existing_entries = existing.get("entries", {})
    for name, entry in entries.items():
        if only_set and name not in only_set:
            continue
        if skip_vetted:
            prev = existing_entries.get(name)
            if prev and _is_fresh(
                prev, entry.get("version", ""), entry.get("build", "")
            ):
                continue
        targets.append(entry)
    if limit is not None:
        targets = targets[:limit]
    return targets


async def _run_realtime(targets: list[dict], existing: dict, out: Path) -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/red]")
        sys.exit(2)

    client = anthropic.AsyncAnthropic(api_key=api_key)
    sem_api = asyncio.Semaphore(REALTIME_CONCURRENCY)
    sem_url = asyncio.Semaphore(URL_CHECK_CONCURRENCY)

    async with httpx.AsyncClient() as http:
        tasks = [
            _vet_one_realtime(client, http, sem_api, sem_url, entry)
            for entry in targets
        ]

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("vetting", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                name, result = await coro
                if result is not None:
                    existing.setdefault("entries", {})[name] = asdict(result)
                progress.advance(task_id)


def _run_batches(targets: list[dict], existing: dict, out: Path) -> None:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        console.print("[red]ANTHROPIC_API_KEY not set[/red]")
        sys.exit(2)

    client = anthropic.Anthropic(api_key=api_key)

    # Pre-flight URL checks (synchronous wrapper around the async helper).
    console.log(f"Pre-flight URL checks for {len(targets)} packages…")
    statuses: dict[str, int | None] = asyncio.run(_prefetch_statuses(targets))

    requests = []
    for entry in targets:
        name = entry["name"]
        primary_status = statuses.get(name)
        user_msg = _build_user_message(entry, primary_status)
        # custom_id must be ≤64 chars and unique per batch.
        # Conda names fit comfortably; truncate if a wild one shows up.
        custom_id = name[:64]
        requests.append(
            {
                "custom_id": custom_id,
                "params": {
                    "model": MODEL,
                    "max_tokens": 512,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": user_msg}],
                    "output_config": {
                        "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}
                    },
                },
            }
        )

    console.log(f"Submitting batch of {len(requests)} requests…")
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

    # Map custom_id back to entry so we can persist with full metadata.
    by_custom_id = {entry["name"][:64]: entry for entry in targets}

    for result in client.messages.batches.results(batch.id):
        entry = by_custom_id.get(result.custom_id)
        if entry is None:
            console.log(f"[yellow]Unknown custom_id: {result.custom_id}[/yellow]")
            continue
        if result.result.type != "succeeded":
            console.log(f"[red]{result.custom_id}: {result.result.type}[/red]")
            continue
        parsed = _parse_response_json(result.result.message.content)
        if parsed is None:
            console.log(f"[red]Could not parse: {result.custom_id}[/red]")
            continue
        existing.setdefault("entries", {})[entry["name"]] = asdict(
            VetResult(
                package_version=entry.get("version", ""),
                package_build=entry.get("build", ""),
                vetted_at=datetime.now(UTC).isoformat(timespec="seconds"),
                model=MODEL,
                verdict=parsed["verdict"],
                suggested_purl=parsed.get("suggested_purl"),
                reasoning=parsed["reasoning"],
                primary_purl=entry.get("purl"),
                primary_purl_status=statuses.get(entry["name"]),
            )
        )


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


@app.command()
def main(
    auto_path: Path = typer.Option(DEFAULT_AUTO, "--auto", help="Path to auto.json"),
    out_path: Path = typer.Option(
        DEFAULT_OUT, "--out", help="Path to ai_vet.json sidecar"
    ),
    mode: str = typer.Option("realtime", "--mode", help="realtime | batches"),
    limit: int | None = typer.Option(None, "--limit", help="Cap number of packages"),
    only: str = typer.Option("", "--only", help="Comma-separated package names"),
    skip_vetted: bool = typer.Option(
        True,
        "--skip-vetted/--revet",
        help="Skip packages already vetted at the same version+build",
    ),
) -> None:
    if mode not in {"realtime", "batches"}:
        console.print(f"[red]Unknown mode: {mode}[/red]")
        sys.exit(2)

    auto = _load_auto(auto_path)
    existing = _load_existing(out_path)
    only_list = [n.strip() for n in only.split(",") if n.strip()] if only else None
    targets = _select_targets(
        auto, existing, only=only_list, skip_vetted=skip_vetted, limit=limit
    )

    console.log(
        f"Vetting {len(targets)} packages (mode={mode}, "
        f"skip_vetted={skip_vetted}, limit={limit})"
    )
    if not targets:
        console.log("Nothing to do.")
        return

    existing["model"] = MODEL
    existing["schema_version"] = SCHEMA_VERSION
    existing["generated_at"] = datetime.now(UTC).isoformat(timespec="seconds")

    if mode == "realtime":
        asyncio.run(_run_realtime(targets, existing, out_path))
    else:
        _run_batches(targets, existing, out_path)

    _save(out_path, existing)
    console.log(f"Wrote {out_path}")


if __name__ == "__main__":
    app()
