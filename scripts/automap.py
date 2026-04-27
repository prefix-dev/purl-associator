"""Auto-generate PURL mappings for conda-forge packages.

For each unique package name on conda-forge:
1. Pick the most-recent record across selected platforms.
2. Fetch ``info/recipe/rendered_recipe.yaml`` (rattler-build) or fall back to
   ``info/about.json`` for ``home`` / ``dev_url`` URLs.
3. Run :mod:`scripts.purl_inference` heuristics over those URLs.
4. Persist the result to ``mappings/auto.json`` (incremental: skip names
   whose ``version+build`` is unchanged).
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import typer
import yaml
from rattler.networking import Client
from rattler.package import AboutJson
from rattler.package_streaming import fetch_raw_package_file_from_url
from rattler.platform import Platform
from rattler.repo_data import Gateway, RepoDataRecord, SourceConfig
from rattler.version import VersionWithSource
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from scripts.purl_inference import PurlGuess, derive_recipe_context, infer_all

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

DEFAULT_PLATFORMS = ("linux-64", "noarch")
DEFAULT_CHANNEL = "conda-forge"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "mappings" / "auto.json"


@dataclass
class PurlAlternative:
    purl: str
    type: str
    namespace: str | None
    pkg_name: str
    confidence: float
    source: str


@dataclass
class AutoEntry:
    name: str
    version: str
    build: str
    subdir: str
    url: str
    purl: str | None
    type: str | None
    namespace: str | None
    pkg_name: str | None
    confidence: float
    sources: list[str]
    homepage: str | None
    repo: str | None
    recipe_url: str | None
    summary: str | None
    source_url: str | None = None
    alternative_purls: list[dict] | None = None
    note: str | None = None
    fetched_at: str | None = None


def _record_sort_key(record: RepoDataRecord) -> tuple[VersionWithSource, str, str, int]:
    return (
        record.version,
        record.timestamp.isoformat() if record.timestamp else "",
        record.build,
        record.build_number,
    )


def _pick_latest(records: list[RepoDataRecord]) -> RepoDataRecord | None:
    if not records:
        return None
    return max(records, key=_record_sort_key)


@dataclass(frozen=True)
class RecipeFacts:
    source_urls: list[str]
    about_urls: dict[str, str]
    host_deps: list[str]
    build_deps: list[str]
    noarch: str | None
    summary: str | None


def _stringify_dep(node: object) -> str | None:
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        # rattler-build pin form: {"pin_subpackage": "...", ...}
        for key in ("if", "pin_subpackage", "pin_compatible", "compiler", "stdlib", "spec"):
            if key in node:
                value = node[key]
                if isinstance(value, str):
                    return value
        return None
    return None


def _collect_source_urls(node: object, out: list[str]) -> None:
    if isinstance(node, dict):
        for key in ("url", "git", "git_url"):
            value = node.get(key)
            if isinstance(value, str) and value.startswith(("http", "git")):
                out.append(value)
            elif isinstance(value, list):
                out.extend(v for v in value if isinstance(v, str))
        for value in node.values():
            _collect_source_urls(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_source_urls(item, out)


def _collect_dep_lists(
    requirements: object, host_out: list[str], build_out: list[str]
) -> None:
    if not isinstance(requirements, dict):
        return
    for raw in requirements.get("host") or []:
        stringified = _stringify_dep(raw)
        if stringified:
            host_out.append(stringified)
    for raw in requirements.get("build") or []:
        stringified = _stringify_dep(raw)
        if stringified:
            build_out.append(stringified)


def _extract_recipe_facts(text: str, *, kind: str) -> RecipeFacts:
    """Parse a rendered recipe YAML.

    Two flavours:

    - **conda-build** (``info/recipe/meta.yaml``) — flat top-level keys:
      ``package``, ``source``, ``requirements``, ``about``, ``build``, ``outputs``.
    - **rattler-build** (``info/recipe/rendered_recipe.yaml``) — wraps everything
      under a top-level ``recipe:`` key, also exposes ``schema_version`` and
      ``context`` siblings. Multi-output recipes still use ``outputs:`` but the
      shape under each output mirrors a rattler-build recipe.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return RecipeFacts([], {}, [], [], None, None)
    if not isinstance(data, dict):
        return RecipeFacts([], {}, [], [], None, None)

    recipe = data.get("recipe") if isinstance(data.get("recipe"), dict) else data

    src_urls: list[str] = []
    host_deps: list[str] = []
    build_deps: list[str] = []

    if "source" in recipe:
        _collect_source_urls(recipe["source"], src_urls)
    if "sources" in recipe:
        _collect_source_urls(recipe["sources"], src_urls)

    _collect_dep_lists(recipe.get("requirements"), host_deps, build_deps)

    # Multi-output recipes: walk each output for additional sources/deps.
    outputs = recipe.get("outputs") if isinstance(recipe.get("outputs"), list) else []
    for output in outputs:
        if not isinstance(output, dict):
            continue
        if "source" in output:
            _collect_source_urls(output["source"], src_urls)
        _collect_dep_lists(output.get("requirements"), host_deps, build_deps)

    about = recipe.get("about") or data.get("about")
    about_urls: dict[str, str] = {}
    summary: str | None = None
    if isinstance(about, dict):
        for key in ("homepage", "home", "dev_url", "repository", "doc_url"):
            value = about.get(key)
            if isinstance(value, str):
                about_urls.setdefault(key, value)
            elif isinstance(value, list) and value and isinstance(value[0], str):
                about_urls.setdefault(key, value[0])
        if isinstance(about.get("summary"), str):
            summary = about["summary"]

    noarch: str | None = None
    build_block = recipe.get("build") if isinstance(recipe.get("build"), dict) else None
    if isinstance(build_block, dict):
        n = build_block.get("noarch")
        if isinstance(n, str):
            noarch = n
        # rattler-build form: build.python.noarch / build.noarch can be bool
        if noarch is None and isinstance(n, bool) and n:
            noarch = "generic"

    _ = kind  # currently informational; both shapes converge above
    return RecipeFacts(
        source_urls=src_urls,
        about_urls=about_urls,
        host_deps=host_deps,
        build_deps=build_deps,
        noarch=noarch,
        summary=summary,
    )


async def _fetch_about(
    client: Client, url: str
) -> tuple[list[str], list[str], list[str]]:
    """Return (homepage_urls, repo_urls, doc_urls) from info/about.json."""
    about = await AboutJson.from_remote_url(client, url)
    homepage = [str(u) for u in (about.home or [])]
    repo = [str(u) for u in (about.dev_url or [])]
    doc = [str(u) for u in (about.doc_url or [])]
    return homepage, repo, doc


async def _fetch_rendered_recipe(client: Client, url: str) -> tuple[str, str] | None:
    """Return (recipe_text, recipe_kind) where kind is "rattler-build" or
    "conda-build". rattler-build packages carry ``rendered_recipe.yaml`` with a
    different nesting (everything under a top-level ``recipe:`` key) than
    conda-build's ``meta.yaml``.
    """
    candidates = (
        ("info/recipe/rendered_recipe.yaml", "rattler-build"),
        ("info/recipe/recipe.yaml", "rattler-build"),
        ("info/recipe/meta.yaml", "conda-build"),
    )
    for inner, kind in candidates:
        try:
            data = await fetch_raw_package_file_from_url(client, url, inner)
        except Exception:
            continue
        return data.decode("utf-8", errors="replace"), kind
    return None


async def _process_record(
    client: Client,
    record: RepoDataRecord,
    *,
    semaphore: asyncio.Semaphore,
) -> AutoEntry:
    name = record.name.normalized
    url = str(record.url)

    async with semaphore:
        rendered = await _fetch_rendered_recipe(client, url)
        try:
            home, repo, _doc = await _fetch_about(client, url)
        except Exception:
            home, repo, _doc = [], [], []

    if rendered is not None:
        text, kind = rendered
        facts = _extract_recipe_facts(text, kind=kind)
    else:
        facts = RecipeFacts([], {}, [], [], None, None)

    homepage = (
        (home[0] if home else None)
        or facts.about_urls.get("homepage")
        or facts.about_urls.get("home")
    )
    repo_url = (
        (repo[0] if repo else None)
        or facts.about_urls.get("repository")
        or facts.about_urls.get("dev_url")
    )

    candidate_urls = [u for u in facts.source_urls if u]
    if repo_url:
        candidate_urls.append(repo_url)
    if homepage:
        candidate_urls.append(homepage)

    context = derive_recipe_context(
        conda_name=name,
        host_deps=facts.host_deps,
        build_deps=facts.build_deps,
        noarch=facts.noarch,
    )
    candidates: list[PurlGuess] = infer_all(candidate_urls, context=context)
    primary: PurlGuess | None = candidates[0] if candidates else None
    alternates = [
        {
            "purl": c.purl,
            "type": c.type,
            "namespace": c.namespace,
            "pkg_name": c.pkg_name,
            "confidence": c.confidence,
            "source": c.source,
        }
        for c in candidates[1:]
    ]

    note: str | None = None
    if primary is None:
        note = "No automatic match — heuristics did not recognise any source URL."

    primary_source = next((u for u in facts.source_urls if u), None)
    return AutoEntry(
        name=name,
        version=str(record.version),
        build=record.build,
        subdir=record.subdir,
        url=url,
        purl=primary.purl if primary else None,
        type=primary.type if primary else None,
        namespace=primary.namespace if primary else None,
        pkg_name=primary.pkg_name if primary else None,
        confidence=primary.confidence if primary else 0.0,
        sources=[primary.source] if primary else [],
        homepage=homepage,
        repo=repo_url,
        recipe_url=f"https://github.com/conda-forge/{name}-feedstock/blob/main/recipe/meta.yaml",
        summary=facts.summary,
        source_url=primary_source,
        alternative_purls=alternates if alternates else None,
        note=note,
        fetched_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )


async def _gather_records(
    *, channel: str, platforms: Iterable[str], names: Iterable[str] | None = None
) -> list[RepoDataRecord]:
    gateway = Gateway(
        default_config=SourceConfig(sharded_enabled=True, cache_action="cache-or-fetch"),
        show_progress=False,
    )
    platform_objs = [Platform(p) for p in platforms]

    if names:
        specs = list(names)
    else:
        all_names = await gateway.names(sources=[channel], platforms=platform_objs)
        specs = sorted({n.normalized for n in all_names})
        console.log(f"Discovered [bold]{len(specs):,}[/] package names on {channel}")

    by_source = await gateway.query(
        sources=[channel], platforms=platform_objs, specs=specs, recursive=False
    )

    by_name: dict[str, list[RepoDataRecord]] = {}
    for source_records in by_source:
        for record in source_records:
            by_name.setdefault(record.name.normalized, []).append(record)

    latest: list[RepoDataRecord] = []
    for name, records in by_name.items():
        pick = _pick_latest(records)
        if pick is not None:
            latest.append(pick)
    return latest


def _load_existing(out_path: Path) -> dict[str, AutoEntry]:
    if not out_path.exists():
        return {}
    try:
        payload = json.loads(out_path.read_text())
    except json.JSONDecodeError:
        return {}
    entries: dict[str, AutoEntry] = {}
    for name, raw in payload.get("packages", {}).items():
        try:
            entries[name] = AutoEntry(**raw)
        except TypeError:
            continue
    return entries


def _write_out(out_path: Path, entries: dict[str, AutoEntry]) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "channel": DEFAULT_CHANNEL,
        "package_count": len(entries),
        "packages": {name: asdict(entry) for name, entry in sorted(entries.items())},
    }
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")


@app.command()
def main(
    out: Path = typer.Option(DEFAULT_OUT, help="Output JSON file"),
    channel: str = typer.Option(DEFAULT_CHANNEL, help="conda channel"),
    platforms: list[str] = typer.Option(
        list(DEFAULT_PLATFORMS), help="platforms to scan"
    ),
    limit: int | None = typer.Option(
        None, help="Process at most N packages (test runs)"
    ),
    only: str | None = typer.Option(
        None, help="Comma-separated names to process (test runs)"
    ),
    parallel: int = typer.Option(20, help="parallel inflight recipe fetches"),
    force: bool = typer.Option(
        False, help="Re-fetch all packages, ignoring the cache"
    ),
) -> None:
    """Generate or refresh the auto mapping JSON."""
    asyncio.run(
        _async_main(
            out=out,
            channel=channel,
            platforms=platforms,
            limit=limit,
            only=only.split(",") if only else None,
            parallel=parallel,
            force=force,
        )
    )


async def _async_main(
    *,
    out: Path,
    channel: str,
    platforms: list[str],
    limit: int | None,
    only: list[str] | None,
    parallel: int,
    force: bool,
) -> None:
    started = time.monotonic()
    existing = {} if force else _load_existing(out)
    console.log(f"Loaded {len(existing):,} cached entries from {out}")

    records = await _gather_records(channel=channel, platforms=platforms, names=only)
    if limit is not None:
        records = sorted(records, key=lambda r: r.name.normalized)[:limit]
    console.log(f"Latest records to consider: [bold]{len(records):,}[/]")

    needs_fetch: list[RepoDataRecord] = []
    cache_hits: list[RepoDataRecord] = []
    for record in records:
        prior = existing.get(record.name.normalized)
        if (
            not force
            and prior is not None
            and prior.version == str(record.version)
            and prior.build == record.build
        ):
            cache_hits.append(record)
            continue
        needs_fetch.append(record)
    console.log(
        f"Cache hits: {len(cache_hits):,} • need fresh fetch: [bold]{len(needs_fetch):,}[/]"
    )

    client = Client()
    semaphore = asyncio.Semaphore(parallel)

    new_entries: dict[str, AutoEntry] = dict(existing)

    if needs_fetch:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Fetching recipes…", total=len(needs_fetch))

            async def runner(record: RepoDataRecord) -> AutoEntry:
                try:
                    return await _process_record(
                        client, record, semaphore=semaphore
                    )
                except Exception as exc:  # noqa: BLE001
                    return AutoEntry(
                        name=record.name.normalized,
                        version=str(record.version),
                        build=record.build,
                        subdir=record.subdir,
                        url=str(record.url),
                        purl=None,
                        type=None,
                        namespace=None,
                        pkg_name=None,
                        confidence=0.0,
                        sources=[],
                        homepage=None,
                        repo=None,
                        recipe_url=None,
                        summary=None,
                        note=f"fetch error: {exc}",
                        fetched_at=datetime.now(UTC).isoformat(timespec="seconds"),
                    )
                finally:
                    progress.advance(task)

            results = await asyncio.gather(*(runner(r) for r in needs_fetch))
            for entry in results:
                new_entries[entry.name] = entry

    # Drop entries for packages that disappeared from the channel
    if not only and not limit:
        live_names = {r.name.normalized for r in records}
        for stale in [n for n in new_entries if n not in live_names]:
            del new_entries[stale]

    _write_out(out, new_entries)
    elapsed = time.monotonic() - started
    mapped = sum(1 for e in new_entries.values() if e.purl)
    console.log(
        f"Wrote [bold]{len(new_entries):,}[/] entries to {out} "
        f"({mapped:,} mapped, {len(new_entries) - mapped:,} unmapped) in {elapsed:.1f}s"
    )


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)
