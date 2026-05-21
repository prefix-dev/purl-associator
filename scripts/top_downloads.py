"""Shrink ``mappings/auto.json`` to the top-N most-downloaded conda-forge
packages on prefix.dev.

Steps:
1. Page through ``channel(name: "conda-forge").packages`` on the prefix.dev
   public GraphQL API, collecting ``(name, totalCount)`` for every package.
2. Sort by ``totalCount`` descending and keep the top ``--limit`` names.
3. Invoke ``scripts.automap`` with ``--only <names>`` so each gets a fresh
   PURL inference (the automap cache handles unchanged entries).
4. Filter ``mappings/auto.json`` down to just those names — ``automap.py``
   skips its drop-stale step when ``--only`` is set, so we prune here.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

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
DEFAULT_NAMES_OUT = ROOT / "mappings" / "top_downloads.json"
DEFAULT_ENDPOINT = "https://prefix.dev/api/graphql"
DEFAULT_CHANNEL = "conda-forge"

PAGE_SIZE = 50

PAGE_QUERY = """
query($channel: String!, $limit: Int!, $page: Int!) {
  channel(name: $channel) {
    packages(limit: $limit, page: $page) {
      pages
      totalCount
      page { name totalCount }
    }
  }
}
""".strip()


@dataclass
class PackageRank:
    name: str
    total_count: int


async def fetch_page(
    client: httpx.AsyncClient,
    endpoint: str,
    channel: str,
    page: int,
) -> tuple[int, int, list[PackageRank]]:
    """Return ``(total_pages, total_packages, rows)`` for one page."""
    resp = await client.post(
        endpoint,
        json={
            "query": PAGE_QUERY,
            "variables": {"channel": channel, "limit": PAGE_SIZE, "page": page},
        },
    )
    resp.raise_for_status()
    payload = resp.json()
    if payload.get("errors"):
        raise RuntimeError(f"GraphQL errors on page {page}: {payload['errors']}")
    pkgs = payload["data"]["channel"]["packages"]
    rows = [
        PackageRank(name=p["name"], total_count=p.get("totalCount") or 0)
        for p in pkgs["page"]
    ]
    return pkgs["pages"], pkgs["totalCount"], rows


async def fetch_all(endpoint: str, channel: str, concurrency: int) -> list[PackageRank]:
    timeout = httpx.Timeout(connect=15.0, read=60.0, write=15.0, pool=15.0)
    limits = httpx.Limits(
        max_connections=concurrency, max_keepalive_connections=concurrency
    )
    async with httpx.AsyncClient(timeout=timeout, limits=limits, http2=False) as client:
        total_pages, total_packages, first_rows = await fetch_page(
            client, endpoint, channel, page=0
        )
        console.log(
            f"Channel [bold]{channel}[/]: {total_packages:,} packages across "
            f"{total_pages:,} pages of {PAGE_SIZE}"
        )

        all_rows: list[PackageRank] = list(first_rows)
        if total_pages <= 1:
            return all_rows

        semaphore = asyncio.Semaphore(concurrency)

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task("Paging prefix.dev…", total=total_pages - 1)

            async def runner(page: int) -> list[PackageRank]:
                async with semaphore:
                    for attempt in range(4):
                        try:
                            _, _, rows = await fetch_page(
                                client, endpoint, channel, page
                            )
                            progress.advance(task)
                            return rows
                        except (httpx.HTTPError, RuntimeError) as exc:
                            if attempt == 3:
                                raise
                            await asyncio.sleep(0.5 * (2**attempt))
                            console.log(
                                f"[yellow]retry page {page} ({exc.__class__.__name__})[/]"
                            )
                    return []

            results = await asyncio.gather(*(runner(p) for p in range(1, total_pages)))

        for rows in results:
            all_rows.extend(rows)
        return all_rows


def select_top(rows: list[PackageRank], limit: int) -> list[PackageRank]:
    # Tie-break by name so the output is deterministic when many packages
    # share totalCount == 0.
    rows.sort(key=lambda r: (-r.total_count, r.name))
    return rows[:limit]


async def fetch_top_names(
    limit: int,
    channel: str = DEFAULT_CHANNEL,
    endpoint: str = DEFAULT_ENDPOINT,
    concurrency: int = 16,
) -> list[str]:
    """Return the top-``limit`` package names on ``channel``, ranked by
    ``Package.totalCount`` on prefix.dev (descending)."""
    rows = await fetch_all(endpoint, channel, concurrency)
    return [r.name for r in select_top(rows, limit)]


def _write_names(out: Path, channel: str, picked: list[PackageRank]) -> None:
    payload = {
        "schema_version": 1,
        "channel": channel,
        "source": "prefix.dev GraphQL (Package.totalCount)",
        "limit": len(picked),
        "packages": [{"name": r.name, "total_count": r.total_count} for r in picked],
    }
    out.write_text(json.dumps(payload, indent=2) + "\n")


def _run_automap(names: list[str], extra_args: list[str]) -> None:
    only = ",".join(names)
    cmd = [
        sys.executable,
        "-m",
        "scripts.automap",
        "--only",
        only,
        *extra_args,
    ]
    console.log(
        f"Invoking automap on {len(names):,} names "
        f"({len(only):,} bytes of --only payload)"
    )
    subprocess.run(cmd, check=True, cwd=ROOT)


def _prune_auto(auto_path: Path, keep: set[str]) -> tuple[int, int]:
    """Drop entries from ``auto.json`` whose name is not in ``keep``."""
    data = json.loads(auto_path.read_text())
    packages = data.get("packages", {})
    before = len(packages)
    data["packages"] = {name: entry for name, entry in packages.items() if name in keep}
    data["package_count"] = len(data["packages"])
    auto_path.write_text(json.dumps(data, indent=2) + "\n")
    return before, len(data["packages"])


@app.command()
def main(
    limit: int = typer.Option(1000, help="How many top packages to keep"),
    channel: str = typer.Option(DEFAULT_CHANNEL, help="prefix.dev channel"),
    endpoint: str = typer.Option(DEFAULT_ENDPOINT, help="GraphQL endpoint"),
    concurrency: int = typer.Option(16, help="Max concurrent GraphQL page requests"),
    names_out: Path = typer.Option(
        DEFAULT_NAMES_OUT,
        help="Where to write the ranked top-N list (audit artifact)",
    ),
    auto: Path = typer.Option(DEFAULT_AUTO, help="auto.json path to refresh + prune"),
    skip_automap: bool = typer.Option(
        False,
        "--skip-automap",
        help="Only fetch + write the ranked list; do not run automap or prune auto.json",
    ),
    automap_arg: list[str] = typer.Option(
        [],
        "--automap-arg",
        help="Extra arg forwarded to automap (repeatable, e.g. --automap-arg --parallel --automap-arg 40)",
    ),
) -> None:
    started = time.monotonic()

    rows = asyncio.run(fetch_all(endpoint, channel, concurrency))
    console.log(f"Collected [bold]{len(rows):,}[/] rows from prefix.dev")

    picked = select_top(rows, limit)
    if not picked:
        raise typer.Exit("No packages returned from prefix.dev")

    _write_names(names_out, channel, picked)
    top = picked[0]
    last = picked[-1]
    console.log(
        f"Top: {top.name} ({top.total_count:,}) · "
        f"#{len(picked)}: {last.name} ({last.total_count:,})"
    )
    console.log(f"Wrote ranked list → {names_out}")

    if skip_automap:
        console.log("[yellow]--skip-automap set; leaving auto.json untouched[/]")
        return

    names = [r.name for r in picked]
    _run_automap(names, automap_arg)
    before, after = _prune_auto(auto, set(names))
    console.log(
        f"Pruned {auto}: {before:,} → [bold]{after:,}[/] entries "
        f"(dropped {before - after:,})"
    )
    console.log(f"Total elapsed: {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    app()
