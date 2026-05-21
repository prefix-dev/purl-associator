"""Backfill ``download_count`` on every entry in ``mappings/auto.json``
using prefix.dev's ``Package.totalCount``.

Fetches the full ranking once (one full GraphQL paginated walk), then
joins by package name. Names that aren't visible on prefix.dev get
``download_count: null`` so downstream code can distinguish "no data" from
"zero downloads".
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import typer
from rich.console import Console

from scripts.top_downloads import (
    DEFAULT_CHANNEL,
    DEFAULT_ENDPOINT,
    fetch_all,
)

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"


async def _hydrate(
    *,
    auto: Path,
    channel: str,
    endpoint: str,
    concurrency: int,
) -> None:
    started = time.monotonic()

    rows = await fetch_all(endpoint, channel, concurrency)
    counts: dict[str, int] = {r.name: r.total_count for r in rows}
    console.log(
        f"Fetched [bold]{len(counts):,}[/] (name, totalCount) rows from prefix.dev"
    )

    data = json.loads(auto.read_text())
    packages = data.get("packages", {})
    if not isinstance(packages, dict) or not packages:
        raise typer.BadParameter(f"{auto} has no packages — run automap first.")

    hits = misses = changed = 0
    for name, entry in packages.items():
        new_count = counts.get(name)
        old_count = entry.get("download_count")
        if new_count is None:
            misses += 1
        else:
            hits += 1
        if new_count != old_count:
            entry["download_count"] = new_count
            changed += 1

    auto.write_text(json.dumps(data, indent=2) + "\n")

    elapsed = time.monotonic() - started
    console.log(
        f"Hydrated {len(packages):,} entries → {hits:,} with counts · "
        f"{misses:,} unknown · {changed:,} changed ({elapsed:.1f}s)"
    )


@app.command()
def main(
    auto: Path = typer.Option(DEFAULT_AUTO, help="auto.json path"),
    channel: str = typer.Option(DEFAULT_CHANNEL, help="prefix.dev channel"),
    endpoint: str = typer.Option(DEFAULT_ENDPOINT, help="GraphQL endpoint"),
    concurrency: int = typer.Option(16, help="Max concurrent GraphQL page requests"),
) -> None:
    asyncio.run(
        _hydrate(auto=auto, channel=channel, endpoint=endpoint, concurrency=concurrency)
    )


if __name__ == "__main__":
    app()
