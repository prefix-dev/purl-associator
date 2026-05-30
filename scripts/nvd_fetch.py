"""Download and index NVD's CVE 2.0 JSON feeds.

NVD publishes ``nvdcve-2.0-<year>.json.gz`` files for every year from 2002
onward, plus a rolling ``nvdcve-2.0-modified.json.gz`` (last 8 days of adds
and updates). Each archive contains the same shape the REST API returns —
``{vulnerabilities: [{cve: {...}}, ...]}`` — so the consumer-facing record
is byte-identical to ``scripts.nvd_prototype._fetch_nvd``'s old output.

This module:

1. Walks the year sequence 2002 → present, fetching each yearly file when
   the local cache's sha256 doesn't match the published ``.meta`` digest.
2. Fetches the ``modified`` feed if older than ``max_modified_age_hours``.
3. Builds an in-memory index keyed by ``(part, vendor, product)`` →
   ``[cve, ...]``. Each ``cpeMatch`` entry the CVE references contributes
   one entry to the index, so the same CVE can be reached via several keys.
4. Exposes :meth:`NvdIndex.for_cpe` for prefix-style lookups
   (``cpe:2.3:a:gnu:ncurses`` → ``[cve, ...]``).

Used by :mod:`scripts.nvd_prototype`. Can also be run standalone to refresh
the cache:

    pixi run python -m scripts.nvd_fetch --cache-dir ./nvd_cache
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import json
import re
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / "nvd_cache"

FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
MODIFIED_FEED = "modified"
FIRST_YEAR = 2002

# CPE 2.3 strings look like ``cpe:2.3:<part>:<vendor>:<product>:<rest>``.
# We only need the three identifying segments to key our index.
_CPE_HEAD = re.compile(r"^cpe:2\.3:([aoh]):([^:]+):([^:]+):")


# ---------- cache primitives ----------


@dataclass
class FeedFile:
    """One yearly or modified feed file on disk."""

    name: str  # e.g. "2024" or "modified"
    path: Path
    sha256: str
    fetched_at: float
    cve_count: int


def _gz_path(cache_dir: Path, name: str) -> Path:
    return cache_dir / f"nvdcve-2.0-{name}.json.gz"


def _meta_path(cache_dir: Path, name: str) -> Path:
    return cache_dir / f"nvdcve-2.0-{name}.meta"


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def _parse_meta(text: str) -> dict[str, str]:
    """The .meta sidecar is ``key:value`` lines; values like
    ``sha256:44E247...`` are documented uppercase hex."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


# ---------- download ----------


async def _fetch_meta(client: httpx.AsyncClient, name: str) -> dict[str, str] | None:
    """Pull the .meta sidecar. Returns ``None`` for 404 (used to detect the
    year-range upper bound: NVD returns 404 for years it hasn't reached)."""
    url = f"{FEED_BASE}/nvdcve-2.0-{name}.meta"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise RuntimeError(f"NVD .meta fetch failed for {name}: {resp.status_code}")
    return _parse_meta(resp.text)


async def _download_feed(
    client: httpx.AsyncClient,
    name: str,
    cache_dir: Path,
    progress: Progress,
    expected_sha256: str | None,
) -> Path:
    """Download ``nvdcve-2.0-<name>.json.gz`` if the local sha256 doesn't
    match ``expected_sha256``. Otherwise reuse the cached file."""
    target = _gz_path(cache_dir, name)
    if expected_sha256 and target.exists() and _sha256_of(target) == expected_sha256:
        return target  # cache hit — same content, skip the network

    url = f"{FEED_BASE}/nvdcve-2.0-{name}.json.gz"
    tmp = target.with_suffix(".gz.partial")
    task_id = progress.add_task(f"NVD {name}", start=False)
    async with client.stream("GET", url, follow_redirects=True) as resp:
        if resp.status_code != 200:
            progress.update(task_id, visible=False)
            raise RuntimeError(
                f"NVD feed download failed for {name}: {resp.status_code}"
            )
        total = int(resp.headers.get("Content-Length") or 0) or None
        progress.update(task_id, total=total)
        progress.start_task(task_id)
        tmp.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("wb") as fp:
            async for chunk in resp.aiter_bytes(chunk_size=1 << 16):
                fp.write(chunk)
                progress.update(task_id, advance=len(chunk))
    tmp.replace(target)
    progress.update(task_id, visible=False)
    return target


async def _discover_year_range(client: httpx.AsyncClient) -> list[int]:
    """Walk forward from FIRST_YEAR until NVD returns 404 — that's the
    first year with no feed yet. The result is FIRST_YEAR .. last published."""
    years: list[int] = []
    year = FIRST_YEAR
    while True:
        meta = await _fetch_meta(client, str(year))
        if meta is None:
            break
        years.append(year)
        year += 1
        if year > 2100:  # safety: bail rather than loop forever
            break
    return years


async def fetch_feeds(
    *,
    cache_dir: Path = DEFAULT_CACHE,
    force: bool = False,
    max_modified_age_hours: float = 2.0,
) -> list[FeedFile]:
    """Refresh the local feed cache and return a manifest of files on disk.

    Each call:

    * Fetches every yearly ``.meta`` sidecar.
    * Re-downloads a yearly ``.json.gz`` only when its sha256 changed.
    * Re-downloads the ``modified`` feed if its local cache is older than
      ``max_modified_age_hours``. (NVD's modified feed rolls roughly every
      2 hours.)

    ``force=True`` bypasses both freshness checks.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    timeout = httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=15.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        years = await _discover_year_range(client)
        names: list[tuple[str, str | None]] = []  # (name, expected_sha256)
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            for year in years:
                meta = await _fetch_meta(client, str(year))
                expected = (meta or {}).get("sha256") if not force else None
                names.append((str(year), expected))

            # Modified feed: only re-download when older than max_modified_age_hours.
            mod_target = _gz_path(cache_dir, MODIFIED_FEED)
            mod_age_h = (
                (time.time() - mod_target.stat().st_mtime) / 3600
                if mod_target.exists()
                else float("inf")
            )
            if force or mod_age_h >= max_modified_age_hours:
                meta = await _fetch_meta(client, MODIFIED_FEED)
                expected = (meta or {}).get("sha256") if not force else None
                names.append((MODIFIED_FEED, expected))

            results: list[FeedFile] = []
            for name, expected in names:
                path = await _download_feed(client, name, cache_dir, progress, expected)
                results.append(
                    FeedFile(
                        name=name,
                        path=path,
                        sha256=_sha256_of(path),
                        fetched_at=time.time(),
                        cve_count=0,  # filled by the index builder
                    )
                )
    # If we skipped the modified feed (cache fresh), still report it so the
    # index builder doesn't miss recent records.
    if all(f.name != MODIFIED_FEED for f in results) and mod_target.exists():
        results.append(
            FeedFile(
                name=MODIFIED_FEED,
                path=mod_target,
                sha256=_sha256_of(mod_target),
                fetched_at=mod_target.stat().st_mtime,
                cve_count=0,
            )
        )
    return results


# ---------- indexing ----------


def _iter_cves_in_feed(path: Path) -> Iterator[dict]:
    """Yield each ``cve`` dict from one feed file. The on-disk shape is
    ``{vulnerabilities: [{cve: {...}}, ...]}`` — the same envelope the
    REST API returns."""
    with gzip.open(path, "rb") as fp:
        # Feed files are <10 MB gzipped (<100 MB uncompressed) — small
        # enough to slurp in one shot.
        data = json.loads(fp.read())
    for entry in data.get("vulnerabilities") or []:
        cve = entry.get("cve")
        if isinstance(cve, dict) and isinstance(cve.get("id"), str):
            yield cve


def _cpe_head(criteria: str) -> tuple[str, str, str] | None:
    """Extract ``(part, vendor, product)`` from a CPE 2.3 string. Used as
    the index key. Returns ``None`` for malformed CPEs."""
    m = _CPE_HEAD.match(criteria)
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _cve_cpe_heads(cve: dict) -> set[tuple[str, str, str]]:
    """All distinct ``(part, vendor, product)`` triples this CVE references.

    A single CVE can carry dozens of cpeMatches (one per affected version
    snapshot). They usually share the same (part, vendor, product), so the
    set is much smaller than the cpeMatch count."""
    heads: set[tuple[str, str, str]] = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for cm in node.get("cpeMatch") or []:
                criteria = cm.get("criteria")
                if not isinstance(criteria, str):
                    continue
                head = _cpe_head(criteria)
                if head is not None:
                    heads.add(head)
    return heads


@dataclass
class NvdIndex:
    """In-memory map ``(part, vendor, product) → [cve, ...]``. Each CVE
    can appear under multiple keys (e.g. an ncurses CVE that lists both
    ``gnu:ncurses`` and ``invisible-island:ncurses`` cpeMatches).

    The same CVE id is stored only once across all its keys — duplicates
    arising from the ``modified`` feed overwriting yearly entries are
    handled by the builder before insertion."""

    feeds: list[FeedFile]
    by_pp: dict[tuple[str, str, str], list[dict]] = field(default_factory=dict)
    by_id: dict[str, dict] = field(default_factory=dict)
    # Secondary index: product → list of (part, vendor, product) heads with
    # that exact product segment. Built once by ``_build_index`` so
    # ``products_matching`` is O(1) lookup instead of an O(|by_pp|) scan.
    by_product: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)

    def for_cpe(self, cpe: str) -> list[dict]:
        """Return all CVEs whose ``cpeMatch.criteria`` shares the
        ``(part, vendor, product)`` prefix of ``cpe``.

        Accepts both bare prefixes (``cpe:2.3:a:gnu:ncurses``) and fully
        qualified strings — only the part/vendor/product segments matter."""
        # Allow trailing segments for either form: tack on `:` so the regex
        # always finds at least four colons.
        head = _cpe_head(cpe if cpe.count(":") >= 5 else cpe + ":*:*:*:*:*:*:*")
        if head is None:
            return []
        return list(self.by_pp.get(head, []))

    def products_matching(self, product: str) -> list[tuple[str, str, str]]:
        """All ``(part, vendor, product)`` keys whose ``product`` segment
        equals ``product`` exactly. Used by candidate discovery: given a
        normalized conda name, return every CPE prefix NVD knows about
        with that product, across all vendors."""
        return list(self.by_product.get(product, ()))

    def github_url_hit_rate(self, head: tuple[str, str, str], owner_repo: str) -> float:
        """Fraction of CVEs at ``head`` whose ``references[].url`` contains
        ``owner_repo`` (e.g. ``"openssl/openssl"``). Heuristic H1: a high
        hit rate is strong evidence the CPE identifies the same upstream
        as the conda package's GitHub PURL."""
        cves = self.by_pp.get(head) or []
        if not cves:
            return 0.0
        needle = owner_repo.lower()
        hits = 0
        for cve in cves:
            refs = cve.get("references") or []
            for r in refs:
                url = r.get("url") if isinstance(r, dict) else None
                if isinstance(url, str) and needle in url.lower():
                    hits += 1
                    break
        return hits / len(cves)

    def total_cves(self) -> int:
        return len(self.by_id)


def _build_index(feeds: list[FeedFile]) -> NvdIndex:
    """Walk every feed file and bucket each CVE by its CPE heads.

    Order matters: the ``modified`` feed is applied last so its records
    overwrite older yearly versions of the same CVE id. Re-insertion
    rebuilds the (part, vendor, product) buckets for that CVE."""
    yearly = [f for f in feeds if f.name != MODIFIED_FEED]
    modified = [f for f in feeds if f.name == MODIFIED_FEED]

    by_pp: dict[tuple[str, str, str], list[dict]] = {}
    by_id: dict[str, dict] = {}

    def _insert(cve: dict) -> None:
        cid = cve["id"]
        if cid in by_id:
            # Drop the older copy from every bucket that holds it.
            old = by_id[cid]
            for head in _cve_cpe_heads(old):
                bucket = by_pp.get(head)
                if bucket is not None:
                    bucket[:] = [c for c in bucket if c["id"] != cid]
        by_id[cid] = cve
        for head in _cve_cpe_heads(cve):
            by_pp.setdefault(head, []).append(cve)

    # Yearly first, modified last.
    for feed in yearly + modified:
        count = 0
        for cve in _iter_cves_in_feed(feed.path):
            _insert(cve)
            count += 1
        feed.cve_count = count

    # Secondary product → heads index, built once now that by_pp is final.
    by_product: dict[str, list[tuple[str, str, str]]] = {}
    for head in by_pp:
        by_product.setdefault(head[2], []).append(head)

    return NvdIndex(feeds=feeds, by_pp=by_pp, by_id=by_id, by_product=by_product)


async def fetch_index(
    *,
    cache_dir: Path = DEFAULT_CACHE,
    force: bool = False,
    max_modified_age_hours: float = 2.0,
) -> NvdIndex:
    """End-to-end: refresh the cache and build a queryable index."""
    feeds = await fetch_feeds(
        cache_dir=cache_dir,
        force=force,
        max_modified_age_hours=max_modified_age_hours,
    )
    index = _build_index(feeds)
    return index


# ---------- CLI ----------


@app.command()
def main(
    cache_dir: Path = typer.Option(DEFAULT_CACHE, help="Where to store NVD feed files"),
    force: bool = typer.Option(
        False, help="Re-download every feed regardless of sha256"
    ),
    max_modified_age_hours: float = typer.Option(
        2.0, help="Re-download the modified feed if older than this"
    ),
) -> None:
    """Refresh the NVD feed cache and print a summary."""

    async def _run() -> None:
        index = await fetch_index(
            cache_dir=cache_dir,
            force=force,
            max_modified_age_hours=max_modified_age_hours,
        )
        console.log(
            f"Indexed [bold]{index.total_cves():,}[/] CVEs across "
            f"{len(index.feeds)} feed file(s), {len(index.by_pp):,} distinct "
            f"(part, vendor, product) keys."
        )
        # Friendly sample
        sample = next(iter(index.by_pp.items()), None)
        if sample:
            head, cves = sample
            console.log(f"sample key {head}: {len(cves)} CVE(s)")

    asyncio.run(_run())


if __name__ == "__main__":
    app()
