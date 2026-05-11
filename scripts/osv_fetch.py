"""Download and index the OSV vulnerability dumps.

OSV publishes per-ecosystem zips at
``https://osv-vulnerabilities.storage.googleapis.com/<ECOSYSTEM>/all.zip``.
Each archive contains one JSON file per advisory. We download the dumps for
the ecosystems we emit PURLs against (PyPI, npm, crates.io, RubyGems, Maven,
Go, CRAN), then build an in-memory index keyed by ``(ecosystem, normalized
name)`` → list of advisories.

Used directly by :mod:`scripts.cve_match`. Can be run standalone to refresh
the cache:

    pixi run python -m scripts.osv_fetch --cache-dir ./osv_cache
"""

from __future__ import annotations

import asyncio
import json
import time
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
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

from scripts.purl_inference import normalize_pypi_name

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / "osv_cache"

# PURL type → OSV ecosystem path segment. OSV is case-sensitive about these:
# the bucket really does have "PyPI", "crates.io" with the dot, etc.
PURL_TO_OSV: dict[str, str] = {
    "pypi": "PyPI",
    "npm": "npm",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "maven": "Maven",
    "golang": "Go",
    "cran": "CRAN",
}

# Reverse direction: OSV ecosystem string → our PURL type. OSV occasionally
# reports the ecosystem with a qualifier (``Maven:org.apache``), so we also
# match a prefix before the colon.
OSV_TO_PURL: dict[str, str] = {v: k for k, v in PURL_TO_OSV.items()}


def osv_zip_url(ecosystem: str) -> str:
    # The bucket URL-encodes the ecosystem segment (``crates.io`` is fine,
    # but a ``:`` qualifier would need encoding). For the seven names above
    # we never need encoding.
    return f"https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"


# ---------- normalization ----------


def normalize_name(ecosystem: str, name: str) -> str:
    """Normalize a package name to whatever form we use for index lookups.

    Each ecosystem has its own canonicalization rules; the goal here is just
    to agree with what :mod:`scripts.purl_inference` produces for the same
    package so the index lookup hits.
    """
    if ecosystem == "PyPI":
        return normalize_pypi_name(name)
    if ecosystem == "npm":
        # npm names are case-insensitive but lookups should be lowercase.
        return name.lower()
    if ecosystem == "crates.io":
        # Crate names are case-insensitive in the registry; the canonical
        # form is lowercase with underscores preserved (no ``-``/``_`` fold).
        return name.lower()
    if ecosystem == "RubyGems":
        return name.lower()
    if ecosystem == "Go":
        # Go module paths are case-sensitive; only fold for lookups in a
        # case-insensitive way against our heuristic-derived name.
        return name
    if ecosystem == "CRAN":
        # CRAN is case-sensitive, but for our matching it's safer to fold —
        # conda often lowercases ``r-`` package names.
        return name.lower()
    if ecosystem.startswith("Maven"):
        return name  # group:artifact form, case preserved
    return name


def osv_ecosystem_for_purl_type(purl_type: str) -> str | None:
    return PURL_TO_OSV.get(purl_type)


# ---------- download + cache ----------


@dataclass
class CachedDump:
    ecosystem: str
    path: Path
    size: int
    fetched_at: float
    advisory_count: int


async def _download_one(
    client: httpx.AsyncClient,
    ecosystem: str,
    cache_dir: Path,
    progress: Progress,
) -> CachedDump:
    url = osv_zip_url(ecosystem)
    target = cache_dir / f"{ecosystem}.zip"
    tmp = target.with_suffix(".zip.partial")
    task_id = progress.add_task(f"OSV {ecosystem}", start=False)

    async with client.stream("GET", url, follow_redirects=True) as resp:
        if resp.status_code != 200:
            progress.update(task_id, visible=False)
            raise RuntimeError(
                f"OSV download failed for {ecosystem}: {resp.status_code}"
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

    size = target.stat().st_size
    # Quickly peek into the zip to count entries — gives users a sanity-check
    # number in the summary without forcing a full re-read later.
    with zipfile.ZipFile(target) as zf:
        count = sum(1 for n in zf.namelist() if n.endswith(".json"))
    return CachedDump(
        ecosystem=ecosystem,
        path=target,
        size=size,
        fetched_at=time.time(),
        advisory_count=count,
    )


async def _download_all(
    ecosystems: Iterable[str], cache_dir: Path, force: bool, max_age_hours: float
) -> list[CachedDump]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    fresh: list[CachedDump] = []
    needs: list[str] = []
    now = time.time()
    for eco in ecosystems:
        target = cache_dir / f"{eco}.zip"
        if not force and target.exists():
            age = (now - target.stat().st_mtime) / 3600
            if age < max_age_hours:
                with zipfile.ZipFile(target) as zf:
                    count = sum(1 for n in zf.namelist() if n.endswith(".json"))
                fresh.append(
                    CachedDump(
                        ecosystem=eco,
                        path=target,
                        size=target.stat().st_size,
                        fetched_at=target.stat().st_mtime,
                        advisory_count=count,
                    )
                )
                continue
        needs.append(eco)

    if not needs:
        return fresh

    timeout = httpx.Timeout(connect=15.0, read=120.0, write=15.0, pool=15.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as progress:
            tasks = [_download_one(client, eco, cache_dir, progress) for eco in needs]
            results = await asyncio.gather(*tasks)
    return fresh + results


# ---------- indexing ----------


@dataclass
class Advisory:
    """One advisory as it pertains to a single ecosystem+name. We don't keep
    the full OSV record around; only the fields the matcher and the
    frontend need. ``raw_affected`` is the OSV ``affected[]`` entry that
    matched this package, preserved so the matcher can read the structured
    ranges + version lists."""

    id: str
    ecosystem: str
    name: str
    aliases: list[str]
    summary: str | None
    details: str | None
    published: str | None
    modified: str | None
    severity: list[dict]
    references: list[dict]
    raw_affected: dict

    def cve_ids(self) -> list[str]:
        return sorted({a for a in [*self.aliases, self.id] if a.startswith("CVE-")})

    def primary_id(self) -> str:
        # Prefer the human-friendly CVE id when present; fall back to the
        # native OSV id (GHSA/PYSEC/RUSTSEC/etc.).
        for c in self.cve_ids():
            return c
        return self.id


@dataclass
class OsvIndex:
    """Index of OSV advisories keyed by ``(ecosystem, normalized name)``."""

    dumps: list[CachedDump]
    # (ecosystem, normalized name) → list of Advisory
    by_pkg: dict[tuple[str, str], list[Advisory]]

    def for_purl(self, purl_type: str, name: str) -> list[Advisory]:
        eco = PURL_TO_OSV.get(purl_type)
        if not eco:
            return []
        key = (eco, normalize_name(eco, name))
        return self.by_pkg.get(key, [])

    def ecosystems(self) -> list[str]:
        return sorted({d.ecosystem for d in self.dumps})

    def total_advisories(self) -> int:
        return sum(len(v) for v in self.by_pkg.values())


def _iter_zip_jsons(path: Path) -> Iterable[dict]:
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            with zf.open(name) as fp:
                # OSV records are small (KB-range); read in one shot.
                try:
                    yield json.loads(fp.read())
                except json.JSONDecodeError:
                    continue


def _build_index(dumps: list[CachedDump]) -> dict[tuple[str, str], list[Advisory]]:
    by_pkg: dict[tuple[str, str], list[Advisory]] = {}
    for dump in dumps:
        for raw in _iter_zip_jsons(dump.path):
            adv_id = raw.get("id")
            if not isinstance(adv_id, str):
                continue
            aliases = [a for a in (raw.get("aliases") or []) if isinstance(a, str)]
            summary = (
                raw.get("summary") if isinstance(raw.get("summary"), str) else None
            )
            details = (
                raw.get("details") if isinstance(raw.get("details"), str) else None
            )
            published = (
                raw.get("published") if isinstance(raw.get("published"), str) else None
            )
            modified = (
                raw.get("modified") if isinstance(raw.get("modified"), str) else None
            )
            severity = (
                raw.get("severity") if isinstance(raw.get("severity"), list) else []
            )
            references = (
                raw.get("references") if isinstance(raw.get("references"), list) else []
            )

            for entry in raw.get("affected") or []:
                if not isinstance(entry, dict):
                    continue
                pkg = (
                    entry.get("package")
                    if isinstance(entry.get("package"), dict)
                    else None
                )
                if not pkg:
                    continue
                eco_raw = pkg.get("ecosystem")
                name = pkg.get("name")
                if not isinstance(eco_raw, str) or not isinstance(name, str):
                    continue
                # OSV may suffix Maven with the group ("Maven:org.apache"); the
                # zip we downloaded only contains records whose primary
                # ecosystem is the bucket's ecosystem, but the suffixed form
                # is still what shows up in the record. Normalize back to the
                # bucket's name so the index keys line up with PURL types.
                eco = eco_raw.split(":", 1)[0]
                if eco != dump.ecosystem and eco_raw != dump.ecosystem:
                    continue
                eco = dump.ecosystem
                key = (eco, normalize_name(eco, name))
                by_pkg.setdefault(key, []).append(
                    Advisory(
                        id=adv_id,
                        ecosystem=eco,
                        name=name,
                        aliases=aliases,
                        summary=summary,
                        details=details,
                        published=published,
                        modified=modified,
                        severity=severity,
                        references=references,
                        raw_affected=entry,
                    )
                )
    return by_pkg


async def fetch_index(
    *,
    cache_dir: Path = DEFAULT_CACHE,
    purl_types: Iterable[str] | None = None,
    force: bool = False,
    max_age_hours: float = 6.0,
) -> OsvIndex:
    """Download (or refresh) the OSV dumps for the requested PURL types and
    return a queryable index. ``max_age_hours`` controls when an existing
    cache file is considered too old to reuse."""
    if purl_types is None:
        ecosystems = list(PURL_TO_OSV.values())
    else:
        ecosystems = [PURL_TO_OSV[t] for t in purl_types if t in PURL_TO_OSV]
    if not ecosystems:
        return OsvIndex(dumps=[], by_pkg={})
    dumps = await _download_all(
        ecosystems, cache_dir=cache_dir, force=force, max_age_hours=max_age_hours
    )
    by_pkg = _build_index(dumps)
    return OsvIndex(dumps=dumps, by_pkg=by_pkg)


# ---------- CLI ----------


@app.command()
def main(
    cache_dir: Path = typer.Option(DEFAULT_CACHE, help="Where to store OSV dumps"),
    ecosystems: list[str] = typer.Option(
        list(PURL_TO_OSV.values()),
        "--ecosystem",
        "-e",
        help="OSV ecosystem name(s); defaults to all we use",
    ),
    force: bool = typer.Option(False, help="Re-download even if cache is fresh"),
    max_age_hours: float = typer.Option(
        6.0, help="Max cache age before a re-download is forced"
    ),
) -> None:
    """Refresh the OSV cache and print a summary."""
    started = time.monotonic()
    index = asyncio.run(
        _refresh(
            cache_dir=cache_dir,
            ecosystems=ecosystems,
            force=force,
            max_age_hours=max_age_hours,
        )
    )
    elapsed = time.monotonic() - started
    console.log(
        f"Indexed [bold]{index.total_advisories():,}[/] affected-package entries "
        f"across {len(index.dumps)} ecosystem(s) in {elapsed:.1f}s"
    )
    for d in index.dumps:
        size_mb = d.size / 1_000_000
        try:
            shown = d.path.resolve().relative_to(ROOT)
        except ValueError:
            shown = d.path
        console.log(
            f"  • {d.ecosystem:<12} {d.advisory_count:>6,} advisories  "
            f"{size_mb:>6.1f} MB  ← {shown}"
        )


async def _refresh(
    *, cache_dir: Path, ecosystems: list[str], force: bool, max_age_hours: float
) -> OsvIndex:
    dumps = await _download_all(
        ecosystems, cache_dir=cache_dir, force=force, max_age_hours=max_age_hours
    )
    by_pkg = _build_index(dumps)
    return OsvIndex(dumps=dumps, by_pkg=by_pkg)


if __name__ == "__main__":
    app()
