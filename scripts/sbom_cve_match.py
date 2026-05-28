"""Match SBOM components against OSV advisories.

For every CycloneDX document under ``mappings/sboms/`` (produced by
``scripts.sbom_extract``) this script:

1. Pulls each component's ``pkg:cargo`` or ``pkg:golang`` PURL.
2. Looks the package up in the OSV index (``crates.io`` / ``Go`` ecosystems).
3. Checks whether the *specific component version* falls inside any of the
   advisory's affected ranges — reusing :func:`scripts.cve_match.version_in_affected_entry`.
4. Writes one JSON file per conda package to ``mappings/sbom_cves/<name>.json``
   with the matched advisory ids, the offending component, and the affected
   version range. Also writes a single ``web/public/sboms.json`` summary so
   the frontend can show transitive component / CVE counts per package.

Unlike :mod:`scripts.cve_match` which matches the package's own PURL, this
script surfaces vulnerabilities in *transitive* dependencies baked into the
shipped binary.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)

from scripts.cve_match import parse_purl, version_in_affected_entry
from scripts.osv_fetch import fetch_index
from rattler.version import Version

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
SBOM_DIR = ROOT / "mappings" / "sboms"
OUT_DIR = ROOT / "mappings" / "sbom_cves"
INSPECTIONS_IN = ROOT / "mappings" / "sbom_inspections.json"
SUMMARY_OUT = ROOT / "web" / "public" / "sboms.json"
OSV_CACHE = ROOT / "osv_cache"

# OSV ecosystems we care about for SBOM components.
SUPPORTED_PURL_TYPES = ("cargo", "golang")


def _components_of(sbom: dict) -> list[dict]:
    """Yield each component with the metadata we need for matching."""
    components: list[dict] = []
    for c in sbom.get("components", []):
        purl = c.get("purl")
        if not isinstance(purl, str):
            continue
        parsed = parse_purl(purl)
        if not parsed or parsed.type not in SUPPORTED_PURL_TYPES:
            continue
        version = c.get("version", "")
        # Strip Go's "(devel)" placeholder — that's the main module.
        if not version or version.startswith("("):
            continue
        # Go module versions carry a "v" prefix that rattler.Version mis-orders
        # ("v0.53.0" parses as a leading-string-segment value that sorts below
        # any numeric version). OSV records strip the prefix on the fixed/range
        # side, so strip on the input side too.
        compare_version = version[1:] if version.startswith("v") else version
        try:
            parsed_version = Version(compare_version)
        except Exception:
            continue
        full_name = (
            f"{parsed.namespace}/{parsed.name}" if parsed.namespace else parsed.name
        )
        components.append(
            {
                "purl": purl,
                "type": parsed.type,
                "name": full_name,
                "lookup_name": full_name,
                "version_str": version,
                "version": parsed_version,
            }
        )
    return components


def _conda_name_from_sbom(sbom: dict) -> str | None:
    meta = sbom.get("metadata") or {}
    comp = meta.get("component") or {}
    if isinstance(comp.get("name"), str):
        return comp["name"]
    return None


def _conda_version_from_sbom(sbom: dict) -> str | None:
    meta = sbom.get("metadata") or {}
    comp = meta.get("component") or {}
    if isinstance(comp.get("version"), str):
        return comp["version"]
    return None


def _load_inspections(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}
    packages = data.get("packages")
    return packages if isinstance(packages, dict) else {}


def _compact_summary(row: dict) -> dict:
    return {
        k: v
        for k, v in row.items()
        if v is not None and not (k == "status" and v == "ok")
    }


@app.command()
def main(
    sbom_dir: Path = typer.Option(SBOM_DIR, help="Folder of CycloneDX SBOM JSON"),
    out_dir: Path = typer.Option(OUT_DIR, help="Per-package output dir"),
    summary_out: Path = typer.Option(
        SUMMARY_OUT, help="Where the frontend summary lands"
    ),
    inspections: Path = typer.Option(
        INSPECTIONS_IN, help="Scan-status summary from scripts.sbom_extract"
    ),
    osv_cache: Path = typer.Option(OSV_CACHE, help="OSV download cache"),
    osv_max_age_hours: float = typer.Option(
        24.0, help="Re-download OSV dump if older than this"
    ),
    force_osv: bool = typer.Option(False, help="Force re-download of OSV"),
) -> None:
    """Match every SBOM component against OSV, write per-package + summary files."""
    asyncio.run(
        _async_main(
            sbom_dir=sbom_dir,
            out_dir=out_dir,
            summary_out=summary_out,
            inspections=inspections,
            osv_cache=osv_cache,
            osv_max_age_hours=osv_max_age_hours,
            force_osv=force_osv,
        )
    )


async def _async_main(
    *,
    sbom_dir: Path,
    out_dir: Path,
    summary_out: Path,
    inspections: Path,
    osv_cache: Path,
    osv_max_age_hours: float,
    force_osv: bool,
) -> None:
    started = time.monotonic()
    sbom_files = sorted(sbom_dir.glob("*.json"))
    if not sbom_files:
        console.log(f"[yellow]No SBOMs found in {sbom_dir} — nothing to match.[/]")
        return
    console.log(f"Loaded {len(sbom_files)} SBOM(s) from {sbom_dir}")

    sboms = {f.stem: json.loads(f.read_text()) for f in sbom_files}
    inspection_summary = _load_inspections(inspections)

    # Figure out the union of OSV ecosystems we need.
    types_present: set[str] = set()
    for sbom in sboms.values():
        for c in _components_of(sbom):
            types_present.add(c["type"])
    if not types_present:
        console.log("[yellow]No cargo/golang components — exiting.[/]")
        return
    console.log(f"PURL types in play: [bold]{', '.join(sorted(types_present))}[/]")

    osv = await fetch_index(
        cache_dir=osv_cache,
        purl_types=types_present,
        force=force_osv,
        max_age_hours=osv_max_age_hours,
    )
    console.log(
        f"OSV: {osv.total_advisories():,} affected-package entries "
        f"across {len(osv.dumps)} ecosystem(s)"
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, dict] = {
        name: _compact_summary(
            {
                "name": name,
                "version": entry.get("version", ""),
                "ecosystem": entry.get("ecosystem") or "",
                "expected_ecosystems": entry.get("expected_ecosystems"),
                "signals": entry.get("signals"),
                "status": entry.get("status"),
                "warning": entry.get("warning"),
                "binary_path": entry.get("binary_path"),
                "component_count": entry.get("component_count") or 0,
                "matched_component_count": 0,
                "advisory_count": 0,
                "vulnerable_component_count": 0,
            }
        )
        for name, entry in inspection_summary.items()
        if isinstance(entry, dict)
    }
    written = 0
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Matching components…", total=len(sboms))
        for conda_name, sbom in sboms.items():
            components = _components_of(sbom)
            ecosystem = next(
                (
                    p["value"]
                    for p in sbom.get("metadata", {}).get("properties", [])
                    if p.get("name") == "purl-associator:source-ecosystem"
                ),
                "",
            )
            hits: list[dict] = []
            # Group by advisory id so we can list which components triggered it.
            adv_to_comps: dict[str, dict] = defaultdict(
                lambda: {"advisory": None, "components": []}
            )

            for comp in components:
                advisories = osv.for_purl(comp["type"], comp["lookup_name"])
                for adv in advisories:
                    try:
                        if not version_in_affected_entry(
                            comp["version"], adv.raw_affected
                        ):
                            continue
                    except Exception:
                        continue
                    record = adv_to_comps[adv.id]
                    record["advisory"] = adv
                    record["components"].append(
                        {
                            "purl": comp["purl"],
                            "name": comp["name"],
                            "version": comp["version_str"],
                        }
                    )

            for adv_id, group in sorted(adv_to_comps.items()):
                adv = group["advisory"]
                comps = group["components"]
                hits.append(
                    {
                        "advisory_id": adv_id,
                        "primary_id": adv.primary_id(),
                        "aliases": adv.aliases,
                        "summary": adv.summary,
                        "severity": adv.severity,
                        "references": adv.references[:4],
                        "components": comps,
                    }
                )

            conda_version = _conda_version_from_sbom(sbom) or ""
            base_summary = summary.get(conda_name, {})
            summary[conda_name] = _compact_summary(
                {
                    "name": conda_name,
                    "version": conda_version,
                    "ecosystem": ecosystem,
                    "expected_ecosystems": base_summary.get("expected_ecosystems"),
                    "signals": base_summary.get("signals"),
                    "status": "ok",
                    "warning": base_summary.get("warning"),
                    "binary_path": base_summary.get("binary_path"),
                    "component_count": len(sbom.get("components", [])),
                    "matched_component_count": len(components),
                    "advisory_count": len(hits),
                    "vulnerable_component_count": len(
                        {c["purl"] for h in hits for c in h["components"]}
                    ),
                }
            )

            if hits:
                payload = {
                    "schema_version": 1,
                    "package": conda_name,
                    "package_version": conda_version,
                    "ecosystem": ecosystem,
                    "generated_at": generated_at,
                    "component_count": len(sbom.get("components", [])),
                    "matched_component_count": len(components),
                    "advisories": hits,
                }
                (out_dir / f"{conda_name}.json").write_text(
                    json.dumps(payload, indent=2) + "\n"
                )
                written += 1
            else:
                # Remove stale file from a previous run.
                stale = out_dir / f"{conda_name}.json"
                if stale.exists():
                    stale.unlink()
            progress.advance(task_id)

    summary_payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "packages": summary,
    }
    summary_out.parent.mkdir(parents=True, exist_ok=True)
    summary_out.write_text(json.dumps(summary_payload, indent=2) + "\n")

    elapsed = time.monotonic() - started
    total_advs = sum(s["advisory_count"] for s in summary.values())
    total_vuln_comps = sum(s["vulnerable_component_count"] for s in summary.values())
    console.log(
        f"Wrote [bold]{written}[/] per-package SBOM-CVE files to {out_dir} "
        f"({total_advs} advisories, {total_vuln_comps} unique vulnerable components) "
        f"in {elapsed:.1f}s. Summary at {summary_out.relative_to(ROOT)}"
    )
    console.log("\n[bold]Per-package:[/]")
    for name in sorted(summary):
        s = summary[name]
        if s["advisory_count"]:
            console.log(
                f"  [red]●[/] {name:20} {s['ecosystem']:7} "
                f"comp={s['component_count']:4} vuln={s['vulnerable_component_count']:3} "
                f"adv={s['advisory_count']}"
            )
        else:
            console.log(
                f"  [green]●[/] {name:20} {s['ecosystem']:7} "
                f"comp={s['component_count']:4} clean"
            )


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)
