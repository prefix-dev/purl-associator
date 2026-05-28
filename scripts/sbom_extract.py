"""Extract dependency SBOMs from compiled binaries inside conda packages.

For Rust binaries built with ``cargo auditable`` and Go binaries (which always
carry ``runtime/debug.BuildInfo`` since Go 1.13), we can recover the full
dependency tree directly from the shipped executable. This is a "second level"
scan over what ``scripts.automap`` already does, surfacing per-package PURLs
that map to the source ecosystem (``pkg:cargo``, ``pkg:golang``).

The script:

1. Reads conda package URLs from ``mappings/auto.json``.
2. Uses :func:`rattler.package_streaming.fetch_raw_package_file_from_url` to
   pull only ``info/paths.json`` and the binary file(s) under ``bin/`` via
   sparse range requests — no full archive download.
3. Parses the ELF section table in pure Python, locates the
   ``.dep-v0`` (cargo-auditable) or ``.go.buildinfo`` section, and decodes it.
4. Writes a CycloneDX 1.5 JSON document to ``mappings/sboms/<name>.json``.

Limitations of this prototype:

- Linux ELF only. (conda-forge ``linux-64`` packages. Mach-O / PE encoded
  buildinfo lives in different sections; not yet supported.)
- Rust extraction requires the recipe to invoke ``cargo auditable build``.
  Many conda-forge feedstocks use plain ``cargo build`` and will return empty.
"""

from __future__ import annotations

import asyncio
import json
import struct
import sys
import time
import uuid
import zlib
from datetime import UTC, datetime
from pathlib import Path

import typer
from rattler.networking import Client
from rattler.package_streaming import fetch_raw_package_file_from_url
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
AUTO_PATH = ROOT / "mappings" / "auto.json"
SBOM_DIR = ROOT / "mappings" / "sboms"
INSPECTIONS_OUT = ROOT / "mappings" / "sbom_inspections.json"


# ---------------------------------------------------------------------------
# Minimal ELF section reader
# ---------------------------------------------------------------------------


def read_elf_sections(data: bytes) -> dict[str, bytes]:
    """Return a mapping ``{section_name: section_bytes}`` for an ELF binary."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF binary")
    ei_class = data[4]
    ei_data = data[5]
    endian = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        e_shoff = struct.unpack_from(f"{endian}Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from(f"{endian}H", data, 0x3A)[0]
        e_shnum = struct.unpack_from(f"{endian}H", data, 0x3C)[0]
        e_shstrndx = struct.unpack_from(f"{endian}H", data, 0x3E)[0]
        sh_struct = f"{endian}IIQQQQIIQQ"
    elif ei_class == 1:
        e_shoff = struct.unpack_from(f"{endian}I", data, 0x20)[0]
        e_shentsize = struct.unpack_from(f"{endian}H", data, 0x2E)[0]
        e_shnum = struct.unpack_from(f"{endian}H", data, 0x30)[0]
        e_shstrndx = struct.unpack_from(f"{endian}H", data, 0x32)[0]
        sh_struct = f"{endian}IIIIIIIIII"
    else:
        raise ValueError(f"unsupported ELF class {ei_class}")

    def section_header(idx: int) -> tuple:
        return struct.unpack_from(sh_struct, data, e_shoff + idx * e_shentsize)

    shstr = section_header(e_shstrndx)
    shstr_offset = shstr[4]
    shstr_size = shstr[5]
    strtab = data[shstr_offset : shstr_offset + shstr_size]

    sections: dict[str, bytes] = {}
    for i in range(e_shnum):
        sh = section_header(i)
        sh_name_offset = sh[0]
        sh_offset = sh[4]
        sh_size = sh[5]
        end = strtab.find(b"\x00", sh_name_offset)
        name = strtab[sh_name_offset:end].decode("utf-8", errors="replace")
        sections[name] = bytes(data[sh_offset : sh_offset + sh_size])
    return sections


# ---------------------------------------------------------------------------
# Rust cargo-auditable
# ---------------------------------------------------------------------------


def extract_cargo_auditable(sections: dict[str, bytes]) -> dict | None:
    blob = sections.get(".dep-v0")
    if not blob:
        return None
    try:
        return json.loads(zlib.decompress(blob))
    except (zlib.error, json.JSONDecodeError) as exc:
        return {"_error": f"decode failed: {exc}"}


def rust_components(auditable: dict) -> list[dict]:
    components: list[dict] = []
    for pkg in auditable.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        source = pkg.get("source", "")
        kind = pkg.get("kind", "runtime")
        purl: str | None = None
        # cargo-auditable emits "crates.io" for the canonical registry.
        if source in (
            "crates.io",
            "registry+https://github.com/rust-lang/crates.io-index",
        ):
            purl = f"pkg:cargo/{name}@{version}"
        comp: dict = {
            "type": "library",
            "name": name,
            "version": version,
            "properties": [
                {"name": "cargo-auditable:source", "value": str(source)},
                {"name": "cargo-auditable:kind", "value": kind},
            ],
        }
        if purl:
            comp["purl"] = purl
        components.append(comp)
    return components


# ---------------------------------------------------------------------------
# Go buildinfo
# ---------------------------------------------------------------------------

GO_BUILDINFO_MAGIC = b"\xff Go buildinf:"


def _go_uvarint(data: bytes, pos: int) -> tuple[int, int]:
    value, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if b < 0x80:
            return value, pos
        shift += 7


def _go_read_string(data: bytes, pos: int) -> tuple[str, int]:
    length, pos = _go_uvarint(data, pos)
    return data[pos : pos + length].decode("utf-8", errors="replace"), pos + length


def extract_go_buildinfo(sections: dict[str, bytes]) -> dict | None:
    hdr = sections.get(".go.buildinfo")
    if hdr is None or not hdr.startswith(GO_BUILDINFO_MAGIC):
        return None
    flags = hdr[15]
    # Bit 1 (0x02): strings are inline length-prefixed (Go >= 1.18 inline form).
    if not (flags & 0x02):
        return {"_error": "legacy ptr-based buildinfo not supported"}
    pos = 32
    go_version, pos = _go_read_string(hdr, pos)
    mod_block, _ = _go_read_string(hdr, pos)
    # Strip 16-byte sentinels framing the modinfo string.
    if len(mod_block) >= 33:
        mod_block = mod_block[16:-16]
    modules = _parse_go_mod_block(mod_block)
    return {"go_version": go_version, "modules": modules}


def _parse_go_mod_block(text: str) -> list[dict]:
    result: list[dict] = []
    last_dep: dict | None = None
    for line in text.split("\n"):
        if not line:
            continue
        parts = line.split("\t")
        tag = parts[0]
        if tag == "path":
            result.append({"kind": "path", "path": parts[1] if len(parts) > 1 else ""})
        elif tag in ("mod", "dep"):
            entry = {
                "kind": tag,
                "path": parts[1] if len(parts) > 1 else "",
                "version": parts[2] if len(parts) > 2 else "",
                "hash": parts[3] if len(parts) > 3 else "",
            }
            result.append(entry)
            last_dep = entry
        elif tag == "=>" and last_dep is not None:
            last_dep["replaced_by"] = {
                "path": parts[1] if len(parts) > 1 else "",
                "version": parts[2] if len(parts) > 2 else "",
                "hash": parts[3] if len(parts) > 3 else "",
            }
    return result


def go_components(buildinfo: dict) -> list[dict]:
    components: list[dict] = []
    for mod in buildinfo.get("modules", []):
        if mod.get("kind") not in ("mod", "dep"):
            continue
        path = mod.get("path", "")
        version = mod.get("version", "")
        # `(devel)` is the main module — no PURL, but worth keeping as a record.
        purl = (
            f"pkg:golang/{path}@{version}"
            if path and version and version != "(devel)"
            else None
        )
        comp: dict = {
            "type": "library",
            "name": path,
            "version": version,
            "properties": [{"name": "go-buildinfo:kind", "value": mod["kind"]}],
        }
        if mod.get("hash"):
            comp["properties"].append(
                {"name": "go-buildinfo:hash", "value": mod["hash"]}
            )
        if purl:
            comp["purl"] = purl
        components.append(comp)
    return components


# ---------------------------------------------------------------------------
# Network: fetch info/paths.json + bin/*
# ---------------------------------------------------------------------------


async def _fetch_paths(client: Client, url: str) -> list[dict]:
    raw = await fetch_raw_package_file_from_url(client, url, "info/paths.json")
    payload = json.loads(raw)
    return payload.get("paths", [])


def _binary_candidates(paths: list[dict], conda_name: str) -> list[str]:
    """Return likely ELF binary paths from ``info/paths.json``.

    Picks executable commands under ``bin/`` and native shared objects under
    ``lib/``. The latter catches Python packages backed by Rust extensions,
    such as py-rattler.
    """
    out: list[str] = []
    for entry in paths:
        p = entry.get("_path", "")
        if not isinstance(p, str):
            continue
        if p.startswith("bin/") and p.count("/") == 1:
            leaf = p.rsplit("/", 1)[1]
            if any(leaf.endswith(ext) for ext in (".sh", ".py", ".bat", ".ps1")):
                continue
            out.append(p)
        elif p.startswith("lib/") and (".so" in p or p.endswith(".dylib")):
            out.append(p)
    # Heuristic: if a binary matches the conda name (or a known alias), float
    # it to the front so the simple case still works when there are many bins.
    aliases = {"ripgrep": "rg", "fd-find": "fd"}
    primary = aliases.get(conda_name, conda_name)
    out.sort(
        key=lambda p: (
            0 if p.endswith("/" + primary) else 1,
            0 if p.startswith("bin/") else 1,
            len(p),
            p,
        )
    )
    return out


# ---------------------------------------------------------------------------
# CycloneDX serializer
# ---------------------------------------------------------------------------


def cyclonedx(
    *,
    conda_name: str,
    conda_version: str,
    binary_path: str,
    ecosystem: str,
    components: list[dict],
    extra_props: list[dict] | None = None,
) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
            "tools": [{"vendor": "purl-associator", "name": "sbom_extract"}],
            "component": {
                "type": "application",
                "name": conda_name,
                "version": conda_version,
                "purl": (f"pkg:conda/{conda_name}@{conda_version}?channel=conda-forge"),
            },
            "properties": [
                {"name": "purl-associator:source-ecosystem", "value": ecosystem},
                {"name": "purl-associator:binary-path", "value": binary_path},
                *(extra_props or []),
            ],
        },
        "components": components,
    }


# ---------------------------------------------------------------------------
# Per-package pipeline
# ---------------------------------------------------------------------------


async def _process_one(
    client: Client,
    semaphore: asyncio.Semaphore,
    *,
    conda_name: str,
    conda_version: str,
    url: str,
    expected: dict | None,
) -> dict:
    """Return a status dict for logging plus the SBOM document (or None)."""
    async with semaphore:
        try:
            paths = await _fetch_paths(client, url)
        except Exception as exc:  # noqa: BLE001
            return {"name": conda_name, "status": "no-paths-json", "detail": str(exc)}

        for candidate in _binary_candidates(paths, conda_name):
            try:
                data = await fetch_raw_package_file_from_url(client, url, candidate)
            except Exception:  # noqa: BLE001
                continue
            if not data.startswith(b"\x7fELF"):
                continue

            sections = read_elf_sections(data)
            rust = extract_cargo_auditable(sections)
            if rust and "packages" in rust:
                bom = cyclonedx(
                    conda_name=conda_name,
                    conda_version=conda_version,
                    binary_path=candidate,
                    ecosystem="cargo",
                    components=rust_components(rust),
                    extra_props=[
                        {
                            "name": "cargo-auditable:format-version",
                            "value": str(rust.get("format", "")),
                        }
                    ],
                )
                return {
                    "name": conda_name,
                    "status": "ok",
                    "ecosystem": "cargo",
                    "components": len(bom["components"]),
                    "binary_path": candidate,
                    "bom": bom,
                }

            go = extract_go_buildinfo(sections)
            if go and "modules" in go:
                bom = cyclonedx(
                    conda_name=conda_name,
                    conda_version=conda_version,
                    binary_path=candidate,
                    ecosystem="golang",
                    components=go_components(go),
                    extra_props=[
                        {
                            "name": "go-buildinfo:go-version",
                            "value": go.get("go_version", ""),
                        }
                    ],
                )
                return {
                    "name": conda_name,
                    "status": "ok",
                    "ecosystem": "golang",
                    "components": len(bom["components"]),
                    "binary_path": candidate,
                    "bom": bom,
                }

        result = {"name": conda_name, "status": "no-sbom"}
        if expected:
            result["expected_ecosystems"] = expected.get("ecosystems") or []
            result["signals"] = expected.get("signals") or []
            if "cargo" in result["expected_ecosystems"]:
                if expected.get("uses_cargo_auditable") is False:
                    result["warning"] = expected.get("warning")
                else:
                    result["warning"] = (
                        "Rust compiler detected in recipe, but no "
                        "cargo-auditable metadata was found in scanned ELF files."
                    )
        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_auto(path: Path) -> dict[str, dict]:
    return json.loads(path.read_text()).get("packages", {})


def _resolve_targets(
    auto: dict[str, dict], *, only: list[str] | None, candidates: bool
) -> list[tuple[str, str, str, dict | None]]:
    """Return list of (name, version, url, expected) tuples to process."""
    if only:
        wanted = set(only)
    elif candidates:
        wanted = {
            name
            for name, entry in auto.items()
            if isinstance(entry.get("deep_inspection"), dict)
            and entry["deep_inspection"].get("candidate")
        }
        # Backward-compatible fallback for older auto.json snapshots that do
        # not yet carry recipe-derived deep-inspection metadata.
        wanted.update(
            {
                # Go
                "hugo",
                "gh",
                "syft",
                "cosign",
                "grype",
                "mc",
                # Rust (cargo-auditable known to be used)
                "pixi",
                "rattler-build",
                "cargo-nextest",
                "wasm-pack",
                "cargo-zigbuild",
                "py-rattler",
                # Rust (no cargo-auditable as of now — included for visibility)
                "ripgrep",
                "fd-find",
                "bat",
                "hyperfine",
                "starship",
                "just",
                "tokei",
                "sccache",
                "eza",
                "helix",
                "dprint",
                "taplo",
                "uv",
            }
        )
    else:
        wanted = set(auto)

    out: list[tuple[str, str, str, dict | None]] = []
    for name in sorted(wanted):
        entry = auto.get(name)
        if not entry:
            console.log(f"[yellow]skip[/] {name}: not in auto.json")
            continue
        url = entry.get("url")
        version = entry.get("version", "")
        if not url:
            continue
        expected = entry.get("deep_inspection")
        out.append(
            (name, version, url, expected if isinstance(expected, dict) else None)
        )
    return out


@app.command()
def main(
    only: str | None = typer.Option(
        None, help="Comma-separated conda package names to probe"
    ),
    candidates: bool = typer.Option(
        True,
        "--candidates/--all",
        help="Restrict to a shortlist of known Rust/Go packages (default). "
        "Use --all to probe every package in auto.json (slow).",
    ),
    auto: Path = typer.Option(AUTO_PATH, help="Path to mappings/auto.json"),
    out_dir: Path = typer.Option(SBOM_DIR, help="Output folder for SBOM JSON"),
    inspections_out: Path = typer.Option(
        INSPECTIONS_OUT, help="Output scan-status summary JSON"
    ),
    parallel: int = typer.Option(8, help="Parallel inflight binary fetches"),
) -> None:
    """Walk a set of conda packages and emit CycloneDX SBOMs for those whose
    binaries embed cargo-auditable or Go buildinfo data."""
    asyncio.run(
        _async_main(
            only=only.split(",") if only else None,
            candidates=candidates,
            auto=auto,
            out_dir=out_dir,
            inspections_out=inspections_out,
            parallel=parallel,
        )
    )


async def _async_main(
    *,
    only: list[str] | None,
    candidates: bool,
    auto: Path,
    out_dir: Path,
    inspections_out: Path,
    parallel: int,
) -> None:
    started = time.monotonic()
    auto_packages = _load_auto(auto)
    targets = _resolve_targets(auto_packages, only=only, candidates=candidates)
    console.log(f"Probing {len(targets):,} package(s)")

    out_dir.mkdir(parents=True, exist_ok=True)

    client = Client()
    semaphore = asyncio.Semaphore(parallel)
    summary: list[dict] = []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task("Scanning binaries…", total=len(targets))

        async def runner(
            name: str, version: str, url: str, expected: dict | None
        ) -> dict:
            try:
                result = await _process_one(
                    client,
                    semaphore,
                    conda_name=name,
                    conda_version=version,
                    url=url,
                    expected=expected,
                )
            except Exception as exc:  # noqa: BLE001
                result = {"name": name, "status": "error", "detail": str(exc)}
            finally:
                progress.advance(task_id)
            return result

        results = await asyncio.gather(
            *(runner(n, v, u, expected) for n, v, u, expected in targets)
        )

    for result in results:
        bom = result.pop("bom", None)
        summary.append(result)
        if bom is None:
            continue
        out_path = out_dir / f"{result['name']}.json"
        out_path.write_text(json.dumps(bom, indent=2) + "\n")

    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    inspection_payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "packages": {
            r["name"]: {
                "name": r["name"],
                "version": auto_packages.get(r["name"], {}).get("version", ""),
                "status": r.get("status"),
                "ecosystem": r.get("ecosystem"),
                "expected_ecosystems": r.get("expected_ecosystems"),
                "signals": r.get("signals"),
                "warning": r.get("warning"),
                "binary_path": r.get("binary_path"),
                "component_count": r.get("components"),
            }
            for r in sorted(summary, key=lambda x: x["name"])
        },
    }
    inspections_out.parent.mkdir(parents=True, exist_ok=True)
    inspections_out.write_text(json.dumps(inspection_payload, indent=2) + "\n")

    elapsed = time.monotonic() - started
    ok = sum(1 for r in summary if r["status"] == "ok")
    no_sbom = sum(1 for r in summary if r["status"] == "no-sbom")
    errors = len(summary) - ok - no_sbom
    console.log(
        f"Done in {elapsed:.1f}s: [bold green]{ok}[/] with SBOM, "
        f"[bold]{no_sbom}[/] without, [bold red]{errors}[/] errors"
    )
    console.log(f"Inspection summary at {inspections_out.relative_to(ROOT)}")
    # Pretty per-package table.
    for r in summary:
        if r["status"] == "ok":
            console.log(
                f"  [green]✓[/] {r['name']:20} {r['ecosystem']:7} "
                f"components={r['components']}"
            )
        elif r["status"] == "no-sbom":
            console.log(f"  [dim]·[/] {r['name']:20} (no embedded SBOM)")
        else:
            console.log(
                f"  [red]✗[/] {r['name']:20} {r['status']}: {r.get('detail', '')}"
            )


if __name__ == "__main__":
    try:
        app()
    except KeyboardInterrupt:
        sys.exit(130)
