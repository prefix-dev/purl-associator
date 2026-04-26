"""Merge ``mappings/auto.json`` and ``mappings/manual.json`` into the
single payload the frontend consumes.

``manual.json`` is human-curated (edited via PRs from the web UI). Any keys it
specifies override the auto guesses. The merged output goes to
``web/public/mappings.json`` so the static site fetches a single file.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import typer

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL = ROOT / "mappings" / "manual.json"
DEFAULT_OUT = ROOT / "web" / "public" / "mappings.json"

app = typer.Typer(add_completion=False, help=__doc__)


def _load_json(path: Path, default: dict) -> dict:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return default


@app.command()
def main(
    auto: Path = typer.Option(DEFAULT_AUTO),
    manual: Path = typer.Option(DEFAULT_MANUAL),
    out: Path = typer.Option(DEFAULT_OUT),
) -> None:
    auto_data = _load_json(auto, {"packages": {}})
    manual_data = _load_json(manual, {"packages": {}})

    merged: dict[str, dict] = {}
    for name, entry in auto_data.get("packages", {}).items():
        merged[name] = {**entry, "status": "auto-unverified", "source": "auto"}

    for name, override in manual_data.get("packages", {}).items():
        base = merged.get(name, {"name": name})
        merged[name] = {
            **base,
            **override,
            "status": override.get("status", "verified"),
            "source": "manual",
        }
        # remember the auto suggestion (for diff display)
        if name in auto_data.get("packages", {}):
            merged[name]["auto"] = {
                "purl": auto_data["packages"][name].get("purl"),
                "type": auto_data["packages"][name].get("type"),
                "namespace": auto_data["packages"][name].get("namespace"),
                "pkg_name": auto_data["packages"][name].get("pkg_name"),
                "confidence": auto_data["packages"][name].get("confidence", 0.0),
                "sources": auto_data["packages"][name].get("sources", []),
            }

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "auto_generated_at": auto_data.get("generated_at"),
        "manual_updated_at": manual_data.get("updated_at"),
        "channel": auto_data.get("channel", "conda-forge"),
        "package_count": len(merged),
        "packages": dict(sorted(merged.items())),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")
    typer.echo(
        f"Merged {len(auto_data.get('packages', {}))} auto + "
        f"{len(manual_data.get('packages', {}))} manual → {out} "
        f"({len(merged)} total)"
    )


if __name__ == "__main__":
    app()
