"""Publish committed SBOM inspection data into the frontend public folder.

The canonical SBOM inspection artifacts live under ``mappings/``:

* ``mappings/sboms.json`` — summary keyed by conda package name
* ``mappings/sbom_cves/*.json`` — per-package advisory details

Vite only serves files under ``web/public``. This script mirrors the canonical
artifacts there during local builds and GitHub Pages deploys without requiring
the heavier SBOM extraction dependencies in the lite environment.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUMMARY_IN = ROOT / "mappings" / "sboms.json"
DEFAULT_DETAIL_IN = ROOT / "mappings" / "sbom_cves"
DEFAULT_SUMMARY_OUT = ROOT / "web" / "public" / "sboms.json"
DEFAULT_DETAIL_OUT = ROOT / "web" / "public" / "sbom_cves"


def _copy_file(src: Path, dst: Path) -> bool:
    if not src.exists():
        if dst.exists():
            dst.unlink()
        return False
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dst)
    return True


def _sync_dir(src: Path, dst: Path) -> int:
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True, exist_ok=True)
    if not src.exists():
        return 0

    count = 0
    for path in sorted(src.glob("*.json")):
        shutil.copyfile(path, dst / path.name)
        count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary-in", type=Path, default=DEFAULT_SUMMARY_IN)
    parser.add_argument("--detail-in", type=Path, default=DEFAULT_DETAIL_IN)
    parser.add_argument("--summary-out", type=Path, default=DEFAULT_SUMMARY_OUT)
    parser.add_argument("--detail-out", type=Path, default=DEFAULT_DETAIL_OUT)
    args = parser.parse_args()

    copied_summary = _copy_file(args.summary_in, args.summary_out)
    detail_count = _sync_dir(args.detail_in, args.detail_out)
    summary_label = "copied" if copied_summary else "absent"
    print(
        f"SBOM public artifacts: summary {summary_label}, "
        f"{detail_count} detail file(s) copied"
    )


if __name__ == "__main__":
    main()
