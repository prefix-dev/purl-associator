"""Generate review candidates for packages intentionally lacking a PURL.

Rules never mutate mapping sources. A classification becomes authoritative only
when a reviewer promotes an exact candidate list into a normal contribution.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from scripts.merge_mappings import UNMAPPED_REASON_CODES

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = ROOT / "web" / "public" / "mappings.json"
DEFAULT_OUTPUT = ROOT / ".tmp" / "unmapped-candidates.json"
CDT_SOURCE_HOSTS = frozenset(
    {
        "dl.rockylinux.org",
        "download.sinenomine.net",
        "mirror.centos.org",
        "repo.almalinux.org",
        "vault.centos.org",
    }
)

DEPENDENCY_ONLY_PACKAGES = frozenset(
    {
        "cublasmp",
        "cuda",
        "cuda-arch",
        "cuda-command-line-tools",
        "cuda-libraries",
        "cuda-libraries-dev",
        "cuda-libraries-static",
        "cuda-minimal-build",
        "cuda-runtime",
        "cuda-toolkit",
        "cuda-tools",
        "cuda-version",
        "cusolvermp",
        "cyclus-build-deps",
        "fonts-conda-ecosystem",
        "libnvpl-dev",
        "nvidia-gds",
    }
)
TOOLCHAIN_SELECTOR_PACKAGES = frozenset(
    {
        "binutils-meta",
        "c-compiler",
        "compilers",
        "cuda-compiler",
        "cxx-compiler",
        "fortran-compiler",
        "go-cgo-compiler",
        "go-nocgo-compiler",
    }
)
ENVIRONMENT_MUTEX_PACKAGES = frozenset(
    {"_nvpl_dev_mutex", "_r-mutex", "ros-conda-mutex"}
)
PINNING_PACKAGES = frozenset({"conda-forge-pinning"})
COMPATIBILITY_SHIMS = frozenset({"git-bash"})


@dataclass(frozen=True)
class Rule:
    rule_id: str
    code: str
    explanation: str
    matches: Callable[[str, dict[str, Any]], bool]


def _eligible(entry: dict[str, Any]) -> bool:
    if entry.get("unmapped") is True or entry.get("status") == "unmapped":
        return False
    return not any(
        identity.get("kind") == "purl" for identity in entry.get("identities", [])
    )


def _cdt_repackage(_name: str, entry: dict[str, Any]) -> bool:
    summary = entry.get("summary")
    source_url = entry.get("source_url")
    if not isinstance(summary, str) or not summary.startswith("(CDT)"):
        return False
    if not isinstance(source_url, str):
        return False
    try:
        parsed = urlsplit(source_url)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and (parsed.hostname or "").lower() in CDT_SOURCE_HOSTS
        and parsed.path.lower().endswith(".rpm")
    )


def _in(packages: frozenset[str]) -> Callable[[str, dict[str, Any]], bool]:
    return lambda name, _entry: name in packages


RULES = (
    Rule(
        "cdt-rpm-repackage-v1",
        "conda_cdt_repackage",
        "Conda distribution-toolchain repackaging of an RPM; it has no independent upstream package coordinate.",
        _cdt_repackage,
    ),
    Rule(
        "environment-mutex-v1",
        "environment_mutex",
        "Conda environment mutex used only to select mutually compatible dependency variants.",
        _in(ENVIRONMENT_MUTEX_PACKAGES),
    ),
    Rule(
        "toolchain-selector-v1",
        "toolchain_selector",
        "Conda toolchain selector that resolves to platform compiler packages rather than shipping an independent upstream project.",
        _in(TOOLCHAIN_SELECTOR_PACKAGES),
    ),
    Rule(
        "dependency-only-metapackage-v1",
        "dependency_only_metapackage",
        "Conda dependency-only aggregate or convenience package without an independent upstream package payload.",
        _in(DEPENDENCY_ONLY_PACKAGES),
    ),
    Rule(
        "pinning-metadata-v1",
        "pinning_metadata",
        "Conda-forge ecosystem pinning metadata rather than an independently released upstream software package.",
        _in(PINNING_PACKAGES),
    ),
    Rule(
        "compatibility-shim-v1",
        "compatibility_shim",
        "Conda compatibility package whose purpose is only to depend on the replacement package.",
        _in(COMPATIBILITY_SHIMS),
    ),
)

assert {rule.code for rule in RULES} <= UNMAPPED_REASON_CODES


def _evidence(entry: dict[str, Any]) -> dict[str, str]:
    return {
        key: str(entry[key])
        for key in ("version", "build", "summary", "source_url", "repo", "homepage")
        if entry.get(key) is not None and str(entry[key]).strip()
    }


def classify_packages(payload: dict[str, Any]) -> dict[str, Any]:
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("mapping bundle packages must be an object")
    candidates: list[dict[str, Any]] = []
    for name, entry in sorted(packages.items()):
        if (
            not isinstance(name, str)
            or not isinstance(entry, dict)
            or not _eligible(entry)
        ):
            continue
        rule = next((rule for rule in RULES if rule.matches(name, entry)), None)
        if rule is None:
            continue
        evidence = _evidence(entry)
        if not evidence:
            raise ValueError(f"{name}: classification has no persisted evidence")
        candidates.append(
            {
                "name": name,
                "unmapped_reason": {
                    "code": rule.code,
                    "explanation": rule.explanation,
                    "rule_id": rule.rule_id,
                    "evidence": evidence,
                },
            }
        )
    counts = Counter(row["unmapped_reason"]["code"] for row in candidates)
    return {
        "schema_version": 1,
        "candidate_count": len(candidates),
        "counts_by_reason": dict(sorted(counts.items())),
        "candidates": candidates,
    }


def contribution_from_candidates(
    candidates: dict[str, Any],
    approved_names: set[str],
    *,
    author: str,
    author_name: str,
    timestamp: str,
) -> dict[str, Any]:
    by_name = {row["name"]: row for row in candidates.get("candidates", [])}
    unknown = approved_names - set(by_name)
    if unknown:
        raise ValueError(f"approved packages are not candidates: {sorted(unknown)!r}")
    return {
        "schema_version": 1,
        "title": "Classify packages intentionally without an upstream PURL",
        "author": author,
        "author_name": author_name,
        "timestamp": timestamp,
        "packages": {
            name: {
                "unmapped": True,
                "unmapped_reason": by_name[name]["unmapped_reason"],
            }
            for name in sorted(approved_names)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    payload = json.loads(args.input.read_text())
    report = classify_packages(payload)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print(f"Wrote {report['candidate_count']:,} candidates to {args.output}")


if __name__ == "__main__":
    main()
