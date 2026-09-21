"""Dependency-light readers for CPE discovery, vet, and promotion payloads."""

from __future__ import annotations

from typing import Any

SUPPORTED_CANDIDATE_SCHEMA_VERSIONS = frozenset({1, 2})


class UnsupportedCandidateSchema(ValueError):
    pass


def validate_candidates_schema(payload: dict) -> None:
    version = payload.get("schema_version", 1)
    if version not in SUPPORTED_CANDIDATE_SCHEMA_VERSIONS:
        raise UnsupportedCandidateSchema(
            f"Unsupported CPE candidates schema_version {version!r}; "
            f"expected one of {sorted(SUPPORTED_CANDIDATE_SCHEMA_VERSIONS)}"
        )


def packages_in_bucket(
    payload: dict, bucket: str, only: set[str] | None = None
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Return package records with a non-empty explicit automation bucket."""
    out: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for package in payload.get("packages") or []:
        if not isinstance(package, dict):
            continue
        name = package.get("conda_name")
        if not isinstance(name, str) or (only is not None and name not in only):
            continue
        entries = package.get(bucket) or []
        if not isinstance(entries, list) or not entries:
            continue
        valid_entries = [entry for entry in entries if isinstance(entry, dict)]
        if valid_entries:
            out.append((package, valid_entries))
    return out


def collect_accepts(payload: dict) -> dict[str, list[str]]:
    """Collect only heuristic accepts; schema-2 review evidence is ignored."""
    out: dict[str, list[str]] = {}
    for package, entries in packages_in_bucket(payload, "accept"):
        cpes = [entry["cpe"] for entry in entries if isinstance(entry.get("cpe"), str)]
        if cpes:
            out[package["conda_name"]] = cpes
    return out


def collect_vet_confident(payload: dict) -> dict[str, list[str]]:
    """Return confident, syntactically valid CPE choices from a vet payload."""
    out: dict[str, list[str]] = {}
    for verdict in payload.get("verdicts") or []:
        if not isinstance(verdict, dict) or verdict.get("verdict") != "confident":
            continue
        name = verdict.get("conda_name")
        cpes = verdict.get("selected_cpes") or []
        if not isinstance(name, str) or not isinstance(cpes, list):
            continue
        valid = [
            cpe for cpe in cpes if isinstance(cpe, str) and cpe.startswith("cpe:2.3:")
        ]
        if valid:
            out[name] = valid
    return out


def merge_accepts_with_vet(
    accepts: dict[str, list[str]], vet_confident: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Union heuristic accepts with confident vet choices, preserving order."""
    merged = {name: list(cpes) for name, cpes in accepts.items()}
    for name, cpes in vet_confident.items():
        existing = merged.setdefault(name, [])
        seen = set(existing)
        for cpe in cpes:
            if cpe not in seen:
                existing.append(cpe)
                seen.add(cpe)
    return merged
