"""Report primary-PURL coverage from a freshly merged full mapping bundle.

This is a read-only report, not a mapper or a source-layer merger. Rebuild older
published bundles with scripts.merge_mappings first: the current identities
contract is required. Alternative PURLs and CPEs do not count as primary PURLs.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scripts import merge_mappings, validate

REPORT_SCHEMA_VERSION = 1
URL_EVIDENCE_FIELDS = ("source_url", "repo", "homepage")
EVIDENCE_FIELDS = ("version", *URL_EVIDENCE_FIELDS, "note")
UNRESOLVED_DIAGNOSTICS = (
    "recorded_processing_error",
    "alternative_only",
    "no_parseable_source_host",
    "no_primary_from_url_evidence",
)


def _source_hosts(entry: dict[str, Any]) -> tuple[str, ...]:
    """Return normalized, unique hostnames from persisted URL evidence."""
    hosts: set[str] = set()
    for field in URL_EVIDENCE_FIELDS:
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            hostname = urlsplit(value).hostname
        except ValueError:
            continue
        if hostname:
            normalized = hostname.lower().rstrip(".")
            if normalized:
                hosts.add(normalized)
    return tuple(sorted(hosts))


def _has_alternative_purl(entry: dict[str, Any]) -> bool:
    """Use the canonical identity contract rather than legacy alternatives."""
    return any(
        identity["kind"] == "purl" and identity["role"] == "alternative"
        for identity in entry["identities"]
    )


def _diagnose_unresolved(entry: dict[str, Any]) -> str:
    """Classify persisted evidence without claiming an authoritative root cause."""
    note = (entry.get("note") or "").strip()
    if note.lower().startswith("fetch error:"):
        return "recorded_processing_error"
    if _has_alternative_purl(entry):
        return "alternative_only"
    if not _source_hosts(entry):
        return "no_parseable_source_host"
    return "no_primary_from_url_evidence"


def build_report(payload: dict[str, Any]) -> dict[str, Any]:
    """Summarize effective identities without inferring why a PURL is absent.

    Explicit unmapped decisions are distinct from unresolved packages. Neither
    missing URLs nor automatic diagnostic notes establish an intentional
    no-PURL decision. Notes can survive reviewed overrides and are evidence,
    not authoritative mapping state.
    """
    if not isinstance(payload, dict):
        raise ValueError("bundle must be an object")
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != validate.CURRENT_BUNDLE_SCHEMA
    ):
        raise ValueError(
            f"report requires full bundle schema {validate.CURRENT_BUNDLE_SCHEMA}; "
            "rebuild with scripts.merge_mappings"
        )
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise ValueError("bundle.packages must be an object")
    if type(payload.get("package_count")) is not int or payload["package_count"] != len(
        packages
    ):
        raise ValueError("bundle.package_count must equal the number of packages")
    channel = payload.get("channel")
    if not isinstance(channel, str) or not channel:
        raise ValueError("bundle.channel must be a non-empty string")
    if any(not isinstance(name, str) or not name for name in packages):
        raise ValueError("package names must be non-empty strings")

    counts = {"primary_present": 0, "explicitly_unmapped": 0, "unresolved": 0}
    unresolved_by_diagnostic = {diagnostic: 0 for diagnostic in UNRESOLVED_DIAGNOSTICS}
    missing: list[dict[str, Any]] = []
    for name, entry in sorted(packages.items()):
        label = f"packages.{name}"
        if not isinstance(entry, dict):
            raise ValueError(f"{label} must be an object")
        if "unmapped" in entry and not isinstance(entry["unmapped"], bool):
            raise ValueError(f"{label}.unmapped must be a boolean")
        if entry.get("status") == "unmapped" and entry.get("unmapped") is not True:
            raise ValueError(f"{label}.status unmapped requires unmapped: true")
        if entry.get("purl") is not None and not isinstance(entry["purl"], str):
            raise ValueError(f"{label}.purl must be a string or null")
        for field in EVIDENCE_FIELDS:
            if entry.get(field) is not None and not isinstance(entry[field], str):
                raise ValueError(f"{label}.{field} must be a string or null")
        downloads = entry.get("download_count")
        if downloads is not None and (type(downloads) is not int or downloads < 0):
            raise ValueError(
                f"{label}.download_count must be a non-negative integer or null"
            )

        # Reuse the published contract, including legacy/identity consistency
        # and reviewed-unmapped invariants, rather than accepting corrupt data
        # as apparently successful empty coverage.
        errors: list[str] = []
        validate._validate_identity_contract(entry, label, errors)
        if errors:
            raise ValueError("\n".join(errors))
        has_primary = any(
            identity["kind"] == "purl" and identity["role"] == "primary"
            for identity in entry["identities"]
        )
        state = (
            "primary_present"
            if has_primary
            else "explicitly_unmapped"
            if entry.get("unmapped") is True
            else "unresolved"
        )
        counts[state] += 1
        if not has_primary:
            diagnostic_reason = None
            if state == "unresolved":
                diagnostic_reason = _diagnose_unresolved(entry)
                unresolved_by_diagnostic[diagnostic_reason] += 1
            missing.append(
                {
                    "name": name,
                    "state": state,
                    "diagnostic_reason": diagnostic_reason,
                    **{field: entry.get(field) for field in EVIDENCE_FIELDS},
                    "download_count": downloads,
                }
            )

    if sum(counts.values()) != len(packages):
        raise RuntimeError("primary-PURL coverage counts do not reconcile")
    if sum(unresolved_by_diagnostic.values()) != counts["unresolved"]:
        raise RuntimeError("unresolved diagnostic counts do not reconcile")

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "input_schema_version": payload["schema_version"],
        "channel": channel,
        "counts": {
            "total": len(packages),
            **counts,
            "primary_missing": counts["explicitly_unmapped"] + counts["unresolved"],
        },
        "unresolved_by_diagnostic": unresolved_by_diagnostic,
        "missing_packages": missing,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Freshly merged full mappings.json bundle",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write the report to this path instead of standard output",
    )
    args = parser.parse_args()
    try:
        # The shared loader rejects duplicate keys and non-finite JSON numbers.
        report = build_report(merge_mappings._load_json(args.input))
        rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"mappings report: {exc}\n")


if __name__ == "__main__":
    main()
