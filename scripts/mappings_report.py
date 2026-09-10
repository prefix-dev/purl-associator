"""Report primary-PURL coverage from a freshly merged full mapping bundle.

This is a read-only report, not a mapper or a source-layer merger. Rebuild older
published bundles with scripts.merge_mappings first: the current identities
contract is required. Alternative PURLs and CPEs do not count as primary PURLs.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
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
COVERAGE_LABELS = (
    ("total", "Total packages"),
    ("primary_present", "Primary PURL present"),
    ("explicitly_unmapped", "Explicitly unmapped"),
    ("unresolved", "Unresolved"),
    ("primary_missing", "Primary PURL missing"),
)
DIAGNOSTIC_LABELS = {
    "recorded_processing_error": "Recorded processing error",
    "alternative_only": "Alternative PURL only",
    "no_parseable_source_host": "No parseable source host",
    "no_primary_from_url_evidence": "URL evidence without primary PURL",
}


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


def _diagnose_unresolved(entry: dict[str, Any], source_hosts: tuple[str, ...]) -> str:
    """Classify persisted evidence without claiming an authoritative root cause."""
    note = (entry.get("note") or "").strip()
    if note.lower().startswith("fetch error:"):
        return "recorded_processing_error"
    if _has_alternative_purl(entry):
        return "alternative_only"
    if not source_hosts:
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
    unresolved_source_hosts: Counter[str] = Counter()
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
            source_hosts = _source_hosts(entry)
            diagnostic_reason = None
            if state == "unresolved":
                diagnostic_reason = _diagnose_unresolved(entry, source_hosts)
                unresolved_by_diagnostic[diagnostic_reason] += 1
                unresolved_source_hosts.update(source_hosts)
            missing.append(
                {
                    "name": name,
                    "state": state,
                    "diagnostic_reason": diagnostic_reason,
                    "source_hosts": list(source_hosts),
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
        "unresolved_by_source_host": [
            {"host": host, "package_count": package_count}
            for host, package_count in sorted(
                unresolved_source_hosts.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "missing_packages": missing,
    }


def _non_negative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _comparison_metrics(
    report: Any, label: str
) -> tuple[dict[str, int], dict[str, int]]:
    """Validate and return stable aggregate metrics used for comparisons."""
    if (
        not isinstance(report, dict)
        or report.get("schema_version") != REPORT_SCHEMA_VERSION
    ):
        raise ValueError(f"{label} must use report schema {REPORT_SCHEMA_VERSION}")
    if type(report.get("input_schema_version")) is not int:
        raise ValueError(f"{label}.input_schema_version must be an integer")
    raw_counts = report.get("counts")
    expected_counts = {key for key, _ in COVERAGE_LABELS}
    if not isinstance(raw_counts, dict) or set(raw_counts) != expected_counts:
        raise ValueError(f"{label}.counts has an unsupported shape")
    counts = {
        key: _non_negative_int(raw_counts[key], f"{label}.counts.{key}")
        for key, _ in COVERAGE_LABELS
    }
    if (
        counts["primary_present"] + counts["explicitly_unmapped"] + counts["unresolved"]
        != counts["total"]
        or counts["explicitly_unmapped"] + counts["unresolved"]
        != counts["primary_missing"]
    ):
        raise ValueError(f"{label}.counts do not reconcile")

    raw_diagnostics = report.get("unresolved_by_diagnostic")
    if not isinstance(raw_diagnostics, dict) or set(raw_diagnostics) != set(
        UNRESOLVED_DIAGNOSTICS
    ):
        raise ValueError(f"{label}.unresolved_by_diagnostic has an unsupported shape")
    diagnostics = {
        diagnostic: _non_negative_int(
            raw_diagnostics[diagnostic],
            f"{label}.unresolved_by_diagnostic.{diagnostic}",
        )
        for diagnostic in UNRESOLVED_DIAGNOSTICS
    }
    if sum(diagnostics.values()) != counts["unresolved"]:
        raise ValueError(f"{label}.unresolved_by_diagnostic does not reconcile")
    return counts, diagnostics


def _delta(value: int) -> str:
    return f"+{value:,}" if value > 0 else f"{value:,}"


def render_markdown(
    report: dict[str, Any],
    *,
    baseline: dict[str, Any] | None = None,
    top_hosts: int = 15,
) -> str:
    """Render bounded, deterministic coverage Markdown for humans and PR bodies."""
    if top_hosts < 0:
        raise ValueError("top_hosts must be non-negative")
    counts, diagnostics = _comparison_metrics(report, "report")
    baseline_counts: dict[str, int] | None = None
    baseline_diagnostics: dict[str, int] | None = None
    if baseline is not None:
        baseline_counts, baseline_diagnostics = _comparison_metrics(
            baseline, "baseline report"
        )
        if baseline.get("input_schema_version") != report.get("input_schema_version"):
            raise ValueError("baseline and current input schema versions differ")

    out = ["## Primary-PURL coverage", ""]
    if baseline_counts is None:
        out.extend(["| Metric | Count |", "|---|---:|"])
        out.extend(
            f"| {metric_label} | {counts[key]:,} |"
            for key, metric_label in COVERAGE_LABELS
        )
    else:
        out.extend(["| Metric | Before | After | Delta |", "|---|---:|---:|---:|"])
        out.extend(
            f"| {metric_label} | {baseline_counts[key]:,} | {counts[key]:,} | "
            f"{_delta(counts[key] - baseline_counts[key])} |"
            for key, metric_label in COVERAGE_LABELS
        )
    coverage = (
        100 * counts["primary_present"] / counts["total"] if counts["total"] else 0
    )
    out.extend(["", f"Primary-PURL coverage: **{coverage:.2f}%**.", ""])

    out.extend(["### Unresolved diagnostics", ""])
    if baseline_diagnostics is None:
        out.extend(["| Diagnostic | Count |", "|---|---:|"])
        out.extend(
            f"| {DIAGNOSTIC_LABELS[diagnostic]} | {diagnostics[diagnostic]:,} |"
            for diagnostic in UNRESOLVED_DIAGNOSTICS
        )
    else:
        out.extend(["| Diagnostic | Before | After | Delta |", "|---|---:|---:|---:|"])
        out.extend(
            f"| {DIAGNOSTIC_LABELS[diagnostic]} | "
            f"{baseline_diagnostics[diagnostic]:,} | {diagnostics[diagnostic]:,} | "
            f"{_delta(diagnostics[diagnostic] - baseline_diagnostics[diagnostic])} |"
            for diagnostic in UNRESOLVED_DIAGNOSTICS
        )

    raw_hosts = report.get("unresolved_by_source_host")
    if not isinstance(raw_hosts, list):
        raise ValueError("report.unresolved_by_source_host must be an array")
    hosts: list[tuple[str, int]] = []
    for index, raw_host in enumerate(raw_hosts):
        if not isinstance(raw_host, dict) or set(raw_host) != {"host", "package_count"}:
            raise ValueError(
                f"report.unresolved_by_source_host[{index}] has an unsupported shape"
            )
        host = raw_host["host"]
        if not isinstance(host, str) or not host:
            raise ValueError(
                f"report.unresolved_by_source_host[{index}].host must be non-empty"
            )
        hosts.append(
            (
                host,
                _non_negative_int(
                    raw_host["package_count"],
                    f"report.unresolved_by_source_host[{index}].package_count",
                ),
            )
        )
    if hosts != sorted(hosts, key=lambda item: (-item[1], item[0])):
        raise ValueError("report.unresolved_by_source_host is not sorted")

    out.extend(
        [
            "",
            f"### Top unresolved source hosts ({min(top_hosts, len(hosts)):,})",
            "",
            "Host counts are non-exclusive; each host is counted once per unresolved package.",
            "",
            "| Source host | Packages |",
            "|---|---:|",
        ]
    )
    out.extend(
        f"| `{host}` | {package_count:,} |" for host, package_count in hosts[:top_hosts]
    )
    return "\n".join(out) + "\n"


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
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--baseline-report",
        type=Path,
        help="Earlier JSON report to compare in Markdown output",
    )
    parser.add_argument(
        "--top-hosts",
        type=int,
        default=15,
        help="Maximum source hosts in Markdown output (default: 15)",
    )
    args = parser.parse_args()
    if args.baseline_report and args.format != "markdown":
        parser.error("--baseline-report requires --format markdown")
    try:
        # The shared loader rejects duplicate keys and non-finite JSON numbers.
        report = build_report(merge_mappings._load_json(args.input))
        baseline = (
            merge_mappings._load_json(args.baseline_report)
            if args.baseline_report
            else None
        )
        rendered = (
            json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
            if args.format == "json"
            else render_markdown(report, baseline=baseline, top_hosts=args.top_hosts)
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError) as exc:
        parser.exit(1, f"mappings report: {exc}\n")


if __name__ == "__main__":
    main()
