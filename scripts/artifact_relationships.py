"""Review-only, ecosystem-neutral artifact relationships. No publication/matching.

Replace/remove records are an append-only review log, keyed by exact conda PURL
and digest. Evidence is content-addressed and typed separately. All historical
records remain validated, including those superseded or removed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from packageurl import PackageURL

from scripts.merge_mappings import (
    _duplicate_safe_object,
    _parse_timestamp,
    _reject_nonstandard_number,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RELATIONSHIPS = ROOT / "mappings/artifact_relationships"
DEFAULT_EVIDENCE = ROOT / "mappings/relationship_evidence"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def fields(value: object, names: str, label: str) -> dict:
    require(
        isinstance(value, dict) and set(value) == set(names.split()),
        f"{label}: unsupported fields",
    )
    return value


def text(value: object, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label}: required string")
    return value


def digest(value: object) -> None:
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
        "invalid SHA256",
    )


def purl(value: object) -> PackageURL:
    value = text(value, "PURL")
    parsed = PackageURL.from_string(value)
    require(
        parsed.to_string() == value and not parsed.subpath,
        "noncanonical or subpath PURL",
    )
    return parsed


def validate_subject(value: object) -> None:
    value = fields(value, "purl sha256", "subject")
    parsed = purl(value["purl"])
    require(
        parsed.type == "conda"
        and parsed.namespace == "conda-forge"
        and bool(parsed.version)
        and set(parsed.qualifiers) == {"build", "subdir"},
        "subject requires exact conda version/build/subdir",
    )
    digest(value["sha256"])


def validate_claim(value: object, subject: dict) -> None:
    value = fields(value, "relationship upstream", "claim")
    require(
        value["relationship"] in {"derived_from", "contains"},
        "unsupported relationship",
    )
    upstream = fields(value["upstream"], "purl sha256", "upstream")
    parsed = purl(upstream["purl"])
    require(
        upstream["purl"] != subject["purl"]
        or upstream["sha256"] not in (None, subject["sha256"]),
        "self relationship is forbidden",
    )
    if upstream["sha256"] is not None:
        digest(upstream["sha256"])
        require(
            bool(parsed.version), "artifact digest requires versioned upstream PURL"
        )
    if value["relationship"] == "derived_from":
        require(
            bool(parsed.version) and upstream["sha256"] is not None,
            "derived_from requires exact upstream version and digest",
        )
    # contains may describe a versionless project; this never asserts version
    # equivalence, a source commit, or vulnerability applicability.


def validate_claims(claims: object, subject: dict) -> None:
    require(isinstance(claims, list) and bool(claims), "nonempty claims required")
    seen = set()
    for claim in claims:
        validate_claim(claim, subject)
        key = claim_key(claim)
        require(key not in seen, "duplicate relationship")
        seen.add(key)


def load_document(path: Path, expected_digest: str | None = None) -> dict:
    raw = path.read_bytes()
    if expected_digest is not None:
        digest(expected_digest)
        require(
            hashlib.sha256(raw).hexdigest() == expected_digest,
            "evidence digest mismatch",
        )
    return json.loads(
        raw,
        object_pairs_hook=_duplicate_safe_object,
        parse_constant=_reject_nonstandard_number,
    )


def validate_evidence(data: dict) -> None:
    fields(data, "schema_version kind subject claims details", "evidence")
    require(
        type(data["schema_version"]) is int and data["schema_version"] == 1,
        "unsupported evidence schema",
    )
    validate_subject(data["subject"])
    validate_claims(data["claims"], data["subject"])
    if data["kind"] == "reviewed-provenance":
        # Ecosystem-neutral manual evidence, not an assertion of byte equality.
        details = fields(data["details"], "references notes", "reviewed provenance")
        text(details["notes"], "evidence notes")
        require(
            isinstance(details["references"], list) and bool(details["references"]),
            "evidence references required",
        )
        from urllib.parse import urlsplit

        for reference in details["references"]:
            fields(reference, "url description", "reference")
            url = urlsplit(text(reference["url"], "reference URL"))
            require(
                url.scheme == "https" and bool(url.hostname) and not url.username,
                "reference requires HTTPS URL",
            )
            text(reference["description"], "reference description")
    elif data["kind"] == "rpm-payload-comparison":
        from scripts.rpm_component_evidence import validate_evidence_details

        details = data["details"]
        validate_evidence_details(details)
        require(
            data["subject"]
            == {
                "purl": details["subject"]["purl"],
                "sha256": details["subject"]["artifact"]["sha256"],
            },
            "RPM evidence subject mismatch",
        )
        expected = [
            {
                "relationship": "derived_from",
                "upstream": {
                    "purl": details["derived_from"]["purl"],
                    "sha256": details["derived_from"]["artifact"]["sha256"],
                },
            },
            {
                "relationship": "contains",
                "upstream": {
                    "purl": details["contains"]["upstream_purl"],
                    "sha256": None,
                },
            },
        ]
        require(
            sorted(data["claims"], key=claim_key) == sorted(expected, key=claim_key),
            "RPM evidence claims mismatch",
        )
    else:
        raise ValueError(
            "unsupported evidence kind; add a validator before accepting it"
        )


def subject_key(subject: dict) -> tuple[str, str]:
    return subject["purl"], subject["sha256"]


def claim_key(claim: dict) -> tuple[str, str, str]:
    return (
        claim["relationship"],
        claim["upstream"]["purl"],
        claim["upstream"]["sha256"] or "",
    )


def evidence_path(root: Path, value: object) -> Path:
    value = text(value, "evidence path")
    require(
        not value.startswith("/")
        and "\\" not in value
        and all(p not in {"", ".", ".."} for p in value.split("/")),
        "unsafe evidence path",
    )
    target = (root / value).resolve()
    require(
        target.is_relative_to(root.resolve()) and target.is_file(),
        "missing or escaping evidence file",
    )
    return target


def validate_record(data: dict, evidence_root: Path) -> None:
    fields(
        data,
        "schema_version status operation subject review rationale relationships",
        "relationship record",
    )
    require(
        type(data["schema_version"]) is int and data["schema_version"] == 1,
        "unsupported relationship schema",
    )
    require(
        data["status"] == "review-only", "relationship record cannot enable matching"
    )
    require(data["operation"] in {"replace", "remove"}, "unsupported operation")
    validate_subject(data["subject"])
    review = fields(data["review"], "reviewer reviewed_at", "review")
    text(review["reviewer"], "reviewer")
    _parse_timestamp(review["reviewed_at"], "reviewed_at")
    text(data["rationale"], "rationale")
    require(isinstance(data["relationships"], list), "relationships must be an array")
    if data["operation"] == "remove":
        require(not data["relationships"], "remove must have no relationships")
        return
    claims = []
    for relationship in data["relationships"]:
        fields(relationship, "relationship upstream evidence", "relationship")
        claim = {k: relationship[k] for k in ("relationship", "upstream")}
        reference = fields(
            relationship["evidence"], "path sha256", "evidence reference"
        )
        digest(reference["sha256"])
        path = evidence_path(evidence_root, reference["path"])
        evidence = load_document(path, reference["sha256"])
        validate_evidence(evidence)
        require(
            evidence["subject"] == data["subject"],
            "evidence bound to a different subject",
        )
        require(
            claim in evidence["claims"],
            "relationship not supported by referenced evidence",
        )
        claims.append(claim)
    validate_claims(claims, data["subject"])


def replay_records(
    records: list[tuple[dict, str]], evidence_root: Path
) -> dict[tuple[str, str], dict]:
    """Deterministic full replacement; removals remain explicit tombstones.

    PURL plus digest is the subject key: multiple archive representations can
    legitimately share coordinates. Never fall back to coordinates alone.
    Conflicting same-instant decisions for the same exact artifact fail closed.
    """
    ordered = []
    instants = {}
    filenames = set()
    for data, filename in records:
        require(filename not in filenames, "duplicate review filename")
        filenames.add(filename)
        validate_record(data, evidence_root)
        key = subject_key(data["subject"])
        instant = _parse_timestamp(data["review"]["reviewed_at"], "reviewed_at")
        normalized = {
            **data,
            "review": {**data["review"], "reviewed_at": instant.isoformat()},
            "relationships": sorted(data["relationships"], key=claim_key),
        }
        if (key, instant) in instants:
            require(
                instants[key, instant] == normalized,
                "conflicting reviews at same instant",
            )
        instants[key, instant] = normalized
        ordered.append((instant, filename, normalized))
    effective = {}
    for _, filename, data in sorted(ordered, key=lambda r: (r[0], r[1])):
        effective[subject_key(data["subject"])] = {**data, "source": filename}
    return dict(sorted(effective.items()))


def load_relationships(
    directory: Path = DEFAULT_RELATIONSHIPS, evidence_root: Path = DEFAULT_EVIDENCE
) -> dict[tuple[str, str], dict]:
    require(
        directory.is_dir() and evidence_root.is_dir(),
        "missing relationship/evidence directory",
    )
    # Orphan evidence is allowed during review, but must still be valid.
    for path in sorted(evidence_root.rglob("*.json")):
        require(
            path.resolve().is_relative_to(evidence_root.resolve()),
            "escaping evidence file",
        )
        validate_evidence(load_document(path))
    return replay_records(
        [(load_document(path), path.name) for path in sorted(directory.glob("*.json"))],
        evidence_root,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT_RELATIONSHIPS)
    parser.add_argument("--evidence-directory", type=Path, default=DEFAULT_EVIDENCE)
    args = parser.parse_args()
    try:
        effective = load_relationships(args.directory, args.evidence_directory)
        removed = sum(d["operation"] == "remove" for d in effective.values())
        print(
            f"Validated {len(effective)} review-only subjects ({removed} tombstones); structure/evidence digests only, artifact bytes not checked. No mappings published."
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"artifact relationships: {exc}\n")


if __name__ == "__main__":
    main()
