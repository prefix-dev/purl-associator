"""Stage immutable CDT review contributions for a human-approved PR, never publish."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from packageurl import PackageURL

from scripts import cdt_automap as cdt

ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTIONS = Path("mappings/cdt_contributions")
EVIDENCE = Path("mappings/cdt_evidence")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def fields(value, names):
    require(
        isinstance(value, dict) and set(value) == set(names.split()),
        f"Unexpected fields; expected {names}",
    )


def document(path):
    require(
        not path.is_symlink() and path.stat().st_size <= 16 * 1024 * 1024,
        "Unsafe/oversized review file",
    )
    return cdt.load_json(path.read_bytes())


def key_for(draft):
    return cdt.sha256(
        (
            draft["subject"]["purl"] + "\n" + draft["subject"]["artifact"]["sha256"]
        ).encode()
    )


def validate_candidate(draft, metadata_path):
    fields(
        draft,
        "draft_schema_version generator status subject relationships evidence limitations",
    )
    require(
        type(draft["draft_schema_version"]) is int
        and draft["draft_schema_version"] == 1,
        "Unsupported draft schema",
    )
    require(
        draft["generator"] == cdt.GENERATOR
        and draft["status"] == "candidate-needs-review",
        "No automatic approval or unknown generator allowed",
    )
    fields(draft["subject"], "purl artifact")
    subject = PackageURL.from_string(draft["subject"]["purl"])
    require(
        subject.to_string() == draft["subject"]["purl"]
        and subject.type == "conda"
        and subject.namespace == "conda-forge"
        and subject.version
        and not subject.subpath
        and set(subject.qualifiers) == {"build", "subdir"},
        "Subject must be exact canonical conda coordinates",
    )
    artifact = draft["subject"]["artifact"]
    fields(artifact, "url sha256")
    require(cdt.valid_digest(artifact["sha256"]), "Missing conda digest")
    entry = {
        "name": subject.name,
        "version": subject.version,
        "build": subject.qualifiers["build"],
        "subdir": subject.qualifiers["subdir"],
        **artifact,
    }
    evidence = draft["evidence"]
    fields(
        evidence,
        "conda_release_metadata recipe_source_url rpm_header embedded_files transformation",
    )
    ref = evidence["conda_release_metadata"]
    fields(ref, "url sha256 basename")
    require(
        cdt.valid_digest(ref["sha256"]) and not metadata_path.is_symlink(),
        "Invalid metadata reference",
    )
    require(metadata_path.stat().st_size <= 8 * cdt.MAX_METADATA, "Oversized metadata")
    require(
        cdt.sha256(metadata_path.read_bytes()) == ref["sha256"],
        "Metadata checksum mismatch",
    )
    _, actual_ref = cdt.conda_descriptor(
        entry, SimpleNamespace(get=lambda *a, **kw: metadata_path)
    )
    require(ref == actual_ref, "Metadata not bound to subject")
    embedded = {}
    require(
        isinstance(evidence["embedded_files"], list), "Embedded files must be a list"
    )
    for file in evidence["embedded_files"]:
        fields(file, "path sha256 text")
        require(
            file["path"]
            in {"info/index.json", "info/recipe/meta.yaml", "info/recipe/build.sh"}
            and file["path"] not in embedded,
            "Duplicate/unsupported embedded file",
        )
        require(
            isinstance(file["text"], str)
            and len(file["text"].encode()) <= cdt.MAX_METADATA
            and cdt.sha256(file["text"].encode()) == file["sha256"],
            "Embedded evidence checksum mismatch",
        )
        embedded[file["path"]] = file["text"]
    require(
        {"info/index.json", "info/recipe/meta.yaml"} <= embedded.keys(),
        "Missing embedded index/recipe",
    )
    index = cdt.load_json(embedded["info/index.json"])
    require(
        all(index.get(k) == entry[k] for k in ("name", "version", "build", "subdir")),
        "Embedded index differs from subject",
    )
    recipe, source = cdt.parse_recipe(embedded["info/recipe/meta.yaml"].encode())
    require(
        recipe.get("package", {}).get("name") == subject.name
        and str(recipe.get("package", {}).get("version")) == subject.version,
        "Recipe differs from subject",
    )
    require(
        source["recipe_url"] == evidence["recipe_source_url"], "Recipe source mismatch"
    )
    header = evidence["rpm_header"]
    fields(header, "name version release epoch arch vendor sourcerpm")
    require(
        all(isinstance(v, str) and v for k, v in header.items() if k != "epoch"),
        "Missing RPM header",
    )
    require(
        header["epoch"] is None
        or type(header["epoch"]) is int
        and header["epoch"] >= 0,
        "Invalid epoch",
    )
    require(
        header["vendor"] == "CentOS"
        and header["arch"] in {source["repository_arch"], "noarch"},
        "RPM distro/arch mismatch",
    )
    require(
        source["filename"]
        == f"{header['name']}-{header['version']}-{header['release']}.{header['arch']}.rpm",
        "RPM filename/header mismatch",
    )
    major = source["distro"].split("-")[1].split(".")[0]
    require(
        re.search(rf"\.el{major}(?:[._]|$)", header["release"]) is not None,
        "RPM release/distro mismatch",
    )
    qualifiers = {"arch": header["arch"], "distro": source["distro"]}
    if header["epoch"] is not None:
        qualifiers["epoch"] = str(header["epoch"])
    expected_purl = PackageURL(
        type="rpm",
        namespace="centos",
        name=header["name"],
        version=header["version"] + "-" + header["release"],
        qualifiers=qualifiers,
    ).to_string()
    require(
        draft["relationships"]
        == [
            {
                "relationship": "derived_from",
                "upstream": {
                    "purl": expected_purl,
                    "artifact": {"url": source["url"], "sha256": source["sha256"]},
                },
            }
        ],
        "Only the exact recipe-bound RPM derivation is supported",
    )
    transform = evidence["transformation"]
    fields(transform, "kind prefix payload")
    require(
        transform["kind"] == "sysroot-prefix-relocation"
        and isinstance(transform["prefix"], str)
        and re.fullmatch(r"[A-Za-z0-9_-]+/sysroot/", transform["prefix"]),
        "Unsupported transformation",
    )
    require(
        isinstance(transform["payload"], list)
        and 0 < len(transform["payload"]) <= cdt.MAX_MEMBERS,
        "Empty/oversized payload manifest",
    )
    seen = set()
    for row in transform["payload"]:
        fields(
            row,
            "conda_path rpm_path kind sha256 size"
            + (" target" if row.get("kind") == "symlink" else ""),
        )
        cdt.safe_path(row["rpm_path"])
        require(
            row["conda_path"] == transform["prefix"] + row["rpm_path"]
            and row["rpm_path"] not in seen,
            "Duplicate/mis-scoped payload path",
        )
        seen.add(row["rpm_path"])
        require(
            row["kind"] in {"file", "symlink"}
            and cdt.valid_digest(row["sha256"])
            and type(row["size"]) is int
            and 0 <= row["size"] <= cdt.MAX_EXPANDED,
            "Invalid payload metadata",
        )
        if row["kind"] == "symlink":
            require(
                isinstance(row["target"], str)
                and cdt.sha256(row["target"].encode()) == row["sha256"]
                and len(row["target"].encode()) == row["size"],
                "Symlink evidence mismatch",
            )
    require(
        sum(row["size"] for row in transform["payload"]) <= cdt.MAX_EXPANDED,
        "Payload total exceeds generator limit",
    )
    require(
        isinstance(draft["limitations"], list)
        and draft["limitations"]
        and all(isinstance(v, str) and v.strip() for v in draft["limitations"]),
        "Limitations required",
    )
    return entry


def validate_directory(root=ROOT):
    directory, evidence = root / CONTRIBUTIONS, root / EVIDENCE
    count = 0
    require(
        not directory.is_symlink()
        and not evidence.is_symlink()
        and directory.resolve().is_relative_to(root.resolve())
        and evidence.resolve().is_relative_to(root.resolve()),
        "Review directories cannot escape the checkout",
    )
    for path in sorted(directory.glob("*.json")):
        draft = document(path)
        ref = draft["evidence"]["conda_release_metadata"]["sha256"]
        require(cdt.valid_digest(ref), "Invalid evidence filename")
        validate_candidate(draft, evidence / (ref + ".json"))
        require(
            path.name == key_for(draft) + ".json",
            "Contribution filename/subject mismatch",
        )
        count += 1
    for path in evidence.glob("*.json"):
        require(
            not path.is_symlink() and path.stem == cdt.sha256(path.read_bytes()),
            "Evidence filename/digest mismatch",
        )
        document(path)
    return count


def stable_claim(draft):
    value = copy.deepcopy(draft)
    # API download counters/upload listings may change without changing the
    # artifact proof. Keep the originally reviewed evidence, not weekly churn.
    value["evidence"]["conda_release_metadata"].pop("sha256")
    return value


def prepare(bundle, root, body):
    require(
        not any(
            body.resolve().is_relative_to(path.resolve())
            for path in (root / "mappings", root / "web/public")
        ),
        "PR body must stay outside mapping/public data",
    )
    validate_directory(root)
    report = document(bundle / "drafts/report.json")
    snapshot = document(bundle / "input-snapshot.json")["packages"]
    run = document(bundle / "run.json")
    require(
        re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", run["source_revision"]) is not None
        and cdt.valid_digest(run["source_sha256"]),
        "Missing source provenance",
    )
    fields(report, "draft_schema_version generator counts results")
    require(
        type(report["draft_schema_version"]) is int
        and report["draft_schema_version"] == 1
        and report["generator"] == cdt.GENERATOR,
        "Unsupported report schema/generator",
    )
    require(run["only"] is None or isinstance(run["only"], str), "Invalid selector")
    selected_again = cdt.select_entries(snapshot, run["only"], run["limit"])
    require(
        {p["name"] for p in selected_again} == set(snapshot),
        "Input does not match selector",
    )
    selector = {
        "only": sorted(run["only"].split(",")) if run["only"] else None,
        "limit": None if run["only"] else run["limit"],
    }
    branch = (
        "cdt/review-" + cdt.sha256(json.dumps(selector, sort_keys=True).encode())[:20]
    )
    rows = report["results"]
    require(
        isinstance(rows, list) and 0 < len(rows) <= 100, "Incomplete/oversized report"
    )
    require(
        len({r["name"] for r in rows}) == len(rows)
        and {r["name"] for r in rows} == set(snapshot) == set(run["selected_packages"]),
        "Report does not cover the exact selected input",
    )
    require(
        report["counts"] == dict(Counter(r["status"] for r in rows))
        and all(r["status"] in {"candidate-needs-review", "deferred"} for r in rows),
        "Failed/inconsistent batches cannot update a review PR",
    )
    pending, unchanged = [], 0
    for row in rows:
        if row["status"] != "candidate-needs-review":
            require("draft" not in row, "Deferred row cannot contribute a draft")
            continue
        require(
            re.fullmatch(r"[0-9a-f]{64}\.json", row["draft"]) is not None,
            "Unsafe draft filename",
        )
        draft = document(bundle / "drafts" / row["draft"])
        ref = draft["evidence"]["conda_release_metadata"]
        metadata = bundle / "metadata" / (cdt.sha256(ref["url"].encode()) + ".json")
        entry = validate_candidate(draft, metadata)
        selected = snapshot[row["name"]]
        require(
            all(
                entry[k] == selected[k]
                for k in ("name", "version", "build", "subdir", "url")
            )
            and row["url"] == entry["url"],
            "Candidate differs from selected artifact",
        )
        require(
            "sha256" not in selected or selected["sha256"] == entry["sha256"],
            "Pinned selection checksum differs",
        )
        require(
            row["payload_entries"]
            == len(draft["evidence"]["transformation"]["payload"]),
            "Report payload count mismatch",
        )
        require(row["draft"] == key_for(draft) + ".json", "Draft filename mismatch")
        target = root / CONTRIBUTIONS / row["draft"]
        if target.exists():
            require(
                stable_claim(document(target)) == stable_claim(draft),
                "Existing reviewed artifact conflicts; explicit correction required",
            )
            unchanged += 1
        else:
            pending.append((target, draft, metadata.read_bytes()))
    # Do not write anything until the entire batch and existing records validate.
    for target, draft, raw in pending:
        target.parent.mkdir(parents=True, exist_ok=True)
        (root / EVIDENCE).mkdir(parents=True, exist_ok=True)
        evidence_target = root / EVIDENCE / (cdt.sha256(raw) + ".json")
        if evidence_target.exists():
            require(evidence_target.read_bytes() == raw, "Existing evidence conflicts")
        else:
            evidence_target.write_bytes(raw)
        target.write_text(json.dumps(draft, indent=2) + "\n")
    lines = [
        "## Generated CDT review contributions",
        "",
        "**Human review and merge required. No auto-merge, approval attribution, active mapping or vulnerability coverage change.**",
        "",
        f"Source revision: `{run['source_revision']}`",
        f"Mapper snapshot SHA256: `{run['source_sha256']}`",
        f"New contributions: **{len(pending)}**; already recorded: **{unchanged}**.",
        "",
        "Approve/merge this PR to retain these exact-artifact identity reviews. Records preserve their generated candidate status; the GitHub review/merge history records human acceptance. Publication/Basilisk consumption remain separate gates.",
        "",
        "### Batch results",
    ]
    lines += [
        f"- `{r['name']}`: {r['status']}"
        + (f" ({r['reason']})" if "reason" in r else "")
        for r in rows
    ]
    lines += ["", "### New exact-artifact claims"]
    for target, draft, _ in pending:
        lines += [
            f"- `{draft['subject']['purl']}` → `{draft['relationships'][0]['upstream']['purl']}`",
            f"  - {len(draft['evidence']['transformation']['payload'])} payload entries; contribution `{target.name}`; conda SHA256 `{draft['subject']['artifact']['sha256']}`.",
        ]
    lines += [
        "",
        "### Review checklist",
        "- [ ] Inspect exact conda/RPM PURLs, checksums, embedded recipe and full payload manifest.",
        "- [ ] Confirm the CentOS source/release/architecture and preserve all deferrals.",
        "- [ ] Confirm no package-wide primary/alternative identity or CVE conclusion is inferred.",
        "",
        "CI validates structure and evidence bindings offline; it does not independently re-download and re-verify archive bytes. Do not manually rewrite immutable records to change an existing artifact claim.",
        "",
    ]
    body.write_text("\n".join(lines))
    return {"branch": branch, "added": len(pending), "unchanged": unchanged}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--bundle", type=Path)
    mode.add_argument("--validate", action="store_true")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--body", type=Path)
    args = parser.parse_args()
    try:
        if args.validate:
            print(
                f"Validated {validate_directory(args.root)} dormant CDT review contribution(s); no active identities emitted"
            )
        else:
            require(args.body is not None, "--body required for submissions")
            result = prepare(args.bundle, args.root, args.body)
            print(json.dumps(result, sort_keys=True))
            if os.environ.get("GITHUB_OUTPUT"):
                with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
                    output.writelines(
                        f"{key}={result[key]}\n"
                        for key in ("branch", "added", "unchanged")
                    )
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"CDT review submission: {exc}\n")


if __name__ == "__main__":
    main()
