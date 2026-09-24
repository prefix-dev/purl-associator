"""RPM-specific evidence adapter for the generic artifact relationship contract.

Supports a single RPM copied under a sysroot prefix, not arbitrary transforms.
Never infers relationships, downloads, extracts files onto disk, or enables
matching. Local byte verification requires the optional rpmfile dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from packageurl import PackageURL

from scripts.merge_mappings import _load_json


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


def relative_path(value: object) -> str:
    path = text(value, "path")
    require(
        not path.startswith("/")
        and "\\" not in path
        and all(p not in {"", ".", ".."} for p in path.split("/")),
        "unsafe/noncanonical path",
    )
    return path


def artifact(value: object) -> None:
    value = fields(value, "url sha256", "artifact")
    url = urlsplit(text(value["url"], "artifact URL"))
    require(
        url.scheme == "https"
        and bool(url.hostname)
        and not url.username
        and not url.fragment,
        "artifact requires HTTPS URL",
    )
    digest(value["sha256"])


def purl(value: object, expected_type: str) -> PackageURL:
    value = text(value, "PURL")
    parsed = PackageURL.from_string(value)
    require(
        parsed.type == expected_type
        and parsed.to_string() == value
        and not parsed.subpath,
        "wrong/noncanonical PURL",
    )
    return parsed


def validate_evidence_details(data: dict) -> None:
    fields(
        data,
        "subject derived_from contains transformation evidence",
        "RPM evidence details",
    )
    subject = fields(data["subject"], "purl artifact", "subject")
    conda = purl(subject["purl"], "conda")
    require(
        conda.namespace == "conda-forge"
        and bool(conda.version)
        and set(conda.qualifiers) == {"build", "subdir"},
        "subject must identify an exact conda build/subdir",
    )
    artifact(subject["artifact"])
    source = fields(data["derived_from"], "purl artifact rpm_header", "derived_from")
    rpm = purl(source["purl"], "rpm")
    artifact(source["artifact"])
    header = fields(
        source["rpm_header"],
        "name version release epoch arch vendor sourcerpm",
        "RPM header",
    )
    for key in set(header) - {"epoch"}:
        text(header[key], f"rpm_header.{key}")
    epoch = header["epoch"]
    require(epoch is None or (type(epoch) is int and epoch >= 0), "invalid RPM epoch")
    require(
        rpm.name == header["name"]
        and rpm.namespace == header["vendor"].lower()
        and rpm.version == f"{header['version']}-{header['release']}",
        "RPM identity/header mismatch",
    )
    require(
        set(rpm.qualifiers)
        == ({"arch", "distro"} | ({"epoch"} if epoch is not None else set())),
        "RPM qualifiers must preserve architecture/distro/epoch",
    )
    require(
        rpm.qualifiers["arch"] == header["arch"] and bool(rpm.qualifiers["distro"]),
        "RPM architecture/distro mismatch",
    )
    if epoch is not None:
        require(rpm.qualifiers["epoch"] == str(epoch), "RPM epoch mismatch")
    component = fields(
        data["contains"],
        "name upstream_purl cpe reported_upstream_version evidence_paths",
        "contains",
    )
    text(component["name"], "component name")
    upstream = purl(component["upstream_purl"], "git")
    require(
        bool(upstream.namespace) and not upstream.version and not upstream.qualifiers,
        "component repository identity must be versionless",
    )
    require(
        re.fullmatch(r"cpe:2\.3:a:[^:]+:[^:]+", text(component["cpe"], "component CPE"))
        is not None,
        "component CPE must be a product prefix",
    )
    require(
        component["reported_upstream_version"] == header["version"],
        "reported version must come from RPM, not conda wrapper version",
    )
    transform = fields(data["transformation"], "kind prefix payload", "transformation")
    require(
        transform["kind"] == "sysroot-prefix-relocation", "unsupported transformation"
    )
    prefix = text(transform["prefix"], "prefix")
    require(prefix.endswith("/"), "prefix must end with slash")
    relative_path(prefix[:-1])
    require(
        isinstance(transform["payload"], list) and bool(transform["payload"]),
        "payload evidence required",
    )
    paths = set()
    regular = set()
    for item in transform["payload"]:
        require(
            isinstance(item, dict) and item.get("kind") in {"file", "symlink"},
            "unsupported payload kind",
        )
        fields(
            item,
            "conda_path rpm_path kind sha256"
            + (" target" if item["kind"] == "symlink" else ""),
            "payload entry",
        )
        path = relative_path(item["conda_path"])
        original = relative_path(item["rpm_path"])
        require(
            path == prefix + original and path not in paths,
            "duplicate path or invalid relocation",
        )
        paths.add(path)
        digest(item["sha256"])
        if item["kind"] == "file":
            regular.add(path)
        else:
            # The pilot only handles same-directory links, not arbitrary rewrites.
            target = relative_path(item["target"])
            require("/" not in target, "unsupported symlink target")
            require(
                hashlib.sha256(target.encode()).hexdigest() == item["sha256"],
                "symlink digest mismatch",
            )
    for item in transform["payload"]:
        if item["kind"] == "symlink":
            require(
                str(PurePosixPath(item["conda_path"]).parent / item["target"])
                in regular,
                "missing symlink target",
            )
    evidence_paths = component["evidence_paths"]
    require(
        isinstance(evidence_paths, list)
        and bool(evidence_paths)
        and all(isinstance(p, str) for p in evidence_paths),
        "component evidence paths required",
    )
    require(
        len(evidence_paths) == len(set(evidence_paths))
        and set(evidence_paths) <= regular,
        "component evidence must reference regular payload files",
    )
    evidence = fields(
        data["evidence"],
        "embedded_recipe_files matching_recipe_url upstream_repository_reference notes",
        "evidence",
    )
    for key in ("matching_recipe_url", "upstream_repository_reference", "notes"):
        text(evidence[key], key)
    require(
        re.fullmatch(
            r"https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/.+",
            evidence["matching_recipe_url"],
        )
        is not None,
        "recipe reference must be immutable",
    )
    require(
        urlsplit(evidence["upstream_repository_reference"]).scheme == "https",
        "upstream reference must use HTTPS",
    )
    recipe_files = evidence["embedded_recipe_files"]
    require(
        isinstance(recipe_files, list) and len(recipe_files) == 2,
        "recipe and build script digests required",
    )
    for item in recipe_files:
        fields(item, "path sha256", "embedded recipe")
        digest(item["sha256"])
    require(
        {i["path"] for i in recipe_files}
        == {"info/recipe/meta.yaml", "info/recipe/build.sh"},
        "wrong embedded recipe paths",
    )


def verify_artifacts(data: dict, conda_path: Path, rpm_path: Path) -> None:
    """Verify local bytes, headers, embedded recipe and complete payload equality.

    Never extract paths onto disk or execute package scripts. Checksums are
    verified before parsing the locally supplied archives.
    """
    validate_evidence_details(data)
    for path, expected in (
        (conda_path, data["subject"]),
        (rpm_path, data["derived_from"]),
    ):
        with path.open("rb") as stream:
            require(
                hashlib.file_digest(stream, "sha256").hexdigest()
                == expected["artifact"]["sha256"],
                f"artifact checksum mismatch: {path}",
            )
    try:
        import rpmfile
    except ImportError as exc:
        raise ValueError(
            "artifact verification requires rpmfile; see README command"
        ) from exc
    conda_purl = PackageURL.from_string(data["subject"]["purl"])
    with tarfile.open(conda_path) as conda, rpmfile.open(str(rpm_path)) as rpm:
        members = conda.getmembers()
        require(
            len({m.name for m in members}) == len(members),
            "duplicate conda archive paths",
        )
        index = json.load(conda.extractfile("info/index.json"))
        require(
            (index["name"], index["version"], index["build"], index["subdir"])
            == (
                conda_purl.name,
                conda_purl.version,
                conda_purl.qualifiers["build"],
                conda_purl.qualifiers["subdir"],
            ),
            "conda index/PURL mismatch",
        )
        for key, expected in data["derived_from"]["rpm_header"].items():
            actual = rpm.headers.get("serial" if key == "epoch" else key)
            if isinstance(actual, bytes):
                actual = actual.decode()
            require(actual == expected, f"RPM header mismatch: {key}")
        for recipe in data["evidence"]["embedded_recipe_files"]:
            raw = conda.extractfile(recipe["path"]).read()
            require(
                hashlib.sha256(raw).hexdigest() == recipe["sha256"],
                "embedded recipe checksum mismatch",
            )
        payload = {
            m.name: m
            for m in members
            if not m.isdir() and not m.name.startswith("info/")
        }
        expected = {
            item["conda_path"]: item for item in data["transformation"]["payload"]
        }
        require(
            payload.keys() == expected.keys(),
            "conda payload is not fully accounted for",
        )
        rpm_members = rpm.getmembers()
        rpm_files = {m.name.removeprefix("./"): m for m in rpm_members if not m.isdir}
        require(
            len(rpm_files) == sum(not m.isdir for m in rpm_members),
            "duplicate RPM payload paths",
        )
        require(
            set(rpm_files) == {i["rpm_path"] for i in expected.values()},
            "RPM payload is not fully accounted for",
        )
        for path, member in payload.items():
            row = expected[path]
            require(
                member.issym() if row["kind"] == "symlink" else member.isfile(),
                "conda payload kind mismatch",
            )
            actual = (
                member.linkname.encode()
                if member.issym()
                else conda.extractfile(member).read()
            )
            original_member = rpm_files[row["rpm_path"]]
            require(
                bool(original_member.issymlink) == member.issym(),
                "RPM/conda payload kind mismatch",
            )
            original = rpm.extractfile(original_member).read()
            require(
                actual == original
                and hashlib.sha256(actual).hexdigest() == row["sha256"],
                f"payload mismatch: {path}",
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify", type=Path, required=True, help="Typed RPM evidence JSON"
    )
    parser.add_argument("--conda-artifact", type=Path, required=True)
    parser.add_argument("--rpm-artifact", type=Path, required=True)
    args = parser.parse_args()
    try:
        from scripts.artifact_relationships import validate_evidence

        evidence = _load_json(args.verify)
        validate_evidence(evidence)
        require(evidence["kind"] == "rpm-payload-comparison", "not RPM evidence")
        verify_artifacts(evidence["details"], args.conda_artifact, args.rpm_artifact)
        print(
            "RPM/conda artifact bytes verified; no mappings published or matching enabled"
        )
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        parser.exit(1, f"RPM evidence: {exc}\n")


if __name__ == "__main__":
    main()
