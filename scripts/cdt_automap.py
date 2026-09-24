"""Generate review-only single-RPM CDT candidates; never update active mappings.

Only exact conda-forge .tar.bz2 artifacts, embedded rendered recipes, CentOS
vault RPMs, and complete byte-identical sysroot relocation are supported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import tarfile
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from packageurl import PackageURL

from scripts.merge_mappings import _duplicate_safe_object, _reject_nonstandard_number

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = "cdt-automap-v1"
MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_METADATA = 1024 * 1024
HOSTS = {"conda.anaconda.org", "api.anaconda.org", "vault.centos.org"}


class Deferred(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def need(condition, code, detail):
    if not condition:
        raise Deferred(code, detail)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_json(raw):
    return json.loads(
        raw,
        object_pairs_hook=_duplicate_safe_object,
        parse_constant=_reject_nonstandard_number,
    )


def safe_path(value):
    need(
        isinstance(value, str)
        and value
        and not value.startswith("/")
        and "\\" not in value
        and "\0" not in value
        and all(p not in {"", ".", ".."} for p in value.split("/")),
        "unsafe-path",
        "Noncanonical archive path",
    )
    return value


def allowed_url(url):
    parsed = urlsplit(url)
    need(
        parsed.scheme == "https"
        and parsed.hostname in HOSTS
        and parsed.username is None
        and parsed.password is None
        and parsed.port in (None, 443)
        and not parsed.query
        and not parsed.fragment,
        "unsupported-url",
        "Only credential-free HTTPS allowlisted origins are supported",
    )
    return parsed


class SameOriginRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = allowed_url(newurl)
        need(
            target.netloc == urlsplit(req.full_url).netloc,
            "unsupported-redirect",
            "Cross-origin redirects are not allowed",
        )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Cache:
    def __init__(self, directory: Path, offline=False):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self.opener = build_opener(SameOriginRedirect())

    def get(self, url, expected=None, limit=MAX_DOWNLOAD):
        allowed_url(url)
        if expected is not None:
            need(
                valid_digest(expected),
                "missing-checksum",
                "A pinned SHA256 is required",
            )
        path = self.directory / sha256(url.encode())
        if not path.exists():
            need(not self.offline, "offline-cache-miss", url)
            with self.opener.open(
                Request(url, headers={"User-Agent": GENERATOR}), timeout=30
            ) as response:
                allowed_url(response.url)
                raw = response.read(limit + 1)
            need(len(raw) <= limit, "resource-limit", "Download exceeds size limit")
            if expected is not None:
                need(
                    sha256(raw) == expected,
                    "checksum-mismatch",
                    "Downloaded archive does not match pinned SHA256",
                )
            with tempfile.NamedTemporaryFile(
                dir=self.directory, delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(raw)
            temporary.replace(path)
        need(
            path.stat().st_size <= limit,
            "resource-limit",
            "Cached object exceeds size limit",
        )
        if expected is not None:
            with path.open("rb") as stream:
                need(
                    hashlib.file_digest(stream, "sha256").hexdigest() == expected,
                    "checksum-mismatch",
                    "Cached archive does not match pinned SHA256; remove corrupt cache entry to retry",
                )
        return path


def conda_descriptor(entry, cache):
    for key in ("name", "version", "build", "subdir", "url"):
        need(
            isinstance(entry.get(key), str) and bool(entry[key]),
            "missing-coordinate",
            f"Missing exact conda {key}",
        )
    url = allowed_url(entry["url"])
    basename = (
        f"{entry['subdir']}/{entry['name']}-{entry['version']}-{entry['build']}.tar.bz2"
    )
    need(
        url.hostname == "conda.anaconda.org" and url.path == "/conda-forge/" + basename,
        "unsupported-conda-artifact",
        "Requires an exact conda-forge .tar.bz2 URL matching the selected coordinates",
    )
    api_url = f"https://api.anaconda.org/release/conda-forge/{quote(entry['name'], safe='')}/{quote(entry['version'], safe='')}"
    metadata = cache.get(api_url, limit=8 * MAX_METADATA).read_bytes()
    matches = [
        d
        for d in load_json(metadata).get("distributions", [])
        if d.get("basename") == basename
    ]
    need(
        len(matches) == 1,
        "ambiguous-conda-metadata",
        "Exact distribution must occur once in release metadata",
    )
    dist = matches[0]
    need(
        dist.get("attrs", {}).get("build") == entry["build"]
        and dist.get("attrs", {}).get("subdir") == entry["subdir"]
        and dist.get("version") == entry["version"],
        "conda-metadata-mismatch",
        "Release metadata disagrees with selected coordinates",
    )
    need(
        valid_digest(dist.get("sha256")),
        "missing-conda-sha256",
        "Exact distribution has no SHA256; MD5 fallback is forbidden",
    )
    if "sha256" in entry:
        need(
            valid_digest(entry["sha256"]) and entry["sha256"] == dist["sha256"],
            "conda-metadata-mismatch",
            "Pinned input checksum disagrees with release metadata",
        )
    return dist["sha256"], {
        "url": api_url,
        "sha256": sha256(metadata),
        "basename": basename,
    }


def parse_recipe(raw):
    import yaml

    need(len(raw) <= MAX_METADATA, "resource-limit", "Embedded recipe too large")
    text = raw.decode("utf-8")
    need(
        "{{" not in text and "{%" not in text and not re.search(r"#\s*\[", text),
        "unrendered-recipe",
        "Recipe contains templates or unevaluated selectors",
    )
    need(
        not any(
            isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken))
            for t in yaml.scan(text)
        ),
        "ambiguous-recipe",
        "YAML aliases/anchors are unsupported",
    )

    class UniqueLoader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                need(key not in result, "ambiguous-recipe", "Duplicate YAML key")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    recipe = yaml.load(text, Loader=UniqueLoader)
    need(
        isinstance(recipe, dict) and "outputs" not in recipe,
        "multi-output-recipe",
        "Output/parent source attribution needs separate review",
    )
    sources = recipe.get("source")
    sources = [sources] if isinstance(sources, dict) else sources
    need(
        isinstance(sources, list)
        and len(sources) == 1
        and isinstance(sources[0], dict),
        "multiple-or-missing-sources",
        "Requires exactly one embedded recipe source",
    )
    source = sources[0]
    urls = source.get("url")
    urls = urls if isinstance(urls, list) else [urls]
    need(
        len(urls) == 1 and isinstance(urls[0], str),
        "ambiguous-source-url",
        "Requires one explicit RPM source URL",
    )
    original = urls[0]
    # Upgrade only the historical CentOS vault origin, not arbitrary HTTP URLs.
    url = (
        original.replace("http://vault.centos.org/", "https://vault.centos.org/", 1)
        if original.startswith("http://vault.centos.org/")
        else original
    )
    parsed = allowed_url(url)
    match = re.fullmatch(
        r"/(?:altarch/)?(6\.\d+|7\.\d+\.\d+)/(?:os|updates)/([^/]+)/Packages/([^/]+\.rpm)",
        parsed.path,
    )
    need(
        parsed.hostname == "vault.centos.org" and match is not None,
        "unsupported-distro-source",
        "Only pinned CentOS 6/7 vault OS/update RPM URLs are supported",
    )
    need(
        valid_digest(source.get("sha256")),
        "missing-rpm-sha256",
        "Recipe must pin the RPM SHA256",
    )
    return recipe, {
        "url": url,
        "recipe_url": original,
        "sha256": source["sha256"],
        "distro": "centos-" + match[1],
        "repository_arch": match[2],
        "filename": match[3],
    }


def read_conda(path, entry):
    payload, recipes = {}, {}
    total = 0
    with tarfile.open(path, "r:bz2") as archive:
        seen = set()
        for member in archive:
            need(len(seen) < MAX_MEMBERS, "resource-limit", "Too many archive members")
            name = safe_path(
                member.name.removesuffix("/") if member.isdir() else member.name
            )
            need(name not in seen, "duplicate-path", "Duplicate conda archive path")
            seen.add(name)
            if member.isdir():
                continue
            need(
                member.isfile() or member.issym(),
                "unsupported-file-kind",
                "Conda hardlinks/devices and special files need separate review",
            )
            need(member.size >= 0, "resource-limit", "Negative archive size")
            total += member.size
            need(
                total <= MAX_EXPANDED,
                "resource-limit",
                "Expanded conda payload exceeds limit",
            )
            if name.startswith("info/"):
                if name in {
                    "info/index.json",
                    "info/recipe/meta.yaml",
                    "info/recipe/build.sh",
                }:
                    need(
                        member.isfile() and member.size <= MAX_METADATA,
                        "invalid-metadata",
                        "Expected small regular metadata file",
                    )
                    recipes[name] = archive.extractfile(member).read()
                continue
            raw = (
                member.linkname.encode()
                if member.issym()
                else archive.extractfile(member).read()
            )
            payload[name] = {
                "kind": "symlink" if member.issym() else "file",
                "sha256": sha256(raw),
                "size": len(raw),
            }
            if member.issym():
                payload[name]["target"] = member.linkname
    need(
        "info/index.json" in recipes and "info/recipe/meta.yaml" in recipes,
        "missing-embedded-recipe",
        "Requires index and rendered embedded recipe, not flattened mapper provenance",
    )
    index = load_json(recipes["info/index.json"])
    need(
        all(index.get(k) == entry[k] for k in ("name", "version", "build", "subdir")),
        "conda-index-mismatch",
        "Conda archive coordinates differ from requested artifact",
    )
    need(
        bool(payload),
        "empty-payload",
        "Empty package is not evidence of an RPM relationship",
    )
    return payload, recipes


def read_cpio(stream):
    """Read bounded newc CPIO directly: rpmfile's member API drops file types."""
    payload, seen, consumed = {}, set(), 0

    def read_exact(size):
        nonlocal consumed
        need(
            0 <= size <= MAX_EXPANDED - consumed,
            "resource-limit",
            "Expanded RPM exceeds limit",
        )
        raw = stream.read(size)
        consumed += len(raw)
        need(len(raw) == size, "truncated-rpm", "Truncated CPIO payload")
        return raw

    while True:
        need(
            read_exact(6) == b"070701",
            "unsupported-cpio",
            "Only newc CPIO is supported",
        )
        raw = read_exact(104)
        need(
            re.fullmatch(b"[0-9a-fA-F]{104}", raw) is not None,
            "invalid-cpio",
            "Invalid CPIO header",
        )
        values = [int(raw[i : i + 8], 16) for i in range(0, 104, 8)]
        mode, links, size, name_size = values[1], values[4], values[6], values[11]
        need(1 <= name_size <= 4096, "resource-limit", "CPIO name exceeds limit")
        name_raw = read_exact(name_size)
        need(name_raw.endswith(b"\0"), "invalid-cpio", "CPIO name is not terminated")
        name = name_raw[:-1].decode("utf-8")
        read_exact((-consumed) % 4)
        if name == "TRAILER!!!":
            need(size == 0, "invalid-cpio", "CPIO trailer has data")
            tail = stream.read(4097)
            need(
                len(tail) <= 4096 and not tail.strip(b"\0"),
                "unsupported-cpio",
                "Data after CPIO trailer",
            )
            return payload
        need(len(seen) < MAX_MEMBERS, "resource-limit", "Too many RPM members")
        name = name.removeprefix("./")
        if name != "." or not stat.S_ISDIR(mode):
            name = safe_path(name.removesuffix("/") if stat.S_ISDIR(mode) else name)
        need(name not in seen, "duplicate-path", "Duplicate RPM archive path")
        seen.add(name)
        need(
            stat.S_ISREG(mode) or stat.S_ISLNK(mode) or stat.S_ISDIR(mode),
            "unsupported-file-kind",
            "RPM devices/special files need separate review",
        )
        need(
            not stat.S_ISREG(mode) or links == 1,
            "unsupported-file-kind",
            "RPM hardlinks need separate review",
        )
        need(
            not stat.S_ISDIR(mode) or size == 0,
            "invalid-cpio",
            "Directory has payload bytes",
        )
        need(
            size <= MAX_EXPANDED - consumed,
            "resource-limit",
            "Expanded RPM exceeds limit",
        )
        need(
            not stat.S_ISLNK(mode) or size <= 4096,
            "resource-limit",
            "Symlink target exceeds limit",
        )
        remaining, digest, link = size, hashlib.sha256(), b""
        while remaining:
            chunk = read_exact(min(remaining, MAX_METADATA))
            remaining -= len(chunk)
            digest.update(chunk)
            if stat.S_ISLNK(mode):
                link += chunk
        read_exact((-consumed) % 4)
        if not stat.S_ISDIR(mode):
            row = {
                "kind": "symlink" if stat.S_ISLNK(mode) else "file",
                "sha256": digest.hexdigest(),
                "size": size,
            }
            if stat.S_ISLNK(mode):
                row["target"] = link.decode("utf-8")
            payload[name] = row


def read_rpm(path, source):
    import rpmfile

    with rpmfile.open(str(path)) as rpm:
        header = {}
        for key in (
            "name",
            "version",
            "release",
            "epoch",
            "arch",
            "vendor",
            "sourcerpm",
        ):
            value = rpm.headers.get("serial" if key == "epoch" else key)
            header[key] = value.decode("utf-8") if isinstance(value, bytes) else value
        need(
            all(
                isinstance(header[k], str) and header[k] for k in header if k != "epoch"
            ),
            "missing-rpm-header",
            "Incomplete native RPM header",
        )
        need(
            header["epoch"] is None
            or type(header["epoch"]) is int
            and header["epoch"] >= 0,
            "invalid-epoch",
            "Unexpected RPM epoch representation",
        )
        need(
            header["vendor"] == "CentOS", "distro-mismatch", "RPM vendor is not CentOS"
        )
        need(
            header["arch"] in {source["repository_arch"], "noarch"},
            "architecture-mismatch",
            "RPM architecture differs from vault repository",
        )
        need(
            source["filename"]
            == f"{header['name']}-{header['version']}-{header['release']}.{header['arch']}.rpm",
            "rpm-filename-mismatch",
            "RPM header disagrees with source filename",
        )
        major = source["distro"].split("-")[1].split(".")[0]
        need(
            re.search(rf"\.el{major}(?:[._]|$)", header["release"]) is not None,
            "distro-mismatch",
            "RPM release does not correspond to vault major version",
        )
        need(
            rpm.headers.get("archive_compression", b"gzip")
            in {b"gzip", b"xz", b"bzip2"},
            "unsupported-compression",
            "Only streaming gzip/xz/bzip2 RPM payloads are supported",
        )
        payload = read_cpio(rpm.data_file)
    return header, payload


def compare_payloads(conda, rpm):
    prefixes = set()
    for name in conda:
        match = re.match(r"^([A-Za-z0-9_-]+/sysroot/)(.+)$", name)
        need(
            match is not None,
            "unsupported-transformation",
            "Every payload entry must be under one sysroot prefix",
        )
        prefixes.add(match[1])
    need(
        len(prefixes) == 1,
        "unsupported-transformation",
        "Multiple sysroot prefixes require separate review",
    )
    prefix = prefixes.pop()
    relocated = {name[len(prefix) :]: row for name, row in conda.items()}
    need(
        relocated.keys() == rpm.keys(),
        "partial-or-mixed-payload",
        f"Payload sets differ: conda={len(conda)}, RPM={len(rpm)}, unmatched conda={len(relocated.keys() - rpm.keys())}, unmatched RPM={len(rpm.keys() - relocated.keys())}",
    )
    manifest = []
    for name in sorted(rpm):
        need(
            relocated[name] == rpm[name],
            "payload-mismatch",
            f"Bytes, file kind, or symlink target differ: {name}",
        )
        manifest.append({"conda_path": prefix + name, "rpm_path": name, **rpm[name]})
    return {"kind": "sysroot-prefix-relocation", "prefix": prefix, "payload": manifest}


def generate(entry, cache):
    conda_sha, metadata = conda_descriptor(entry, cache)
    conda = cache.get(entry["url"], conda_sha)
    payload, recipes = read_conda(conda, entry)
    recipe, source = parse_recipe(recipes["info/recipe/meta.yaml"])
    need(
        str(recipe.get("package", {}).get("version")) == entry["version"]
        and recipe.get("package", {}).get("name") == entry["name"],
        "recipe-subject-mismatch",
        "Embedded recipe package identity disagrees with conda index",
    )
    rpm = cache.get(source["url"], source["sha256"])
    header, original = read_rpm(rpm, source)
    transformation = compare_payloads(payload, original)
    qualifiers = {"arch": header["arch"], "distro": source["distro"]}
    if header["epoch"] is not None:
        qualifiers["epoch"] = str(header["epoch"])
    upstream = PackageURL(
        type="rpm",
        namespace="centos",
        name=header["name"],
        version=header["version"] + "-" + header["release"],
        qualifiers=qualifiers,
    ).to_string()
    subject = PackageURL(
        type="conda",
        namespace="conda-forge",
        name=entry["name"],
        version=entry["version"],
        qualifiers={"build": entry["build"], "subdir": entry["subdir"]},
    ).to_string()
    return {
        "draft_schema_version": 1,
        "generator": GENERATOR,
        "status": "candidate-needs-review",
        "subject": {
            "purl": subject,
            "artifact": {"url": entry["url"], "sha256": conda_sha},
        },
        "relationships": [
            {
                "relationship": "derived_from",
                "upstream": {
                    "purl": upstream,
                    "artifact": {"url": source["url"], "sha256": source["sha256"]},
                },
            }
        ],
        "evidence": {
            "conda_release_metadata": metadata,
            "recipe_source_url": source["recipe_url"],
            "rpm_header": header,
            "embedded_files": [
                {"path": name, "sha256": sha256(raw), "text": raw.decode("utf-8")}
                for name, raw in sorted(recipes.items())
            ],
            "transformation": transformation,
        },
        "limitations": [
            "Not approved or published; no reviewer attribution is inferred.",
            "Complete path/kind/content comparison, not installed filesystem metadata equivalence.",
            "No upstream project/CPE, source commit, distro advisory equivalence, or vulnerability verdict inferred.",
        ],
    }


def select_entries(packages, only=None, limit=None):
    need(
        isinstance(packages, dict)
        and all(
            isinstance(p, dict) and p.get("name") == name
            for name, p in packages.items()
        ),
        "invalid-input",
        "Input must contain a name-keyed package object",
    )
    if only is not None:
        names = only.split(",")
        need(
            all(names) and len(names) == len(set(names)) and len(names) <= 100,
            "invalid-selection",
            "Provide 1-100 unique package names",
        )
        need(
            all(n in packages for n in names),
            "unknown-package",
            "Some selected names are absent from the mapper snapshot",
        )
        return [packages[n] for n in sorted(names)]
    need(
        type(limit) is int and 1 <= limit <= 100,
        "invalid-selection",
        "Batch limit must be between 1 and 100",
    )
    # Discovery hints ONLY. Relationships come from exact archives and embedded
    # recipes, never from this flattened source_url or a package-name suffix.
    candidates = [
        p
        for p in packages.values()
        if "(CDT)" in (p.get("summary") or "")
        or "vault.centos.org/" in (p.get("source_url") or "")
    ]
    return sorted(
        candidates, key=lambda p: (-(p.get("download_count") or 0), p["name"])
    )[:limit]


def run_batch(entries, cache, output):
    # Fresh directory prevents stale successful drafts surviving a failed retry.
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for entry in entries:
        row = {"name": entry.get("name"), "url": entry.get("url")}
        try:
            draft = generate(entry, cache)
            key = sha256(
                (
                    draft["subject"]["purl"]
                    + "\n"
                    + draft["subject"]["artifact"]["sha256"]
                ).encode()
            )
            filename = key + ".json"
            (output / filename).write_text(json.dumps(draft, indent=2) + "\n")
            row.update(
                status="candidate-needs-review",
                draft=filename,
                payload_entries=len(draft["evidence"]["transformation"]["payload"]),
            )
        except Deferred as exc:
            row.update(status="deferred", reason=exc.code, detail=str(exc))
        except Exception as exc:  # noqa: BLE001
            # Per-package isolation; unexpected parser/transport failures are
            # visibly errors, never approved candidates or policy deferrals.
            row.update(status="error", reason=type(exc).__name__, detail=str(exc))
        results.append(row)
    report = {
        "draft_schema_version": 1,
        "generator": GENERATOR,
        "counts": dict(sorted(Counter(r["status"] for r in results).items())),
        "results": results,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "mappings/auto.json")
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--only",
        help="Comma-separated package names; resolves current exact snapshot artifacts",
    )
    selection.add_argument(
        "--limit", type=int, help="Highest-download CDT hints, maximum 100"
    )
    parser.add_argument("--cache", type=Path, default=ROOT / ".tmp/cdt-cache")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New directory outside mappings/ and web/public/",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Require cached metadata and archives; no network",
    )
    args = parser.parse_args()
    try:
        import rpmfile  # noqa: F401
        import yaml  # noqa: F401

        for path in (args.output, args.cache):
            need(
                not any(
                    path.resolve().is_relative_to(root)
                    for root in (
                        (ROOT / "mappings").resolve(),
                        (ROOT / "web/public").resolve(),
                    )
                ),
                "unsafe-output",
                "Candidates/cache must remain outside active mapping/public directories",
            )
        entries = select_entries(
            load_json(args.input.read_bytes())["packages"], args.only, args.limit
        )
        report = run_batch(entries, Cache(args.cache, args.offline), args.output)
        print(json.dumps(report["counts"], sort_keys=True))
        print(
            f"Review drafts and explicit deferrals: {args.output / 'report.json'}; no active mappings changed."
        )
        if report["counts"].get("error"):
            parser.exit(
                1, "Some packages failed; inspect report.json before retrying.\n"
            )
    except (ImportError, ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(1, f"CDT automapper: {exc}\n")


if __name__ == "__main__":
    main()
