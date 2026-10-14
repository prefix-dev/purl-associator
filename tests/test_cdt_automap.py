import contextlib
import copy
import importlib.util
import io
import json
import stat
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts import cdt_automap as cdt

YAML = importlib.util.find_spec("yaml") is not None


def cpio(entries):
    result = bytearray()
    for name, raw, mode, links in [*entries, ("TRAILER!!!", b"", 0, 1)]:
        name = name.encode() + b"\0"
        fields = [0, mode, 0, 0, links, 0, len(raw), 0, 0, 0, 0, len(name), 0]
        result.extend(b"070701" + b"".join(f"{n:08x}".encode() for n in fields))
        result.extend(name)
        result.extend(b"\0" * (-len(result) % 4))
        result.extend(raw)
        result.extend(b"\0" * (-len(result) % 4))
    return bytes(result)


class CdtAutomapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = {
            "name": "example-cos7-x86_64",
            "version": "1.0",
            "build": "abc_0",
            "subdir": "noarch",
            "url": "https://conda.anaconda.org/conda-forge/noarch/example-cos7-x86_64-1.0-abc_0.tar.bz2",
        }
        self.source_url = "https://vault.centos.org/7.9.2009/os/x86_64/Packages/example-1.0-1.el7.x86_64.rpm"
        self.recipe = f"package:\n  name: {self.entry['name']}\n  version: '1.0'\nsource:\n  url: {self.source_url}\n  sha256: {'b' * 64}\n"
        self.prefix = "x86_64-conda-linux-gnu/sysroot/"

    def archive(self, extra=(), index=None, recipe=None, missing=()):
        path = self.root / "package.tar.bz2"
        entries = [
            (
                "info/index.json",
                json.dumps(index or self.entry).encode(),
                tarfile.REGTYPE,
            ),
            (
                "info/recipe/meta.yaml",
                (recipe or self.recipe).encode(),
                tarfile.REGTYPE,
            ),
            (self.prefix + "usr/lib/a", b"library bytes", tarfile.REGTYPE),
            (self.prefix + "usr/lib/b", b"a", tarfile.SYMTYPE),
            *extra,
        ]
        with tarfile.open(path, "w:bz2") as archive:
            for name, raw, kind in entries:
                if name in missing:
                    continue
                member = tarfile.TarInfo(name)
                member.type = kind
                if kind == tarfile.SYMTYPE:
                    member.linkname = raw.decode()
                    archive.addfile(member)
                else:
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
        return path

    def test_conda_walk_counts_real_payload_without_info_files(self):
        payload, recipes = cdt.read_conda(self.archive(), self.entry)
        self.assertEqual(len(payload), 2)
        self.assertEqual(payload[self.prefix + "usr/lib/b"]["target"], "a")
        self.assertIn("info/recipe/meta.yaml", recipes)

    def test_conda_rejects_unsafe_duplicate_hardlink_and_missing_recipe(self):
        for extra in (
            [("../escape", b"x", tarfile.REGTYPE)],
            [(self.prefix + "usr/lib/a", b"x", tarfile.REGTYPE)],
            [("hardlink", b"", tarfile.LNKTYPE)],
            [("info/recipe/build.sh", b"target", tarfile.SYMTYPE)],
        ):
            with self.subTest(extra=extra), self.assertRaises(cdt.Deferred):
                cdt.read_conda(self.archive(extra), self.entry)
        with self.assertRaisesRegex(cdt.Deferred, "rendered embedded recipe"):
            cdt.read_conda(self.archive(missing=["info/recipe/meta.yaml"]), self.entry)
        with self.assertRaisesRegex(cdt.Deferred, "coordinates differ"):
            cdt.read_conda(
                self.archive(index={**self.entry, "build": "other"}), self.entry
            )

    def test_empty_payload_is_not_a_mapping(self):
        with self.assertRaises(cdt.Deferred) as exc:
            cdt.read_conda(
                self.archive(
                    missing=[self.prefix + "usr/lib/a", self.prefix + "usr/lib/b"]
                ),
                self.entry,
            )
        self.assertEqual(exc.exception.code, "empty-payload")

    def test_cpio_reads_files_and_links_without_extracting(self):
        raw = cpio(
            [
                ("./usr/lib/a", b"library bytes", stat.S_IFREG | 0o644, 1),
                ("./usr/lib/b", b"a", stat.S_IFLNK | 0o777, 1),
            ]
        )
        rpm = cdt.read_cpio(io.BytesIO(raw))
        conda, _ = cdt.read_conda(self.archive(), self.entry)
        result = cdt.compare_payloads(conda, rpm)
        self.assertEqual(result["prefix"], self.prefix)
        self.assertEqual(len(result["payload"]), 2)

    def test_cpio_rejects_devices_hardlinks_duplicates_traversal_and_truncation(self):
        for entries in (
            [("usr/device", b"", stat.S_IFCHR, 1)],
            [("usr/a", b"", stat.S_IFREG, 2)],
            [("../escape", b"", stat.S_IFREG, 1)],
            [("usr/a", b"", stat.S_IFREG, 1)] * 2,
        ):
            with self.subTest(entries=entries), self.assertRaises(cdt.Deferred):
                cdt.read_cpio(io.BytesIO(cpio(entries)))
        for raw in (b"", cpio([])[:-2], cpio([]) + b"hidden"):
            with self.subTest(raw=raw), self.assertRaises(cdt.Deferred):
                cdt.read_cpio(io.BytesIO(raw))

    def test_payload_mismatch_and_partial_copy_are_deferred(self):
        conda, _ = cdt.read_conda(self.archive(), self.entry)
        rpm = {k[len(self.prefix) :]: copy.deepcopy(v) for k, v in conda.items()}
        cdt.compare_payloads(conda, rpm)
        for mutate in (
            lambda r: r.pop("usr/lib/b"),
            lambda r: r["usr/lib/a"].update(sha256="c" * 64),
            lambda r: r["usr/lib/b"].update(target="changed"),
            lambda r: r.update({"extra": r["usr/lib/a"]}),
        ):
            bad = copy.deepcopy(rpm)
            mutate(bad)
            with self.assertRaises(cdt.Deferred):
                cdt.compare_payloads(conda, bad)
        with self.assertRaises(cdt.Deferred):
            cdt.compare_payloads({"usr/a": rpm["usr/lib/a"]}, rpm)

    @unittest.skipUnless(YAML, "optional CDT environment required")
    def test_recipe_is_single_source_and_http_upgrade_is_specific(self):
        _, source = cdt.parse_recipe(
            self.recipe.replace("https://vault", "http://vault").encode()
        )
        self.assertEqual(source["url"], self.source_url)
        self.assertEqual(source["distro"], "centos-7.9.2009")
        for bad in (
            self.recipe + "outputs: []\n",
            "source:\n  - url: https://example.com/a\n  - url: https://example.com/b\n",
            self.recipe.replace("source:", "source: &anchor"),
            self.recipe + "build:\n  number: '{{ number }}'\n",
            self.recipe + "build: {} # [linux]\n",
            self.recipe + "package: {}\n",
            self.recipe.replace("vault.centos.org", "example.com"),
            self.recipe.replace("7.9.2009", "7"),
            self.recipe.replace("b" * 64, "missing"),
        ):
            with (
                self.subTest(recipe=bad),
                self.assertRaises((cdt.Deferred, ValueError)),
            ):
                cdt.parse_recipe(bad.encode())

    def metadata_cache(self, digest):
        raw = json.dumps(
            {
                "distributions": [
                    {
                        "basename": "noarch/example-cos7-x86_64-1.0-abc_0.tar.bz2",
                        "attrs": {"build": "abc_0", "subdir": "noarch"},
                        "version": "1.0",
                        "sha256": digest,
                    }
                ]
            }
        ).encode()
        path = self.root / "metadata.json"
        path.write_bytes(raw)
        return SimpleNamespace(get=lambda *a, **kw: path)

    def test_conda_metadata_requires_exact_sha256_and_coordinates(self):
        digest, _ = cdt.conda_descriptor(self.entry, self.metadata_cache("a" * 64))
        self.assertEqual(digest, "a" * 64)
        for digest in (None, "", "a" * 32):
            with self.assertRaises(cdt.Deferred):
                cdt.conda_descriptor(self.entry, self.metadata_cache(digest))
        with self.assertRaises(cdt.Deferred):
            cdt.conda_descriptor(
                {**self.entry, "sha256": "b" * 64}, self.metadata_cache("a" * 64)
            )
        with self.assertRaises(cdt.Deferred):
            cdt.conda_descriptor(
                {**self.entry, "url": self.entry["url"].replace(".tar.bz2", ".conda")},
                self.metadata_cache("a" * 64),
            )

    def test_cache_checks_checksums_offline_and_disallows_other_origins(self):
        cache = cdt.Cache(self.root / "cache", offline=True)
        path = cache.directory / cdt.sha256(self.source_url.encode())
        path.write_bytes(b"pinned")
        self.assertEqual(cache.get(self.source_url, cdt.sha256(b"pinned")), path)
        with self.assertRaises(cdt.Deferred):
            cache.get(self.source_url, "b" * 64)
        with self.assertRaises(cdt.Deferred):
            cache.get(self.source_url + "?token=secret")
        with self.assertRaises(cdt.Deferred):
            cache.get("https://127.0.0.1/private")
        with self.assertRaises(cdt.Deferred):
            cache.get("https://vault.centos.org/missing")
        with self.assertRaises(cdt.Deferred):
            cdt.allowed_url("https://user:secret@vault.centos.org/file")

    def test_native_rpm_headers_must_match_recipe_origin(self):
        header = {
            "name": b"example",
            "version": b"1.0",
            "release": b"1.el7",
            "arch": b"x86_64",
            "vendor": b"CentOS",
            "sourcerpm": b"example-1.0-1.el7.src.rpm",
        }
        source = {
            "repository_arch": "x86_64",
            "filename": "example-1.0-1.el7.x86_64.rpm",
            "distro": "centos-7.9.2009",
        }
        raw = cpio([("usr/a", b"bytes", stat.S_IFREG | 0o644, 1)])

        def fake_open(path):
            return contextlib.nullcontext(
                SimpleNamespace(headers=header, data_file=io.BytesIO(raw))
            )

        with patch.dict(sys.modules, {"rpmfile": SimpleNamespace(open=fake_open)}):
            native, payload = cdt.read_rpm(Path("unused"), source)
            self.assertIsNone(native["epoch"])
            self.assertEqual(len(payload), 1)
            for key, value in (
                ("vendor", b"Red Hat"),
                ("arch", b"aarch64"),
                ("serial", True),
                ("release", b"1.el8"),
                ("archive_compression", b"zstd"),
            ):
                with (
                    self.subTest(key=key),
                    patch.dict(header, {key: value}),
                    self.assertRaises(cdt.Deferred),
                ):
                    cdt.read_rpm(Path("unused"), source)

    def test_bad_download_is_never_committed_to_cache(self):
        cache = cdt.Cache(self.root / "cache")
        response = SimpleNamespace(url=self.source_url, read=lambda limit: b"bad bytes")
        cache.opener = SimpleNamespace(
            open=lambda *a, **kw: contextlib.nullcontext(response)
        )
        with self.assertRaises(cdt.Deferred):
            cache.get(self.source_url, "b" * 64)
        self.assertEqual(list(cache.directory.iterdir()), [])
        with self.assertRaises(cdt.Deferred):
            cache.get(self.source_url, limit=2)
        self.assertEqual(list(cache.directory.iterdir()), [])

    def test_cross_origin_redirect_is_refused(self):
        request = SimpleNamespace(full_url=self.source_url)
        with self.assertRaises(cdt.Deferred):
            cdt.SameOriginRedirect().redirect_request(
                request, None, 302, "redirect", {}, "https://conda.anaconda.org/private"
            )
        with self.assertRaises(cdt.Deferred):
            cdt.SameOriginRedirect().redirect_request(
                request, None, 302, "redirect", {}, "http://vault.centos.org/file"
            )

    def test_cli_cannot_write_candidates_or_cache_into_active_directories(self):
        for output, cache in (
            (cdt.ROOT / "mappings/leak", self.root / "cache"),
            (self.root / "output", cdt.ROOT / "web/public/leak"),
        ):
            argv = [
                "cdt_automap",
                "--only",
                "example",
                "--output",
                str(output),
                "--cache",
                str(cache),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.dict(
                    sys.modules,
                    {"rpmfile": SimpleNamespace(), "yaml": SimpleNamespace()},
                ),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as exc,
            ):
                cdt.main()
            self.assertEqual(exc.exception.code, 1)
            self.assertFalse(output.exists())
            self.assertFalse(cache.exists())

    def test_resource_limits_are_enforced(self):
        with patch.object(cdt, "MAX_EXPANDED", 10), self.assertRaises(cdt.Deferred):
            cdt.read_cpio(io.BytesIO(cpio([])))
        with patch.object(cdt, "MAX_MEMBERS", 1), self.assertRaises(cdt.Deferred):
            cdt.read_conda(self.archive(), self.entry)
        cache = cdt.Cache(self.root / "cache", offline=True)
        (cache.directory / cdt.sha256(self.source_url.encode())).write_bytes(b"large")
        with self.assertRaises(cdt.Deferred):
            cache.get(self.source_url, limit=1)

    def test_batch_isolates_deferrals_errors_and_refuses_stale_output(self):
        drafts = {
            "subject": {
                "purl": "pkg:conda/conda-forge/a@1?build=x&subdir=noarch",
                "artifact": {"sha256": "a" * 64},
            },
            "evidence": {"transformation": {"payload": [1]}},
        }
        entries = [{"name": name, "url": "test"} for name in ("a", "b", "c")]
        with patch.object(
            cdt,
            "generate",
            side_effect=[
                drafts,
                cdt.Deferred("ambiguous", "multiple sources"),
                RuntimeError("parser failure"),
            ],
        ):
            report = cdt.run_batch(entries, None, self.root / "output")
        self.assertEqual(
            report["counts"], {"candidate-needs-review": 1, "deferred": 1, "error": 1}
        )
        self.assertEqual(len(list((self.root / "output").glob("*.json"))), 2)
        with self.assertRaises(FileExistsError):
            cdt.run_batch([], None, self.root / "output")

    def test_selection_is_bounded_and_deterministic(self):
        packages = {
            name: {"name": name, "summary": "(CDT)", "download_count": count}
            for name, count in (("b", 10), ("a", 10), ("c", 1))
        }
        self.assertEqual(
            [p["name"] for p in cdt.select_entries(packages, limit=2)], ["a", "b"]
        )
        self.assertEqual(
            [p["name"] for p in cdt.select_entries(packages, only="b,a")], ["a", "b"]
        )
        for only, limit in (("a,a", None), ("unknown", None), (None, 101), (None, 0)):
            with self.assertRaises(cdt.Deferred):
                cdt.select_entries(packages, only, limit)

    @unittest.skipUnless(YAML, "optional CDT environment required")
    def test_generate_is_deterministic_and_never_invents_approval_or_project(self):
        archive = self.archive()
        digest = cdt.sha256(archive.read_bytes())
        metadata_cache = self.metadata_cache(digest)
        header = {
            "name": "example",
            "version": "1.0",
            "release": "1.el7",
            "epoch": None,
            "arch": "x86_64",
            "vendor": "CentOS",
            "sourcerpm": "example-1.0-1.el7.src.rpm",
        }
        conda, _ = cdt.read_conda(archive, self.entry)
        rpm = {k[len(self.prefix) :]: v for k, v in conda.items()}
        cache = SimpleNamespace(
            get=lambda url, *a, **kw: (
                metadata_cache.get(url) if "api.anaconda.org" in url else archive
            )
        )
        with patch.object(cdt, "read_rpm", return_value=(header, rpm)):
            draft = cdt.generate(self.entry, cache)
            self.assertEqual(draft, cdt.generate(self.entry, cache))
            header["epoch"] = 0
            with_epoch = cdt.generate(self.entry, cache)
        self.assertEqual(draft["status"], "candidate-needs-review")
        self.assertNotIn("review", draft)
        self.assertNotIn("cpes", draft)
        self.assertEqual(len(draft["relationships"]), 1)
        self.assertNotIn("epoch=", draft["relationships"][0]["upstream"]["purl"])
        self.assertIn("epoch=0", with_epoch["relationships"][0]["upstream"]["purl"])
        self.assertNotIn("purl", draft)


if __name__ == "__main__":
    unittest.main()
