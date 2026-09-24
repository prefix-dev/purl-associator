import copy
import hashlib
import io
import json
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import component_reviews as reviews
from scripts.merge_mappings import _build_published_packages, _load_contributions

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "mappings/component_reviews/libxml2-cos7-x86_64-2.9.1-ha675448_1106.json"


class ComponentReviewTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(PILOT.read_text())

    def test_all_committed_reviews_validate(self):
        self.assertGreaterEqual(reviews.validate_directory(), 1)
        self.assertEqual(
            self.data["subject"]["purl"],
            "pkg:conda/conda-forge/libxml2-cos7-x86_64@2.9.1?build=ha675448_1106&subdir=noarch",
        )
        self.assertEqual(
            self.data["derived_from"]["purl"],
            "pkg:rpm/centos/libxml2@2.9.1-6.el7.5?arch=x86_64&distro=centos-7.9.2009",
        )
        self.assertIsNone(self.data["derived_from"]["rpm_header"]["epoch"])
        self.assertEqual(
            self.data["contains"]["upstream_purl"],
            "pkg:git/gitlab.gnome.org/GNOME/libxml2",
        )
        payload = self.data["transformation"]["payload"]
        self.assertEqual(len(payload), 12)
        self.assertEqual(sum(p["kind"] == "file" for p in payload), 11)
        self.assertEqual(
            self.data["derived_from"]["artifact"]["sha256"],
            "c06a84f18b2fd44867a1d729dd1021d2ee8047419bc540875995a06626472f36",
        )

    def test_rejects_unsafe_or_ambiguous_relationships(self):
        mutations = [
            lambda d: d.update(schema_version=2),
            lambda d: d.update(status="active"),
            lambda d: d.update(evaluation_policy="match-upstream-version"),
            lambda d: d.update(purl=d["derived_from"]["purl"]),
            lambda d: d["subject"].update(
                purl="pkg:conda/conda-forge/libxml2-cos7-x86_64"
            ),
            lambda d: d["derived_from"]["rpm_header"].update(release="6.el7.6"),
            lambda d: d["derived_from"]["rpm_header"].update(arch="aarch64"),
            lambda d: d["derived_from"]["rpm_header"].update(epoch=0),
            lambda d: d["contains"].update(reported_upstream_version="2.9.1-6.el7.5"),
            lambda d: d["contains"].update(
                upstream_purl="pkg:git/gitlab.gnome.org/GNOME/libxml2@2.9.1"
            ),
            lambda d: d["contains"].update(evidence_paths=["not-in-payload"]),
            lambda d: d["transformation"]["payload"][0].update(rpm_path="../outside"),
            lambda d: d["transformation"]["payload"].append(
                d["transformation"]["payload"][0]
            ),
            lambda d: d["subject"]["artifact"].update(sha256="bad"),
            lambda d: d["evidence"].update(
                matching_recipe_url="https://github.com/conda-forge/cdt-builds/blob/main/recipe/meta.yaml"
            ),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                data = copy.deepcopy(self.data)
                mutate(data)
                with self.assertRaises(ValueError):
                    reviews.validate_review(data)

    def test_duplicate_subjects_and_missing_directory_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a", "b"):
                (root / f"{name}.json").write_text(json.dumps(self.data))
            with self.assertRaisesRegex(ValueError, "duplicate exact-artifact"):
                reviews.validate_directory(root)
            with self.assertRaisesRegex(ValueError, "missing component"):
                reviews.validate_directory(root / "missing")

    def test_pilot_does_not_enter_active_identity_payload(self):
        mappings = ROOT / "mappings"
        auto = json.loads((mappings / "auto.json").read_text())
        manual = json.loads((mappings / "manual.json").read_text())
        contributions = _load_contributions(mappings / "contributions")
        published = _build_published_packages(
            auto,
            manual,
            contributions,
            {},
            auto_label="auto",
            manual_label="manual",
            contributions_label=mappings / "contributions",
        )
        subject = published["libxml2-cos7-x86_64"]
        self.assertTrue(subject["unmapped"])
        self.assertEqual(subject["unmapped_reason"]["code"], "conda_cdt_repackage")
        self.assertEqual(subject["identities"], [])
        self.assertIsNone(subject["purl"])

    def artifact_fixture(self, directory):
        """Synthetic archive for verifier negative controls, not review evidence."""
        data = copy.deepcopy(self.data)
        conda_path = directory / "conda.tar.bz2"
        rpm_path = directory / "rpm"
        rpm_path.write_bytes(b"synthetic RPM input; parser mocked")
        original = {}
        members = []
        with tarfile.open(conda_path, "w:bz2") as archive:

            def add(name, raw):
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))

            index = {
                "name": "libxml2-cos7-x86_64",
                "version": "2.9.1",
                "build": "ha675448_1106",
                "subdir": "noarch",
            }
            add("info/index.json", json.dumps(index).encode())
            for item in data["evidence"]["embedded_recipe_files"]:
                raw = item["path"].encode()
                item["sha256"] = hashlib.sha256(raw).hexdigest()
                add(item["path"], raw)
            for item in data["transformation"]["payload"]:
                islink = item["kind"] == "symlink"
                raw = item["target"].encode() if islink else item["rpm_path"].encode()
                item["sha256"] = hashlib.sha256(raw).hexdigest()
                original[item["rpm_path"]] = raw
                members.append(
                    types.SimpleNamespace(
                        name="./" + item["rpm_path"], isdir=False, issymlink=islink
                    )
                )
                if islink:
                    member = tarfile.TarInfo(item["conda_path"])
                    member.type = tarfile.SYMTYPE
                    member.linkname = item["target"]
                    archive.addfile(member)
                else:
                    add(item["conda_path"], raw)
        for key, path in (("subject", conda_path), ("derived_from", rpm_path)):
            data[key]["artifact"]["sha256"] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
        headers = {
            ("serial" if k == "epoch" else k): v.encode() if isinstance(v, str) else v
            for k, v in data["derived_from"]["rpm_header"].items()
        }

        class FakeRpm:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def getmembers(self):
                return members

            def extractfile(self, member):
                return io.BytesIO(original[member.name.removeprefix("./")])

        rpm = FakeRpm()
        rpm.headers = headers
        return data, conda_path, rpm_path, rpm, original

    def test_artifact_verification_and_negative_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            data, conda, rpm_path, rpm, original = self.artifact_fixture(
                Path(directory)
            )
            with patch.dict(
                "sys.modules", {"rpmfile": types.SimpleNamespace(open=lambda _: rpm)}
            ):
                reviews.verify_artifacts(data, conda, rpm_path)
                rpm.headers["arch"] = b"aarch64"
                with self.assertRaisesRegex(ValueError, "RPM header mismatch"):
                    reviews.verify_artifacts(data, conda, rpm_path)
                rpm.headers["arch"] = b"x86_64"
                path = next(iter(original))
                saved = original[path]
                original[path] = b"changed"
                with self.assertRaisesRegex(ValueError, "payload mismatch"):
                    reviews.verify_artifacts(data, conda, rpm_path)
                original[path] = saved
                incomplete = copy.deepcopy(data)
                # Remove an otherwise irrelevant doc to prove full accounting.
                incomplete["transformation"]["payload"] = [
                    r
                    for r in incomplete["transformation"]["payload"]
                    if not r["rpm_path"].endswith("/NEWS")
                ]
                with self.assertRaisesRegex(
                    ValueError, "payload is not fully accounted"
                ):
                    reviews.verify_artifacts(incomplete, conda, rpm_path)
                conda.write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "artifact checksum mismatch"):
                    reviews.verify_artifacts(data, conda, rpm_path)


if __name__ == "__main__":
    unittest.main()
