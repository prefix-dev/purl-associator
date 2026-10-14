import copy
import importlib.util
import json
import shutil
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from scripts import cdt_automap as cdt
from scripts import cdt_submit as submit
from tests import test_cdt_automap as fixtures


@unittest.skipUnless(importlib.util.find_spec("yaml"), "CDT environment required")
class CdtSubmitTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CdtAutomapTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f = self.fixture
        archive = f.archive()
        meta_cache = f.metadata_cache(cdt.sha256(archive.read_bytes()))
        payload, _ = cdt.read_conda(archive, f.entry)
        rpm = {k[len(f.prefix) :]: v for k, v in payload.items()}
        header = {
            "name": "example",
            "version": "1.0",
            "release": "1.el7",
            "epoch": None,
            "arch": "x86_64",
            "vendor": "CentOS",
            "sourcerpm": "example-1.0-1.el7.src.rpm",
        }
        cache = SimpleNamespace(
            get=lambda url, *a, **kw: (
                meta_cache.get(url) if "api.anaconda.org" in url else archive
            )
        )
        with patch.object(cdt, "read_rpm", return_value=(header, rpm)):
            self.draft = cdt.generate(f.entry, cache)
        self.root = f.root / "repository"
        self.root.mkdir()
        self.bundle = f.root / "bundle"
        (self.bundle / "drafts").mkdir(parents=True)
        (self.bundle / "metadata").mkdir()
        self.filename = submit.key_for(self.draft) + ".json"
        ref = self.draft["evidence"]["conda_release_metadata"]
        self.metadata = (
            self.bundle / "metadata" / (cdt.sha256(ref["url"].encode()) + ".json")
        )
        shutil.copyfile(meta_cache.get(None), self.metadata)
        self.report = {
            "draft_schema_version": 1,
            "generator": cdt.GENERATOR,
            "counts": {"candidate-needs-review": 1},
            "results": [
                {
                    "name": f.entry["name"],
                    "url": f.entry["url"],
                    "status": "candidate-needs-review",
                    "draft": self.filename,
                    "payload_entries": 2,
                }
            ],
        }
        self.save_draft()
        self.save_report()
        (self.bundle / "input-snapshot.json").write_text(
            json.dumps({"packages": {f.entry["name"]: f.entry}})
        )
        (self.bundle / "run.json").write_text(
            json.dumps(
                {
                    "source_revision": "a" * 40,
                    "source_sha256": "b" * 64,
                    "selected_packages": [f.entry["name"]],
                    "only": f.entry["name"],
                    "limit": None,
                }
            )
        )
        self.body = f.root / "PR.md"

    def save_draft(self):
        (self.bundle / "drafts" / self.filename).write_text(json.dumps(self.draft))

    def save_report(self):
        (self.bundle / "drafts/report.json").write_text(json.dumps(self.report))

    def stage(self):
        return submit.prepare(self.bundle, self.root, self.body)

    def test_generates_validated_review_contribution_not_active_mapping(self):
        result = self.stage()
        self.assertEqual(result["added"], 1)
        self.assertTrue(result["branch"].startswith("cdt/review-"))
        self.assertEqual(submit.validate_directory(self.root), 1)
        saved = json.loads(
            (self.root / submit.CONTRIBUTIONS / self.filename).read_text()
        )
        self.assertEqual(saved, self.draft)
        self.assertNotIn("reviewer", saved)
        self.assertFalse((self.root / "mappings/contributions").exists())
        self.assertFalse((self.root / "web/public").exists())
        self.assertIn("Human review and merge required", self.body.read_text())

    def test_unchanged_and_api_counter_only_reruns_do_not_create_changes(self):
        first = self.stage()
        before = {str(p): p.read_bytes() for p in self.root.rglob("*.json")}
        self.assertEqual(self.stage()["unchanged"], 1)
        meta = json.loads(self.metadata.read_text())
        meta["download_count"] = 123
        self.metadata.write_text(json.dumps(meta))
        self.draft["evidence"]["conda_release_metadata"]["sha256"] = cdt.sha256(
            self.metadata.read_bytes()
        )
        self.save_draft()
        result = self.stage()
        self.assertEqual(
            result, {"branch": first["branch"], "added": 0, "unchanged": 1}
        )
        self.assertEqual(
            before, {str(p): p.read_bytes() for p in self.root.rglob("*.json")}
        )

    def test_existing_artifact_cannot_be_overwritten_with_different_claims(self):
        self.stage()
        self.draft["limitations"].append(
            "Changed claim requiring explicit review correction."
        )
        self.save_draft()
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.stage()

    def test_failed_incomplete_or_misbound_report_writes_nothing(self):
        original = copy.deepcopy(self.report)
        for mutation in (
            lambda r: r.update(counts={"error": 1}),
            lambda r: r.update(results=[]),
            lambda r: r["results"][0].update(name="different"),
            lambda r: r["results"][0].update(draft="../escape.json"),
            lambda r: r["results"][0].update(payload_entries=99),
            lambda r: r.update(generator="unknown"),
        ):
            self.report = copy.deepcopy(original)
            mutation(self.report)
            self.save_report()
            with self.assertRaises(ValueError):
                self.stage()
            self.assertFalse((self.root / submit.CONTRIBUTIONS).exists())

    def test_approval_forgery_and_evidence_tampering_fail(self):
        original = copy.deepcopy(self.draft)
        for mutation in (
            lambda d: d.update(status="approved"),
            lambda d: d.update(reviewer="human"),
            lambda d: d["evidence"]["embedded_files"][0].update(text="changed"),
            lambda d: d["relationships"][0]["upstream"].update(
                purl="pkg:rpm/centos/other@1"
            ),
            lambda d: d["evidence"]["transformation"]["payload"].append(
                d["evidence"]["transformation"]["payload"][0]
            ),
        ):
            self.draft = copy.deepcopy(original)
            mutation(self.draft)
            self.save_draft()
            with self.assertRaises(ValueError):
                self.stage()
        self.draft = original
        self.save_draft()
        self.metadata.write_text("{}")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.stage()

    def test_deferred_run_can_close_stale_proposal_without_deleting_accepted_records(
        self,
    ):
        branch = self.stage()["branch"]
        self.report["counts"] = {"deferred": 1}
        self.report["results"] = [
            {
                "name": self.fixture.entry["name"],
                "url": self.fixture.entry["url"],
                "status": "deferred",
                "reason": "unsupported-transformation",
            }
        ]
        self.save_report()
        result = self.stage()
        self.assertEqual(result, {"branch": branch, "added": 0, "unchanged": 0})
        self.assertEqual(submit.validate_directory(self.root), 1)

    def test_pr_body_cannot_overwrite_active_mapping_data(self):
        for body in (
            self.root / "mappings/auto.json",
            self.root / "web/public/mappings.json",
        ):
            with self.assertRaisesRegex(ValueError, "outside mapping/public"):
                submit.prepare(self.bundle, self.root, body)
            self.assertFalse((self.root / submit.CONTRIBUTIONS).exists())

    def test_directory_rejects_wrong_filenames_and_symlink_evidence(self):
        self.stage()
        path = self.root / submit.CONTRIBUTIONS / self.filename
        path.rename(path.with_name("wrong.json"))
        with self.assertRaisesRegex(ValueError, "filename"):
            submit.validate_directory(self.root)
        path.with_name("wrong.json").rename(path)
        evidence = next((self.root / submit.EVIDENCE).glob("*.json"))
        evidence.unlink()
        evidence.symlink_to(self.metadata)
        with self.assertRaises(ValueError):
            submit.validate_directory(self.root)


if __name__ == "__main__":
    unittest.main()
