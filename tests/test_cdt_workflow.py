"""Exercise the actual workflow's embedded Python without GitHub/network access."""

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(importlib.util.find_spec("yaml"), "CDT environment required")
class CdtWorkflowTests(unittest.TestCase):
    def setUp(self):
        import yaml

        self.workflow = yaml.load(
            (ROOT / ".github/workflows/cdt_automap.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.steps = self.workflow["jobs"]["drafts"]["steps"]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "mappings").mkdir()
        (self.root / "mappings/auto.json").write_text(
            json.dumps(
                {
                    "packages": {
                        "example": {
                            "name": "example",
                            "summary": "(CDT)",
                            "download_count": 10,
                        }
                    }
                }
            )
        )
        self.bundle = self.root / "bundle"
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.env = {
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "BUNDLE": str(self.bundle),
            "CDT_CACHE": str(self.cache),
            "INPUT_ONLY": "",
            "INPUT_LIMIT": "10",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_STEP_SUMMARY": str(self.root / "summary.md"),
        }

    def step(self, prefix):
        return next(s for s in self.steps if s.get("name", "").startswith(prefix))

    def run_python(self, prefix):
        shell = self.step(prefix)["run"]
        code = shell.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        return subprocess.run(
            [sys.executable, "-c", code],
            env=self.env,
            cwd=self.root,
            check=False,
            text=True,
            capture_output=True,
        )

    def test_trigger_permissions_and_failure_preservation(self):
        self.assertIn("schedule", self.workflow["on"])
        self.assertIn("workflow_dispatch", self.workflow["on"])
        self.assertEqual(
            self.workflow["permissions"],
            {"contents": "write", "pull-requests": "write"},
        )
        for prefix in ("Stage validated", "Mint pipeline", "Open or update"):
            self.assertIn("github.ref == 'refs/heads/main'", self.step(prefix)["if"])
            self.assertNotIn("always()", self.step(prefix)["if"])
        pr = self.step("Open or update")
        self.assertEqual(pr["with"]["base"], "main")
        self.assertEqual(
            pr["with"]["add-paths"].split(),
            ["mappings/cdt_contributions/**", "mappings/cdt_evidence/**"],
        )
        self.assertNotIn("gh pr merge", str(self.steps))
        self.assertIn("PIPELINE_PAT", pr["with"]["token"])
        self.assertEqual(self.workflow["jobs"]["drafts"]["timeout-minutes"], "45")
        self.assertEqual(self.step("Summarize")["if"], "always()")
        self.assertEqual(self.step("Upload")["if"], "always()")
        self.assertNotIn("continue-on-error", self.step("Generate bounded"))
        self.assertEqual(self.step("Upload")["with"]["retention-days"], "30")
        for step in self.steps:
            if "run" in step:
                self.assertNotIn("${{", step["run"])
                syntax = subprocess.run(
                    ["bash", "-n"],
                    input=step["run"],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_snapshot_records_exact_selection_and_revision(self):
        result = self.run_python("Capture")
        self.assertEqual(result.returncode, 0, result.stderr)
        snapshot = json.loads((self.bundle / "input-snapshot.json").read_text())
        provenance = json.loads((self.bundle / "run.json").read_text())
        self.assertEqual(list(snapshot["packages"]), ["example"])
        self.assertEqual(provenance["source_revision"], self.env["GITHUB_SHA"])
        self.assertEqual(
            provenance["source_sha256"],
            hashlib.sha256((self.root / "mappings/auto.json").read_bytes()).hexdigest(),
        )

    def test_dispatch_values_are_data_and_selection_is_bounded(self):
        for only, limit in (
            ("", "101"),
            ("", "0"),
            ("example; touch INJECTED", "10"),
            ("", "$(touch INJECTED)"),
        ):
            with self.subTest(only=only, limit=limit):
                self.env.update(INPUT_ONLY=only, INPUT_LIMIT=limit)
                self.assertNotEqual(self.run_python("Capture").returncode, 0)
                self.assertFalse(self.bundle.exists())
                self.assertFalse((self.root / "INJECTED").exists())
        self.env.update(INPUT_ONLY="example", INPUT_LIMIT="ignored")
        result = self.run_python("Capture")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_summary_retains_evidence_and_package_errors(self):
        self.bundle.mkdir()
        drafts = self.bundle / "drafts"
        drafts.mkdir()
        url = "https://api.anaconda.org/release/conda-forge/example/1"
        raw = b'{"distributions": []}'
        key = hashlib.sha256(url.encode()).hexdigest()
        (self.cache / key).write_bytes(raw)
        (drafts / "candidate.json").write_text(
            json.dumps(
                {
                    "evidence": {
                        "conda_release_metadata": {
                            "url": url,
                            "sha256": hashlib.sha256(raw).hexdigest(),
                        }
                    }
                }
            )
        )
        (drafts / "report.json").write_text(
            json.dumps(
                {
                    "counts": {"candidate-needs-review": 1, "error": 1},
                    "results": [
                        {
                            "name": "example",
                            "status": "candidate-needs-review",
                            "draft": "candidate.json",
                        },
                        {"name": "failed", "status": "error", "reason": "OSError"},
                    ],
                }
            )
        )
        result = self.run_python("Summarize")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.bundle / "metadata" / (key + ".json")).read_bytes(), raw)
        self.assertIn('"error": 1', (self.bundle / "SUMMARY.md").read_text())
        (self.cache / key).write_bytes(b"tampered")
        self.assertNotEqual(self.run_python("Summarize").returncode, 0)

    def test_missing_report_is_explicitly_incomplete(self):
        self.bundle.mkdir()
        result = self.run_python("Summarize")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "No complete batch report", (self.bundle / "SUMMARY.md").read_text()
        )
        self.assertIn("incomplete", (self.root / "summary.md").read_text())


if __name__ == "__main__":
    unittest.main()
