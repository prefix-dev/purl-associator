from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import mappings_report, merge_mappings

ROOT = Path(__file__).resolve().parent.parent


class MappingsReportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.bundle = self.root / "out" / "mappings.json"
        auto_entry = {
            "purl": None,
            "confidence": 0.0,
            "sources": [],
            "note": "No automatic match — heuristics did not recognise any source URL.",
        }
        self._write(
            "auto.json",
            {
                "schema_version": 1,
                "channel": "conda-forge",
                "packages": {
                    "mapped": {**auto_entry, "purl": "pkg:pypi/mapped"},
                    "reviewed": auto_entry,
                    "rejected": {**auto_entry, "purl": "pkg:pypi/rejected"},
                    "alternative-only": {
                        **auto_entry,
                        "alternative_purls": ["pkg:pypi/alternative"],
                    },
                    "cpe-only": {**auto_entry, "cpes": ["cpe:2.3:a:vendor:product"]},
                    "no-evidence": auto_entry,
                    "error": {
                        **auto_entry,
                        "note": "fetch error: RecipeFacts missing summary",
                        "source_url": "https://example.org/archive.tar.gz",
                        "repo": "https://example.org/repo",
                        "homepage": "https://example.org",
                        "version": "1.0",
                        "download_count": 42,
                    },
                },
            },
        )
        self._write(
            "manual.json",
            {
                "schema_version": 1,
                "updated_by": "reviewer",
                "updated_at": "2026-01-01T00:00:00Z",
                "packages": {"reviewed": {"purl": "pkg:pypi/reviewed"}},
            },
        )
        self._write(
            "contributions/review.json",
            {
                "schema_version": 1,
                "author": "contributor",
                "timestamp": "2026-01-02T00:00:00Z",
                "packages": {
                    "rejected": {"unmapped": True},
                    "contributed": {"purl": "pkg:pypi/contributed"},
                },
            },
        )
        self._write("downloads.json", {"packages": []})
        with contextlib.redirect_stdout(io.StringIO()):
            merge_mappings.main(
                self.root / "auto.json",
                self.root / "manual.json",
                self.root / "contributions",
                self.root / "downloads.json",
                self.bundle,
                self.root / "out" / "mappings-index.json",
                self.root / "out" / "mapping_packages",
                generated_at="2026-01-03T00:00:00Z",
            )
        self.payload = json.loads(self.bundle.read_text())

    def _write(self, path: str, payload: object) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload))

    def _cli(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "scripts.mappings_report", "--input", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def test_counts_effective_merged_primary_identities(self) -> None:
        report = mappings_report.build_report(self.payload)
        self.assertEqual(
            report["counts"],
            {
                "total": 8,
                "primary_present": 3,
                "explicitly_unmapped": 1,
                "unresolved": 4,
                "primary_missing": 5,
            },
        )
        states = {row["name"]: row["state"] for row in report["missing_packages"]}
        self.assertEqual(
            states,
            {
                "alternative-only": "unresolved",
                "cpe-only": "unresolved",
                "error": "unresolved",
                "no-evidence": "unresolved",
                "rejected": "explicitly_unmapped",
            },
        )
        self.assertEqual(report["counts"]["primary_missing"], len(states))

    def test_assigns_exclusive_unresolved_diagnostics(self) -> None:
        report = mappings_report.build_report(self.payload)
        self.assertEqual(
            report["unresolved_by_diagnostic"],
            {
                "recorded_processing_error": 1,
                "alternative_only": 1,
                "no_parseable_source_host": 2,
                "no_primary_from_url_evidence": 0,
            },
        )
        rows = {row["name"]: row for row in report["missing_packages"]}
        self.assertEqual(
            rows["error"]["diagnostic_reason"], "recorded_processing_error"
        )
        self.assertEqual(
            rows["alternative-only"]["diagnostic_reason"], "alternative_only"
        )
        self.assertEqual(
            rows["cpe-only"]["diagnostic_reason"], "no_parseable_source_host"
        )
        self.assertEqual(
            rows["no-evidence"]["diagnostic_reason"], "no_parseable_source_host"
        )
        self.assertIsNone(rows["rejected"]["diagnostic_reason"])
        self.assertEqual(
            sum(report["unresolved_by_diagnostic"].values()),
            report["counts"]["unresolved"],
        )

    def test_diagnostic_precedence_is_conservative(self) -> None:
        payload = copy.deepcopy(self.payload)
        payload["packages"]["alternative-only"]["note"] = "  FETCH ERROR: stale"
        payload["packages"]["rejected"]["note"] = "fetch error: stale"
        report = mappings_report.build_report(payload)
        rows = {row["name"]: row for row in report["missing_packages"]}
        self.assertEqual(
            rows["alternative-only"]["diagnostic_reason"],
            "recorded_processing_error",
        )
        self.assertIsNone(rows["rejected"]["diagnostic_reason"])
        self.assertEqual(
            report["unresolved_by_diagnostic"],
            {
                "recorded_processing_error": 2,
                "alternative_only": 0,
                "no_parseable_source_host": 2,
                "no_primary_from_url_evidence": 0,
            },
        )

    def test_url_evidence_classification_normalizes_and_deduplicates_hosts(
        self,
    ) -> None:
        payload = copy.deepcopy(self.payload)
        entry = payload["packages"]["cpe-only"]
        entry.update(
            {
                "source_url": "https://GitLab.COM./group/project/archive.tar.gz",
                "repo": "HTTPS://gitlab.com/group/project",
                "homepage": "https://gitlab.com:443/group/project",
            }
        )
        report = mappings_report.build_report(payload)
        rows = {row["name"]: row for row in report["missing_packages"]}
        self.assertEqual(
            rows["cpe-only"]["diagnostic_reason"],
            "no_primary_from_url_evidence",
        )
        self.assertEqual(mappings_report._source_hosts(entry), ("gitlab.com",))
        self.assertEqual(
            report["unresolved_by_diagnostic"],
            {
                "recorded_processing_error": 1,
                "alternative_only": 1,
                "no_parseable_source_host": 1,
                "no_primary_from_url_evidence": 1,
            },
        )

    def test_relative_empty_and_malformed_urls_have_no_parseable_host(self) -> None:
        entry = {
            "source_url": "",
            "repo": "group/project",
            "homepage": "https://[invalid",
        }
        self.assertEqual(mappings_report._source_hosts(entry), ())

    def test_preserves_evidence_without_treating_notes_as_mapping_state(self) -> None:
        report = mappings_report.build_report(self.payload)
        rows = {row["name"]: row for row in report["missing_packages"]}
        for field in (*mappings_report.EVIDENCE_FIELDS, "download_count"):
            self.assertEqual(
                rows["error"][field], self.payload["packages"]["error"][field]
            )
        self.assertIsNone(rows["no-evidence"]["source_url"])
        # A stale auto failure note survives both positive and negative review.
        self.assertNotIn("reviewed", rows)
        self.assertEqual(rows["rejected"]["state"], "explicitly_unmapped")

    def test_deterministic_and_read_only(self) -> None:
        original = copy.deepcopy(self.payload)
        first = mappings_report.build_report(self.payload)
        self.assertEqual(self.payload, original)
        reordered = copy.deepcopy(self.payload)
        reordered["packages"] = dict(reversed(list(reordered["packages"].items())))
        reordered["generated_at"] = "2026-02-01T00:00:00Z"
        self.assertEqual(first, mappings_report.build_report(reordered))
        before_bytes = self.bundle.read_bytes()
        a, b = self._cli(self.bundle), self._cli(self.bundle)
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(json.loads(a.stdout), first)
        self.assertEqual(self.bundle.read_bytes(), before_bytes)

    def test_empty_bundle(self) -> None:
        self.payload.update(packages={}, package_count=0)
        report = mappings_report.build_report(self.payload)
        self.assertTrue(all(count == 0 for count in report["counts"].values()))
        self.assertTrue(
            all(count == 0 for count in report["unresolved_by_diagnostic"].values())
        )
        self.assertEqual(report["missing_packages"], [])

    def test_rejects_invalid_envelope(self) -> None:
        for patch in (
            {"schema_version": 1},
            {"schema_version": 4},  # Compact index is not a full bundle.
            {"schema_version": True},
            {"packages": []},
            {"package_count": 0},
            {"package_count": True},
            {"channel": None},
        ):
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                mappings_report.build_report({**self.payload, **patch})

    def test_rejects_invalid_package_contract(self) -> None:
        for patch in (
            {"identities": None},
            {"identities": []},  # Must not silently ignore a missing canonical primary.
            {"purl": 123},
            {"unmapped": "true"},
            {"unmapped": True},  # Contradicts the published primary.
            {"status": "unmapped"},
            {"source_url": []},
            {"download_count": True},
            {"download_count": -1},
        ):
            payload = copy.deepcopy(self.payload)
            payload["packages"]["mapped"].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                mappings_report.build_report(payload)

    def test_cli_rejects_missing_or_invalid_json_without_success_output(self) -> None:
        paths = [self.root / "missing.json"]
        for index, text in enumerate(
            ("{", '{"packages":{},"packages":{}}', '{"x":NaN}')
        ):
            path = self.root / f"invalid-{index}.json"
            path.write_text(text)
            paths.append(path)
        for path in paths:
            with self.subTest(path=path):
                result = self._cli(path)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("mappings report:", result.stderr)


if __name__ == "__main__":
    unittest.main()
