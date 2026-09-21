import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from scripts import cpe_candidate_contract as candidate_contract
from scripts import cpe_evidence as cpe_discover
from scripts import cpe_summary


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))


class EffectiveCpeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.auto = self.root / "auto.json"
        self.manual = self.root / "manual.json"
        self.contributions = self.root / "contributions"
        self.contributions.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_effective_cpes_follow_replacement_and_clear_semantics(self) -> None:
        write_json(
            self.manual,
            {
                "packages": {
                    "widget": {
                        "cpes": ["cpe:2.3:a:old:widget"],
                        "approved_by": "manual-reviewer",
                        "approved_at": "2026-01-01T00:00:00Z",
                    }
                }
            },
        )
        write_json(
            self.contributions / "later.json",
            {
                "timestamp": "2026-01-02T00:00:00Z",
                "author": "pipeline",
                "packages": {"widget": {"cpes": ["cpe:2.3:a:new:widget"]}},
            },
        )
        write_json(
            self.contributions / "latest.json",
            {
                "timestamp": "2026-01-03T00:00:00Z",
                "author": "curator",
                "packages": {"widget": {"cpes": []}},
            },
        )

        effective = cpe_discover._load_effective_cpes(self.manual, self.contributions)

        self.assertEqual(effective["widget"].cpes, ())
        self.assertEqual(effective["widget"].source, "latest.json")
        self.assertEqual(effective["widget"].reviewer, "curator")
        self.assertNotIn(
            "widget",
            cpe_discover._load_existing_cpes(self.manual, self.contributions),
        )

    def test_contribution_order_uses_utc_instant_then_filename(self) -> None:
        write_json(self.manual, {"packages": {}})
        write_json(
            self.contributions / "lexically-later.json",
            {
                "timestamp": "2026-01-01T01:00:00+01:00",
                "author": "first",
                "packages": {
                    "widget": {
                        "cpes": ["cpe:2.3:a:first:widget"],
                        "purl": "pkg:github/first/widget",
                    }
                },
            },
        )
        write_json(
            self.contributions / "lexically-earlier.json",
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "author": "second",
                "packages": {
                    "widget": {
                        "cpes": ["cpe:2.3:a:second:widget"],
                        "purl": "pkg:github/second/widget",
                    }
                },
            },
        )

        effective = cpe_discover._load_effective_cpes(self.manual, self.contributions)

        self.assertEqual(effective["widget"].cpes, ("cpe:2.3:a:first:widget",))
        self.assertEqual(effective["widget"].source, "lexically-later.json")
        write_json(self.auto, {"packages": {}})
        mapping = cpe_discover._load_effective_mappings(
            self.auto, self.manual, self.contributions
        )["widget"]
        self.assertEqual(mapping.purl, "pkg:github/first/widget")

    def test_primary_overlay_matches_reviewed_unmapped_semantics(self) -> None:
        base = cpe_discover.AutoEntry(
            purl="pkg:github/example/widget",
            purl_type="github",
            namespace="example",
            pkg_name="widget",
            summary="Widget",
            download_count=1,
            alternative_purl_types=("pypi",),
        )

        null_only = cpe_discover._overlay_purl(base, {"purl": None})
        cpe_only = cpe_discover._overlay_purl(base, {"cpes": ["cpe:widget"]})
        unmapped = cpe_discover._overlay_purl(base, {"unmapped": True})

        self.assertEqual(null_only, base)
        self.assertEqual(cpe_only, base)
        self.assertTrue(unmapped.unmapped)
        self.assertIsNone(unmapped.purl)
        self.assertIsNone(unmapped.purl_type)
        self.assertEqual(unmapped.alternative_purl_types, ())

    def test_effective_mapping_retains_source_version_and_unmapped_state(self) -> None:
        write_json(
            self.auto,
            {
                "packages": {
                    "widget": {
                        "purl": None,
                        "type": None,
                        "namespace": None,
                        "pkg_name": None,
                        "summary": "Widget runtime",
                        "download_count": 42,
                        "version": "1.2.3",
                        "source_url": "https://example.test/widget-1.2.3.tar.gz",
                    }
                }
            },
        )
        write_json(
            self.manual,
            {
                "packages": {
                    "widget": {
                        "unmapped": True,
                        "approved_by": "reviewer",
                        "approved_at": "2026-01-01T00:00:00Z",
                    }
                }
            },
        )

        effective = cpe_discover._load_effective_mappings(
            self.auto, self.manual, self.contributions
        )["widget"]

        self.assertEqual(effective.version, "1.2.3")
        self.assertEqual(
            effective.source_url, "https://example.test/widget-1.2.3.tar.gz"
        )
        self.assertTrue(effective.unmapped)


class SharedSourceEvidenceTests(unittest.TestCase):
    @staticmethod
    def entry(
        *,
        version: str | None = "1.0",
        source_url: str | None = "https://example.test/project-1.0.tar.gz",
        purl_type: str | None = None,
        unmapped: bool = False,
    ) -> cpe_discover.AutoEntry:
        return cpe_discover.AutoEntry(
            purl=None,
            purl_type=purl_type,
            namespace=None,
            pkg_name=None,
            summary="Project output",
            download_count=1,
            version=version,
            source_url=source_url,
            unmapped=unmapped,
        )

    @staticmethod
    def reviewed(
        *cpes: str, source: str = "review.json"
    ) -> cpe_discover.ReviewedCpeSet:
        return cpe_discover.ReviewedCpeSet(
            cpes=cpes,
            source=source,
            reviewer="reviewer",
            reviewed_at="2026-01-01T00:00:00Z",
        )

    def test_exact_source_and_version_emit_review_only_evidence(self) -> None:
        entries = {
            "project": self.entry(),
            "project-runtime": self.entry(),
        }
        reviewed = {"project": self.reviewed("cpe:2.3:a:vendor:project")}

        reviews, conflicts = cpe_discover._shared_source_evidence(entries, reviewed)
        evidence = reviews["project-runtime"][0]

        self.assertEqual(conflicts, {})
        self.assertEqual(evidence["cpes"], ["cpe:2.3:a:vendor:project"])
        self.assertTrue(evidence["requires_review"])

    def test_different_source_or_version_does_not_match(self) -> None:
        anchor = self.entry()
        reviewed = {"project": self.reviewed("cpe:2.3:a:vendor:project")}
        cases = {
            "version": self.entry(version="2.0"),
            "scheme": self.entry(source_url="http://example.test/project-1.0.tar.gz"),
            "mirror": self.entry(source_url="https://mirror.test/project-1.0.tar.gz"),
            "missing-source": self.entry(source_url=None),
            "missing-version": self.entry(version=None),
        }
        for label, target in cases.items():
            with self.subTest(label=label):
                reviews, conflicts = cpe_discover._shared_source_evidence(
                    {"project": anchor, "target": target}, reviewed
                )
                self.assertNotIn("target", reviews)
                self.assertNotIn("target", conflicts)

    def test_agreement_ignores_cpe_order(self) -> None:
        entries = {
            "anchor-a": self.entry(),
            "anchor-b": self.entry(),
            "target": self.entry(),
        }
        reviewed = {
            "anchor-a": self.reviewed("cpe:a", "cpe:b", source="a.json"),
            "anchor-b": self.reviewed("cpe:b", "cpe:a", source="b.json"),
        }

        reviews, conflicts = cpe_discover._shared_source_evidence(entries, reviewed)

        self.assertIn("target", reviews)
        self.assertNotIn("target", conflicts)
        self.assertEqual(
            [a["package"] for a in reviews["target"][0]["anchors"]],
            ["anchor-a", "anchor-b"],
        )

    def test_disagreeing_anchors_emit_conflict_without_proposal(self) -> None:
        entries = {
            "mysql": self.entry(),
            "mysql-server": self.entry(),
            "mysql-client": self.entry(),
        }
        reviewed = {
            "mysql": self.reviewed("cpe:2.3:a:oracle:mysql"),
            "mysql-server": self.reviewed("cpe:2.3:a:mysql:mysql_server"),
        }

        reviews, conflicts = cpe_discover._shared_source_evidence(entries, reviewed)

        self.assertNotIn("mysql-client", reviews)
        self.assertEqual(
            [a["package"] for a in conflicts["mysql-client"]["anchors"]],
            ["mysql", "mysql-server"],
        )

    def test_output_is_deterministic_across_input_order(self) -> None:
        entries_a = {
            "anchor-b": self.entry(),
            "target": self.entry(),
            "anchor-a": self.entry(),
        }
        entries_b = dict(reversed(list(entries_a.items())))
        reviewed_a = {
            "anchor-b": self.reviewed("cpe:b", "cpe:a", source="b.json"),
            "anchor-a": self.reviewed("cpe:a", "cpe:b", source="a.json"),
        }
        reviewed_b = dict(reversed(list(reviewed_a.items())))

        self.assertEqual(
            cpe_discover._shared_source_evidence(entries_a, reviewed_a),
            cpe_discover._shared_source_evidence(entries_b, reviewed_b),
        )

    def test_intentional_unmapped_and_osv_packages_remain_ineligible(self) -> None:
        self.assertFalse(
            cpe_discover._is_cpe_candidate("wrapper", self.entry(unmapped=True))
        )
        self.assertFalse(
            cpe_discover._is_cpe_candidate(
                "registry-package", self.entry(purl_type="pypi")
            )
        )

    def test_libglvnd_component_evidence_stays_review_only(self) -> None:
        entries = {
            "libglx": self.entry(
                source_url="https://gitlab.freedesktop.org/glvnd/libglvnd.tar.gz"
            ),
            "libegl": self.entry(
                source_url="https://gitlab.freedesktop.org/glvnd/libglvnd.tar.gz"
            ),
        }
        reviewed = {"libglx": self.reviewed("cpe:2.3:a:x:libglx")}
        reviews, _conflicts = cpe_discover._shared_source_evidence(entries, reviewed)

        self.assertEqual(
            reviews["libegl"][0]["cpes"],
            ["cpe:2.3:a:x:libglx"],
        )
        self.assertTrue(reviews["libegl"][0]["requires_review"])


class SummaryTests(unittest.TestCase):
    def test_summary_labels_shared_source_evidence_as_not_shipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            candidates = Path(tmp) / "candidates.json"
            write_json(
                candidates,
                {
                    "schema_version": 2,
                    "top_considered": 0,
                    "candidates_processed": 2,
                    "heuristics_summary": {
                        "shared_source_review_packages": 1,
                        "shared_source_review_cpes": 1,
                        "shared_source_conflict_packages": 1,
                    },
                    "packages": [
                        {
                            "conda_name": "libegl",
                            "accept": [],
                            "shared_source_review": [
                                {
                                    "cpes": ["cpe:2.3:a:x:libglx"],
                                    "shared_version": "1.7.0",
                                    "anchors": [{"package": "libglx"}],
                                }
                            ],
                        },
                        {
                            "conda_name": "mysql-client",
                            "accept": [],
                            "shared_source_conflict": {
                                "anchors": [
                                    {
                                        "package": "mysql",
                                        "cpes": ["cpe:2.3:a:oracle:mysql"],
                                    },
                                    {
                                        "package": "mysql-server",
                                        "cpes": ["cpe:2.3:a:mysql:mysql_server"],
                                    },
                                ]
                            },
                        },
                    ],
                },
            )
            stdout = io.StringIO()
            with (
                mock.patch(
                    "sys.argv",
                    ["cpe_summary", "--candidates", str(candidates)],
                ),
                redirect_stdout(stdout),
            ):
                cpe_summary.main()

        rendered = stdout.getvalue()
        self.assertIn("No new CPEs promoted", rendered)
        self.assertIn("shared-source review required | 1 package / 1 CPE", rendered)
        self.assertIn("human review required, not shipped", rendered)
        self.assertIn("**libegl**", rendered)
        self.assertIn("shared-source conflict", rendered)
        self.assertIn("**mysql-client**", rendered)


class AutomationIsolationTests(unittest.TestCase):
    def test_review_only_candidate_is_not_vetted_or_promoted(self) -> None:
        payload = {
            "schema_version": 2,
            "packages": [
                {
                    "conda_name": "libegl",
                    "shared_source_review": [
                        {
                            "cpes": ["cpe:2.3:a:x:libglx"],
                            "requires_review": True,
                        }
                    ],
                    "accept": [],
                    "ambiguous": [],
                }
            ],
        }

        self.assertEqual(
            candidate_contract.packages_in_bucket(payload, "ambiguous"), []
        )
        self.assertEqual(candidate_contract.collect_accepts(payload), {})

    def test_automation_reads_only_its_explicit_bucket(self) -> None:
        payload = {
            "schema_version": 2,
            "packages": [
                {
                    "conda_name": "project",
                    "shared_source_review": [{"cpes": ["cpe:2.3:a:review:project"]}],
                    "accept": [{"cpe": "cpe:2.3:a:auto:project"}],
                    "ambiguous": [{"cpe": "cpe:2.3:a:ambiguous:project"}],
                }
            ],
        }

        vetted = candidate_contract.packages_in_bucket(payload, "ambiguous")
        promoted = candidate_contract.collect_accepts(payload)

        self.assertEqual(
            [candidate["cpe"] for candidate in vetted[0][1]],
            ["cpe:2.3:a:ambiguous:project"],
        )
        self.assertEqual(promoted, {"project": ["cpe:2.3:a:auto:project"]})

    def test_consumers_accept_candidate_schema_one_and_two_only(self) -> None:
        for version in (1, 2):
            with self.subTest(version=version):
                candidate_contract.validate_candidates_schema(
                    {"schema_version": version}
                )
        with self.assertRaises(candidate_contract.UnsupportedCandidateSchema):
            candidate_contract.validate_candidates_schema({"schema_version": 3})


if __name__ == "__main__":
    unittest.main()
