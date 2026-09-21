import json
import tempfile
import unittest
from pathlib import Path

from scripts import cpe_discover


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
                "packages": {"widget": {"cpes": ["cpe:2.3:a:first:widget"]}},
            },
        )
        write_json(
            self.contributions / "lexically-earlier.json",
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "author": "second",
                "packages": {"widget": {"cpes": ["cpe:2.3:a:second:widget"]}},
            },
        )

        effective = cpe_discover._load_effective_cpes(self.manual, self.contributions)

        self.assertEqual(effective["widget"].cpes, ("cpe:2.3:a:first:widget",))
        self.assertEqual(effective["widget"].source, "lexically-later.json")

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


if __name__ == "__main__":
    unittest.main()
