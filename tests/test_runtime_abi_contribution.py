import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTION = (
    ROOT / "mappings" / "contributions" / "2026-09-17T13-48-17Z--nichmor--pfx-1986.json"
)
EXPECTED_CPES = {
    "libfreetype6": "cpe:2.3:a:freetype:freetype",
    "libwebp-base": "cpe:2.3:a:webmproject:libwebp",
    "libxml2-16": "cpe:2.3:a:xmlsoft:libxml2",
}
REVIEWED_FEEDSTOCKS = {
    "conda-forge/freetype-feedstock/blob/3520c4122afde3a5c30609f035de7cc4f501c069",
    "conda-forge/libwebp-feedstock/blob/65c3ff7f9acf969383c0b621a40640c5a310c6ae",
    "conda-forge/libxml2-feedstock/blob/1a38dbff8f5c32a9332c5568055dfbbfe8eb6a99",
}


class RuntimeAbiContributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contribution = json.loads(CONTRIBUTION.read_text())
        cls.packages = cls.contribution["packages"]

    def test_scope_is_exact(self) -> None:
        self.assertEqual(set(self.packages), set(EXPECTED_CPES))
        self.assertNotIn("libxml2-devel", self.packages)
        self.assertNotIn("libglx", self.packages)
        self.assertNotIn("libegl", self.packages)

    def test_runtime_outputs_receive_only_the_reviewed_cpe(self) -> None:
        for name, cpe in EXPECTED_CPES.items():
            with self.subTest(name=name):
                self.assertEqual(self.packages[name], {"cpes": [cpe]})

    def test_review_evidence_uses_immutable_feedstock_commits(self) -> None:
        source = self.contribution["source"]
        for feedstock in REVIEWED_FEEDSTOCKS:
            with self.subTest(feedstock=feedstock):
                self.assertIn(feedstock, source)


if __name__ == "__main__":
    unittest.main()
