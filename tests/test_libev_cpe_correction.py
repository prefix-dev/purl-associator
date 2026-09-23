import json
import unittest
from pathlib import Path

from scripts.cpe_evidence import _load_effective_cpes, _load_existing_cpes
from scripts.merge_mappings import _build_published_packages, _load_contributions


ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = ROOT / "mappings"
CONTRIBUTION = "2026-09-23T06-00-00Z--nichmor--libev-cpe-correction.json"
WRONG_CPE = "cpe:2.3:a:shadowsocks:shadowsocks-libev"


class LibevCpeCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contribution = json.loads((MAPPINGS / "contributions" / CONTRIBUTION).read_text())
        contributions = _load_contributions(MAPPINGS / "contributions")
        auto = json.loads((MAPPINGS / "auto.json").read_text())
        manual = json.loads((MAPPINGS / "manual.json").read_text())

        def publish(rows):
            return _build_published_packages(
                auto, manual, rows, {}, auto_label="auto", manual_label="manual",
                contributions_label=MAPPINGS / "contributions",
            )

        cls.before = publish([row for row in contributions if row[1] != CONTRIBUTION])
        cls.after = publish(contributions)

    def test_scope_is_only_an_explicit_cpe_clear(self):
        self.assertEqual(self.contribution["packages"], {"libev": {"cpes": []}})
        self.assertIn("865d6e94ceab52b90efb1658293f4d63f3cc6e69", self.contribution["source"])
        self.assertIn("223314a7476bdeb00f698937b6960fc51cb98627af2ac5a629e5150bcddb8abf", self.contribution["source"])

    def test_effective_published_identity_does_not_identify_shadowsocks(self):
        self.assertIn(WRONG_CPE, self.before["libev"]["cpes"])
        self.assertEqual(self.after["libev"]["cpes"], [])
        self.assertFalse(any(i["kind"] == "cpe" for i in self.after["libev"]["identities"]))
        # Legacy attribution follows the latest review, but the primary
        # disposition/status and any alternative identities stay intact.
        for key in ("purl", "unmapped", "unmapped_reason", "alternative_purls", "status"):
            self.assertEqual(self.before["libev"].get(key), self.after["libev"].get(key), key)

    def test_other_packages_are_unchanged(self):
        self.assertEqual(self.before.keys(), self.after.keys())
        self.assertEqual(
            {n: e for n, e in self.before.items() if n != "libev"},
            {n: e for n, e in self.after.items() if n != "libev"},
        )

    def test_discovery_no_longer_uses_libev_as_a_reviewed_cpe_anchor(self):
        effective = _load_effective_cpes(MAPPINGS / "manual.json", MAPPINGS / "contributions")
        self.assertFalse(effective["libev"].cpes)
        self.assertEqual(effective["libev"].source, CONTRIBUTION)
        self.assertNotIn("libev", _load_existing_cpes(MAPPINGS / "manual.json", MAPPINGS / "contributions"))


if __name__ == "__main__":
    unittest.main()
