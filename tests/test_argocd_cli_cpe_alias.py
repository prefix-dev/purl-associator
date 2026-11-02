import json
import unittest
from pathlib import Path

from scripts.cpe_evidence import _load_effective_cpes
from scripts.merge_mappings import _build_published_packages, _load_contributions


ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = ROOT / "mappings"
CONTRIBUTION = "2026-11-02T14-18-23Z--nichmor--argocd-cli-argoproj-cpe.json"
LINUXFOUNDATION_CPE = "cpe:2.3:a:linuxfoundation:argo-cd"
ARGOPROJ_CPE = "cpe:2.3:a:argoproj:argo_cd"


class ArgocdCliCpeAliasTests(unittest.TestCase):
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

    def test_scope_is_only_the_argocd_cli_cpe_list(self):
        self.assertEqual(
            self.contribution["packages"],
            {"argocd-cli": {"cpes": [LINUXFOUNDATION_CPE, ARGOPROJ_CPE]}},
        )
        self.assertIn("issues/407", self.contribution["source"])

    def test_effective_published_identity_carries_both_vendors(self):
        self.assertEqual(self.before["argocd-cli"]["cpes"], [LINUXFOUNDATION_CPE])
        self.assertEqual(self.after["argocd-cli"]["cpes"], [LINUXFOUNDATION_CPE, ARGOPROJ_CPE])
        cpe_identities = [i for i in self.after["argocd-cli"]["identities"] if i["kind"] == "cpe"]
        self.assertEqual([i["value"] for i in cpe_identities], [LINUXFOUNDATION_CPE, ARGOPROJ_CPE])
        for identity in cpe_identities:
            self.assertEqual(identity["provenance"]["review"]["status"], "verified")
            self.assertEqual(identity["provenance"]["review"]["reviewer"], "nichmor")
        # The primary PURL disposition and any alternative identities stay intact.
        for key in ("purl", "unmapped", "unmapped_reason", "alternative_purls", "status"):
            self.assertEqual(self.before["argocd-cli"].get(key), self.after["argocd-cli"].get(key), key)

    def test_other_packages_are_unchanged(self):
        self.assertEqual(self.before.keys(), self.after.keys())
        self.assertEqual(
            {n: e for n, e in self.before.items() if n != "argocd-cli"},
            {n: e for n, e in self.after.items() if n != "argocd-cli"},
        )

    def test_discovery_treats_the_alias_list_as_the_reviewed_anchor(self):
        effective = _load_effective_cpes(MAPPINGS / "manual.json", MAPPINGS / "contributions")
        self.assertEqual(effective["argocd-cli"].cpes, (LINUXFOUNDATION_CPE, ARGOPROJ_CPE))
        self.assertEqual(effective["argocd-cli"].source, CONTRIBUTION)


if __name__ == "__main__":
    unittest.main()
