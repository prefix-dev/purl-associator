"""Offline guards for the individually reviewed PFX-1990 product identities.

Evidence is in the contribution, not inferred from suffixes or shared sources.
These tests lock identity scope/provenance, not affected-version conclusions.
"""
import json
import unittest
from pathlib import Path

from scripts.cpe_evidence import _load_effective_cpes
from scripts.merge_mappings import _build_published_packages, _load_contributions

ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = ROOT / "mappings"
FILENAME = "2026-09-23T07-29-36Z--nichmor--pfx-1990.json"
EXPECTED = {
    "mpfr": ["cpe:2.3:a:mpfr:gnu_mpfr"],
    "lzo": ["cpe:2.3:a:oberhumer:liblzo2", "cpe:2.3:a:oberhumer:lzo2"],
    "nspr": ["cpe:2.3:a:mozilla:netscape_portable_runtime"],
    "xerces-c": [r"cpe:2.3:a:apache:xerces-c\+\+"],
    "jbig": ["cpe:2.3:a:cambridge_enterprise:jbig-kit"],
}
# Feedstock revision, artifact digest, and actual code-bearing output inspected.
EVIDENCE = {
    "mpfr": ("f0626e5b9fa91958eaf73226921b704b2160452b", "8d2a8450dc7a45f712ae49e9ea4e97c8870314b22cda65a421c3553941148518", "Library/bin/libmpfr-6.dll"),
    "lzo": ("d8595a3cb3261df0c3e777fd44b63ae9f9107e2d", "95d5f16bfa62ff50980a5e0329920bb2b5ec66d0e0d6c87954603713c3519ece", "lib/liblzo2.2.0.0.dylib"),
    "nspr": ("cd185077f21ae9792918fa955fcb048b89bb3e70", "ffe667fdca4d74442b5b8871cd74cc74d94f57fa229137311e5400ee5e40a1c6", "lib/libnspr4.so"),
    "xerces-c": ("dd55be470b125a4c787f5ad1a1df3807730a4abb", "4a55a2a141f830715c08592e6343de552c0e71450a4d40bef306d9cdffe599a5", "lib/libxerces-c-3.3.dylib"),
    "jbig": ("87d416d4a75919495c23a6b532dfac2072b21967", "4c813113a533045c4904f772505bb3d984fd37f60b88c71d6e972afca6d0a634", "Library/bin/jbig.dll"),
}


class UpstreamAliasContributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contribution = json.loads((MAPPINGS / "contributions" / FILENAME).read_text())
        contributions = _load_contributions(MAPPINGS / "contributions")
        auto = json.loads((MAPPINGS / "auto.json").read_text())
        manual = json.loads((MAPPINGS / "manual.json").read_text())

        def publish(rows):
            return _build_published_packages(
                auto, manual, rows, {}, auto_label="auto", manual_label="manual",
                contributions_label=MAPPINGS / "contributions",
            )

        cls.before = publish([row for row in contributions if row[1] != FILENAME])
        cls.after = publish(contributions)

    def test_exact_five_package_six_cpe_scope(self):
        self.assertEqual(self.contribution["packages"], {
            name: {"cpes": cpes} for name, cpes in EXPECTED.items()
        })
        self.assertEqual(sum(map(len, EXPECTED.values())), 6)
        # Do not add deprecated Xerces-C, Java parsers, Firefox/NSS or JBIG2,
        # nor propagate these identities to RPM repackages or sibling outputs.
        for name in ("xerces-j", "xerces2", "firefox", "nss", "jbig2dec", "lzo-cos7-x86_64"):
            self.assertNotIn(name, self.contribution["packages"])

    def test_immutable_recipe_and_artifact_payload_evidence(self):
        source = self.contribution["source"]
        for name, (revision, digest, binary) in EVIDENCE.items():
            with self.subTest(package=name):
                self.assertIn(f"{name}-feedstock/blob/{revision}/recipe/", source)
                self.assertIn(digest, source)
                self.assertIn(binary, source)
        for cve in ("CVE-2014-9474", "CVE-2014-4607", "CVE-2016-1951", "CVE-2024-23807", "CVE-2013-6369"):
            self.assertIn(f"https://nvd.nist.gov/vuln/detail/{cve}", source)
        self.assertIn("32-bit platforms", source)
        self.assertIn("do not assert a current affected version", source)

    def test_effective_identities_have_reviewed_provenance(self):
        effective = _load_effective_cpes(MAPPINGS / "manual.json", MAPPINGS / "contributions")
        for name, cpes in EXPECTED.items():
            with self.subTest(package=name):
                entry = self.after[name]
                self.assertEqual(entry["cpes"], cpes)
                identities = [i for i in entry["identities"] if i["kind"] == "cpe"]
                self.assertEqual([i["value"] for i in identities], cpes)
                for identity in identities:
                    self.assertEqual(identity["role"], "associated")
                    self.assertEqual(identity["provenance"], {
                        "availability": "available", "source": "manual",
                        "review": {"status": "verified", "reviewer": "nichmor",
                                   "reviewed_at": self.contribution["timestamp"]},
                    })
                self.assertEqual(set(effective[name].cpes), set(cpes))
                self.assertEqual(effective[name].source, FILENAME)

    def test_no_primary_changes_or_unreviewed_sibling_propagation(self):
        self.assertEqual(self.before.keys(), self.after.keys())
        for name in EXPECTED:
            for key in ("purl", "type", "namespace", "pkg_name", "alternative_purls", "unmapped", "unmapped_reason"):
                self.assertEqual(self.before[name].get(key), self.after[name].get(key), (name, key))
            self.assertEqual(
                [i for i in self.before[name]["identities"] if i["kind"] == "purl"],
                [i for i in self.after[name]["identities"] if i["kind"] == "purl"],
            )
        self.assertEqual(
            {n: e for n, e in self.before.items() if n not in EXPECTED},
            {n: e for n, e in self.after.items() if n not in EXPECTED},
        )


if __name__ == "__main__":
    unittest.main()
