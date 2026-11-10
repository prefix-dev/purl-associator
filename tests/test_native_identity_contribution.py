import json
import unittest
from pathlib import Path

from scripts.merge_mappings import _build_published_packages, _load_contributions


ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = ROOT / "mappings"
CONTRIBUTION = "2026-11-10T17-10-00Z--wolfv--pfx-2246.json"
EXPECTED = {
    "poppler": (
        "pkg:git/gitlab.freedesktop.org/poppler/poppler",
        ["cpe:2.3:a:freedesktop:poppler"],
    ),
    "gstreamer": (
        "pkg:git/gitlab.freedesktop.org/gstreamer/gstreamer",
        ["cpe:2.3:a:gstreamer:gstreamer"],
    ),
    "r-base": (
        "pkg:generic/r",
        ["cpe:2.3:a:r_project:r", "cpe:2.3:a:r_foundation:r"],
    ),
}
REGISTRY_TYPES = {"bioconductor", "cargo", "cpan", "cran", "gem", "npm", "pypi"}


class NativeIdentityContributionTests(unittest.TestCase):
    """PFX-2246: poppler, gstreamer and r-base are not registry packages."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.contribution = json.loads(
            (MAPPINGS / "contributions" / CONTRIBUTION).read_text()
        )
        contributions = _load_contributions(MAPPINGS / "contributions")
        auto = json.loads((MAPPINGS / "auto.json").read_text())
        manual = json.loads((MAPPINGS / "manual.json").read_text())

        def publish(rows):
            return _build_published_packages(
                auto,
                manual,
                rows,
                {},
                auto_label="auto",
                manual_label="manual",
                contributions_label=MAPPINGS / "contributions",
            )

        cls.before = publish([row for row in contributions if row[1] != CONTRIBUTION])
        cls.after = publish(contributions)

    def test_scope_is_exact(self) -> None:
        self.assertEqual(set(self.contribution["packages"]), set(EXPECTED))

    def test_published_identities_are_reviewed_and_native(self) -> None:
        for name, (purl, cpes) in EXPECTED.items():
            with self.subTest(name=name):
                entry = self.after[name]
                self.assertEqual(entry["purl"], purl)
                self.assertNotIn(entry["type"], REGISTRY_TYPES)
                self.assertEqual(entry["cpes"], cpes)
                self.assertEqual(entry["status"], "verified")
                self.assertEqual(
                    [(i["kind"], i["role"], i["value"]) for i in entry["identities"]],
                    [("purl", "primary", purl)]
                    + [("cpe", "associated", cpe) for cpe in cpes],
                )
                for identity in entry["identities"]:
                    review = identity["provenance"]["review"]
                    self.assertEqual(review["status"], "verified")
                    self.assertEqual(review["reviewer"], "wolfv")

    def test_cpes_cite_their_evidence(self) -> None:
        source = self.contribution["source"]
        for _, cpes in EXPECTED.values():
            for cpe in cpes:
                with self.subTest(cpe=cpe):
                    self.assertIn(cpe, source)

    def test_other_packages_are_unchanged(self) -> None:
        self.assertEqual(self.before.keys(), self.after.keys())
        self.assertEqual(
            {n: e for n, e in self.before.items() if n not in EXPECTED},
            {n: e for n, e in self.after.items() if n not in EXPECTED},
        )


if __name__ == "__main__":
    unittest.main()
