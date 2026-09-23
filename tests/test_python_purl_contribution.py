import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTION = (
    ROOT
    / "mappings"
    / "contributions"
    / "2026-09-22T15-43-35Z--nichmor--pfx-1989.json"
)
EXPECTED_PURLS = {
    "dvc": "pkg:pypi/dvc",
    "kivy": "pkg:pypi/kivy",
}
REVIEWED_EVIDENCE = {
    "conda-forge/dvc-feedstock/blob/ed183d2387af67b67469f92327161627fd2348e9",
    "conda-forge/kivy-feedstock/blob/956edc27a389e998b4ec360071f433a4a42dc2e0",
    "pypi.org/project/dvc/3.67.1",
    "pypi.org/project/Kivy/2.3.1",
}


class PythonPurlContributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contribution = json.loads(CONTRIBUTION.read_text())
        cls.packages = cls.contribution["packages"]

    def test_scope_is_exact(self) -> None:
        self.assertEqual(set(self.packages), set(EXPECTED_PURLS))

    def test_reviewed_pypi_purls_are_primary(self) -> None:
        for name, purl in EXPECTED_PURLS.items():
            with self.subTest(name=name):
                self.assertEqual(
                    self.packages[name],
                    {
                        "purl": purl,
                        "type": "pypi",
                        "namespace": None,
                        "pkg_name": name,
                    },
                )

    def test_review_evidence_is_immutable_and_versioned(self) -> None:
        source = self.contribution["source"]
        for evidence in REVIEWED_EVIDENCE:
            with self.subTest(evidence=evidence):
                self.assertIn(evidence, source)


if __name__ == "__main__":
    unittest.main()
