import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRIBUTION = (
    ROOT / "mappings" / "contributions" / "2026-09-17T08-10-22Z--nichmor--pfx-1985.json"
)
CPE = "cpe:2.3:a:gnu:binutils"

CPE_PACKAGES = {
    "binutils_impl_linux-64",
    "binutils_impl_linux-aarch64",
    "binutils_impl_linux-ppc64le",
    "binutils_impl_linux-riscv64",
    "binutils_impl_linux-s390x",
    "binutils_impl_osx-64",
    "binutils_impl_osx-arm64",
    "binutils_impl_win-64",
    "ld_impl_linux-64",
    "ld_impl_linux-aarch64",
    "ld_impl_linux-ppc64le",
    "ld_impl_linux-riscv64",
    "ld_impl_linux-s390x",
    "ld_impl_win-64",
}
WRAPPER_PACKAGES = {
    "binutils_linux-64",
    "binutils_linux-aarch64",
    "binutils_linux-ppc64le",
    "binutils_linux-riscv64",
    "binutils_linux-s390x",
    "binutils_osx-64",
    "binutils_osx-arm64",
    "binutils_win-64",
}


class BinutilsContributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contribution = json.loads(CONTRIBUTION.read_text())
        cls.packages = cls.contribution["packages"]

    def test_scope_is_exact(self) -> None:
        self.assertEqual(set(self.packages), CPE_PACKAGES | WRAPPER_PACKAGES)
        self.assertNotIn("binutils", self.packages)
        self.assertNotIn("binutils-meta", self.packages)
        self.assertNotIn("cargo-binutils", self.packages)
        self.assertNotIn("m2w64-binutils", self.packages)

    def test_code_bearing_outputs_receive_only_reviewed_cpe(self) -> None:
        self.assertIn(
            "conda-forge/binutils-feedstock/blob/63b8c1c78a0d5a3df123116c458ef2ecbddf2274",
            self.contribution["source"],
        )
        for name in CPE_PACKAGES:
            with self.subTest(name=name):
                self.assertEqual(self.packages[name], {"cpes": [CPE]})

    def test_activation_outputs_are_classified_with_snapshot_evidence(self) -> None:
        for name in WRAPPER_PACKAGES:
            with self.subTest(name=name):
                entry = self.packages[name]
                self.assertTrue(entry["unmapped"])
                reason = entry["unmapped_reason"]
                self.assertEqual(reason["code"], "dependency_only_metapackage")
                self.assertEqual(reason["rule_id"], "binutils-activation-wrapper-v1")
                evidence = reason["evidence"]
                self.assertTrue(evidence["version"])
                self.assertTrue(evidence["build"])
                self.assertTrue(evidence["summary"])
                self.assertRegex(
                    evidence["source_url"],
                    r"^https://ftp\.gnu\.org/gnu/binutils/binutils-[^/]+\.tar\.bz2$",
                )
                self.assertEqual(
                    evidence["homepage"], "https://www.gnu.org/software/binutils/"
                )


if __name__ == "__main__":
    unittest.main()
