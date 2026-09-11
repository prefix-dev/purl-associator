from __future__ import annotations

import copy
import unittest

from scripts.unmapped_classification import (
    classify_packages,
    contribution_from_candidates,
)


def package(**overrides: object) -> dict:
    return {
        "version": "1.0",
        "build": "build_0",
        "summary": "ordinary software",
        "source_url": None,
        "repo": None,
        "homepage": None,
        "status": "auto-unverified",
        "unmapped": False,
        "identities": [],
        **overrides,
    }


class UnmappedClassificationTest(unittest.TestCase):
    def test_classifies_strong_cdt_evidence_across_reviewed_hosts(self) -> None:
        packages = {
            f"cdt-{index}": package(
                summary="(CDT) System development package",
                source_url=f"https://{host}/path/system-1.0.arch.rpm",
            )
            for index, host in enumerate(
                (
                    "vault.centos.org",
                    "dl.rockylinux.org",
                    "repo.almalinux.org",
                    "download.sinenomine.net",
                    "mirror.centos.org",
                )
            )
        }
        result = classify_packages({"packages": packages})
        self.assertEqual(result["candidate_count"], 5)
        self.assertEqual(result["counts_by_reason"], {"conda_cdt_repackage": 5})
        for candidate in result["candidates"]:
            reason = candidate["unmapped_reason"]
            self.assertEqual(reason["rule_id"], "cdt-rpm-repackage-v1")
            self.assertIn("summary", reason["evidence"])
            self.assertIn("source_url", reason["evidence"])

    def test_classifies_only_reviewed_selector_names(self) -> None:
        payload = {
            "packages": {
                "_r-mutex": package(summary="A mutex package"),
                "c-compiler": package(summary="A metapackage to obtain a compiler"),
                "cuda-runtime": package(summary="Meta-package containing runtimes"),
                "conda-forge-pinning": package(summary="Baseline pinning metadata"),
                "git-bash": package(summary="Dummy compatibility package"),
            }
        }
        result = classify_packages(payload)
        self.assertEqual(
            result["counts_by_reason"],
            {
                "compatibility_shim": 1,
                "dependency_only_metapackage": 1,
                "environment_mutex": 1,
                "pinning_metadata": 1,
                "toolchain_selector": 1,
            },
        )
        self.assertEqual(
            [row["name"] for row in result["candidates"]], sorted(payload["packages"])
        )

    def test_rejects_broad_suffix_summary_and_host_shortcuts(self) -> None:
        negatives = {
            "gsoap_abi": package(
                summary="The gSOAP code generator",
                source_url="https://downloads.sourceforge.net/gsoap.zip",
            ),
            "clang_variant": package(
                summary="Development headers and libraries for Clang",
                source_url="http://root.cern.ch/git/clang.git",
            ),
            "real-devel": package(summary="A real development library"),
            "real-static": package(summary="A real static library"),
            "geomodel": package(
                summary="GeoModel metapackage",
                source_url="https://gitlab.cern.ch/GeoModel.tar.gz",
            ),
            "mysql": package(
                summary="Meta package for backwards compatibility",
                source_url="https://cdn.mysql.com/mysql.tar.gz",
            ),
            "host-only": package(
                summary="Ordinary package",
                source_url="https://vault.centos.org/path/package.rpm",
            ),
            "summary-only": package(summary="(CDT) Package", source_url=None),
            "not-rpm": package(
                summary="(CDT) Package",
                source_url="https://vault.centos.org/path/package.tar.gz",
            ),
        }
        self.assertEqual(classify_packages({"packages": negatives})["candidates"], [])

    def test_never_overwrites_any_existing_identity_or_decision(self) -> None:
        packages = {
            "primary": package(
                summary="(CDT) Package",
                source_url="https://vault.centos.org/path/package.rpm",
                identities=[{"kind": "purl", "role": "primary", "value": "pkg:rpm/x"}],
            ),
            "alternative": package(
                summary="(CDT) Package",
                source_url="https://vault.centos.org/path/package.rpm",
                identities=[
                    {"kind": "purl", "role": "alternative", "value": "pkg:rpm/x"}
                ],
            ),
            "reviewed-unmapped": package(
                summary="(CDT) Package",
                source_url="https://vault.centos.org/path/package.rpm",
                unmapped=True,
                status="unmapped",
            ),
        }
        self.assertEqual(classify_packages({"packages": packages})["candidates"], [])

    def test_output_is_deterministic_and_promoted_decisions_are_idempotent(
        self,
    ) -> None:
        payload = {
            "packages": {
                "z": package(summary="A mutex package"),
                "_r-mutex": package(summary="A mutex package"),
                "c-compiler": package(summary="Compiler metapackage"),
            }
        }
        first = classify_packages(payload)
        second = classify_packages(copy.deepcopy(payload))
        self.assertEqual(first, second)
        self.assertEqual(
            [row["name"] for row in first["candidates"]], ["_r-mutex", "c-compiler"]
        )

        contribution = contribution_from_candidates(
            first,
            {"_r-mutex"},
            author="reviewer",
            author_name="Package Reviewer",
            timestamp="2026-09-11T00:00:00Z",
        )
        self.assertEqual(list(contribution["packages"]), ["_r-mutex"])
        self.assertTrue(contribution["packages"]["_r-mutex"]["unmapped"])

        payload["packages"]["_r-mutex"].update(unmapped=True, status="unmapped")
        self.assertEqual(
            [row["name"] for row in classify_packages(payload)["candidates"]],
            ["c-compiler"],
        )
        with self.assertRaisesRegex(ValueError, "not candidates"):
            contribution_from_candidates(
                first,
                {"unknown"},
                author="reviewer",
                author_name="Package Reviewer",
                timestamp="2026-09-11T00:00:00Z",
            )

    def test_rejects_invalid_bundle_shape(self) -> None:
        with self.assertRaisesRegex(ValueError, "packages must be an object"):
            classify_packages({"packages": []})


if __name__ == "__main__":
    unittest.main()
