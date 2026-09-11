from __future__ import annotations

import unittest
from types import SimpleNamespace

from scripts.automap_cache import (
    can_reuse_cached_entry,
    has_recorded_fetch_error,
    preserved_download_count,
)
from scripts.parselmouth_identity import artifact_identity_pairs


class AutomapCacheTest(unittest.TestCase):
    @staticmethod
    def entry(
        *,
        version: str = "1.0",
        build: str = "build_0",
        note: str | None = None,
        download_count: int | None = 42,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            version=version,
            build=build,
            note=note,
            download_count=download_count,
        )

    def test_reuses_only_unchanged_successful_entries(self) -> None:
        entry = self.entry(note="Informational mapping hint")
        self.assertTrue(
            can_reuse_cached_entry(entry, version="1.0", build="build_0", force=False)
        )
        self.assertFalse(
            can_reuse_cached_entry(entry, version="2.0", build="build_0", force=False)
        )
        self.assertFalse(
            can_reuse_cached_entry(entry, version="1.0", build="build_1", force=False)
        )
        self.assertFalse(
            can_reuse_cached_entry(entry, version="1.0", build="build_0", force=True)
        )
        self.assertFalse(
            can_reuse_cached_entry(None, version="1.0", build="build_0", force=False)
        )

    def test_retries_recorded_fetch_errors_despite_unchanged_build(self) -> None:
        for note in (
            "fetch error: timeout",
            "  FETCH ERROR: RecipeFacts missing summary",
        ):
            with self.subTest(note=note):
                entry = self.entry(note=note)
                self.assertTrue(has_recorded_fetch_error(entry))
                self.assertFalse(
                    can_reuse_cached_entry(
                        entry, version="1.0", build="build_0", force=False
                    )
                )
        self.assertFalse(has_recorded_fetch_error(self.entry(note=None)))
        self.assertFalse(
            has_recorded_fetch_error(self.entry(note="No automatic match found"))
        )

    def test_retry_preserves_hydrated_download_count(self) -> None:
        failed = self.entry(note="fetch error: timeout", download_count=123)
        self.assertEqual(
            preserved_download_count(failed, name="demo", fallback={"demo": 456}),
            123,
        )
        self.assertEqual(
            preserved_download_count(None, name="demo", fallback={"demo": 456}),
            456,
        )
        self.assertIsNone(
            preserved_download_count(None, name="unknown", fallback={"demo": 456})
        )


class ArtifactIdentityTest(unittest.TestCase):
    def test_vendored_dependencies_are_not_alternative_identities(self) -> None:
        pairs = [
            ("pkg:pypi/flask-rest-orm", "flask-rest-orm"),
            ("pkg:pypi/flask-restful", "flask-restful"),
            ("pkg:pypi/sqlalchemy", "sqlalchemy"),
        ]

        self.assertEqual(
            artifact_identity_pairs(pairs, normalized_conda_name="flask-rest-orm"),
            [("pkg:pypi/flask-rest-orm", "flask-rest-orm")],
        )

    def test_multi_distribution_artifact_without_name_match_has_no_identity(
        self,
    ) -> None:
        pairs = [
            ("pkg:pypi/suite-core", "suite-core"),
            ("pkg:pypi/suite-cli", "suite-cli"),
        ]

        self.assertEqual(
            artifact_identity_pairs(pairs, normalized_conda_name="suite"),
            [],
        )

    def test_single_distribution_can_differ_from_conda_name(self) -> None:
        pairs = [("pkg:pypi/upstream-name", "upstream-name")]

        self.assertEqual(
            artifact_identity_pairs(pairs, normalized_conda_name="conda-name"),
            pairs,
        )


if __name__ == "__main__":
    unittest.main()
