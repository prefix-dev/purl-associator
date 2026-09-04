from __future__ import annotations

import unittest

from scripts.parselmouth_identity import artifact_identity_pairs


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
