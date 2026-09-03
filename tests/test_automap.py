from __future__ import annotations

import unittest

from scripts.automap import _artifact_identity_pairs
from scripts.parselmouth_lookup import ParselmouthMapping


class ArtifactIdentityTest(unittest.TestCase):
    def test_vendored_dependencies_are_not_alternative_identities(self) -> None:
        mapping = ParselmouthMapping(
            pypi_normalized_names=[
                "flask-rest-orm",
                "flask-restful",
                "sqlalchemy",
            ],
            versions={
                "flask-rest-orm": "0.5.0",
                "flask-restful": "0.3.6",
                "sqlalchemy": "1.2.5",
            },
            conda_name="flask-rest-orm",
        )

        self.assertEqual(
            _artifact_identity_pairs(mapping, conda_name="flask-rest-orm"),
            [("pkg:pypi/flask-rest-orm", "flask-rest-orm")],
        )

    def test_same_version_does_not_make_a_contained_distribution_an_identity(
        self,
    ) -> None:
        mapping = ParselmouthMapping(
            pypi_normalized_names=["suite", "suite-cli", "dependency"],
            versions={"suite": "2.0", "suite-cli": "2.0", "dependency": "1.4"},
        )

        self.assertEqual(
            _artifact_identity_pairs(mapping, conda_name="suite"),
            [("pkg:pypi/suite", "suite")],
        )

    def test_single_distribution_can_differ_from_conda_name(self) -> None:
        mapping = ParselmouthMapping(
            pypi_normalized_names=["upstream-name"],
            versions={"upstream-name": "1.0"},
        )

        self.assertEqual(
            _artifact_identity_pairs(mapping, conda_name="conda-name"),
            [("pkg:pypi/upstream-name", "upstream-name")],
        )


if __name__ == "__main__":
    unittest.main()
