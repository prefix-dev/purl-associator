from __future__ import annotations

import unittest

from scripts.purl_inference import (
    RecipeContext,
    guess_bitbucket,
    guess_cpan,
    guess_gitlab,
    infer_all,
)


class GitLabInferenceTest(unittest.TestCase):
    def test_repository_and_archive_routes(self) -> None:
        cases = {
            "https://gitlab.com/saalen/ansifilter": "pkg:git/gitlab.com/saalen/ansifilter",
            "https://gitlab.com/atomicrex/atomicrex/-/archive/v1.0.4/atomicrex-v1.0.4.tar.gz": "pkg:git/gitlab.com/atomicrex/atomicrex",
            "https://gitlab.com/charliecloud/charliecloud/-/releases/v0.45/downloads/charliecloud.tar.gz": "pkg:git/gitlab.com/charliecloud/charliecloud",
            "https://gitlab.com/gnutls/gnutls/tree/master": "pkg:git/gitlab.com/gnutls/gnutls",
            "https://gitlab.com/group/project.git?download=1#readme": "pkg:git/gitlab.com/group/project",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                guess = guess_gitlab(url)
                self.assertIsNotNone(guess)
                assert guess is not None
                self.assertEqual(guess.purl, expected)
                self.assertEqual(guess.type, "git")
                self.assertEqual(guess.confidence, 0.85)
                self.assertEqual(guess.source, "recipe-source")

    def test_preserves_nested_namespace_and_path_case(self) -> None:
        guess = guess_gitlab(
            "https://gitlab.com/tango-controls/device-servers/DeviceClasses/"
            "simulation/UniversalTest"
        )
        self.assertIsNotNone(guess)
        assert guess is not None
        self.assertEqual(
            guess.purl,
            "pkg:git/gitlab.com/tango-controls/device-servers/DeviceClasses/"
            "simulation/UniversalTest",
        )
        self.assertEqual(
            guess.namespace,
            "gitlab.com/tango-controls/device-servers/DeviceClasses/simulation",
        )
        self.assertEqual(guess.pkg_name, "UniversalTest")

    def test_route_word_can_still_be_a_repository_name(self) -> None:
        guess = guess_gitlab("https://gitlab.com/example/tree")
        self.assertIsNotNone(guess)
        assert guess is not None
        self.assertEqual(guess.purl, "pkg:git/gitlab.com/example/tree")

    def test_rejects_ambiguous_or_non_gitlab_urls(self) -> None:
        urls = (
            "https://git.example.org/group/project",
            "https://gitlab.com.evil.example/group/project",
            "https://gitlab.com/group",
            "https://gitlab.com/group/-/issues",
            "https://gitlab.com/group%2Fsub/project",
            "https://gitlab.com/group/../project",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIsNone(guess_gitlab(url))


class BitbucketInferenceTest(unittest.TestCase):
    def test_normalizes_repository_and_download_routes(self) -> None:
        cases = {
            "https://bitbucket.org/ICL/LAPACKPP": "pkg:bitbucket/icl/lapackpp",
            "https://bitbucket.org/gahuber95/browndye2/get/29-Dec-2023.tar.gz": "pkg:bitbucket/gahuber95/browndye2",
            "https://bitbucket.org/fenics-project/dolfin/downloads/dolfin-2019.1.0.tar.gz": "pkg:bitbucket/fenics-project/dolfin",
            "https://bitbucket.org/icl/magma/src/master/": "pkg:bitbucket/icl/magma",
            "https://bitbucket.org/haypo/hachoir/wiki/hachoir-urwid": "pkg:bitbucket/haypo/hachoir",
            "https://bitbucket.org/Owner/Repo.git?raw=1#source": "pkg:bitbucket/owner/repo",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                guess = guess_bitbucket(url)
                self.assertIsNotNone(guess)
                assert guess is not None
                self.assertEqual(guess.purl, expected)
                self.assertEqual(guess.type, "bitbucket")
                self.assertEqual(guess.namespace, expected.split("/")[-2])
                self.assertEqual(guess.pkg_name, expected.split("/")[-1])

    def test_rejects_ambiguous_or_non_bitbucket_urls(self) -> None:
        urls = (
            "https://bitbucket.example.org/owner/repo",
            "https://bitbucket.org.evil.example/owner/repo",
            "https://bitbucket.org/owner/",
            "https://bitbucket.org/owner%2Fteam/repo",
            "https://bitbucket.org/owner/../repo",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIsNone(guess_bitbucket(url))


class CpanInferenceTest(unittest.TestCase):
    def test_release_and_distribution_pages_preserve_case(self) -> None:
        cases = {
            "https://metacpan.org/release/Algorithm-Diff": "pkg:cpan/Algorithm-Diff",
            "https://metacpan.org/dist/PerlIO-gzip": "pkg:cpan/PerlIO-gzip",
            "http://www.cpan.org/release/DB_File?source=conda": "pkg:cpan/DB_File",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                guess = guess_cpan(url)
                self.assertIsNotNone(guess)
                assert guess is not None
                self.assertEqual(guess.purl, expected)
                self.assertEqual(guess.type, "cpan")
                self.assertIsNone(guess.namespace)
                self.assertEqual(guess.confidence, 0.97)

    def test_author_archives_extract_distribution_not_module(self) -> None:
        cases = {
            "https://cpan.metacpan.org/authors/id/R/RJ/RJBS/Algorithm-Diff-1.201.tar.gz": "pkg:cpan/Algorithm-Diff",
            "https://cpan.metacpan.org/authors/id/D/DB/DBOOK/Text-Tabs+Wrap-2021.0814.tar.gz": "pkg:cpan/Text-Tabs%2BWrap",
            "https://cpan.metacpan.org/authors/id/R/RU/RURBAN/DB_File-1.858.tgz": "pkg:cpan/DB_File",
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                guess = guess_cpan(url)
                self.assertIsNotNone(guess)
                assert guess is not None
                self.assertEqual(guess.purl, expected)
                self.assertEqual(guess.confidence, 0.95)

    def test_rejects_module_pages_and_unstructured_downloads(self) -> None:
        urls = (
            "https://metacpan.org/pod/Algorithm::Diff",
            "https://metacpan.org/release/Algorithm::Diff",
            "https://cpan.metacpan.org/authors/id/A/AU/AUTHOR/No-Version.tar.gz",
            "https://cpan.metacpan.org/modules/02packages.details.txt.gz",
            "https://example.org/authors/id/R/RJ/RJBS/Algorithm-Diff-1.201.tar.gz",
            "https://metacpan.org/dist/foo%2Fbar",
        )
        for url in urls:
            with self.subTest(url=url):
                self.assertIsNone(guess_cpan(url))

    def test_prefers_authoritative_release_name_over_archive_duplicate(self) -> None:
        candidates = infer_all(
            [
                "https://cpan.metacpan.org/authors/id/R/RJ/RJBS/Algorithm-Diff-1.201.tar.gz",
                "https://metacpan.org/release/Algorithm-Diff",
            ]
        )
        self.assertEqual(
            [candidate.purl for candidate in candidates], ["pkg:cpan/Algorithm-Diff"]
        )
        self.assertEqual(candidates[0].confidence, 0.97)


class SourceHostRankingTest(unittest.TestCase):
    def test_deduplicates_gitlab_display_case_variants(self) -> None:
        candidates = infer_all(
            [
                "https://gitlab.com/stochastic-control/stopt/-/archive/v7.1/stopt.tar.gz",
                "https://gitlab.com/stochastic-control/StOpt",
            ]
        )
        self.assertEqual(
            [candidate.purl for candidate in candidates],
            ["pkg:git/gitlab.com/stochastic-control/stopt"],
        )

    def test_prunes_an_unrelated_dependency_repository(self) -> None:
        candidates = infer_all(
            [
                "https://gitlab.com/graphviz/graphviz/-/archive/14.1.2/graphviz.tar.gz",
                "https://gitlab.com/graphviz/graphviz-windows-dependencies/-/archive/2025/deps.tar.gz",
            ],
            context=RecipeContext(conda_name="graphviz"),
        )
        self.assertEqual(
            [candidate.purl for candidate in candidates],
            ["pkg:git/gitlab.com/graphviz/graphviz"],
        )

    def test_direct_registry_identity_ranks_above_repository_identity(self) -> None:
        candidates = infer_all(
            [
                "https://gitlab.com/example/algorithm-diff",
                "https://metacpan.org/release/Algorithm-Diff",
            ]
        )
        self.assertEqual(candidates[0].purl, "pkg:cpan/Algorithm-Diff")
        self.assertEqual(
            candidates[1].purl, "pkg:git/gitlab.com/example/algorithm-diff"
        )

    def test_existing_ecosystem_context_remains_primary(self) -> None:
        candidates = infer_all(
            [
                "https://files.pythonhosted.org/packages/source/d/demo/demo-1.0.tar.gz",
                "https://bitbucket.org/example/demo",
            ],
            context=RecipeContext(
                conda_name="demo", ecosystem_hint="pypi", inferred_name="demo"
            ),
        )
        self.assertEqual(candidates[0].purl, "pkg:pypi/demo")
        self.assertAlmostEqual(candidates[0].confidence, 0.94)
        self.assertEqual(candidates[1].purl, "pkg:bitbucket/example/demo")


if __name__ == "__main__":
    unittest.main()
