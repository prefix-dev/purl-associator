"""Regression tests for automap platform coverage.

Run with: ``pixi run python -m unittest tests.test_automap_platforms`` (the
default environment carries py-rattler, which ``scripts.automap`` imports).
"""

from __future__ import annotations

import unittest

from scripts.automap import DEFAULT_PLATFORMS


class DefaultPlatformsTest(unittest.TestCase):
    """Guard against issue #106: packages that ship on no ``linux-64``/``noarch``
    build (e.g. ``pywin32-ctypes``, which is ``win-32``/``win-64`` only) must
    still be enumerated. ``_gather_records`` discovers names via
    ``gateway.names(platforms=...)``, so a platform absent from the default set
    is invisible to the full-channel scan.
    """

    def test_covers_full_conda_forge_matrix(self) -> None:
        # The platforms a package can ship on without ever appearing on
        # linux-64/noarch. Each must be in the default scan or that package
        # silently vanishes from the mappings.
        required = {
            "noarch",
            "linux-64",
            "linux-aarch64",
            "linux-ppc64le",
            "osx-64",
            "osx-arm64",
            "win-64",
            "win-32",
        }
        missing = required - set(DEFAULT_PLATFORMS)
        self.assertEqual(
            missing,
            set(),
            f"DEFAULT_PLATFORMS omits {sorted(missing)}; packages exclusive to "
            "those platforms would be missed (issue #106).",
        )

    def test_includes_windows_for_pywin32_ctypes(self) -> None:
        # The concrete package from issue #106 is win-only.
        self.assertIn("win-64", DEFAULT_PLATFORMS)


if __name__ == "__main__":
    unittest.main()
