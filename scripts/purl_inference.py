"""Heuristics that turn rendered-recipe source URLs into PURLs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class PurlGuess:
    purl: str
    type: str
    namespace: str | None
    pkg_name: str
    confidence: float
    source: str  # which heuristic fired


_PYPI_HOSTS = {
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "pythonhosted.org",
}
_NPM_HOSTS = {"registry.npmjs.org"}
_CARGO_HOSTS = {"crates.io", "static.crates.io"}
_RUBY_HOSTS = {"rubygems.org"}
_CRAN_HOSTS = {"cran.r-project.org", "cloud.r-project.org"}
_BIOCONDUCTOR_HOSTS = {"bioconductor.org"}


def _strip_archive_suffix(name: str) -> str:
    for suffix in (
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tgz",
        ".tbz2",
        ".zip",
        ".whl",
        ".tar",
    ):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _strip_version_tail(stem: str) -> str:
    # numpy-2.2.4 → numpy
    return re.sub(r"[-_]v?\d[\d.\w-]*$", "", stem)


def guess_pypi(url: str) -> PurlGuess | None:
    host = urlparse(url).netloc
    if host not in _PYPI_HOSTS:
        return None
    # pypi.org/project/<name>/...
    m = re.search(r"pypi\.org/(?:project|simple)/([^/]+)/", url)
    if m:
        name = m.group(1)
        return PurlGuess(
            f"pkg:pypi/{name.lower()}", "pypi", None, name.lower(), 0.97, "recipe-source"
        )
    # files.pythonhosted.org/packages/.../<name>-<version>.tar.gz
    parsed = urlparse(url)
    leaf = parsed.path.rsplit("/", 1)[-1]
    stem = _strip_archive_suffix(leaf)
    name = _strip_version_tail(stem)
    if name:
        return PurlGuess(
            f"pkg:pypi/{name.lower()}", "pypi", None, name.lower(), 0.9, "recipe-source"
        )
    return None


def guess_github(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    repo = repo.removesuffix(".git")
    return PurlGuess(
        f"pkg:github/{owner}/{repo}",
        "github",
        owner,
        repo,
        0.85,
        "recipe-source",
    )


def guess_cargo(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc not in _CARGO_HOSTS:
        return None
    # crates.io/api/v1/crates/<name>/<version>/download
    m = re.search(r"/crates/([^/]+)/", parsed.path)
    if m:
        name = m.group(1)
        return PurlGuess(
            f"pkg:cargo/{name}", "cargo", None, name, 0.95, "recipe-source"
        )
    return None


def guess_npm(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc not in _NPM_HOSTS:
        return None
    # registry.npmjs.org/<scope?>/<name>/-/<name>-<v>.tgz
    parts = [p for p in parsed.path.split("/") if p]
    if not parts:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        scope, name = parts[0], parts[1]
        return PurlGuess(
            f"pkg:npm/{scope}/{name}", "npm", scope, name, 0.95, "recipe-source"
        )
    name = parts[0]
    return PurlGuess(f"pkg:npm/{name}", "npm", None, name, 0.95, "recipe-source")


def guess_gem(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc not in _RUBY_HOSTS:
        return None
    leaf = parsed.path.rsplit("/", 1)[-1]
    stem = leaf.removesuffix(".gem")
    name = _strip_version_tail(stem)
    if name:
        return PurlGuess(f"pkg:gem/{name}", "gem", None, name, 0.9, "recipe-source")
    return None


def guess_cran(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc not in _CRAN_HOSTS:
        return None
    leaf = parsed.path.rsplit("/", 1)[-1]
    stem = _strip_archive_suffix(leaf)
    name = _strip_version_tail(stem)
    if name:
        return PurlGuess(f"pkg:cran/{name}", "cran", None, name, 0.92, "recipe-source")
    return None


def guess_bioconductor(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc not in _BIOCONDUCTOR_HOSTS:
        return None
    leaf = parsed.path.rsplit("/", 1)[-1]
    stem = _strip_archive_suffix(leaf)
    name = _strip_version_tail(stem)
    if name:
        return PurlGuess(
            f"pkg:bioconductor/{name}",
            "bioconductor",
            None,
            name,
            0.92,
            "recipe-source",
        )
    return None


_GUESSERS = (
    guess_pypi,
    guess_github,
    guess_cargo,
    guess_npm,
    guess_gem,
    guess_cran,
    guess_bioconductor,
)


@dataclass(frozen=True)
class RecipeContext:
    """Minimal recipe-derived signals used to bias inference.

    ``ecosystem_hint`` is the strongly-implied ecosystem (e.g. "pypi" if the
    recipe uses pip / python-build / maturin / cython, "cargo" if cargo is in
    the build deps, "cran"/"bioconductor" from the conda name prefix).
    ``inferred_name`` is the best-guess upstream name for that ecosystem.
    """

    conda_name: str
    ecosystem_hint: str | None = None
    inferred_name: str | None = None


_PYTHON_BUILD_SIGNALS = {
    "pip",
    "python-build",
    "python-setuptools",
    "setuptools",
    "poetry-core",
    "poetry",
    "flit",
    "flit-core",
    "hatchling",
    "hatch-vcs",
    "meson-python",
    "scikit-build",
    "scikit-build-core",
    "maturin",
    "cython",
    "pdm-backend",
    "pdm-pep517",
}
_RUST_BUILD_SIGNALS = {"cargo", "rust", "rust_compiler", "maturin"}
_NPM_BUILD_SIGNALS = {"nodejs", "yarn", "pnpm"}


def derive_recipe_context(
    *, conda_name: str, host_deps: list[str], build_deps: list[str], noarch: str | None
) -> RecipeContext:
    deps_norm = {d.split()[0].split("=")[0].strip().lower() for d in host_deps + build_deps}

    if conda_name.startswith("r-"):
        return RecipeContext(
            conda_name=conda_name,
            ecosystem_hint="cran",
            inferred_name=conda_name[2:],
        )
    if conda_name.startswith("bioconductor-"):
        return RecipeContext(
            conda_name=conda_name,
            ecosystem_hint="bioconductor",
            inferred_name=conda_name[len("bioconductor-") :],
        )

    if noarch == "python" or deps_norm & _PYTHON_BUILD_SIGNALS:
        return RecipeContext(
            conda_name=conda_name, ecosystem_hint="pypi", inferred_name=conda_name
        )
    if deps_norm & _RUST_BUILD_SIGNALS:
        return RecipeContext(
            conda_name=conda_name, ecosystem_hint="cargo", inferred_name=conda_name
        )
    if deps_norm & _NPM_BUILD_SIGNALS:
        return RecipeContext(
            conda_name=conda_name, ecosystem_hint="npm", inferred_name=conda_name
        )
    return RecipeContext(conda_name=conda_name)


def infer(
    urls: list[str], *, context: RecipeContext | None = None
) -> PurlGuess | None:
    """Best-effort PURL guess from source URLs + recipe context.

    Strategy:
    1. Run each URL guesser, collect all hits.
    2. If a recipe-context ecosystem hint is set, prefer the matching guess
       (and bump its confidence). If no URL matched the hinted ecosystem,
       synthesise a hint-only guess (lower confidence).
    3. Otherwise return the highest-confidence URL guess.
    """
    hits: list[PurlGuess] = []
    for url in urls:
        for guesser in _GUESSERS:
            try:
                guess = guesser(url)
            except Exception:
                continue
            if guess is not None:
                hits.append(guess)

    if context and context.ecosystem_hint:
        matching = [h for h in hits if h.type == context.ecosystem_hint]
        if matching:
            best = max(matching, key=lambda h: h.confidence)
            return PurlGuess(
                purl=best.purl,
                type=best.type,
                namespace=best.namespace,
                pkg_name=best.pkg_name,
                confidence=min(0.99, best.confidence + 0.04),
                source=f"{best.source}+recipe-deps",
            )
        if context.inferred_name:
            return PurlGuess(
                purl=f"pkg:{context.ecosystem_hint}/{context.inferred_name}",
                type=context.ecosystem_hint,
                namespace=None,
                pkg_name=context.inferred_name,
                confidence=0.6,
                source="recipe-deps",
            )

    if not hits:
        return None
    return max(hits, key=lambda h: h.confidence)


# Backwards-compat alias.
def infer_from_urls(urls: list[str]) -> PurlGuess | None:
    return infer(urls)


def conda_name_to_pypi_hint(name: str) -> str | None:
    """Some conda packages have stable name patterns (e.g. r-foo → cran/foo)."""
    if name.startswith("r-"):
        return name[2:]
    if name.startswith("bioconductor-"):
        return name[len("bioconductor-") :]
    return None
