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


_PYPI_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 / purl-spec PyPI normalization: lowercase + collapse runs of
    ``[-_.]`` to a single ``-``. ``Foo_Bar.Baz`` → ``foo-bar-baz``."""
    return _PYPI_NORMALIZE_RE.sub("-", name).lower()


def normalize_purl(purl: str) -> str:
    """Apply type-specific name normalization to a PURL.

    Per the package-url spec (https://github.com/package-url/purl-spec/tree/main/types):
    - pypi: lowercase + collapse runs of [-_.] to a single - (PEP 503)
    - npm: lowercase (scope + name)
    - github: lowercase (owner + repo)
    - cargo, cran, gem, bioconductor: case-sensitive, no normalization
    """
    if not purl.startswith("pkg:"):
        return purl
    body = purl[len("pkg:") :]
    type_, slash, rest = body.partition("/")
    if not slash:
        return purl
    # Split off qualifiers / subpath first (they always come after @version).
    rest, sub_sep, sub_part = rest.partition("#")
    rest, qual_sep, qual_part = rest.partition("?")
    # @version is the LAST '@' — but for npm scoped names the FIRST '@' is the
    # scope marker, not a version separator. Use rfind so we don't confuse it.
    last_at = rest.rfind("@")
    if last_at > 0:
        head, ver = rest[:last_at], rest[last_at:]
    else:
        head, ver = rest, ""

    if type_ == "pypi":
        head = normalize_pypi_name(head)
    elif type_ in {"npm", "github"}:
        head = head.lower()
    else:
        return purl

    out = f"pkg:{type_}/{head}{ver}"
    if qual_sep:
        out = f"{out}?{qual_part}"
    if sub_sep:
        out = f"{out}#{sub_part}"
    return out


def guess_pypi(url: str) -> PurlGuess | None:
    host = urlparse(url).netloc
    if host not in _PYPI_HOSTS:
        return None
    # pypi.org/project/<name>/...
    m = re.search(r"pypi\.org/(?:project|simple)/([^/]+)/", url)
    if m:
        name = normalize_pypi_name(m.group(1))
        return PurlGuess(f"pkg:pypi/{name}", "pypi", None, name, 0.97, "recipe-source")
    # files.pythonhosted.org/packages/.../<name>-<version>.tar.gz
    parsed = urlparse(url)
    leaf = parsed.path.rsplit("/", 1)[-1]
    stem = _strip_archive_suffix(leaf)
    name = _strip_version_tail(stem)
    if name:
        name = normalize_pypi_name(name)
        return PurlGuess(f"pkg:pypi/{name}", "pypi", None, name, 0.9, "recipe-source")
    return None


def guess_github(url: str) -> PurlGuess | None:
    parsed = urlparse(url)
    if parsed.netloc != "github.com":
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    owner = parts[0].lower()
    repo = parts[1].removesuffix(".git").lower()
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
        scope, name = parts[0].lower(), parts[1].lower()
        return PurlGuess(
            f"pkg:npm/{scope}/{name}", "npm", scope, name, 0.95, "recipe-source"
        )
    name = parts[0].lower()
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
    # Homepage short-link: /package=NAME (or ?package=NAME)
    m = re.search(r"package=([A-Za-z][A-Za-z0-9.]*)", parsed.path + "?" + parsed.query)
    if m:
        name = m.group(1)
        return PurlGuess(f"pkg:cran/{name}", "cran", None, name, 0.92, "recipe-source")
    # /web/packages/NAME/...
    m = re.search(r"/web/packages/([A-Za-z][A-Za-z0-9.]*)", parsed.path)
    if m:
        name = m.group(1)
        return PurlGuess(f"pkg:cran/{name}", "cran", None, name, 0.92, "recipe-source")
    # /src/contrib/NAME_VERSION.tar.gz (also under /Archive/NAME/...)
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
    deps_norm = {
        d.split()[0].split("=")[0].strip().lower() for d in host_deps + build_deps
    }

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


def infer_all(
    urls: list[str], *, context: RecipeContext | None = None
) -> list[PurlGuess]:
    """Return all candidate PURL guesses, ranked from most to least likely.

    A package can legitimately carry several PURLs — e.g. numpy is both
    ``pkg:pypi/numpy`` (in the PyPI security feed) and
    ``pkg:github/numpy/numpy`` (in the GitHub advisory feed). Callers should
    treat the first entry as primary and the rest as alternatives.
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

    # Dedupe by PURL string, keeping the highest-confidence entry.
    by_purl: dict[str, PurlGuess] = {}
    for h in hits:
        prior = by_purl.get(h.purl)
        if prior is None or h.confidence > prior.confidence:
            by_purl[h.purl] = h
    deduped = list(by_purl.values())

    # Tiered ranking: a recipe-context ecosystem hint forces that ecosystem
    # to be primary (because that's the ecosystem CVE feeds index against).
    # Other URL-only matches become alternatives, sorted by confidence.
    if context and context.ecosystem_hint:
        matching = [h for h in deduped if h.type == context.ecosystem_hint]
        others = sorted(
            (h for h in deduped if h.type != context.ecosystem_hint),
            key=lambda h: h.confidence,
            reverse=True,
        )
        if matching:
            primary = max(matching, key=lambda h: h.confidence)
            boosted = PurlGuess(
                purl=primary.purl,
                type=primary.type,
                namespace=primary.namespace,
                pkg_name=primary.pkg_name,
                confidence=min(0.99, primary.confidence + 0.04),
                source=f"{primary.source}+recipe-deps",
            )
            return [boosted] + [h for h in matching if h is not primary] + others
        if context.inferred_name:
            synth = PurlGuess(
                purl=f"pkg:{context.ecosystem_hint}/{context.inferred_name}",
                type=context.ecosystem_hint,
                namespace=None,
                pkg_name=context.inferred_name,
                confidence=0.6,
                source="recipe-deps",
            )
            return [synth] + others
        return others

    return sorted(deduped, key=lambda h: h.confidence, reverse=True)


def infer(urls: list[str], *, context: RecipeContext | None = None) -> PurlGuess | None:
    """Best single PURL guess (the primary). See :func:`infer_all` for the
    full candidate list."""
    candidates = infer_all(urls, context=context)
    return candidates[0] if candidates else None


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
