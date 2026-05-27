"""Discover candidate CPE coordinates for top-downloaded conda-forge packages
that currently lack OSV-mappable PURLs.

Pipeline (heuristics-only; no AI step):

1. Rank ``mappings/auto.json`` entries by ``download_count`` (already
   populated by ``scripts.hydrate_downloads``) and take the top ``--top``.
2. Skip names that are already mapped to an OSV ecosystem (PyPI, npm, etc.)
   or already carry a ``cpes`` list in ``manual.json`` or any contribution
   file. Remaining names are candidates for a CPE override.
3. Build the NVD ``(part, vendor, product) → [cves]`` index once
   (:mod:`scripts.nvd_fetch`).
4. For each candidate, propose **product names** by light normalization
   (strip ``lib``/``python-`` prefixes, ``-ng``/``-dev``/``-devel`` suffixes,
   swap ``-`` ↔ ``_``). For every guess, pull all matching application
   CPEs (``part='a'``) from the NVD index.
5. Apply heuristics H1–H8 to each ``(vendor, product)`` candidate:

   * H1: fraction of CVEs whose ``references[].url`` includes the conda
     PURL's GitHub ``owner/repo`` substring (strongest signal).
   * H2: ``vendor == github_owner`` or ``product == github_repo``.
   * H3: only one ``(vendor, product)`` survives all filters.
   * H4: ``vendor == product`` (self-naming, very common for primary
     upstream).
   * H5: vendor in a small trusted-allowlist (``gnu``, ``apache``, …).
   * H6: top CVE description mentions the conda name as a token.
   * H7: at least 3 CVEs (filters out single-CVE noise matches).
   * H8: negative list — drop OS (``o``) / hardware (``h``) parts and
     conda-infra vendors.

6. Bucket each candidate as ``accept`` / ``ambiguous`` / ``drop`` based on
   how many heuristics fired and with what strength. The ``ambiguous``
   bucket is what a future ``cpe_vet.py`` would hand to Claude Haiku for
   tie-breaking.
7. Write a single audit file ``mappings/cpe_candidates/<ISO>.json`` with
   all three buckets plus per-heuristic scores, so a human can sanity
   check what fired.

Run it:

    pixi run cpe-discover
    pixi run cpe-discover --top 50 --out .tmp/cpe-candidates.json
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from scripts.nvd_fetch import NvdIndex, fetch_index

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL = ROOT / "mappings" / "manual.json"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_OUT_DIR = ROOT / "mappings" / "cpe_candidates"
DEFAULT_NVD_CACHE = ROOT / "nvd_cache"

# PURL types that are already covered by the OSV → cve_match pipeline. A
# package mapped to one of these doesn't need a CPE override.
OSV_PURL_TYPES = frozenset(
    {"pypi", "npm", "cargo", "gem", "maven", "golang", "cran", "bioconductor"}
)

# H5 — Vendors that are nearly always the authoritative upstream for the
# product they ship. When a candidate (vendor, product) has ``vendor`` in
# this list and the product name matches a conda-name normalization, the
# match is strong enough to skip AI review. Keep this list short and
# conservative; adding a vendor here only raises confidence — it doesn't
# create new candidates that weren't already in the NVD index.
TRUSTED_VENDORS = frozenset(
    {
        "gnu",
        "apache",
        "mozilla",
        "python",
        "postgresql",
        "mysql",
        "openssl",
        "libssh",
        "libssh2",
        "openssh",
        "kerberos",
        "isc",  # bind, dhcp
        "haxx",  # curl
        "nlnetlabs",  # unbound, ldns
        "tcl",
        "tcltk",
        "sqlite",
        "openldap",
        "redis",
        "nginx",
        "icu-project",
        "unicode",
        "unicode-org",
        "libtiff",
        "libpng",
        "libexpat",
        "zlib",
        "facebook",
        "google",
        "kitware",  # cmake
    }
)

# H8 — Negative list. Vendors here are conda packaging infra, not real
# upstreams; any CPE match against them is spurious. Same for product
# names that are clearly conda-build internals.
BANNED_VENDORS = frozenset(
    {
        "conda-forge",
        "anaconda",
        "continuum_analytics",
        "continuum",
    }
)

# Common conda package-name prefixes and suffixes that don't appear in
# upstream CPE product names. ``libssh2`` ↔ ``libssh2`` matches both ways;
# ``libxml2`` keeps the ``lib`` prefix in NVD too, so we don't blindly
# strip — we keep both forms as candidates.
_PREFIXES_TO_STRIP = ("lib", "python-", "python3-", "py-")
_SUFFIXES_TO_STRIP = ("-ng", "-dev", "-devel", "-bin", "-tools", "-utils")

# Description keyword (H6) hit when the conda name appears as a token,
# case-insensitive, with non-word boundaries on either side.
_TOKEN_RE_CACHE: dict[str, re.Pattern[str]] = {}


def _token_re(token: str) -> re.Pattern[str]:
    if token not in _TOKEN_RE_CACHE:
        _TOKEN_RE_CACHE[token] = re.compile(
            rf"(?<!\w){re.escape(token)}(?!\w)", re.IGNORECASE
        )
    return _TOKEN_RE_CACHE[token]


# ---------- inputs ----------


def _load_existing_cpes(manual: Path, contrib_dir: Path) -> set[str]:
    """Names that already carry a ``cpes`` list in any reviewed source.
    These are skipped (we don't want to overwrite a curator's choice)."""
    have: set[str] = set()
    if manual.exists():
        try:
            mdata = json.loads(manual.read_text())
        except json.JSONDecodeError:
            mdata = {}
        for name, entry in (mdata.get("packages") or {}).items():
            if isinstance(entry, dict) and entry.get("cpes"):
                have.add(name)
    if contrib_dir.exists():
        for f in contrib_dir.glob("*.json"):
            try:
                cdata = json.loads(f.read_text())
            except json.JSONDecodeError:
                continue
            for name, entry in (cdata.get("packages") or {}).items():
                if isinstance(entry, dict) and entry.get("cpes"):
                    have.add(name)
    return have


@dataclass(frozen=True)
class AutoEntry:
    purl: str | None
    purl_type: str | None
    namespace: str | None
    pkg_name: str | None
    summary: str | None
    download_count: int  # 0 when missing; used for top-N ranking

    @property
    def github_owner_repo(self) -> str | None:
        """``owner/repo`` if the PURL is a ``pkg:github`` entry, else None."""
        if (
            self.purl_type == "github"
            and isinstance(self.namespace, str)
            and isinstance(self.pkg_name, str)
        ):
            return f"{self.namespace}/{self.pkg_name}"
        return None


_PURL_FIELDS = ("purl", "type", "namespace", "pkg_name")


def _overlay_purl(base: AutoEntry, override: dict) -> AutoEntry:
    """Return a new AutoEntry with PURL-related fields replaced where the
    override provides them. Mirrors ``merge_mappings``' replace-on-present
    semantics for the PURL layer."""
    if not any(k in override for k in _PURL_FIELDS):
        return base
    return AutoEntry(
        purl=override.get("purl", base.purl),
        purl_type=override.get("type", base.purl_type),
        namespace=override.get("namespace", base.namespace),
        pkg_name=override.get("pkg_name", base.pkg_name),
        summary=base.summary,  # human reviews never change the conda summary
        download_count=base.download_count,
    )


def _load_effective_mappings(
    auto: Path, manual: Path, contrib_dir: Path
) -> dict[str, AutoEntry]:
    """Return the merged ``{name: AutoEntry}`` view that ``merge_mappings``
    would produce for the PURL fields.

    Layered, newest wins: ``auto.json`` → ``manual.json`` → ``contributions``
    (sorted by ``timestamp`` then filename). We only need the PURL portion
    here — the ``cpes`` overrides are handled separately by
    :func:`_load_existing_cpes`."""
    out: dict[str, AutoEntry] = {}

    # Layer 1: auto.json — also carries the ``download_count`` we rank by.
    if auto.exists():
        data = json.loads(auto.read_text())
        for name, entry in (data.get("packages") or {}).items():
            if not isinstance(entry, dict):
                continue
            dc = entry.get("download_count")
            out[name] = AutoEntry(
                purl=entry.get("purl"),
                purl_type=entry.get("type"),
                namespace=entry.get("namespace"),
                pkg_name=entry.get("pkg_name"),
                summary=entry.get("summary"),
                download_count=dc if isinstance(dc, int) else 0,
            )

    blank = AutoEntry(
        purl=None,
        purl_type=None,
        namespace=None,
        pkg_name=None,
        summary=None,
        download_count=0,
    )

    # Layer 2: manual.json
    if manual.exists():
        try:
            mdata = json.loads(manual.read_text())
        except json.JSONDecodeError:
            mdata = {}
        for name, override in (mdata.get("packages") or {}).items():
            if not isinstance(override, dict):
                continue
            out[name] = _overlay_purl(out.get(name, blank), override)

    # Layer 3: contributions, oldest → newest (chronological), so the
    # newest reviewed override is what we see.
    if contrib_dir.exists():
        contribs: list[tuple[str, str, dict]] = []
        for f in sorted(contrib_dir.glob("*.json")):
            try:
                cdata = json.loads(f.read_text())
            except json.JSONDecodeError:
                continue
            ts = (
                cdata.get("timestamp")
                if isinstance(cdata.get("timestamp"), str)
                else f.stem
            )
            contribs.append((ts, f.name, cdata))
        contribs.sort(key=lambda t: (t[0], t[1]))
        for _ts, _fname, cdata in contribs:
            for name, override in (cdata.get("packages") or {}).items():
                if not isinstance(override, dict):
                    continue
                out[name] = _overlay_purl(out.get(name, blank), override)

    return out


# ---------- candidate selection ----------


def _is_cpe_candidate(name: str, entry: AutoEntry | None) -> bool:
    """A package is a CPE candidate if the OSV → cve_match pipeline cannot
    cover it: no PURL at all, or a PURL whose type isn't OSV-mappable."""
    # Skip conda-build internal feedstocks.
    if name.startswith("_") or name.startswith("python_abi"):
        return False
    if entry is None or not entry.purl:
        return True
    if entry.purl_type in OSV_PURL_TYPES:
        return False
    return True


def _product_guesses(
    conda_name: str, auto_entry: AutoEntry | None = None
) -> tuple[list[str], set[str]]:
    """All product-name normalizations to try against the NVD index.

    Returns ``(ordered_guesses, repo_fallback_guesses)``. ``ordered_guesses``
    is the lowercased, deduplicated list to search. ``repo_fallback_guesses``
    is the subset that came from the GitHub repo name of an auto-inferred
    PURL — these are weaker evidence because automap occasionally assigns
    the wrong repo (e.g. several ``libgcc``-family conda packages currently
    point to ``madler/zlib``), so candidates that match *only* via a
    repo-fallback guess get downgraded during bucketing."""
    lower = conda_name.lower()
    guesses = [lower]

    # Strip common conda prefixes (but keep the original too — ``libxml2``
    # is itself a real CPE product).
    for prefix in _PREFIXES_TO_STRIP:
        if lower.startswith(prefix) and len(lower) > len(prefix):
            guesses.append(lower[len(prefix) :])

    # Strip common suffixes.
    for suffix in _SUFFIXES_TO_STRIP:
        if lower.endswith(suffix) and len(lower) > len(suffix):
            guesses.append(lower[: -len(suffix)])

    # Swap separators — ``ld_impl_linux-64`` becomes nothing useful, but
    # ``libssh2-bin`` → ``libssh2`` already handled by suffix; this catches
    # things like ``libnsl-py`` ↔ ``libnsl_py``.
    swapped = lower.replace("-", "_")
    if swapped != lower:
        guesses.append(swapped)
    swapped2 = lower.replace("_", "-")
    if swapped2 != lower:
        guesses.append(swapped2)

    # Track name-derived guesses before adding the repo-fallback.
    repo_fallback: set[str] = set()

    # GitHub repo name from the auto-inferred PURL — catches conda-vs-upstream
    # name divergence (e.g. ``liblzma`` → ``tukaani-project/xz`` → guess ``xz``).
    if auto_entry and auto_entry.github_owner_repo:
        repo = auto_entry.github_owner_repo.split("/", 1)[1].lower()
        if repo not in guesses:
            repo_fallback.add(repo)
        guesses.append(repo)

    # Dedup, preserve order.
    seen: set[str] = set()
    out: list[str] = []
    for g in guesses:
        if g and g not in seen:
            seen.add(g)
            out.append(g)
    # ``repo_fallback`` was computed against the pre-dedup list; intersect
    # with the final set so its membership is meaningful.
    return out, repo_fallback & seen


# ---------- per-candidate scoring ----------


@dataclass
class CandidateScore:
    """One ``(vendor, product)`` CPE candidate scored by all heuristics."""

    cpe: str  # the bare prefix ``cpe:2.3:a:<vendor>:<product>``
    vendor: str
    product: str
    cve_count: int
    sample_summaries: list[str] = field(default_factory=list)
    # Heuristic scores. Booleans for binary heuristics, float for H1.
    h1_github_url_rate: float = 0.0
    h2_owner_or_repo_match: bool = False
    h4_vendor_eq_product: bool = False
    h5_trusted_vendor: bool = False
    h6_desc_mentions_name: bool = False
    h7_cve_count_ok: bool = False  # ≥ 3 CVEs — used as a corroborating signal
    # True when the ONLY product guess that matched this head was the
    # GitHub repo-name fallback. Such candidates skip the strongest
    # acceptance paths because the conda PURL we trusted to derive the
    # guess may itself be wrong.
    repo_fallback_only: bool = False
    # Decision rationale — populated by the bucketer.
    triggers: list[str] = field(default_factory=list)


def _summary_for(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and isinstance(d.get("value"), str):
            return d["value"][:240]
    return ""


def _score_candidate(
    *,
    head: tuple[str, str, str],
    cves: list[dict],
    conda_name: str,
    auto_entry: AutoEntry | None,
) -> CandidateScore:
    """Compute every heuristic for one ``(part, vendor, product)`` head."""
    part, vendor, product = head
    cpe_prefix = f"cpe:2.3:{part}:{vendor}:{product}"
    score = CandidateScore(
        cpe=cpe_prefix,
        vendor=vendor,
        product=product,
        cve_count=len(cves),
    )

    # H4: self-naming.
    score.h4_vendor_eq_product = vendor == product
    # H5: trusted vendor allowlist.
    score.h5_trusted_vendor = vendor in TRUSTED_VENDORS
    # H7: enough CVEs to suggest a real product rather than NVD noise.
    score.h7_cve_count_ok = len(cves) >= 3

    # H2: structural overlap with the conda PURL's GitHub coordinates.
    owner_repo = auto_entry.github_owner_repo if auto_entry else None
    if owner_repo:
        owner, repo = owner_repo.split("/", 1)
        score.h2_owner_or_repo_match = (
            vendor == owner.lower() or product == repo.lower()
        )

    # H6: conda name appears as a token in the top CVE's description.
    if cves:
        top = max(cves, key=lambda c: _summary_for(c) and len(_summary_for(c)))
        desc = _summary_for(top)
        if desc and _token_re(conda_name).search(desc):
            score.h6_desc_mentions_name = True
        # Collect a few sample descriptions for the audit file.
        seen_ids: set[str] = set()
        for cve in cves:
            cid = cve.get("id")
            if not isinstance(cid, str) or cid in seen_ids:
                continue
            seen_ids.add(cid)
            d = _summary_for(cve)
            if d:
                score.sample_summaries.append(f"{cid}: {d[:160]}")
            if len(score.sample_summaries) >= 3:
                break

    return score


# ---------- bucketing ----------


def _attach_h1(score: CandidateScore, index: NvdIndex, owner_repo: str | None) -> None:
    """Compute H1 lazily — only the candidates with a GitHub-owner conda
    package need it, and only when we're considering scoring."""
    if owner_repo:
        score.h1_github_url_rate = index.github_url_hit_rate(
            (
                "a",
                score.vendor,
                score.product,
            ),
            owner_repo,
        )


def _bucket_candidates(
    candidates: list[CandidateScore],
) -> tuple[list[CandidateScore], list[CandidateScore], list[CandidateScore]]:
    """Split scored candidates into (accept, ambiguous, drop).

    Acceptance rules — any of:
      A1. H1 (GitHub-URL hit rate) ≥ 0.5
      A2. H2 ∧ H4 (vendor matches owner/repo AND vendor == product)
      A3. H3 (single survivor) ∧ (H4 ∨ H5)
      A4. H5 ∧ H7 (trusted vendor with ≥ 3 CVEs) when only one candidate
          shares this product across all vendors

    Ambiguous: anything with at least one fired heuristic that isn't
    decisive (H2 alone, H4 alone, H5 alone, H6 alone, or multiple
    competing vendors).

    Drop: nothing fires.
    """
    accept: list[CandidateScore] = []
    ambiguous: list[CandidateScore] = []
    drop: list[CandidateScore] = []

    # H3 inputs: how many candidates remain after H7/H8 filtering.
    # ``candidates`` is already post-H8/H7 (caller filtered), so this is
    # just len-based.
    n = len(candidates)
    unique_survivor = n == 1

    # Group by product to apply A4 (trusted vendor + single vendor for
    # that product among survivors).
    by_product: dict[str, list[CandidateScore]] = {}
    for c in candidates:
        by_product.setdefault(c.product, []).append(c)

    for c in candidates:
        product_unique = len(by_product[c.product]) == 1
        accepted_via: str | None = None
        # A repo-fallback-only candidate cannot trust its product-name
        # match alone — automap may have pointed us at the wrong repo.
        # Such candidates always go to ambiguous regardless of how many
        # heuristics fire.
        if c.repo_fallback_only:
            pass
        elif c.h1_github_url_rate >= 0.5:
            accepted_via = f"H1 github-url-rate={c.h1_github_url_rate:.2f}"
        elif c.h2_owner_or_repo_match and c.h4_vendor_eq_product:
            accepted_via = "H2+H4 owner-match AND vendor==product"
        elif unique_survivor and (c.h4_vendor_eq_product or c.h5_trusted_vendor):
            accepted_via = (
                "H3+H4 unique-survivor AND vendor==product"
                if c.h4_vendor_eq_product
                else "H3+H5 unique-survivor AND trusted-vendor"
            )
        elif c.h5_trusted_vendor and product_unique:
            accepted_via = "H5 trusted-vendor AND single vendor for product"

        if accepted_via:
            c.triggers.append(accepted_via)
            accept.append(c)
            continue

        fired: list[str] = []
        if c.h2_owner_or_repo_match:
            fired.append("H2")
        if c.h4_vendor_eq_product:
            fired.append("H4")
        if c.h5_trusted_vendor:
            fired.append("H5")
        if c.h6_desc_mentions_name:
            fired.append("H6")
        if c.h1_github_url_rate > 0:
            fired.append(f"H1={c.h1_github_url_rate:.2f}")
        if c.repo_fallback_only:
            fired.append("repo-fallback-only")
        if fired:
            c.triggers = fired
            ambiguous.append(c)
        else:
            drop.append(c)

    return accept, ambiguous, drop


# ---------- main ----------


def _candidate_to_dict(c: CandidateScore) -> dict:
    return {
        "cpe": c.cpe,
        "vendor": c.vendor,
        "product": c.product,
        "cve_count": c.cve_count,
        "scores": {
            "h1_github_url_rate": round(c.h1_github_url_rate, 3),
            "h2_owner_or_repo_match": c.h2_owner_or_repo_match,
            "h4_vendor_eq_product": c.h4_vendor_eq_product,
            "h5_trusted_vendor": c.h5_trusted_vendor,
            "h6_desc_mentions_name": c.h6_desc_mentions_name,
            "h7_cve_count_ok": c.h7_cve_count_ok,
            "repo_fallback_only": c.repo_fallback_only,
        },
        "triggers": c.triggers,
        "sample_summaries": c.sample_summaries,
    }


def _process_candidate(
    *,
    conda_name: str,
    auto_entry: AutoEntry | None,
    download_count: int,
    index: NvdIndex,
) -> dict[str, Any]:
    """Score every NVD product-name match for one conda candidate and
    bucket the results."""
    guesses, repo_fallback = _product_guesses(conda_name, auto_entry)
    # Walk the index for each guess, dedupe heads across guesses. Track
    # *every* guess that matched a given head so we can tell whether it
    # was reachable via at least one name-derived guess.
    heads: dict[tuple[str, str, str], list[dict]] = {}
    matched_guesses: dict[tuple[str, str, str], set[str]] = {}
    for g in guesses:
        for head in index.products_matching(g):
            part, vendor, _product = head
            if part != "a":  # H8: applications only
                continue
            if vendor in BANNED_VENDORS:  # H8: conda-infra negative list
                continue
            cves = index.by_pp.get(head) or []
            if not cves:  # NVD index dropped this somehow; defensive
                continue
            heads.setdefault(head, cves)
            matched_guesses.setdefault(head, set()).add(g)

    scored: list[CandidateScore] = []
    owner_repo = auto_entry.github_owner_repo if auto_entry else None
    for head, cves in heads.items():
        s = _score_candidate(
            head=head, cves=cves, conda_name=conda_name, auto_entry=auto_entry
        )
        # If every guess that surfaced this head was the repo fallback,
        # the candidate's only link back to the conda package goes through
        # a (possibly wrong) auto-inferred PURL. Flag it so bucketing can
        # downgrade.
        matched_g = matched_guesses[head]
        s.repo_fallback_only = bool(repo_fallback) and matched_g.issubset(repo_fallback)
        _attach_h1(s, index, owner_repo)
        scored.append(s)

    accept, ambiguous, drop = _bucket_candidates(scored)

    return {
        "conda_name": conda_name,
        "download_count": download_count,
        "current_purl": auto_entry.purl if auto_entry else None,
        "github_owner_repo": owner_repo,
        "product_guesses": guesses,
        "matched_heads": len(scored),
        "accept": [_candidate_to_dict(c) for c in accept],
        "ambiguous": [_candidate_to_dict(c) for c in ambiguous],
        "drop": [_candidate_to_dict(c) for c in drop],
    }


@app.command()
def main(
    top: int = typer.Option(100, help="How many top-downloaded packages to consider"),
    auto: Path = typer.Option(DEFAULT_AUTO),
    manual: Path = typer.Option(DEFAULT_MANUAL),
    contributions: Path = typer.Option(DEFAULT_CONTRIB_DIR),
    out_dir: Path = typer.Option(DEFAULT_OUT_DIR),
    out: Path | None = typer.Option(
        None, help="Explicit output path; default <out_dir>/latest.json"
    ),
    nvd_cache: Path = typer.Option(DEFAULT_NVD_CACHE),
    force_nvd: bool = typer.Option(False),
    nvd_max_age_hours: float = typer.Option(2.0),
) -> None:
    """Discover CPE candidates for top-downloaded conda-forge packages."""
    auto_data = _load_effective_mappings(auto, manual, contributions)
    already_have_cpes = _load_existing_cpes(manual, contributions)

    # Rank packages by ``download_count`` (already populated on every
    # auto.json entry by ``scripts.hydrate_downloads``). Tie-break by name
    # for deterministic output when many entries share count == 0.
    ranked = sorted(
        auto_data.items(),
        key=lambda kv: (-kv[1].download_count, kv[0]),
    )

    candidates: list[tuple[str, int, AutoEntry | None]] = []
    considered = 0
    for name, entry in ranked:
        if considered >= top:
            break
        considered += 1
        if name in already_have_cpes:
            continue
        if not _is_cpe_candidate(name, entry):
            continue
        candidates.append((name, entry.download_count, entry))

    console.log(
        f"Top {top}: {len(candidates)} CPE candidates after filtering "
        f"({considered - len(candidates)} skipped — OSV-mapped, "
        f"already-CPE'd, or conda-infra)"
    )

    if not candidates:
        console.log("[yellow]No candidates — nothing to do.[/]")
        return

    console.log("Refreshing NVD feed cache…")
    index = asyncio.run(
        fetch_index(
            cache_dir=nvd_cache,
            force=force_nvd,
            max_modified_age_hours=nvd_max_age_hours,
        )
    )
    console.log(
        f"NVD index: [bold]{index.total_cves():,}[/] CVEs across "
        f"{len(index.by_pp):,} (part,vendor,product) keys."
    )

    results: list[dict] = []
    accept_total = ambiguous_total = drop_total = 0
    no_match = 0
    for name, dc, entry in candidates:
        result = _process_candidate(
            conda_name=name, auto_entry=entry, download_count=dc, index=index
        )
        results.append(result)
        accept_total += len(result["accept"])
        ambiguous_total += len(result["ambiguous"])
        drop_total += len(result["drop"])
        if result["matched_heads"] == 0:
            no_match += 1

    # Sort so the most actionable rows (any accept) bubble to the top.
    results.sort(
        key=lambda r: (
            0 if r["accept"] else 1 if r["ambiguous"] else 2,
            -r["download_count"],
        )
    )

    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    payload = {
        "schema_version": 1,
        "generated_at": generated_at,
        "top_considered": top,
        "candidates_processed": len(candidates),
        "heuristics_summary": {
            "auto_accept_total": accept_total,
            "ambiguous_total": ambiguous_total,
            "drop_total": drop_total,
            "no_nvd_match": no_match,
        },
        "packages": results,
    }

    if out is None:
        # Rolling snapshot: overwrite the same file on each run so git
        # tracks evolution via that file's history. The full audit is
        # always reproducible from (NVD state + mappings state), so
        # there's no information lost compared to timestamped files.
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "latest.json"
    out = out.resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n")

    accepted_pkgs = sum(1 for r in results if r["accept"])
    ambiguous_pkgs = sum(1 for r in results if not r["accept"] and r["ambiguous"])
    console.log(
        f"[green]auto-accept[/]: {accepted_pkgs} packages "
        f"({accept_total} CPEs) · "
        f"[yellow]ambiguous[/]: {ambiguous_pkgs} packages "
        f"({ambiguous_total} CPEs) · "
        f"[red]no match[/]: {no_match} packages"
    )
    try:
        rel = out.relative_to(ROOT)
    except ValueError:
        rel = out
    console.log(f"Wrote {rel}")


if __name__ == "__main__":
    app()
