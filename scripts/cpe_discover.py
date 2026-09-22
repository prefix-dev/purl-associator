"""Discover candidate CPE coordinates for top-downloaded conda-forge packages
that currently lack ecosystem PURLs commonly covered by OSV.

Pipeline (heuristics-only; no AI step):

1. Rank ``mappings/auto.json`` entries by ``download_count`` (already
   populated by ``scripts.hydrate_downloads``) and take the top ``--top``.
2. Skip names that are already mapped to a package ecosystem commonly covered
   by OSV (PyPI, npm, etc.) or already carry a ``cpes`` list in ``manual.json``
   or any contribution file. Remaining names are candidates for a CPE identity.
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
   bucket is what ``cpe_vet.py`` hands to Claude Haiku for tie-breaking.
7. Separately surface exact source-URL/version siblings of reviewed CPE-backed
   packages as ``shared_source_review`` evidence. Agreeing anchors create a
   human review candidate; disagreeing anchors create an auditable conflict.
   Neither path changes heuristic scores or enters automated promotion.
8. Write a single audit file ``mappings/cpe_candidates/latest.json`` with
   all buckets, review evidence, and per-heuristic scores.

Run it:

    pixi run cpe:discover
    pixi run cpe:discover --top 50 --out .tmp/cpe-candidates.json
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

from scripts.cpe_evidence import (
    AutoEntry,
    _is_cpe_candidate,
    _load_effective_cpes,
    _load_effective_mappings,
    _shared_source_evidence,
)
from scripts.nvd_fetch import NvdIndex, fetch_index

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUTO = ROOT / "mappings" / "auto.json"
DEFAULT_MANUAL = ROOT / "mappings" / "manual.json"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "contributions"
DEFAULT_OUT_DIR = ROOT / "mappings" / "cpe_candidates"
DEFAULT_NVD_CACHE = ROOT / "nvd_cache"

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

    # H6: conda name appears as a token in any CVE's description. We check
    # every CVE — picking just one (e.g. the longest description) lets the
    # token hide there even when it shows up clearly in others, and the
    # whole-list scan is still O(n) over an already-bounded list.
    if cves:
        token_re = _token_re(conda_name)
        seen_ids: set[str] = set()
        for cve in cves:
            cid = cve.get("id")
            if not isinstance(cid, str) or cid in seen_ids:
                continue
            seen_ids.add(cid)
            desc = _summary_for(cve)
            if not desc:
                continue
            if not score.h6_desc_mentions_name and token_re.search(desc):
                score.h6_desc_mentions_name = True
            if len(score.sample_summaries) < 3:
                score.sample_summaries.append(f"{cid}: {desc[:160]}")

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
      A3. H3 (single survivor) ∧ H4
      A4. H3 (single survivor) ∧ H5 ∧ H7   (trusted vendor needs ≥3 CVEs)
      A5. H5 ∧ product_unique ∧ H7        (trusted vendor needs ≥3 CVEs)
      A6. H5 ∧ H1>0                       (trusted vendor + any URL corroboration)

    H5 (trusted-vendor allowlist) is intentionally **not** a stand-alone
    shipping gate. The allowlist is hard-coded in this file, so trusting
    it alone for single-CVE matches would let a stale or wrong entry ship
    without any non-allowlist evidence. Pair H5 with H7 (≥3 CVEs from
    NVD corroborates a real product), H1 (the conda PURL's repo appears
    in the NVD references), or push to the AI vet step.

    Ambiguous: anything with at least one fired heuristic that isn't
    decisive (H2 alone, H4 alone, H5 alone, H6 alone, H5+single-CVE,
    or multiple competing vendors).

    Drop: nothing fires.
    """
    accept: list[CandidateScore] = []
    ambiguous: list[CandidateScore] = []
    drop: list[CandidateScore] = []

    # candidates list is the post-H8 (part='a', not in BANNED_VENDORS) set
    # surfaced by _process_candidate. H7 (≥3 CVEs) is **not** a filter
    # here — it's a per-candidate score we check at acceptance time.
    n = len(candidates)
    unique_survivor = n == 1

    # Group by product to apply A5 (trusted vendor + only one vendor for
    # that product among survivors + enough CVEs).
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
        elif unique_survivor and c.h4_vendor_eq_product:
            accepted_via = "H3+H4 unique-survivor AND vendor==product"
        elif unique_survivor and c.h5_trusted_vendor and c.h7_cve_count_ok:
            accepted_via = "H3+H5+H7 unique-survivor AND trusted-vendor AND ≥3 CVEs"
        elif c.h5_trusted_vendor and product_unique and c.h7_cve_count_ok:
            accepted_via = "H5+H7 trusted-vendor AND single vendor AND ≥3 CVEs"
        elif c.h5_trusted_vendor and c.h1_github_url_rate > 0:
            accepted_via = (
                f"H5+H1 trusted-vendor AND github-url-rate={c.h1_github_url_rate:.2f}"
            )

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
    shared_source_review: list[dict[str, Any]] | None = None,
    shared_source_conflict: dict[str, Any] | None = None,
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
    accepted_cpes = {candidate.cpe for candidate in accept}
    review = [
        evidence
        for evidence in (shared_source_review or [])
        if not set(evidence.get("cpes") or ()).issubset(accepted_cpes)
    ]

    return {
        "conda_name": conda_name,
        "download_count": download_count,
        "current_purl": auto_entry.purl if auto_entry else None,
        # Conda summary is small but powerful disambiguation signal for the
        # AI vet step — passing it through here so cpe_vet doesn't need to
        # reload auto.json.
        "conda_summary": auto_entry.summary if auto_entry else None,
        "github_owner_repo": owner_repo,
        "product_guesses": guesses,
        "matched_heads": len(scored),
        "accept": [_candidate_to_dict(c) for c in accept],
        "shared_source_review": review,
        "shared_source_conflict": shared_source_conflict,
        "ambiguous": [_candidate_to_dict(c) for c in ambiguous],
        "drop": [_candidate_to_dict(c) for c in drop],
    }


@app.command()
def main(
    top: int = typer.Option(
        0,
        help="How many top-downloaded packages to consider. 0 (the default) "
        "or any value <= 0 means no cap — consider every package.",
    ),
    only: str | None = typer.Option(
        None,
        help="Comma-separated conda names to process. When set, only these "
        "names are considered regardless of --top (still filtered by the "
        "OSV-mappable and already-CPE'd checks).",
    ),
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
    effective_cpes = _load_effective_cpes(manual, contributions)
    already_have_cpes = {
        name for name, reviewed in effective_cpes.items() if reviewed.cpes
    }
    shared_reviews, shared_conflicts = _shared_source_evidence(
        auto_data, effective_cpes
    )

    only_set = {n.strip() for n in only.split(",") if n.strip()} if only else None

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
        # ``--only`` bypasses the top-N cutoff: callers asking for a
        # specific name want that name considered regardless of rank.
        if only_set is not None:
            if name not in only_set:
                continue
        else:
            # ``top <= 0`` is the sentinel for "no cap" — consider every
            # ranked package. A positive ``top`` keeps the historical
            # top-N behaviour.
            if top > 0 and considered >= top:
                break
        considered += 1
        if name in already_have_cpes:
            continue
        if not _is_cpe_candidate(name, entry):
            continue
        candidates.append((name, entry.download_count, entry))

    if only_set:
        scope_desc = f"--only set ({len(only_set)} names)"
    elif top > 0:
        scope_desc = f"top {top}"
    else:
        scope_desc = "all packages (no cap)"
    console.log(
        f"{scope_desc}: {len(candidates)} CPE candidates after filtering "
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
    shared_review_packages = shared_review_cpes = shared_review_downloads = 0
    shared_conflict_packages = shared_conflict_downloads = 0
    shared_review_groups: set[tuple[str, str]] = set()
    shared_conflict_groups: set[tuple[str, str]] = set()
    no_match = 0
    for name, dc, entry in candidates:
        result = _process_candidate(
            conda_name=name,
            auto_entry=entry,
            download_count=dc,
            index=index,
            shared_source_review=shared_reviews.get(name),
            shared_source_conflict=shared_conflicts.get(name),
        )
        results.append(result)
        accept_total += len(result["accept"])
        ambiguous_total += len(result["ambiguous"])
        drop_total += len(result["drop"])
        if result["shared_source_review"]:
            shared_review_packages += 1
            shared_review_downloads += dc
            shared_review_cpes += sum(
                len(evidence["cpes"]) for evidence in result["shared_source_review"]
            )
            shared_review_groups.update(
                (evidence["shared_source_url"], evidence["shared_version"])
                for evidence in result["shared_source_review"]
            )
        if result["shared_source_conflict"]:
            shared_conflict_packages += 1
            shared_conflict_downloads += dc
            conflict = result["shared_source_conflict"]
            shared_conflict_groups.add(
                (conflict["shared_source_url"], conflict["shared_version"])
            )
        if result["matched_heads"] == 0:
            no_match += 1

    # Sort automatic accepts first, then explicit human-review evidence,
    # heuristic ambiguity, conflicts, and finally rows with no useful signal.
    results.sort(
        key=lambda r: (
            0
            if r["accept"]
            else 1
            if r["shared_source_review"]
            else 2
            if r["ambiguous"]
            else 3
            if r["shared_source_conflict"]
            else 4,
            -r["download_count"],
        )
    )

    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    payload = {
        "schema_version": 2,
        "generated_at": generated_at,
        "top_considered": top,
        "candidates_processed": len(candidates),
        "heuristics_summary": {
            "auto_accept_total": accept_total,
            "ambiguous_total": ambiguous_total,
            "drop_total": drop_total,
            "no_nvd_match": no_match,
            "shared_source_review_groups": len(shared_review_groups),
            "shared_source_review_packages": shared_review_packages,
            "shared_source_review_cpes": shared_review_cpes,
            "shared_source_review_downloads": shared_review_downloads,
            "shared_source_conflict_groups": len(shared_conflict_groups),
            "shared_source_conflict_packages": shared_conflict_packages,
            "shared_source_conflict_downloads": shared_conflict_downloads,
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
        f"[magenta]shared-source review[/]: {len(shared_review_groups)} groups / "
        f"{shared_review_packages} packages / {shared_review_cpes} CPEs / "
        f"{shared_review_downloads:,} downloads · "
        f"[magenta]conflicts[/]: {len(shared_conflict_groups)} groups / "
        f"{shared_conflict_packages} packages / "
        f"{shared_conflict_downloads:,} downloads · "
        f"[red]no match[/]: {no_match} packages"
    )
    try:
        rel = out.relative_to(ROOT)
    except ValueError:
        rel = out
    console.log(f"Wrote {rel}")


if __name__ == "__main__":
    app()
