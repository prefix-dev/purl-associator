# Artifact relationships — source contract v1

This is the **review-only source contract**, not a new public mapping payload.
It replaces the initial, unmerged RPM-only component-review prototype in PR #320;
there is no production migration or compatibility format to maintain.

## Boundaries

- Subjects remain exact conda-forge artifacts. Upstream identities are generic
  PURLs: RPM, deb, PyPI, npm, cargo, repository types, or other PURL ecosystems.
- A relationship is neither identity equivalence nor a vulnerability verdict.
  Do not copy upstream PURLs into active primary/alternative mappings.
- No publication, UI integration, automatic discovery/promotion, readiness-count
  changes, Basilisk ingestion, or vulnerability evaluation in this PR.
- PURL parsing is syntax validation, not proof that a package exists or that an
  evaluator supports its ecosystem. Review claims require human evidence review.
- Multiple sources/components are permitted, but individually evidenced; a
  recipe's source list does not imply every output contains every input.

## Review log

Store append-only JSON records in `mappings/artifact_relationships/`. Example
below abbreviates checksums; actual files require lowercase 64-digit SHA256.

```json
{
  "schema_version": 1,
  "status": "review-only",
  "operation": "replace",
  "subject": {
    "purl": "pkg:conda/conda-forge/example@1.0?build=abc_0&subdir=linux-64",
    "sha256": "<exact conda artifact digest>"
  },
  "review": {
    "reviewer": "reviewer-name",
    "reviewed_at": "2026-09-24T10:00:00Z"
  },
  "rationale": "Explain the decision and its scope.",
  "relationships": [
    {
      "relationship": "derived_from",
      "upstream": {
        "purl": "pkg:pypi/example@1.0",
        "sha256": "<exact upstream artifact digest>"
      },
      "evidence": {
        "path": "example-proof.json",
        "sha256": "<SHA256 of evidence JSON bytes>"
      }
    },
    {
      "relationship": "contains",
      "upstream": {
        "purl": "pkg:github/example/component",
        "sha256": null
      },
      "evidence": {
        "path": "example-proof.json",
        "sha256": "<SHA256 of evidence JSON bytes>"
      }
    }
  ]
}
```

### Fields and semantics

| Field | Meaning |
|---|---|
| `schema_version` | Source contract version, exactly integer 1. Unknown schemas/fields fail. |
| `status` | Exactly `review-only`; source records cannot enable matching. |
| `operation` | `replace` or `remove`, scoped to exactly one subject. |
| `subject.purl` | Canonical, versioned conda-forge PURL; requires `build` and `subdir`, no fragment. |
| `subject.sha256` | Digest of exact conda archive bytes. Coordinates alone do not establish byte identity. |
| `review` | Nonempty reviewer and timezone-aware timestamp; compared as UTC instants. This is repository attribution, not a cryptographic signature. |
| `rationale` | Nonempty explanation, including why relationships are withdrawn when applicable. |
| `relationships` | Complete reviewed list for replacement, empty for removal. Order has no semantic significance. |
| `relationship` | `derived_from`: uses a particular upstream artifact as an input. `contains`: payload includes the named component/project. Neither means all files or versions are identical. |
| `upstream.purl` | Canonical PURL; ecosystem-specific version/qualifiers remain intact. No automatic cross-namespace or mirror equivalence. |
| `upstream.sha256` | Required for `derived_from`; a non-null digest requires a versioned PURL. May be null for `contains` when only project/component identity is established. |
| `evidence` | Local path relative to `mappings/relationship_evidence/` and digest of exact JSON bytes. Subject and claim must match that evidence. |

No implicit conda-to-upstream version substitution. A versionless `contains`
project has no asserted version/commit mapping. Unknown applicability remains
unknown. Changing any evidence byte requires a new digest and reviewed record.

### Replacement, removal and conflicts

1. Validate **every** historical record and evidence reference, even if a later
   record supersedes or removes it. Do not delete or rewrite historical evidence.
2. Key the review stream by **(canonical subject PURL, SHA256)**. Both are required
   for an exact match. Different archive formats can legitimately share conda
   coordinates (for example `.conda` and `.tar.bz2`) while having different bytes.
   They are separate subjects, never implicit aliases. An unknown or mismatched
   digest has no relationship, even if its PURL matches a reviewed subject.
3. Order by UTC review instant, then filename. Same-instant differing decisions
   fail closed. Identical decisions (including reviewer/rationale/evidence), with
   relationship ordering and timezone spelling normalized, use the filename tie
   breaker only for deterministic attribution.
4. `replace` replaces the **entire list**; it is not a union. Adding a component
   requires a new complete reviewed list with evidence for every retained claim.
5. `remove` requires an empty list. Replay retains the removal record as an
   explicit tombstone with subject, attribution and rationale. It is not silently
   discarded, nor does it restore an older list. A later reviewed replacement
   can restore relationships for the same exact artifact.
6. Relationship keys are `(relationship, canonical upstream PURL, SHA256-or-null)`;
   duplicates fail. Multiple upstream artifacts (e.g. a wheel and source archive)
   can share a versioned PURL but differ in bytes: neither relationship substitutes
   for the other. Self-relationships to the subject artifact fail.
7. No wildcard name/version/build/checksum matching. Another build/subdir/archive
   has no inherited relationship, and removing one subject does not affect another.

The source replay function exposes tombstones for a future publication/consumer
contract. That future contract must preserve explicit removals and invalidate
any dependent results; no runtime invalidation is implemented here.

## Typed evidence, separate from relationships

Files under `mappings/relationship_evidence/` use a common binding envelope:

```json
{
  "schema_version": 1,
  "kind": "reviewed-provenance",
  "subject": {
    "purl": "pkg:conda/conda-forge/example@1.0?build=abc_0&subdir=linux-64",
    "sha256": "<exact conda artifact digest>"
  },
  "claims": [
    {
      "relationship": "derived_from",
      "upstream": {
        "purl": "pkg:pypi/example@1.0",
        "sha256": "<exact upstream artifact digest>"
      }
    }
  ],
  "details": {
    "references": [
      {"url": "https://example.org/immutable-source", "description": "Explain what this reference establishes."}
    ],
    "notes": "Scope, method and unresolved limitations."
  }
}
```

- `reviewed-provenance` is ecosystem-neutral review evidence. References and
  explanation are required; it does **not** claim automatic byte verification.
  Prefer immutable, authoritative references. Syntax validation cannot prove
  their contents or factual correctness.
- `rpm-payload-comparison` carries the libxml2 pilot's RPM headers, archive URLs,
  embedded recipe digests, contained-project evidence and complete relocation
  manifest in `details`. Only this adapter requires RPM-specific fields.
- Unknown evidence kinds fail until an explicit validator is added. Supporting
  a new upstream PURL type with generic review evidence does not require adding
  an RPM adapter, or enabling any vulnerability evaluator.
- Evidence subject PURL/digest and each referenced claim must match exactly.
  Digest checks bind record bytes, not the truth of their claims. Duplicate JSON
  keys, non-finite numbers, escaping paths/symlinks and missing references fail.
  Unreferenced evidence is allowed during review but is still validated.

## Libxml2 fixture and real artifact verification

The real record is:

`mappings/artifact_relationships/2026-09-24T08-07-52Z--nichmor--libxml2.json`

Its claims are:

- Subject: `pkg:conda/conda-forge/libxml2-cos7-x86_64@2.9.1?build=ha675448_1106&subdir=noarch`
- Derived from: `pkg:rpm/centos/libxml2@2.9.1-6.el7.5?arch=x86_64&distro=centos-7.9.2009`
- Contains: `pkg:git/gitlab.gnome.org/GNOME/libxml2` (versionless project identity)

Detailed CPE `cpe:2.3:a:xmlsoft:libxml2` and reported upstream version `2.9.1`
remain review context in the typed evidence, not active matcher inputs. The
RPM release is preserved, not replaced with conda's shorter version. The conda
artifact is `noarch`, but its binary payload targets x86_64. No epoch tag is
present in the RPM: recorded as null, not an invented zero.

All eleven regular payload files and one symlink target match the CentOS RPM
byte-for-byte after prefix relocation. Embedded recipe/build-script digests and
an immutable matching cdt-builds recipe are retained; the artifact does not attest
that recipe's Git commit. This does not prove unpatched upstream equivalence,
source-commit mapping or affected-version applicability.

Validate source records and evidence digests offline:

```sh
pixi run -e lite mappings:validate-relationships
```

This also runs from `mappings:validate`. It does not fetch or check archive bytes.
To reproduce the stronger RPM check, download the two exact `artifact.url` values
in the RPM evidence's `details` into local files, then run:

```sh
uv run --no-project --with rpmfile==2.2.1 --with packageurl-python==0.17.6 \
  python -m scripts.rpm_component_evidence \
  --verify mappings/relationship_evidence/libxml2-cos7-x86_64-2.9.1-ha675448_1106.json \
  --conda-artifact /path/to/libxml2-conda.tar.bz2 \
  --rpm-artifact /path/to/libxml2.rpm
```

`uv` obtains isolated dependencies; the verifier itself makes no network requests,
extracts no files onto disk and executes no package code. Checksums, conda index,
RPM header, embedded recipes, complete payload coverage and bytes/link targets
must agree. This adapter currently handles only single-RPM prefix relocation;
other transformations require their own evidence validation.

## Follow-up PR boundaries

1. **This PR:** generic source contract, replay, evidence validation and real fixture.
2. **Publication:** version public payloads, publish relationships and referenced
   evidence, update readers; retain all existing primary/alternative/CPE semantics.
3. **Basilisk ingestion:** store exact-artifact relationships generically, resolve
   artifacts safely, retain pending subjects and removals.
4. **Evaluation:** add explicit ecosystem/distro adapters and applicability tests.

Until those gates pass, readiness counts and the CDT no-primary-PURL disposition
remain unchanged. No vulnerability data, CVE verdicts, or automatic coverage gains
are introduced by this contract.
