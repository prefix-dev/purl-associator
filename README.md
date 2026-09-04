# PURL Associator

This repository maintains canonical **conda-forge package identity mappings**.
Each mapping record is keyed by conda-forge package name and carries identifiers
that downstream security tooling can use:

- a primary Package URL (**PURL**) and optional alternative PURLs
- optional CPE 2.3 vendor/product prefixes for NVD matching
- package context such as latest observed version, recipe/source URLs, summary,
  and download counts

CVE assignment, OpenVEX review state, AI CVE drafts, and SBOM-derived findings
are intentionally out of scope. A downstream CVE project should consume the
identity mapping payload produced here, enumerate conda-forge versions there,
and join those versions with OSV/NVD affected-version data there.

## Data model

The core object is a conda-forge package identity record:

```json
{
  "name": "ncurses",
  "version": "6.5",
  "purl": "pkg:github/ThomasDickey/ncurses-snapshots",
  "type": "github",
  "namespace": "ThomasDickey",
  "pkg_name": "ncurses-snapshots",
  "alternative_purls": [],
  "cpes": [
    "cpe:2.3:a:gnu:ncurses",
    "cpe:2.3:a:invisible-island:ncurses"
  ],
  "status": "verified",
  "identities": [
    {
      "kind": "purl",
      "role": "primary",
      "value": "pkg:github/ThomasDickey/ncurses-snapshots",
      "provenance": {
        "availability": "available",
        "source": "manual",
        "review": {
          "status": "verified",
          "reviewer": "nichmor",
          "reviewed_at": "2026-05-25T00:00:00Z"
        }
      }
    },
    {
      "kind": "cpe",
      "role": "associated",
      "value": "cpe:2.3:a:gnu:ncurses",
      "provenance": {
        "availability": "available",
        "source": "manual",
        "review": {
          "status": "verified",
          "reviewer": "nichmor",
          "reviewed_at": "2026-05-25T00:00:00Z"
        }
      }
    },
    {
      "kind": "cpe",
      "role": "associated",
      "value": "cpe:2.3:a:invisible-island:ncurses",
      "provenance": {
        "availability": "available",
        "source": "manual",
        "review": {
          "status": "verified",
          "reviewer": "nichmor",
          "reviewed_at": "2026-05-25T00:00:00Z"
        }
      }
    }
  ]
}
```

PURLs identify source/package ecosystem coordinates. CPEs identify NVD
vendor/product coordinates. CPE strings stored here are identity-level prefixes;
this repository does not store CVE affected ranges or per-CVE version decisions.

### Published identity provenance contract

The generated payload's `identities` array is the authoritative per-identity
view for downstream consumers:

- `kind: "purl", role: "primary"` identifies the primary PURL. Its provenance
  contains a required review `status`, a nullable `reviewer`, and an optional
  `reviewed_at`. Automatic primary identities additionally retain their
  available confidence and source evidence.
- `kind: "purl", role: "alternative"` identifies an alternative PURL. Detailed
  alternatives retain their own `source` and `confidence`; bare string
  alternatives use `availability: "unavailable"`. They never inherit the
  primary PURL's review object.
- `kind: "cpe", role: "associated"` identifies a CPE prefix. Its provenance
  identifies the automatic or reviewed source layer that last replaced the
  package's CPE list, including that layer's review state and attribution.

Identity order is deterministic: primary PURL, alternatives in source order,
then CPEs in source order. A missing primary PURL produces no primary identity.

Coverage is identity-based. A package has no identity only when `identities` is
empty; a missing primary PURL can still leave alternative PURLs or CPEs. The
legacy `unmapped` field records an intentional no-PURL decision, not the absence
of every identity.
Every published confidence is a finite JSON number; `NaN` and infinities are
rejected. Contribution precedence compares timezone-aware timestamps as UTC
instants, with the on-disk filename as the deterministic tie-breaker.

## Sources and outputs

| Path | Purpose |
|---|---|
| `mappings/auto.json` | automatically inferred PURL mappings |
| `mappings/manual.json` | legacy/manual reviewed overrides |
| `mappings/contributions/*.json` | PR-submitted mapping contributions, including CPE pipeline output |
| `mappings/cpe_candidates/*.json` | audit output from CPE discovery |
| `mappings/cpe_vet/*.json` | optional AI tiebreaker output for ambiguous CPE candidates |
| `web/public/mappings.json` | generated full mapping bundle |
| `web/public/mappings-index.json` | generated compact index for the web app |
| `web/public/mapping_packages/*.json` | generated sharded package detail payloads |

### Payload versions and compatibility

PFX-1826 introduced `identities` in bundle schema 2, index schema 3, and detail
schema 2. CPE provenance advances those payloads to bundle schema **3**, index
schema **4**, and detail schema **3**. Legacy `purl`, `alternative_purls`,
`cpes`, `status`, and attribution fields remain unchanged. New clients should
reject unknown future schema versions rather than guessing. The validator and
web decoder accept the earlier payload generations but require attributed CPE
provenance on current schemas.

The payload deployed by the Pages workflow is canonical. The checked-in
`mappings-index.json` and shard files are build inputs/cache for the app, not a
supported raw-consumer contract on their own: a source change can leave them
stale until `mappings:merge` regenerates the bundle, index, and all shards
atomically. Consumers should use the deployed Pages payload rather than mixing
checked-in generations. Routine changes should not commit the 257-file shard
churn unless repository policy explicitly requires an atomic generated-data
refresh.

## PURL flow

```mermaid
flowchart TD
  A[conda-forge metadata] --> B[scripts.automap]
  B --> C[mappings/auto.json]
  C --> D[scripts.merge_mappings]
  E[mappings/manual.json] --> D
  F[mappings/contributions/*.json] --> D
  D --> G[web/public/mappings*.json]
  G --> H[PURL editing UI]
  H --> I[Worker POST /api/submit]
  I --> F
```

Useful commands:

```sh
pixi run purl:automap --only numpy,ripgrep,pandas
pixi run -e lite mappings:merge
pixi run -e lite mappings:validate
pixi run purl:test
```

## CPE flow

CPE discovery is part of identity mapping, not CVE assignment. The retained CPE
pipeline proposes NVD vendor/product prefixes and promotes accepted mappings as
normal contribution files. Those CPEs then flow through `scripts.merge_mappings`
into the public mapping payload.

CPE list behavior is intentionally unchanged: a contribution containing `cpes`
replaces the prior list. Changing that to union semantics could make explicit
UI/pipeline removals impossible, so PFX-1826 does not silently change it. A
separate follow-up should decide whether CPE contributions need an explicit
replace/union operation before any union behavior is introduced.

```mermaid
flowchart TD
  A[mappings/auto.json + reviewed mappings] --> B[scripts.cpe_discover]
  B --> C[mappings/cpe_candidates/*.json]
  C --> D[scripts.cpe_vet optional]
  D --> E[mappings/cpe_vet/*.json]
  C --> F[scripts.cpe_promote]
  E --> F
  F --> G[mappings/contributions/*--cpe-pipeline--*.json]
  G --> H[scripts.merge_mappings]
```

Useful commands:

```sh
pixi run cpe:discover --top 50
pixi run cpe:vet --dry-run
pixi run cpe:promote --dry-run
pixi run -e lite mappings:merge
pixi run -e lite mappings:validate
```

## Frontend behavior

The GitHub Pages app is a PURL editing UI:

- users can review, edit, approve, or mark PURL mappings as unmapped
- staged identity edits are saved locally until submitted
- submitted edits open PRs containing one new file under `mappings/contributions/`
- CPEs can be reviewed and edited alongside PURL mappings
- no CVE dashboard, OpenVEX review, AI CVE queue, or deep-inspection routes are
  served from this repository

The Worker exposes only:

- `POST /exchange` for GitHub OAuth code exchange
- `POST /api/submit` for PURL mapping contribution PRs

## Downstream CVE consumption

A downstream CVE project should consume `web/public/mappings.json` or the split
`mappings-index.json` + `mapping_packages/*.json` payload. It should then:

1. enumerate conda-forge package versions independently,
2. use PURLs for OSV/package-ecosystem matching,
3. use CPE prefixes for NVD matching,
4. apply OSV/NVD affected-version logic in that downstream project, and
5. store CVE assignment/review state outside this repository.

## Verification

Run these checks before opening a PR:

```sh
pixi run -e lite mappings:merge
pixi run -e lite mappings:test
pixi run -e lite mappings:validate
pixi run app:check
```

For frontend/Worker-only checks:

```sh
cd web && npm run build
cd worker && npm run typecheck
```
