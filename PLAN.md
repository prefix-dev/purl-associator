# Simplify to PURL + CPE Mapping Plan

## Context

The repository currently maintains PURL mappings for conda-forge packages and also derives/serves CVE, AI review, VEX contribution, and SBOM-derived CVE data. The target direction is to keep this project focused on canonical package identity mapping data, while moving CVE assignment/review workflows into a separate downstream project. CPE mapping should remain in scope because downstream CVE mapping can consume both PURL and CPE mappings from here.

Initial scan:
- `README.md` describes PURL, CVE, AI review, VEX, and SBOM flows.
- `pixi.toml` exposes PURL tasks plus many CVE/SBOM/AI/CPE tasks.
- `mappings/` contains PURL inputs (`auto.json`, `manual.json`, `contributions/`) plus CVE, AI, SBOM, and CPE folders.
- Existing CPE scripts are present: `scripts/cpe_discover.py`, `scripts/cpe_vet.py`, `scripts/cpe_promote.py`, `scripts/nvd_fetch.py`, and `scripts/nvd_prototype.py`.

## Approach

Preserve the repository as the canonical conda-forge package identity mapping source. The central object should be a **conda-forge package identity record**: one conda package identity with curated identifiers for upstream/security ecosystems.

Recommended abstraction:
- **Subject:** conda-forge package name (currently `packages[<name>]`). This is what the UI, contributions, automap, and CPE discovery all key by.
- **Conda package metadata:** keep non-authoritative package context already present in `auto.json`/merged payloads (`version`, `build`, `subdir`, recipe/source URLs, summary, download count). This helps reviewers and downstream tools, but should not be treated as the complete version universe for CVE matching.
- **PURL identities:** primary `purl` plus `alternative_purls`, representing source/package ecosystem identities. These remain editable in the web UI.
- **CPE identities:** `cpes: string[]`, representing versionless CPE 2.3 vendor/product prefixes for the same upstream software where PURLs are insufficient for downstream CVE matching. CPEs should stay on the canonical mapping record and be visible read-only in the frontend; the web UI remains for PURL editing only.
- **Version information for CVE matching:** this repo should not store affected CVE ranges or per-CVE version decisions. The downstream CVE project should combine these identity mappings with its own conda-forge version enumeration and OSV/NVD affected-version logic. If the downstream project needs more identity-level version context later, add it as mapping metadata deliberately (for example a reviewed CPE version qualifier), not as CVE assignment data.
- **Out of scope:** actual CVE assignment state, OpenVEX reviews, AI CVE queues/drafts, and SBOM-derived CVE findings. Those should move to the downstream project.

Implementation direction:
- Keep `mappings/auto.json`, `mappings/manual.json`, `mappings/contributions/`, generated `web/public/mappings*.json`, the PURL UI, and Worker `POST /api/submit`.
- Update the frontend so it is PURL-mapping-only: remove CVE/deep-inspection pages and navigation, keep the PURL editor/table, and surface CPEs as part of each package identity record.
- Keep the existing CPE discovery/vet/promote pipeline, because it already writes CPEs as normal mapping contributions consumed by `scripts.merge_mappings`.
- Rename scripts/tasks/workflows where useful so names match the new identity-mapping scope instead of the old CVE-centric scope.
- Remove CVE/SBOM/AI-review scripts, schemas, workflows, web pages/components/data loaders, worker endpoints, generated public CVE/SBOM files, and committed historical data directories.
- Simplify validation to mapping-only checks.
- Rewrite `README.md` around the new identity-mapping model, including PURL flow, CPE flow, frontend behavior, task names, outputs, and downstream CVE-consumption expectations.

## Files to modify

Critical retained/simplified files:
- `README.md` — full rewrite around PURL + CPE identity mapping only, including the public data contract and downstream CVE handoff.
- `pixi.toml` — remove CVE/SBOM/AI tasks and dependencies that are only used by removed scripts; audit all task names and rename any that no longer describe the new scope. Keep/possibly rename automap, merge, validate, download counts, and CPE tasks.
- `scripts/validate.py` — strip CVE/OpenVEX/AI queue/schema validation; keep mapping split payload and reviewed `alternative_purls` invariant checks; add CPE format validation for `cpes` arrays.
- `scripts/*` — remove obsolete CVE/SBOM/AI scripts, including `scripts/nvd_prototype.py` because downstream owns actual NVD/CVE matching; rename retained CPE/PURL helper scripts if needed for clarity.
- `.github/workflows/pages.yml` — generate/validate only mapping payloads before building web.
- `.github/workflows/automap.yml`, `.github/workflows/cpe_discover.yml`, `.github/workflows/download_counts.yml` — keep/update only if they support PURL/CPE mapping; rename workflow labels/files if needed; remove CVE/SBOM/AI review workflows.
- `web/vite.config.ts`, `web/*.html`, `web/src/**` — remove CVE dashboard and deep inspection pages/routes/imports; keep `App.tsx`, PURL editor/table, mapping data loaders, auth, PR drawer; add/update frontend presentation for CPE identity data.
- `worker/src/index.ts`, `worker/wrangler.toml` — keep `/exchange` and `/api/submit`; remove `/api/submit-cves`, `/api/enqueue-cve-review`, and CVE-related env vars/types/helpers.
- `.gitignore` — remove obsolete CVE/SBOM generated paths; keep mapping generated paths and NVD cache if CPE discovery remains.

Data/directories to retain:
- `mappings/auto.json`
- `mappings/manual.json`
- `mappings/contributions/`
- `mappings/cpe_candidates/`
- `mappings/cpe_vet/`
- `web/public/mappings-index.json`
- `web/public/mapping_packages/`

Data/directories to remove:
- `mappings/cves/`
- `mappings/cve_contributions/`
- `mappings/cve_review_queue/`
- `mappings/cve_ai_drafts/`
- `mappings/sboms/`
- `mappings/sboms.json`
- `mappings/sbom_cves/`
- `mappings/sbom_inspections.json`
- `web/public/cves-index.json`, `web/public/cve_ai_drafts.json`, `web/public/cve_ai_queue.json`, `web/public/cve_packages/`, and any generated SBOM public files.

## Reuse

Existing code to reuse:
- PURL inference/automation: `scripts.automap`, `scripts.purl_inference`, `scripts.parselmouth_lookup`, `scripts.automap_summary`.
- PURL/CPE merge/public data contract: `scripts.merge_mappings`; it already includes `cpes` in `REVIEWED_MAPPING_FIELDS` and emits `cpes` into the index/detail payloads. Consider renaming this task/script or at least documenting that it merges identity mappings, not only PURLs.
- PURL frontend: `web/src/App.tsx`, `web/src/components/MappingEditor.tsx`, `PackageTable.tsx`, `PRDrawer.tsx`, `web/src/data/useMappingsData.ts`, `web/src/github/api.ts`.
- CPE discovery and promotion: `scripts.cpe_discover`, `scripts.cpe_vet`, `scripts.cpe_promote`, `scripts.cpe_summary`, `scripts.nvd_fetch`.
- CPE display primitives: `web/src/components/Primitives.tsx` (`CpeChip`) and existing `cpes` fields in `web/src/data/types.ts`.

Notable finding:
- CPE mappings are already modeled as package identity metadata on the same mapping record (`cpes` in `manual.json`/contributions → `merge_mappings` → web payload). This supports the “conda-forge package identity record” abstraction without inventing a separate CPE data model.

## Steps

- [x] Remove CVE/SBOM/AI data directories and generated public files from the repo.
- [x] Delete or de-register CVE/SBOM/AI scripts from `pixi.toml`; remove unused schemas.
- [x] Audit and update task names in `pixi.toml` so retained commands read as identity/PURL/CPE mapping tasks. Renamed retained commands into namespaces such as `mappings:merge`, `purl:automap`, `cpe:discover`, `web:dev`, and `worker:typecheck`.
- [x] Simplify `scripts.validate` to validate only mapping payload consistency and CPE string shape.
- [x] Update `pages.yml` to run only mapping merge + mapping-only validate before web build, using any renamed task names.
- [x] Remove CVE/SBOM workflows (`cve_refresh.yml`, `cve_ai_review.yml`, `cve_sidecars.yml`, `sbom_refresh.yml`) and keep/update/rename CPE discovery workflow.
- [x] Simplify Worker env/types/routes to PURL edit PRs only.
- [x] Remove web multipage CVE/deep inspection entries and all CVE/SBOM-specific source files/components/imports.
- [x] Update the frontend to make the new abstraction clear: PURL editing remains primary, CPEs appear as package identity metadata, and no CVE/deep-inspection navigation or loaders remain.
- [x] Show CPEs read-only in the PURL UI and keep PURL edit submission payloads unchanged except for removing stale CVE/deep-inspection references.
- [x] Rewrite `README.md` to document the identity mapping model, PURL flow, CPE flow, task names, outputs, frontend behavior, downstream CVE consumption, and verification commands.

## Verification

Planned checks after implementation:
- `pixi run -e lite mappings:merge`
- `pixi run -e lite mappings:validate`
- `pixi run purl:test`
- `pixi run cpe:promote --dry-run` using an existing/new candidate file
- `cd web && npm run build`
- `cd worker && npm run build` or `npm run typecheck` if available
- Manual web check: PURL mapping UI loads, filters/search work, edits can open `/api/submit` PR payloads, no links to CVE/deep pages remain.

## Decisions captured

- The core abstraction is a conda-forge package identity record keyed by package name.
- Latest package metadata (`version`, `build`, `subdir`, etc.) stays as reviewer/downstream context, but complete version enumeration and CVE affected-version logic move downstream.
- The frontend remains a PURL editing UI only; CPEs are surfaced read-only as identity metadata.
- `scripts.nvd_prototype.py` should be removed with the CVE matching code; retained NVD code is only for CPE discovery.
