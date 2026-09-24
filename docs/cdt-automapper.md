# Bounded CDT automapper

This tool generates **reviewable candidates**, not approved mappings. Its purpose
is to automate the tedious evidence collection for multiple exact CDT artifacts
before finalizing the broader relationship contract in PR #320. It is independent
of that PR and does not introduce a second public mapping schema.

## Run it

The dedicated `cdt` Pixi environment contains packageurl-python, PyYAML and pinned
`rpmfile==2.2.1`. Ordinary mapping validation still uses the lite environment.

```sh
pixi run -e cdt cdt:automap \
  --only libxml2-cos7-x86_64,expat-cos7-x86_64,libxau-cos7-x86_64 \
  --cache /tmp/cdt-cache \
  --output /tmp/cdt-review-first
```

Or investigate the 25 highest-download CDT discovery hints:

```sh
pixi run -e cdt cdt:automap --limit 25 --output /tmp/cdt-top25
```

- `--input` defaults to `mappings/auto.json`. Selects its exact recorded artifact
  for each package, **not every historical version/build/platform** and not a
  freshly inferred latest version.
- Exactly one of `--only` and `--limit` is required; batches are capped at 100.
- Automatic queue selection uses `(CDT)` summaries/CentOS vault URL hints and
  download counts. Those are discovery hints only, never relationship evidence.
- No hand-written RPM PURL, prefix, manifest, reviewer identity or evidence JSON
  is needed. These are derived from archive data; approval remains separate.
- The output directory must not already exist. A failed retry cannot leave an old
  successful candidate looking current. Use a new output directory for every run.
- Candidate/cache paths inside this checkout's `mappings/` or `web/public/` are
  rejected. Nothing invokes the active mapping merge or promotion pipelines.

### Scheduled and manual GitHub Actions runs

`.github/workflows/cdt_automap.yml` runs weekly on Thursday at **08:37 UTC**, with
10 highest-download CDT hints by default. This is after the usual mapper refresh
window, **not a dependency on that run or its PR merging**: it uses only the
committed `mappings/auto.json` snapshot at checkout. The schedule activates after
the workflow lands on the default branch.

Use **Actions → Generate CDT review drafts → Run workflow**, or:

```sh
gh workflow run cdt_automap.yml --ref main -f limit=10
# Explicit names override limit; no shell expressions are evaluated.
gh workflow run cdt_automap.yml --ref main \
  -f only=libxml2-cos7-x86_64,expat-cos7-x86_64
```

Both modes retain the 100-package cap. Jobs have a 45-minute timeout and read-only
repository permissions; they do not commit files, create PRs, promote candidates,
or run the normal mapping publisher. No bot token or additional secret is needed.

Each run uploads a **`cdt-review-<run-id>-<attempt>`** artifact, retained for 30 days:

- Exact selected input snapshot, source revision and source-file hash.
- Generated drafts and the batch report, including deferrals/errors.
- Captured API response bytes referenced by successful candidates.
- A readable summary, also shown in the Actions run summary.

Unexpected package errors still fail the job. Summary/upload steps use `always()`
so available partial/error material is retained when those steps can run. A hard
runner termination or timeout can prevent uploading; missing reports are explicitly
marked incomplete, never presented as a successful empty batch.

Each run uses a fresh temporary data cache so API metadata is not silently carried
across scheduled runs. Only Pixi dependencies are cached between runs. Downloaded
conda/RPM archives are **not** uploaded. These artifacts are review material, not
accepted contributions for the current mapping editor. Review/promotion and public
relationship distribution remain separate integration work.

### Offline replay

```sh
pixi run -e cdt cdt:automap \
  --only libxml2-cos7-x86_64,expat-cos7-x86_64,libxau-cos7-x86_64 \
  --cache /tmp/cdt-cache --offline --output /tmp/cdt-review-replay
```

The cache contains both release metadata and pinned archives. All required URLs
must already be cached; there is no network fallback in offline mode. Archive
checksums are rechecked before parsing. Identical selected inputs and cache bytes
produce identical JSON, without volatile generation timestamps.

Metadata is a cached snapshot, not a promise of freshness. Use a fresh cache to
refresh remote metadata; remove a corrupt entry to retry its download. Keep the
cache with a review if you need to reproduce the captured API response digest.
New upstream metadata can change evidence hashes even when package bytes match.

## Evidence pipeline

1. Require an exact conda-forge `.tar.bz2` URL corresponding to the selected
   name/version/build/subdir. No nearest-build substitution or format conversion.
2. Resolve that exact file in Anaconda release metadata and require SHA256.
   Optional `sha256` in the selected input is also enforced. **No MD5 fallback.**
3. Download/cache and check the conda archive digest before parsing. Read the
   real archive payload, index and embedded rendered `info/recipe/meta.yaml`.
   Missing `info/files` does not imply an empty payload; neither it nor
   `info/paths.json` is used as a substitute for actual archive entries.
4. Require matching embedded package coordinates and exactly one source URL with
   a pinned RPM SHA256. Reject templates, selectors, YAML duplicates/aliases,
   multi-source and multi-output recipes. Never evaluate Jinja or build scripts.
5. Accept only explicit CentOS 6/7 vault OS/update URLs, including `altarch`.
   Historical `http://vault.centos.org/` is upgraded to HTTPS. Other HTTP origins,
   credentials, query strings and cross-origin redirects are refused.
6. Download/check the exact RPM before parsing. Require CentOS vendor, consistent
   filename, architecture and release major. Preserve native name, version,
   release, epoch (null when absent), architecture, vendor and source-RPM filename.
   RPM epoch zero is retained when explicitly present, not invented when absent.
7. Require **all non-directory payload entries on both sides** to agree after
   removal of a single sysroot prefix. Compare path sets, file kinds, bytes and
   symlink target bytes. Different paths, changed symlinks, partial copies or
   additional components defer the package; there is no fuzzy content matching.
8. Generate an exact `derived_from` RPM PURL and evidence. The conda subdir and
   native RPM architecture remain separate (e.g. conda `noarch`, RPM `x86_64`).

Embedded recipes are bound by the conda archive digest and their own digests.
No guessed feedstock URL or build-commit attestation is added. The existing
flattened `source_url` may be wrong for multi-output packages; it is never used
as the asserted RPM source.

## Outputs and review

`report.json` records every selected package with one of:

- `candidate-needs-review`: exact relationship draft with complete comparison.
- `deferred`: a known unsupported/ambiguous case, with a reason code and detail.
- `error`: unexpected parser, transport or filesystem failure. Other packages
  continue, but the overall command exits nonzero. Fix/retry rather than treating
  errors as intentional no-identity decisions.

Each successful draft includes:

- exact conda PURL, archive URL and SHA256;
- exact native RPM PURL, archive URL and SHA256;
- the source metadata URL/hash and selected distribution;
- embedded recipe/index/build-script contents and hashes (build script when present);
- native RPM header and full prefix-relocation payload manifest;
- generator/version, candidate status and explicit limitations.

Draft filenames identify the subject using SHA256 of canonical conda PURL,
a newline and archive SHA256. They are not a hash of the draft contents. Distinct
archives at the same coordinates remain separate; neither inherits the other's
proof. Evidence is currently inline to make drafts convenient to inspect; its
reviewed/public representation belongs to the subsequent contract/publication work.

A reviewer must inspect the provenance, scope and any unresolved limitations.
The tool does **not** invent reviewer attribution, automatically approve drafts,
create contributions, infer a `contains` upstream project/CPE, or assign CVEs.
Do not paste its RPM PURL into a package-wide primary/alternative mapping field.
There is no exporter into #320's reviewed contract yet: its shape should follow
these multi-package results rather than require manual reconstruction first.

CentOS identity is not automatic Red Hat advisory equivalence. Distro-aware
vulnerability applicability and RPM version/backport evaluation remain Basilisk
work, outside this automapper.

## Bounded scope and safety

Supported: single RPM, complete newc CPIO payload, gzip/xz/bzip2 RPM compression,
regular files/symlinks and sysroot prefix relocation. No package extraction onto
disk, shell execution, Jinja execution, RPM installation or maintainer-script
execution occurs.

Known deferrals include `.conda` archives, missing SHA256, empty payloads,
multi-source/multi-output recipes, non-vault distributions, RPM hardlinks/devices,
unknown compression/CPIO types, altered files/links and partial or mixed payloads.
This deliberately favors fewer defensible drafts over guessed relationships.

Network requests are restricted to `conda.anaconda.org`, `api.anaconda.org` and
`vault.centos.org`, over HTTPS, with 30-second socket timeouts. Checks include
128 MiB artifact downloads, 8 MiB release metadata, 1 MiB recipe/index reads,
256 MiB expanded-payload limits and 20,000 members per archive. CPIO is read in
bounded chunks so native file types/hardlink markers are retained; rpmfile's
member convenience API discards those details. These are defensive limits,
not a sandbox for arbitrary untrusted archives or a total wall-clock deadline.
RPM signatures and installed filesystem metadata equivalence are not verified.

## Reproduced multi-package sample

`examples/cdt-automap-sample.json` pins thirteen exact artifacts from mapper
snapshot `cbf905c5`. Run all named entries without editing their structures:

```sh
names=$(pixi run -e cdt python -c \
  'import json; print(",".join(json.load(open("examples/cdt-automap-sample.json"))["packages"]))')
pixi run -e cdt cdt:automap --input examples/cdt-automap-sample.json \
  --only "$names" --cache /tmp/cdt-cache --output /tmp/cdt-sample
```

Observed result: **6 candidates, 7 deferrals, no errors**. This is a selected
pilot, not a measured success rate across all 1,110 deferred CDTs.

| Exact package output | Payload entries | Result |
|---|---:|---|
| `libxml2-cos7-x86_64` | 12 | Candidate; complete comparison |
| `expat-cos7-x86_64` | 6 | Candidate; complete comparison |
| `libxau-cos7-x86_64` | 6 | Candidate; complete comparison |
| `libxi-cos7-x86_64` | 3 | Candidate; complete comparison |
| `libx11-cos7-aarch64` | 4 | Candidate; complete comparison |
| `pixman-cos7-aarch64` | 2 | Candidate; complete comparison |
| `libdrm-cos7-x86_64` | 15 | Deferred: payload path sets differ |
| `mesa-libgl-cos7-x86_64` | 3 | Deferred: `libGLX_system.so.0` differs |
| `alsa-lib-cos7-x86_64` | 89 | Deferred: payload path sets differ |
| `alsa-lib-cos6-x86_64` | — | Deferred: release metadata lacks SHA256 |
| `kernel-headers_linux-64` | — | Deferred: `.conda` format |
| `sysroot_linux-64` | — | Deferred: `.conda` format |
| `_sysroot_linux-64_curr_repodata_hack` | — | Deferred: `.conda` format |

The last three are stopped before payload analysis: their classifications are
not inferred from these deferrals. Synthetic tests independently cover empty and
mixed-source payloads. The actual sample is manually exercised with downloads;
CI runs deterministic offline synthetic fixtures, not external CentOS services.

Run those tests locally:

```sh
pixi run -e cdt python -m unittest tests.test_cdt_automap -v
```

No active identity or readiness count changes until evidence is separately
reviewed, published and consumed. The automapper simply makes gathering that
review material practical for multiple packages.
