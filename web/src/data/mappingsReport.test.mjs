import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer } from "vite";

let server;
let reports;

before(async () => {
  server = await createServer({
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
    logLevel: "error",
  });
  reports = await server.ssrLoadModule("/src/data/mappingsReport.ts");
});

after(async () => {
  await server?.close();
});

function missing(fields = {}) {
  return {
    name: "missing",
    state: "unresolved",
    diagnostic_reason: "no_parseable_source_host",
    unmapped_reason: null,
    source_hosts: [],
    version: "1.0",
    source_url: null,
    repo: null,
    homepage: null,
    note: null,
    download_count: 10,
    ...fields,
  };
}

function report() {
  return {
    schema_version: 2,
    input_schema_version: 4,
    channel: "conda-forge",
    counts: {
      total: 3,
      primary_present: 1,
      explicitly_unmapped: 1,
      classified_unmapped: 1,
      legacy_unmapped: 0,
      unresolved: 1,
      actionable_missing: 1,
      primary_missing: 2,
    },
    classified_by_reason: {
      conda_cdt_repackage: 0,
      dependency_only_metapackage: 0,
      toolchain_selector: 0,
      environment_mutex: 1,
      pinning_metadata: 0,
      compatibility_shim: 0,
    },
    unresolved_by_diagnostic: {
      recorded_processing_error: 0,
      alternative_only: 0,
      no_parseable_source_host: 1,
      no_primary_from_url_evidence: 0,
    },
    unresolved_by_source_host: [],
    missing_packages: [
      missing(),
      missing({
        name: "rejected",
        state: "explicitly_unmapped",
        diagnostic_reason: null,
        unmapped_reason: {
          code: "environment_mutex",
          explanation: "A test mutex.",
          rule_id: "environment-mutex-v1",
          evidence: { summary: "A mutex package" },
          review: {
            status: "verified",
            reviewer: "reviewer",
            reviewed_at: "2026-09-15T00:00:00Z",
          },
        },
        download_count: null,
      }),
    ],
  };
}

test("derives review cohorts without changing stored mapping states", () => {
  const decoded = reports.decodeMappingsReport(report());
  const packaging = decoded.missing_packages[1];
  const cdt = { ...packaging, name: "cdt", download_count: 123, unmapped_reason: { ...packaging.unmapped_reason, code: "conda_cdt_repackage" } };
  const legacy = { ...packaging, name: "legacy", unmapped_reason: null, download_count: 0 };
  const rows = [...decoded.missing_packages, cdt, legacy];
  const before = structuredClone(rows);
  const groups = reports.summarizeDispositions(rows);
  assert.deepEqual(groups.map(({ key, packages, knownDownloads, unknownDownloadPackages }) =>
    [key, packages, knownDownloads, unknownDownloadPackages]), [
    ["packaging_only", 1, 0, 1], ["cdt_deferred", 1, 123, 0], ["legacy_review", 1, 0, 0],
  ]);
  for (const [filter, names] of [
    ["all", ["missing", "rejected", "cdt", "legacy"]],
    ["unresolved", ["missing"]],
    ["explicitly_unmapped", ["rejected", "cdt", "legacy"]],
    ["packaging_only", ["rejected"]], ["cdt_deferred", ["cdt"]], ["legacy_review", ["legacy"]],
  ]) {
    assert.deepEqual(rows.filter((row) => reports.matchesCoverageFilter(row, filter)).map((row) => row.name), names);
  }
  assert.deepEqual(rows, before);
  assert.equal(reports.noPurlDisposition(rows[0]), null);
  assert.ok(reports.summarizeDispositions([]).every((g) => g.packages === 0 && g.knownDownloads === 0 && g.unknownDownloadPackages === 0));
});

test("decodes a reconciled coverage report", () => {
  assert.deepEqual(reports.decodeMappingsReport(report()), report());
});

test("rejects inconsistent aggregate and package diagnostics", () => {
  const aggregate = report();
  aggregate.unresolved_by_diagnostic.no_parseable_source_host = 0;
  assert.throws(() => reports.decodeMappingsReport(aggregate), /do not reconcile/);

  const row = report();
  row.missing_packages[0].diagnostic_reason = "alternative_only";
  assert.throws(() => reports.decodeMappingsReport(row), /package rows do not reconcile/);

  const explicit = report();
  explicit.missing_packages[1].diagnostic_reason = "recorded_processing_error";
  assert.throws(() => reports.decodeMappingsReport(explicit), /must be null/);
});

test("accepts canonical source hosts and reconciles their aggregate", () => {
  const value = report();
  value.unresolved_by_diagnostic.no_parseable_source_host = 0;
  value.unresolved_by_diagnostic.no_primary_from_url_evidence = 1;
  value.unresolved_by_source_host = [{ host: "gitlab.com", package_count: 1 }];
  Object.assign(value.missing_packages[0], {
    diagnostic_reason: "no_primary_from_url_evidence",
    source_hosts: ["gitlab.com"],
    source_url: "https://GitLab.COM./group/project/archive.tar.gz",
  });
  assert.deepEqual(reports.decodeMappingsReport(value), value);
});

test("rejects noncanonical or inconsistent source hosts", () => {
  for (const source_hosts of [
    ["GitLab.com"],
    ["gitlab.com."],
    ["z.example", "a.example"],
    ["gitlab.com", "gitlab.com"],
  ]) {
    const value = report();
    value.missing_packages[0].source_hosts = source_hosts;
    assert.throws(() => reports.decodeMappingsReport(value), /normalized, unique, sorted/);
  }

  const mismatch = report();
  mismatch.missing_packages[0].source_hosts = ["gitlab.com"];
  assert.throws(() => reports.decodeMappingsReport(mismatch), /package rows do not reconcile/);
});
