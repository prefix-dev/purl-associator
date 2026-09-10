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
    schema_version: 1,
    input_schema_version: 3,
    channel: "conda-forge",
    counts: {
      total: 3,
      primary_present: 1,
      explicitly_unmapped: 1,
      unresolved: 1,
      primary_missing: 2,
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
        download_count: null,
      }),
    ],
  };
}

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
