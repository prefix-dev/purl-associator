import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer } from "vite";

let server;
let coverage;

before(async () => {
  server = await createServer({
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
    logLevel: "error",
  });
  coverage = await server.ssrLoadModule("/src/data/identityCoverage.ts");
});

after(async () => {
  await server?.close();
});

function pkg(fields = {}) {
  return {
    name: "demo",
    status: "auto-unverified",
    purl: null,
    alternative_purls: [],
    cpes: [],
    ...fields,
  };
}

function edit(fields = {}) {
  return {
    type: "",
    namespace: "",
    pkgName: "",
    purl: "",
    alternative_purls: [],
    unmapped: false,
    note: "",
    ...fields,
  };
}

test("coverage distinguishes every PURL and CPE combination", () => {
  assert.equal(coverage.packageIdentityCoverage(pkg()), "none");
  assert.equal(
    coverage.packageIdentityCoverage(pkg({ purl: "pkg:pypi/demo" })),
    "purl",
  );
  assert.equal(
    coverage.packageIdentityCoverage(pkg({ cpes: ["cpe:2.3:a:example:demo"] })),
    "cpe",
  );
  assert.equal(
    coverage.packageIdentityCoverage(
      pkg({ purl: "pkg:pypi/demo", cpes: ["cpe:2.3:a:example:demo"] }),
    ),
    "purl+cpe",
  );
});

test("alternative PURLs count as identities without a primary", () => {
  assert.equal(
    coverage.packageIdentityCoverage(pkg({ alternative_purls: ["pkg:npm/demo"] })),
    "purl",
  );
});

test("current identities are authoritative over legacy coverage fields", () => {
  assert.equal(
    coverage.packageIdentityCoverage(
      pkg({
        purl: "pkg:pypi/stale",
        identities: [
          {
            kind: "cpe",
            role: "associated",
            value: "cpe:2.3:a:example:demo",
            provenance: { availability: "unavailable" },
          },
        ],
      }),
    ),
    "cpe",
  );
});

test("draft replacements determine effective coverage", () => {
  const published = pkg({ purl: "pkg:pypi/demo" });
  assert.equal(
    coverage.packageIdentityCoverage(published, edit({ unmapped: true })),
    "none",
  );
  assert.equal(
    coverage.packageIdentityCoverage(
      published,
      edit({ unmapped: true, cpes: ["cpe:2.3:a:example:demo"] }),
    ),
    "cpe",
  );
  assert.equal(
    coverage.packageIdentityCoverage(
      published,
      edit({ alternative_purls: ["pkg:npm/demo"] }),
    ),
    "purl",
  );
});

test("PURL decisions remain separate from identity coverage", () => {
  const cpeOnly = pkg({
    status: "verified",
    cpes: ["cpe:2.3:a:example:demo"],
  });
  assert.equal(coverage.needsPurlDecision(cpeOnly), true);
  assert.equal(
    coverage.needsPurlDecision({ ...cpeOnly, status: "unmapped", unmapped: true }),
    false,
  );
  assert.equal(
    coverage.needsPurlDecision(cpeOnly, edit({ unmapped: true })),
    false,
  );
  assert.equal(
    coverage.needsPurlDecision(cpeOnly, edit({ purl: "pkg:pypi/demo" })),
    false,
  );
});

test("drafts override package review status without conflating coverage", () => {
  assert.equal(coverage.effectiveMappingStatus(pkg()), "auto-unverified");
  assert.equal(
    coverage.effectiveMappingStatus(
      pkg({
        status: "unmapped",
        cpes: ["cpe:2.3:a:example:demo"],
      }),
    ),
    "unmapped",
  );
  assert.equal(
    coverage.effectiveMappingStatus(
      pkg({ purl: "pkg:pypi/demo", status: "auto-unverified" }),
      edit(),
    ),
    "edited",
  );
});
