import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { after, before, test } from "node:test";
import { createServer } from "vite";

let server;
let loader;
const responses = new Map();
const realFetch = globalThis.fetch;

before(async () => {
  server = await createServer({
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
    logLevel: "error",
  });
  loader = await server.ssrLoadModule("/src/data/loader.ts");
  globalThis.fetch = async (url) => {
    const key = String(url);
    if (!responses.has(key)) throw new Error(`Unexpected test fetch: ${key}`);
    const value = responses.get(key);
    return new Response(JSON.stringify(value), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
});

after(async () => {
  globalThis.fetch = realFetch;
  await server?.close();
});

function metadata(schemaVersion, packages) {
  return {
    schema_version: schemaVersion,
    generated_at: "2026-01-01T00:00:00Z",
    auto_generated_at: "2026-01-01T00:00:00Z",
    manual_updated_at: null,
    channel: "conda-forge",
    package_count: Object.keys(packages).length,
    packages,
  };
}

function alternative(owner, confidence) {
  return {
    purl: `pkg:github/${owner}/demo`,
    type: "github",
    namespace: owner,
    pkg_name: "demo",
    confidence,
    source: "recipe-source",
  };
}

function alternativeIdentity(value, confidence) {
  return {
    kind: "purl",
    role: "alternative",
    value: value.purl,
    coordinates: {
      type: value.type,
      namespace: value.namespace,
      pkg_name: value.pkg_name,
    },
    provenance: {
      availability: "available",
      source: value.source,
      confidence,
    },
  };
}

function fixture(name, detailPath) {
  const alternatives = [alternative("one", 0.8), alternative("two", 0.7)];
  const identities = [
    {
      kind: "purl",
      role: "primary",
      value: "pkg:pypi/demo",
      provenance: {
        availability: "available",
        source: "auto",
        confidence: 0.9,
        sources: ["recipe-source"],
        review: { status: "auto-verified", reviewer: null },
      },
    },
    alternativeIdentity(alternatives[0], 0.8),
    alternativeIdentity(alternatives[1], 0.7),
    {
      kind: "cpe",
      role: "associated",
      value: "cpe:2.3:a:example:demo",
      provenance: {
        availability: "available",
        source: "auto",
        review: { status: "auto-verified", reviewer: null },
      },
    },
  ];
  const common = {
    name,
    version: "1.0",
    purl: "pkg:pypi/demo",
    type: "pypi",
    namespace: null,
    pkg_name: "demo",
    status: "auto-verified",
    download_count: 42,
    alternative_purls: alternatives,
    cpes: ["cpe:2.3:a:example:demo"],
    identities,
    auto: {
      purl: "pkg:pypi/demo",
      type: "pypi",
      namespace: null,
      pkg_name: "demo",
      confidence: 0.9,
      sources: ["recipe-source"],
      alternative_purls: structuredClone(alternatives),
    },
  };
  const index = { ...structuredClone(common), detail_path: detailPath };
  const detail = {
    ...structuredClone(common),
    build: "py_0",
    subdir: "noarch",
    url: "https://example.invalid/demo.conda",
    confidence: 0.9,
    sources: ["recipe-source"],
    homepage: null,
    repo: null,
    recipe_url: null,
    summary: "demo",
    source_url: null,
    note: null,
    fetched_at: "2026-01-01T00:00:00Z",
    auto_verified: true,
    verification_sources: ["recipe-inference"],
    source: "auto",
  };
  return { index, detail };
}

let sequence = 0;
async function loadCurrentCase(mutateDetail = () => {}) {
  const id = sequence++;
  const name = `demo-${id}`;
  const indexPath = `./hostile-index-${id}.json`;
  const detailPath = `hostile-detail-${id}.json`;
  const { index, detail } = fixture(name, detailPath);
  mutateDetail(detail);
  responses.set(indexPath, metadata(4, { [name]: index }));
  responses.set(`./${detailPath}`, { schema_version: 3, packages: { [name]: detail } });
  const decodedIndex = await loader.loadMappingsIndex(indexPath);
  return loader.loadMappingPackageDetail(decodedIndex.packages[name]);
}

test("current index and detail accept an identical normalized identity contract", async () => {
  const detail = await loadCurrentCase();
  assert.equal(detail.purl, "pkg:pypi/demo");
});

test("hostile current shards cannot replace an internally valid index identity contract", async (t) => {
  const cases = {
    "reviewer payload: mutually different primary PURLs": (detail) => {
      detail.purl = "pkg:pypi/replacement";
      detail.identities[0].value = detail.purl;
    },
    "reviewer payload: mutually different identity provenance": (detail) => {
      detail.identities[0].provenance.confidence = 0.25;
    },
    "alternative value": (detail) => {
      detail.alternative_purls[0].purl = "pkg:github/attacker/demo";
      detail.identities[1].value = detail.alternative_purls[0].purl;
    },
    "alternative ordering": (detail) => {
      detail.alternative_purls.reverse();
      const primary = detail.identities[0];
      const cpe = detail.identities.at(-1);
      detail.identities = [primary, detail.identities[2], detail.identities[1], cpe];
    },
    "CPE value": (detail) => {
      detail.cpes[0] = "cpe:2.3:a:attacker:demo";
      detail.identities.at(-1).value = detail.cpes[0];
    },
    "CPE provenance": (detail) => {
      detail.identities.at(-1).provenance = {
        availability: "available",
        source: "manual",
        review: {
          status: "verified",
          reviewer: "attacker",
          reviewed_at: "2026-01-02T03:04:05Z",
        },
      };
    },
    status: (detail) => {
      detail.status = "auto-unverified";
    },
    "legacy package type": (detail) => {
      detail.type = "npm";
    },
    "legacy package namespace": (detail) => {
      detail.namespace = "attacker";
    },
    "legacy package name coordinates": (detail) => {
      detail.pkg_name = "replacement";
    },
    version: (detail) => {
      detail.version = "2.0";
    },
    "download metadata": (detail) => {
      detail.download_count = 99;
    },
    "automatic mapping metadata": (detail) => {
      detail.auto.confidence = 0.1;
    },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    await t.test(label, async () => {
      await assert.rejects(loadCurrentCase(mutate), /identity contract mismatch/);
    });
  }
});

test("previous identity schema accepts explicitly unavailable CPE provenance", async () => {
  const id = sequence++;
  const name = `previous-${id}`;
  const { detail } = fixture(name, "unused.json");
  detail.identities.at(-1).provenance = { availability: "unavailable" };
  const bundlePath = `./previous-${id}.json`;
  responses.set(bundlePath, metadata(2, { [name]: detail }));
  const decoded = await loader.loadMappings(bundlePath);
  assert.equal(decoded.packages[name].identities.at(-1).provenance.availability, "unavailable");
});

test("current identity schema requires attributed CPE provenance", async () => {
  await assert.rejects(
    loadCurrentCase((detail) => {
      detail.identities.at(-1).provenance = { availability: "unavailable" };
    }),
    /CPE provenance/,
  );
});

function legacyBundle(id) {
  const name = `legacy-${id}`;
  const { detail } = fixture(name, "unused.json");
  delete detail.identities;
  return metadata(1, { [name]: detail });
}

test("legacy schemas reject malformed required metadata and field types", async (t) => {
  const cases = {
    "boolean generated_at": (payload) => {
      payload.generated_at = true;
    },
    "numeric channel": (payload) => {
      payload.channel = 7;
    },
    "object package_count": (payload) => {
      payload.package_count = {};
    },
    "missing required summary": (payload) => {
      delete Object.values(payload.packages)[0].summary;
    },
    "boolean confidence": (payload) => {
      Object.values(payload.packages)[0].confidence = true;
    },
    "object sources": (payload) => {
      Object.values(payload.packages)[0].sources = {};
    },
    "numeric status": (payload) => {
      Object.values(payload.packages)[0].status = 1;
    },
    "object source": (payload) => {
      Object.values(payload.packages)[0].source = {};
    },
    "numeric optional auto_verified": (payload) => {
      Object.values(payload.packages)[0].auto_verified = 1;
    },
    "object nullable note": (payload) => {
      Object.values(payload.packages)[0].note = {};
    },
    "boolean alternative confidence": (payload) => {
      Object.values(payload.packages)[0].alternative_purls[0].confidence = false;
    },
    "missing auto confidence": (payload) => {
      const entry = Object.values(payload.packages)[0];
      entry.auto = {
        purl: entry.purl,
        type: entry.type,
        namespace: entry.namespace,
        pkg_name: entry.pkg_name,
        sources: entry.sources,
      };
    },
  };
  for (const [label, mutate] of Object.entries(cases)) {
    await t.test(label, async () => {
      const id = sequence++;
      const payload = legacyBundle(id);
      mutate(payload);
      const bundlePath = `./malformed-legacy-${id}.json`;
      responses.set(bundlePath, payload);
      await assert.rejects(loader.loadMappings(bundlePath));
    });
  }
});

test("browser decoder accepts every entry in the checked-in snapshot", async () => {
  const publicDir = path.resolve("public");
  const index = JSON.parse(await readFile(path.join(publicDir, "mappings-index.json"), "utf8"));
  // The snapshot is regenerated by the data pipelines, so its package count and
  // schema version both move under this test. Assert what has to hold for any
  // snapshot — a self-consistent count over a corpus-sized payload — and let
  // loadMappingsIndex below reject an unsupported schema version.
  const packageCount = Object.keys(index.packages).length;
  assert.equal(index.package_count, packageCount);
  assert.ok(
    packageCount > 30_000,
    `checked-in snapshot holds only ${packageCount} packages`,
  );

  responses.set("./real-snapshot-index.json", index);
  const detailPaths = new Set(Object.values(index.packages).map((entry) => entry.detail_path));
  await Promise.all(
    [...detailPaths].map(async (detailPath) => {
      const payload = JSON.parse(await readFile(path.join(publicDir, detailPath), "utf8"));
      responses.set(`./${detailPath}`, payload);
    }),
  );

  const decoded = await loader.loadMappingsIndex("./real-snapshot-index.json");
  const firstByShard = new Map();
  for (const entry of Object.values(decoded.packages)) {
    if (!firstByShard.has(entry.detail_path)) firstByShard.set(entry.detail_path, entry);
  }
  await Promise.all(
    [...firstByShard.values()].map((entry) => loader.loadMappingPackageDetail(entry)),
  );
  assert.equal(Object.keys(decoded.packages).length, packageCount);
  assert.equal(firstByShard.size, detailPaths.size);
});
