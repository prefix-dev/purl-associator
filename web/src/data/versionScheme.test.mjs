import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createServer } from "vite";

let server;
let schemes;

before(async () => {
  server = await createServer({
    server: { middlewareMode: true, hmr: false },
    appType: "custom",
    logLevel: "error",
  });
  schemes = await server.ssrLoadModule("/src/data/versionScheme.ts");
});

after(async () => {
  await server?.close();
});

const LETTER_PATCH = {
  scheme: "letter-patch",
  review: { status: "verified", reviewer: "r", reviewed_at: "2026-11-16T00:00:00Z" },
};

test("effective scheme prefers a staged edit, including an explicit clear", () => {
  const plain = { version_scheme: undefined };
  const marked = { version_scheme: LETTER_PATCH };
  assert.equal(schemes.effectiveVersionScheme(plain), null);
  assert.equal(schemes.effectiveVersionScheme(marked), "letter-patch");
  assert.equal(schemes.effectiveVersionScheme(marked, {}), "letter-patch");
  assert.equal(schemes.effectiveVersionScheme(marked, { versionScheme: null }), null);
  assert.equal(
    schemes.effectiveVersionScheme(plain, { versionScheme: "letter-patch" }),
    "letter-patch",
  );
});

test("a scheme equal to the published one is not a change", () => {
  const marked = { version_scheme: LETTER_PATCH };
  assert.deepEqual(
    schemes.reconcileVersionScheme(marked, { versionScheme: "letter-patch" }, true, false),
    { versionScheme: undefined, metadataOnly: false },
  );
  assert.deepEqual(
    schemes.reconcileVersionScheme({}, { versionScheme: null }, true, false),
    { versionScheme: undefined, metadataOnly: false },
  );
});

test("a scheme-only change is metadata-only unless the mapping is also reviewed", () => {
  const plain = {};
  assert.deepEqual(
    schemes.reconcileVersionScheme(plain, { versionScheme: "letter-patch" }, true, false),
    { versionScheme: "letter-patch", metadataOnly: true },
  );
  // A changed mapping or an explicit approval reviews the whole package.
  assert.deepEqual(
    schemes.reconcileVersionScheme(plain, { versionScheme: "letter-patch" }, false, false),
    { versionScheme: "letter-patch", metadataOnly: false },
  );
  assert.deepEqual(
    schemes.reconcileVersionScheme(plain, { versionScheme: "letter-patch" }, true, true),
    { versionScheme: "letter-patch", metadataOnly: false },
  );
  // Clearing a published scheme is a change too.
  assert.deepEqual(
    schemes.reconcileVersionScheme({ version_scheme: LETTER_PATCH }, { versionScheme: null }, true, false),
    { versionScheme: null, metadataOnly: true },
  );
});
