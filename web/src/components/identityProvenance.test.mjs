import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

let server;
let describe;
let component;

before(async () => {
  server = await createServer({
    server: { middlewareMode: true },
    appType: "custom",
    logLevel: "error",
  });
  describe = await server.ssrLoadModule("/src/data/identityProvenance.ts");
  component = await server.ssrLoadModule("/src/components/IdentityProvenance.tsx");
});

after(async () => {
  await server?.close();
});

// The real theme comes from a hook; the shape is all these components read.
const theme = {
  dark: false,
  setDark: () => {},
  t: {
    page: "#fff",
    surface: "#fff",
    surface2: "#fff",
    inset: "#eee",
    fg1: "#000",
    fg2: "#333",
    fg3: "#777",
    border: "#ddd",
    borderStrong: "#ccc",
    accent: "#ffd432",
    accentFg: "#001d38",
    link: "#3957ff",
    rowHover: "#eee",
    rowSelected: "#eee",
    good: "#5b9b2c",
    bad: "#d94e1f",
    warn: "#b07d00",
  },
};

const manualPrimary = {
  kind: "purl",
  role: "primary",
  value: "pkg:pypi/demo",
  provenance: {
    availability: "available",
    source: "manual",
    review: {
      status: "verified",
      reviewer: "octocat",
      reviewed_at: "2026-02-03T10:11:12Z",
    },
  },
};

const autoPrimary = {
  kind: "purl",
  role: "primary",
  value: "pkg:pypi/demo",
  provenance: {
    availability: "available",
    source: "auto",
    confidence: 0.72,
    sources: ["recipe-source"],
    review: { status: "auto-unverified", reviewer: null },
  },
};

const recipeAlternative = {
  kind: "purl",
  role: "alternative",
  value: "pkg:github/demo-org/demo",
  coordinates: { type: "github", namespace: "demo-org", pkg_name: "demo" },
  provenance: {
    availability: "available",
    source: "recipe-source",
    confidence: 0.8,
  },
};

const bareAlternative = {
  kind: "purl",
  role: "alternative",
  value: "pkg:npm/demo",
  provenance: { availability: "unavailable" },
};

const cpeIdentity = {
  kind: "cpe",
  role: "associated",
  value: "cpe:2.3:a:example:demo",
  provenance: { availability: "unavailable" },
};

function render(identities, mappingStatus, stale = false) {
  return renderToStaticMarkup(
    createElement(component.IdentityProvenance, {
      theme,
      identities,
      mappingStatus,
      stale,
    }),
  );
}

test("a manual verified primary names its reviewer", () => {
  const [row] = describe.describeIdentities([manualPrimary]);
  assert.equal(row.source, "manual");
  assert.equal(row.review.status, "verified");
  assert.equal(row.review.humanReviewed, true);
  assert.equal(row.review.reviewer, "octocat");
  assert.equal(row.review.reviewedAt, "2026-02-03");
  assert.equal(row.confidence, null);

  const html = render([manualPrimary], "verified");
  assert.match(html, /Verified/);
  assert.match(html, /@octocat/);
  assert.match(html, /primary/);
  // Mapping status and identity review agree: no divergence callout.
  assert.doesNotMatch(html, /nobody vouched/);
});

test("an auto-unverified primary shows its confidence and never reads as human-verified", () => {
  const [row] = describe.describeIdentities([autoPrimary]);
  assert.equal(row.source, "auto");
  assert.equal(row.confidence, 0.72);
  assert.deepEqual(row.sources, ["recipe-source"]);
  assert.equal(row.review.humanReviewed, false);
  assert.equal(row.review.label, "Auto, unreviewed");

  const html = render([autoPrimary], "auto-unverified");
  assert.match(html, /Auto, unreviewed/);
  assert.match(html, /72/);
  assert.match(html, /recipe-source/);
  assert.doesNotMatch(html, /@/);
});

test("a recipe-source alternative shows provenance without a review state", () => {
  const [row] = describe.describeIdentities([recipeAlternative]);
  assert.equal(row.role, "alternative");
  assert.equal(row.roleLabel, "alt");
  assert.equal(row.source, "recipe-source");
  assert.equal(row.confidence, 0.8);
  assert.equal(row.review, null);

  const html = render([recipeAlternative], "auto-verified");
  assert.match(html, /recipe-source/);
  assert.match(html, /80/);
  assert.match(html, /alt/);
  assert.doesNotMatch(html, /Verified/);
});

test("a human-blessed mapping with an auto primary reports both facts", () => {
  const divergence = describe.primaryReviewDivergence("verified", [
    autoPrimary,
    recipeAlternative,
  ]);
  assert.equal(divergence.mappingStatus, "verified");
  assert.equal(divergence.identityReview.status, "auto-unverified");

  const html = render([autoPrimary, recipeAlternative], "verified");
  assert.match(html, /Mapping status is/);
  assert.match(html, /nobody vouched for this PURL itself/);
  assert.match(html, /Auto, unreviewed/);
});

test("agreeing statuses and non-human mapping statuses raise no divergence", () => {
  assert.equal(describe.primaryReviewDivergence("verified", [manualPrimary]), null);
  assert.equal(
    describe.primaryReviewDivergence("auto-unverified", [autoPrimary]),
    null,
  );
  assert.equal(describe.primaryReviewDivergence("verified", []), null);
});

test("identities without provenance render as unrecorded rather than defaulted", () => {
  const [alternative, cpe] = describe.describeIdentities([
    bareAlternative,
    cpeIdentity,
  ]);
  assert.equal(alternative.hasProvenance, false);
  assert.equal(alternative.source, null);
  assert.equal(alternative.confidence, null);
  assert.equal(cpe.hasProvenance, false);
  assert.equal(cpe.roleLabel, "cpe");

  const html = render([bareAlternative, cpeIdentity], "verified");
  assert.match(html, /no provenance recorded/);
  assert.doesNotMatch(html, /confidence/);
});

test("payloads without identities render nothing", () => {
  assert.deepEqual(describe.describeIdentities(undefined), []);
  assert.deepEqual(describe.describeIdentities(null), []);
  assert.equal(render(undefined, "auto-verified"), "");
  assert.equal(render([], "auto-verified"), "");
});

test("an open draft marks the published rows as stale", () => {
  assert.match(render([manualPrimary], "verified", true), /not reflected here/);
  assert.doesNotMatch(render([manualPrimary], "verified", false), /not reflected here/);
});
