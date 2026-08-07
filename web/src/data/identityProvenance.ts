import type { PublishedIdentity, ReviewStatus } from "./types";

/** How a single identity was reviewed — deliberately *not* the package-level
 *  `status`. A mapping a human blessed routinely still carries an
 *  automatically derived, individually unreviewed primary identity. */
export type IdentityReviewDisplay = {
  status: "verified" | "edited" | "auto-verified" | "auto-unverified";
  label: string;
  /** true only when a named person signed off on this identity. */
  humanReviewed: boolean;
  reviewer: string | null;
  /** date part of the review timestamp, null when none was published. */
  reviewedAt: string | null;
  hint: string;
};

export type IdentityDisplay = {
  key: string;
  kind: "purl" | "cpe";
  role: "primary" | "alternative" | "associated";
  value: string;
  roleLabel: string;
  /** provenance source as published; null when the payload records none. */
  source: string | null;
  confidence: number | null;
  /** evidence the automatic pipeline used, empty when not published. */
  sources: string[];
  review: IdentityReviewDisplay | null;
  /** false when the payload marks this identity's provenance unavailable. */
  hasProvenance: boolean;
  hint: string;
};

const ROLE_LABELS = {
  primary: "primary",
  alternative: "alt",
  associated: "cpe",
} as const;

const REVIEW_LABELS = {
  verified: "Verified",
  edited: "Edited",
  "auto-verified": "Auto-verified",
  "auto-unverified": "Auto, unreviewed",
} as const;

function reviewDisplay(
  status: IdentityReviewDisplay["status"],
  reviewer: string | null,
  reviewedAt: string | null,
): IdentityReviewDisplay {
  const humanReviewed = status === "verified" || status === "edited";
  const who = reviewer ? `@${reviewer}` : "a reviewer";
  const when = reviewedAt ? ` on ${reviewedAt}` : "";
  const hint = humanReviewed
    ? status === "edited"
      ? `Edited and approved by ${who}${when}.`
      : `Reviewed and approved by ${who}${when}.`
    : status === "auto-verified"
      ? "Derived automatically and cross-checked against another source. No person reviewed it."
      : "Derived automatically. Nothing has confirmed it — neither a person nor a second source.";
  return {
    status,
    label: REVIEW_LABELS[status],
    humanReviewed,
    reviewer,
    reviewedAt,
    hint,
  };
}

function dateOf(timestamp: string | null | undefined): string | null {
  return timestamp ? timestamp.slice(0, 10) : null;
}

export function describeIdentity(identity: PublishedIdentity): IdentityDisplay {
  const base = {
    key: `${identity.kind}:${identity.value}`,
    kind: identity.kind,
    role: identity.role,
    value: identity.value,
    roleLabel: ROLE_LABELS[identity.role],
    source: null,
    confidence: null,
    sources: [] as string[],
    review: null,
    hasProvenance: false,
    hint: "",
  } satisfies IdentityDisplay;

  if (identity.kind === "cpe") {
    return {
      ...base,
      hint: "CPE prefix recorded for downstream NVD matching. The payload publishes no provenance for CPEs.",
    };
  }

  if (identity.role === "primary") {
    const provenance = identity.provenance;
    if (provenance.source === "auto") {
      return {
        ...base,
        source: "auto",
        confidence: provenance.confidence,
        sources: provenance.sources,
        review: reviewDisplay(provenance.review.status, null, null),
        hasProvenance: true,
        hint: "Primary PURL derived by the automatic pipeline.",
      };
    }
    return {
      ...base,
      source: "manual",
      review: reviewDisplay(
        provenance.review.status,
        provenance.review.reviewer,
        dateOf(provenance.review.reviewed_at),
      ),
      hasProvenance: true,
      hint: "Primary PURL set by a reviewer.",
    };
  }

  if (identity.provenance.availability === "available") {
    return {
      ...base,
      source: identity.provenance.source,
      confidence: identity.provenance.confidence,
      hasProvenance: true,
      hint: `Alternative PURL derived from ${identity.provenance.source}.`,
    };
  }

  return {
    ...base,
    hint: "Alternative PURL recorded without provenance — it predates per-identity provenance or was added by hand.",
  };
}

/** Absent (v2-era payloads) and empty both yield an empty list; callers render
 *  nothing rather than inventing defaults. */
export function describeIdentities(
  identities: PublishedIdentity[] | null | undefined,
): IdentityDisplay[] {
  return (identities ?? []).map(describeIdentity);
}

/** The package-level `status` records a reviewer's sign-off on the mapping;
 *  the primary identity's review records who vouched for the PURL itself.
 *  A human-blessed mapping routinely carries an automatically derived,
 *  individually unreviewed primary — hundreds of packages in the corpus are in
 *  that state — so the UI must never let one stand in for the other. Returns
 *  both facts when the mapping claims human review the primary identity does
 *  not have, and null otherwise. */
export function primaryReviewDivergence(
  mappingStatus: ReviewStatus | null | undefined,
  identities: PublishedIdentity[] | null | undefined,
): { mappingStatus: ReviewStatus; identityReview: IdentityReviewDisplay } | null {
  const primary = describeIdentities(identities).find(
    (identity) => identity.kind === "purl" && identity.role === "primary",
  );
  if (!primary?.review || primary.review.humanReviewed) return null;
  if (mappingStatus !== "verified" && mappingStatus !== "edited") return null;
  return { mappingStatus, identityReview: primary.review };
}
