import {
  describeIdentities,
  primaryReviewDivergence,
  type IdentityDisplay,
  type IdentityReviewDisplay,
} from "../data/identityProvenance";
import type { PublishedIdentity, ReviewStatus } from "../data/types";
import {
  ConfidenceBar,
  CpeChip,
  Glyph,
  PurlChip,
  SourceTag,
  Theme,
} from "./Primitives";

type Props = {
  theme: Theme;
  identities: PublishedIdentity[] | null | undefined;
  /** package-level review status, shown only to contrast it with the
   *  per-identity review state — the two are different facts. */
  mappingStatus: ReviewStatus | null | undefined;
  /** true while a local draft is open: the rows describe what is published,
   *  not what the editor above currently holds. */
  stale?: boolean;
};

/** Published per-identity provenance. Renders nothing for payloads that
 *  predate the identity contract. */
export function IdentityProvenance({
  theme,
  identities,
  mappingStatus,
  stale = false,
}: Props) {
  const t = theme.t;
  const rows = describeIdentities(identities);
  if (rows.length === 0) return null;
  const divergence = primaryReviewDivergence(mappingStatus, identities);

  return (
    <div
      style={{
        background: t.surface,
        border: `1px solid ${t.border}`,
        borderRadius: 12,
        padding: 14,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 10,
        }}
      >
        <span
          style={{
            fontSize: 11,
            color: t.fg2,
            fontWeight: 600,
            letterSpacing: ".04em",
            textTransform: "uppercase",
          }}
        >
          Published identities
        </span>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            background: theme.dark ? "#0a0d11" : "#ece8df",
            color: t.fg2,
            padding: "0 6px",
            borderRadius: 3,
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {rows.length}
        </span>
        <span style={{ fontSize: 11, color: t.fg3 }}>
          {stale
            ? "as last published — your draft above is not reflected here"
            : "each carries its own provenance and review state"}
        </span>
      </div>

      {divergence && (
        <div
          style={{
            display: "flex",
            gap: 8,
            alignItems: "flex-start",
            marginBottom: 10,
            padding: "8px 10px",
            background: theme.dark ? "#2a2616" : "#fff7d6",
            border: `1px solid ${theme.dark ? "#3a3416" : "#f0e2a3"}`,
            borderRadius: 6,
            fontSize: 12,
            color: t.fg1,
          }}
        >
          <span style={{ color: t.warn, display: "flex", marginTop: 2 }}>
            <Glyph name="info" size={12} />
          </span>
          <span>
            Mapping status is <strong>{divergence.mappingStatus}</strong>, but
            the primary PURL below is{" "}
            <strong>{divergence.identityReview.label.toLowerCase()}</strong>. A
            reviewer signed off on the package; nobody vouched for this PURL
            itself.
          </span>
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {rows.map((row) => (
          <IdentityRow key={row.key} row={row} theme={theme} />
        ))}
      </div>
    </div>
  );
}

function IdentityRow({ row, theme }: { row: IdentityDisplay; theme: Theme }) {
  const t = theme.t;
  const isPrimary = row.role === "primary";
  return (
    <div
      title={row.hint}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        flexWrap: "wrap",
        padding: "7px 10px",
        background: isPrimary
          ? theme.dark
            ? "#1a2233"
            : "#fff7d6"
          : t.surface2,
        border: `1px solid ${
          isPrimary ? (theme.dark ? "#2a3a55" : "#f0e2a3") : t.border
        }`,
        borderRadius: 8,
      }}
    >
      {row.kind === "cpe" ? (
        <CpeChip cpe={row.value} theme={theme} />
      ) : (
        <PurlChip purl={row.value} theme={theme} />
      )}
      <RoleBadge label={row.roleLabel} emphasis={isPrimary} theme={theme} />
      {row.source && <SourceTag source={row.source} theme={theme} />}
      {row.confidence !== null && (
        <ConfidenceBar score={row.confidence} theme={theme} width={50} />
      )}
      {row.sources.length > 0 && (
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 4,
            fontSize: 10.5,
            color: t.fg3,
          }}
        >
          via
          {row.sources.map((source) => (
            <SourceTag key={source} source={source} theme={theme} />
          ))}
        </span>
      )}
      <div style={{ flex: 1 }} />
      {row.review ? (
        <ReviewBadge review={row.review} theme={theme} />
      ) : (
        !row.hasProvenance && (
          <span style={{ fontSize: 10.5, color: t.fg3, fontStyle: "italic" }}>
            no provenance recorded
          </span>
        )
      )}
    </div>
  );
}

function RoleBadge({
  label,
  emphasis,
  theme,
}: {
  label: string;
  emphasis: boolean;
  theme: Theme;
}) {
  const t = theme.t;
  return (
    <span
      style={{
        fontSize: 9.5,
        fontWeight: 700,
        letterSpacing: ".06em",
        textTransform: "uppercase",
        color: emphasis ? (theme.dark ? "#ffd432" : "#866400") : t.fg2,
        background: emphasis
          ? theme.dark
            ? "#2a2616"
            : "#ffeec4"
          : "transparent",
        padding: emphasis ? "2px 6px" : 0,
        borderRadius: 3,
      }}
    >
      {label}
    </span>
  );
}

/** Review state of one identity. Kept visually distinct from `StatusPill`,
 *  which reports the package-level mapping status: an automatic identity must
 *  never read as if a person had verified it. */
function ReviewBadge({
  review,
  theme,
}: {
  review: IdentityReviewDisplay;
  theme: Theme;
}) {
  const tones = {
    verified: {
      bg: theme.dark ? "#1a2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    edited: {
      bg: theme.dark ? "#1a2233" : "#e3ecff",
      fg: theme.dark ? "#9aaaff" : "#3957ff",
    },
    "auto-verified": {
      bg: theme.dark ? "#162726" : "#dff8f4",
      fg: theme.dark ? "#69d7c8" : "#15776d",
    },
    "auto-unverified": {
      bg: theme.dark ? "#2a2616" : "#fff4d2",
      fg: theme.dark ? "#f5c542" : "#866400",
    },
  } as const;
  const tone = tones[review.status];
  return (
    <span
      title={review.hint}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontSize: 10,
        fontWeight: 600,
        padding: "2px 7px",
        borderRadius: 4,
        background: tone.bg,
        color: tone.fg,
        letterSpacing: "0.02em",
        fontFamily: "Inter, sans-serif",
        whiteSpace: "nowrap",
      }}
    >
      <Glyph name={review.humanReviewed ? "check" : "sparkle"} size={10} />
      {review.label}
      {review.reviewer && (
        <span style={{ fontWeight: 500, opacity: 0.85 }}>@{review.reviewer}</span>
      )}
    </span>
  );
}
