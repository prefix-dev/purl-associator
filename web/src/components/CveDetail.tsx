import { useMemo, useState } from "react";
import type {
  Advisory,
  CvePackage,
  Review,
  ReviewEdit,
  ReviewStatus,
} from "../data/cves";
import { REVIEW_STATUSES, editFromReview, isEditNonEmpty } from "../data/cves";
import { Btn, Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  pkg: CvePackage | null;
  edits: Record<string, ReviewEdit>;
  onEdit: (advisoryId: string, next: ReviewEdit) => void;
  onResetEdit: (advisoryId: string) => void;
  blankEdit: () => ReviewEdit;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
};

function severityLevel(score: string): {
  label: string;
  color: string;
  bg: string;
} | null {
  // Pull the base CVSS score out of a vector string. The "base" segment is
  // formatted differently across V3/V4 — for our purposes we just look for
  // the trailing "/X.Y" pattern or any single number, mapping to a band.
  const m = score.match(/(\d+\.\d+)/);
  if (!m) return null;
  const v = parseFloat(m[1]);
  if (v >= 9.0) return { label: `${v.toFixed(1)} critical`, color: "#fff", bg: "#a8201f" };
  if (v >= 7.0) return { label: `${v.toFixed(1)} high`, color: "#fff", bg: "#d94e1f" };
  if (v >= 4.0) return { label: `${v.toFixed(1)} medium`, color: "#001d38", bg: "#ffd432" };
  if (v > 0) return { label: `${v.toFixed(1)} low`, color: "#fff", bg: "#5b9b2c" };
  return null;
}

function SeverityPill({ adv }: { adv: Advisory }) {
  if (!adv.severity?.score) return null;
  const lvl = severityLevel(adv.severity.score);
  if (!lvl) return null;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: 10.5,
        fontWeight: 700,
        padding: "2px 7px",
        borderRadius: 4,
        background: lvl.bg,
        color: lvl.color,
        letterSpacing: ".02em",
        textTransform: "uppercase",
        fontFamily: "Inter, sans-serif",
      }}
      title={adv.severity.score}
    >
      {lvl.label}
    </span>
  );
}

function ReviewBadge({
  theme,
  status,
  isEdited,
}: {
  theme: Theme;
  status: ReviewStatus | undefined;
  isEdited: boolean;
}) {
  const map: Record<ReviewStatus, { label: string; bg: string; fg: string }> = {
    confirmed: {
      label: "Confirmed",
      bg: theme.dark ? "#1a2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    rejected: {
      label: "Rejected",
      bg: theme.dark ? "#2a1818" : "#ffe1d8",
      fg: theme.dark ? "#ff8e6a" : "#a8401b",
    },
    "not-applicable": {
      label: "Not applicable",
      bg: theme.dark ? "#222" : "#ece8df",
      fg: theme.dark ? "#dcdfe4" : "#3a3d44",
    },
    "needs-review": {
      label: "Needs review",
      bg: theme.dark ? "#2a2616" : "#fff4d2",
      fg: theme.dark ? "#f5c542" : "#866400",
    },
  };
  if (isEdited) {
    return (
      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 5,
          fontSize: 10.5,
          fontWeight: 600,
          padding: "2px 7px",
          borderRadius: 4,
          background: theme.dark ? "#1a2233" : "#e3ecff",
          color: theme.dark ? "#9aaaff" : "#3957ff",
          textTransform: "uppercase",
          letterSpacing: ".02em",
        }}
      >
        <span
          style={{
            width: 5,
            height: 5,
            borderRadius: "50%",
            background: theme.dark ? "#9aaaff" : "#3957ff",
          }}
        />
        Edited
      </span>
    );
  }
  if (!status) {
    return (
      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 5,
          fontSize: 10.5,
          fontWeight: 600,
          padding: "2px 7px",
          borderRadius: 4,
          background: theme.dark ? "#2a2616" : "#fff4d2",
          color: theme.dark ? "#f5c542" : "#866400",
          textTransform: "uppercase",
          letterSpacing: ".02em",
        }}
      >
        <span
          style={{
            width: 5,
            height: 5,
            borderRadius: "50%",
            background: theme.dark ? "#f5c542" : "#866400",
          }}
        />
        Unreviewed
      </span>
    );
  }
  const m = map[status];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontSize: 10.5,
        fontWeight: 600,
        padding: "2px 7px",
        borderRadius: 4,
        background: m.bg,
        color: m.fg,
        textTransform: "uppercase",
        letterSpacing: ".02em",
      }}
    >
      <span
        style={{ width: 5, height: 5, borderRadius: "50%", background: m.fg }}
      />
      {m.label}
    </span>
  );
}

function VersionChip({
  theme,
  version,
  state,
  onClick,
  title,
}: {
  theme: Theme;
  version: string;
  state: "affected" | "removed" | "added";
  onClick?: () => void;
  title?: string;
}) {
  const t = theme.t;
  const styles =
    state === "affected"
      ? {
          bg: theme.dark ? "#2a1818" : "#ffe5dc",
          fg: theme.dark ? "#ff8e6a" : "#a8401b",
          border: theme.dark ? "#5a2a1a" : "#f3c3b0",
        }
      : state === "removed"
        ? {
            bg: theme.dark ? "#161616" : "#f3efe6",
            fg: t.fg3,
            border: t.border,
          }
        : {
            bg: theme.dark ? "#1a2a18" : "#ecf5dc",
            fg: theme.dark ? "#9adf6d" : "#5b9b2c",
            border: theme.dark ? "#26421e" : "#c9e2a4",
          };
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      title={title}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 11,
        padding: "2px 7px",
        borderRadius: 4,
        background: styles.bg,
        color: styles.fg,
        border: `1px solid ${styles.border}`,
        cursor: onClick ? "pointer" : "default",
        textDecoration: state === "removed" ? "line-through" : "none",
      }}
    >
      {version}
    </button>
  );
}

export function CveDetail({
  theme,
  pkg,
  edits,
  onEdit,
  onResetEdit,
  isLoggedIn,
  onRequestLogin,
}: Props) {
  const t = theme.t;

  if (!pkg) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: t.fg3,
          background: t.page,
        }}
      >
        <div style={{ textAlign: "center", maxWidth: 380 }}>
          <div
            style={{
              fontFamily: "Moranga, serif",
              fontSize: 28,
              color: t.fg2,
              marginBottom: 8,
              fontWeight: 300,
            }}
          >
            No package selected
          </div>
          <div style={{ fontSize: 13, color: t.fg3 }}>
            Pick a conda-forge package on the left to view its associated
            advisories.
          </div>
        </div>
      </div>
    );
  }

  const advisories = useMemo(
    () =>
      [...pkg.advisories].sort((a, b) => {
        // Prioritize unreviewed, then critical→low severity, then date.
        const ea = edits[`${pkg.package}::${a.id}`];
        const eb = edits[`${pkg.package}::${b.id}`];
        const ra = ea?.status ?? a.review?.status;
        const rb = eb?.status ?? b.review?.status;
        if (!ra && rb) return -1;
        if (ra && !rb) return 1;
        const sa = a.severity?.score
          ? parseFloat(a.severity.score.match(/(\d+\.\d+)/)?.[1] || "0")
          : 0;
        const sb = b.severity?.score
          ? parseFloat(b.severity.score.match(/(\d+\.\d+)/)?.[1] || "0")
          : 0;
        if (sa !== sb) return sb - sa;
        return (b.modified || "").localeCompare(a.modified || "");
      }),
    [pkg, edits],
  );

  return (
    <div style={{ flex: 1, overflowY: "auto", background: t.page }}>
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 5,
          background: t.surface,
          borderBottom: `1px solid ${t.border}`,
          padding: "14px 24px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <h1
            style={{
              fontFamily: "Moranga, serif",
              fontWeight: 300,
              fontSize: 28,
              color: t.fg1,
              margin: 0,
              lineHeight: 1.1,
            }}
          >
            {pkg.package}
          </h1>
          <span
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 12,
              color: t.fg2,
              background: t.inset,
              padding: "2px 7px",
              borderRadius: 4,
            }}
          >
            {pkg.advisories.length} advisor
            {pkg.advisories.length === 1 ? "y" : "ies"}
          </span>
          <span style={{ fontSize: 11, color: t.fg3 }}>
            {pkg.conda_versions_total} conda-forge version
            {pkg.conda_versions_total === 1 ? "" : "s"} known
          </span>
        </div>
        <div style={{ marginTop: 6, display: "flex", gap: 12, flexWrap: "wrap" }}>
          {pkg.purls.map((purl) => (
            <code
              key={purl}
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 11,
                color: t.fg2,
              }}
            >
              {purl}
            </code>
          ))}
        </div>
      </div>

      <div style={{ maxWidth: 1000, margin: "0 auto", padding: "20px 24px 60px" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {advisories.map((adv) => (
            <AdvisoryCard
              key={adv.id}
              theme={theme}
              pkgName={pkg.package}
              adv={adv}
              edit={edits[`${pkg.package}::${adv.id}`]}
              onEdit={(next) => onEdit(adv.id, next)}
              onReset={() => onResetEdit(adv.id)}
              isLoggedIn={isLoggedIn}
              onRequestLogin={onRequestLogin}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

function AdvisoryCard({
  theme,
  pkgName: _pkgName,
  adv,
  edit,
  onEdit,
  onReset,
  isLoggedIn,
  onRequestLogin,
}: {
  theme: Theme;
  pkgName: string;
  adv: Advisory;
  edit: ReviewEdit | undefined;
  onEdit: (next: ReviewEdit) => void;
  onReset: () => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
}) {
  const t = theme.t;
  const [expanded, setExpanded] = useState(true);

  const baseReview: Review | undefined = adv.review;
  const eff: ReviewEdit = edit ?? editFromReview(baseReview);
  const isEdited = !!edit && isEditNonEmpty(eff, baseReview);
  const status: ReviewStatus | undefined = edit?.status ?? baseReview?.status;

  function setField<K extends keyof ReviewEdit>(key: K, value: ReviewEdit[K]): void {
    if (!isLoggedIn && !edit) {
      onRequestLogin();
    }
    onEdit({ ...eff, [key]: value });
  }

  function toggleNotAffected(version: string): void {
    if (!isLoggedIn && !edit) onRequestLogin();
    const cur = new Set(eff.version_overrides.not_affected);
    const aff = new Set(eff.version_overrides.affected);
    if (cur.has(version)) cur.delete(version);
    else {
      cur.add(version);
      aff.delete(version);
    }
    onEdit({
      ...eff,
      version_overrides: {
        affected: [...aff],
        not_affected: [...cur],
      },
    });
  }

  function toggleManuallyAffected(version: string): void {
    if (!isLoggedIn && !edit) onRequestLogin();
    const cur = new Set(eff.version_overrides.affected);
    const not = new Set(eff.version_overrides.not_affected);
    if (cur.has(version)) cur.delete(version);
    else {
      cur.add(version);
      not.delete(version);
    }
    onEdit({
      ...eff,
      version_overrides: {
        affected: [...cur],
        not_affected: [...not],
      },
    });
  }

  // Compute the effective affected set after applying the pending override.
  const effectiveAffected = useMemo(() => {
    const base = new Set(adv.affected_conda_versions);
    for (const v of eff.version_overrides.not_affected) base.delete(v);
    for (const v of eff.version_overrides.affected) base.add(v);
    return [...base];
  }, [adv.affected_conda_versions, eff.version_overrides]);

  return (
    <div
      id={`adv-${adv.id}`}
      style={{
        background: t.surface,
        border: `1px solid ${isEdited ? (theme.dark ? "#2a3a55" : "#c2d0fb") : t.border}`,
        borderRadius: 12,
        overflow: "hidden",
      }}
    >
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: "12px 16px",
          display: "flex",
          alignItems: "flex-start",
          gap: 10,
          cursor: "pointer",
          background: expanded ? t.surface : t.surface2,
        }}
      >
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
              marginBottom: 4,
            }}
          >
            <a
              href={adv.osv_url}
              target="_blank"
              rel="noreferrer"
              onClick={(e) => e.stopPropagation()}
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontWeight: 700,
                fontSize: 13,
                color: t.link,
                textDecoration: "none",
              }}
            >
              {adv.primary_id}
            </a>
            {adv.primary_id !== adv.id && (
              <code
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 11,
                  color: t.fg3,
                }}
              >
                {adv.id}
              </code>
            )}
            <SeverityPill adv={adv} />
            <ReviewBadge theme={theme} status={status} isEdited={isEdited} />
            <span style={{ flex: 1 }} />
            <span style={{ fontSize: 11, color: t.fg3 }}>
              {(adv.modified || adv.published || "").slice(0, 10)}
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setExpanded(!expanded);
              }}
              style={{
                background: "transparent",
                border: 0,
                color: t.fg2,
                cursor: "pointer",
                padding: 0,
                transform: expanded ? "rotate(180deg)" : "none",
                transition: "transform 150ms",
              }}
              aria-label={expanded ? "Collapse" : "Expand"}
            >
              <Glyph name="chev" size={14} />
            </button>
          </div>
          {adv.summary && (
            <div
              style={{
                fontSize: 13,
                color: t.fg1,
                fontWeight: 500,
                lineHeight: 1.4,
                margin: "2px 0",
              }}
            >
              {adv.summary}
            </div>
          )}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexWrap: "wrap",
              marginTop: 4,
              fontSize: 11,
              color: t.fg2,
            }}
          >
            <span>
              <strong style={{ color: t.fg1 }}>
                {effectiveAffected.length}
              </strong>{" "}
              conda version{effectiveAffected.length === 1 ? "" : "s"} affected
            </span>
            {adv.cve_ids.length > 0 && (
              <>
                <span style={{ color: t.fg3 }}>·</span>
                <span>{adv.cve_ids.join(", ")}</span>
              </>
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div
          style={{ padding: "0 16px 16px", display: "flex", flexDirection: "column", gap: 14 }}
        >
          {adv.details && (
            <details
              style={{
                background: t.surface2,
                border: `1px solid ${t.border}`,
                borderRadius: 8,
                padding: "8px 12px",
                fontSize: 12,
                color: t.fg2,
              }}
            >
              <summary
                style={{
                  cursor: "pointer",
                  fontSize: 11,
                  fontWeight: 600,
                  color: t.fg1,
                  textTransform: "uppercase",
                  letterSpacing: ".04em",
                }}
              >
                Details
              </summary>
              <div
                style={{
                  marginTop: 8,
                  whiteSpace: "pre-wrap",
                  fontSize: 12.5,
                  lineHeight: 1.5,
                  color: t.fg1,
                }}
              >
                {adv.details}
              </div>
            </details>
          )}

          {adv.osv_ranges.length > 0 && (
            <Section title="Upstream affected ranges" theme={theme}>
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: 4,
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 12,
                  color: t.fg1,
                }}
              >
                {adv.osv_ranges.map((rng, i) => (
                  <div key={i}>
                    <span style={{ color: t.fg3 }}>{rng.type}: </span>
                    {rng.events
                      .map((ev) =>
                        Object.entries(ev as Record<string, string>)
                          .map(([k, v]) => `${k} ${v}`)
                          .join(", "),
                      )
                      .join(" → ")}
                  </div>
                ))}
              </div>
            </Section>
          )}

          <Section
            title={`Conda versions (${effectiveAffected.length} affected)`}
            theme={theme}
            hint="Click a version to flip it in or out of the affected set."
          >
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                gap: 5,
                maxHeight: 200,
                overflowY: "auto",
                padding: 6,
                background: t.surface2,
                border: `1px solid ${t.border}`,
                borderRadius: 8,
              }}
            >
              {adv.affected_conda_versions.length === 0 &&
                eff.version_overrides.affected.length === 0 && (
                  <span
                    style={{ fontSize: 12, fontStyle: "italic", color: t.fg3 }}
                  >
                    OSV ranges didn't intersect any conda version. Use the
                    box below to add specific versions if needed.
                  </span>
                )}
              {adv.affected_conda_versions.map((v) => {
                const removed = eff.version_overrides.not_affected.includes(v);
                return (
                  <VersionChip
                    key={v}
                    theme={theme}
                    version={v}
                    state={removed ? "removed" : "affected"}
                    onClick={() => toggleNotAffected(v)}
                    title={
                      removed
                        ? `Override: not affected. Click to undo.`
                        : `Auto-detected affected. Click to mark as NOT affected.`
                    }
                  />
                );
              })}
              {eff.version_overrides.affected
                .filter((v) => !adv.affected_conda_versions.includes(v))
                .map((v) => (
                  <VersionChip
                    key={v}
                    theme={theme}
                    version={v}
                    state="added"
                    onClick={() => toggleManuallyAffected(v)}
                    title="Manually added. Click to remove."
                  />
                ))}
              <AddVersionInline
                theme={theme}
                onAdd={(v) => toggleManuallyAffected(v)}
              />
            </div>
          </Section>

          <Section title="Review" theme={theme}>
            <div
              style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}
            >
              {REVIEW_STATUSES.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setField("status", s.id)}
                  style={{
                    background: eff.status === s.id ? t.accent : t.surface2,
                    color: eff.status === s.id ? t.accentFg : t.fg1,
                    border: `1px solid ${eff.status === s.id ? t.accent : t.border}`,
                    borderRadius: 6,
                    padding: "5px 10px",
                    fontSize: 12,
                    fontWeight: 600,
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                  }}
                >
                  {s.label}
                </button>
              ))}
            </div>
            <textarea
              value={eff.note}
              onChange={(e) => setField("note", e.target.value)}
              placeholder={
                "Optional note. e.g. 'Conda patches CVE-XXXX in build 1.21.5-py39_2.'"
              }
              style={{
                width: "100%",
                background: t.surface2,
                color: t.fg1,
                border: `1px solid ${t.border}`,
                borderRadius: 8,
                padding: "8px 10px",
                fontSize: 13,
                fontFamily: "Inter, sans-serif",
                outline: "none",
                minHeight: 56,
                resize: "vertical",
              }}
            />
            {baseReview && (
              <div
                style={{
                  fontSize: 11,
                  color: t.fg3,
                  marginTop: 8,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <Glyph name="check" size={11} /> Last reviewed by{" "}
                <strong>@{baseReview.reviewer}</strong>
                {baseReview.reviewed_at &&
                  ` on ${baseReview.reviewed_at.slice(0, 10)}`}
              </div>
            )}
            {isEdited && (
              <div style={{ marginTop: 10, display: "flex", gap: 8 }}>
                <Btn theme={theme} variant="ghost" size="sm" icon="undo" onClick={onReset}>
                  Reset
                </Btn>
              </div>
            )}
          </Section>

          {adv.references.length > 0 && (
            <Section title="References" theme={theme}>
              <ul
                style={{
                  margin: 0,
                  paddingLeft: 18,
                  fontSize: 12,
                  color: t.fg1,
                  display: "flex",
                  flexDirection: "column",
                  gap: 3,
                }}
              >
                {adv.references.slice(0, 8).map((r, i) => (
                  <li key={i}>
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      style={{
                        color: t.link,
                        textDecoration: "none",
                        fontSize: 12,
                        wordBreak: "break-all",
                      }}
                    >
                      {r.url}
                    </a>{" "}
                    <span style={{ color: t.fg3, fontSize: 10.5 }}>
                      [{r.type}]
                    </span>
                  </li>
                ))}
              </ul>
            </Section>
          )}
        </div>
      )}
    </div>
  );
}

function Section({
  title,
  hint,
  theme,
  children,
}: {
  title: string;
  hint?: string;
  theme: Theme;
  children: React.ReactNode;
}) {
  const t = theme.t;
  return (
    <div>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: t.fg2,
          letterSpacing: ".04em",
          textTransform: "uppercase",
          marginBottom: 6,
        }}
      >
        {title}
        {hint && (
          <span
            style={{
              fontWeight: 400,
              textTransform: "none",
              letterSpacing: 0,
              fontSize: 11,
              color: t.fg3,
              marginLeft: 8,
            }}
          >
            {hint}
          </span>
        )}
      </div>
      {children}
    </div>
  );
}

function AddVersionInline({
  theme,
  onAdd,
}: {
  theme: Theme;
  onAdd: (v: string) => void;
}) {
  const t = theme.t;
  const [draft, setDraft] = useState("");
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const v = draft.trim();
        if (v) {
          onAdd(v);
          setDraft("");
        }
      }}
      style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
    >
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        placeholder="+ add version"
        style={{
          background: "transparent",
          color: t.fg1,
          border: `1px dashed ${t.border}`,
          borderRadius: 4,
          padding: "2px 7px",
          fontSize: 11,
          fontFamily: "JetBrains Mono, monospace",
          outline: "none",
          width: 110,
        }}
      />
    </form>
  );
}
