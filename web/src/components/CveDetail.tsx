import { useMemo, useState } from "react";
import type {
  Advisory,
  AiDraft,
  AiDraftsPayload,
  AiQueuePayload,
  CvePackage,
  ReviewEdit,
  Vex,
  VexJustification,
  VexStatus,
} from "../data/cves";
import {
  VEX_JUSTIFICATIONS,
  VEX_STATUSES,
  advisoryVex,
  affectedVersions,
  bestSeverity,
  cveIds,
  editFromAiDraft,
  editFromVex,
  getAiDraftFor,
  isAdvisoryQueued,
  isEditNonEmpty,
  osvRanges,
  osvUrl,
  primaryId,
} from "../data/cves";
import {
  DraftSelect,
  DraftTextArea,
  DraftTextInput,
  draftClick,
  handleDraftSubmit,
} from "./DraftFields";
import { cvssBaseMetrics } from "../data/cvssMetrics";
import { Btn, Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  pkg: CvePackage | null;
  edits: Record<string, ReviewEdit>;
  onEdit: (advisoryId: string, next: ReviewEdit) => void;
  onResetEdit: (advisoryId: string) => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
  aiDrafts: AiDraftsPayload | null;
  aiQueue: AiQueuePayload | null;
  enqueuedAdvisories: Set<string>;
  onEnqueueAi: (pkg: string, advisoryId: string) => void;
};

function severityLevel(v: number): {
  label: string;
  color: string;
  bg: string;
} | null {
  if (v >= 9.0) return { label: `${v.toFixed(1)} critical`, color: "#fff", bg: "#a8201f" };
  if (v >= 7.0) return { label: `${v.toFixed(1)} high`, color: "#fff", bg: "#d94e1f" };
  if (v >= 4.0) return { label: `${v.toFixed(1)} medium`, color: "#001d38", bg: "#ffd432" };
  if (v > 0) return { label: `${v.toFixed(1)} low`, color: "#fff", bg: "#5b9b2c" };
  return null;
}

function SeverityPill({ adv }: { adv: Advisory }) {
  const severity = bestSeverity(adv);
  if (!severity?.score || severity.score_num == null) return null;
  const lvl = severityLevel(severity.score_num);
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
      title={severity.score}
    >
      {lvl.label}
    </span>
  );
}

function CvssBaseMetricsSection({ adv, theme }: { adv: Advisory; theme: Theme }) {
  const [showNone, setShowNone] = useState(false);
  const metrics = cvssBaseMetrics(bestSeverity(adv));
  if (!metrics) return null;

  const visible = metrics.items.filter((item) => item.value !== "None");
  const none = metrics.items.filter((item) => item.value === "None");
  const shown = showNone ? metrics.items : visible;
  const rows = shown.map((item) => ({
    key: item.metricCode,
    label: item.metric,
    value: item.value,
  }));
  const hiddenNone = none.length > 0 && !showNone;

  return (
    <Section
      title="CVSS base metrics"
      theme={theme}
      hint={metrics.versionLabel}
      hintHref={metrics.metricsUrl}
      action={
        none.length > 0 ? (
          <button
            onClick={() => setShowNone(!showNone)}
            style={{
              background: "transparent",
              border: 0,
              color: theme.t.link,
              padding: 0,
              fontSize: 11,
              fontFamily: "Inter, sans-serif",
              cursor: "pointer",
            }}
          >
            {hiddenNone
              ? `Show ${none.length} none metric${none.length === 1 ? "" : "s"}`
              : `Hide none metric${none.length === 1 ? "" : "s"}`}
          </button>
        ) : undefined
      }
    >
      <KeyValueTable theme={theme} rows={rows} />
    </Section>
  );
}

function ReviewBadge({
  theme,
  status,
  isEdited,
}: {
  theme: Theme;
  status: VexStatus | undefined;
  isEdited: boolean;
}) {
  const map: Record<VexStatus, { label: string; bg: string; fg: string }> = {
    affected: {
      label: "Affected",
      bg: theme.dark ? "#2a1818" : "#ffe1d8",
      fg: theme.dark ? "#ff8e6a" : "#a8401b",
    },
    not_affected: {
      label: "Not affected",
      bg: theme.dark ? "#1a2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    fixed: {
      label: "Fixed",
      bg: theme.dark ? "#1a2a18" : "#ecf5dc",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    under_investigation: {
      label: "Under investigation",
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
  aiDrafts,
  aiQueue,
  enqueuedAdvisories,
  onEnqueueAi,
}: Props) {
  const t = theme.t;

  // PFX-1607: keep the order stable during an editing session. We sort once
  // when the focused package (or its underlying data) changes, using only
  // the *committed* VEX status from the data file — pending ``edits`` in
  // memory deliberately don't participate, otherwise toggling status /
  // version overrides / notes would re-rank the row the user is editing
  // and yank it out from under their cursor. Re-sorting happens naturally
  // when ``pkg`` changes (user picks another package, or data reloads).
  const advisories = useMemo(
    () =>
      pkg
        ? [...pkg.advisories].sort((a, b) => {
            // Prioritize unreviewed, then critical→low severity, then date.
            const ra = advisoryVex(a)?.status;
            const rb = advisoryVex(b)?.status;
            if (!ra && rb) return -1;
            if (ra && !rb) return 1;
            const sevA = bestSeverity(a)?.score;
            const sevB = bestSeverity(b)?.score;
            const sa = sevA
              ? parseFloat(sevA.match(/(\d+\.\d+)/)?.[1] || "0")
              : 0;
            const sb = sevB
              ? parseFloat(sevB.match(/(\d+\.\d+)/)?.[1] || "0")
              : 0;
            if (sa !== sb) return sb - sa;
            return (b.modified || "").localeCompare(a.modified || "");
          })
        : [],
    [pkg],
  );

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
              aiDraft={getAiDraftFor(aiDrafts, pkg.package, adv.id)}
              aiQueued={
                Boolean(isAdvisoryQueued(aiQueue, pkg.package, adv.id)) ||
                enqueuedAdvisories.has(`${pkg.package}::${adv.id}`)
              }
              onEnqueueAi={() => onEnqueueAi(pkg.package, adv.id)}
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
  aiDraft,
  aiQueued,
  onEnqueueAi,
}: {
  theme: Theme;
  pkgName: string;
  adv: Advisory;
  edit: ReviewEdit | undefined;
  onEdit: (next: ReviewEdit) => void;
  onReset: () => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
  aiDraft: AiDraft | undefined;
  aiQueued: boolean;
  onEnqueueAi: () => void;
}) {
  const t = theme.t;
  const [expanded, setExpanded] = useState(true);

  const baseVex: Vex | undefined = advisoryVex(adv);
  const eff: ReviewEdit = edit ?? editFromVex(baseVex);
  const isEdited = !!edit && isEditNonEmpty(eff, baseVex);
  const status: VexStatus | undefined = edit?.status ?? baseVex?.status;

  function setField<K extends keyof ReviewEdit>(key: K, value: ReviewEdit[K]): void {
    onEdit({ ...eff, [key]: value });
  }

  function toggleNotAffected(version: string): void {
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
    const base = new Set(affectedVersions(adv));
    for (const v of eff.version_overrides.not_affected) base.delete(v);
    for (const v of eff.version_overrides.affected) base.add(v);
    return [...base];
  }, [adv, eff.version_overrides]);

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
              href={osvUrl(adv)}
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
              {primaryId(adv)}
            </a>
            {primaryId(adv) !== adv.id && (
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
            <AiChip
              theme={theme}
              aiDraft={aiDraft}
              aiQueued={aiQueued}
              humanReviewed={Boolean(baseVex)}
              onEnqueue={(e) => {
                e.stopPropagation();
                onEnqueueAi();
              }}
            />
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
            {cveIds(adv).length > 0 && (
              <>
                <span style={{ color: t.fg3 }}>·</span>
                <span>{cveIds(adv).join(", ")}</span>
              </>
            )}
          </div>
        </div>
      </div>

      {expanded && (
        <div
          style={{ padding: "0 16px 16px", display: "flex", flexDirection: "column", gap: 14 }}
        >
          {aiDraft && !baseVex && (
            <AiDraftPanel
              theme={theme}
              draft={aiDraft}
              onUseAsStartingPoint={() => {
                if (!isLoggedIn) onRequestLogin();
                onEdit(editFromAiDraft(aiDraft));
              }}
            />
          )}
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

          <CvssBaseMetricsSection adv={adv} theme={theme} />

          {osvRanges(adv).length > 0 && (
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
                {osvRanges(adv).map((rng, i) => (
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
              {affectedVersions(adv).length === 0 &&
                eff.version_overrides.affected.length === 0 && (
                  <span
                    style={{ fontSize: 12, fontStyle: "italic", color: t.fg3 }}
                  >
                    OSV ranges didn't intersect any conda version. Use the
                    box below to add specific versions if needed.
                  </span>
                )}
              {affectedVersions(adv).map((v) => {
                const removed = eff.version_overrides.not_affected.includes(v);
                return (
                  <VersionChip
                    key={v}
                    theme={theme}
                    version={v}
                    state={removed ? "removed" : "affected"}
                    onClick={draftClick(() => toggleNotAffected(v))}
                    title={
                      removed
                        ? `Override: not affected. Click to undo.`
                        : `Auto-detected affected. Click to mark as NOT affected.`
                    }
                  />
                );
              })}
              {eff.version_overrides.affected
                .filter((v) => !affectedVersions(adv).includes(v))
                .map((v) => (
                  <VersionChip
                    key={v}
                    theme={theme}
                    version={v}
                    state="added"
                    onClick={draftClick(() => toggleManuallyAffected(v))}
                    title="Manually added. Click to remove."
                  />
                ))}
              <AddVersionInline
                theme={theme}
                onAdd={(v) => toggleManuallyAffected(v)}
              />
            </div>
          </Section>

          <Section title="VEX review" theme={theme}>
            <div
              style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}
            >
              {VEX_STATUSES.map((s) => (
                <button
                  key={s.id}
                  onClick={draftClick(() => setField("status", s.id))}
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
            {eff.status === "not_affected" && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: t.fg2, marginBottom: 4 }}>
                  VEX justification{" "}
                  <span style={{ color: t.fg3 }}>
                    — required for a “not affected” claim
                  </span>
                </div>
                <DraftSelect
                  value={eff.justification}
                  onDraftChange={(justification) =>
                    setField("justification", justification as VexJustification)
                  }
                  style={{
                    width: "100%",
                    background: t.surface2,
                    color: t.fg1,
                    border: `1px solid ${t.border}`,
                    borderRadius: 8,
                    padding: "7px 10px",
                    fontSize: 13,
                    fontFamily: "Inter, sans-serif",
                    outline: "none",
                  }}
                >
                  {VEX_JUSTIFICATIONS.map((j) => (
                    <option key={j.id} value={j.id}>
                      {j.label}
                    </option>
                  ))}
                </DraftSelect>
              </div>
            )}
            {eff.status === "affected" && (
              <DraftTextInput
                value={eff.action_statement}
                onDraftChange={(action) => setField("action_statement", action)}
                placeholder="Action statement — e.g. 'Upgrade to requests ≥ 2.32.4.'"
                theme={theme}
                style={{ background: t.surface2, marginBottom: 10 }}
              />
            )}
            <DraftTextArea
              value={eff.notes}
              onDraftChange={(notes) => setField("notes", notes)}
              placeholder={
                "Optional status note. e.g. 'Conda patches CVE-XXXX in build 1.21.5-py39_2.'"
              }
              theme={theme}
              style={{ background: t.surface2, minHeight: 56 }}
            />
            {baseVex?.author && (
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
                <strong>@{baseVex.author}</strong>
                {baseVex.reviewed_at &&
                  ` on ${baseVex.reviewed_at.slice(0, 10)}`}
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

          {(adv.references ?? []).length > 0 && (
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
                {(adv.references ?? []).slice(0, 8).map((r, i) => (
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

function KeyValueTable({
  theme,
  rows,
}: {
  theme: Theme;
  rows: { key: string; label: React.ReactNode; value: React.ReactNode }[];
}) {
  const t = theme.t;
  return (
    <div
      style={{
        border: `1px solid ${t.border}`,
        borderRadius: 8,
        overflow: "hidden",
        background: t.surface2,
      }}
    >
      {rows.map((row, index) => (
        <div
          key={row.key}
          style={{
            display: "grid",
            gridTemplateColumns: "minmax(180px, 1fr) minmax(140px, 1fr)",
            gap: 12,
            alignItems: "center",
            padding: "7px 10px",
            borderTop: index === 0 ? 0 : `1px solid ${t.border}`,
            fontSize: 12,
          }}
        >
          <div style={{ color: t.fg2 }}>{row.label}</div>
          <div style={{ color: t.fg1, fontWeight: 600 }}>{row.value}</div>
        </div>
      ))}
    </div>
  );
}

function Section({
  title,
  hint,
  hintHref,
  action,
  theme,
  children,
}: {
  title: string;
  hint?: string;
  hintHref?: string;
  action?: React.ReactNode;
  theme: Theme;
  children: React.ReactNode;
}) {
  const t = theme.t;
  return (
    <div>
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          gap: 8,
          marginBottom: 6,
        }}
      >
        <div
          style={{
            fontSize: 11,
            fontWeight: 600,
            color: t.fg2,
            letterSpacing: ".04em",
            textTransform: "uppercase",
          }}
        >
          {title}
          {hint &&
            (hintHref ? (
              <a
                href={hintHref}
                target="_blank"
                rel="noreferrer"
                style={{
                  fontWeight: 400,
                  textTransform: "none",
                  letterSpacing: 0,
                  fontSize: 11,
                  color: t.link,
                  marginLeft: 8,
                  textDecoration: "none",
                }}
                title="Open CVSS base metrics documentation"
              >
                {hint}
              </a>
            ) : (
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
            ))}
        </div>
        {action && <div style={{ marginLeft: "auto" }}>{action}</div>}
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
      onSubmit={(e) =>
        handleDraftSubmit(e, () => {
          const v = draft.trim();
          if (v) {
            onAdd(v);
            setDraft("");
          }
        })
      }
      style={{ display: "inline-flex", alignItems: "center", gap: 4 }}
    >
      <DraftTextInput
        value={draft}
        onDraftChange={setDraft}
        placeholder="+ add version"
        theme={theme}
        mono
        style={{ 
          background: "transparent",
          border: `1px dashed ${t.border}`,
          borderRadius: 4,
          padding: "2px 7px",
          fontSize: 11,
          width: 110,
        }}
      />
    </form>
  );
}

/* ------------ AI CVE review (drafts + queue) ------------ */

function AiChip({
  theme,
  aiDraft,
  aiQueued,
  humanReviewed,
  onEnqueue,
}: {
  theme: Theme;
  aiDraft: AiDraft | undefined;
  aiQueued: boolean;
  humanReviewed: boolean;
  onEnqueue: (e: React.MouseEvent) => void;
}) {
  const t = theme.t;
  // Priority: human review > AI draft > queued > "Ask AI" button.
  if (humanReviewed) return null;
  if (aiDraft) {
    return (
      <span
        title={`AI draft (${aiDraft.model})`}
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 4,
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
        🤖 AI draft
      </span>
    );
  }
  if (aiQueued) {
    return (
      <span
        title="Queued for AI review — drafts appear after the next cve_ai_review run."
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 4,
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
        ⏳ AI queued
      </span>
    );
  }
  return (
    <button
      onClick={onEnqueue}
      title="Ask Claude to assess this advisory's coverage and runtime applicability."
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        fontSize: 10.5,
        fontWeight: 600,
        padding: "2px 7px",
        borderRadius: 4,
        background: "transparent",
        color: t.fg2,
        border: `1px dashed ${t.border}`,
        textTransform: "uppercase",
        letterSpacing: ".02em",
        cursor: "pointer",
      }}
    >
      🤖 Ask AI
    </button>
  );
}

function AiDraftPanel({
  theme,
  draft,
  onUseAsStartingPoint,
}: {
  theme: Theme;
  draft: AiDraft;
  onUseAsStartingPoint: () => void;
}) {
  const t = theme.t;
  const af = draft.affected_versions;
  const rt = draft.runtime_applicability;
  const sev = draft.severity_in_conda_context;
  return (
    <div
      style={{
        background: theme.dark ? "#1a2233" : "#f1f5ff",
        border: `1px solid ${theme.dark ? "#2a3a55" : "#c2d0fb"}`,
        borderRadius: 8,
        padding: 12,
        fontSize: 12,
        color: t.fg1,
        display: "flex",
        flexDirection: "column",
        gap: 8,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <strong style={{ fontSize: 12 }}>🤖 AI draft assessment</strong>
        <span style={{ color: t.fg3, fontSize: 11 }}>
          {draft.model} · {(draft.generated_at || "").slice(0, 10)}
        </span>
        <span style={{ flex: 1 }} />
        <Btn theme={theme} variant="primary" onClick={onUseAsStartingPoint}>
          Use as starting point
        </Btn>
      </div>

      {/* The headline reasoning — what the maintainer reads first. Rendered
          full-width with body-size text and the panel's primary fg color so
          it doesn't disappear under the per-dimension micro-reasonings. */}
      <div
        style={{
          fontSize: 13,
          color: t.fg1,
          lineHeight: 1.5,
          padding: "10px 12px",
          background: theme.dark ? "#11192a" : "#ffffff",
          border: `1px solid ${theme.dark ? "#243150" : "#d6deef"}`,
          borderRadius: 6,
          whiteSpace: "pre-wrap",
        }}
      >
        <div
          style={{
            fontSize: 10.5,
            fontWeight: 700,
            textTransform: "uppercase",
            letterSpacing: ".04em",
            color: theme.dark ? "#9aaaff" : "#3957ff",
            marginBottom: 6,
          }}
        >
          Why the AI accepts this
        </div>
        {draft.rationale ||
          "(AI did not provide a rationale; treat the per-dimension reasoning below as the only narrative.)"}
      </div>

      <div style={{ color: t.fg2 }}>
        Proposed status:{" "}
        <strong style={{ color: t.fg1 }}>{draft.openvex_status}</strong>
        {draft.openvex_justification && <> · {draft.openvex_justification}</>}
      </div>
      {draft.openvex_action_statement && (
        <div style={{ color: t.fg2 }}>
          <strong style={{ color: t.fg1 }}>Action:</strong>{" "}
          {draft.openvex_action_statement}
        </div>
      )}
      <DraftDimension
        theme={theme}
        title="Affected versions"
        valueLabel={af.agrees_with_match ? "agrees with auto match" : "disagrees"}
        reasoning={af.reasoning}
        extra={
          (af.suggested_adds ?? []).length || (af.suggested_removes ?? []).length ? (
            <>
              {(af.suggested_adds ?? []).length > 0 && (
                <div>+ {af.suggested_adds!.join(", ")}</div>
              )}
              {(af.suggested_removes ?? []).length > 0 && (
                <div>− {af.suggested_removes!.join(", ")}</div>
              )}
            </>
          ) : null
        }
      />
      <DraftDimension
        theme={theme}
        title="Runtime applicability"
        valueLabel={rt.applies}
        reasoning={rt.reasoning}
      />
      <DraftDimension
        theme={theme}
        title="Severity in conda context"
        valueLabel={sev.assessment}
        reasoning={sev.reasoning}
      />
      {draft.notes && (
        <DraftDimension
          theme={theme}
          title="Notes"
          valueLabel=""
          reasoning={draft.notes}
        />
      )}
      <div style={{ fontSize: 10.5, color: t.fg3, marginTop: 4 }}>
        This is a draft, not authoritative. Click "Use as starting point" to seed the
        OpenVEX form below, edit if needed, then submit via the Review changes drawer.
      </div>
    </div>
  );
}

function DraftDimension({
  theme,
  title,
  valueLabel,
  reasoning,
  extra,
}: {
  theme: Theme;
  title: string;
  valueLabel: string;
  reasoning: string;
  extra?: React.ReactNode;
}) {
  const t = theme.t;
  return (
    <div>
      <div
        style={{
          fontSize: 10.5,
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: ".04em",
          color: t.fg2,
        }}
      >
        {title}
        {valueLabel ? (
          <>
            {" — "}
            <span style={{ color: t.fg1 }}>{valueLabel}</span>
          </>
        ) : null}
      </div>
      <div style={{ color: t.fg1, marginTop: 2, lineHeight: 1.45 }}>
        {reasoning}
      </div>
      {extra && <div style={{ marginTop: 4, color: t.fg2 }}>{extra}</div>}
    </div>
  );
}
