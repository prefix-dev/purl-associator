import type { SbomDetailPayload, SbomSummaryEntry } from "../data/sboms";
import type { PackageEntry } from "../data/types";
import { Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  pkg: PackageEntry | null;
  summary?: SbomSummaryEntry | null;
  detail?: SbomDetailPayload | null;
};

export function DeepInspectionPanel({ theme, pkg, summary, detail }: Props) {
  const t = theme.t;
  const expected = pkg?.deep_inspection;
  const panelSummary = summary ?? null;
  const hasCandidate = Boolean(expected?.candidate || panelSummary);

  return (
    <aside
      style={{
        flex: 1,
        minWidth: 0,
        background: t.page,
        borderLeft: `1px solid ${t.border}`,
        overflowY: "auto",
      }}
    >
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 4,
          background: t.surface,
          borderBottom: `1px solid ${t.border}`,
          padding: "14px 18px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Glyph name="db" size={15} />
          <h2
            style={{
              margin: 0,
              fontFamily: "Moranga, serif",
              fontWeight: 300,
              fontSize: 22,
              color: t.fg1,
              lineHeight: 1.15,
            }}
          >
            Deep inspections
          </h2>
        </div>
        {pkg && (
          <div
            style={{
              marginTop: 6,
              color: t.fg2,
              fontSize: 12,
              fontFamily: "JetBrains Mono, monospace",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {pkg.name}
          </div>
        )}
      </div>

      <div style={{ padding: 18 }}>
        {!pkg && <EmptyState theme={theme} label="No package selected" />}

        {pkg && !hasCandidate && (
          <EmptyState theme={theme} label="No Rust or Go compiler signals" />
        )}

        {pkg && hasCandidate && !panelSummary && (
          <CandidateCard theme={theme} expected={expected ?? null} />
        )}

        {panelSummary && (
          <SbomSection
            theme={theme}
            summary={panelSummary}
            detail={detail ?? null}
          />
        )}
      </div>
    </aside>
  );
}

function EmptyState({ theme, label }: { theme: Theme; label: string }) {
  return (
    <div
      style={{
        padding: 18,
        color: theme.t.fg3,
        fontSize: 12,
        textAlign: "center",
        border: `1px dashed ${theme.t.border}`,
        borderRadius: 8,
        background: theme.t.surface,
      }}
    >
      {label}
    </div>
  );
}

function CandidateCard({
  theme,
  expected,
}: {
  theme: Theme;
  expected: PackageEntry["deep_inspection"] | null;
}) {
  const t = theme.t;
  return (
    <div
      style={{
        background: t.surface,
        border: `1px solid ${t.border}`,
        borderRadius: 8,
        padding: 12,
        display: "flex",
        flexDirection: "column",
        gap: 10,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Glyph name="refresh" size={14} />
        <strong style={{ fontSize: 13, color: t.fg1 }}>
          Scan candidate
        </strong>
      </div>
      {expected?.ecosystems && (
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {expected.ecosystems.map((e) => (
            <MiniPill key={e} theme={theme} label={ecosystemLabel(e)} />
          ))}
        </div>
      )}
      {expected?.warning && <Warning theme={theme}>{expected.warning}</Warning>}
      {expected?.signals && expected.signals.length > 0 && (
        <SignalList theme={theme} signals={expected.signals} />
      )}
    </div>
  );
}

function SbomSection({
  theme,
  summary,
  detail,
}: {
  theme: Theme;
  summary: SbomSummaryEntry;
  detail: SbomDetailPayload | null;
}) {
  const t = theme.t;
  const hasCves = summary.advisory_count > 0;
  const status = summary.status ?? "ok";
  const hasSbom = status === "ok";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div
        style={{
          display: "flex",
          gap: 10,
          alignItems: "center",
          padding: 12,
          background: t.surface,
          border: `1px solid ${t.border}`,
          borderRadius: 8,
          flexWrap: "wrap",
        }}
      >
        <Glyph name={hasSbom ? "db" : "alert"} size={16} />
        <div style={{ fontSize: 13, color: t.fg1 }}>
          {hasSbom ? (
            <>
              <strong>{summary.component_count}</strong> components /{" "}
              <span style={{ color: t.fg2 }}>
                {ecosystemLabel(summary.ecosystem)}
              </span>
            </>
          ) : (
            <strong>{statusLabel(status)}</strong>
          )}
        </div>
        <div style={{ flex: 1 }} />
        {hasSbom &&
          (hasCves ? (
            <SbomPill
              theme={theme}
              tone="red"
              label={`${summary.advisory_count} advisories`}
              sub={`across ${summary.vulnerable_component_count} components`}
            />
          ) : (
            <SbomPill theme={theme} tone="green" label="No transitive CVEs" />
          ))}
      </div>

      {summary.warning && <Warning theme={theme}>{summary.warning}</Warning>}

      {summary.signals && summary.signals.length > 0 && (
        <SignalList theme={theme} signals={summary.signals} />
      )}

      {hasCves && detail && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 8,
          }}
        >
          {detail.advisories.slice(0, 60).map((a) => (
            <SbomAdvisoryRow key={a.advisory_id} theme={theme} advisory={a} />
          ))}
          {detail.advisories.length > 60 && (
            <div
              style={{
                fontSize: 12,
                color: t.fg3,
                padding: "4px 12px",
                textAlign: "center",
              }}
            >
              ... and {detail.advisories.length - 60} more
            </div>
          )}
        </div>
      )}

      {hasCves && !detail && (
        <div style={{ fontSize: 12, color: t.fg3, padding: "8px 12px" }}>
          Loading advisory detail...
        </div>
      )}
    </div>
  );
}

function Warning({ theme, children }: { theme: Theme; children: string }) {
  return (
    <div
      style={{
        padding: "9px 10px",
        background: theme.dark ? "#2a2616" : "#fff7d6",
        border: `1px solid ${theme.dark ? "#3a3416" : "#f0e2a3"}`,
        borderRadius: 8,
        color: theme.t.fg1,
        display: "flex",
        alignItems: "flex-start",
        gap: 8,
        fontSize: 12,
        lineHeight: 1.4,
      }}
    >
      <span style={{ color: theme.t.warn, display: "flex", marginTop: 2 }}>
        <Glyph name="info" size={12} />
      </span>
      <span>{children}</span>
    </div>
  );
}

function SignalList({ theme, signals }: { theme: Theme; signals: string[] }) {
  return (
    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
      {signals.slice(0, 8).map((signal) => (
        <MiniPill key={signal} theme={theme} label={signal} />
      ))}
    </div>
  );
}

function MiniPill({ theme, label }: { theme: Theme; label: string }) {
  return (
    <span
      title={label}
      style={{
        maxWidth: "100%",
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        border: `1px solid ${theme.t.border}`,
        background: theme.t.surface2,
        color: theme.t.fg2,
        borderRadius: 4,
        padding: "2px 6px",
        fontSize: 11,
      }}
    >
      {label}
    </span>
  );
}

function SbomPill({
  theme,
  tone,
  label,
  sub,
}: {
  theme: Theme;
  tone: "red" | "green";
  label: string;
  sub?: string;
}) {
  const palette =
    tone === "red"
      ? {
          bg: theme.dark ? "#3a0d14" : "#fdecef",
          fg: theme.dark ? "#ffb3bc" : "#a8112a",
        }
      : {
          bg: theme.dark ? "#0e3b1f" : "#e6f6ec",
          fg: theme.dark ? "#7ed3a3" : "#0d6b34",
        };
  return (
    <div
      style={{
        background: palette.bg,
        color: palette.fg,
        border: `1px solid ${palette.fg}33`,
        borderRadius: 999,
        padding: "4px 10px",
        fontSize: 11,
        fontWeight: 600,
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      <span>{label}</span>
      {sub && <span style={{ color: theme.t.fg3, fontWeight: 400 }}>/ {sub}</span>}
    </div>
  );
}

function severityBand(score?: number): { label: string; color: string } | null {
  if (score == null) return null;
  if (score >= 9) return { label: "critical", color: "#a8112a" };
  if (score >= 7) return { label: "high", color: "#c9461c" };
  if (score >= 4) return { label: "medium", color: "#a87a00" };
  return { label: "low", color: "#7a7a7a" };
}

function SbomAdvisoryRow({
  theme,
  advisory,
}: {
  theme: Theme;
  advisory: SbomDetailPayload["advisories"][number];
}) {
  const t = theme.t;
  const score = advisory.severity?.find((s) => s.score_num != null)?.score_num;
  const band = severityBand(score);
  return (
    <div
      style={{
        padding: "10px 12px",
        background: t.surface,
        border: `1px solid ${t.border}`,
        borderRadius: 8,
        display: "flex",
        flexDirection: "column",
        gap: 6,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          flexWrap: "wrap",
        }}
      >
        <a
          href={`https://osv.dev/vulnerability/${advisory.advisory_id}`}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: 12,
            color: t.link,
            textDecoration: "none",
          }}
        >
          {advisory.primary_id}
        </a>
        {band && (
          <span
            style={{
              fontSize: 10,
              fontWeight: 700,
              textTransform: "uppercase",
              color: band.color,
              border: `1px solid ${band.color}55`,
              borderRadius: 4,
              padding: "1px 5px",
            }}
          >
            {band.label}
            {score != null && (
              <span style={{ fontWeight: 400, marginLeft: 4 }}>
                {score.toFixed(1)}
              </span>
            )}
          </span>
        )}
        {advisory.components.map((c) => (
          <code
            key={c.purl}
            title={c.purl}
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 11,
              color: t.fg2,
              background: t.surface2,
              border: `1px solid ${t.border}`,
              borderRadius: 4,
              padding: "1px 5px",
              maxWidth: "100%",
              overflow: "hidden",
              textOverflow: "ellipsis",
            }}
          >
            {c.name}@{c.version}
          </code>
        ))}
      </div>
      {advisory.summary && (
        <div style={{ fontSize: 12, color: t.fg2, lineHeight: 1.4 }}>
          {advisory.summary}
        </div>
      )}
    </div>
  );
}

function ecosystemLabel(ecosystem: string | undefined | null): string {
  if (ecosystem === "cargo") return "Rust (cargo-auditable)";
  if (ecosystem === "golang") return "Go (buildinfo)";
  return ecosystem || "unknown";
}

function statusLabel(status: string): string {
  if (status === "no-sbom") return "No embedded SBOM found";
  if (status === "no-paths-json") return "Could not inspect package paths";
  if (status === "error") return "Inspection failed";
  return status;
}
