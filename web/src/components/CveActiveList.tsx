import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  advisoryVex,
  bestSeverity,
  cveIds,
  isActiveOnLatest,
  isFutureAffected,
  primaryId,
} from "../data/cves";
import type { Advisory, CvePackage, ReviewEdit } from "../data/cves";
import { Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  packages: CvePackage[];
  edits: Record<string, ReviewEdit>;
  focusedPkg: string | null;
  onSelect: (pkgName: string, advisoryId: string) => void;
};

type Kind = "now" | "future";

type Row = {
  pkg: CvePackage;
  adv: Advisory;
  kind: Kind;
  score: number; // CVSS base score (0 when unknown)
  reviewed: boolean; // has a real VEX status other than under_investigation
};

const SEVERITY_BAND = (
  v: number,
): { label: string; bg: string; fg: string } | null => {
  if (v >= 9.0) return { label: "critical", bg: "#a8201f", fg: "#fff" };
  if (v >= 7.0) return { label: "high", bg: "#d94e1f", fg: "#fff" };
  if (v >= 4.0) return { label: "medium", bg: "#ffd432", fg: "#001d38" };
  if (v > 0) return { label: "low", bg: "#5b9b2c", fg: "#fff" };
  return null;
};

type SeverityFilter = "all" | "critical" | "high+";
type KindFilter = "all" | "now" | "future";

export function CveActiveList({
  theme,
  packages,
  edits,
  focusedPkg,
  onSelect,
}: Props) {
  const t = theme.t;
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<SeverityFilter>("all");
  const [kindFilter, setKindFilter] = useState<KindFilter>("all");
  const [onlyUnreviewed, setOnlyUnreviewed] = useState(true);

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    for (const pkg of packages) {
      for (const adv of pkg.advisories) {
        let kind: Kind | null = null;
        if (isActiveOnLatest(pkg, adv)) kind = "now";
        else if (isFutureAffected(pkg, adv)) kind = "future";
        if (!kind) continue;
        // Editing in-memory takes precedence over the persisted VEX status, so
        // a row the user has already triaged in this session drops out of
        // "unreviewed" immediately.
        const key = `${pkg.package}::${adv.id}`;
        const editStatus = edits[key]?.status;
        const persisted = advisoryVex(adv)?.status;
        const effective = editStatus ?? persisted;
        const reviewed = !!effective && effective !== "under_investigation";
        out.push({
          pkg,
          adv,
          kind,
          score: bestSeverity(adv)?.score_num ?? 0,
          reviewed,
        });
      }
    }
    // Highest severity first; within a tie: shipping now > future > tied;
    // then unreviewed first; then by package name for stable ordering.
    out.sort((a, b) => {
      if (a.score !== b.score) return b.score - a.score;
      if (a.kind !== b.kind) return a.kind === "now" ? -1 : 1;
      if (a.reviewed !== b.reviewed) return a.reviewed ? 1 : -1;
      return a.pkg.package.localeCompare(b.pkg.package);
    });
    return out;
  }, [packages, edits]);

  const counts = useMemo(() => {
    let critical = 0;
    let high = 0;
    let unreviewed = 0;
    let now = 0;
    let future = 0;
    for (const r of rows) {
      if (r.score >= 9.0) critical++;
      if (r.score >= 7.0) high++;
      if (!r.reviewed) unreviewed++;
      if (r.kind === "now") now++;
      else future++;
    }
    return { total: rows.length, critical, high, unreviewed, now, future };
  }, [rows]);

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (sev === "critical" && r.score < 9.0) return false;
      if (sev === "high+" && r.score < 7.0) return false;
      if (kindFilter !== "all" && r.kind !== kindFilter) return false;
      if (onlyUnreviewed && r.reviewed) return false;
      if (ql) {
        const inName = r.pkg.package.toLowerCase().includes(ql);
        const inCve =
          cveIds(r.adv).some((id) => id.toLowerCase().includes(ql)) ||
          r.adv.id.toLowerCase().includes(ql);
        const inSummary = (r.adv.summary || "").toLowerCase().includes(ql);
        if (!inName && !inCve && !inSummary) return false;
      }
      return true;
    });
  }, [rows, q, sev, kindFilter, onlyUnreviewed]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const ROW_H = 68;
  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 8,
  });

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: t.surface,
        borderRight: `1px solid ${t.border}`,
        minWidth: 0,
      }}
    >
      <div
        style={{
          padding: "12px 14px",
          borderBottom: `1px solid ${t.border}`,
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Glyph name="alert" size={15} />
          <div style={{ fontSize: 13, fontWeight: 600, color: t.fg1 }}>
            Active on latest conda-forge
          </div>
          <div
            style={{
              fontSize: 11,
              color: t.fg2,
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {filtered.length.toLocaleString()}{" "}
            <span style={{ color: t.fg3 }}>
              / {counts.total.toLocaleString()}
            </span>
          </div>
        </div>
        <div style={{ fontSize: 11, color: t.fg3, lineHeight: 1.45 }}>
          Advisories shipping on the newest conda-forge build (
          <strong style={{ color: t.fg2 }}>now</strong>) plus ones targeting
          a future version we don't have yet (
          <strong style={{ color: t.fg2 }}>future</strong>) — block them
          before they land.
        </div>

        <div style={{ position: "relative" }}>
          <span
            style={{
              position: "absolute",
              left: 10,
              top: "50%",
              transform: "translateY(-50%)",
              color: t.fg3,
              display: "flex",
            }}
          >
            <Glyph name="search" size={13} />
          </span>
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by name, CVE id, or summary…"
            style={{
              width: "100%",
              background: t.surface2,
              border: `1px solid ${t.border}`,
              borderRadius: 8,
              padding: "7px 10px 7px 30px",
              fontSize: 13,
              fontFamily: "Inter, sans-serif",
              color: t.fg1,
              outline: "none",
            }}
          />
          {q && (
            <button
              onClick={() => setQ("")}
              style={{
                position: "absolute",
                right: 6,
                top: "50%",
                transform: "translateY(-50%)",
                background: "transparent",
                border: 0,
                cursor: "pointer",
                color: t.fg3,
                padding: 4,
              }}
            >
              <Glyph name="close" size={12} />
            </button>
          )}
        </div>

        <div style={{ display: "flex", gap: 5, flexWrap: "wrap" }}>
          <Chip theme={theme} active={sev === "all"} onClick={() => setSev("all")}>
            All <CountTag active={sev === "all"} theme={theme}>{counts.total}</CountTag>
          </Chip>
          <Chip theme={theme} active={sev === "high+"} onClick={() => setSev("high+")}>
            High+ <CountTag active={sev === "high+"} theme={theme}>{counts.high}</CountTag>
          </Chip>
          <Chip
            theme={theme}
            active={sev === "critical"}
            onClick={() => setSev("critical")}
          >
            Critical{" "}
            <CountTag active={sev === "critical"} theme={theme}>{counts.critical}</CountTag>
          </Chip>
          <span style={{ width: 1, background: t.border, margin: "0 3px" }} />
          <Chip
            theme={theme}
            active={kindFilter === "now"}
            onClick={() =>
              setKindFilter(kindFilter === "now" ? "all" : "now")
            }
          >
            Shipping now{" "}
            <CountTag active={kindFilter === "now"} theme={theme}>
              {counts.now}
            </CountTag>
          </Chip>
          <Chip
            theme={theme}
            active={kindFilter === "future"}
            onClick={() =>
              setKindFilter(kindFilter === "future" ? "all" : "future")
            }
          >
            Future version{" "}
            <CountTag active={kindFilter === "future"} theme={theme}>
              {counts.future}
            </CountTag>
          </Chip>
          <span style={{ width: 1, background: t.border, margin: "0 3px" }} />
          <Chip
            theme={theme}
            active={onlyUnreviewed}
            onClick={() => setOnlyUnreviewed(!onlyUnreviewed)}
          >
            Unreviewed only{" "}
            <CountTag active={onlyUnreviewed} theme={theme}>{counts.unreviewed}</CountTag>
          </Chip>
        </div>
      </div>

      <div ref={scrollRef} style={{ flex: 1, overflowY: "auto" }}>
        {filtered.length === 0 ? (
          <div
            style={{
              padding: 30,
              textAlign: "center",
              color: t.fg3,
              fontSize: 12,
            }}
          >
            Nothing to triage.
          </div>
        ) : (
          <div
            style={{
              height: virtualizer.getTotalSize(),
              position: "relative",
              width: "100%",
            }}
          >
            {virtualizer.getVirtualItems().map((vi) => {
              const r = filtered[vi.index];
              const focused =
                focusedPkg === r.pkg.package;
              const band = SEVERITY_BAND(r.score);
              return (
                <div
                  key={`${r.pkg.package}::${r.adv.id}`}
                  onClick={() => onSelect(r.pkg.package, r.adv.id)}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: ROW_H,
                    transform: `translateY(${vi.start}px)`,
                    display: "flex",
                    flexDirection: "column",
                    justifyContent: "center",
                    gap: 4,
                    padding: "8px 14px",
                    borderBottom: `1px solid ${t.border}`,
                    background: focused ? t.rowSelected : "transparent",
                    cursor: "pointer",
                    borderLeft: focused
                      ? `3px solid ${t.accent}`
                      : "3px solid transparent",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      minWidth: 0,
                    }}
                  >
                    {band ? (
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 4,
                          fontSize: 10.5,
                          fontWeight: 700,
                          padding: "2px 7px",
                          borderRadius: 4,
                          background: band.bg,
                          color: band.fg,
                          letterSpacing: ".02em",
                          textTransform: "uppercase",
                          minWidth: 88,
                          justifyContent: "center",
                        }}
                      >
                        {r.score.toFixed(1)} {band.label}
                      </span>
                    ) : (
                      <span
                        style={{
                          fontSize: 10.5,
                          color: t.fg3,
                          minWidth: 88,
                          textAlign: "center",
                        }}
                      >
                        no score
                      </span>
                    )}
                    <code
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 13,
                        fontWeight: 600,
                        color: t.fg1,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {r.pkg.package}
                    </code>
                    <KindBadge theme={theme} kind={r.kind} />
                    <span
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 10.5,
                        color: t.fg3,
                        background: t.inset,
                        padding: "1px 6px",
                        borderRadius: 3,
                      }}
                      title={
                        r.kind === "now"
                          ? "Latest conda-forge version (affected)"
                          : "Latest conda-forge version (not yet affected — newer version is)"
                      }
                    >
                      {r.pkg.latest_version}
                    </span>
                    <code
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 11,
                        color: t.fg2,
                        marginLeft: "auto",
                      }}
                    >
                      {primaryId(r.adv)}
                    </code>
                    {!r.reviewed && (
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: "1px 6px",
                          borderRadius: 3,
                          background: theme.dark ? "#2a2616" : "#fff4d2",
                          color: theme.dark ? "#f5c542" : "#866400",
                          textTransform: "uppercase",
                          letterSpacing: ".02em",
                        }}
                      >
                        Unreviewed
                      </span>
                    )}
                  </div>
                  {r.adv.summary && (
                    <div
                      style={{
                        fontSize: 11.5,
                        color: t.fg2,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {r.adv.summary}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function KindBadge({ theme, kind }: { theme: Theme; kind: Kind }) {
  const styles =
    kind === "now"
      ? {
          bg: theme.dark ? "#2a1818" : "#ffe1d8",
          fg: theme.dark ? "#ff8e6a" : "#a8401b",
          label: "now",
          title: "Active on the newest conda-forge release",
        }
      : {
          bg: theme.dark ? "#1f2a16" : "#fff4d2",
          fg: theme.dark ? "#f5c542" : "#866400",
          label: "future",
          title:
            "Affected version is newer than conda-forge's latest — block before it lands",
        };
  return (
    <span
      title={styles.title}
      style={{
        fontSize: 10,
        fontWeight: 700,
        padding: "1px 6px",
        borderRadius: 3,
        background: styles.bg,
        color: styles.fg,
        textTransform: "uppercase",
        letterSpacing: ".02em",
        fontFamily: "Inter, sans-serif",
      }}
    >
      {styles.label}
    </span>
  );
}

function Chip({
  theme,
  active,
  onClick,
  children,
}: {
  theme: Theme;
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  const t = theme.t;
  return (
    <button
      onClick={onClick}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        background: active ? t.accent : t.surface2,
        color: active ? t.accentFg : t.fg1,
        border: `1px solid ${active ? t.accent : t.border}`,
        borderRadius: 6,
        padding: "3px 8px",
        fontSize: 11.5,
        fontWeight: 600,
        cursor: "pointer",
        fontFamily: "Inter, sans-serif",
      }}
    >
      {children}
    </button>
  );
}

function CountTag({
  theme,
  active,
  children,
}: {
  theme: Theme;
  active: boolean;
  children: React.ReactNode;
}) {
  return (
    <span
      style={{
        fontSize: 10,
        fontWeight: 700,
        fontVariantNumeric: "tabular-nums",
        background: active
          ? "rgba(0,29,56,.15)"
          : theme.dark
            ? "#0a0d11"
            : "#ece8df",
        color: active ? "#001d38" : theme.t.fg2,
        padding: "0 5px",
        borderRadius: 3,
      }}
    >
      {children}
    </span>
  );
}
