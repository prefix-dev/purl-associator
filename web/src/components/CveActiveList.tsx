import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type {
  CveAdvisoryIndex,
  CvePackageIndex,
  ReviewEdit,
} from "../data/cves";
import { Btn, Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  packages: CvePackageIndex[];
  /** Representative package name → every conda package collapsed into it
   *  (including the representative). Lets the header show "shared by N
   *  packages" and the search match hidden variant names. */
  membersByRep: Map<string, string[]>;
  edits: Record<string, ReviewEdit>;
  focusedPkg: string | null;
  focusedAdvisoryId: string | null;
  onNextTriagePackage: (() => void) | null;
  triageRemaining: number;
  enqueuedAdvisories?: Set<string>;
  onBulkEnqueue?: (items: { package: string; advisory_id: string }[]) => void;
  onSelect: (pkgName: string, advisoryId: string) => void;
};

type Kind = "now" | "future";

type Row = {
  pkg: CvePackageIndex;
  adv: CveAdvisoryIndex;
  kind: Kind;
  score: number; // CVSS base score (0 when unknown)
  reviewed: boolean; // has a real VEX status other than under_investigation
};

type Group = {
  pkg: CvePackageIndex;
  rows: Row[]; // filtered rows visible in the list
  worst: number;
  unreviewed: number;
  hasNow: boolean;
};

function downloadCount(pkg: CvePackageIndex): number {
  return pkg.download_count ?? -1;
}

function formatDownloads(count: number | null | undefined): string {
  if (count == null) return "downloads unknown";
  return `${count.toLocaleString()} downloads`;
}

type Item =
  | { type: "header"; group: Group }
  | { type: "row"; group: Group; row: Row };

const HEADER_H = 38;
const ROW_H = 68;

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
  membersByRep,
  edits,
  focusedPkg,
  focusedAdvisoryId,
  onNextTriagePackage,
  triageRemaining,
  enqueuedAdvisories,
  onBulkEnqueue,
  onSelect,
}: Props) {
  const t = theme.t;
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<SeverityFilter>("all");
  const [kindFilter, setKindFilter] = useState<KindFilter>("all");
  const [onlyUnreviewed, setOnlyUnreviewed] = useState(true);

  // Compute all triage-relevant rows once, unfiltered, so totals stay stable.
  const allRows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    for (const pkg of packages) {
      for (const adv of pkg.advisories) {
        let kind: Kind | null = null;
        if (adv.active_now) kind = "now";
        else if (adv.affects_future) kind = "future";
        if (!kind) continue;
        const key = `${pkg.package}::${adv.id}`;
        const editStatus = edits[key]?.status;
        const persisted = adv.vex_status;
        const effective = editStatus ?? persisted;
        const reviewed = !!effective && effective !== "under_investigation";
        out.push({
          pkg,
          adv,
          kind,
          score: adv.severity?.score_num ?? 0,
          reviewed,
        });
      }
    }
    return out;
  }, [packages, edits]);

  const counts = useMemo(() => {
    let critical = 0;
    let high = 0;
    let unreviewed = 0;
    let now = 0;
    let future = 0;
    for (const r of allRows) {
      if (r.score >= 9.0) critical++;
      if (r.score >= 7.0) high++;
      if (!r.reviewed) unreviewed++;
      if (r.kind === "now") now++;
      else future++;
    }
    return { total: allRows.length, critical, high, unreviewed, now, future };
  }, [allRows]);

  const ql = q.trim().toLowerCase();
  const passesFilter = (r: Row): boolean => {
    if (sev === "critical" && r.score < 9.0) return false;
    if (sev === "high+" && r.score < 7.0) return false;
    if (kindFilter !== "all" && r.kind !== kindFilter) return false;
    if (onlyUnreviewed && r.reviewed) return false;
    if (ql) {
      const inName =
        r.pkg.package.toLowerCase().includes(ql) ||
        (membersByRep.get(r.pkg.package) ?? []).some((m) =>
          m.toLowerCase().includes(ql),
        );
      const inCve =
        (r.adv.cve_ids ?? []).some((id) => id.toLowerCase().includes(ql)) ||
        (r.adv.aliases ?? []).some((id) => id.toLowerCase().includes(ql)) ||
        r.adv.id.toLowerCase().includes(ql);
      const inSummary = (r.adv.summary || "").toLowerCase().includes(ql);
      if (!inName && !inCve && !inSummary) return false;
    }
    return true;
  };

  // Group filtered rows by package; drop packages whose rows all got filtered.
  const groups = useMemo<Group[]>(() => {
    const byPkg = new Map<string, Group>();
    for (const r of allRows) {
      if (!passesFilter(r)) continue;
      let g = byPkg.get(r.pkg.package);
      if (!g) {
        g = {
          pkg: r.pkg,
          rows: [],
          worst: 0,
          unreviewed: 0,
          hasNow: false,
        };
        byPkg.set(r.pkg.package, g);
      }
      g.rows.push(r);
      if (r.score > g.worst) g.worst = r.score;
      if (!r.reviewed) g.unreviewed++;
      if (r.kind === "now") g.hasNow = true;
    }
    const out = [...byPkg.values()];
    // Sort rows within a package: severity desc, then now > future, then
    // unreviewed first, then primary id for stability.
    for (const g of out) {
      g.rows.sort((a, b) => {
        if (a.score !== b.score) return b.score - a.score;
        if (a.kind !== b.kind) return a.kind === "now" ? -1 : 1;
        if (a.reviewed !== b.reviewed) return a.reviewed ? 1 : -1;
        return a.adv.primary_id.localeCompare(b.adv.primary_id);
      });
    }
    // Sort packages by popularity first so the default triage path handles
    // high-impact conda-forge packages before obscure ones. Severity and
    // "shipping now" remain tie-breakers, and rows inside a package are still
    // severity-sorted above.
    out.sort((a, b) => {
      const downloads = downloadCount(b.pkg) - downloadCount(a.pkg);
      if (downloads !== 0) return downloads;
      if (a.worst !== b.worst) return b.worst - a.worst;
      if (a.hasNow !== b.hasNow) return a.hasNow ? -1 : 1;
      return a.pkg.package.localeCompare(b.pkg.package);
    });
    return out;
    // We intentionally re-derive on every filter change; the row build above
    // is the expensive part and only depends on packages/edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allRows, ql, sev, kindFilter, onlyUnreviewed]);

  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    for (const g of groups) {
      out.push({ type: "header", group: g });
      for (const r of g.rows) out.push({ type: "row", group: g, row: r });
    }
    return out;
  }, [groups]);

  const visibleRowCount = useMemo(
    () => groups.reduce((sum, g) => sum + g.rows.length, 0),
    [groups],
  );

  const bulkAiCandidates = useMemo(() => {
    const queued = enqueuedAdvisories ?? new Set<string>();
    return groups.flatMap((g) =>
      g.rows
        .filter((r) => !r.reviewed && !queued.has(`${r.pkg.package}::${r.adv.id}`))
        .map((r) => ({ package: r.pkg.package, advisory_id: r.adv.id })),
    );
  }, [groups, enqueuedAdvisories]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (i) => (items[i]?.type === "header" ? HEADER_H : ROW_H),
    overscan: 8,
  });

  // Scroll the focused row into view when the selection changes — e.g. the
  // "Next package" button or PR drawer. Only fires on focus change (items
  // lives behind a ref to avoid re-running on every re-render); only
  // scrolls if the focused row isn't already visible, so clicking an
  // on-screen row doesn't yank the viewport.
  const itemsRef = useRef(items);
  itemsRef.current = items;
  useEffect(() => {
    if (!focusedAdvisoryId) return;
    const list = scrollRef.current;
    if (!list) return;
    const arr = itemsRef.current;
    // Match on (package, advisory) — adv.id alone is not unique across
    // packages: e.g. several airflow-with-* feedstocks share the same
    // upstream GHSA records.
    const idx = arr.findIndex(
      (it) =>
        it.type === "row" &&
        it.row.adv.id === focusedAdvisoryId &&
        it.row.pkg.package === focusedPkg,
    );
    if (idx < 0) return;
    let rowTop = 0;
    let headerTop = 0;
    for (let i = 0; i < idx; i++) {
      if (arr[i].type === "header") headerTop = rowTop;
      rowTop += arr[i].type === "header" ? HEADER_H : ROW_H;
    }
    const rowBottom = rowTop + ROW_H;
    const view = list.scrollTop;
    const viewBottom = view + list.clientHeight;
    if (rowTop < view || rowBottom > viewBottom) {
      // Anchor the package header to the top of the viewport so the user
      // sees the whole group, not just a row floating mid-list.
      list.scrollTo({ top: headerTop, behavior: "auto" });
    }
  }, [focusedAdvisoryId, focusedPkg]);

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
            Triage
          </div>
          <div
            style={{
              fontSize: 11,
              color: t.fg2,
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {visibleRowCount.toLocaleString()}{" "}
            <span style={{ color: t.fg3 }}>
              / {counts.total.toLocaleString()}
            </span>
          </div>
          {onBulkEnqueue && bulkAiCandidates.length > 0 && (
            <span style={{ marginLeft: "auto" }}>
              <Btn
                theme={theme}
                variant="secondary"
                onClick={() => onBulkEnqueue(bulkAiCandidates)}
              >
                🤖 Add visible to AI ({bulkAiCandidates.length})
              </Btn>
            </span>
          )}
          <button
            onClick={() => onNextTriagePackage?.()}
            disabled={!onNextTriagePackage}
            title={
              onNextTriagePackage
                ? `Jump to the next package with unreviewed advisories (${triageRemaining} left)`
                : "Nothing left to triage."
            }
            style={{
              marginLeft: "auto",
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              background: onNextTriagePackage ? t.accent : t.surface2,
              color: onNextTriagePackage ? t.accentFg : t.fg3,
              border: `1px solid ${onNextTriagePackage ? t.accent : t.border}`,
              borderRadius: 6,
              padding: "4px 10px",
              fontSize: 11.5,
              fontWeight: 600,
              cursor: onNextTriagePackage ? "pointer" : "not-allowed",
              fontFamily: "Inter, sans-serif",
            }}
          >
            Next package
            <span style={{ fontSize: 13 }}>→</span>
          </button>
        </div>
        <div style={{ fontSize: 11, color: t.fg3, lineHeight: 1.45 }}>
          Advisories hitting conda-forge's latest build (
          <strong style={{ color: t.fg2 }}>now</strong>) or a version we haven't
          shipped yet (<strong style={{ color: t.fg2 }}>future</strong>), sorted by
          package download count.
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
          <Chip
            theme={theme}
            active={sev === "all"}
            onClick={() => setSev("all")}
          >
            All{" "}
            <CountTag active={sev === "all"} theme={theme}>
              {counts.total}
            </CountTag>
          </Chip>
          <Chip
            theme={theme}
            active={sev === "high+"}
            onClick={() => setSev("high+")}
          >
            High+{" "}
            <CountTag active={sev === "high+"} theme={theme}>
              {counts.high}
            </CountTag>
          </Chip>
          <Chip
            theme={theme}
            active={sev === "critical"}
            onClick={() => setSev("critical")}
          >
            Critical{" "}
            <CountTag active={sev === "critical"} theme={theme}>
              {counts.critical}
            </CountTag>
          </Chip>
          <span style={{ width: 1, background: t.border, margin: "0 3px" }} />
          <Chip
            theme={theme}
            active={kindFilter === "now"}
            onClick={() => setKindFilter(kindFilter === "now" ? "all" : "now")}
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
            <CountTag active={onlyUnreviewed} theme={theme}>
              {counts.unreviewed}
            </CountTag>
          </Chip>
        </div>
      </div>

      <div ref={scrollRef} style={{ flex: 1, overflowY: "auto" }}>
        {items.length === 0 ? (
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
              const it = items[vi.index];
              if (it.type === "header") {
                const focused = focusedPkg === it.group.pkg.package;
                return (
                  <GroupHeader
                    key={`hdr::${it.group.pkg.package}`}
                    theme={theme}
                    group={it.group}
                    variants={membersByRep.get(it.group.pkg.package) ?? []}
                    focused={focused}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: HEADER_H,
                      transform: `translateY(${vi.start}px)`,
                    }}
                    onClick={() =>
                      onSelect(it.group.pkg.package, it.group.rows[0].adv.id)
                    }
                  />
                );
              }
              const r = it.row;
              const inFocusedGroup = focusedPkg === r.pkg.package;
              const focused = inFocusedGroup && focusedAdvisoryId === r.adv.id;
              const band = SEVERITY_BAND(r.score);
              return (
                <div
                  key={`row::${r.pkg.package}::${r.adv.id}`}
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
                    padding: "8px 14px 8px 28px",
                    borderBottom: `1px solid ${t.border}`,
                    background: focused ? t.rowSelected : "transparent",
                    cursor: "pointer",
                    borderLeft: focused
                      ? `3px solid ${t.accent}`
                      : inFocusedGroup
                        ? `3px solid ${t.border}`
                        : "3px solid transparent",
                  }}
                >
                  <div
                    style={{
                      position: "absolute",
                      left: 14,
                      top: 0,
                      bottom: 0,
                      width: 1,
                      background: t.border,
                    }}
                  />
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
                    <KindBadge theme={theme} kind={r.kind} />
                    <code
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 12,
                        fontWeight: 600,
                        color: t.fg1,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {r.adv.primary_id}
                    </code>
                    <span style={{ flex: 1 }} />
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

function GroupHeader({
  theme,
  group,
  variants,
  focused,
  onClick,
  style,
}: {
  theme: Theme;
  group: Group;
  variants: string[];
  focused: boolean;
  onClick: () => void;
  style: React.CSSProperties;
}) {
  const t = theme.t;
  const band = SEVERITY_BAND(group.worst);
  const variantCount = variants.length;
  return (
    <div
      onClick={onClick}
      style={{
        ...style,
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "0 14px",
        background: focused ? t.surface2 : t.inset,
        borderTop: `1px solid ${t.border}`,
        borderBottom: `1px solid ${t.border}`,
        cursor: "pointer",
        borderLeft: focused ? `3px solid ${t.accent}` : "3px solid transparent",
      }}
    >
      <code
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 12.5,
          fontWeight: 700,
          color: t.fg1,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          minWidth: 0,
        }}
      >
        {group.pkg.package}
      </code>
      <span
        style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 10.5,
          color: t.fg3,
        }}
        title="Latest conda-forge version"
      >
        {group.pkg.latest_version}
      </span>
      <span
        style={{
          fontSize: 10.5,
          color: t.fg3,
          fontVariantNumeric: "tabular-nums",
          whiteSpace: "nowrap",
        }}
        title="prefix.dev package download count"
      >
        {formatDownloads(group.pkg.download_count)}
      </span>
      {variantCount > 1 && (
        <span
          style={{
            fontSize: 10,
            fontWeight: 600,
            padding: "1px 6px",
            borderRadius: 3,
            background: t.inset,
            color: t.fg2,
            border: `1px solid ${t.border}`,
            whiteSpace: "nowrap",
          }}
          title={`Same PURL & version as ${variantCount} conda packages — a review here applies to all of them:\n${variants.join("\n")}`}
        >
          ×{variantCount}
        </span>
      )}
      <span style={{ flex: 1 }} />
      {group.hasNow && (
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            padding: "1px 6px",
            borderRadius: 3,
            background: theme.dark ? "#2a1818" : "#ffe1d8",
            color: theme.dark ? "#ff8e6a" : "#a8401b",
            textTransform: "uppercase",
            letterSpacing: ".02em",
          }}
        >
          now
        </span>
      )}
      <span
        style={{
          fontSize: 11,
          color: t.fg2,
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {group.rows.length} advisor{group.rows.length === 1 ? "y" : "ies"}
      </span>
      {band && (
        <span
          style={{
            display: "inline-flex",
            alignItems: "center",
            fontSize: 10.5,
            fontWeight: 700,
            padding: "1px 6px",
            borderRadius: 3,
            background: band.bg,
            color: band.fg,
            letterSpacing: ".02em",
            textTransform: "uppercase",
          }}
          title="Worst CVSS score in this package"
        >
          {group.worst.toFixed(1)}
        </span>
      )}
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
