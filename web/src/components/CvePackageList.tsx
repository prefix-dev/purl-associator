import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { CvePackage, ReviewEdit } from "../data/cves";
import { Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  packages: CvePackage[];
  edits: Record<string, ReviewEdit>;
  focusedId: string | null;
  setFocusedId: (id: string) => void;
  q: string;
  setQ: (v: string) => void;
  statusFilter: "all" | "unreviewed" | "reviewed";
  setStatusFilter: (s: "all" | "unreviewed" | "reviewed") => void;
};

function packageStats(p: CvePackage, edits: Record<string, ReviewEdit>) {
  let unreviewed = 0;
  let confirmed = 0;
  let rejected = 0;
  let notApplicable = 0;
  let editsHere = 0;
  let affectedVersions = 0;
  let unique = new Set<string>();
  for (const adv of p.advisories) {
    const edit = edits[`${p.package}::${adv.id}`];
    const status = edit?.status ?? adv.review?.status;
    if (edit) editsHere++;
    if (!status) unreviewed++;
    else if (status === "confirmed") confirmed++;
    else if (status === "rejected") rejected++;
    else if (status === "not-applicable") notApplicable++;
    else if (status === "needs-review") unreviewed++;
    affectedVersions += adv.affected_conda_versions.length;
    for (const v of adv.affected_conda_versions) unique.add(v);
  }
  return {
    total: p.advisories.length,
    unreviewed,
    confirmed,
    rejected,
    notApplicable,
    editsHere,
    affectedVersions,
    uniqueVersions: unique.size,
  };
}

export function CvePackageList({
  theme,
  packages,
  edits,
  focusedId,
  setFocusedId,
  q,
  setQ,
  statusFilter,
  setStatusFilter,
}: Props) {
  const t = theme.t;

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return packages.filter((p) => {
      if (ql) {
        const inName = p.package.toLowerCase().includes(ql);
        const inCve = p.advisories.some((a) =>
          a.cve_ids.some((id) => id.toLowerCase().includes(ql)) ||
          a.id.toLowerCase().includes(ql) ||
          a.aliases.some((al) => al.toLowerCase().includes(ql)),
        );
        const inSummary = p.advisories.some(
          (a) => (a.summary || "").toLowerCase().includes(ql),
        );
        if (!inName && !inCve && !inSummary) return false;
      }
      if (statusFilter === "all") return true;
      const s = packageStats(p, edits);
      if (statusFilter === "unreviewed") return s.unreviewed > 0;
      if (statusFilter === "reviewed") return s.unreviewed === 0;
      return true;
    });
  }, [packages, q, edits, statusFilter]);

  const counts = useMemo(() => {
    let withUnreviewed = 0;
    let fullyReviewed = 0;
    let totalAdv = 0;
    for (const p of packages) {
      const s = packageStats(p, edits);
      totalAdv += s.total;
      if (s.unreviewed > 0) withUnreviewed++;
      else fullyReviewed++;
    }
    return { all: packages.length, withUnreviewed, fullyReviewed, totalAdv };
  }, [packages, edits]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const ROW_H = 56;
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
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Glyph name="alert" size={15} />
          <div style={{ fontSize: 13, fontWeight: 600, color: t.fg1 }}>
            Packages with advisories
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
              / {packages.length.toLocaleString()}
            </span>
          </div>
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
          <FilterChip
            theme={theme}
            active={statusFilter === "all"}
            onClick={() => setStatusFilter("all")}
          >
            All <Count active={statusFilter === "all"} theme={theme}>{counts.all}</Count>
          </FilterChip>
          <FilterChip
            theme={theme}
            active={statusFilter === "unreviewed"}
            onClick={() => setStatusFilter("unreviewed")}
          >
            Has unreviewed{" "}
            <Count active={statusFilter === "unreviewed"} theme={theme}>
              {counts.withUnreviewed}
            </Count>
          </FilterChip>
          <FilterChip
            theme={theme}
            active={statusFilter === "reviewed"}
            onClick={() => setStatusFilter("reviewed")}
          >
            Fully reviewed{" "}
            <Count active={statusFilter === "reviewed"} theme={theme}>
              {counts.fullyReviewed}
            </Count>
          </FilterChip>
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
            No matches.
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
              const p = filtered[vi.index];
              const focused = focusedId === p.package;
              const s = packageStats(p, edits);
              return (
                <div
                  key={p.package}
                  onClick={() => setFocusedId(p.package)}
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
                    padding: "0 14px",
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
                      {p.package}
                    </code>
                    {s.editsHere > 0 && (
                      <span
                        style={{
                          fontSize: 10,
                          fontWeight: 700,
                          padding: "1px 6px",
                          borderRadius: 3,
                          background: theme.dark ? "#1a2233" : "#e3ecff",
                          color: theme.dark ? "#9aaaff" : "#3957ff",
                        }}
                      >
                        +{s.editsHere}
                      </span>
                    )}
                    <span
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        fontSize: 10.5,
                        color: t.fg3,
                        marginLeft: "auto",
                      }}
                    >
                      {p.purls[0]?.replace(/^pkg:/, "")}
                    </span>
                  </div>
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 6,
                      fontSize: 11,
                      color: t.fg2,
                    }}
                  >
                    <span>
                      <strong style={{ color: t.fg1 }}>{s.total}</strong>{" "}
                      advisor{s.total === 1 ? "y" : "ies"}
                    </span>
                    {s.uniqueVersions > 0 && (
                      <>
                        <span style={{ color: t.fg3 }}>·</span>
                        <span>
                          <strong style={{ color: t.fg1 }}>
                            {s.uniqueVersions}
                          </strong>{" "}
                          affected version{s.uniqueVersions === 1 ? "" : "s"}
                        </span>
                      </>
                    )}
                    {s.unreviewed > 0 && (
                      <span
                        style={{
                          marginLeft: "auto",
                          color: theme.dark ? "#f5c542" : "#866400",
                          fontWeight: 700,
                          fontSize: 10.5,
                        }}
                      >
                        {s.unreviewed} unreviewed
                      </span>
                    )}
                    {s.unreviewed === 0 && s.total > 0 && (
                      <span
                        style={{
                          marginLeft: "auto",
                          color: theme.dark ? "#9adf6d" : "#5b9b2c",
                          fontWeight: 700,
                          fontSize: 10.5,
                        }}
                      >
                        ✓ reviewed
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function FilterChip({
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

function Count({
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
