import { useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Edit, PackageEntry } from "../data/types";
import { ECOSYSTEMS } from "../data/loader";
import { EcosystemChip, Glyph, StatusPill, Theme } from "./Primitives";

export type SortKey = "name" | "version" | "ecosystem" | "purl" | "status";
export type SortDir = "asc" | "desc";

type Filters = {
  unmappedOnly: boolean;
  unverifiedOnly: boolean;
  ecosystem: string;
};

type Props = {
  theme: Theme;
  packages: PackageEntry[];
  edits: Record<string, Edit>;
  selectedSet: Set<string>;
  setSelectedSet: (s: Set<string>) => void;
  focusedId: string | null;
  setFocusedId: (id: string | null) => void;
  q: string;
  setQ: (v: string) => void;
  filters: Filters;
  setFilters: (f: Filters) => void;
};

function effectiveStatus(p: PackageEntry, edits: Record<string, Edit>): string {
  if (edits[p.name]) return "edited";
  if (p.purl === null || p.status === "unmapped") return "unmapped";
  return p.status;
}

function effectivePurl(p: PackageEntry, edits: Record<string, Edit>): string {
  return edits[p.name]?.purl ?? p.purl ?? "";
}

function effectiveType(p: PackageEntry, edits: Record<string, Edit>): string {
  return edits[p.name]?.type ?? p.type ?? "none";
}

const STATUS_RANK: Record<string, number> = {
  edited: 0,
  unmapped: 1,
  "auto-unverified": 2,
  verified: 3,
};

export function PackageTable({
  theme,
  packages,
  edits,
  selectedSet,
  setSelectedSet,
  focusedId,
  setFocusedId,
  q,
  setQ,
  filters,
  setFilters,
}: Props) {
  const t = theme.t;
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const lastClickedRef = useRef<string | null>(null);

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    const out = packages.filter((p) => {
      if (
        filters.unmappedOnly &&
        p.status !== "unmapped" &&
        p.purl !== null &&
        !edits[p.name]?.unmapped
      )
        return false;
      if (
        filters.unverifiedOnly &&
        p.status === "verified" &&
        !edits[p.name]
      )
        return false;
      if (
        filters.ecosystem &&
        filters.ecosystem !== "all" &&
        (p.type ?? "none") !== filters.ecosystem
      )
        return false;
      if (!ql) return true;
      const purl = edits[p.name]?.purl ?? p.purl ?? "";
      return (
        p.name.toLowerCase().includes(ql) || purl.toLowerCase().includes(ql)
      );
    });

    const dir = sortDir === "asc" ? 1 : -1;
    out.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "name":
          cmp = a.name.localeCompare(b.name);
          break;
        case "version":
          cmp = a.version.localeCompare(b.version, undefined, { numeric: true });
          break;
        case "ecosystem":
          cmp = effectiveType(a, edits).localeCompare(effectiveType(b, edits));
          break;
        case "purl":
          cmp = effectivePurl(a, edits).localeCompare(effectivePurl(b, edits));
          break;
        case "status":
          cmp =
            (STATUS_RANK[effectiveStatus(a, edits)] ?? 99) -
            (STATUS_RANK[effectiveStatus(b, edits)] ?? 99);
          break;
      }
      return cmp * dir;
    });
    return out;
  }, [packages, q, filters, edits, sortKey, sortDir]);

  const counts = useMemo(() => {
    const c = {
      all: packages.length,
      unmapped: 0,
      unverified: 0,
      verified: 0,
      edited: Object.keys(edits).length,
    };
    for (const p of packages) {
      if (p.status === "unmapped" || p.purl === null) c.unmapped++;
      else if (p.status === "auto-unverified") c.unverified++;
      else if (p.status === "verified") c.verified++;
    }
    return c;
  }, [packages, edits]);

  // Virtualizer
  const scrollRef = useRef<HTMLDivElement>(null);
  const ROW_H = 38;
  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_H,
    overscan: 8,
  });

  function onSort(key: SortKey): void {
    if (sortKey === key) setSortDir(sortDir === "asc" ? "desc" : "asc");
    else {
      setSortKey(key);
      setSortDir("asc");
    }
  }

  function selectOnly(name: string): void {
    setSelectedSet(new Set([name]));
    setFocusedId(name);
    lastClickedRef.current = name;
  }

  function toggleOne(name: string): void {
    const next = new Set(selectedSet);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    setSelectedSet(next);
    setFocusedId(name);
    lastClickedRef.current = name;
  }

  function selectRange(name: string): void {
    if (!lastClickedRef.current) {
      selectOnly(name);
      return;
    }
    const last = lastClickedRef.current;
    const ai = filtered.findIndex((p) => p.name === last);
    const bi = filtered.findIndex((p) => p.name === name);
    if (ai === -1 || bi === -1) {
      selectOnly(name);
      return;
    }
    const [lo, hi] = ai < bi ? [ai, bi] : [bi, ai];
    const next = new Set(selectedSet);
    for (let i = lo; i <= hi; i++) next.add(filtered[i].name);
    setSelectedSet(next);
    setFocusedId(name);
  }

  function handleRowClick(e: React.MouseEvent, name: string): void {
    if (e.metaKey || e.ctrlKey) toggleOne(name);
    else if (e.shiftKey) selectRange(name);
    else selectOnly(name);
  }

  function toggleAllVisible(): void {
    const allVisible = filtered.every((p) => selectedSet.has(p.name));
    const next = new Set(selectedSet);
    if (allVisible) {
      for (const p of filtered) next.delete(p.name);
    } else {
      for (const p of filtered) next.add(p.name);
    }
    setSelectedSet(next);
  }

  const allVisibleSelected =
    filtered.length > 0 && filtered.every((p) => selectedSet.has(p.name));
  const someVisibleSelected =
    !allVisibleSelected && filtered.some((p) => selectedSet.has(p.name));

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
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Glyph name="db" size={15} />
            <div style={{ fontSize: 13, fontWeight: 600, color: t.fg1 }}>
              Packages
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
              {selectedSet.size > 0 && (
                <span style={{ color: t.link, marginLeft: 8 }}>
                  · {selectedSet.size} selected
                </span>
              )}
            </div>
          </div>
          {selectedSet.size > 0 && (
            <button
              onClick={() => setSelectedSet(new Set())}
              style={{
                background: "transparent",
                border: 0,
                color: t.fg2,
                fontSize: 11,
                cursor: "pointer",
                padding: 0,
              }}
            >
              clear selection
            </button>
          )}
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
            placeholder="Search by conda name or PURL…"
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
            active={!filters.unmappedOnly && !filters.unverifiedOnly}
            onClick={() =>
              setFilters({ ...filters, unmappedOnly: false, unverifiedOnly: false })
            }
          >
            All <Count active={false} theme={theme}>{counts.all}</Count>
          </FilterChip>
          <FilterChip
            theme={theme}
            active={filters.unmappedOnly}
            onClick={() =>
              setFilters({
                ...filters,
                unmappedOnly: !filters.unmappedOnly,
                unverifiedOnly: false,
              })
            }
          >
            Unmapped{" "}
            <Count active={filters.unmappedOnly} theme={theme}>
              {counts.unmapped}
            </Count>
          </FilterChip>
          <FilterChip
            theme={theme}
            active={filters.unverifiedOnly}
            onClick={() =>
              setFilters({
                ...filters,
                unverifiedOnly: !filters.unverifiedOnly,
                unmappedOnly: false,
              })
            }
          >
            Unverified{" "}
            <Count active={filters.unverifiedOnly} theme={theme}>
              {counts.unverified}
            </Count>
          </FilterChip>

          <select
            value={filters.ecosystem}
            onChange={(e) =>
              setFilters({ ...filters, ecosystem: e.target.value })
            }
            style={{
              background: t.surface2,
              color: t.fg1,
              border: `1px solid ${t.border}`,
              borderRadius: 6,
              padding: "3px 8px",
              fontSize: 11.5,
              fontFamily: "Inter, sans-serif",
              cursor: "pointer",
              outline: "none",
              marginLeft: "auto",
            }}
          >
            <option value="all">All ecosystems</option>
            {ECOSYSTEMS.map((e) => (
              <option key={e.id} value={e.id}>
                {e.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Column header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns:
            "32px minmax(180px, 1fr) 70px 110px minmax(220px, 2fr) 100px",
          gap: 8,
          padding: "6px 14px",
          borderBottom: `1px solid ${t.border}`,
          background: t.surface2,
          fontSize: 10.5,
          fontWeight: 600,
          letterSpacing: ".05em",
          textTransform: "uppercase",
          color: t.fg2,
          alignItems: "center",
        }}
      >
        <input
          type="checkbox"
          checked={allVisibleSelected}
          ref={(el) => {
            if (el) el.indeterminate = someVisibleSelected;
          }}
          onChange={toggleAllVisible}
          style={{ accentColor: t.accent, cursor: "pointer" }}
        />
        <SortHeader
          theme={theme}
          label="Name"
          col="name"
          activeKey={sortKey}
          dir={sortDir}
          onSort={onSort}
        />
        <SortHeader
          theme={theme}
          label="Ver"
          col="version"
          activeKey={sortKey}
          dir={sortDir}
          onSort={onSort}
        />
        <SortHeader
          theme={theme}
          label="Ecosystem"
          col="ecosystem"
          activeKey={sortKey}
          dir={sortDir}
          onSort={onSort}
        />
        <SortHeader
          theme={theme}
          label="Primary PURL"
          col="purl"
          activeKey={sortKey}
          dir={sortDir}
          onSort={onSort}
        />
        <SortHeader
          theme={theme}
          label="Status"
          col="status"
          activeKey={sortKey}
          dir={sortDir}
          onSort={onSort}
        />
      </div>

      {/* Virtualized rows */}
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
            No matches. Try clearing filters.
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
              const checked = selectedSet.has(p.name);
              const focused = focusedId === p.name;
              const status = effectiveStatus(p, edits);
              const purl = effectivePurl(p, edits);
              const eco = effectiveType(p, edits);
              return (
                <div
                  key={p.name}
                  onClick={(e) => handleRowClick(e, p.name)}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: ROW_H,
                    transform: `translateY(${vi.start}px)`,
                    display: "grid",
                    gridTemplateColumns:
                      "32px minmax(180px, 1fr) 70px 110px minmax(220px, 2fr) 100px",
                    gap: 8,
                    padding: "0 14px",
                    alignItems: "center",
                    borderBottom: `1px solid ${t.border}`,
                    background: focused
                      ? t.rowSelected
                      : checked
                        ? theme.dark
                          ? "#1f2631"
                          : "#fff8e6"
                        : "transparent",
                    cursor: "pointer",
                    fontSize: 12,
                    color: t.fg1,
                  }}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onClick={(e) => e.stopPropagation()}
                    onChange={() => toggleOne(p.name)}
                    style={{ accentColor: t.accent, cursor: "pointer" }}
                  />
                  <span
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: 12.5,
                      fontWeight: 600,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {p.name}
                  </span>
                  <span
                    style={{
                      color: t.fg2,
                      fontSize: 11,
                      fontVariantNumeric: "tabular-nums",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {p.version}
                  </span>
                  <span style={{ overflow: "hidden" }}>
                    <EcosystemChip id={eco} theme={theme} />
                  </span>
                  <code
                    style={{
                      fontFamily: "JetBrains Mono, monospace",
                      fontSize: 11,
                      color: t.fg2,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {purl || (
                      <span style={{ color: t.fg3, fontStyle: "italic" }}>
                        no purl
                      </span>
                    )}
                  </code>
                  <span style={{ overflow: "hidden" }}>
                    <StatusPill
                      status={
                        status as
                          | "verified"
                          | "auto-unverified"
                          | "unmapped"
                          | "edited"
                      }
                      theme={theme}
                    />
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function SortHeader({
  theme,
  label,
  col,
  activeKey,
  dir,
  onSort,
}: {
  theme: Theme;
  label: string;
  col: SortKey;
  activeKey: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const active = col === activeKey;
  const t = theme.t;
  return (
    <button
      onClick={() => onSort(col)}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 4,
        background: "transparent",
        border: 0,
        cursor: "pointer",
        color: active ? t.fg1 : t.fg2,
        font: "inherit",
        textTransform: "inherit",
        letterSpacing: "inherit",
        padding: 0,
        textAlign: "left",
        overflow: "hidden",
      }}
    >
      <span
        style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
      >
        {label}
      </span>
      {active && (
        <span
          style={{
            fontSize: 9,
            transform: dir === "desc" ? "rotate(180deg)" : "none",
            transition: "transform 120ms",
          }}
        >
          ▲
        </span>
      )}
    </button>
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
