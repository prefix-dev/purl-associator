import { useMemo } from "react";
import type { Edit, PackageEntry } from "../data/types";
import { ECOSYSTEMS } from "../data/loader";
import {
  EcosystemChip,
  Glyph,
  StatusPill,
  Theme,
} from "./Primitives";

type Filters = {
  unmappedOnly: boolean;
  unverifiedOnly: boolean;
  ecosystem: string;
};

type Props = {
  theme: Theme;
  packages: PackageEntry[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  edits: Record<string, Edit>;
  q: string;
  setQ: (v: string) => void;
  filters: Filters;
  setFilters: (f: Filters) => void;
};

export function PackageList({
  theme,
  packages,
  selectedId,
  onSelect,
  edits,
  q,
  setQ,
  filters,
  setFilters,
}: Props) {
  const t = theme.t;

  const filtered = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return packages.filter((p) => {
      if (
        filters.unmappedOnly &&
        p.status !== "unmapped" &&
        !edits[p.name]?.unmapped &&
        p.purl !== null
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
  }, [packages, q, filters, edits]);

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

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        background: t.surface,
        borderRight: `1px solid ${t.border}`,
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
            </div>
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
        </div>

        <select
          value={filters.ecosystem}
          onChange={(e) =>
            setFilters({ ...filters, ecosystem: e.target.value })
          }
          style={{
            width: "100%",
            background: t.surface2,
            color: t.fg1,
            border: `1px solid ${t.border}`,
            borderRadius: 6,
            padding: "5px 8px",
            fontSize: 12,
            fontFamily: "Inter, sans-serif",
            cursor: "pointer",
            outline: "none",
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

      <div style={{ flex: 1, overflowY: "auto" }}>
        {filtered.length === 0 && (
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
        )}
        {filtered.map((p) => {
          const edit = edits[p.name];
          const selected = selectedId === p.name;
          const purl = edit?.purl ?? p.purl ?? null;
          const ecosystem = edit?.type ?? p.type ?? "none";
          const status = edit
            ? "edited"
            : p.status === "unmapped" || p.purl === null
              ? "unmapped"
              : p.status;
          return (
            <div
              key={p.name}
              onClick={() => onSelect(p.name)}
              style={{
                padding: "9px 14px",
                borderBottom: `1px solid ${t.border}`,
                cursor: "pointer",
                background: selected ? t.rowSelected : "transparent",
                borderLeft: selected
                  ? `3px solid ${t.accent}`
                  : "3px solid transparent",
                transition: "background 120ms",
              }}
              onMouseEnter={(e) => {
                if (!selected)
                  (e.currentTarget as HTMLDivElement).style.background = t.rowHover;
              }}
              onMouseLeave={(e) => {
                if (!selected)
                  (e.currentTarget as HTMLDivElement).style.background = "transparent";
              }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: 8,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 7,
                    minWidth: 0,
                    flex: 1,
                  }}
                >
                  <div
                    style={{
                      fontSize: 13,
                      fontWeight: 600,
                      color: t.fg1,
                      fontFamily: "JetBrains Mono, monospace",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {p.name}
                  </div>
                  <span
                    style={{
                      fontSize: 10.5,
                      color: t.fg3,
                      fontVariantNumeric: "tabular-nums",
                      flexShrink: 0,
                    }}
                  >
                    {p.version}
                  </span>
                </div>
                <StatusPill status={status} theme={theme} />
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                  marginTop: 4,
                  minWidth: 0,
                }}
              >
                <EcosystemChip id={ecosystem} theme={theme} />
                {purl ? (
                  <code
                    style={{
                      fontSize: 10.5,
                      color: t.fg2,
                      fontFamily: "JetBrains Mono, monospace",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      flex: 1,
                    }}
                  >
                    {purl}
                  </code>
                ) : (
                  <span
                    style={{ fontSize: 11, color: t.fg3, fontStyle: "italic" }}
                  >
                    no purl
                  </span>
                )}
              </div>
            </div>
          );
        })}
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
