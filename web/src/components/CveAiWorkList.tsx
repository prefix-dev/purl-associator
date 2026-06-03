import { useMemo } from "react";
import type {
  AiDraftsPayload,
  AiQueuePayload,
  CvePackageIndex,
  ReviewEdit,
} from "../data/cves";
import {
  aiStatusChangeLabel,
  buildCveAiWorkRows,
  draftNeedsCloserRead,
  type CveAiWorkRow,
} from "../data/cveAiWorkItems";
import { Glyph, Theme, Btn, FilterChip } from "./Primitives";
import { useCveAiWorkListPrefsStore } from "../stores/userState";
import type { EnqueueItem } from "../github/cve_enqueue_api";
import { useSetSelection } from "../hooks/useSetSelection";

type Mode = "queue" | "drafts";
type SeverityFilter = "all" | "critical" | "high+";
type StatusChangeFilter = "all" | string;

type Props = {
  theme: Theme;
  mode: Mode;
  packages: CvePackageIndex[];
  membersByRep: Map<string, string[]>;
  edits: Record<string, ReviewEdit>;
  focusedPkg: string | null;
  focusedAdvisoryId: string | null;
  aiDrafts: AiDraftsPayload | null;
  aiQueue: AiQueuePayload | null;
  enqueuedAdvisories: Set<string>;
  onSelect: (pkgName: string, advisoryId: string) => void;
  onBulkEnqueue: (items: EnqueueItem[]) => void;
};

function rowKey(row: Pick<CveAiWorkRow, "pkg" | "adv">): string {
  return `${row.pkg.package}::${row.adv.id}`;
}

function severityLabel(score: number): string {
  if (score >= 9) return `${score.toFixed(1)} critical`;
  if (score >= 7) return `${score.toFixed(1)} high`;
  if (score >= 4) return `${score.toFixed(1)} medium`;
  if (score > 0) return `${score.toFixed(1)} low`;
  return "unknown";
}

function AiBadge({
  theme,
  tone,
  label,
}: {
  theme: Theme;
  tone: "good" | "warn" | "info";
  label: string;
}) {
  const colors = {
    good: {
      bg: theme.dark ? "#1a2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#4f8125",
      border: theme.dark ? "#2f4a29" : "#cfe5b7",
    },
    warn: {
      bg: theme.dark ? "#2a2616" : "#fff4d2",
      fg: theme.dark ? "#f5c542" : "#7a5b00",
      border: theme.dark ? "#4a3e1d" : "#ead58b",
    },
    info: {
      bg: theme.dark ? "#1a2233" : "#e3ecff",
      fg: theme.dark ? "#9aaaff" : "#3957ff",
      border: theme.dark ? "#2a3a55" : "#c2d0fb",
    },
  }[tone];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        border: `1px solid ${colors.border}`,
        background: colors.bg,
        color: colors.fg,
        borderRadius: 999,
        padding: "2px 7px",
        fontSize: 10.5,
        fontWeight: 700,
        lineHeight: 1.2,
      }}
    >
      {label}
    </span>
  );
}

export function CveAiWorkList({
  theme,
  mode,
  packages,
  membersByRep,
  edits,
  focusedPkg,
  focusedAdvisoryId,
  aiDrafts,
  aiQueue,
  enqueuedAdvisories,
  onSelect,
  onBulkEnqueue,
}: Props) {
  const t = theme.t;
  const searchByMode = useCveAiWorkListPrefsStore((state) => state.search);
  const severityByMode = useCveAiWorkListPrefsStore((state) => state.severity);
  const statusChangeByMode = useCveAiWorkListPrefsStore((state) => state.statusChange);
  const setModePref = useCveAiWorkListPrefsStore((state) => state.setModePref);
  const q = searchByMode[mode] ?? "";
  const sev = (severityByMode[mode] ?? "all") as SeverityFilter;
  const statusChange = (statusChangeByMode[mode] ?? "all") as StatusChangeFilter;
  const setQ = (value: string) => setModePref("search", mode, value);
  const setSev = (value: SeverityFilter) => setModePref("severity", mode, value);
  const setStatusChange = (value: StatusChangeFilter) => setModePref("statusChange", mode, value);
  const { selected, toggleSelected, selectItems, clearSelection } = useSetSelection(rowKey);

  const allRows = useMemo(
    () =>
      buildCveAiWorkRows({
        mode,
        packages,
        membersByRep,
        edits,
        aiDrafts,
        aiQueue,
        enqueuedAdvisories,
      }),
    [packages, membersByRep, aiDrafts, aiQueue, enqueuedAdvisories, edits, mode],
  );

  const ql = q.trim().toLowerCase();
  const rows = useMemo(() => {
    return allRows.filter((r) => {
      if (sev === "critical" && r.score < 9) return false;
      if (sev === "high+" && r.score < 7) return false;
      if (mode === "drafts" && statusChange !== "all" && r.draft && aiStatusChangeLabel(r.adv, r.draft) !== statusChange) return false;
      if (!ql) return true;
      const names = [r.pkg.package, ...(membersByRep.get(r.pkg.package) ?? [])].join(" ").toLowerCase();
      const ids = [r.adv.id, r.adv.primary_id, ...(r.adv.cve_ids ?? []), ...(r.adv.aliases ?? [])].join(" ").toLowerCase();
      return names.includes(ql) || ids.includes(ql) || (r.adv.summary ?? "").toLowerCase().includes(ql);
    });
  }, [allRows, ql, sev, statusChange, mode, membersByRep]);

  const statusChangeOptions = useMemo(() => {
    const labels = new Set<string>();
    for (const row of allRows) {
      if (row.draft) labels.add(aiStatusChangeLabel(row.adv, row.draft));
    }
    return [...labels].sort();
  }, [allRows]);

  const selectableRows = mode === "drafts" ? rows.filter((r) => !r.locallyQueued) : [];
  const selectedRows = selectableRows.filter((r) => selected.has(rowKey(r)));

  function selectVisible(): void {
    selectItems(selectableRows);
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", background: t.surface }}>
      <div style={{ padding: 12, borderBottom: `1px solid ${t.border}`, display: "flex", flexDirection: "column", gap: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Glyph name={mode === "drafts" ? "edit" : "branch"} size={13} />
          <strong style={{ color: t.fg1, fontSize: 13 }}>
            {mode === "drafts" ? "Open AI drafts" : "Pending AI queue"}
          </strong>
          <span style={{ color: t.fg3, fontSize: 12 }}>{rows.length} item{rows.length === 1 ? "" : "s"}</span>
        </div>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by package, CVE, or summary…"
          style={{ background: t.inset, color: t.fg1, border: `1px solid ${t.border}`, borderRadius: 6, padding: "7px 9px", fontSize: 12 }}
        />
        <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
          {(["all", "critical", "high+"] as SeverityFilter[]).map((value) => (
            <FilterChip
              key={value}
              theme={theme}
              active={sev === value}
              onClick={() => setSev(value)}
              rounded
            >
              {value === "high+" ? "High + critical" : value[0].toUpperCase() + value.slice(1)}
            </FilterChip>
          ))}
          {mode === "drafts" && statusChangeOptions.length > 0 && (
            <select
              value={statusChange}
              onChange={(e) => setStatusChange(e.target.value)}
              title="Filter by AI status change"
              style={{
                background: t.inset,
                color: t.fg1,
                border: `1px solid ${t.border}`,
                borderRadius: 999,
                padding: "4px 8px",
                fontSize: 11,
              }}
            >
              <option value="all">All status changes</option>
              {statusChangeOptions.map((label) => (
                <option key={label} value={label}>{label}</option>
              ))}
            </select>
          )}
          {mode === "drafts" && selectableRows.length > 0 && (
            <span style={{ marginLeft: "auto", display: "inline-flex", gap: 6, alignItems: "center" }}>
              <button
                onClick={selectVisible}
                style={{
                  background: "transparent",
                  border: `1px solid ${t.border}`,
                  color: t.fg2,
                  borderRadius: 999,
                  padding: "4px 8px",
                  fontSize: 11,
                  cursor: "pointer",
                }}
              >
                Select visible
              </button>
              {selectedRows.length > 0 && (
                <button
                  onClick={clearSelection}
                  style={{
                    background: "transparent",
                    border: `1px solid ${t.border}`,
                    color: t.fg2,
                    borderRadius: 999,
                    padding: "4px 8px",
                    fontSize: 11,
                    cursor: "pointer",
                  }}
                >
                  Clear
                </button>
              )}
              <Btn
                theme={theme}
                variant="secondary"
                size="sm"
                disabled={selectedRows.length === 0}
                onClick={() => {
                  onBulkEnqueue(
                    selectedRows.map((r) => ({
                      package: r.pkg.package,
                      advisory_id: r.adv.id,
                      force: true,
                    })),
                  );
                  clearSelection();
                }}
              >
                Requeue selected ({selectedRows.length})
              </Btn>
            </span>
          )}
        </div>
      </div>
      <div style={{ overflow: "auto", flex: 1 }}>
        {rows.length === 0 ? (
          <div style={{ color: t.fg3, fontSize: 13, textAlign: "center", padding: 28 }}>
            {mode === "drafts" ? "No open AI drafts match this filter." : "No pending AI queue items match this filter."}
          </div>
        ) : rows.map((r) => {
          const active = focusedPkg === r.pkg.package && focusedAdvisoryId === r.adv.id;
          const key = rowKey(r);
          const isSelectable = mode === "drafts" && !r.locallyQueued;
          const isSelected = selected.has(key);
          return (
            <button
              key={key}
              onClick={() => onSelect(r.pkg.package, r.adv.id)}
              style={{
                width: "100%",
                textAlign: "left",
                display: "block",
                padding: "10px 12px",
                border: 0,
                borderBottom: `1px solid ${t.border}`,
                background: active ? t.surface2 : "transparent",
                color: t.fg1,
                cursor: "pointer",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                {mode === "drafts" && (
                  <input
                    type="checkbox"
                    checked={isSelected}
                    disabled={!isSelectable}
                    onClick={(e) => e.stopPropagation()}
                    onChange={(e) => {
                      e.stopPropagation();
                      if (isSelectable) toggleSelected(key);
                    }}
                    title={isSelectable ? "Select for requeue" : "Already staged for requeue"}
                    style={{ cursor: isSelectable ? "pointer" : "not-allowed" }}
                  />
                )}
                <span style={{ fontFamily: "JetBrains Mono, monospace", fontWeight: 700, fontSize: 12 }}>{r.adv.primary_id}</span>
                <span style={{ fontSize: 10.5, color: r.score >= 9 ? "#a8201f" : r.score >= 7 ? "#d94e1f" : t.fg3, fontWeight: 700, textTransform: "uppercase" }}>{severityLabel(r.score)}</span>
                <span style={{ marginLeft: "auto", fontSize: 11, color: t.fg3 }}>{mode === "drafts" ? "needs human review" : "waiting for AI"}</span>
              </div>
              {mode === "drafts" && r.draft && (
                <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 6 }}>
                  <AiBadge
                    theme={theme}
                    tone={draftNeedsCloserRead(r.draft) ? "warn" : "good"}
                    label={draftNeedsCloserRead(r.draft) ? "Needs closer read" : "Confident"}
                  />
                  <AiBadge
                    theme={theme}
                    tone="info"
                    label={aiStatusChangeLabel(r.adv, r.draft)}
                  />
                </div>
              )}
              <div style={{ marginTop: 4, fontFamily: "JetBrains Mono, monospace", color: t.fg2, fontSize: 11 }}>
                {r.pkg.package}
                {mode === "queue" && r.packageQueueCount > 1 && (
                  <span style={{ marginLeft: 8, fontFamily: "Inter, sans-serif", color: t.fg3 }}>
                    {r.packageQueueCount} CVEs queued for this package
                  </span>
                )}
              </div>
              {r.adv.summary && <div style={{ marginTop: 4, color: t.fg2, fontSize: 12, lineHeight: 1.35 }}>{r.adv.summary}</div>}
            </button>
          );
        })}
      </div>
    </div>
  );
}
