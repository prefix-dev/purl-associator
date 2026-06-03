import { useMemo, useState } from "react";
import type {
  AiDraft,
  AiDraftsPayload,
  AiQueuePayload,
  CveAdvisoryIndex,
  CvePackageIndex,
  ReviewEdit,
} from "../data/cves";
import { Glyph, Theme, Btn } from "./Primitives";

type Mode = "queue" | "drafts";
type SeverityFilter = "all" | "critical" | "high+";

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
  onBulkEnqueue: (items: { package: string; advisory_id: string }[]) => void;
};

type Row = {
  pkg: CvePackageIndex;
  adv: CveAdvisoryIndex;
  score: number;
  reviewed: boolean;
  queued: boolean;
  drafted: boolean;
  draft?: AiDraft;
  locallyQueued: boolean;
};

function reviewedStatus(edit: ReviewEdit | undefined, adv: CveAdvisoryIndex): boolean {
  const status = edit?.status ?? adv.vex_status;
  return !!status && status !== "under_investigation";
}

function packageDraft(
  aiDrafts: AiDraftsPayload | null,
  packages: string[],
  advisoryId: string,
): AiDraft | undefined {
  for (const pkg of packages) {
    const draft = aiDrafts?.drafts[pkg]?.[advisoryId];
    if (draft) return draft;
  }
  return undefined;
}

function draftNeedsCloserRead(draft: AiDraft): boolean {
  return (
    !draft.affected_versions.agrees_with_match ||
    draft.runtime_applicability.applies === "unknown" ||
    draft.runtime_applicability.applies === "partial" ||
    draft.severity_in_conda_context.assessment === "unknown"
  );
}

function statusChangeLabel(adv: CveAdvisoryIndex, draft: AiDraft): string {
  const current = adv.vex_status ?? "unreviewed";
  return current === draft.openvex_status
    ? `keeps ${draft.openvex_status}`
    : `${current} → ${draft.openvex_status}`;
}

function packageQueued(
  aiQueue: AiQueuePayload | null,
  packages: string[],
  advisoryId: string,
): boolean {
  return packages.some((pkg) => Boolean(aiQueue?.queue[pkg]?.[advisoryId]));
}

function locallyQueued(
  enqueued: Set<string>,
  packages: string[],
  advisoryId: string,
): boolean {
  return packages.some((pkg) => enqueued.has(`${pkg}::${advisoryId}`));
}

function rowKey(row: Pick<Row, "pkg" | "adv">): string {
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
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<SeverityFilter>("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const allRows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    for (const pkg of packages) {
      const lookupPackages = membersByRep.get(pkg.package) ?? [pkg.package];
      for (const adv of pkg.advisories) {
        const key = `${pkg.package}::${adv.id}`;
        const draft = packageDraft(aiDrafts, lookupPackages, adv.id);
        const drafted = Boolean(draft);
        const queued = packageQueued(aiQueue, lookupPackages, adv.id);
        const locallyQueued_ = locallyQueued(enqueuedAdvisories, lookupPackages, adv.id);
        const reviewed = reviewedStatus(edits[key], adv);
        if (mode === "drafts") {
          if (!drafted || reviewed) continue;
        } else {
          if (!queued || drafted || reviewed) continue;
        }
        out.push({
          pkg,
          adv,
          score: adv.severity?.score_num ?? 0,
          reviewed,
          queued,
          drafted,
          draft,
          locallyQueued: locallyQueued_,
        });
      }
    }
    out.sort((a, b) => {
      if (a.score !== b.score) return b.score - a.score;
      return a.adv.primary_id.localeCompare(b.adv.primary_id) || a.pkg.package.localeCompare(b.pkg.package);
    });
    return out;
  }, [packages, membersByRep, aiDrafts, aiQueue, enqueuedAdvisories, edits, mode]);

  const ql = q.trim().toLowerCase();
  const rows = useMemo(() => {
    return allRows.filter((r) => {
      if (sev === "critical" && r.score < 9) return false;
      if (sev === "high+" && r.score < 7) return false;
      if (!ql) return true;
      const names = [r.pkg.package, ...(membersByRep.get(r.pkg.package) ?? [])].join(" ").toLowerCase();
      const ids = [r.adv.id, r.adv.primary_id, ...(r.adv.cve_ids ?? []), ...(r.adv.aliases ?? [])].join(" ").toLowerCase();
      return names.includes(ql) || ids.includes(ql) || (r.adv.summary ?? "").toLowerCase().includes(ql);
    });
  }, [allRows, ql, sev, membersByRep]);

  const selectableRows = mode === "drafts" ? rows.filter((r) => !r.locallyQueued) : [];
  const selectedRows = selectableRows.filter((r) => selected.has(rowKey(r)));

  function toggleSelected(key: string): void {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function selectVisible(): void {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const row of selectableRows) next.add(rowKey(row));
      return next;
    });
  }

  function clearSelection(): void {
    setSelected(new Set());
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
            <button
              key={value}
              onClick={() => setSev(value)}
              style={{
                border: `1px solid ${sev === value ? t.accent : t.border}`,
                background: sev === value ? t.surface2 : "transparent",
                color: sev === value ? t.fg1 : t.fg2,
                borderRadius: 999,
                padding: "4px 8px",
                fontSize: 11,
                cursor: "pointer",
              }}
            >
              {value === "high+" ? "High + critical" : value[0].toUpperCase() + value.slice(1)}
            </button>
          ))}
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
                    label={statusChangeLabel(r.adv, r.draft)}
                  />
                </div>
              )}
              <div style={{ marginTop: 4, fontFamily: "JetBrains Mono, monospace", color: t.fg2, fontSize: 11 }}>{r.pkg.package}</div>
              {r.adv.summary && <div style={{ marginTop: 4, color: t.fg2, fontSize: 12, lineHeight: 1.35 }}>{r.adv.summary}</div>}
            </button>
          );
        })}
      </div>
    </div>
  );
}
