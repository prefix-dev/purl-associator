/* Types + loader for the CVE dashboard payload.
 *
 * The payload (web/public/cves.json) is produced by scripts/merge_cves.py.
 * Each advisory is a *verbatim OSV record*; the conda-forge match and the
 * resolved OpenVEX review both live under database_specific["conda-forge"].
 * The accessors below mirror scripts/cve_common.py so the frontend and the
 * Python pipeline read the layout the same way.
 */

/* ---- OSV record shape (https://ossf.github.io/osv-schema/) ---- */

export type OsvSeverity = { type: string; score: string; score_num?: number };
export type OsvReference = { type: string; url: string };
export type OsvEvent = {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
};
export type OsvRange = { type: string; repo?: string; events: OsvEvent[] };
export type OsvAffected = {
  package?: { ecosystem: string; name: string; purl?: string };
  ranges?: OsvRange[];
  versions?: string[];
};

/* ---- VEX (OpenVEX 0.2.0 — https://openvex.dev) ---- */

export type VexStatus =
  | "affected"
  | "not_affected"
  | "fixed"
  | "under_investigation";

export type VexJustification =
  | "component_not_present"
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

/** The review resolved from OpenVEX contributions, stamped by merge_cves. */
export type Vex = {
  status?: VexStatus;
  justification?: VexJustification;
  impact_statement?: string;
  action_statement?: string;
  status_notes?: string | null;
  author?: string;
  reviewed_at?: string;
  version_overrides?: { affected: string[]; not_affected: string[] };
};

/** Our database_specific["conda-forge"] extension block. */
export type CondaForgeBlock = {
  package: string;
  purl: string;
  source_purls?: string[];
  affected_versions: string[];
  /** True iff the OSV record names a version newer than the package's
   *  latest conda-forge release as affected. Set by scripts/cve_match.py
   *  using rattler Version comparison. */
  affects_future?: boolean;
  conda_versions_total?: number;
  derived_by?: string;
  generated_at?: string;
  vex?: Vex;
};

/** NVD/CPE metadata for advisories that came from the NVD feeds rather
 *  than OSV. Set by scripts/nvd_prototype.py — ``matched_via`` is the
 *  subset of the package's curated ``cpes`` that actually surfaced this
 *  particular CVE. */
export type NvdBlock = {
  cpes?: string[];
  matched_via?: string[];
  source?: string;
};

/** A verbatim OSV record carrying the conda-forge match in database_specific. */
export type Advisory = {
  schema_version?: string;
  id: string;
  aliases?: string[];
  related?: string[];
  summary?: string;
  details?: string;
  published?: string;
  modified?: string;
  withdrawn?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: {
    "conda-forge"?: CondaForgeBlock;
    nvd?: NvdBlock;
    [key: string]: unknown;
  };
};

export type CvePackage = {
  schema_version: number;
  package: string;
  purls: string[];
  cpes?: string[];
  generated_at: string;
  conda_versions_total: number;
  /** Newest conda-forge version of this package by rattler version order. */
  latest_version?: string | null;
  advisories: Advisory[];
};

export type CvePayload = {
  schema_version: number;
  generated_at: string;
  contribution_count: number;
  package_count: number;
  advisory_count: number;
  affected_version_count: number;
  packages: Record<string, CvePackage>;
};

/* ---- accessors over the OSV-record layout (mirror scripts/cve_common.py) ---- */

export function condaBlock(adv: Advisory): CondaForgeBlock | undefined {
  return adv.database_specific?.["conda-forge"];
}

export function affectedVersions(adv: Advisory): string[] {
  return condaBlock(adv)?.affected_versions ?? [];
}

export function advisoryVex(adv: Advisory): Vex | undefined {
  return condaBlock(adv)?.vex;
}

export function cveIds(adv: Advisory): string[] {
  const ids = new Set<string>([adv.id, ...(adv.aliases ?? [])]);
  return [...ids].filter((i) => i.startsWith("CVE-")).sort();
}

/** Prefer a human-friendly CVE id; fall back to the native OSV id. */
export function primaryId(adv: Advisory): string {
  return cveIds(adv)[0] ?? adv.id;
}

export function osvUrl(adv: Advisory): string {
  return `https://osv.dev/vulnerability/${adv.id}`;
}

const SEVERITY_RANK: Record<string, number> = {
  CVSS_V4: 4,
  CVSS_V3: 3,
  CVSS_V2: 2,
};

/** The most expressive CVSS entry from the OSV `severity` array. */
export function bestSeverity(adv: Advisory): OsvSeverity | undefined {
  let best: OsvSeverity | undefined;
  let bestRank = -1;
  for (const s of adv.severity ?? []) {
    const rank = SEVERITY_RANK[s.type] ?? 0;
    if (rank > bestRank) {
      best = s;
      bestRank = rank;
    }
  }
  return best;
}

/** True iff the package's newest conda-forge release is still listed as
 *  affected by this advisory and no review has marked it not_affected/fixed.
 *  These are the highest-priority entries for triage — a CVE actively shipping
 *  to users today. Returns false when latest_version is unknown. */
export function isActiveOnLatest(pkg: CvePackage, adv: Advisory): boolean {
  const latest = pkg.latest_version;
  if (!latest) return false;
  const status = advisoryVex(adv)?.status;
  if (status === "not_affected" || status === "fixed") return false;
  return affectedVersions(adv).includes(latest);
}

/** True iff the advisory targets a version newer than the package's latest
 *  conda-forge release. These are CVEs we can BLOCK before they ship —
 *  e.g. mistralai's malicious 2.4.6 dropper, while conda-forge still has
 *  2.4.5. Computed in scripts/cve_match.py with rattler.Version semantics. */
export function isFutureAffected(pkg: CvePackage, adv: Advisory): boolean {
  if (isActiveOnLatest(pkg, adv)) return false;
  const status = advisoryVex(adv)?.status;
  if (status === "not_affected" || status === "fixed") return false;
  return condaBlock(adv)?.affects_future === true;
}

/** Every non-GIT affected range across all affected[] entries. */
export function osvRanges(adv: Advisory): OsvRange[] {
  const out: OsvRange[] = [];
  for (const aff of adv.affected ?? []) {
    for (const r of aff.ranges ?? []) {
      if (r.type !== "GIT") out.push(r);
    }
  }
  return out;
}

const DEFAULT_PATH = "./cves.json";

export async function loadCves(path = DEFAULT_PATH): Promise<CvePayload> {
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) {
    throw new Error(`Failed to load ${path}: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

/* ---- AI CVE review sidecars (cve_ai_drafts.json + cve_ai_queue.json) ---- */

/** One per-advisory AI assessment as surfaced by scripts.merge_ai_drafts. */
export type AiDraft = {
  model: string;
  run_id: string;
  generated_at: string;
  /** Narrative prose (3-6 sentences) — the AI's "why this CVE applies (or
   *  doesn't)" headline. Surfaced at the top of the draft panel. */
  rationale: string;
  openvex_status: VexStatus;
  openvex_justification: VexJustification | null;
  openvex_impact_statement: string | null;
  openvex_action_statement: string | null;
  affected_versions: {
    agrees_with_match: boolean;
    suggested_adds?: string[];
    suggested_removes?: string[];
    reasoning: string;
  };
  runtime_applicability: {
    applies: "yes" | "no" | "partial" | "unknown";
    reasoning: string;
  };
  severity_in_conda_context: {
    assessment: "lower" | "same" | "higher" | "unknown";
    reasoning: string;
  };
  notes?: string;
};

export type AiDraftsPayload = {
  schema_version: number;
  generated_at: string;
  drafts: Record<string, Record<string, AiDraft>>; // package → advisory_id → AiDraft
  draft_count: number;
  package_count: number;
};

export type AiQueueEntry = {
  enqueued_at: string;
  enqueued_by: string;
};

export type AiQueuePayload = {
  schema_version: number;
  generated_at: string;
  queue: Record<string, Record<string, AiQueueEntry>>;
  queue_count: number;
  package_count: number;
};

const DEFAULT_AI_DRAFTS_PATH = "./cve_ai_drafts.json";
const DEFAULT_AI_QUEUE_PATH = "./cve_ai_queue.json";

const EMPTY_DRAFTS: AiDraftsPayload = {
  schema_version: 1,
  generated_at: "",
  drafts: {},
  draft_count: 0,
  package_count: 0,
};

const EMPTY_QUEUE: AiQueuePayload = {
  schema_version: 1,
  generated_at: "",
  queue: {},
  queue_count: 0,
  package_count: 0,
};

/** Load the AI drafts sidecar. Missing file is non-fatal — returns empty,
 *  with a console warning so production debugging is possible. */
export async function loadAiDrafts(
  path = DEFAULT_AI_DRAFTS_PATH,
): Promise<AiDraftsPayload> {
  try {
    const res = await fetch(path, { cache: "no-cache" });
    if (!res.ok) {
      // 404 is the "file not deployed yet" case — common before the first
      // cve_ai_review run lands, not worth shouting about. Anything else is.
      if (res.status !== 404) {
        console.warn(
          `loadAiDrafts(${path}): HTTP ${res.status} ${res.statusText} — AI draft chips disabled`,
        );
      }
      return EMPTY_DRAFTS;
    }
    return (await res.json()) as AiDraftsPayload;
  } catch (err) {
    console.warn(
      `loadAiDrafts(${path}): ${err instanceof Error ? err.message : String(err)} — AI draft chips disabled`,
    );
    return EMPTY_DRAFTS;
  }
}

/** Load the AI queue sidecar. Missing file is non-fatal — returns empty,
 *  with a console warning so production debugging is possible. */
export async function loadAiQueue(
  path = DEFAULT_AI_QUEUE_PATH,
): Promise<AiQueuePayload> {
  try {
    const res = await fetch(path, { cache: "no-cache" });
    if (!res.ok) {
      if (res.status !== 404) {
        console.warn(
          `loadAiQueue(${path}): HTTP ${res.status} ${res.statusText} — AI queue chips disabled`,
        );
      }
      return EMPTY_QUEUE;
    }
    return (await res.json()) as AiQueuePayload;
  } catch (err) {
    console.warn(
      `loadAiQueue(${path}): ${err instanceof Error ? err.message : String(err)} — AI queue chips disabled`,
    );
    return EMPTY_QUEUE;
  }
}

export function getAiDraftFor(
  payload: AiDraftsPayload | null,
  pkg: string,
  advisoryId: string,
): AiDraft | undefined {
  return payload?.drafts[pkg]?.[advisoryId];
}

export function isAdvisoryQueued(
  payload: AiQueuePayload | null,
  pkg: string,
  advisoryId: string,
): AiQueueEntry | undefined {
  return payload?.queue[pkg]?.[advisoryId];
}

function coerceJustification(
  value: string | null | undefined,
  fallback: VexJustification,
): VexJustification {
  // VEX_JUSTIFICATIONS is declared further down; check membership at call
  // time to avoid the TS "used before declaration" hoisting issue.
  if (
    value &&
    VEX_JUSTIFICATIONS.some((j) => j.id === (value as VexJustification))
  ) {
    return value as VexJustification;
  }
  return fallback;
}

/** Translate an AI draft's suggested status + reasoning into a ReviewEdit so
 *  the existing OpenVEX form can pre-fill from the AI's recommendation.
 *
 *  Note on validation: the AI's `openvex_justification` is constrained to the
 *  five enum values by `scripts/cve_ai_review.py`'s response schema, but we
 *  defensively coerce here in case the model slips through with a free-text
 *  reason — otherwise the OpenVEX form would display a value that isn't in
 *  the dropdown and the user couldn't toggle off. */
export function editFromAiDraft(draft: AiDraft): ReviewEdit {
  const base = blankReviewEdit();
  return {
    status: draft.openvex_status,
    justification: coerceJustification(
      draft.openvex_justification,
      base.justification,
    ),
    action_statement: draft.openvex_action_statement ?? "",
    notes: draft.notes ?? draft.openvex_impact_statement ?? "",
    version_overrides: {
      affected: draft.affected_versions.suggested_adds ?? [],
      not_affected: draft.affected_versions.suggested_removes ?? [],
    },
  };
}

/* ---- staged review edits (dashboard-side, pre-submit) ---- */

export const VEX_STATUSES: { id: VexStatus; label: string }[] = [
  { id: "affected", label: "Affected" },
  { id: "not_affected", label: "Not affected" },
  { id: "fixed", label: "Fixed" },
  { id: "under_investigation", label: "Under investigation" },
];

export const VEX_JUSTIFICATIONS: { id: VexJustification; label: string }[] = [
  { id: "component_not_present", label: "Component not present" },
  { id: "vulnerable_code_not_present", label: "Vulnerable code not present" },
  {
    id: "vulnerable_code_not_in_execute_path",
    label: "Vulnerable code not in execute path",
  },
  {
    id: "vulnerable_code_cannot_be_controlled_by_adversary",
    label: "Not controllable by an adversary",
  },
  {
    id: "inline_mitigations_already_exist",
    label: "Inline mitigations already exist",
  },
];

/** A pending, not-yet-committed review edit produced by the dashboard. */
export type ReviewEdit = {
  status: VexStatus;
  /** Required by OpenVEX when status is not_affected. */
  justification: VexJustification;
  /** Required by OpenVEX when status is affected. */
  action_statement: string;
  /** Free-text status_notes. */
  notes: string;
  version_overrides: { affected: string[]; not_affected: string[] };
};

export function blankReviewEdit(): ReviewEdit {
  return {
    status: "affected",
    justification: "vulnerable_code_not_present",
    action_statement: "",
    notes: "",
    version_overrides: { affected: [], not_affected: [] },
  };
}

export function editFromVex(vex: Vex | undefined): ReviewEdit {
  const blank = blankReviewEdit();
  if (!vex) return blank;
  return {
    status: vex.status ?? blank.status,
    justification: vex.justification ?? blank.justification,
    action_statement: vex.action_statement ?? "",
    notes: vex.status_notes ?? "",
    version_overrides: {
      affected: vex.version_overrides?.affected ?? [],
      not_affected: vex.version_overrides?.not_affected ?? [],
    },
  };
}

function setEq(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const bs = new Set(b);
  return a.every((v) => bs.has(v));
}

/** True when `edit` would change something relative to the stored review. */
export function isEditNonEmpty(edit: ReviewEdit, base?: Vex): boolean {
  const b = editFromVex(base);
  if (edit.status !== b.status) return true;
  if (edit.status === "not_affected" && edit.justification !== b.justification) {
    return true;
  }
  if (
    edit.status === "affected" &&
    edit.action_statement.trim() !== b.action_statement.trim()
  ) {
    return true;
  }
  if (edit.notes.trim() !== b.notes.trim()) return true;
  if (!setEq(edit.version_overrides.affected, b.version_overrides.affected)) {
    return true;
  }
  if (
    !setEq(edit.version_overrides.not_affected, b.version_overrides.not_affected)
  ) {
    return true;
  }
  return false;
}
