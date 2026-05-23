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
    [key: string]: unknown;
  };
};

export type CvePackage = {
  schema_version: number;
  package: string;
  purls: string[];
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
