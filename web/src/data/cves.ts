/* Types + loader for the CVE dashboard payload.
 *
 * Mirrors the shape produced by `scripts/merge_cves.py`. The payload is the
 * source of truth for what each advisory says, what versions are affected,
 * and whether a reviewer has weighed in.
 */

export type OsvEvent =
  | { introduced?: string }
  | { fixed?: string }
  | { last_affected?: string }
  | { limit?: string };

export type OsvRange = {
  type: string;
  events: OsvEvent[];
};

export type OsvSeverity = {
  type: string;
  score: string;
};

export type OsvReference = {
  type: string;
  url: string;
};

export type Review = {
  status: "confirmed" | "rejected" | "not-applicable" | "needs-review";
  note: string | null;
  reviewer: string;
  reviewed_at: string;
  version_overrides: {
    affected?: string[];
    not_affected?: string[];
  } | null;
};

export type Advisory = {
  id: string;
  primary_id: string;
  aliases: string[];
  cve_ids: string[];
  ecosystem: string;
  upstream_name: string;
  summary: string | null;
  details: string | null;
  published: string | null;
  modified: string | null;
  severity: OsvSeverity | null;
  all_severity: OsvSeverity[];
  references: OsvReference[];
  osv_url: string;
  osv_ranges: OsvRange[];
  osv_versions: string[] | null;
  affected_conda_versions: string[];
  review?: Review;
};

export type CvePackage = {
  schema_version: number;
  package: string;
  purls: string[];
  generated_at: string;
  conda_versions_total: number;
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

const DEFAULT_PATH = "./cves.json";

export async function loadCves(path = DEFAULT_PATH): Promise<CvePayload> {
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) {
    throw new Error(`Failed to load ${path}: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export type ReviewStatus = Review["status"];

export const REVIEW_STATUSES: { id: ReviewStatus; label: string }[] = [
  { id: "confirmed", label: "Confirmed" },
  { id: "rejected", label: "Rejected" },
  { id: "not-applicable", label: "Not applicable" },
  { id: "needs-review", label: "Needs review" },
];

/** A pending, not-yet-committed review edit produced by the dashboard. */
export type ReviewEdit = {
  status: ReviewStatus;
  note: string;
  version_overrides: {
    affected: string[];
    not_affected: string[];
  };
};

export function blankReviewEdit(): ReviewEdit {
  return {
    status: "confirmed",
    note: "",
    version_overrides: { affected: [], not_affected: [] },
  };
}

export function editFromReview(r: Review | undefined): ReviewEdit {
  if (!r) return blankReviewEdit();
  return {
    status: r.status,
    note: r.note ?? "",
    version_overrides: {
      affected: r.version_overrides?.affected ?? [],
      not_affected: r.version_overrides?.not_affected ?? [],
    },
  };
}

export function isEditNonEmpty(edit: ReviewEdit, base?: Review): boolean {
  const baseEdit = editFromReview(base);
  if (edit.status !== baseEdit.status) return true;
  if ((edit.note || "") !== (baseEdit.note || "")) return true;
  const a = new Set(edit.version_overrides.affected);
  const ba = new Set(baseEdit.version_overrides.affected);
  if (a.size !== ba.size || [...a].some((v) => !ba.has(v))) return true;
  const b = new Set(edit.version_overrides.not_affected);
  const bb = new Set(baseEdit.version_overrides.not_affected);
  if (b.size !== bb.size || [...b].some((v) => !bb.has(v))) return true;
  return false;
}
