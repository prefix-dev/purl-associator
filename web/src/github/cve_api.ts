/* Submit a batch of CVE-advisory review edits as a PR.
 *
 * Mirrors the PURL-side flow in ./api.ts: the SPA sends the user-to-server
 * OAuth token + the review edits to the Cloudflare Worker, which mints an
 * installation token and writes a uniquely-named OpenVEX document under
 * `mappings/cve_contributions/`. The merge step (`scripts/merge_cves.py`)
 * resolves those OpenVEX statements onto the OSV records at deploy time.
 *
 * The frontend builds the VEX *statements*; the Worker wraps them in the
 * OpenVEX envelope (@context / @id / author / timestamp / version).
 */
import { config } from "../config";
import type { ReviewEdit } from "../data/cves";

const CONDA_QUALIFIER = "channel=conda-forge";

/** A package-level or version-pinned conda PURL (purl-spec `conda` type). */
function condaPurl(pkg: string, version?: string): string {
  return version
    ? `pkg:conda/${pkg}@${version}?${CONDA_QUALIFIER}`
    : `pkg:conda/${pkg}?${CONDA_QUALIFIER}`;
}

// Fallback action_statement — OpenVEX requires one on every `affected`
// statement. Reviewers can refine it; this keeps the document schema-valid.
const DEFAULT_ACTION = "Update to a fixed conda-forge build of the package.";

/** One OpenVEX 0.2.0 statement (the Worker supplies the document envelope). */
export type OpenVexStatement = {
  vulnerability: { name: string };
  products: { "@id": string }[];
  status: ReviewEdit["status"];
  justification?: string;
  action_statement?: string;
  status_notes?: string;
};

export type CveSubmitOptions = {
  token: string;
  /** Map of `${packageName}::${advisoryId}` → review edit. */
  edits: Record<string, ReviewEdit>;
  title: string;
  body: string;
};

export type CveSubmitResult = {
  number: number;
  html_url: string;
  branch: string;
  file: string;
};

/** Convert the flat edits map into OpenVEX statements.
 *
 * Each edit yields a package-level statement (the overall review status) plus,
 * when the reviewer flipped individual conda versions, one version-pinned
 * statement per status bucket. */
export function buildStatements(
  edits: Record<string, ReviewEdit>,
): OpenVexStatement[] {
  const statements: OpenVexStatement[] = [];
  for (const [key, edit] of Object.entries(edits)) {
    const sep = key.indexOf("::");
    if (sep < 0) continue;
    const pkg = key.slice(0, sep);
    const advisoryId = key.slice(sep + 2);
    // The OSV id is matched against id/aliases by merge_cves — unambiguous.
    const vulnerability = { name: advisoryId };

    const action = edit.action_statement.trim() || DEFAULT_ACTION;
    const notes = edit.notes.trim();

    // Package-level statement: the overall review status.
    const pkgStmt: OpenVexStatement = {
      vulnerability,
      products: [{ "@id": condaPurl(pkg) }],
      status: edit.status,
    };
    if (edit.status === "not_affected") {
      pkgStmt.justification = edit.justification;
    } else if (edit.status === "affected") {
      pkgStmt.action_statement = action;
    }
    if (notes) pkgStmt.status_notes = notes;
    statements.push(pkgStmt);

    // Version-pinned statements: flip individual conda versions.
    const { not_affected, affected } = edit.version_overrides;
    if (not_affected.length > 0) {
      statements.push({
        vulnerability,
        products: not_affected.map((v) => ({ "@id": condaPurl(pkg, v) })),
        status: "not_affected",
        justification: edit.justification,
      });
    }
    if (affected.length > 0) {
      statements.push({
        vulnerability,
        products: affected.map((v) => ({ "@id": condaPurl(pkg, v) })),
        status: "affected",
        action_statement: action,
      });
    }
  }
  return statements;
}

export async function submitCveReviewsAsPR(
  opts: CveSubmitOptions,
): Promise<CveSubmitResult> {
  if (!config.oauthWorkerUrl) {
    throw new Error("Worker URL not configured — cannot submit PR.");
  }
  const statements = buildStatements(opts.edits);
  const endpoint = `${config.oauthWorkerUrl.replace(/\/$/, "")}/api/submit-cves`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      userToken: opts.token,
      statements,
      title: opts.title,
      body: opts.body,
    }),
  });
  if (!res.ok) {
    let detail = await res.text();
    try {
      detail = JSON.stringify(JSON.parse(detail), null, 2);
    } catch {
      // keep raw text
    }
    throw new Error(`Submit failed: ${res.status}\n${detail}`);
  }
  return (await res.json()) as CveSubmitResult;
}
