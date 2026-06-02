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
import {
  buildPackageStatement,
  buildVersionOverrideStatement,
  type OpenVexStatement,
} from "../data/openvex";

export type { OpenVexStatement } from "../data/openvex";

export type CveSubmitOptions = {
  token: string;
  /** Map of `${packageName}::${advisoryId}` → review edit. */
  edits: Record<string, ReviewEdit>;
  /** Representative package name → every conda package collapsed into it
   *  (including the representative). A single review staged against a
   *  representative is fanned out to a statement per member so the OpenVEX
   *  document covers every interchangeable package (e.g. all `airflow-with-*`
   *  variants), not just the one the reviewer happened to see. Omit for no
   *  fan-out. */
  membersByRep?: Map<string, string[]>;
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
  membersByRep?: Map<string, string[]>,
): OpenVexStatement[] {
  const statements: OpenVexStatement[] = [];
  for (const [key, edit] of Object.entries(edits)) {
    const sep = key.indexOf("::");
    if (sep < 0) continue;
    const rep = key.slice(0, sep);
    const advisoryId = key.slice(sep + 2);
    // Fan the review out across every package collapsed under this
    // representative (same PURLs + version ⇒ same advisory). Falls back to
    // just the representative when no grouping is supplied.
    const targets = membersByRep?.get(rep) ?? [rep];
    for (const pkg of targets) {
      statements.push(buildPackageStatement(pkg, advisoryId, edit));

      // Version-pinned statements: flip individual conda versions.
      const { not_affected, affected } = edit.version_overrides;
      if (not_affected.length > 0) {
        statements.push(
          buildVersionOverrideStatement(
            pkg,
            advisoryId,
            not_affected,
            "not_affected",
            edit,
          ),
        );
      }
      if (affected.length > 0) {
        statements.push(
          buildVersionOverrideStatement(pkg, advisoryId, affected, "affected", edit),
        );
      }
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
  const statements = buildStatements(opts.edits, opts.membersByRep);
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
