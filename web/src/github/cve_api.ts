/* Submit a batch of CVE-advisory review edits as a PR.
 *
 * Mirrors the PURL-side flow in ./api.ts: the SPA sends the user-to-server
 * OAuth token + the edits payload to the Cloudflare Worker, which mints an
 * installation token and writes a uniquely-named contribution file under
 * `mappings/cve_contributions/`. The merge step (`scripts/merge_cves.py`)
 * layers contributions on top of the auto-matcher output at deploy time.
 */
import { config } from "../config";
import type { ReviewEdit } from "../data/cves";

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

/** Reshape the flat edits map into the nested `{ pkg: { advisoryId: review } }`
 *  form the Worker writes verbatim into the contribution file. */
export function buildReviewsPayload(
  edits: Record<string, ReviewEdit>,
): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const [key, edit] of Object.entries(edits)) {
    const sep = key.indexOf("::");
    if (sep < 0) continue;
    const pkg = key.slice(0, sep);
    const advisoryId = key.slice(sep + 2);
    if (!out[pkg]) out[pkg] = {};
    out[pkg][advisoryId] = {
      status: edit.status,
      note: edit.note || undefined,
      version_overrides:
        edit.version_overrides.affected.length > 0 ||
        edit.version_overrides.not_affected.length > 0
          ? {
              affected:
                edit.version_overrides.affected.length > 0
                  ? edit.version_overrides.affected
                  : undefined,
              not_affected:
                edit.version_overrides.not_affected.length > 0
                  ? edit.version_overrides.not_affected
                  : undefined,
            }
          : undefined,
    };
  }
  return out;
}

export async function submitCveReviewsAsPR(
  opts: CveSubmitOptions,
): Promise<CveSubmitResult> {
  if (!config.oauthWorkerUrl) {
    throw new Error("Worker URL not configured — cannot submit PR.");
  }
  const reviews = buildReviewsPayload(opts.edits);
  const endpoint = `${config.oauthWorkerUrl.replace(/\/$/, "")}/api/submit-cves`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      userToken: opts.token,
      reviews,
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
