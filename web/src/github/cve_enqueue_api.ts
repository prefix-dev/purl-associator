/* Submit one or more (package, advisory) pairs for AI CVE coverage review.
 *
 * Mirrors ../github/cve_api.ts (and ./api.ts) — the SPA POSTs the user OAuth
 * token + the batch to the Cloudflare Worker, which writes a queue file under
 * `mappings/cve_review_queue/` and opens a PR. A maintainer must merge that
 * queue PR; the next `cve_ai_review.yml` run on main then picks up the queued
 * items and produces an AI-draft PR.
 */
import { config } from "../config";

export type EnqueueItem = {
  package: string;
  advisory_id: string;
  note?: string;
  /** Force a re-draft even when the pair is already drafted and nothing drifted. */
  force?: boolean;
};

export type EnqueueOptions = {
  token: string;
  items: EnqueueItem[];
  title?: string;
  body?: string;
};

export type EnqueueResult = {
  number: number;
  html_url: string;
  branch: string;
  file: string;
};

export async function enqueueAiReviewAsPR(
  opts: EnqueueOptions,
): Promise<EnqueueResult> {
  if (!config.oauthWorkerUrl) {
    throw new Error("Worker URL not configured — cannot queue review.");
  }
  const endpoint = `${config.oauthWorkerUrl.replace(/\/$/, "")}/api/enqueue-cve-review`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      userToken: opts.token,
      items: opts.items,
      title: opts.title,
      body: opts.body,
    }),
  });
  if (!res.ok) {
    let detail = await res.text();
    try {
      detail = JSON.stringify(JSON.parse(detail), null, 2);
    } catch {
      // keep raw
    }
    throw new Error(`Enqueue failed: ${res.status}\n${detail}`);
  }
  return (await res.json()) as EnqueueResult;
}
