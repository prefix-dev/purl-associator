/* PR submission via the Worker.
 *
 * The Worker holds the GitHub App's private key and does the file write +
 * branch + PR creation with an installation token (scoped to a single repo).
 * The SPA only sends the user's OAuth token (so the Worker can identify who's
 * submitting) and the edits payload.
 */
import { config } from "../config";
import type { Edit, PackageEntry } from "../data/types";

export type CreatedPR = {
  number: number;
  html_url: string;
  branch: string;
};

export type SubmitOptions = {
  token: string;
  user: { login: string };
  packages: PackageEntry[];
  edits: Record<string, Edit>;
  title: string;
  body: string;
};

export type SubmitResult = {
  pr: CreatedPR;
  branch: string;
};

export async function submitEditsAsPR(opts: SubmitOptions): Promise<SubmitResult> {
  if (!config.oauthWorkerUrl) {
    throw new Error("Worker URL not configured — cannot submit PR.");
  }
  // Defensive: drop edits whose package isn't in the loaded payload.
  const known = new Set(opts.packages.map((p) => p.name));
  const filtered: Record<string, Edit> = {};
  for (const [name, edit] of Object.entries(opts.edits)) {
    if (known.has(name)) filtered[name] = edit;
  }

  const endpoint = `${config.oauthWorkerUrl.replace(/\/$/, "")}/api/submit`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      userToken: opts.token,
      edits: filtered,
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
  const data = (await res.json()) as {
    number: number;
    html_url: string;
    branch: string;
  };
  return {
    pr: { number: data.number, html_url: data.html_url, branch: data.branch },
    branch: data.branch,
  };
}
