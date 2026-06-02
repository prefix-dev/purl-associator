/* Runtime configuration for the SPA.
 *
 * Values come from environment variables (Vite's import.meta.env, prefixed
 * VITE_) or, at deploy time, from a window.__PURL_CONFIG__ object injected by
 * the hosting page. This means the same static bundle can be deployed to
 * different repos / OAuth workers without rebuilding.
 */

export type RuntimeConfig = {
  /** Repo to PR mapping changes against, e.g. "prefix-dev/purl-mappings". */
  repoOwner: string;
  repoName: string;
  defaultBranch: string;
  /** Optional: where mappings.json lives relative to the site root. */
  mappingsUrl: string;
  /** Optional: where mappings-index.json lives relative to the site root. */
  mappingsIndexUrl: string;
  /** Optional: where cves.json (legacy per-advisory dataset) lives. */
  cvesUrl: string;
  /** Optional: where cves-index.json (compact CVE dashboard index) lives. */
  cvesIndexUrl: string;
  /** Optional: where cve_ai_drafts.json (AI draft sidecar) lives. */
  aiDraftsUrl: string;
  /** Optional: where cve_ai_queue.json (AI review queue sidecar) lives. */
  aiQueueUrl: string;
  /** Cloudflare Worker URL handling GitHub OAuth code-exchange. */
  oauthWorkerUrl: string | null;
  /** OAuth app's public client_id. */
  githubClientId: string | null;
};

declare global {
  interface Window {
    __PURL_CONFIG__?: Partial<RuntimeConfig>;
  }
}

const env = import.meta.env;

const fromEnv: Partial<RuntimeConfig> = {
  repoOwner: env.VITE_REPO_OWNER,
  repoName: env.VITE_REPO_NAME,
  defaultBranch: env.VITE_REPO_BRANCH,
  mappingsUrl: env.VITE_MAPPINGS_URL,
  mappingsIndexUrl: env.VITE_MAPPINGS_INDEX_URL,
  cvesUrl: env.VITE_CVES_URL,
  cvesIndexUrl: env.VITE_CVES_INDEX_URL,
  aiDraftsUrl: env.VITE_AI_DRAFTS_URL,
  aiQueueUrl: env.VITE_AI_QUEUE_URL,
  oauthWorkerUrl: env.VITE_OAUTH_WORKER_URL,
  githubClientId: env.VITE_GITHUB_CLIENT_ID,
};

const injected = (typeof window !== "undefined" && window.__PURL_CONFIG__) || {};

export const config: RuntimeConfig = {
  repoOwner: injected.repoOwner ?? fromEnv.repoOwner ?? "prefix-dev",
  repoName: injected.repoName ?? fromEnv.repoName ?? "purl-associator",
  defaultBranch: injected.defaultBranch ?? fromEnv.defaultBranch ?? "main",
  mappingsUrl: injected.mappingsUrl ?? fromEnv.mappingsUrl ?? "./mappings.json",
  mappingsIndexUrl:
    injected.mappingsIndexUrl ?? fromEnv.mappingsIndexUrl ?? "./mappings-index.json",
  cvesUrl: injected.cvesUrl ?? fromEnv.cvesUrl ?? "./cves.json",
  cvesIndexUrl:
    injected.cvesIndexUrl ?? fromEnv.cvesIndexUrl ?? "./cves-index.json",
  aiDraftsUrl:
    injected.aiDraftsUrl ?? fromEnv.aiDraftsUrl ?? "./cve_ai_drafts.json",
  aiQueueUrl:
    injected.aiQueueUrl ?? fromEnv.aiQueueUrl ?? "./cve_ai_queue.json",
  oauthWorkerUrl: injected.oauthWorkerUrl ?? fromEnv.oauthWorkerUrl ?? null,
  githubClientId: injected.githubClientId ?? fromEnv.githubClientId ?? null,
};

export const repoFullName = `${config.repoOwner}/${config.repoName}`;
export const repoUrl = `https://github.com/${repoFullName}`;
