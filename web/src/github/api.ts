/* Minimal GitHub API client for opening a PR with edited mappings.
 *
 * Flow ("commit to a branch on origin"):
 * 1. GET /repos/:owner/:repo to learn default branch + permissions.
 * 2. If user has push access → push directly to a new branch in the same repo.
 *    Otherwise → fork the repo, then push to a branch in the fork.
 * 3. PUT /repos/:owner/:repo/contents/mappings/manual.json with the merged
 *    file contents (base64 encoded) and a commit message.
 * 4. POST /repos/:upstream-owner/:repo/pulls with head=user:branch.
 */
import { config } from "../config";
import type { Edit, PackageEntry } from "../data/types";

type Headers = Record<string, string>;

function authHeaders(token: string): Headers {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

async function gh<T>(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const res = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      ...authHeaders(token),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GitHub ${method} ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

export type RepoMeta = {
  default_branch: string;
  permissions?: { push?: boolean; pull?: boolean; admin?: boolean };
  owner: { login: string };
  name: string;
  fork: boolean;
};

export async function getRepo(token: string, owner: string, name: string): Promise<RepoMeta> {
  return gh<RepoMeta>(token, "GET", `/repos/${owner}/${name}`);
}

export async function ensureFork(
  token: string,
  upstreamOwner: string,
  repo: string,
  userLogin: string,
): Promise<RepoMeta> {
  // Try to read the user's fork; if 404, create it.
  try {
    const fork = await getRepo(token, userLogin, repo);
    if (fork.fork) return fork;
  } catch {
    // fall through to create
  }
  await gh(token, "POST", `/repos/${upstreamOwner}/${repo}/forks`, {});
  // Forks are created async — poll briefly.
  for (let i = 0; i < 10; i++) {
    try {
      return await getRepo(token, userLogin, repo);
    } catch {
      await new Promise((r) => setTimeout(r, 1500));
    }
  }
  throw new Error("Fork was not ready in time, please try again.");
}

type RefObject = { object: { sha: string } };

async function getDefaultBranchSha(
  token: string,
  owner: string,
  repo: string,
  branch: string,
): Promise<string> {
  const ref = await gh<RefObject>(
    token,
    "GET",
    `/repos/${owner}/${repo}/git/refs/heads/${branch}`,
  );
  return ref.object.sha;
}

async function createBranch(
  token: string,
  owner: string,
  repo: string,
  newBranch: string,
  sha: string,
): Promise<void> {
  await gh(token, "POST", `/repos/${owner}/${repo}/git/refs`, {
    ref: `refs/heads/${newBranch}`,
    sha,
  });
}

type FileContents = { sha: string; content: string };

async function readFile(
  token: string,
  owner: string,
  repo: string,
  path: string,
  ref: string,
): Promise<FileContents | null> {
  try {
    return await gh<FileContents>(
      token,
      "GET",
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`,
    );
  } catch (err) {
    if (String(err).includes("404")) return null;
    throw err;
  }
}

function encodeBase64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function decodeBase64Utf8(b64: string): string {
  const bin = atob(b64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

async function writeFile(
  token: string,
  owner: string,
  repo: string,
  branch: string,
  path: string,
  content: string,
  sha: string | undefined,
  message: string,
): Promise<void> {
  await gh(token, "PUT", `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
    message,
    content: encodeBase64Utf8(content),
    sha,
    branch,
  });
}

export type CreatedPR = {
  number: number;
  html_url: string;
  head: { ref: string };
};

async function createPullRequest(
  token: string,
  upstreamOwner: string,
  repo: string,
  head: string,
  base: string,
  title: string,
  body: string,
): Promise<CreatedPR> {
  return gh<CreatedPR>(token, "POST", `/repos/${upstreamOwner}/${repo}/pulls`, {
    title,
    head,
    base,
    body,
    maintainer_can_modify: true,
  });
}

/** Apply a set of edits to the existing manual.json in the repo and return
 *  the new file contents as a JSON string. */
export function applyEditsToManual(
  manualText: string,
  packages: PackageEntry[],
  edits: Record<string, Edit>,
  user: { login: string },
): string {
  let manual: {
    schema_version?: number;
    updated_at?: string | null;
    description?: string;
    packages: Record<string, unknown>;
  };
  try {
    manual = JSON.parse(manualText);
  } catch {
    manual = { packages: {} };
  }
  if (!manual.packages || typeof manual.packages !== "object") manual.packages = {};

  const now = new Date().toISOString();
  for (const [id, edit] of Object.entries(edits)) {
    const pkg = packages.find((p) => p.name === id);
    if (!pkg) continue;
    if (edit.unmapped) {
      manual.packages[pkg.name] = {
        unmapped: true,
        note: edit.note || undefined,
        approved_by: user.login,
        approved_at: now,
      };
    } else {
      manual.packages[pkg.name] = {
        purl: edit.purl,
        type: edit.type,
        namespace: edit.namespace || null,
        pkg_name: edit.pkgName,
        alternative_purls:
          edit.alternative_purls.length > 0 ? edit.alternative_purls : undefined,
        note: edit.note || undefined,
        approved_by: user.login,
        approved_at: now,
      };
    }
  }
  manual.updated_at = now;
  manual.schema_version = manual.schema_version ?? 1;
  manual.description =
    manual.description ??
    "Human-curated PURL overrides for conda-forge packages. Editing happens through the web UI.";
  return JSON.stringify(manual, null, 2) + "\n";
}

export type SubmitOptions = {
  token: string;
  user: { login: string };
  packages: PackageEntry[];
  edits: Record<string, Edit>;
  title: string;
  body: string;
  manualPath?: string;
};

export type SubmitResult = {
  pr: CreatedPR;
  branch: string;
  workingRepoOwner: string;
};

export async function submitEditsAsPR(opts: SubmitOptions): Promise<SubmitResult> {
  const upstreamOwner = config.repoOwner;
  const upstreamRepo = config.repoName;
  const baseBranch = config.defaultBranch;
  const manualPath = opts.manualPath ?? "mappings/manual.json";

  const upstream = await getRepo(opts.token, upstreamOwner, upstreamRepo);
  const canPush = upstream.permissions?.push === true;
  const workingRepoOwner = canPush ? upstreamOwner : opts.user.login;
  const workingRepoName = upstreamRepo;

  if (!canPush) {
    await ensureFork(opts.token, upstreamOwner, upstreamRepo, opts.user.login);
  }

  const baseSha = await getDefaultBranchSha(
    opts.token,
    workingRepoOwner,
    workingRepoName,
    baseBranch,
  );

  const branch = `purl-mapping/${opts.user.login}-${Date.now().toString(36)}`;
  await createBranch(opts.token, workingRepoOwner, workingRepoName, branch, baseSha);

  const existing = await readFile(
    opts.token,
    workingRepoOwner,
    workingRepoName,
    manualPath,
    branch,
  );
  const existingText = existing
    ? decodeBase64Utf8(existing.content)
    : '{"schema_version":1,"packages":{}}';
  const newText = applyEditsToManual(existingText, opts.packages, opts.edits, opts.user);

  await writeFile(
    opts.token,
    workingRepoOwner,
    workingRepoName,
    branch,
    manualPath,
    newText,
    existing?.sha,
    opts.title,
  );

  const head = canPush ? branch : `${opts.user.login}:${branch}`;
  const pr = await createPullRequest(
    opts.token,
    upstreamOwner,
    upstreamRepo,
    head,
    baseBranch,
    opts.title,
    opts.body,
  );
  return { pr, branch, workingRepoOwner };
}
