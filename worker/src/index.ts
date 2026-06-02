/* PURL Associator OAuth + GitHub App Worker.
 *
 * Two responsibilities:
 *
 * 1. **OAuth code-exchange** (`POST /exchange`)
 *    The SPA can't call https://github.com/login/oauth/access_token directly
 *    (no CORS, and we'd need to embed client_secret). The Worker swaps the
 *    code server-side and returns the user-to-server access token.
 *
 * 2. **PR submission** (`POST /api/submit`)
 *    The user-to-server token is only used to *identify* the user. Actual
 *    writes to the repository are done with an **installation token** minted
 *    on demand from the GitHub App's private key. This keeps the user's
 *    OAuth scope at "Read your public profile" while still allowing the App
 *    to commit + open PRs scoped to the single repo it's installed on.
 */

type Env = {
  // OAuth (user → identity only)
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;

  // GitHub App credentials (for installation tokens)
  GITHUB_APP_ID: string;
  GITHUB_APP_PRIVATE_KEY: string;
  GITHUB_INSTALLATION_ID: string;

  // Where the App is installed and what to write to
  GITHUB_REPO_OWNER: string;
  GITHUB_REPO_NAME: string;
  GITHUB_DEFAULT_BRANCH: string;
  /** Directory each PURL-edit PR drops a uniquely-named contribution file into. */
  GITHUB_CONTRIBUTIONS_DIR: string;
  /** Directory each CVE-review PR drops a uniquely-named contribution file into. */
  GITHUB_CVE_CONTRIBUTIONS_DIR: string;
  /** Directory each AI-review enqueue PR drops a uniquely-named queue file into. */
  GITHUB_CVE_REVIEW_QUEUE_DIR: string;
  /** Directory where per-package CVE files live (used to validate enqueue requests). */
  GITHUB_CVES_DIR: string;
};

// ---------- Common helpers ----------

const UA = "purl-associator-worker";

function corsHeaders(origin: string | null, _env: Env): Headers {
  // The endpoints here are safe to expose cross-origin: /exchange relies on
  // GitHub validating the OAuth code against the registered client_id +
  // redirect URI, /api/submit requires a user-to-server token from this
  // specific GitHub App, and neither path uses cookies. So echo whatever
  // Origin the browser sent back instead of maintaining an allowlist.
  const headers = new Headers();
  if (origin) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
  } else {
    headers.set("Access-Control-Allow-Origin", "*");
  }
  headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  headers.set("Access-Control-Max-Age", "600");
  return headers;
}

function json(
  body: unknown,
  init: ResponseInit & { origin: string | null; env: Env },
): Response {
  const headers = corsHeaders(init.origin, init.env);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    headers,
  });
}

function b64urlEncodeBytes(bytes: ArrayBuffer | Uint8Array): string {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function b64urlEncodeJson(obj: unknown): string {
  return b64urlEncodeBytes(new TextEncoder().encode(JSON.stringify(obj)));
}

function b64encode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---------- GitHub App: JWT signing + installation tokens ----------

function pemToArrayBuffer(pem: string): ArrayBuffer {
  const stripped = pem
    .replace(/-----BEGIN [A-Z ]+-----/g, "")
    .replace(/-----END [A-Z ]+-----/g, "")
    .replace(/\s+/g, "");
  const binary = atob(stripped);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

let cachedKey: CryptoKey | null = null;

async function loadAppKey(env: Env): Promise<CryptoKey> {
  if (cachedKey) return cachedKey;
  cachedKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToArrayBuffer(env.GITHUB_APP_PRIVATE_KEY),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return cachedKey;
}

async function signAppJwt(env: Env): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  // GitHub Apps now recommend client_id as the JWT issuer; App ID still works.
  const payload = {
    iat: now - 60,
    exp: now + 9 * 60,
    iss: env.GITHUB_CLIENT_ID || env.GITHUB_APP_ID,
  };
  const headerB64 = b64urlEncodeJson(header);
  const payloadB64 = b64urlEncodeJson(payload);
  const data = `${headerB64}.${payloadB64}`;
  const key = await loadAppKey(env);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(data),
  );
  return `${data}.${b64urlEncodeBytes(sig)}`;
}

type InstallationToken = { token: string; expires_at: string };

let cachedToken: InstallationToken | null = null;

async function getInstallationToken(env: Env): Promise<string> {
  if (cachedToken) {
    const expires = new Date(cachedToken.expires_at).getTime();
    if (expires - Date.now() > 60_000) return cachedToken.token;
  }
  const jwt = await signAppJwt(env);
  const res = await fetch(
    `https://api.github.com/app/installations/${env.GITHUB_INSTALLATION_ID}/access_tokens`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: "application/vnd.github+json",
        "User-Agent": UA,
      },
    },
  );
  if (!res.ok) {
    throw new Error(`installation token failed: ${res.status} ${await res.text()}`);
  }
  cachedToken = (await res.json()) as InstallationToken;
  return cachedToken.token;
}

async function ghApi<T>(
  token: string,
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const res = await fetch(`https://api.github.com${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "User-Agent": UA,
      "X-GitHub-Api-Version": "2022-11-28",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 204) return undefined as T;
  if (!res.ok) {
    throw new Error(`GitHub ${method} ${path} → ${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as T;
}

/**
 * Fetch a repository file as raw text via the GitHub Contents API.
 *
 * Uses `Accept: application/vnd.github.raw` instead of the default JSON
 * envelope. Two benefits:
 *
 * 1. The response body is already UTF-8 text — no base64 round-trip — so
 *    non-ASCII advisory text (accents, em-dashes, non-Latin scripts) decodes
 *    correctly.
 * 2. Bypasses the JSON-envelope's 1 MB content limit; raw can return files
 *    far larger than what `contents` returns base64-encoded.
 *
 * Returns 404 → throws an Error with `(404)` in the message so callers can
 * branch on "genuinely missing" vs "transient failure".
 */
async function ghApiText(token: string, path: string): Promise<string> {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github.raw",
      "User-Agent": UA,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });
  if (!res.ok) {
    throw new Error(`GitHub GET ${path} → ${res.status}: ${await res.text()}`);
  }
  return await res.text();
}

// ---------- /exchange ----------

async function handleExchange(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");
  let payload: { code?: string; state?: string };
  try {
    payload = await request.json();
  } catch {
    return json({ error: "invalid_json" }, { status: 400, origin, env });
  }
  if (!payload.code) {
    return json({ error: "missing_code" }, { status: 400, origin, env });
  }
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) {
    return json({ error: "server_misconfigured" }, { status: 500, origin, env });
  }
  const ghBody = new URLSearchParams({
    client_id: env.GITHUB_CLIENT_ID,
    client_secret: env.GITHUB_CLIENT_SECRET,
    code: payload.code,
  });
  const ghResp = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: ghBody.toString(),
  });
  if (!ghResp.ok) {
    return json(
      { error: "github_error", status: ghResp.status, body: await ghResp.text() },
      { status: 502, origin, env },
    );
  }
  const data = (await ghResp.json()) as Record<string, string>;
  if (data.error) {
    return json(
      { error: data.error, description: data.error_description },
      { status: 400, origin, env },
    );
  }
  return json(
    {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
      token_type: data.token_type,
    },
    { status: 200, origin, env },
  );
}

// ---------- /api/submit (apply edits, open PR) ----------

type EditPayload = {
  type: string;
  namespace: string;
  pkgName: string;
  purl: string;
  alternative_purls: string[];
  unmapped: boolean;
  note: string;
};

type SubmitBody = {
  userToken: string;
  edits: Record<string, EditPayload>;
  title: string;
  body: string;
};

type GhUser = {
  login: string;
  name: string | null;
  email: string | null;
};

/** Build the contribution-file payload. Each PR produces one such file
 *  with a unique filename, so two PRs editing the same packages never
 *  conflict on disk. The pages-build step merges all contributions in
 *  chronological order before the SPA reads them.
 */
function buildContributionFile(
  edits: Record<string, EditPayload>,
  user: GhUser,
  title: string,
  timestamp: string,
): string {
  const packages: Record<string, unknown> = {};
  for (const [name, edit] of Object.entries(edits)) {
    if (edit.unmapped) {
      packages[name] = {
        unmapped: true,
        note: edit.note || undefined,
      };
    } else {
      packages[name] = {
        purl: edit.purl,
        type: edit.type,
        namespace: edit.namespace || null,
        pkg_name: edit.pkgName,
        // Always persist the list, including an empty one. Omitting this field
        // lets merge_mappings keep auto-generated alternatives from the base
        // layer, which makes reviewer removals ineffective.
        alternative_purls: edit.alternative_purls,
        note: edit.note || undefined,
      };
    }
  }
  const payload = {
    schema_version: 1,
    title,
    author: user.login,
    author_name: user.name ?? null,
    timestamp,
    packages,
  };
  return JSON.stringify(payload, null, 2) + "\n";
}

function contributionFilename(user: GhUser, timestamp: string): string {
  // Unique per PR, sortable, easy to attribute. e.g.
  //   2026-04-27T08-00-00-000Z--wolfv--3kf91.json
  const tsSafe = timestamp.replace(/[:.]/g, "-");
  const rand = Math.random().toString(36).slice(2, 7);
  const userSafe = user.login.replace(/[^A-Za-z0-9._-]/g, "_");
  return `${tsSafe}--${userSafe}--${rand}.json`;
}

async function handleSubmit(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");
  let payload: SubmitBody;
  try {
    payload = (await request.json()) as SubmitBody;
  } catch {
    return json({ error: "invalid_json" }, { status: 400, origin, env });
  }
  if (
    !payload.userToken ||
    !payload.edits ||
    typeof payload.edits !== "object"
  ) {
    return json({ error: "missing_fields" }, { status: 400, origin, env });
  }
  if (!env.GITHUB_APP_PRIVATE_KEY || !env.GITHUB_INSTALLATION_ID) {
    return json({ error: "app_not_configured" }, { status: 500, origin, env });
  }

  // 1. Identify the user via the OAuth user-to-server token.
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${payload.userToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": UA,
    },
  });
  if (!userRes.ok) {
    return json(
      { error: "invalid_user_token", status: userRes.status },
      { status: 401, origin, env },
    );
  }
  const user = (await userRes.json()) as GhUser;

  // 2. Mint an installation token (App identity) and do the writes with it.
  let installToken: string;
  try {
    installToken = await getInstallationToken(env);
  } catch (err) {
    return json(
      { error: "installation_token_failed", detail: String(err) },
      { status: 500, origin, env },
    );
  }

  const owner = env.GITHUB_REPO_OWNER;
  const repo = env.GITHUB_REPO_NAME;
  const baseBranch = env.GITHUB_DEFAULT_BRANCH || "main";
  const dir = (env.GITHUB_CONTRIBUTIONS_DIR || "mappings/contributions").replace(
    /\/+$/,
    "",
  );
  const timestamp = new Date().toISOString();
  const filename = contributionFilename(user, timestamp);
  const path = `${dir}/${filename}`;
  const branch = `purl-mapping/${user.login}-${Date.now().toString(36)}`;

  try {
    // 3. Branch off default.
    const ref = await ghApi<{ object: { sha: string } }>(
      installToken,
      `/repos/${owner}/${repo}/git/refs/heads/${baseBranch}`,
    );
    await ghApi(
      installToken,
      `/repos/${owner}/${repo}/git/refs`,
      "POST",
      { ref: `refs/heads/${branch}`, sha: ref.object.sha },
    );

    // 4. Each PR writes a uniquely-named contribution file — never edits an
    //    existing one. Two simultaneous PRs are conflict-free on disk.
    const newText = buildContributionFile(
      payload.edits,
      user,
      payload.title,
      timestamp,
    );
    const email = user.email ?? `${user.login}@users.noreply.github.com`;
    const authorBlock = { name: user.name ?? user.login, email };
    await ghApi(
      installToken,
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
      "PUT",
      {
        message: payload.title || "purl: contribution",
        content: b64encode(newText),
        branch,
        author: authorBlock,
        committer: authorBlock,
      },
    );

    // 5. Open the PR.
    const pr = await ghApi<{ number: number; html_url: string }>(
      installToken,
      `/repos/${owner}/${repo}/pulls`,
      "POST",
      {
        title: payload.title || "Update PURL mappings",
        head: branch,
        base: baseBranch,
        body: payload.body,
        maintainer_can_modify: true,
      },
    );

    return json(
      { number: pr.number, html_url: pr.html_url, branch, file: path },
      { status: 200, origin, env },
    );
  } catch (err) {
    return json(
      { error: "github_write_failed", detail: String(err) },
      { status: 500, origin, env },
    );
  }
}

// ---------- /api/submit-cves (apply CVE review edits, open PR) ----------

/** One OpenVEX 0.2.0 statement, as built by the dashboard (cve_api.ts). */
type OpenVexStatement = {
  vulnerability: { name: string };
  products: { "@id": string }[];
  status: string;
  justification?: string;
  action_statement?: string;
  status_notes?: string;
};

type CveSubmitBody = {
  userToken: string;
  /** OpenVEX statements; the Worker wraps them in the document envelope. */
  statements: OpenVexStatement[];
  title: string;
  body: string;
};

const OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0";
const VEX_STATUSES = new Set([
  "affected",
  "not_affected",
  "fixed",
  "under_investigation",
]);

function validateOpenVexStatements(statements: unknown): string | null {
  if (!Array.isArray(statements) || statements.length === 0) {
    return "statements must be a non-empty array";
  }
  for (const [i, stmt] of statements.entries()) {
    if (!stmt || typeof stmt !== "object") {
      return `statements[${i}] must be an object`;
    }
    const s = stmt as Record<string, unknown>;
    const vuln = s.vulnerability;
    if (!vuln || typeof vuln !== "object") {
      return `statements[${i}].vulnerability is required`;
    }
    const vulnName = (vuln as Record<string, unknown>).name;
    if (typeof vulnName !== "string" || vulnName.trim() === "") {
      return `statements[${i}].vulnerability.name is required`;
    }
    if (typeof s.status !== "string" || !VEX_STATUSES.has(s.status)) {
      return `statements[${i}].status is invalid`;
    }
    if (!Array.isArray(s.products) || s.products.length === 0) {
      return `statements[${i}].products must be a non-empty array`;
    }
    for (const [j, product] of s.products.entries()) {
      if (!product || typeof product !== "object") {
        return `statements[${i}].products[${j}] must be an object`;
      }
      const id = (product as Record<string, unknown>)["@id"];
      if (typeof id !== "string" || !id.startsWith("pkg:conda/")) {
        return `statements[${i}].products[${j}].@id must be a conda PURL`;
      }
    }
    if (
      s.status === "not_affected" &&
      typeof s.justification !== "string" &&
      typeof s.impact_statement !== "string"
    ) {
      return `statements[${i}] not_affected requires justification or impact_statement`;
    }
    if (
      s.status === "affected" &&
      (typeof s.action_statement !== "string" ||
        s.action_statement.trim() === "")
    ) {
      return `statements[${i}] affected requires action_statement`;
    }
    for (const key of [
      "justification",
      "impact_statement",
      "action_statement",
      "status_notes",
    ]) {
      if (key in s && typeof s[key] !== "string") {
        return `statements[${i}].${key} must be a string`;
      }
    }
  }
  return null;
}

function buildCveContributionFile(
  statements: OpenVexStatement[],
  user: GhUser,
  docId: string,
  timestamp: string,
): string {
  // A complete OpenVEX 0.2.0 document. The dashboard supplies the
  // statements; the Worker owns the envelope — identity, author, time —
  // which it can attest to and the client cannot forge.
  const doc = {
    "@context": OPENVEX_CONTEXT,
    "@id": docId,
    author: user.login,
    timestamp,
    version: 1,
    tooling: "purl-associator CVE dashboard",
    statements,
  };
  return JSON.stringify(doc, null, 2) + "\n";
}

function cveContributionFilename(user: GhUser, timestamp: string): string {
  const tsSafe = timestamp.replace(/[:.]/g, "-");
  const rand = Math.random().toString(36).slice(2, 7);
  const userSafe = user.login.replace(/[^A-Za-z0-9._-]/g, "_");
  return `${tsSafe}--${userSafe}--${rand}.json`;
}

async function handleSubmitCves(request: Request, env: Env): Promise<Response> {
  const origin = request.headers.get("Origin");
  let payload: CveSubmitBody;
  try {
    payload = (await request.json()) as CveSubmitBody;
  } catch {
    return json({ error: "invalid_json" }, { status: 400, origin, env });
  }
  if (
    !payload.userToken ||
    !Array.isArray(payload.statements) ||
    payload.statements.length === 0
  ) {
    return json({ error: "missing_fields" }, { status: 400, origin, env });
  }
  const statementError = validateOpenVexStatements(payload.statements);
  if (statementError) {
    return json(
      { error: "invalid_openvex", detail: statementError },
      { status: 400, origin, env },
    );
  }
  if (!env.GITHUB_APP_PRIVATE_KEY || !env.GITHUB_INSTALLATION_ID) {
    return json({ error: "app_not_configured" }, { status: 500, origin, env });
  }

  // 1. Identify the user.
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${payload.userToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": UA,
    },
  });
  if (!userRes.ok) {
    return json(
      { error: "invalid_user_token", status: userRes.status },
      { status: 401, origin, env },
    );
  }
  const user = (await userRes.json()) as GhUser;

  // 2. Installation token.
  let installToken: string;
  try {
    installToken = await getInstallationToken(env);
  } catch (err) {
    return json(
      { error: "installation_token_failed", detail: String(err) },
      { status: 500, origin, env },
    );
  }

  const owner = env.GITHUB_REPO_OWNER;
  const repo = env.GITHUB_REPO_NAME;
  const baseBranch = env.GITHUB_DEFAULT_BRANCH || "main";
  const dir = (
    env.GITHUB_CVE_CONTRIBUTIONS_DIR || "mappings/cve_contributions"
  ).replace(/\/+$/, "");
  const timestamp = new Date().toISOString();
  const filename = cveContributionFilename(user, timestamp);
  const path = `${dir}/${filename}`;
  const branch = `cve-review/${user.login}-${Date.now().toString(36)}`;

  try {
    const ref = await ghApi<{ object: { sha: string } }>(
      installToken,
      `/repos/${owner}/${repo}/git/refs/heads/${baseBranch}`,
    );
    await ghApi(
      installToken,
      `/repos/${owner}/${repo}/git/refs`,
      "POST",
      { ref: `refs/heads/${branch}`, sha: ref.object.sha },
    );

    const docId = `https://github.com/${owner}/${repo}/blob/${baseBranch}/${path}`;
    const newText = buildCveContributionFile(
      payload.statements,
      user,
      docId,
      timestamp,
    );
    const email = user.email ?? `${user.login}@users.noreply.github.com`;
    const authorBlock = { name: user.name ?? user.login, email };
    await ghApi(
      installToken,
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
      "PUT",
      {
        message: payload.title || "cves: review",
        content: b64encode(newText),
        branch,
        author: authorBlock,
        committer: authorBlock,
      },
    );

    const pr = await ghApi<{ number: number; html_url: string }>(
      installToken,
      `/repos/${owner}/${repo}/pulls`,
      "POST",
      {
        title: payload.title || "Review CVE assignments",
        head: branch,
        base: baseBranch,
        body: payload.body,
        maintainer_can_modify: true,
      },
    );

    return json(
      { number: pr.number, html_url: pr.html_url, branch, file: path },
      { status: 200, origin, env },
    );
  } catch (err) {
    return json(
      { error: "github_write_failed", detail: String(err) },
      { status: 500, origin, env },
    );
  }
}

// ---------- /api/enqueue-cve-review (queue AI review of one or more advisories) ----------

type EnqueueItem = {
  package: string;
  advisory_id: string;
  reason?: string;
  note?: string;
};

type EnqueueBody = {
  userToken: string;
  items: EnqueueItem[];
  title?: string;
  body?: string;
};

const ENQUEUE_MAX_ITEMS = 50;
const ADVISORY_ID_RE =
  /^(GHSA-|CVE-|OSV-|PYSEC-|RUSTSEC-|GO-|MAL-|NPM-|PLDB-|HSEC-|ASB-|ALAS-|RHSA-)/;

function validateEnqueueItems(items: unknown): { ok: EnqueueItem[]; error: string | null } {
  if (!Array.isArray(items) || items.length === 0) {
    return { ok: [], error: "items must be a non-empty array" };
  }
  if (items.length > ENQUEUE_MAX_ITEMS) {
    return { ok: [], error: `at most ${ENQUEUE_MAX_ITEMS} items per request` };
  }
  const seen = new Set<string>();
  const out: EnqueueItem[] = [];
  for (const [i, raw] of items.entries()) {
    if (!raw || typeof raw !== "object") {
      return { ok: [], error: `items[${i}] must be an object` };
    }
    const r = raw as Record<string, unknown>;
    const pkg = r.package;
    const adv = r.advisory_id;
    if (typeof pkg !== "string" || pkg.trim() === "") {
      return { ok: [], error: `items[${i}].package is required` };
    }
    if (typeof adv !== "string" || !ADVISORY_ID_RE.test(adv)) {
      return { ok: [], error: `items[${i}].advisory_id is not a recognised id` };
    }
    const key = `${pkg}\x00${adv}`;
    if (seen.has(key)) {
      return { ok: [], error: `items[${i}] duplicate (${pkg}, ${adv})` };
    }
    seen.add(key);
    const item: EnqueueItem = { package: pkg, advisory_id: adv };
    if (typeof r.reason === "string") item.reason = r.reason;
    if (typeof r.note === "string") item.note = r.note;
    out.push(item);
  }
  return { ok: out, error: null };
}

type dict = Record<string, unknown> | null;

/** A per-request cache entry. `null` = package file is genuinely missing
 *  (404). `"skipped"` = could not fetch/parse for other reasons; callers
 *  should fail-open rather than reject the queue request. */
type PkgFetchResult = dict | "skipped";

async function fetchPkgFile(
  installToken: string,
  owner: string,
  repo: string,
  branch: string,
  cvesDir: string,
  pkg: string,
): Promise<PkgFetchResult> {
  const path = `${cvesDir}/${pkg}.json`;
  const url = `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(branch)}`;
  let raw: string;
  try {
    raw = await ghApiText(installToken, url);
  } catch (err) {
    const msg = String(err);
    // 404 — file genuinely doesn't exist; let the caller reject the request.
    if (/→ 404/.test(msg)) return null;
    // Anything else (5xx, network blip, surprise schema) — fail-open. We
    // would rather queue a possibly-bad item than fail the whole batch on a
    // transient GitHub hiccup. The AI workflow itself rejects unknown pairs
    // with a clean skipped[] entry.
    console.warn(`fetchPkgFile(${pkg}): falling back to fail-open: ${msg}`);
    return "skipped";
  }
  try {
    return JSON.parse(raw) as dict;
  } catch (err) {
    console.warn(`fetchPkgFile(${pkg}): JSON parse failed, fail-open: ${err}`);
    return "skipped";
  }
}

async function verifyAdvisoryExists(
  installToken: string,
  owner: string,
  repo: string,
  branch: string,
  cvesDir: string,
  pkg: string,
  advisoryId: string,
  pkgCache: Map<string, PkgFetchResult>,
): Promise<string | null> {
  let pkgData = pkgCache.get(pkg);
  if (pkgData === undefined) {
    pkgData = await fetchPkgFile(
      installToken,
      owner,
      repo,
      branch,
      cvesDir,
      pkg,
    );
    pkgCache.set(pkg, pkgData);
  }
  if (pkgData === null) {
    return `unknown package: ${pkg}`;
  }
  if (pkgData === "skipped") {
    // Couldn't verify — accept the pair and let the AI workflow handle it.
    return null;
  }
  const advisories = (pkgData as { advisories?: unknown[] }).advisories ?? [];
  for (const adv of advisories) {
    if (!adv || typeof adv !== "object") continue;
    const a = adv as Record<string, unknown>;
    if (a.id === advisoryId) return null;
    const aliases = a.aliases;
    if (Array.isArray(aliases) && aliases.includes(advisoryId)) return null;
  }
  return `advisory ${advisoryId} not found in ${pkg}.json`;
}

function buildQueueFile(
  items: EnqueueItem[],
  user: GhUser,
  timestamp: string,
): string {
  return (
    JSON.stringify(
      {
        schema_version: 1,
        enqueued_at: timestamp,
        enqueued_by: "worker",
        author: user.login,
        items,
      },
      null,
      2,
    ) + "\n"
  );
}

function queueFilename(user: GhUser, timestamp: string): string {
  const tsSafe = timestamp.replace(/[:.]/g, "-");
  const rand = Math.random().toString(36).slice(2, 7);
  const userSafe = user.login.replace(/[^A-Za-z0-9._-]/g, "_");
  return `${tsSafe}--${userSafe}--${rand}.json`;
}

function renderEnqueuePrBody(items: EnqueueItem[], user: GhUser, extra: string): string {
  const rows = items
    .map(
      (it) =>
        `- \`${it.package}\` / \`${it.advisory_id}\`${
          it.note ? ` — ${it.note}` : ""
        }`,
    )
    .join("\n");
  const trailer = extra ? `\n\n---\n\n${extra}` : "";
  return (
    `Queueing **${items.length}** advisory pair(s) for AI CVE coverage review ` +
    `(requested by @${user.login}).\n\n${rows}\n\n` +
    `Merge this queue PR first. After it lands on \`main\`, the next ` +
    `\`cve_ai_review.yml\` run will pick these up and open a separate ` +
    `"AI CVE review drafts" PR with the model's verdicts.${trailer}`
  );
}

async function handleEnqueueCveReview(
  request: Request,
  env: Env,
): Promise<Response> {
  const origin = request.headers.get("Origin");
  let payload: EnqueueBody;
  try {
    payload = (await request.json()) as EnqueueBody;
  } catch {
    return json({ error: "invalid_json" }, { status: 400, origin, env });
  }
  if (!payload.userToken) {
    return json({ error: "missing_fields" }, { status: 400, origin, env });
  }
  const { ok: items, error: itemsError } = validateEnqueueItems(payload.items);
  if (itemsError) {
    return json(
      { error: "invalid_items", detail: itemsError },
      { status: 400, origin, env },
    );
  }
  if (!env.GITHUB_APP_PRIVATE_KEY || !env.GITHUB_INSTALLATION_ID) {
    return json({ error: "app_not_configured" }, { status: 500, origin, env });
  }

  // 1. Identify the user.
  const userRes = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${payload.userToken}`,
      Accept: "application/vnd.github+json",
      "User-Agent": UA,
    },
  });
  if (!userRes.ok) {
    return json(
      { error: "invalid_user_token", status: userRes.status },
      { status: 401, origin, env },
    );
  }
  const user = (await userRes.json()) as GhUser;

  // 2. Installation token (App identity for writes).
  let installToken: string;
  try {
    installToken = await getInstallationToken(env);
  } catch (err) {
    return json(
      { error: "installation_token_failed", detail: String(err) },
      { status: 500, origin, env },
    );
  }

  const owner = env.GITHUB_REPO_OWNER;
  const repo = env.GITHUB_REPO_NAME;
  const baseBranch = env.GITHUB_DEFAULT_BRANCH || "main";
  const queueDir = (
    env.GITHUB_CVE_REVIEW_QUEUE_DIR || "mappings/cve_review_queue"
  ).replace(/\/+$/, "");
  const cvesDir = (env.GITHUB_CVES_DIR || "mappings/cves").replace(/\/+$/, "");

  // 3. Sanity-check each (package, advisory) pair exists in the bundle on the
  //    default branch — prevents spammers from queueing nonsense or typos.
  //    Fail-open on transient errors (5xx, network blips, parse failures) —
  //    only a genuine 404 on the package file rejects the request.
  const pkgCache = new Map<string, PkgFetchResult>();
  for (const it of items) {
    const err = await verifyAdvisoryExists(
      installToken,
      owner,
      repo,
      baseBranch,
      cvesDir,
      it.package,
      it.advisory_id,
      pkgCache,
    );
    if (err) {
      return json(
        { error: "unknown_pair", detail: err },
        { status: 400, origin, env },
      );
    }
  }

  const timestamp = new Date().toISOString();
  const filename = queueFilename(user, timestamp);
  const path = `${queueDir}/${filename}`;
  const branch = `cve-ai-queue/${user.login}-${Date.now().toString(36)}`;

  try {
    const ref = await ghApi<{ object: { sha: string } }>(
      installToken,
      `/repos/${owner}/${repo}/git/refs/heads/${baseBranch}`,
    );
    await ghApi(installToken, `/repos/${owner}/${repo}/git/refs`, "POST", {
      ref: `refs/heads/${branch}`,
      sha: ref.object.sha,
    });

    const newText = buildQueueFile(items, user, timestamp);
    const email = user.email ?? `${user.login}@users.noreply.github.com`;
    const authorBlock = { name: user.name ?? user.login, email };
    await ghApi(
      installToken,
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
      "PUT",
      {
        message: payload.title || `queue AI CVE review for ${items.length} pair(s)`,
        content: b64encode(newText),
        branch,
        author: authorBlock,
        committer: authorBlock,
      },
    );

    const pr = await ghApi<{ number: number; html_url: string }>(
      installToken,
      `/repos/${owner}/${repo}/pulls`,
      "POST",
      {
        title:
          payload.title || `Queue AI CVE review (${items.length} item${items.length === 1 ? "" : "s"})`,
        head: branch,
        base: baseBranch,
        body: renderEnqueuePrBody(items, user, payload.body || ""),
        maintainer_can_modify: true,
      },
    );

    return json(
      { number: pr.number, html_url: pr.html_url, branch, file: path },
      { status: 200, origin, env },
    );
  } catch (err) {
    return json(
      { error: "github_write_failed", detail: String(err) },
      { status: 500, origin, env },
    );
  }
}

// ---------- Router ----------

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin");
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin, env),
      });
    }
    if (url.pathname === "/healthz") {
      return json({ ok: true }, { origin, env });
    }
    if (url.pathname === "/exchange" && request.method === "POST") {
      return handleExchange(request, env);
    }
    if (url.pathname === "/api/submit" && request.method === "POST") {
      return handleSubmit(request, env);
    }
    if (url.pathname === "/api/submit-cves" && request.method === "POST") {
      return handleSubmitCves(request, env);
    }
    if (url.pathname === "/api/enqueue-cve-review" && request.method === "POST") {
      return handleEnqueueCveReview(request, env);
    }
    return json({ error: "not_found" }, { status: 404, origin, env });
  },
};
