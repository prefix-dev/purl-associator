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
  GITHUB_MANUAL_PATH: string;

  ALLOWED_ORIGINS: string;
};

// ---------- Common helpers ----------

const UA = "purl-associator-worker";

function corsHeaders(origin: string | null, env: Env): Headers {
  const allowed = (env.ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const headers = new Headers();
  if (origin && (allowed.includes(origin) || allowed.includes("*"))) {
    headers.set("Access-Control-Allow-Origin", origin);
    headers.set("Vary", "Origin");
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

function b64urlEncodeBytes(bytes: ArrayBuffer): string {
  const arr = new Uint8Array(bytes);
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

function b64decode(b64: string): string {
  const bin = atob(b64.replace(/\s+/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
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

function applyEditsToManual(
  manualText: string,
  edits: Record<string, EditPayload>,
  user: GhUser,
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
  for (const [name, edit] of Object.entries(edits)) {
    if (edit.unmapped) {
      manual.packages[name] = {
        unmapped: true,
        note: edit.note || undefined,
        approved_by: user.login,
        approved_at: now,
      };
    } else {
      manual.packages[name] = {
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
  const path = env.GITHUB_MANUAL_PATH || "mappings/manual.json";
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

    // 4. Read existing manual.json on the new branch.
    let existing: { sha: string; content: string } | null = null;
    try {
      existing = await ghApi<{ sha: string; content: string }>(
        installToken,
        `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(branch)}`,
      );
    } catch (err) {
      if (!String(err).includes("404")) throw err;
    }
    const existingText = existing
      ? b64decode(existing.content)
      : '{"schema_version":1,"packages":{}}';
    const newText = applyEditsToManual(existingText, payload.edits, user);

    // 5. Commit. Author is the user (so the PR is attributed correctly), but
    //    the commit is made via the App's installation token.
    const email = user.email ?? `${user.login}@users.noreply.github.com`;
    const authorBlock = {
      name: user.name ?? user.login,
      email,
    };
    await ghApi(
      installToken,
      `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`,
      "PUT",
      {
        message: payload.title || "purl: update mappings",
        content: b64encode(newText),
        sha: existing?.sha,
        branch,
        author: authorBlock,
        committer: authorBlock,
      },
    );

    // 6. Open the PR.
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
      { number: pr.number, html_url: pr.html_url, branch },
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
    return json({ error: "not_found" }, { status: 404, origin, env });
  },
};
