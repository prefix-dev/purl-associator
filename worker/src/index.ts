/* OAuth code-exchange worker for the PURL Associator.
 *
 * Endpoints:
 *   POST /exchange   — { code, state } → { access_token, scope, token_type }
 *   GET  /healthz    — health probe
 *
 * Everything else returns 404. The worker is stateless; the GitHub OAuth
 * client_secret comes from the `GITHUB_CLIENT_SECRET` worker secret.
 */
type Env = {
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  ALLOWED_ORIGINS: string; // comma-separated
};

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
  headers.set("Access-Control-Allow-Headers", "Content-Type");
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
    return json(
      { error: "server_misconfigured" },
      { status: 500, origin, env },
    );
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
    const text = await ghResp.text();
    return json(
      { error: "github_error", status: ghResp.status, body: text },
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
      token_type: data.token_type,
      scope: data.scope,
    },
    { status: 200, origin, env },
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin");
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }

    if (url.pathname === "/healthz") {
      return json({ ok: true }, { origin, env });
    }
    if (url.pathname === "/exchange" && request.method === "POST") {
      return handleExchange(request, env);
    }
    return json({ error: "not_found" }, { status: 404, origin, env });
  },
};
