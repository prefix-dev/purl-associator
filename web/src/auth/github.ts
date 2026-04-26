/* GitHub OAuth web flow.
 *
 * Standard authorization-code flow:
 * 1. Frontend redirects user to https://github.com/login/oauth/authorize?...
 * 2. After consent, GitHub redirects back to our callback (the SPA itself)
 *    with ?code=XXX&state=YYY.
 * 3. Frontend POSTs the code to a tiny Cloudflare Worker which holds the
 *    client_secret and calls https://github.com/login/oauth/access_token.
 * 4. Worker returns { access_token, token_type, scope }; we cache it in
 *    sessionStorage. The token is used directly against api.github.com (which
 *    is CORS-enabled, unlike the OAuth endpoints).
 */
import { config } from "../config";
import type { GitHubUser } from "../data/types";

const TOKEN_KEY = "purl-associator/gh_token";
const STATE_KEY = "purl-associator/oauth_state";
const SCOPES = "public_repo";

export type AuthState =
  | { kind: "anonymous" }
  | { kind: "authenticated"; token: string; user: GitHubUser }
  | { kind: "configuring"; reason: string };

export function loadStoredToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function clearStoredToken(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // ignore
  }
}

function storeToken(token: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    // ignore
  }
}

export function isOauthConfigured(): boolean {
  return Boolean(config.githubClientId && config.oauthWorkerUrl);
}

export function startLogin(): void {
  if (!config.githubClientId) {
    throw new Error("GitHub client ID not configured");
  }
  const state = crypto.randomUUID();
  sessionStorage.setItem(STATE_KEY, state);
  const redirectUri = `${location.origin}${location.pathname}`;
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", config.githubClientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("state", state);
  location.assign(url.toString());
}

/** Returns true if the URL contains an OAuth callback we should handle. */
export function hasOauthCallback(): boolean {
  return new URLSearchParams(location.search).has("code");
}

/** Handle a GitHub OAuth redirect: exchange the code via the Worker, store
 *  the token, then strip the query string from the URL. Returns the access
 *  token, or null if no callback was present. */
export async function consumeOauthCallback(): Promise<string | null> {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  const state = params.get("state");
  if (!code) return null;

  const expected = sessionStorage.getItem(STATE_KEY);
  if (expected && expected !== state) {
    throw new Error("OAuth state mismatch — possible CSRF, refusing to continue.");
  }
  sessionStorage.removeItem(STATE_KEY);

  if (!config.oauthWorkerUrl) {
    throw new Error("OAuth worker URL not configured");
  }

  const res = await fetch(`${config.oauthWorkerUrl.replace(/\/$/, "")}/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code, state }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`OAuth exchange failed: ${res.status} ${text}`);
  }
  const payload = (await res.json()) as { access_token?: string; error?: string };
  if (!payload.access_token) {
    throw new Error(payload.error ?? "no access_token in response");
  }
  storeToken(payload.access_token);

  // Strip OAuth params from the URL bar.
  const cleanUrl = `${location.origin}${location.pathname}`;
  history.replaceState({}, "", cleanUrl);
  return payload.access_token;
}

export async function fetchUser(token: string): Promise<GitHubUser> {
  const res = await fetch("https://api.github.com/user", {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
    },
  });
  if (!res.ok) throw new Error(`GitHub /user failed: ${res.status}`);
  const data = await res.json();
  return {
    login: data.login,
    name: data.name ?? null,
    avatar_url: data.avatar_url,
    initial: (data.login as string).charAt(0).toUpperCase(),
    color: "#ffd432",
  };
}

export function logout(): void {
  clearStoredToken();
}
