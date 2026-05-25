/**
 * Centralized low-level browser storage for auth/session data.
 *
 * User-owned draft state lives in `stores/userState.ts` and is persisted via
 * Zustand. OAuth data stays here because it is short-lived, redirect-driven,
 * and intentionally scoped to the current tab/session.
 */
const STORAGE_KEYS = {
  /** GitHub OAuth access token. Tab-local auth cache. */
  githubToken: "purl-associator/gh_token",
  /** GitHub OAuth state nonce. Tab-local CSRF protection for the redirect. */
  oauthState: "purl-associator/oauth_state",
} as const;

class BrowserStorage {
  readonly keys = STORAGE_KEYS;

  loadGithubToken(): string | null {
    return this.getString(sessionStorage, this.keys.githubToken);
  }

  saveGithubToken(token: string): void {
    this.setString(sessionStorage, this.keys.githubToken, token);
  }

  clearGithubToken(): void {
    this.remove(sessionStorage, this.keys.githubToken);
  }

  saveOauthState(state: string): void {
    this.setString(sessionStorage, this.keys.oauthState, state);
  }

  loadOauthState(): string | null {
    return this.getString(sessionStorage, this.keys.oauthState);
  }

  clearOauthState(): void {
    this.remove(sessionStorage, this.keys.oauthState);
  }

  private getString(storage: Storage, key: string): string | null {
    try {
      return storage.getItem(key);
    } catch {
      return null;
    }
  }

  private setString(storage: Storage, key: string, value: string): void {
    try {
      storage.setItem(key, value);
    } catch {
      // Ignore unavailable/quota-limited storage. The app still works in-memory.
    }
  }

  private remove(storage: Storage, key: string): void {
    try {
      storage.removeItem(key);
    } catch {
      // ignore
    }
  }
}

export const browserStorage = new BrowserStorage();
