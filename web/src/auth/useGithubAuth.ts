import { useEffect, useState } from "react";
import type { GitHubUser } from "../data/types";
import {
  consumeOauthCallback,
  fetchUser,
  hasOauthCallback,
  loadStoredToken,
  logout,
} from "./github";

export type GithubAuthState = {
  token: string | null;
  user: GitHubUser | null;
  error: string | null;
  isLoggedIn: boolean;
  signOut: () => void;
};

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Owns GitHub session bootstrap for the SPA.
 *
 * Apps should not duplicate OAuth callback/session handling. Editing is local
 * and auth-agnostic; this hook is only consumed by sign-in UI and PR drawers.
 */
export function useGithubAuth(): GithubAuthState {
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const stored = loadStoredToken();
    if (stored) {
      setToken(stored);
      fetchUser(stored)
        .then(setUser)
        .catch(() => {
          logout();
          setToken(null);
        });
      return;
    }

    if (!hasOauthCallback()) return;

    consumeOauthCallback()
      .then(async (newToken) => {
        if (!newToken) return;
        setToken(newToken);
        try {
          setUser(await fetchUser(newToken));
        } catch (err) {
          setError(errorMessage(err));
        }
      })
      .catch((err) => setError(errorMessage(err)));
  }, []);

  function signOut(): void {
    logout();
    setToken(null);
    setUser(null);
  }

  return {
    token,
    user,
    error,
    isLoggedIn: Boolean(token && user),
    signOut,
  };
}
