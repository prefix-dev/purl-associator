import { useState } from "react";
import { isOauthConfigured, startLogin } from "../auth/github";
import { repoFullName } from "../config";
import { Btn, Glyph, Theme } from "./Primitives";

export function LoginModal({
  theme,
  onClose,
}: {
  theme: Theme;
  onClose: () => void;
}) {
  const t = theme.t;
  const [error, setError] = useState<string | null>(null);
  const configured = isOauthConfigured();

  function handleLogin(): void {
    try {
      startLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <>
      <div
        onClick={onClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,15,36,0.42)",
          zIndex: 60,
        }}
      />
      <div
        style={{
          position: "fixed",
          top: "50%",
          left: "50%",
          transform: "translate(-50%,-50%)",
          background: t.surface,
          border: `1px solid ${t.border}`,
          borderRadius: 16,
          padding: 28,
          width: 400,
          zIndex: 61,
          textAlign: "center",
          boxShadow: "0 20px 60px rgba(0,15,36,.25)",
        }}
      >
        <div
          style={{
            width: 56,
            height: 56,
            borderRadius: 14,
            background: "#001d38",
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            marginBottom: 14,
            color: t.accent,
          }}
        >
          <Glyph name="github" size={28} stroke={1.5} />
        </div>
        <h3
          style={{
            fontFamily: "Moranga, serif",
            fontWeight: 300,
            fontSize: 24,
            margin: "0 0 6px",
          }}
        >
          Sign in to edit
        </h3>
        <div
          style={{
            fontSize: 13,
            color: t.fg2,
            marginBottom: 20,
            lineHeight: 1.5,
          }}
        >
          We'll commit your changes as a pull request to{" "}
          <code
            style={{
              background: t.inset,
              padding: "1px 5px",
              borderRadius: 3,
              fontSize: 11.5,
            }}
          >
            {repoFullName}
          </code>{" "}
          using your GitHub identity.
        </div>

        {!configured && (
          <div
            style={{
              fontSize: 12,
              color: t.fg2,
              background: theme.dark ? "#2a2616" : "#fff7d6",
              border: `1px solid ${theme.dark ? "#3a3416" : "#f0e2a3"}`,
              borderRadius: 8,
              padding: "10px 12px",
              marginBottom: 14,
              textAlign: "left",
              lineHeight: 1.5,
            }}
          >
            <strong>OAuth not configured.</strong>
            <br />
            Deploy the worker in <code>worker/</code>, register a GitHub OAuth
            App, then set <code>VITE_GITHUB_CLIENT_ID</code> and{" "}
            <code>VITE_OAUTH_WORKER_URL</code> when building. See README.
          </div>
        )}

        {error && (
          <div
            style={{
              fontSize: 12,
              color: t.bad,
              background: theme.dark ? "#3a1f1f" : "#ffe5dc",
              padding: "8px 10px",
              borderRadius: 6,
              marginBottom: 12,
              whiteSpace: "pre-wrap",
            }}
          >
            {error}
          </div>
        )}

        <Btn
          theme={theme}
          variant="secondary"
          size="lg"
          icon="github"
          onClick={handleLogin}
          disabled={!configured}
          style={{ width: "100%", justifyContent: "center" }}
        >
          Continue with GitHub
        </Btn>
        <button
          onClick={onClose}
          style={{
            background: "transparent",
            border: 0,
            color: t.fg2,
            fontSize: 12,
            marginTop: 12,
            cursor: "pointer",
            fontWeight: 500,
          }}
        >
          Keep browsing read-only
        </button>
      </div>
    </>
  );
}
