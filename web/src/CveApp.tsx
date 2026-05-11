import { useEffect, useMemo, useState } from "react";
import {
  consumeOauthCallback,
  fetchUser,
  hasOauthCallback,
  loadStoredToken,
  logout,
} from "./auth/github";
import { LoginModal } from "./components/LoginModal";
import { Btn, Glyph, useTheme } from "./components/Primitives";
import { CvePackageList } from "./components/CvePackageList";
import { CveDetail } from "./components/CveDetail";
import { CvePRDrawer } from "./components/CvePRDrawer";
import { config, repoFullName } from "./config";
import {
  blankReviewEdit,
  editFromReview,
  isEditNonEmpty,
  loadCves,
  type CvePayload,
  type ReviewEdit,
} from "./data/cves";
import type { GitHubUser } from "./data/types";

const EDITS_KEY = "purl-associator/staged_cve_edits";

export function CveApp() {
  const theme = useTheme();
  const [payload, setPayload] = useState<CvePayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [focusedPkg, setFocusedPkg] = useState<string | null>(null);
  const [edits, setEdits] = useState<Record<string, ReviewEdit>>({});
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "unreviewed" | "reviewed">(
    "all",
  );
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const t = theme.t;

  useEffect(() => {
    loadCves(config.cvesUrl)
      .then((data) => {
        setPayload(data);
        const first = Object.keys(data.packages).sort()[0];
        if (first) setFocusedPkg(first);
      })
      .catch((err) => setLoadError(err instanceof Error ? err.message : String(err)));
  }, []);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem(EDITS_KEY);
      if (stored) setEdits(JSON.parse(stored));
    } catch {
      // ignore
    }
  }, []);
  useEffect(() => {
    try {
      if (Object.keys(edits).length === 0) sessionStorage.removeItem(EDITS_KEY);
      else sessionStorage.setItem(EDITS_KEY, JSON.stringify(edits));
    } catch {
      // ignore
    }
  }, [edits]);

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
    if (hasOauthCallback()) {
      consumeOauthCallback()
        .then(async (newToken) => {
          if (!newToken) return;
          setToken(newToken);
          try {
            setUser(await fetchUser(newToken));
          } catch (err) {
            setAuthError(err instanceof Error ? err.message : String(err));
          }
        })
        .catch((err) => setAuthError(err instanceof Error ? err.message : String(err)));
    }
  }, []);

  const packages = useMemo(() => {
    if (!payload) return [];
    return Object.values(payload.packages).sort((a, b) =>
      a.package.localeCompare(b.package),
    );
  }, [payload]);

  const focusedPackage = useMemo(
    () =>
      focusedPkg && payload ? payload.packages[focusedPkg] ?? null : null,
    [focusedPkg, payload],
  );

  const editsCount = Object.keys(edits).length;
  const isLoggedIn = Boolean(token && user);

  function editKey(pkg: string, advisoryId: string): string {
    return `${pkg}::${advisoryId}`;
  }

  function handleEdit(
    pkg: string,
    advisoryId: string,
    next: ReviewEdit,
    base: ReviewEdit,
  ): void {
    if (!isLoggedIn) setLoginOpen(true);
    const key = editKey(pkg, advisoryId);
    setEdits((prev) => {
      const out = { ...prev };
      // Erase the edit when it collapses back to whatever the base review
      // already records — keeps the drawer free of "ghost" entries that
      // wouldn't change anything on disk.
      const base_ = focusedPackage
        ? focusedPackage.advisories.find((a) => a.id === advisoryId)?.review
        : undefined;
      const stillDifferent =
        isEditNonEmpty(next, base_) || next.status !== base.status;
      if (!stillDifferent) {
        delete out[key];
      } else {
        out[key] = next;
      }
      return out;
    });
  }

  function handleResetEdit(pkg: string, advisoryId: string): void {
    const key = editKey(pkg, advisoryId);
    setEdits((prev) => {
      const out = { ...prev };
      delete out[key];
      return out;
    });
  }

  function handleSignOut(): void {
    logout();
    setToken(null);
    setUser(null);
  }

  return (
    <div
      className={theme.dark ? "dark-scope" : ""}
      style={{
        background: t.page,
        height: "100vh",
        display: "flex",
        flexDirection: "column",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 18px",
          borderBottom: `1px solid ${t.border}`,
          background: t.surface,
          flexShrink: 0,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <a
            href="./index.html"
            style={{ textDecoration: "none", display: "inline-flex" }}
          >
            <img
              src={theme.dark ? "./assets/logo_dark.svg" : "./assets/logo_light.svg"}
              alt="prefix.dev"
              style={{ height: 22 }}
            />
          </a>
          <nav
            style={{
              display: "flex",
              gap: 6,
              fontSize: 11,
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: ".08em",
              borderLeft: `1px solid ${t.border}`,
              paddingLeft: 14,
            }}
          >
            <a
              href="./index.html"
              style={{
                color: t.fg2,
                textDecoration: "none",
                padding: "4px 8px",
                borderRadius: 6,
              }}
            >
              PURL Mapper
            </a>
            <span
              style={{
                color: t.fg1,
                padding: "4px 8px",
                borderRadius: 6,
                background: t.inset,
              }}
            >
              CVE Dashboard
            </span>
          </nav>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              fontSize: 11,
              padding: "3px 8px",
              borderRadius: 4,
              background: t.inset,
              color: t.fg2,
              fontFamily: "JetBrains Mono, monospace",
            }}
          >
            <Glyph name="branch" size={11} />
            {repoFullName}
          </div>
          {payload && (
            <div style={{ fontSize: 11, color: t.fg3 }}>
              {payload.advisory_count.toLocaleString()} advisories ·{" "}
              {payload.affected_version_count.toLocaleString()} affected versions ·{" "}
              {payload.package_count.toLocaleString()} packages
            </div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <button
            onClick={() => theme.setDark(!theme.dark)}
            style={{
              background: t.surface2,
              border: `1px solid ${t.border}`,
              color: t.fg1,
              borderRadius: 8,
              width: 30,
              height: 30,
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              fontSize: 14,
            }}
            title="Toggle theme"
          >
            {theme.dark ? "☀" : "☾"}
          </button>

          <Btn
            theme={theme}
            variant={editsCount > 0 ? "primary" : "ghost"}
            icon="pr"
            onClick={() => setDrawerOpen(true)}
            disabled={editsCount === 0}
          >
            {editsCount === 0 ? "No staged reviews" : `Review changes (${editsCount})`}
          </Btn>

          {isLoggedIn && user ? (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 7,
                padding: "3px 8px 3px 4px",
                border: `1px solid ${t.border}`,
                borderRadius: 999,
              }}
            >
              <img
                src={user.avatar_url}
                alt={user.login}
                width={22}
                height={22}
                style={{ borderRadius: "50%" }}
              />
              <span style={{ fontSize: 12, fontWeight: 600, color: t.fg1 }}>
                @{user.login}
              </span>
              <button
                onClick={handleSignOut}
                title="Sign out"
                style={{
                  background: "transparent",
                  border: 0,
                  color: t.fg3,
                  cursor: "pointer",
                  padding: 2,
                  marginLeft: 2,
                }}
              >
                <Glyph name="close" size={11} />
              </button>
            </div>
          ) : (
            <Btn
              theme={theme}
              variant="secondary"
              icon="github"
              onClick={() => setLoginOpen(true)}
            >
              Sign in
            </Btn>
          )}
        </div>
      </header>

      {!isLoggedIn && (
        <div
          style={{
            padding: "7px 18px",
            background: theme.dark ? "#1f1a0d" : "#fff7d6",
            borderBottom: `1px solid ${theme.dark ? "#3a3416" : "#f0e2a3"}`,
            fontSize: 12,
            color: t.fg1,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Glyph name="eye" size={13} />
          You're browsing in read-only mode.
          <button
            onClick={() => setLoginOpen(true)}
            style={{
              background: "transparent",
              border: 0,
              color: t.link,
              fontWeight: 600,
              fontSize: 12,
              cursor: "pointer",
              padding: 0,
            }}
          >
            Sign in with GitHub
          </button>
          to submit reviews.
        </div>
      )}

      {authError && (
        <div
          style={{
            padding: "7px 18px",
            background: theme.dark ? "#3a1f1f" : "#ffe5dc",
            color: t.bad,
            fontSize: 12,
          }}
        >
          Auth error: {authError}
        </div>
      )}

      {loadError && (
        <div
          style={{
            padding: "7px 18px",
            background: theme.dark ? "#3a1f1f" : "#ffe5dc",
            color: t.bad,
            fontSize: 12,
          }}
        >
          Failed to load advisories: {loadError}
        </div>
      )}

      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        <div style={{ flex: "0 0 38%", minWidth: 0 }}>
          {payload ? (
            <CvePackageList
              theme={theme}
              packages={packages}
              edits={edits}
              focusedId={focusedPkg}
              setFocusedId={setFocusedPkg}
              q={q}
              setQ={setQ}
              statusFilter={statusFilter}
              setStatusFilter={setStatusFilter}
            />
          ) : (
            <div
              style={{
                padding: 30,
                color: t.fg2,
                textAlign: "center",
                fontSize: 13,
              }}
            >
              Loading advisories…
            </div>
          )}
        </div>

        <div style={{ flex: 1, minWidth: 0, display: "flex" }}>
          <CveDetail
            theme={theme}
            pkg={focusedPackage}
            edits={edits}
            onEdit={(advisoryId, edit) => {
              if (!focusedPackage) return;
              const base = editFromReview(
                focusedPackage.advisories.find((a) => a.id === advisoryId)?.review,
              );
              handleEdit(focusedPackage.package, advisoryId, edit, base);
            }}
            onResetEdit={(advisoryId) => {
              if (!focusedPackage) return;
              handleResetEdit(focusedPackage.package, advisoryId);
            }}
            blankEdit={blankReviewEdit}
            isLoggedIn={isLoggedIn}
            onRequestLogin={() => setLoginOpen(true)}
          />
        </div>
      </div>

      {drawerOpen && payload && (
        <CvePRDrawer
          theme={theme}
          edits={edits}
          packages={payload.packages}
          onClose={() => setDrawerOpen(false)}
          onCommit={() => {
            setEdits({});
            setDrawerOpen(false);
          }}
          onSelect={(pkg, advisoryId) => {
            setFocusedPkg(pkg);
            setDrawerOpen(false);
            // Scroll the advisory into view next tick.
            requestAnimationFrame(() => {
              const el = document.getElementById(`adv-${advisoryId}`);
              if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
            });
          }}
          isLoggedIn={isLoggedIn}
          onRequestLogin={() => setLoginOpen(true)}
          user={user}
          token={token}
        />
      )}

      {loginOpen && <LoginModal theme={theme} onClose={() => setLoginOpen(false)} />}
    </div>
  );
}
