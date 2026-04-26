import { useEffect, useMemo, useState } from "react";
import {
  consumeOauthCallback,
  fetchUser,
  hasOauthCallback,
  loadStoredToken,
  logout,
} from "./auth/github";
import { LoginModal } from "./components/LoginModal";
import { MappingEditor } from "./components/MappingEditor";
import { PackageList } from "./components/PackageList";
import { PRDrawer } from "./components/PRDrawer";
import { Btn, Glyph, useTheme } from "./components/Primitives";
import { config, repoFullName } from "./config";
import { loadMappings, packagesAsList } from "./data/loader";
import type { Edit, GitHubUser, MappingsPayload, PackageEntry } from "./data/types";

export function App() {
  const theme = useTheme();
  const [payload, setPayload] = useState<MappingsPayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [packages, setPackages] = useState<PackageEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [edits, setEdits] = useState<Record<string, Edit>>({});
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState({
    unmappedOnly: false,
    unverifiedOnly: false,
    ecosystem: "all",
  });
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);

  const t = theme.t;

  useEffect(() => {
    loadMappings(config.mappingsUrl)
      .then((data) => {
        setPayload(data);
        setPackages(packagesAsList(data));
      })
      .catch((err) => setLoadError(err instanceof Error ? err.message : String(err)));
  }, []);

  // Restore an existing session, or finish an OAuth callback.
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

  useEffect(() => {
    if (!selectedId && packages.length > 0) setSelectedId(packages[0].name);
  }, [packages, selectedId]);

  const selectedPkg = useMemo(
    () => (selectedId ? packages.find((p) => p.name === selectedId) ?? null : null),
    [packages, selectedId],
  );
  const editsCount = Object.keys(edits).length;
  const isLoggedIn = Boolean(token && user);

  function handleEdit(newEdit: Edit): void {
    if (!isLoggedIn) {
      setLoginOpen(true);
      return;
    }
    if (!selectedPkg) return;
    const auto = selectedPkg.auto ?? {
      purl: selectedPkg.purl,
      type: selectedPkg.type,
      namespace: selectedPkg.namespace,
      pkg_name: selectedPkg.pkg_name,
    };
    const isSame =
      auto.purl &&
      !newEdit.unmapped &&
      newEdit.purl === auto.purl &&
      newEdit.type === auto.type &&
      (newEdit.namespace || "") === (auto.namespace || "") &&
      newEdit.pkgName === auto.pkg_name &&
      !newEdit.note;
    setEdits((prev) => {
      const next = { ...prev };
      if (isSame) delete next[selectedPkg.name];
      else next[selectedPkg.name] = newEdit;
      return next;
    });
  }

  function handleApprove(): void {
    if (!isLoggedIn) {
      setLoginOpen(true);
      return;
    }
    if (!selectedPkg) return;
    const auto = selectedPkg.auto ?? {
      purl: selectedPkg.purl,
      type: selectedPkg.type,
      namespace: selectedPkg.namespace,
      pkg_name: selectedPkg.pkg_name,
    };
    if (!auto.purl) return;
    setEdits((prev) => ({
      ...prev,
      [selectedPkg.name]: {
        purl: auto.purl ?? "",
        type: auto.type ?? "pypi",
        namespace: auto.namespace ?? "",
        pkgName: auto.pkg_name ?? selectedPkg.name,
        unmapped: false,
        note: "",
        approved: true,
      },
    }));
  }

  function handleResetAuto(): void {
    if (!selectedPkg) return;
    setEdits((prev) => {
      const next = { ...prev };
      delete next[selectedPkg.name];
      return next;
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
          <img
            src={theme.dark ? "./assets/logo_dark.svg" : "./assets/logo_light.svg"}
            alt="prefix.dev"
            style={{ height: 22 }}
          />
          <div
            style={{
              fontSize: 11,
              color: t.fg3,
              textTransform: "uppercase",
              letterSpacing: ".08em",
              borderLeft: `1px solid ${t.border}`,
              paddingLeft: 14,
              fontWeight: 600,
            }}
          >
            PURL Associator
          </div>
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
            {editsCount === 0 ? "No staged changes" : `Review changes (${editsCount})`}
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
          to edit mappings.
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
          Failed to load mappings: {loadError}
        </div>
      )}

      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        <div style={{ width: 380, flexShrink: 0 }}>
          {payload ? (
            <PackageList
              theme={theme}
              packages={packages}
              selectedId={selectedId}
              onSelect={setSelectedId}
              edits={edits}
              q={q}
              setQ={setQ}
              filters={filters}
              setFilters={setFilters}
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
              Loading mappings…
            </div>
          )}
        </div>
        <MappingEditor
          theme={theme}
          pkg={selectedPkg}
          edit={selectedPkg ? edits[selectedPkg.name] : undefined}
          onEdit={handleEdit}
          onApprove={handleApprove}
          onResetAuto={handleResetAuto}
          isLoggedIn={isLoggedIn}
          onRequestLogin={() => setLoginOpen(true)}
        />
      </div>

      {drawerOpen && (
        <PRDrawer
          theme={theme}
          edits={edits}
          packages={packages}
          onClose={() => setDrawerOpen(false)}
          onCommit={() => {
            setEdits({});
            setDrawerOpen(false);
          }}
          isLoggedIn={isLoggedIn}
          onRequestLogin={() => setLoginOpen(true)}
          user={user}
          onSelect={(id) => {
            setSelectedId(id);
            setDrawerOpen(false);
          }}
          token={token}
        />
      )}

      {loginOpen && <LoginModal theme={theme} onClose={() => setLoginOpen(false)} />}
    </div>
  );
}
