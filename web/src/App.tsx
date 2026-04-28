import { useEffect, useMemo, useState } from "react";
import {
  consumeOauthCallback,
  fetchUser,
  hasOauthCallback,
  loadStoredToken,
  logout,
} from "./auth/github";
import { BulkPanel } from "./components/BulkPanel";
import { LoginModal } from "./components/LoginModal";
import { MappingEditor } from "./components/MappingEditor";
import { PackageTable } from "./components/PackageTable";
import { PRDrawer } from "./components/PRDrawer";
import { Btn, Glyph, useTheme } from "./components/Primitives";
import { config, repoFullName } from "./config";
import { loadMappings, packagesAsList } from "./data/loader";
import type { Edit, GitHubUser, MappingsPayload, PackageEntry } from "./data/types";

const EDITS_KEY = "purl-associator/staged_edits";

export function App() {
  const theme = useTheme();
  const [payload, setPayload] = useState<MappingsPayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [packages, setPackages] = useState<PackageEntry[]>([]);
  const [selectedSet, setSelectedSet] = useState<Set<string>>(new Set());
  const [focusedId, setFocusedId] = useState<string | null>(null);
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

  // Persist staged edits across the OAuth full-page redirect (sessionStorage
  // is per-tab and survives same-tab navigations).
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

  // Default: when packages first arrive, focus the first row (but don't
  // mark it as selected — selection is the checkbox state).
  useEffect(() => {
    if (focusedId === null && packages.length > 0) {
      setFocusedId(packages[0].name);
    }
  }, [packages, focusedId]);

  const focusedPkg = useMemo(
    () => (focusedId ? packages.find((p) => p.name === focusedId) ?? null : null),
    [packages, focusedId],
  );

  const selectedPackages = useMemo(
    () => packages.filter((p) => selectedSet.has(p.name)),
    [packages, selectedSet],
  );

  const editsCount = Object.keys(edits).length;
  const isLoggedIn = Boolean(token && user);
  const showBulk = selectedSet.size > 1;

  function handleEdit(newEdit: Edit): void {
    if (!isLoggedIn) setLoginOpen(true);
    if (!focusedPkg) return;
    const auto = focusedPkg.auto ?? {
      purl: focusedPkg.purl,
      type: focusedPkg.type,
      namespace: focusedPkg.namespace,
      pkg_name: focusedPkg.pkg_name,
      alternative_purls: focusedPkg.alternative_purls,
    };
    const autoAltSet = new Set(
      (auto.alternative_purls ?? []).map((a) => a.purl).sort(),
    );
    const editAltSet = new Set([...newEdit.alternative_purls].sort());
    const altsMatch =
      autoAltSet.size === editAltSet.size &&
      [...autoAltSet].every((p) => editAltSet.has(p));
    const isSame =
      auto.purl &&
      !newEdit.unmapped &&
      newEdit.purl === auto.purl &&
      newEdit.type === auto.type &&
      (newEdit.namespace || "") === (auto.namespace || "") &&
      newEdit.pkgName === auto.pkg_name &&
      altsMatch &&
      !newEdit.note;
    setEdits((prev) => {
      const next = { ...prev };
      if (isSame) delete next[focusedPkg.name];
      else next[focusedPkg.name] = newEdit;
      return next;
    });
  }

  function approveOne(p: PackageEntry): Edit | null {
    const auto = p.auto ?? {
      purl: p.purl,
      type: p.type,
      namespace: p.namespace,
      pkg_name: p.pkg_name,
      alternative_purls: p.alternative_purls,
    };
    if (!auto.purl) return null;
    return {
      purl: auto.purl,
      type: auto.type ?? "pypi",
      namespace: auto.namespace ?? "",
      pkgName: auto.pkg_name ?? p.name,
      alternative_purls: (auto.alternative_purls ?? []).map((a) => a.purl),
      unmapped: false,
      note: "",
      approved: true,
    };
  }

  function handleApprove(): void {
    if (!isLoggedIn) setLoginOpen(true);
    if (!focusedPkg) return;
    const e = approveOne(focusedPkg);
    if (!e) return;
    setEdits((prev) => ({ ...prev, [focusedPkg.name]: e }));
  }

  function handleResetAuto(): void {
    if (!focusedPkg) return;
    setEdits((prev) => {
      const next = { ...prev };
      delete next[focusedPkg.name];
      return next;
    });
  }

  function handleBulkApprove(): void {
    setEdits((prev) => {
      const next = { ...prev };
      for (const p of selectedPackages) {
        const e = approveOne(p);
        if (e) next[p.name] = e;
      }
      return next;
    });
  }

  function handleBulkMarkUnmapped(): void {
    setEdits((prev) => {
      const next = { ...prev };
      for (const p of selectedPackages) {
        next[p.name] = {
          purl: "",
          type: p.type ?? "generic",
          namespace: p.namespace ?? "",
          pkgName: p.pkg_name ?? p.name,
          alternative_purls: [],
          unmapped: true,
          note: "",
        };
      }
      return next;
    });
  }

  function handleBulkResetSelected(): void {
    setEdits((prev) => {
      const next = { ...prev };
      for (const p of selectedPackages) delete next[p.name];
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
        <div style={{ flex: "0 0 60%", minWidth: 0 }}>
          {payload ? (
            <PackageTable
              theme={theme}
              packages={packages}
              edits={edits}
              selectedSet={selectedSet}
              setSelectedSet={setSelectedSet}
              focusedId={focusedId}
              setFocusedId={setFocusedId}
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

        <div style={{ flex: 1, minWidth: 0, display: "flex" }}>
          {showBulk ? (
            <BulkPanel
              theme={theme}
              selectedPackages={selectedPackages}
              edits={edits}
              isLoggedIn={isLoggedIn}
              onRequestLogin={() => setLoginOpen(true)}
              onApproveAll={handleBulkApprove}
              onMarkUnmappedAll={handleBulkMarkUnmapped}
              onResetSelected={handleBulkResetSelected}
              onClearSelection={() => setSelectedSet(new Set())}
            />
          ) : (
            <MappingEditor
              theme={theme}
              pkg={focusedPkg}
              edit={focusedPkg ? edits[focusedPkg.name] : undefined}
              onEdit={handleEdit}
              onApprove={handleApprove}
              onResetAuto={handleResetAuto}
              isLoggedIn={isLoggedIn}
              onRequestLogin={() => setLoginOpen(true)}
            />
          )}
        </div>
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
            setSelectedSet(new Set([id]));
            setFocusedId(id);
            setDrawerOpen(false);
          }}
          token={token}
        />
      )}

      {loginOpen && <LoginModal theme={theme} onClose={() => setLoginOpen(false)} />}
    </div>
  );
}
