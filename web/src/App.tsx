import { useEffect, useMemo, useState } from "react";
import { useGithubAuth } from "./auth/useGithubAuth";
import { BulkPanel } from "./components/BulkPanel";
import { LocalDraftBanner } from "./components/LocalDraftBanner";
import { LoginModal } from "./components/LoginModal";
import { MappingEditor } from "./components/MappingEditor";
import { PackageTable } from "./components/PackageTable";
import { PRDrawer } from "./components/PRDrawer";
import { Btn, Glyph, useTheme } from "./components/Primitives";
import { repoFullName } from "./config";
import { purlsFromAlternatives } from "./data/purlAlternatives";
import type { Edit, MappingPackageIndex, PackageEntry } from "./data/types";
import { useMappingsData } from "./data/useMappingsData";
import { usePurlEditStore } from "./stores/userState";

export function App() {
  const theme = useTheme();
  const {
    payload,
    packages,
    loadError,
    detailError,
    details,
    loadingDetails,
    ensurePackageDetail,
  } = useMappingsData();
  const [selectedSet, setSelectedSet] = useState<Set<string>>(new Set());
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const edits = usePurlEditStore((state) => state.edits);
  const setEdits = usePurlEditStore((state) => state.setEdits);
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState({
    unmappedOnly: false,
    unverifiedOnly: false,
    deepOnly: false,
    ecosystem: "all",
  });
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const { token, user, error: authError, isLoggedIn, signOut } = useGithubAuth();

  const t = theme.t;

  // Default: when packages first arrive, focus the first row (but don't
  // mark it as selected — selection is the checkbox state).
  useEffect(() => {
    if (focusedId === null && packages.length > 0) {
      setFocusedId(packages[0].name);
    }
  }, [packages, focusedId]);

  useEffect(() => {
    if (focusedId && !details[focusedId]) {
      ensurePackageDetail(focusedId).catch(() => {
        // detailError is set by the hook.
      });
    }
  }, [details, ensurePackageDetail, focusedId]);

  const focusedPkg = focusedId ? details[focusedId] ?? null : null;

  const selectedPackages = useMemo(
    () => packages.filter((p) => selectedSet.has(p.name)),
    [packages, selectedSet],
  );

  const deepInspectionNames = useMemo(() => {
    const names = new Set<string>();
    for (const p of packages) {
      if (p.deep_inspection?.candidate) names.add(p.name);
    }
    return names;
  }, [packages]);

  const editsCount = Object.keys(edits).length;
  const showBulk = selectedSet.size > 1;

  function handleEdit(newEdit: Edit): void {
    if (!focusedPkg) return;
    const currentAltSet = new Set(
      purlsFromAlternatives(focusedPkg.alternative_purls).sort(),
    );
    const editAltSet = new Set([...newEdit.alternative_purls].sort());
    const altsMatch =
      currentAltSet.size === editAltSet.size &&
      [...currentAltSet].every((p) => editAltSet.has(p));
    const isSame =
      !newEdit.unmapped &&
      newEdit.purl === (focusedPkg.purl ?? "") &&
      newEdit.type === (focusedPkg.type ?? "") &&
      (newEdit.namespace || "") === (focusedPkg.namespace || "") &&
      newEdit.pkgName === (focusedPkg.pkg_name ?? focusedPkg.name) &&
      altsMatch &&
      !newEdit.note;
    setEdits((prev) => {
      const next = { ...prev };
      if (isSame) delete next[focusedPkg.name];
      else next[focusedPkg.name] = newEdit;
      return next;
    });
  }

  function approveOne(p: MappingPackageIndex | PackageEntry): Edit | null {
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
      alternative_purls: purlsFromAlternatives(auto.alternative_purls),
      unmapped: false,
      note: "",
      approved: true,
    };
  }

  function handleApprove(): void {
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
            <span
              style={{
                color: t.fg1,
                padding: "4px 8px",
                borderRadius: 6,
                background: t.inset,
              }}
            >
              PURL Mapper
            </span>
            <a
              href="./cve.html"
              style={{
                color: t.fg2,
                textDecoration: "none",
                padding: "4px 8px",
                borderRadius: 6,
              }}
            >
              CVE Dashboard
            </a>
            <a
              href="./deep.html"
              style={{
                color: t.fg2,
                textDecoration: "none",
                padding: "4px 8px",
                borderRadius: 6,
              }}
            >
              Deep Package Inspection
            </a>
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
                onClick={signOut}
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

      <LocalDraftBanner
        theme={theme}
        count={editsCount}
        noun="change"
        onReview={() => setDrawerOpen(true)}
        onDiscard={() => {
          if (window.confirm("Discard all locally saved staged changes?")) {
            setEdits({});
          }
        }}
      />

      {!isLoggedIn && (
        <div
          style={{
            padding: "7px 18px",
            background: theme.dark ? "#151c26" : "#eaf3ff",
            borderBottom: `1px solid ${theme.dark ? "#26364a" : "#c7daf2"}`,
            fontSize: 12,
            color: t.fg1,
            display: "flex",
            alignItems: "center",
            gap: 8,
          }}
        >
          <Glyph name="edit" size={13} />
          You can stage local mapping changes without signing in.
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
          when you're ready to open a PR.
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

      {(loadError || detailError) && (
        <div
          style={{
            padding: "7px 18px",
            background: theme.dark ? "#3a1f1f" : "#ffe5dc",
            color: t.bad,
            fontSize: 12,
          }}
        >
          Failed to load mappings: {loadError || detailError}
        </div>
      )}

      <div
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns: "minmax(0, 60fr) minmax(0, 40fr)",
          minHeight: 0,
        }}
      >
        <div style={{ minWidth: 0, minHeight: 0 }}>
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
              deepInspectionNames={deepInspectionNames}
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

        <div style={{ minWidth: 0, display: "flex" }}>
          {showBulk ? (
            <BulkPanel
              theme={theme}
              selectedPackages={selectedPackages}
              edits={edits}
              onApproveAll={handleBulkApprove}
              onMarkUnmappedAll={handleBulkMarkUnmapped}
              onResetSelected={handleBulkResetSelected}
              onClearSelection={() => setSelectedSet(new Set())}
            />
          ) : focusedId && loadingDetails.has(focusedId) && !focusedPkg ? (
            <div
              style={{
                flex: 1,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: t.page,
                color: t.fg2,
                fontSize: 13,
              }}
            >
              Loading package details…
            </div>
          ) : (
            <MappingEditor
              theme={theme}
              pkg={focusedPkg}
              edit={focusedPkg ? edits[focusedPkg.name] : undefined}
              onEdit={handleEdit}
              onApprove={handleApprove}
              onResetAuto={handleResetAuto}
            />
          )}
        </div>
      </div>

      {drawerOpen && (
        <PRDrawer
          theme={theme}
          edits={edits}
          packages={details}
          ensurePackageDetail={ensurePackageDetail}
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
