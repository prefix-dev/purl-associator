import { useEffect, useMemo, useState } from "react";
import { useGithubAuth } from "./auth/useGithubAuth";
import { BulkPanel } from "./components/BulkPanel";
import { DeepInspectionPanel } from "./components/DeepInspectionPanel";
import { LocalDraftBanner } from "./components/LocalDraftBanner";
import { LoginModal } from "./components/LoginModal";
import { MappingEditor } from "./components/MappingEditor";
import { PackageTable } from "./components/PackageTable";
import { PRDrawer } from "./components/PRDrawer";
import { Btn, Glyph, useTheme } from "./components/Primitives";
import { repoFullName } from "./config";
import {
  loadSbomDetail,
  loadSbomSummary,
  type SbomDetailPayload,
  type SbomSummaryPayload,
} from "./data/sboms";
import { purlsFromAlternatives } from "./data/purlAlternatives";
import type { Edit, PackageEntry } from "./data/types";
import { useMappingsData } from "./data/useMappingsData";
import { usePurlEditStore } from "./stores/userState";

export function App() {
  const theme = useTheme();
  const { payload, packages, loadError } = useMappingsData();
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
  const [activeView, setActiveView] = useState<"mapper" | "deep">("mapper");
  const [sbomSummary, setSbomSummary] = useState<SbomSummaryPayload | null>(null);
  const [sbomDetails, setSbomDetails] = useState<
    Record<string, SbomDetailPayload | null>
  >({});

  const t = theme.t;

  useEffect(() => {
    loadSbomSummary().then(setSbomSummary);
  }, []);

  // Lazy-load the per-artifact SBOM-CVE detail when a package with matches is
  // focused. ``null`` means "we tried and there is no detail file" (i.e. the
  // package has 0 transitive CVEs) so we can render the clean-bill section.
  useEffect(() => {
    if (!focusedId) return;
    const summary = sbomSummary?.packages[focusedId];
    if (!summary) return;
    if (sbomDetails[focusedId] !== undefined) return;
    if (summary.advisory_count === 0) {
      setSbomDetails((prev) => ({ ...prev, [focusedId]: null }));
      return;
    }
    loadSbomDetail(summary).then((d) =>
      setSbomDetails((prev) => ({ ...prev, [focusedId]: d })),
    );
  }, [focusedId, sbomSummary, sbomDetails]);

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

  const deepInspectionNames = useMemo(() => {
    const names = new Set<string>();
    for (const p of packages) {
      if (p.deep_inspection?.candidate) names.add(p.name);
    }
    for (const name of Object.keys(sbomSummary?.packages ?? {})) {
      names.add(name);
    }
    return names;
  }, [packages, sbomSummary]);

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

  function showDeepInspections(): void {
    setActiveView("deep");
    setQ("");
    setFilters({
      unmappedOnly: false,
      unverifiedOnly: false,
      deepOnly: true,
      ecosystem: "all",
    });
    const first = packages.find((p) => deepInspectionNames.has(p.name));
    if (first) {
      setFocusedId(first.name);
      setSelectedSet(new Set());
    }
  }

  function showPurlMapper(): void {
    setActiveView("mapper");
    setFilters((prev) => ({ ...prev, deepOnly: false }));
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
            <button
              onClick={showPurlMapper}
              style={{
                color: activeView === "mapper" ? t.fg1 : t.fg2,
                padding: "4px 8px",
                borderRadius: 6,
                background: activeView === "mapper" ? t.inset : "transparent",
                border: 0,
                font: "inherit",
                textTransform: "inherit",
                letterSpacing: "inherit",
                cursor: "pointer",
              }}
            >
              PURL Mapper
            </button>
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
            <button
              onClick={showDeepInspections}
              style={{
                color: activeView === "deep" ? t.fg1 : t.fg2,
                background: activeView === "deep" ? t.inset : "transparent",
                border: 0,
                textDecoration: "none",
                padding: "4px 8px",
                borderRadius: 6,
                font: "inherit",
                textTransform: "inherit",
                letterSpacing: "inherit",
                cursor: "pointer",
              }}
            >
              Deep Package Inspection
            </button>
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

      <div
        style={{
          flex: 1,
          display: "grid",
          gridTemplateColumns:
            activeView === "deep"
              ? "minmax(0, 48fr) minmax(0, 52fr)"
              : "minmax(0, 60fr) minmax(0, 40fr)",
          minHeight: 0,
        }}
      >
        <div style={{ minWidth: 0 }}>
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

        {activeView === "mapper" ? (
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
        ) : (
          <div style={{ minWidth: 0, display: "flex" }}>
            <DeepInspectionPanel
              theme={theme}
              pkg={focusedPkg}
              summary={
                focusedPkg ? sbomSummary?.packages[focusedPkg.name] ?? null : null
              }
              detail={focusedPkg ? sbomDetails[focusedPkg.name] ?? null : null}
            />
          </div>
        )}
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
