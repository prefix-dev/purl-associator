import { useEffect, useMemo, useState } from "react";
import { useGithubAuth } from "./auth/useGithubAuth";
import { LoadingToast } from "./components/LoadingToast";
import { LocalDraftBanner } from "./components/LocalDraftBanner";
import { LoginModal } from "./components/LoginModal";
import { Btn, Glyph, useTheme } from "./components/Primitives";
import { CvePackageList } from "./components/CvePackageList";
import { CveActiveList } from "./components/CveActiveList";
import { CveAiWorkList } from "./components/CveAiWorkList";
import { CveDetail } from "./components/CveDetail";
import { CvePRDrawer } from "./components/CvePRDrawer";
import { CveEnqueueDrawer } from "./components/CveEnqueueDrawer";
import { config, repoFullName } from "./config";
import {
  advisoryVex,
  editFromVex,
  isEditNonEmpty,
  loadAiDrafts,
  loadAiQueue,
  type CvePackageIndex,
  type AiDraftsPayload,
  type AiQueuePayload,
  type ReviewEdit,
} from "./data/cves";
import { useCveData } from "./data/useCveData";
import { useCveEditStore } from "./stores/userState";
import type { EnqueueItem } from "./github/cve_enqueue_api";

export function CveApp() {
  const theme = useTheme();
  const {
    payload,
    loadError,
    focusedPkg,
    setFocusedPkg,
    representatives,
    membersByRep,
    focusedPackage,
    focusedPackageLoading,
    detailError,
    ensurePackageDetail,
    packageDetails,
  } = useCveData();
  const edits = useCveEditStore((state) => state.edits);
  const setEdits = useCveEditStore((state) => state.setEdits);
  const [focusedAdvisoryId, setFocusedAdvisoryId] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "unreviewed" | "reviewed">(
    "all",
  );
  const [view, setView] = useState<"browse" | "active" | "aiQueue" | "aiDrafts">("active");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loginOpen, setLoginOpen] = useState(false);
  const { token, user, error: authError, isLoggedIn, signOut } = useGithubAuth();

  // AI CVE review state.
  const [aiDrafts, setAiDrafts] = useState<AiDraftsPayload | null>(null);
  const [aiQueue, setAiQueue] = useState<AiQueuePayload | null>(null);
  const [enqueueItems, setEnqueueItems] = useState<EnqueueItem[]>([]);
  const [enqueueOpen, setEnqueueOpen] = useState(false);

  const t = theme.t;

  // AI CVE review sidecars — loaded once on mount. Loaders are non-throwing
  // (return EMPTY_DRAFTS / EMPTY_QUEUE on failure with a console.warn) so a
  // missing sidecar before the first cve_ai_review run doesn't break the
  // dashboard.
  useEffect(() => {
    loadAiDrafts(config.aiDraftsUrl).then(setAiDrafts);
    loadAiQueue(config.aiQueueUrl).then(setAiQueue);
  }, []);

  // Packages that still have at least one unreviewed advisory shipping now
  // (or affecting a future version). Ordered the same way the triage list
  // is — worst severity first, "now" before "future" within ties — so the
  // "next package" button walks through them in priority order. The
  // per-package "first advisory" must match the row that CveActiveList
  // shows at the top of the package's section, otherwise the jump appears
  // to land on a random CVE.
  const triageQueue = useMemo(() => {
    const out: Array<{
      pkg: CvePackageIndex;
      firstAdvId: string;
      worst: number;
      hasNow: boolean;
      downloads: number;
    }> = [];
    for (const pkg of representatives) {
      const rows: Array<{
        adv: (typeof pkg.advisories)[number];
        kind: "now" | "future";
        score: number;
        reviewed: boolean;
      }> = [];
      for (const adv of pkg.advisories) {
        const now = adv.active_now;
        const future = !now && adv.affects_future;
        if (!now && !future) continue;
        const score = adv.severity?.score_num ?? 0;
        const key = `${pkg.package}::${adv.id}`;
        const effective = edits[key]?.status ?? adv.vex_status;
        const reviewed = !!effective && effective !== "under_investigation";
        rows.push({ adv, kind: now ? "now" : "future", score, reviewed });
      }
      if (rows.length === 0) continue;
      // Matches the per-package row sort in CveActiveList.
      rows.sort((a, b) => {
        if (a.score !== b.score) return b.score - a.score;
        if (a.kind !== b.kind) return a.kind === "now" ? -1 : 1;
        if (a.reviewed !== b.reviewed) return a.reviewed ? 1 : -1;
        return a.adv.primary_id.localeCompare(b.adv.primary_id);
      });
      const firstUnreviewed = rows.find((r) => !r.reviewed);
      if (!firstUnreviewed) continue;
      out.push({
        pkg,
        firstAdvId: firstUnreviewed.adv.id,
        worst: rows[0].score,
        hasNow: rows.some((r) => r.kind === "now"),
        downloads: pkg.download_count ?? -1,
      });
    }
    out.sort((a, b) => {
      if (a.downloads !== b.downloads) return b.downloads - a.downloads;
      if (a.worst !== b.worst) return b.worst - a.worst;
      if (a.hasNow !== b.hasNow) return a.hasNow ? -1 : 1;
      return a.pkg.package.localeCompare(b.pkg.package);
    });
    return out;
  }, [representatives, edits]);

  const goToNextTriagePackage = useMemo<(() => void) | null>(() => {
    if (triageQueue.length === 0) return null;
    const idx = triageQueue.findIndex(
      (entry) => entry.pkg.package === focusedPkg,
    );
    const nextIdx = idx === -1 ? 0 : idx + 1;
    if (nextIdx >= triageQueue.length) return null;
    const next = triageQueue[nextIdx];
    return () => {
      setFocusedPkg(next.pkg.package);
      setFocusedAdvisoryId(next.firstAdvId);
    };
  }, [triageQueue, focusedPkg]);

  const editsCount = Object.keys(edits).length;

  function editKey(pkg: string, advisoryId: string): string {
    return `${pkg}::${advisoryId}`;
  }

  function handleEdit(
    pkg: string,
    advisoryId: string,
    next: ReviewEdit,
    base: ReviewEdit,
  ): void {
    const key = editKey(pkg, advisoryId);
    setEdits((prev) => {
      const out = { ...prev };
      // Erase the edit when it collapses back to whatever the base review
      // already records — keeps the drawer free of "ghost" entries that
      // wouldn't change anything on disk.
      const advisory = focusedPackage?.advisories.find(
        (a) => a.id === advisoryId,
      );
      const base_ = advisory ? advisoryVex(advisory) : undefined;
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

  const enqueuedSet = useMemo(
    () => new Set(enqueueItems.map((it) => `${it.package}::${it.advisory_id}`)),
    [enqueueItems],
  );

  function handleEnqueueAi(pkg: string, advisoryId: string): void {
    if (!isLoggedIn) {
      setLoginOpen(true);
    }
    const key = `${pkg}::${advisoryId}`;
    if (enqueuedSet.has(key)) return;
    setEnqueueItems((prev) => [...prev, { package: pkg, advisory_id: advisoryId }]);
    setEnqueueOpen(true);
  }

  function handleRemoveEnqueue(pkg: string, advisoryId: string): void {
    setEnqueueItems((prev) =>
      prev.filter((it) => !(it.package === pkg && it.advisory_id === advisoryId)),
    );
  }

  function handleBulkEnqueueAi(items: EnqueueItem[]): void {
    if (items.length === 0) return;
    if (!isLoggedIn) setLoginOpen(true);
    setEnqueueItems((prev) => {
      const seen = new Set(prev.map((it) => `${it.package}::${it.advisory_id}`));
      const out = [...prev];
      for (const it of items) {
        const key = `${it.package}::${it.advisory_id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(it);
      }
      return out;
    });
    setEnqueueOpen(true);
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
            variant={enqueueItems.length > 0 ? "primary" : "ghost"}
            onClick={() => setEnqueueOpen(true)}
            disabled={enqueueItems.length === 0}
          >
            🤖{" "}
            {enqueueItems.length === 0
              ? "No AI reviews queued"
              : `Ask AI (${enqueueItems.length})`}
          </Btn>

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
        noun="review"
        onReview={() => setDrawerOpen(true)}
        onDiscard={() => {
          if (window.confirm("Discard all locally saved staged reviews?")) {
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
          You can stage local CVE reviews without signing in.
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
          Failed to load advisories: {loadError || detailError}
        </div>
      )}

      <div style={{ flex: 1, display: "flex", minHeight: 0 }}>
        <div
          style={{
            flex: "0 0 38%",
            minWidth: 0,
            display: "flex",
            flexDirection: "column",
            background: t.surface,
            borderRight: `1px solid ${t.border}`,
          }}
        >
          <div
            role="tablist"
            style={{
              display: "flex",
              gap: 4,
              padding: "8px 10px 0 10px",
              borderBottom: `1px solid ${t.border}`,
              background: t.inset,
              flexShrink: 0,
            }}
          >
            <ViewTab
              theme={theme}
              active={view === "active"}
              onClick={() => setView("active")}
              accent
            >
              <Glyph name="alert" size={11} /> Triage
            </ViewTab>
            <ViewTab
              theme={theme}
              active={view === "browse"}
              onClick={() => setView("browse")}
            >
              All packages
            </ViewTab>
            <ViewTab
              theme={theme}
              active={view === "aiQueue"}
              onClick={() => setView("aiQueue")}
            >
              ⏳ AI queue
            </ViewTab>
            <ViewTab
              theme={theme}
              active={view === "aiDrafts"}
              onClick={() => setView("aiDrafts")}
            >
              🤖 AI drafts
            </ViewTab>
          </div>
          <div style={{ flex: 1, minHeight: 0 }}>
            {payload ? (
              view === "browse" ? (
                <CvePackageList
                  theme={theme}
                  packages={representatives}
                  membersByRep={membersByRep}
                  edits={edits}
                  focusedId={focusedPkg}
                  setFocusedId={(id) => {
                    setFocusedPkg(id);
                    setFocusedAdvisoryId(null);
                  }}
                  q={q}
                  setQ={setQ}
                  statusFilter={statusFilter}
                  setStatusFilter={setStatusFilter}
                />
              ) : view === "active" ? (
                <CveActiveList
                  theme={theme}
                  packages={representatives}
                  membersByRep={membersByRep}
                  edits={edits}
                  focusedPkg={focusedPkg}
                  focusedAdvisoryId={focusedAdvisoryId}
                  onNextTriagePackage={goToNextTriagePackage}
                  triageRemaining={triageQueue.length}
                  enqueuedAdvisories={enqueuedSet}
                  onBulkEnqueue={handleBulkEnqueueAi}
                  onSelect={(pkgName, advisoryId) => {
                    setFocusedPkg(pkgName);
                    setFocusedAdvisoryId(advisoryId);
                  }}
                />
              ) : (
                <CveAiWorkList
                  theme={theme}
                  mode={view === "aiQueue" ? "queue" : "drafts"}
                  packages={representatives}
                  membersByRep={membersByRep}
                  edits={edits}
                  focusedPkg={focusedPkg}
                  focusedAdvisoryId={focusedAdvisoryId}
                  aiDrafts={aiDrafts}
                  aiQueue={aiQueue}
                  enqueuedAdvisories={enqueuedSet}
                  onBulkEnqueue={handleBulkEnqueueAi}
                  onSelect={(pkgName, advisoryId) => {
                    setFocusedPkg(pkgName);
                    setFocusedAdvisoryId(advisoryId);
                  }}
                />
              )
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
        </div>

        <div style={{ flex: 1, minWidth: 0, display: "flex" }}>
          {focusedPackageLoading && !focusedPackage ? (
            <div
              style={{
                flex: 1,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: t.fg2,
                background: t.page,
                fontSize: 13,
              }}
            >
              Loading package details…
            </div>
          ) : (
          <CveDetail
            theme={theme}
            pkg={focusedPackage}
            variants={(focusedPkg && membersByRep.get(focusedPkg)) || []}
            edits={edits}
            mode={view === "active" ? "triage" : "browse"}
            focusedAdvisoryId={focusedAdvisoryId}
            onEdit={(advisoryId, edit) => {
              if (!focusedPackage) return;
              const advisory = focusedPackage.advisories.find(
                (a) => a.id === advisoryId,
              );
              const base = editFromVex(
                advisory ? advisoryVex(advisory) : undefined,
              );
              handleEdit(focusedPackage.package, advisoryId, edit, base);
            }}
            onResetEdit={(advisoryId) => {
              if (!focusedPackage) return;
              handleResetEdit(focusedPackage.package, advisoryId);
            }}
            isLoggedIn={isLoggedIn}
            onRequestLogin={() => setLoginOpen(true)}
            aiDrafts={aiDrafts}
            aiQueue={aiQueue}
            enqueuedAdvisories={enqueuedSet}
            onEnqueueAi={handleEnqueueAi}
          />
          )}
        </div>
      </div>

      {drawerOpen && payload && (
        <CvePRDrawer
          theme={theme}
          edits={edits}
          loadedPackages={packageDetails}
          ensurePackageDetail={ensurePackageDetail}
          membersByRep={membersByRep}
          onClose={() => setDrawerOpen(false)}
          onCommit={() => {
            setEdits({});
            setDrawerOpen(false);
          }}
          onSelect={(pkg, advisoryId) => {
            setFocusedPkg(pkg);
            setFocusedAdvisoryId(advisoryId);
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

      {enqueueOpen && (
        <CveEnqueueDrawer
          theme={theme}
          items={enqueueItems}
          onClose={() => setEnqueueOpen(false)}
          onRemove={handleRemoveEnqueue}
          onSubmitted={() => {
            setEnqueueItems([]);
          }}
          isLoggedIn={isLoggedIn}
          onRequestLogin={() => setLoginOpen(true)}
          token={token}
        />
      )}

      {loginOpen && <LoginModal theme={theme} onClose={() => setLoginOpen(false)} />}
      <LoadingToast theme={theme} />
    </div>
  );
}

function ViewTab({
  theme,
  active,
  accent,
  onClick,
  children,
}: {
  theme: ReturnType<typeof useTheme>;
  active: boolean;
  accent?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  const t = theme.t;
  const [hover, setHover] = useState(false);
  const activeColor = accent ? "#a8201f" : t.accent;
  return (
    <button
      role="tab"
      aria-selected={active}
      onClick={onClick}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: "relative",
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        background: active ? t.surface : hover ? t.surface2 : "transparent",
        border: `1px solid ${active ? t.border : "transparent"}`,
        borderBottom: active ? `1px solid ${t.surface}` : "1px solid transparent",
        borderTop: `2px solid ${active ? activeColor : "transparent"}`,
        borderRadius: "6px 6px 0 0",
        color: active ? t.fg1 : hover ? t.fg1 : t.fg2,
        padding: "7px 13px 7px 13px",
        // pull the active tab down 1px so its bottom edge overlaps the strip's
        // bottom border, making it read as connected to the panel below
        marginBottom: -1,
        fontSize: 12,
        fontWeight: 600,
        cursor: "pointer",
        fontFamily: "Inter, sans-serif",
        transition: "background 0.12s, color 0.12s",
      }}
    >
      {children}
    </button>
  );
}
