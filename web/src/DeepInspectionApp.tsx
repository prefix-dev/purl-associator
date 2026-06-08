import { useEffect, useMemo, useState } from "react";
import { DeepInspectionPanel } from "./components/DeepInspectionPanel";
import { LoadingToast } from "./components/LoadingToast";
import { PackageTable } from "./components/PackageTable";
import { Glyph, useTheme } from "./components/Primitives";
import { repoFullName } from "./config";
import {
  loadSbomDetail,
  loadSbomSummary,
  type SbomDetailPayload,
  type SbomSummaryPayload,
} from "./data/sboms";
import { useMappingsData } from "./data/useMappingsData";

export function DeepInspectionApp() {
  const theme = useTheme();
  const {
    payload,
    packages,
    loadError,
    detailError,
    details,
    ensurePackageDetail,
  } = useMappingsData();
  const [selectedSet, setSelectedSet] = useState<Set<string>>(new Set());
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState({
    unmappedOnly: false,
    unverifiedOnly: false,
    deepOnly: true,
    ecosystem: "all",
  });
  const [sbomSummary, setSbomSummary] = useState<SbomSummaryPayload | null>(null);
  const [sbomDetails, setSbomDetails] = useState<
    Record<string, SbomDetailPayload | null>
  >({});

  const t = theme.t;
  const edits = {};

  useEffect(() => {
    loadSbomSummary().then(setSbomSummary);
  }, []);

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

  useEffect(() => {
    if (focusedId !== null || packages.length === 0) return;
    const first = packages.find((p) => deepInspectionNames.has(p.name));
    if (first) setFocusedId(first.name);
  }, [packages, deepInspectionNames, focusedId]);

  useEffect(() => {
    if (focusedId && !details[focusedId]) {
      ensurePackageDetail(focusedId).catch(() => {
        // detailError is surfaced in the banner below.
      });
    }
  }, [details, ensurePackageDetail, focusedId]);

  const focusedPkg = focusedId ? details[focusedId] ?? null : null;

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
            <span
              style={{
                color: t.fg1,
                padding: "4px 8px",
                borderRadius: 6,
                background: t.inset,
              }}
            >
              Deep Package Inspection
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
        </div>

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
      </header>

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
          gridTemplateColumns: "minmax(0, 48fr) minmax(420px, 52fr)",
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

        <div style={{ minWidth: 0, minHeight: 0, display: "flex" }}>
          <DeepInspectionPanel
            theme={theme}
            pkg={focusedPkg}
            summary={focusedPkg ? sbomSummary?.packages[focusedPkg.name] ?? null : null}
            detail={focusedPkg ? sbomDetails[focusedPkg.name] ?? null : null}
          />
        </div>
      </div>
      <LoadingToast theme={theme} />
    </div>
  );
}
