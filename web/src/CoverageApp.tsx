import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { repoFullName } from "./config";
import { LoadingToast } from "./components/LoadingToast";
import { Glyph, useTheme } from "./components/Primitives";
import {
  loadMappingsReport,
  UNRESOLVED_DIAGNOSTICS,
  type MissingPrimaryPackage,
  type MissingPrimaryState,
  type MappingsReport,
  type UnresolvedDiagnostic,
} from "./data/mappingsReport";

type StateFilter = "all" | MissingPrimaryState;
type DiagnosticFilter = "all" | UnresolvedDiagnostic;
type CoverageRow = MissingPrimaryPackage & { hosts: string[] };

const DIAGNOSTIC_META: Record<
  UnresolvedDiagnostic,
  { label: string; short: string; description: string }
> = {
  recorded_processing_error: {
    label: "Recorded processing error",
    short: "Processing error",
    description: "The persisted automap note starts with “fetch error:”.",
  },
  alternative_only: {
    label: "Alternative PURL only",
    short: "Alternative only",
    description: "A canonical alternative PURL exists, but no primary PURL does.",
  },
  no_parseable_source_host: {
    label: "No parseable source host",
    short: "No source host",
    description: "No hostname can be parsed from the persisted source URLs.",
  },
  no_primary_from_url_evidence: {
    label: "URL evidence without primary PURL",
    short: "URL evidence",
    description: "A source hostname exists, but automap did not produce a primary PURL.",
  },
};

function number(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function safeExternalUrl(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : null;
  } catch {
    return null;
  }
}

function urlLabel(value: string): string {
  try {
    const url = new URL(value);
    return `${url.hostname}${url.pathname === "/" ? "" : url.pathname}`;
  } catch {
    return value;
  }
}

export function CoverageApp() {
  const theme = useTheme();
  const { t } = theme;
  const [report, setReport] = useState<MappingsReport | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [state, setState] = useState<StateFilter>("unresolved");
  const [diagnostic, setDiagnostic] = useState<DiagnosticFilter>("all");
  const [host, setHost] = useState("all");
  const [selectedName, setSelectedName] = useState<string | null>(null);

  useEffect(() => {
    loadMappingsReport().then(setReport).catch((error) => setLoadError(errorMessage(error)));
  }, []);

  const rows = useMemo<CoverageRow[]>(
    () =>
      (report?.missing_packages ?? []).map((pkg) => ({
        ...pkg,
        hosts: pkg.source_hosts,
      })),
    [report],
  );

  const hostOptions = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of rows) {
      for (const sourceHost of row.hosts) {
        counts.set(sourceHost, (counts.get(sourceHost) ?? 0) + 1);
      }
    }
    return [...counts.entries()].sort(
      ([hostA, countA], [hostB, countB]) => countB - countA || hostA.localeCompare(hostB),
    );
  }, [rows]);

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return rows
      .filter((row) => state === "all" || row.state === state)
      .filter(
        (row) =>
          diagnostic === "all" ||
          (row.state === "unresolved" && row.diagnostic_reason === diagnostic),
      )
      .filter((row) => host === "all" || row.hosts.includes(host))
      .filter((row) => {
        if (!normalizedQuery) return true;
        return [
          row.name,
          row.version,
          row.note,
          row.source_url,
          row.repo,
          row.homepage,
          ...row.hosts,
        ].some((value) => value?.toLowerCase().includes(normalizedQuery));
      })
      .sort(
        (a, b) =>
          (b.download_count ?? -1) - (a.download_count ?? -1) ||
          a.name.localeCompare(b.name),
      );
  }, [diagnostic, host, query, rows, state]);

  useEffect(() => {
    if (filtered.length === 0) {
      setSelectedName(null);
    } else if (!selectedName || !filtered.some((row) => row.name === selectedName)) {
      setSelectedName(filtered[0].name);
    }
  }, [filtered, selectedName]);

  const selected = selectedName
    ? filtered.find((row) => row.name === selectedName) ?? null
    : null;

  const controlStyle: CSSProperties = {
    height: 34,
    border: `1px solid ${t.borderStrong}`,
    borderRadius: 7,
    background: t.surface,
    color: t.fg1,
    fontSize: 12,
    padding: "0 10px",
    outline: "none",
  };

  return (
    <div className={theme.dark ? "dark-scope coverage-page" : "coverage-page"} style={{ background: t.page, color: t.fg1 }}>
      <header className="coverage-header" style={{ background: t.surface, borderColor: t.border }}>
        <div className="coverage-header-left">
          <img
            src={theme.dark ? "./assets/logo_dark.svg" : "./assets/logo_light.svg"}
            alt="prefix.dev"
            style={{ height: 22 }}
          />
          <nav className="coverage-nav" style={{ borderColor: t.border }}>
            <a href="./index.html" style={{ color: t.fg2 }}>Mapper</a>
            <a href="./coverage.html" className="active" style={{ color: t.fg1, background: t.inset }}>
              PURL coverage
            </a>
          </nav>
          <span className="coverage-repo" style={{ background: t.inset, color: t.fg2 }}>
            <Glyph name="branch" size={11} />
            {repoFullName}
          </span>
        </div>
        <button
          onClick={() => theme.setDark(!theme.dark)}
          className="coverage-theme"
          style={{ background: t.surface2, borderColor: t.border, color: t.fg1 }}
          title="Toggle theme"
        >
          {theme.dark ? "☀" : "☾"}
        </button>
      </header>

      <main className="coverage-main">
        <section className="coverage-intro">
          <div>
            <p className="coverage-eyebrow" style={{ color: t.fg3 }}>PRIMARY-PURL OBSERVABILITY</p>
            <h1>Missing primary PURLs</h1>
            <p style={{ color: t.fg2 }}>
              Inspect packages without a primary PURL. Diagnostics describe recorded evidence,
              not authoritative root causes.
            </p>
          </div>
          {report && (
            <div className="coverage-contract" style={{ color: t.fg3 }}>
              report schema {report.schema_version} · mapping schema {report.input_schema_version} · {report.channel}
            </div>
          )}
        </section>

        {loadError ? (
          <div className="coverage-error" style={{ color: t.bad, background: t.surface, borderColor: t.border }}>
            Failed to load coverage report: {loadError}
          </div>
        ) : !report ? (
          <div className="coverage-loading" style={{ color: t.fg2 }}>Loading coverage report…</div>
        ) : (
          <>
            <section className="coverage-summary">
              <SummaryCard label="All packages" value={report.counts.total} theme={theme} />
              <SummaryCard label="Primary PURL" value={report.counts.primary_present} theme={theme} tone="good" />
              <SummaryCard label="Explicitly unmapped" value={report.counts.explicitly_unmapped} theme={theme} tone="warn" />
              <SummaryCard label="Unresolved" value={report.counts.unresolved} theme={theme} tone="bad" />
            </section>

            <section className="coverage-workspace" style={{ background: t.surface, borderColor: t.border }}>
              <div className="coverage-toolbar" style={{ borderColor: t.border }}>
                <label className="coverage-search" style={{ background: t.surface2, borderColor: t.borderStrong }}>
                  <Glyph name="search" size={14} />
                  <input
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder="Search package, host, URL, or note"
                    style={{ color: t.fg1 }}
                  />
                </label>
                <select
                  value={state}
                  onChange={(event) => {
                    const nextState = event.target.value as StateFilter;
                    setState(nextState);
                    if (nextState === "explicitly_unmapped") setDiagnostic("all");
                  }}
                  style={controlStyle}
                >
                  <option value="all">All missing-primary states</option>
                  <option value="unresolved">Unresolved</option>
                  <option value="explicitly_unmapped">Explicitly unmapped</option>
                </select>
                <select
                  value={diagnostic}
                  onChange={(event) => setDiagnostic(event.target.value as DiagnosticFilter)}
                  disabled={state === "explicitly_unmapped"}
                  style={{ ...controlStyle, opacity: state === "explicitly_unmapped" ? 0.5 : 1 }}
                >
                  <option value="all">All diagnostics</option>
                  {UNRESOLVED_DIAGNOSTICS.map((value) => (
                    <option key={value} value={value}>{DIAGNOSTIC_META[value].label}</option>
                  ))}
                </select>
                <select value={host} onChange={(event) => setHost(event.target.value)} style={controlStyle}>
                  <option value="all">All source hosts</option>
                  {hostOptions.map(([value, count]) => (
                    <option key={value} value={value}>{value} ({number(count)})</option>
                  ))}
                </select>
                <span className="coverage-result-count" style={{ color: t.fg3 }}>
                  {number(filtered.length)} result{filtered.length === 1 ? "" : "s"}
                </span>
              </div>

              <div className="coverage-browser">
                <div className="coverage-table-wrap">
                  <table className="coverage-table">
                    <thead style={{ background: t.surface2, color: t.fg3 }}>
                      <tr>
                        <th>Package</th>
                        <th>Diagnostic</th>
                        <th>Version</th>
                        <th>Downloads</th>
                        <th>Source hosts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((row) => (
                        <tr
                          key={row.name}
                          onClick={() => setSelectedName(row.name)}
                          className={row.name === selectedName ? "selected" : ""}
                          style={{
                            borderColor: t.border,
                            background: row.name === selectedName ? t.rowSelected : undefined,
                          }}
                        >
                          <td><strong>{row.name}</strong></td>
                          <td>
                            {row.diagnostic_reason ? (
                              <DiagnosticPill diagnostic={row.diagnostic_reason} theme={theme} />
                            ) : (
                              <span style={{ color: t.warn }}>Explicit no-PURL</span>
                            )}
                          </td>
                          <td className="mono" style={{ color: t.fg2 }}>{row.version || "—"}</td>
                          <td className="mono" style={{ color: t.fg2 }}>
                            {row.download_count === null ? "—" : number(row.download_count)}
                          </td>
                          <td style={{ color: t.fg2 }}>{row.hosts.join(", ") || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filtered.length === 0 && (
                    <div className="coverage-empty" style={{ color: t.fg2 }}>No packages match these filters.</div>
                  )}
                </div>

                <aside className="coverage-detail" style={{ background: t.surface2, borderColor: t.border }}>
                  {selected ? <PackageEvidence row={selected} theme={theme} /> : <span style={{ color: t.fg2 }}>Select a package to inspect its evidence.</span>}
                </aside>
              </div>
            </section>
          </>
        )}
      </main>
      <LoadingToast theme={theme} />
    </div>
  );
}

function SummaryCard({
  label,
  value,
  theme,
  tone,
}: {
  label: string;
  value: number;
  theme: ReturnType<typeof useTheme>;
  tone?: "good" | "warn" | "bad";
}) {
  const color = tone ? theme.t[tone] : theme.t.fg1;
  return (
    <div className="coverage-summary-card" style={{ background: theme.t.surface, borderColor: theme.t.border }}>
      <span style={{ color: theme.t.fg3 }}>{label}</span>
      <strong style={{ color }}>{number(value)}</strong>
    </div>
  );
}

function DiagnosticPill({ diagnostic, theme }: { diagnostic: UnresolvedDiagnostic; theme: ReturnType<typeof useTheme> }) {
  const urgent = diagnostic === "recorded_processing_error";
  return (
    <span
      className="coverage-diagnostic-pill"
      title={DIAGNOSTIC_META[diagnostic].description}
      style={{
        background: urgent ? (theme.dark ? "#3a1f1f" : "#ffe5dc") : theme.t.inset,
        color: urgent ? theme.t.bad : theme.t.fg2,
      }}
    >
      {DIAGNOSTIC_META[diagnostic].short}
    </span>
  );
}

function PackageEvidence({ row, theme }: { row: CoverageRow; theme: ReturnType<typeof useTheme> }) {
  const links = [
    ["Source", row.source_url],
    ["Repository", row.repo],
    ["Homepage", row.homepage],
  ] as const;
  return (
    <div>
      <p className="coverage-eyebrow" style={{ color: theme.t.fg3 }}>PACKAGE EVIDENCE</p>
      <h2>{row.name}</h2>
      <dl className="coverage-facts">
        <dt style={{ color: theme.t.fg3 }}>State</dt>
        <dd>{row.state === "unresolved" ? "Unresolved" : "Explicitly unmapped"}</dd>
        <dt style={{ color: theme.t.fg3 }}>Version</dt>
        <dd className="mono">{row.version || "—"}</dd>
        <dt style={{ color: theme.t.fg3 }}>Downloads</dt>
        <dd className="mono">{row.download_count === null ? "—" : number(row.download_count)}</dd>
      </dl>
      {row.diagnostic_reason && (
        <div className="coverage-diagnostic-box" style={{ background: theme.t.surface, borderColor: theme.t.border }}>
          <DiagnosticPill diagnostic={row.diagnostic_reason} theme={theme} />
          <p style={{ color: theme.t.fg2 }}>{DIAGNOSTIC_META[row.diagnostic_reason].description}</p>
        </div>
      )}
      <h3>Recorded URLs</h3>
      <div className="coverage-links">
        {links.map(([label, value]) => {
          const href = value ? safeExternalUrl(value) : null;
          return (
            <div key={label}>
              <span style={{ color: theme.t.fg3 }}>{label}</span>
              {href && value ? (
                <a href={href} target="_blank" rel="noreferrer" style={{ color: theme.t.link }} title={value}>
                  {urlLabel(value)}
                </a>
              ) : value ? (
                <code style={{ color: theme.t.fg2 }}>{value}</code>
              ) : (
                <em style={{ color: theme.t.fg3 }}>Not recorded</em>
              )}
            </div>
          );
        })}
      </div>
      <h3>Recorded note</h3>
      <pre className="coverage-note" style={{ background: theme.t.surface, borderColor: theme.t.border, color: theme.t.fg2 }}>
        {row.note || "No note recorded."}
      </pre>
    </div>
  );
}
