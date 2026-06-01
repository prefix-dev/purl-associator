/* Loader for SBOM summaries + per-package transitive CVE matches.
 *
 * scripts/sbom_extract.py writes CycloneDX docs to mappings/sboms/.
 * scripts/sbom_cve_match.py joins those component PURLs with OSV and emits:
 *   - mappings/sboms.json (summary keyed by conda name)
 *   - mappings/sbom_cves/<artifact-id>.json (per-artifact match detail)
 * scripts/merge_sboms.py publishes those files into web/public for Vite.
 *
 * The frontend reads the summary at startup and lazy-loads per-package detail
 * when a user focuses a package with transitive matches.
 */

export type SbomSummaryEntry = {
  name: string;
  version: string;
  artifact_id?: string | null;
  build?: string | null;
  subdir?: string | null;
  sbom_path?: string | null;
  detail_path?: string | null;
  package_url?: string | null;
  package_filename?: string | null;
  ecosystem: "cargo" | "golang" | string;
  expected_ecosystems?: string[] | null;
  signals?: string[] | null;
  status?: "ok" | "no-sbom" | "no-paths-json" | "error" | string | null;
  warning?: string | null;
  binary_path?: string | null;
  component_count: number;
  matched_component_count: number;
  advisory_count: number;
  vulnerable_component_count: number;
};

export type SbomSummaryPayload = {
  schema_version: number;
  generated_at: string;
  packages: Record<string, SbomSummaryEntry>;
};

export type SbomAdvisoryHit = {
  advisory_id: string;
  primary_id: string;
  aliases: string[];
  summary: string | null;
  severity: { type: string; score: string; score_num?: number }[];
  references: { type: string; url: string }[];
  components: { purl: string; name: string; version: string }[];
};

export type SbomDetailPayload = {
  schema_version: number;
  package: string;
  package_version: string;
  artifact_id?: string | null;
  package_build?: string | null;
  package_subdir?: string | null;
  package_url?: string | null;
  package_filename?: string | null;
  ecosystem: string;
  generated_at: string;
  component_count: number;
  matched_component_count: number;
  advisories: SbomAdvisoryHit[];
};

const SUMMARY_PATH = "./sboms.json";

export async function loadSbomSummary(
  path = SUMMARY_PATH,
): Promise<SbomSummaryPayload | null> {
  try {
    const res = await fetch(path, { cache: "no-cache" });
    if (!res.ok) return null;
    return (await res.json()) as SbomSummaryPayload;
  } catch {
    return null;
  }
}

/** Per-artifact SBOM-CVE files live under /sbom_cves in the built frontend.
 *  The summary index carries the exact artifact-specific path.
 */
export async function loadSbomDetail(
  summary: SbomSummaryEntry,
): Promise<SbomDetailPayload | null> {
  if (!summary.detail_path) return null;
  try {
    const res = await fetch(`./${summary.detail_path}`, { cache: "no-cache" });
    if (!res.ok) return null;
    return (await res.json()) as SbomDetailPayload;
  } catch {
    return null;
  }
}
