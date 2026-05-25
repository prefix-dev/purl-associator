/* Loader for SBOM summaries + per-package transitive CVE matches.
 *
 * scripts/sbom_extract.py writes CycloneDX docs to mappings/sboms/.
 * scripts/sbom_cve_match.py joins those component PURLs with OSV and emits:
 *   - web/public/sboms.json (summary keyed by conda name)
 *   - mappings/sbom_cves/<name>.json (per-package match detail, only if hits)
 *
 * The frontend reads the summary at startup and lazy-loads per-package detail
 * when a user focuses a package with transitive matches.
 */

export type SbomSummaryEntry = {
  name: string;
  version: string;
  ecosystem: "cargo" | "golang" | string;
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

/** Per-package SBOM-CVE files live at /mappings/sbom_cves/<name>.json. The
 *  pages build also copies these into web/public, so the frontend can fetch
 *  them at the same relative path layout.
 */
export async function loadSbomDetail(
  name: string,
  base = "./sbom_cves",
): Promise<SbomDetailPayload | null> {
  try {
    const res = await fetch(`${base}/${encodeURIComponent(name)}.json`, {
      cache: "no-cache",
    });
    if (!res.ok) return null;
    return (await res.json()) as SbomDetailPayload;
  } catch {
    return null;
  }
}
