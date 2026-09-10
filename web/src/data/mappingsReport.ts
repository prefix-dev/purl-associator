import { config } from "../config";
import { fetchJsonWithProgress } from "./progressFetch";

export const UNRESOLVED_DIAGNOSTICS = [
  "recorded_processing_error",
  "alternative_only",
  "no_parseable_source_host",
  "no_primary_from_url_evidence",
] as const;

export type UnresolvedDiagnostic = (typeof UNRESOLVED_DIAGNOSTICS)[number];
export type MissingPrimaryState = "explicitly_unmapped" | "unresolved";

export type MissingPrimaryPackage = {
  name: string;
  state: MissingPrimaryState;
  diagnostic_reason: UnresolvedDiagnostic | null;
  version: string | null;
  source_url: string | null;
  repo: string | null;
  homepage: string | null;
  note: string | null;
  download_count: number | null;
};

export type MappingsReport = {
  schema_version: 1;
  input_schema_version: number;
  channel: string;
  counts: {
    total: number;
    primary_present: number;
    explicitly_unmapped: number;
    unresolved: number;
    primary_missing: number;
  };
  unresolved_by_diagnostic: Record<UnresolvedDiagnostic, number>;
  missing_packages: MissingPrimaryPackage[];
};

const DIAGNOSTIC_SET = new Set<string>(UNRESOLVED_DIAGNOSTICS);
const URL_FIELDS = ["source_url", "repo", "homepage"] as const;

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function integer(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function nullableString(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string") throw new Error(`${label} must be a string or null`);
  return value;
}

export function sourceHosts(pkg: MissingPrimaryPackage): string[] {
  const hosts = new Set<string>();
  for (const field of URL_FIELDS) {
    const value = pkg[field];
    if (!value?.trim()) continue;
    try {
      const hostname = new URL(value).hostname.toLowerCase().replace(/\.$/, "");
      if (hostname) hosts.add(hostname);
    } catch {
      // The report intentionally keeps malformed evidence; it is not a host.
    }
  }
  return [...hosts].sort();
}

export function decodeMappingsReport(value: unknown): MappingsReport {
  const report = record(value, "mappings report");
  if (report.schema_version !== 1) {
    throw new Error(
      `mappings report has unsupported schema_version ${String(report.schema_version)}`,
    );
  }
  const inputSchemaVersion = integer(
    report.input_schema_version,
    "mappings report.input_schema_version",
  );
  if (typeof report.channel !== "string" || !report.channel) {
    throw new Error("mappings report.channel must be a non-empty string");
  }

  const rawCounts = record(report.counts, "mappings report.counts");
  const counts = {
    total: integer(rawCounts.total, "mappings report.counts.total"),
    primary_present: integer(
      rawCounts.primary_present,
      "mappings report.counts.primary_present",
    ),
    explicitly_unmapped: integer(
      rawCounts.explicitly_unmapped,
      "mappings report.counts.explicitly_unmapped",
    ),
    unresolved: integer(rawCounts.unresolved, "mappings report.counts.unresolved"),
    primary_missing: integer(
      rawCounts.primary_missing,
      "mappings report.counts.primary_missing",
    ),
  };
  if (
    counts.primary_present + counts.explicitly_unmapped + counts.unresolved !==
      counts.total ||
    counts.explicitly_unmapped + counts.unresolved !== counts.primary_missing
  ) {
    throw new Error("mappings report coverage counts do not reconcile");
  }

  const rawDiagnostics = record(
    report.unresolved_by_diagnostic,
    "mappings report.unresolved_by_diagnostic",
  );
  if (
    Object.keys(rawDiagnostics).length !== UNRESOLVED_DIAGNOSTICS.length ||
    Object.keys(rawDiagnostics).some((key) => !DIAGNOSTIC_SET.has(key))
  ) {
    throw new Error("mappings report has unsupported unresolved diagnostics");
  }
  const unresolvedByDiagnostic = Object.fromEntries(
    UNRESOLVED_DIAGNOSTICS.map((diagnostic) => [
      diagnostic,
      integer(
        rawDiagnostics[diagnostic],
        `mappings report.unresolved_by_diagnostic.${diagnostic}`,
      ),
    ]),
  ) as Record<UnresolvedDiagnostic, number>;
  if (
    Object.values(unresolvedByDiagnostic).reduce((sum, count) => sum + count, 0) !==
    counts.unresolved
  ) {
    throw new Error("mappings report unresolved diagnostics do not reconcile");
  }

  if (!Array.isArray(report.missing_packages)) {
    throw new Error("mappings report.missing_packages must be an array");
  }
  const seenNames = new Set<string>();
  const observedDiagnostics = Object.fromEntries(
    UNRESOLVED_DIAGNOSTICS.map((diagnostic) => [diagnostic, 0]),
  ) as Record<UnresolvedDiagnostic, number>;
  let explicitlyUnmapped = 0;
  let unresolved = 0;
  const packages = report.missing_packages.map((raw, index): MissingPrimaryPackage => {
    const label = `mappings report.missing_packages[${index}]`;
    const pkg = record(raw, label);
    if (typeof pkg.name !== "string" || !pkg.name || seenNames.has(pkg.name)) {
      throw new Error(`${label}.name must be a unique non-empty string`);
    }
    seenNames.add(pkg.name);
    if (pkg.state !== "explicitly_unmapped" && pkg.state !== "unresolved") {
      throw new Error(`${label}.state is unsupported`);
    }
    let diagnostic: UnresolvedDiagnostic | null = null;
    if (pkg.state === "unresolved") {
      if (typeof pkg.diagnostic_reason !== "string" || !DIAGNOSTIC_SET.has(pkg.diagnostic_reason)) {
        throw new Error(`${label}.diagnostic_reason is required for unresolved packages`);
      }
      diagnostic = pkg.diagnostic_reason as UnresolvedDiagnostic;
      observedDiagnostics[diagnostic]++;
      unresolved++;
    } else {
      if (pkg.diagnostic_reason !== null) {
        throw new Error(`${label}.diagnostic_reason must be null when explicitly unmapped`);
      }
      explicitlyUnmapped++;
    }
    const downloads = pkg.download_count;
    if (downloads !== null && (typeof downloads !== "number" || !Number.isInteger(downloads) || downloads < 0)) {
      throw new Error(`${label}.download_count must be a non-negative integer or null`);
    }
    return {
      name: pkg.name,
      state: pkg.state,
      diagnostic_reason: diagnostic,
      version: nullableString(pkg.version, `${label}.version`),
      source_url: nullableString(pkg.source_url, `${label}.source_url`),
      repo: nullableString(pkg.repo, `${label}.repo`),
      homepage: nullableString(pkg.homepage, `${label}.homepage`),
      note: nullableString(pkg.note, `${label}.note`),
      download_count: downloads as number | null,
    };
  });
  if (
    packages.length !== counts.primary_missing ||
    explicitlyUnmapped !== counts.explicitly_unmapped ||
    unresolved !== counts.unresolved ||
    UNRESOLVED_DIAGNOSTICS.some(
      (diagnostic) => observedDiagnostics[diagnostic] !== unresolvedByDiagnostic[diagnostic],
    )
  ) {
    throw new Error("mappings report package rows do not reconcile with aggregate counts");
  }

  return {
    schema_version: 1,
    input_schema_version: inputSchemaVersion,
    channel: report.channel,
    counts,
    unresolved_by_diagnostic: unresolvedByDiagnostic,
    missing_packages: packages,
  };
}

export async function loadMappingsReport(
  path = config.mappingsReportUrl,
): Promise<MappingsReport> {
  return decodeMappingsReport(
    await fetchJsonWithProgress<unknown>(path, { cache: "no-cache" }),
  );
}
