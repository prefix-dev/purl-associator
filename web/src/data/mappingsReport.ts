import { config } from "../config";
import { fetchJsonWithProgress } from "./progressFetch";

export const UNRESOLVED_DIAGNOSTICS = [
  "recorded_processing_error",
  "alternative_only",
  "no_parseable_source_host",
  "no_primary_from_url_evidence",
] as const;

export const UNMAPPED_REASON_CODES = [
  "conda_cdt_repackage",
  "dependency_only_metapackage",
  "toolchain_selector",
  "environment_mutex",
  "pinning_metadata",
  "compatibility_shim",
] as const;

export type UnresolvedDiagnostic = (typeof UNRESOLVED_DIAGNOSTICS)[number];
export type UnmappedReasonCode = (typeof UNMAPPED_REASON_CODES)[number];
export type MissingPrimaryState = "explicitly_unmapped" | "unresolved";
export type UnmappedReason = {
  code: UnmappedReasonCode;
  explanation: string;
  rule_id: string;
  evidence: Record<string, string>;
};

export type MissingPrimaryPackage = {
  name: string;
  state: MissingPrimaryState;
  diagnostic_reason: UnresolvedDiagnostic | null;
  unmapped_reason: UnmappedReason | null;
  source_hosts: string[];
  version: string | null;
  source_url: string | null;
  repo: string | null;
  homepage: string | null;
  note: string | null;
  download_count: number | null;
};

export type MappingsReport = {
  schema_version: 2;
  input_schema_version: number;
  channel: string;
  counts: {
    total: number;
    primary_present: number;
    explicitly_unmapped: number;
    classified_unmapped: number;
    legacy_unmapped: number;
    unresolved: number;
    actionable_missing: number;
    primary_missing: number;
  };
  classified_by_reason: Record<UnmappedReasonCode, number>;
  unresolved_by_diagnostic: Record<UnresolvedDiagnostic, number>;
  unresolved_by_source_host: Array<{ host: string; package_count: number }>;
  missing_packages: MissingPrimaryPackage[];
};

const DIAGNOSTIC_SET = new Set<string>(UNRESOLVED_DIAGNOSTICS);
const REASON_SET = new Set<string>(UNMAPPED_REASON_CODES);
const EVIDENCE_FIELDS = new Set(["version", "build", "summary", "source_url", "repo", "homepage"]);

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

function sourceHostArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  let previous: string | null = null;
  return value.map((item, index) => {
    if (
      typeof item !== "string" ||
      !item ||
      item !== item.toLowerCase() ||
      item.endsWith(".") ||
      (previous !== null && item <= previous)
    ) {
      throw new Error(`${label}[${index}] must be a normalized, unique, sorted host`);
    }
    previous = item;
    return item;
  });
}

function decodeUnmappedReason(value: unknown, label: string, state: unknown): UnmappedReason | null {
  if (value === null) return null;
  if (state !== "explicitly_unmapped") throw new Error(`${label} requires explicitly_unmapped state`);
  const reason = record(value, label);
  if (typeof reason.code !== "string" || !REASON_SET.has(reason.code)) throw new Error(`${label}.code is unsupported`);
  if (typeof reason.explanation !== "string" || !reason.explanation) throw new Error(`${label}.explanation is required`);
  if (typeof reason.rule_id !== "string" || !reason.rule_id) throw new Error(`${label}.rule_id is required`);
  const evidence = record(reason.evidence, `${label}.evidence`);
  if (Object.keys(evidence).length === 0 || Object.keys(evidence).some((key) => !EVIDENCE_FIELDS.has(key))) {
    throw new Error(`${label}.evidence is empty or unsupported`);
  }
  const decodedEvidence: Record<string, string> = {};
  for (const [key, item] of Object.entries(evidence)) {
    if (typeof item !== "string" || !item) throw new Error(`${label}.evidence.${key} is required`);
    decodedEvidence[key] = item;
  }
  return { code: reason.code as UnmappedReasonCode, explanation: reason.explanation, rule_id: reason.rule_id, evidence: decodedEvidence };
}

export function decodeMappingsReport(value: unknown): MappingsReport {
  const report = record(value, "mappings report");
  if (report.schema_version !== 2) {
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
    classified_unmapped: integer(rawCounts.classified_unmapped, "mappings report.counts.classified_unmapped"),
    legacy_unmapped: integer(rawCounts.legacy_unmapped, "mappings report.counts.legacy_unmapped"),
    unresolved: integer(rawCounts.unresolved, "mappings report.counts.unresolved"),
    actionable_missing: integer(rawCounts.actionable_missing, "mappings report.counts.actionable_missing"),
    primary_missing: integer(
      rawCounts.primary_missing,
      "mappings report.counts.primary_missing",
    ),
  };
  if (
    counts.primary_present + counts.explicitly_unmapped + counts.unresolved !==
      counts.total ||
    counts.explicitly_unmapped + counts.unresolved !== counts.primary_missing ||
    counts.classified_unmapped + counts.legacy_unmapped !== counts.explicitly_unmapped ||
    counts.actionable_missing !== counts.unresolved
  ) {
    throw new Error("mappings report coverage counts do not reconcile");
  }

  const rawClassifications = record(report.classified_by_reason, "mappings report.classified_by_reason");
  if (Object.keys(rawClassifications).length !== UNMAPPED_REASON_CODES.length || Object.keys(rawClassifications).some((key) => !REASON_SET.has(key))) {
    throw new Error("mappings report has unsupported classification reasons");
  }
  const classifiedByReason = Object.fromEntries(
    UNMAPPED_REASON_CODES.map((code) => [code, integer(rawClassifications[code], `mappings report.classified_by_reason.${code}`)]),
  ) as Record<UnmappedReasonCode, number>;
  if (Object.values(classifiedByReason).reduce((sum, count) => sum + count, 0) !== counts.classified_unmapped) {
    throw new Error("mappings report classification reasons do not reconcile");
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

  if (!Array.isArray(report.unresolved_by_source_host)) {
    throw new Error("mappings report.unresolved_by_source_host must be an array");
  }
  const unresolvedBySourceHost = report.unresolved_by_source_host.map(
    (raw, index) => {
      const label = `mappings report.unresolved_by_source_host[${index}]`;
      const item = record(raw, label);
      if (typeof item.host !== "string" || !item.host) {
        throw new Error(`${label}.host must be a non-empty string`);
      }
      return {
        host: item.host,
        package_count: integer(item.package_count, `${label}.package_count`),
      };
    },
  );
  for (let index = 0; index < unresolvedBySourceHost.length; index++) {
    const current = unresolvedBySourceHost[index];
    const previous = unresolvedBySourceHost[index - 1];
    if (
      current.host !== current.host.toLowerCase() ||
      current.host.endsWith(".") ||
      current.package_count === 0 ||
      (previous &&
        (current.package_count > previous.package_count ||
          (current.package_count === previous.package_count && current.host <= previous.host)))
    ) {
      throw new Error("mappings report unresolved source hosts are not normalized and sorted");
    }
  }

  if (!Array.isArray(report.missing_packages)) {
    throw new Error("mappings report.missing_packages must be an array");
  }
  const seenNames = new Set<string>();
  const observedDiagnostics = Object.fromEntries(
    UNRESOLVED_DIAGNOSTICS.map((diagnostic) => [diagnostic, 0]),
  ) as Record<UnresolvedDiagnostic, number>;
  const observedSourceHosts = new Map<string, number>();
  const observedClassifications = Object.fromEntries(UNMAPPED_REASON_CODES.map((code) => [code, 0])) as Record<UnmappedReasonCode, number>;
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
    const unmappedReason = decodeUnmappedReason(pkg.unmapped_reason, `${label}.unmapped_reason`, pkg.state);
    if (unmappedReason) observedClassifications[unmappedReason.code]++;
    const sourceHosts = sourceHostArray(pkg.source_hosts, `${label}.source_hosts`);
    if (pkg.state === "unresolved") {
      for (const host of sourceHosts) {
        observedSourceHosts.set(host, (observedSourceHosts.get(host) ?? 0) + 1);
      }
    }
    const downloads = pkg.download_count;
    if (downloads !== null && (typeof downloads !== "number" || !Number.isInteger(downloads) || downloads < 0)) {
      throw new Error(`${label}.download_count must be a non-negative integer or null`);
    }
    return {
      name: pkg.name,
      state: pkg.state,
      diagnostic_reason: diagnostic,
      unmapped_reason: unmappedReason,
      source_hosts: sourceHosts,
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
    UNMAPPED_REASON_CODES.some((code) => observedClassifications[code] !== classifiedByReason[code]) ||
    UNRESOLVED_DIAGNOSTICS.some(
      (diagnostic) => observedDiagnostics[diagnostic] !== unresolvedByDiagnostic[diagnostic],
    ) ||
    unresolvedBySourceHost.length !== observedSourceHosts.size ||
    unresolvedBySourceHost.some(
      ({ host, package_count }) => observedSourceHosts.get(host) !== package_count,
    )
  ) {
    throw new Error("mappings report package rows do not reconcile with aggregate counts");
  }

  return {
    schema_version: 2,
    input_schema_version: inputSchemaVersion,
    channel: report.channel,
    counts,
    classified_by_reason: classifiedByReason,
    unresolved_by_diagnostic: unresolvedByDiagnostic,
    unresolved_by_source_host: unresolvedBySourceHost,
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
