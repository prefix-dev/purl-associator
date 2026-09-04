import { fetchJsonWithProgress } from "./progressFetch";
import type {
  MappingDetailPayload,
  MappingPackageIndex,
  MappingsIndexPayload,
  MappingsPayload,
  PackageEntry,
} from "./types";

const DEFAULT_PATH = "./mappings.json";
const DEFAULT_INDEX_PATH = "./mappings-index.json";
const SUPPORTED_BUNDLE_SCHEMAS = new Set([1, 2, 3]);
const SUPPORTED_INDEX_SCHEMAS = new Set([2, 3, 4]);
const SUPPORTED_DETAIL_SCHEMAS = new Set([1, 2, 3]);
const PURL_PATTERN = /^pkg:[a-z][a-z0-9.+-]*\/[^\s?#]+(?:\?[^\s#]+)?(?:#[^\s]+)?$/;
const CPE_PATTERN = /^cpe:2\.3:[aho*\-]:[^:]+:[^:]+(?::[^:]*){0,10}$/;
const REVIEW_STATUSES = new Set([
  "auto-unverified",
  "auto-verified",
  "verified",
  "unmapped",
  "edited",
]);
const ALTERNATIVE_SOURCES = new Set([
  "recipe-source",
  "recipe-deps",
  "recipe-source+recipe-deps",
  "parselmouth-artifact",
]);

const FULL_ENTRY_KEYS = [
  "name",
  "version",
  "build",
  "subdir",
  "url",
  "purl",
  "type",
  "namespace",
  "pkg_name",
  "confidence",
  "sources",
  "homepage",
  "repo",
  "recipe_url",
  "summary",
  "source_url",
  "note",
  "fetched_at",
  "status",
  "source",
  "unmapped",
  "approved_by",
  "approved_at",
  "alternative_purls",
  "auto_verified",
  "verification_sources",
  "cpes",
  "identities",
  "auto",
  "download_count",
] as const;
const INDEX_ENTRY_KEYS = [
  "name",
  "version",
  "purl",
  "type",
  "namespace",
  "pkg_name",
  "status",
  "download_count",
  "alternative_purls",
  "unmapped",
  "cpes",
  "identities",
  "auto",
  "detail_path",
] as const;

const jsonCache = new Map<string, Promise<unknown>>();
type IndexDecode = {
  schemaVersion: number;
  name: string;
  detailPath: string;
  includeAuto: boolean;
  includeDownloadCount: boolean;
  identityContract: string;
};
const indexDecodeByPackage = new WeakMap<object, IndexDecode>();

async function loadJsonCached(path: string): Promise<unknown> {
  const cached = jsonCache.get(path);
  if (cached) return cached;
  const promise = fetchJsonWithProgress<unknown>(path, { cache: "no-cache" });
  jsonCache.set(path, promise);
  promise.catch(() => jsonCache.delete(path));
  return promise;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function required(value: Record<string, unknown>, key: string, label: string): unknown {
  if (!hasOwn(value, key)) throw new Error(`${label}.${key} is required`);
  return value[key];
}

function stringValue(value: unknown, label: string, allowEmpty = true): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    throw new Error(`${label} must be ${allowEmpty ? "a string" : "a non-empty string"}`);
  }
  return value;
}

function nullableString(value: unknown, label: string): string | null {
  if (value === null) return null;
  return stringValue(value, label);
}

function finiteNumber(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  return value;
}

function nullableFiniteNumber(value: unknown, label: string): number | null {
  if (value === null) return null;
  return finiteNumber(value, label);
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`${label} must be an array of strings`);
  }
  return value;
}

function hasOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
): boolean {
  return Object.keys(value).every((key) => allowed.includes(key));
}

function requireOnlyKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  if (!hasOnlyKeys(value, allowed)) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function decodeVersionedPayload(
  value: unknown,
  label: string,
  supported: Set<number>,
  metadata: boolean,
): Record<string, unknown> {
  const payload = record(value, label);
  if (
    typeof payload.schema_version !== "number" ||
    !Number.isInteger(payload.schema_version) ||
    !supported.has(payload.schema_version)
  ) {
    throw new Error(
      `${label} has unsupported schema_version ${String(payload.schema_version)}; ` +
        `supported versions are ${[...supported].join(", ")}`,
    );
  }
  const packages = record(payload.packages, `${label}.packages`);
  if (metadata) {
    nullableString(required(payload, "generated_at", label), `${label}.generated_at`);
    nullableString(
      required(payload, "auto_generated_at", label),
      `${label}.auto_generated_at`,
    );
    nullableString(
      required(payload, "manual_updated_at", label),
      `${label}.manual_updated_at`,
    );
    stringValue(required(payload, "channel", label), `${label}.channel`, false);
    const packageCount = finiteNumber(
      required(payload, "package_count", label),
      `${label}.package_count`,
    );
    if (!Number.isInteger(packageCount) || packageCount < 0) {
      throw new Error(`${label}.package_count must be a non-negative integer`);
    }
    if (packageCount !== Object.keys(packages).length) {
      throw new Error(`${label}.package_count does not match packages`);
    }
  }
  return payload;
}

function decodePurl(value: unknown, label: string): string {
  const purl = stringValue(value, label, false);
  if (!PURL_PATTERN.test(purl)) throw new Error(`${label} must be a valid PURL`);
  return purl;
}

function decodeNullablePurl(value: unknown, label: string): string | null {
  return value === null ? null : decodePurl(value, label);
}

function decodeAlternative(
  value: unknown,
  label: string,
  allowBare: boolean,
): string | Record<string, unknown> {
  if (typeof value === "string") {
    if (!allowBare) throw new Error(`${label} must be a detailed PURL alternative`);
    return decodePurl(value, label);
  }
  const alternative = record(value, label);
  const keys = ["purl", "type", "namespace", "pkg_name", "confidence", "source"];
  requireOnlyKeys(alternative, keys, label);
  for (const key of keys) required(alternative, key, label);
  decodePurl(alternative.purl, `${label}.purl`);
  stringValue(alternative.type, `${label}.type`, false);
  nullableString(alternative.namespace, `${label}.namespace`);
  stringValue(alternative.pkg_name, `${label}.pkg_name`, false);
  finiteNumber(alternative.confidence, `${label}.confidence`);
  stringValue(alternative.source, `${label}.source`, false);
  return alternative;
}

function decodeAlternatives(
  value: unknown,
  label: string,
  allowBare: boolean,
): (string | Record<string, unknown>)[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array or null`);
  const seen = new Set<string>();
  return value.map((item, index) => {
    const decoded = decodeAlternative(item, `${label}[${index}]`, allowBare);
    const purl = typeof decoded === "string" ? decoded : (decoded.purl as string);
    if (seen.has(purl)) throw new Error(`${label}[${index}] duplicates ${purl}`);
    seen.add(purl);
    return decoded;
  });
}

function decodeCpes(value: unknown, label: string): string[] {
  if (value === null || value === undefined) return [];
  if (!Array.isArray(value)) throw new Error(`${label} must be an array or null`);
  const seen = new Set<string>();
  return value.map((item, index) => {
    if (typeof item !== "string" || !CPE_PATTERN.test(item)) {
      throw new Error(`${label}[${index}] must be a valid CPE 2.3 prefix`);
    }
    if (seen.has(item)) throw new Error(`${label}[${index}] duplicates ${item}`);
    seen.add(item);
    return item;
  });
}

function decodeAutoMapping(value: unknown, label: string): void {
  const auto = record(value, label);
  const keys = [
    "purl",
    "type",
    "namespace",
    "pkg_name",
    "confidence",
    "sources",
    "alternative_purls",
  ];
  requireOnlyKeys(auto, keys, label);
  for (const key of ["purl", "type", "namespace", "pkg_name", "confidence", "sources"]) {
    required(auto, key, label);
  }
  decodeNullablePurl(auto.purl, `${label}.purl`);
  nullableString(auto.type, `${label}.type`);
  nullableString(auto.namespace, `${label}.namespace`);
  nullableString(auto.pkg_name, `${label}.pkg_name`);
  finiteNumber(auto.confidence, `${label}.confidence`);
  stringArray(auto.sources, `${label}.sources`);
  if (hasOwn(auto, "alternative_purls")) {
    decodeAlternatives(auto.alternative_purls, `${label}.alternative_purls`, false);
  }
}

function decodeIdentity(
  value: unknown,
  label: string,
  cpeProvenance: "unavailable" | "available",
): void {
  const identity = record(value, label);
  const identityValue = stringValue(identity.value, `${label}.value`, false);
  if (identity.kind === "purl" && !PURL_PATTERN.test(identityValue)) {
    throw new Error(`${label}.value must be a valid PURL`);
  }
  if (identity.kind === "cpe" && !CPE_PATTERN.test(identityValue)) {
    throw new Error(`${label}.value must be a valid CPE 2.3 prefix`);
  }
  const allowedIdentityKeys =
    identity.kind === "purl" && identity.role === "alternative"
      ? ["kind", "role", "value", "coordinates", "provenance"]
      : ["kind", "role", "value", "provenance"];
  requireOnlyKeys(identity, allowedIdentityKeys, label);
  const provenance = record(identity.provenance, `${label}.provenance`);
  if (identity.kind === "purl" && identity.role === "primary") {
    if (provenance.availability !== "available") {
      throw new Error(`${label} primary provenance must be available`);
    }
    const review = record(provenance.review, `${label}.provenance.review`);
    if (provenance.source === "auto") {
      if (
        !hasOnlyKeys(provenance, [
          "availability",
          "source",
          "confidence",
          "sources",
          "review",
        ]) ||
        !hasOnlyKeys(review, ["status", "reviewer"]) ||
        typeof provenance.confidence !== "number" ||
        !Number.isFinite(provenance.confidence) ||
        !Array.isArray(provenance.sources) ||
        !provenance.sources.every((source) => typeof source === "string") ||
        !["auto-unverified", "auto-verified"].includes(String(review.status)) ||
        review.reviewer !== null
      ) {
        throw new Error(`${label} has malformed automatic primary provenance`);
      }
    } else if (provenance.source === "manual") {
      if (
        !hasOnlyKeys(provenance, ["availability", "source", "review"]) ||
        !hasOnlyKeys(review, ["status", "reviewer", "reviewed_at"]) ||
        !["verified", "edited"].includes(String(review.status)) ||
        typeof review.reviewer !== "string" ||
        review.reviewer.length === 0 ||
        typeof review.reviewed_at !== "string" ||
        !/(?:Z|[+-]\d{2}:\d{2})$/.test(review.reviewed_at) ||
        !Number.isFinite(Date.parse(review.reviewed_at))
      ) {
        throw new Error(`${label} has malformed manual primary provenance`);
      }
    } else {
      throw new Error(`${label} has unsupported primary source`);
    }
  } else if (identity.kind === "purl" && identity.role === "alternative") {
    if (provenance.availability === "available") {
      const coordinates = record(identity.coordinates, `${label}.coordinates`);
      if (
        !hasOnlyKeys(provenance, ["availability", "source", "confidence"]) ||
        !hasOnlyKeys(coordinates, ["type", "namespace", "pkg_name"]) ||
        typeof coordinates.type !== "string" ||
        coordinates.type.length === 0 ||
        (coordinates.namespace !== null && typeof coordinates.namespace !== "string") ||
        typeof coordinates.pkg_name !== "string" ||
        coordinates.pkg_name.length === 0 ||
        !ALTERNATIVE_SOURCES.has(String(provenance.source)) ||
        typeof provenance.confidence !== "number" ||
        !Number.isFinite(provenance.confidence)
      ) {
        throw new Error(`${label} has malformed detailed alternative provenance`);
      }
    } else if (
      provenance.availability !== "unavailable" ||
      !hasOnlyKeys(provenance, ["availability"]) ||
      "coordinates" in identity
    ) {
      throw new Error(`${label} has unsupported alternative provenance`);
    }
  } else if (identity.kind === "cpe" && identity.role === "associated") {
    if (cpeProvenance === "unavailable") {
      if (
        provenance.availability !== "unavailable" ||
        !hasOnlyKeys(provenance, ["availability"])
      ) {
        throw new Error(`${label} CPE provenance must be unavailable`);
      }
    } else {
      if (provenance.availability !== "available") {
        throw new Error(`${label} CPE provenance must be available`);
      }
      const review = record(provenance.review, `${label}.provenance.review`);
      const source = String(provenance.source);
      const automatic =
        source === "auto" &&
        hasOnlyKeys(provenance, ["availability", "source", "review"]) &&
        hasOnlyKeys(review, ["status", "reviewer"]) &&
        ["auto-unverified", "auto-verified"].includes(String(review.status)) &&
        review.reviewer === null;
      const manual =
        source === "manual" &&
        hasOnlyKeys(provenance, ["availability", "source", "review"]) &&
        hasOnlyKeys(review, ["status", "reviewer", "reviewed_at"]) &&
        ["verified", "edited"].includes(String(review.status)) &&
        typeof review.reviewer === "string" &&
        review.reviewer.length > 0 &&
        typeof review.reviewed_at === "string" &&
        /(?:Z|[+-]\d{2}:\d{2})$/.test(review.reviewed_at) &&
        Number.isFinite(Date.parse(review.reviewed_at));
      if (!automatic && !manual) {
        throw new Error(`${label} has malformed CPE provenance`);
      }
    }
  } else {
    throw new Error(`${label} has unsupported identity kind/role`);
  }
}

type IdentitySummary = { kind: "purl" | "cpe"; role: string; value: string };

function decodeLegacyIdentityFields(
  entry: Record<string, unknown>,
  label: string,
): IdentitySummary[] {
  const expected: IdentitySummary[] = [];
  const purl = decodeNullablePurl(required(entry, "purl", label), `${label}.purl`);
  nullableString(required(entry, "type", label), `${label}.type`);
  nullableString(required(entry, "namespace", label), `${label}.namespace`);
  nullableString(required(entry, "pkg_name", label), `${label}.pkg_name`);
  const alternatives = decodeAlternatives(
    entry.alternative_purls,
    `${label}.alternative_purls`,
    true,
  );
  const cpes = decodeCpes(entry.cpes, `${label}.cpes`);
  const unmapped = hasOwn(entry, "unmapped") ? entry.unmapped : false;
  if (typeof unmapped !== "boolean") throw new Error(`${label}.unmapped must be a boolean`);
  if (hasOwn(entry, "auto")) decodeAutoMapping(entry.auto, `${label}.auto`);

  const seenPurls = new Set<string>();
  if (purl !== null) {
    if (unmapped) throw new Error(`${label} cannot be unmapped with a primary PURL`);
    seenPurls.add(purl);
    expected.push({ kind: "purl", role: "primary", value: purl });
  }
  alternatives.forEach((alternative, index) => {
    const value =
      typeof alternative === "string" ? alternative : (alternative.purl as string);
    if (seenPurls.has(value)) {
      throw new Error(`${label}.alternative_purls[${index}] duplicates ${value}`);
    }
    seenPurls.add(value);
    expected.push({ kind: "purl", role: "alternative", value });
  });
  if (unmapped && alternatives.length > 0) {
    throw new Error(`${label} cannot be unmapped with alternative PURLs`);
  }
  expected.push(...cpes.map((value) => ({ kind: "cpe" as const, role: "associated", value })));
  return expected;
}

function decodeCommonEntry(
  entry: Record<string, unknown>,
  name: string,
  label: string,
): IdentitySummary[] {
  if (stringValue(required(entry, "name", label), `${label}.name`, false) !== name) {
    throw new Error(`${label}.name must match package key ${name}`);
  }
  stringValue(required(entry, "version", label), `${label}.version`);
  const status = stringValue(required(entry, "status", label), `${label}.status`);
  if (!REVIEW_STATUSES.has(status)) throw new Error(`${label}.status is unsupported`);
  if (hasOwn(entry, "download_count")) {
    nullableFiniteNumber(entry.download_count, `${label}.download_count`);
  }
  return decodeLegacyIdentityFields(entry, label);
}

function decodeIndexEntry(
  entry: Record<string, unknown>,
  name: string,
  identityContract: IdentityContract,
  label: string,
): void {
  requireOnlyKeys(entry, INDEX_ENTRY_KEYS, label);
  const expected = decodeCommonEntry(entry, name, label);
  stringValue(required(entry, "detail_path", label), `${label}.detail_path`, false);
  decodeCurrentIdentities(entry, expected, identityContract, label);
}

function decodeFullEntry(
  entry: Record<string, unknown>,
  name: string,
  identityContract: IdentityContract,
  label: string,
): void {
  requireOnlyKeys(entry, FULL_ENTRY_KEYS, label);
  const expected = decodeCommonEntry(entry, name, label);
  for (const key of ["build", "subdir", "url"] as const) {
    if (hasOwn(entry, key)) stringValue(entry[key], `${label}.${key}`);
  }
  finiteNumber(required(entry, "confidence", label), `${label}.confidence`);
  stringArray(required(entry, "sources", label), `${label}.sources`);
  for (const key of [
    "homepage",
    "repo",
    "recipe_url",
    "summary",
    "source_url",
    "note",
    "fetched_at",
  ] as const) {
    nullableString(required(entry, key, label), `${label}.${key}`);
  }
  const source = stringValue(required(entry, "source", label), `${label}.source`);
  if (source !== "auto" && source !== "manual") {
    throw new Error(`${label}.source must be auto or manual`);
  }
  for (const key of ["approved_by", "approved_at"] as const) {
    if (hasOwn(entry, key)) stringValue(entry[key], `${label}.${key}`);
  }
  if (hasOwn(entry, "auto_verified") && typeof entry.auto_verified !== "boolean") {
    throw new Error(`${label}.auto_verified must be a boolean`);
  }
  if (hasOwn(entry, "verification_sources") && entry.verification_sources !== null) {
    stringArray(entry.verification_sources, `${label}.verification_sources`);
  }
  decodeCurrentIdentities(entry, expected, identityContract, label);
}

type IdentityContract = "none" | "legacy" | "current";

function decodeCurrentIdentities(
  entry: Record<string, unknown>,
  expected: IdentitySummary[],
  identityContract: IdentityContract,
  label: string,
): void {
  if (identityContract === "none") {
    if (hasOwn(entry, "identities")) {
      throw new Error(`${label}.identities is not supported by this schema`);
    }
    return;
  }
  if (!Array.isArray(entry.identities)) {
    throw new Error(`${label}.identities must be an array`);
  }
  const seenValues = new Set<string>();
  const actual = entry.identities.map((identity, index) => {
    const identityLabel = `${label}.identities[${index}]`;
    decodeIdentity(
      identity,
      identityLabel,
      identityContract === "current" ? "available" : "unavailable",
    );
    const decoded = record(identity, identityLabel);
    const value = decoded.value as string;
    if (seenValues.has(value)) {
      throw new Error(`${identityLabel} duplicates identity value ${value}`);
    }
    seenValues.add(value);
    return { kind: decoded.kind, role: decoded.role, value };
  });
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label}.identities must exactly match legacy identity values and order`);
  }

  const alternatives = decodeAlternatives(
    entry.alternative_purls,
    `${label}.alternative_purls`,
    true,
  );
  let alternativeIndex = 0;
  for (const identity of entry.identities) {
    const decoded = record(identity, `${label}.identities`);
    if (decoded.kind !== "purl" || decoded.role !== "alternative") continue;
    const legacy = alternatives[alternativeIndex++];
    if (typeof legacy === "object") {
      const coordinates = record(decoded.coordinates, `${label}.identity.coordinates`);
      const provenance = record(decoded.provenance, `${label}.identity.provenance`);
      if (
        coordinates.type !== legacy.type ||
        coordinates.namespace !== legacy.namespace ||
        coordinates.pkg_name !== legacy.pkg_name ||
        provenance.availability !== "available" ||
        provenance.source !== legacy.source ||
        provenance.confidence !== legacy.confidence
      ) {
        throw new Error(
          `${label}.identities alternative does not match legacy coordinates/provenance`,
        );
      }
    } else if (
      JSON.stringify(decoded.provenance) !==
        JSON.stringify({ availability: "unavailable" }) ||
      "coordinates" in decoded
    ) {
      throw new Error(`${label}.identities bare alternative has unexpected provenance`);
    }
  }
}

type PackageShape = "index" | "full";

function decodePackages(
  payload: Record<string, unknown>,
  currentVersion: number,
  label: string,
  shape: PackageShape,
): void {
  const packages = record(payload.packages, `${label}.packages`);
  const version = payload.schema_version as number;
  const identityContract: IdentityContract =
    version === currentVersion
      ? "current"
      : version === currentVersion - 1
        ? "legacy"
        : "none";
  for (const [name, rawEntry] of Object.entries(packages)) {
    if (name.length === 0) throw new Error(`${label} has an empty package name`);
    const entryLabel = `${label}.packages.${name}`;
    const entry = record(rawEntry, entryLabel);
    if (shape === "index") decodeIndexEntry(entry, name, identityContract, entryLabel);
    else decodeFullEntry(entry, name, identityContract, entryLabel);
  }
}

function normalizedIndexIdentityContract(
  entry: Record<string, unknown>,
  includeAuto = hasOwn(entry, "auto"),
  includeDownloadCount = hasOwn(entry, "download_count"),
): string {
  const contract: Record<string, unknown> = {
    name: entry.name,
    version: entry.version,
    purl: entry.purl,
    type: entry.type,
    namespace: entry.namespace,
    pkg_name: entry.pkg_name,
    status: entry.status,
    unmapped: entry.unmapped === true,
    alternative_purls: entry.alternative_purls ?? [],
    cpes: entry.cpes ?? [],
    identities: entry.identities,
  };
  if (includeDownloadCount) contract.download_count = entry.download_count;
  if (includeAuto) contract.auto = entry.auto;
  return JSON.stringify(contract);
}

export async function loadMappings(path = DEFAULT_PATH): Promise<MappingsPayload> {
  const payload = decodeVersionedPayload(
    await loadJsonCached(path),
    "mapping bundle",
    SUPPORTED_BUNDLE_SCHEMAS,
    true,
  );
  decodePackages(payload, 3, "mapping bundle", "full");
  return payload as MappingsPayload;
}

export async function loadMappingsIndex(
  path = DEFAULT_INDEX_PATH,
): Promise<MappingsIndexPayload> {
  const payload = decodeVersionedPayload(
    await loadJsonCached(path),
    "mapping index",
    SUPPORTED_INDEX_SCHEMAS,
    true,
  );
  decodePackages(payload, 4, "mapping index", "index");
  const packages = record(payload.packages, "mapping index.packages");
  for (const [name, rawEntry] of Object.entries(packages)) {
    const entry = record(rawEntry, `mapping index.packages.${name}`);
    const includeAuto = hasOwn(entry, "auto");
    const includeDownloadCount = hasOwn(entry, "download_count");
    indexDecodeByPackage.set(entry, {
      schemaVersion: payload.schema_version as number,
      name,
      detailPath: entry.detail_path as string,
      includeAuto,
      includeDownloadCount,
      identityContract: normalizedIndexIdentityContract(
        entry,
        includeAuto,
        includeDownloadCount,
      ),
    });
  }
  return payload as MappingsIndexPayload;
}

export async function loadMappingPackageDetail(
  pkg: MappingPackageIndex,
): Promise<PackageEntry> {
  const decodedIndex = indexDecodeByPackage.get(pkg);
  if (decodedIndex === undefined) {
    throw new Error(`Mapping package ${pkg.name} was not decoded from an index`);
  }
  const currentIndexContract = normalizedIndexIdentityContract(
    pkg as unknown as Record<string, unknown>,
  );
  if (
    pkg.name !== decodedIndex.name ||
    pkg.detail_path !== decodedIndex.detailPath ||
    currentIndexContract !== decodedIndex.identityContract
  ) {
    throw new Error(`Mapping index entry ${decodedIndex.name} changed after decoding`);
  }

  const path = `./${decodedIndex.detailPath}`;
  const payload = decodeVersionedPayload(
    await loadJsonCached(path),
    `mapping detail ${path}`,
    SUPPORTED_DETAIL_SCHEMAS,
    false,
  );
  decodePackages(payload, 3, `mapping detail ${path}`, "full");
  const expectedDetailVersion = decodedIndex.schemaVersion - 1;
  if (payload.schema_version !== expectedDetailVersion) {
    throw new Error(
      `mapping index/detail schema mismatch: index ${decodedIndex.schemaVersion} requires detail ${expectedDetailVersion}`,
    );
  }
  const data = payload as unknown as MappingDetailPayload;
  const detail = data.packages[decodedIndex.name];
  if (!detail) throw new Error(`Missing ${decodedIndex.name} in ${path}`);
  if (
    decodedIndex.schemaVersion >= 3 &&
    normalizedIndexIdentityContract(
      detail as unknown as Record<string, unknown>,
      decodedIndex.includeAuto,
      decodedIndex.includeDownloadCount,
    ) !== decodedIndex.identityContract
  ) {
    throw new Error(
      `Mapping index/detail identity contract mismatch for ${decodedIndex.name}`,
    );
  }
  return detail;
}

export function packagesAsList<T extends { name: string }>(payload: {
  packages: Record<string, T>;
}): T[] {
  const out: T[] = [];
  for (const [name, entry] of Object.entries(payload.packages)) {
    out.push({ ...entry, name });
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}

export const PURL_TYPES = [
  { id: "pypi", label: "pypi" },
  { id: "npm", label: "npm" },
  { id: "github", label: "github" },
  { id: "cargo", label: "cargo" },
  { id: "gem", label: "gem" },
  { id: "golang", label: "golang" },
  { id: "generic", label: "generic" },
  { id: "maven", label: "maven" },
  { id: "cran", label: "cran" },
  { id: "bioconductor", label: "bioconductor" },
] as const;

export const ECOSYSTEMS = [
  { id: "pypi", label: "PyPI", color: "#3776AB" },
  { id: "npm", label: "npm", color: "#CB3837" },
  { id: "github", label: "GitHub", color: "#001d38" },
  { id: "cargo", label: "Cargo", color: "#B7410E" },
  { id: "cran", label: "CRAN", color: "#1E63B5" },
  { id: "bioconductor", label: "Bioconductor", color: "#1A8744" },
  { id: "generic", label: "Generic", color: "#62656a" },
  { id: "none", label: "No primary", color: "#b5b7ba" },
] as const;
