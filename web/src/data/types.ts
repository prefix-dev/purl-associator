export type AutoMapping = {
  purl: string | null;
  type: string | null;
  namespace: string | null;
  pkg_name: string | null;
  confidence: number;
  sources: string[];
  alternative_purls?: PurlAlternative[] | null;
};

export type PurlAlternative = {
  purl: string;
  type: string;
  namespace: string | null;
  pkg_name: string;
  confidence: number;
  source: string;
};

export type ReviewStatus =
  | "auto-unverified"
  | "auto-verified"
  | "verified"
  | "unmapped"
  | "edited";

export type AutomaticPrimaryIdentity = {
  kind: "purl";
  role: "primary";
  value: string;
  provenance: {
    availability: "available";
    source: "auto";
    confidence: number;
    sources: string[];
    review: {
      status: "auto-unverified" | "auto-verified";
      reviewer: null;
    };
  };
};

export type ManualPrimaryIdentity = {
  kind: "purl";
  role: "primary";
  value: string;
  provenance: {
    availability: "available";
    source: "manual";
    review: {
      status: "verified" | "edited";
      reviewer: string;
      reviewed_at: string;
    };
  };
};

export type BareAlternativeIdentity = {
  kind: "purl";
  role: "alternative";
  value: string;
  provenance: { availability: "unavailable" };
};

export type DetailedAlternativeIdentity = {
  kind: "purl";
  role: "alternative";
  value: string;
  coordinates: {
    type: string;
    namespace: string | null;
    pkg_name: string;
  };
  provenance: {
    availability: "available";
    source:
      | "recipe-source"
      | "recipe-deps"
      | "recipe-source+recipe-deps"
      | "parselmouth-artifact";
    confidence: number;
  };
};

export type LegacyCpeIdentity = {
  kind: "cpe";
  role: "associated";
  value: string;
  provenance: { availability: "unavailable" };
};

export type CpeIdentity = {
  kind: "cpe";
  role: "associated";
  value: string;
  provenance:
    | {
        availability: "available";
        source: "auto";
        review: {
          status: "auto-unverified" | "auto-verified";
          reviewer: null;
        };
      }
    | {
        availability: "available";
        source: "manual";
        review: {
          status: "verified" | "edited";
          reviewer: string;
          reviewed_at: string;
        };
      };
};

export type PublishedIdentity =
  | AutomaticPrimaryIdentity
  | ManualPrimaryIdentity
  | BareAlternativeIdentity
  | DetailedAlternativeIdentity
  | LegacyCpeIdentity
  | CpeIdentity;

export type ManualOverride = {
  purl: string | null;
  type: string | null;
  namespace: string | null;
  pkg_name: string | null;
  alternative_purls?: (PurlAlternative | string)[] | null;
  unmapped?: boolean;
  note?: string;
  approved_by?: string;
  approved_at?: string;
};

export type PackageEntry = {
  name: string;
  version: string;
  build?: string;
  subdir?: string;
  url?: string;
  purl: string | null;
  type: string | null;
  namespace: string | null;
  pkg_name: string | null;
  confidence: number;
  sources: string[];
  homepage: string | null;
  repo: string | null;
  recipe_url: string | null;
  summary: string | null;
  source_url: string | null;
  note: string | null;
  fetched_at: string | null;
  status: ReviewStatus;
  source: "auto" | "manual";
  unmapped?: boolean;
  approved_by?: string;
  approved_at?: string;
  alternative_purls?: (PurlAlternative | string)[] | null;
  auto_verified?: boolean;
  verification_sources?: string[] | null;
  /** CPE 2.3 vendor/product prefixes for downstream NVD matching. */
  cpes?: string[] | null;
  /** Versioned public per-identity provenance (absent on legacy schemas). */
  identities?: PublishedIdentity[];
  /** the original auto guess, kept for diff display when an override exists */
  auto?: AutoMapping;
  /** total downloads on prefix.dev for this package (null if not ranked) */
  download_count?: number | null;
};

export type MappingPackageIndex = Pick<
  PackageEntry,
  | "name"
  | "version"
  | "purl"
  | "type"
  | "namespace"
  | "pkg_name"
  | "status"
  | "download_count"
  | "alternative_purls"
  | "unmapped"
  | "cpes"
  | "identities"
  | "auto"
> & {
  detail_path: string;
};

type MappingPayloadMetadata = {
  generated_at: string | null;
  auto_generated_at: string | null;
  manual_updated_at: string | null;
  channel: string;
  package_count: number;
};

export type LegacyMappingsPayload = MappingPayloadMetadata & {
  schema_version: 1;
  packages: Record<string, PackageEntry>;
};

export type PreviousMappingsPayload = MappingPayloadMetadata & {
  schema_version: 2;
  packages: Record<string, PackageEntry & { identities: PublishedIdentity[] }>;
};

export type CurrentMappingsPayload = MappingPayloadMetadata & {
  schema_version: 3;
  packages: Record<string, PackageEntry & { identities: PublishedIdentity[] }>;
};

export type MappingsPayload =
  | LegacyMappingsPayload
  | PreviousMappingsPayload
  | CurrentMappingsPayload;

export type LegacyMappingsIndexPayload = MappingPayloadMetadata & {
  schema_version: 2;
  packages: Record<string, MappingPackageIndex>;
};

export type PreviousMappingsIndexPayload = MappingPayloadMetadata & {
  schema_version: 3;
  packages: Record<
    MappingPackageIndex["name"],
    MappingPackageIndex & { identities: PublishedIdentity[] }
  >;
};

export type CurrentMappingsIndexPayload = MappingPayloadMetadata & {
  schema_version: 4;
  packages: Record<
    MappingPackageIndex["name"],
    MappingPackageIndex & { identities: PublishedIdentity[] }
  >;
};

export type MappingsIndexPayload =
  | LegacyMappingsIndexPayload
  | PreviousMappingsIndexPayload
  | CurrentMappingsIndexPayload;

export type MappingDetailPayload =
  | { schema_version: 1; packages: Record<string, PackageEntry> }
  | {
      schema_version: 2 | 3;
      packages: Record<string, PackageEntry & { identities: PublishedIdentity[] }>;
    };

export type Edit = {
  type: string;
  namespace: string;
  pkgName: string;
  purl: string;
  alternative_purls: string[];
  /** Full replacement CPE list. undefined = untouched — the contribution
   *  omits the field so the cpe-pipeline layer keeps owning CPEs. */
  cpes?: string[];
  unmapped: boolean;
  note: string;
  approved?: boolean;
};

export type Repo = {
  owner: string;
  name: string;
  branch: string;
  url: string;
};

export type GitHubUser = {
  login: string;
  name: string | null;
  avatar_url: string;
  initial: string;
  color: string;
};
