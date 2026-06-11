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
  status: "auto-unverified" | "auto-verified" | "verified" | "unmapped" | "edited";
  source: "auto" | "manual";
  unmapped?: boolean;
  approved_by?: string;
  approved_at?: string;
  alternative_purls?: (PurlAlternative | string)[] | null;
  auto_verified?: boolean;
  verification_sources?: string[] | null;
  /** CPE 2.3 vendor/product prefixes for downstream NVD matching. */
  cpes?: string[] | null;
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
  | "auto"
> & {
  detail_path: string;
};

export type MappingsPayload = {
  schema_version: number;
  generated_at: string | null;
  auto_generated_at: string | null;
  manual_updated_at: string | null;
  channel: string;
  package_count: number;
  packages: Record<string, PackageEntry>;
};

export type MappingsIndexPayload = Omit<MappingsPayload, "packages"> & {
  packages: Record<string, MappingPackageIndex>;
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
