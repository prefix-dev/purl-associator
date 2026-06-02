import type {
  MappingPackageIndex,
  MappingsIndexPayload,
  MappingsPayload,
  PackageEntry,
} from "./types";

const DEFAULT_PATH = "./mappings.json";
const DEFAULT_INDEX_PATH = "./mappings-index.json";

const jsonCache = new Map<string, Promise<unknown>>();

async function loadJsonCached<T>(path: string): Promise<T> {
  const cached = jsonCache.get(path);
  if (cached) return cached as Promise<T>;
  const promise = fetch(path, { cache: "no-cache" }).then((res) => {
    if (!res.ok) {
      throw new Error(`Failed to load ${path}: ${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<T>;
  });
  jsonCache.set(path, promise);
  promise.catch(() => jsonCache.delete(path));
  return promise;
}

export async function loadMappings(path = DEFAULT_PATH): Promise<MappingsPayload> {
  return loadJsonCached<MappingsPayload>(path);
}

export async function loadMappingsIndex(
  path = DEFAULT_INDEX_PATH,
): Promise<MappingsIndexPayload> {
  return loadJsonCached<MappingsIndexPayload>(path);
}

export async function loadMappingPackageDetail(
  pkgOrPath: MappingPackageIndex | string,
): Promise<PackageEntry> {
  if (typeof pkgOrPath === "string") {
    return loadJsonCached<PackageEntry>(pkgOrPath);
  }
  const path = `./${pkgOrPath.detail_path}`;
  const data = await loadJsonCached<
    PackageEntry | { packages: Record<string, PackageEntry> }
  >(path);
  if ("packages" in data) {
    const detail = data.packages[pkgOrPath.name];
    if (!detail) throw new Error(`Missing ${pkgOrPath.name} in ${path}`);
    return detail;
  }
  return data;
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
  { id: "none", label: "Unmapped", color: "#b5b7ba" },
] as const;
