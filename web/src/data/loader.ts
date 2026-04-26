import type { MappingsPayload, PackageEntry } from "./types";

const DEFAULT_PATH = "./mappings.json";

export async function loadMappings(path = DEFAULT_PATH): Promise<MappingsPayload> {
  const res = await fetch(path, { cache: "no-cache" });
  if (!res.ok) {
    throw new Error(`Failed to load ${path}: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export function packagesAsList(payload: MappingsPayload): PackageEntry[] {
  const out: PackageEntry[] = [];
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
