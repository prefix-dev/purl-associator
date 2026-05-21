const CONDA_QUALIFIER = "channel=conda-forge";

/** A package-level or version-pinned conda PURL for the conda-forge channel. */
export function condaPurl(pkg: string, version?: string): string {
  return version
    ? `pkg:conda/${pkg}@${version}?${CONDA_QUALIFIER}`
    : `pkg:conda/${pkg}?${CONDA_QUALIFIER}`;
}

export function isCondaPurl(value: unknown): value is string {
  return typeof value === "string" && value.startsWith("pkg:conda/");
}
