import type { Edit, PackageEntry, VersionSchemeName } from "./types";

/** Reviewer-facing description of each version scheme the payload supports. */
export const VERSION_SCHEME_OPTIONS: {
  value: VersionSchemeName | null;
  label: string;
  example: string;
}[] = [
  {
    value: null,
    label: "Conda ordering",
    example: "1.0a1 < 1.0 — a trailing letter is a pre-release",
  },
  {
    value: "letter-patch",
    label: "Letter patch releases",
    example: "1.1.1 < 1.1.1a < 1.1.1w < 1.1.2 — a trailing letter is a patch release",
  },
];

type SchemePackage = Pick<PackageEntry, "version_scheme">;

/** The published scheme, or null for ordinary conda ordering. */
export function publishedVersionScheme(pkg: SchemePackage): VersionSchemeName | null {
  return pkg.version_scheme?.scheme ?? null;
}

/** The scheme the package will have once the staged edit is merged. */
export function effectiveVersionScheme(
  pkg: SchemePackage,
  edit?: Pick<Edit, "versionScheme">,
): VersionSchemeName | null {
  return edit?.versionScheme !== undefined
    ? edit.versionScheme
    : publishedVersionScheme(pkg);
}

/**
 * Normalise a staged edit's scheme against what is published.
 *
 * Returns the edit's `versionScheme` (undefined when it would not change the
 * package) and whether the edit is metadata-only: the mapping itself is
 * unchanged, so the contribution must carry only `version_scheme` and must not
 * re-review (and so re-attribute) the package's mapping.
 */
export function reconcileVersionScheme(
  pkg: SchemePackage,
  edit: Pick<Edit, "versionScheme">,
  mappingUnchanged: boolean,
  approved: boolean,
): { versionScheme: VersionSchemeName | null | undefined; metadataOnly: boolean } {
  const changed =
    edit.versionScheme !== undefined &&
    edit.versionScheme !== publishedVersionScheme(pkg);
  return {
    versionScheme: changed ? edit.versionScheme : undefined,
    metadataOnly: changed && mappingUnchanged && !approved,
  };
}

export function versionSchemeLabel(scheme: VersionSchemeName | null): string {
  return VERSION_SCHEME_OPTIONS.find((option) => option.value === scheme)?.label ?? String(scheme);
}
