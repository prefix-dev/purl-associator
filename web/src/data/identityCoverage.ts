import type { Edit, PackageEntry, ReviewStatus } from "./types";

export type IdentityCoverage = "none" | "purl" | "cpe" | "purl+cpe";

type IdentityPackage = Pick<
  PackageEntry,
  "purl" | "alternative_purls" | "cpes" | "identities" | "status" | "unmapped"
>;

function publishedIdentityKinds(pkg: IdentityPackage): {
  hasPurl: boolean;
  hasCpe: boolean;
} {
  if (pkg.identities) {
    return {
      hasPurl: pkg.identities.some((identity) => identity.kind === "purl"),
      hasCpe: pkg.identities.some((identity) => identity.kind === "cpe"),
    };
  }
  return {
    hasPurl: Boolean(pkg.purl || pkg.alternative_purls?.length),
    hasCpe: Boolean(pkg.cpes?.length),
  };
}

export function effectiveCpes(pkg: IdentityPackage, edit?: Edit): string[] {
  return edit?.cpes ?? pkg.cpes ?? [];
}

export function packageIdentityCoverage(
  pkg: IdentityPackage,
  edit?: Edit,
): IdentityCoverage {
  const published = publishedIdentityKinds(pkg);
  const mappingEdit = edit?.metadataOnly ? undefined : edit;
  const hasPurl = mappingEdit
    ? !mappingEdit.unmapped &&
      Boolean(mappingEdit.purl || mappingEdit.alternative_purls?.length)
    : published.hasPurl;
  const hasCpe = mappingEdit
    ? effectiveCpes(pkg, mappingEdit).length > 0
    : published.hasCpe;

  if (hasPurl && hasCpe) return "purl+cpe";
  if (hasPurl) return "purl";
  if (hasCpe) return "cpe";
  return "none";
}

export function needsPurlDecision(
  pkg: IdentityPackage,
  edit?: Edit,
): boolean {
  const coverage = packageIdentityCoverage(pkg, edit);
  if (coverage === "purl" || coverage === "purl+cpe") return false;
  return edit ? !edit.unmapped : pkg.unmapped !== true && pkg.status !== "unmapped";
}

export function effectiveMappingStatus(
  pkg: IdentityPackage,
  edit?: Edit,
): ReviewStatus {
  // A scheme-only edit does not review the mapping, so its status stands.
  return edit && !edit.metadataOnly ? "edited" : pkg.status;
}
