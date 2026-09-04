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
  const hasPurl = edit
    ? !edit.unmapped && Boolean(edit.purl || edit.alternative_purls?.length)
    : published.hasPurl;
  const hasCpe = edit ? effectiveCpes(pkg, edit).length > 0 : published.hasCpe;

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
  return edit ? "edited" : pkg.status;
}
