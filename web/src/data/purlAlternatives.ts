import type { PurlAlternative } from "./types";

export type PurlAlternativeValue = PurlAlternative | string;

export function purlFromAlternative(alt: PurlAlternativeValue): string {
  return typeof alt === "string" ? alt : alt.purl;
}

export function purlsFromAlternatives(
  alternatives: PurlAlternativeValue[] | null | undefined,
): string[] {
  return (alternatives ?? []).map(purlFromAlternative);
}

export function alternativeMeta(alt: PurlAlternativeValue): PurlAlternative {
  if (typeof alt !== "string") return alt;

  const m = alt.match(/^pkg:([^/]+)\/(?:([^/]+)\/)?(.+)$/);
  return {
    purl: alt,
    type: m?.[1] ?? "",
    namespace: m?.[2] ?? null,
    pkg_name: m?.[3] ?? alt.replace(/^pkg:[^/]+\//, ""),
    confidence: 1,
    source: "manual",
  };
}

export function alternativeMetas(
  alternatives: PurlAlternativeValue[] | null | undefined,
): PurlAlternative[] {
  return (alternatives ?? []).map(alternativeMeta);
}

/**
 * The reviewed package state is authoritative. Only fall back to the preserved
 * auto snapshot for packages that do not have reviewed alternatives yet.
 */
export function effectiveAlternativeValues({
  reviewed,
  auto,
}: {
  reviewed: PurlAlternativeValue[] | null | undefined;
  auto: PurlAlternative[] | null | undefined;
}): PurlAlternativeValue[] {
  return reviewed ?? auto ?? [];
}
