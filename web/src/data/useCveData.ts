import { useCallback, useEffect, useMemo, useState } from "react";
import { config } from "../config";
import {
  loadCveIndex,
  loadCvePackageDetail,
  purlGroupKey,
  type CveIndexPayload,
  type CvePackage,
  type CvePackageIndex,
} from "./cves";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useCveData() {
  const [payload, setPayload] = useState<CveIndexPayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [focusedPkg, setFocusedPkg] = useState<string | null>(null);
  const [packageDetails, setPackageDetails] = useState<Record<string, CvePackage>>({});
  const [loadingDetails, setLoadingDetails] = useState<Set<string>>(new Set());

  useEffect(() => {
    loadCveIndex(config.cvesIndexUrl)
      .then(setPayload)
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);

  const packages = useMemo(() => {
    if (!payload) return [];
    return Object.values(payload.packages).sort((a, b) =>
      a.package.localeCompare(b.package),
    );
  }, [payload]);

  // Collapse interchangeable packages (same PURLs + same shipped version) so
  // e.g. the 100+ `airflow-with-*` variants surface once instead of flooding
  // the list with identical advisories. We keep one *representative* package
  // per group for display; reviews staged against it fan out to every member
  // at PR-build time (see CvePRDrawer / buildStatements).
  const { representatives, membersByRep } = useMemo(() => {
    const byKey = new Map<string, CvePackageIndex[]>();
    for (const p of packages) {
      const k = purlGroupKey(p);
      const bucket = byKey.get(k);
      if (bucket) bucket.push(p);
      else byKey.set(k, [p]);
    }
    const reps: CvePackageIndex[] = [];
    const members = new Map<string, string[]>();
    for (const bucket of byKey.values()) {
      bucket.sort(
        (a, b) =>
          a.package.length - b.package.length ||
          a.package.localeCompare(b.package),
      );
      const rep = bucket[0];
      reps.push(rep);
      members.set(
        rep.package,
        bucket.map((m) => m.package),
      );
    }
    reps.sort((a, b) => a.package.localeCompare(b.package));
    return { representatives: reps, membersByRep: members };
  }, [packages]);

  useEffect(() => {
    if (focusedPkg == null && representatives.length > 0) {
      setFocusedPkg(representatives[0].package);
    }
  }, [focusedPkg, representatives]);

  const focusedPackageIndex = useMemo(
    () => (focusedPkg && payload ? payload.packages[focusedPkg] ?? null : null),
    [focusedPkg, payload],
  );

  const ensurePackageDetail = useCallback(
    async (pkgName: string): Promise<CvePackage> => {
      const existing = packageDetails[pkgName];
      if (existing) return existing;
      const index = payload?.packages[pkgName];
      if (!index) throw new Error(`Unknown CVE package ${pkgName}`);
      setLoadingDetails((prev) => new Set(prev).add(pkgName));
      try {
        const detail = await loadCvePackageDetail(index);
        setPackageDetails((prev) => ({ ...prev, [pkgName]: detail }));
        setDetailError(null);
        return detail;
      } catch (err) {
        const msg = errorMessage(err);
        setDetailError(msg);
        throw err;
      } finally {
        setLoadingDetails((prev) => {
          const next = new Set(prev);
          next.delete(pkgName);
          return next;
        });
      }
    },
    [packageDetails, payload],
  );

  useEffect(() => {
    if (!focusedPkg || !payload?.packages[focusedPkg] || packageDetails[focusedPkg]) {
      return;
    }
    ensurePackageDetail(focusedPkg).catch(() => {
      // detailError is set by ensurePackageDetail.
    });
  }, [ensurePackageDetail, focusedPkg, packageDetails, payload]);

  const focusedPackage = focusedPkg ? packageDetails[focusedPkg] ?? null : null;
  const focusedPackageLoading = focusedPkg ? loadingDetails.has(focusedPkg) : false;

  return {
    payload,
    loadError,
    detailError,
    focusedPkg,
    setFocusedPkg,
    packages,
    representatives,
    membersByRep,
    focusedPackageIndex,
    focusedPackage,
    focusedPackageLoading,
    packageDetails,
    ensurePackageDetail,
  };
}
