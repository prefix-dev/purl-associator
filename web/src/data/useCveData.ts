import { useEffect, useMemo, useState } from "react";
import { config } from "../config";
import { loadCves, purlGroupKey, type CvePackage, type CvePayload } from "./cves";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useCveData() {
  const [payload, setPayload] = useState<CvePayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [focusedPkg, setFocusedPkg] = useState<string | null>(null);

  useEffect(() => {
    loadCves(config.cvesUrl)
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
    const byKey = new Map<string, CvePackage[]>();
    for (const p of packages) {
      const k = purlGroupKey(p);
      const bucket = byKey.get(k);
      if (bucket) bucket.push(p);
      else byKey.set(k, [p]);
    }
    const reps: CvePackage[] = [];
    const members = new Map<string, string[]>();
    for (const bucket of byKey.values()) {
      // Representative = shortest name (the bare base package, when present),
      // ties broken alphabetically for stability.
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

  // Open on the first representative once the grouping is ready.
  useEffect(() => {
    if (focusedPkg == null && representatives.length > 0) {
      setFocusedPkg(representatives[0].package);
    }
  }, [focusedPkg, representatives]);

  const focusedPackage = useMemo(
    () =>
      focusedPkg && payload ? payload.packages[focusedPkg] ?? null : null,
    [focusedPkg, payload],
  );

  return {
    payload,
    loadError,
    focusedPkg,
    setFocusedPkg,
    packages,
    representatives,
    membersByRep,
    focusedPackage,
  };
}
