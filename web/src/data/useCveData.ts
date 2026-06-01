import { useEffect, useMemo, useState } from "react";
import { config } from "../config";
import { loadCves, type CvePayload } from "./cves";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useCveData() {
  const [payload, setPayload] = useState<CvePayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [focusedPkg, setFocusedPkg] = useState<string | null>(null);

  useEffect(() => {
    loadCves(config.cvesUrl)
      .then((data) => {
        setPayload(data);
        const first = Object.keys(data.packages).sort()[0];
        if (first) setFocusedPkg(first);
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);

  const packages = useMemo(() => {
    if (!payload) return [];
    return Object.values(payload.packages).sort((a, b) =>
      a.package.localeCompare(b.package),
    );
  }, [payload]);

  const focusedPackage = useMemo(
    () =>
      focusedPkg && payload ? payload.packages[focusedPkg] ?? null : null,
    [focusedPkg, payload],
  );

  return { payload, loadError, focusedPkg, setFocusedPkg, packages, focusedPackage };
}
