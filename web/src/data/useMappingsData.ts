import { useCallback, useEffect, useMemo, useState } from "react";
import { config } from "../config";
import {
  loadMappingPackageDetail,
  loadMappingsIndex,
  packagesAsList,
} from "./loader";
import type { MappingPackageIndex, MappingsIndexPayload, PackageEntry } from "./types";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useMappingsData() {
  const [payload, setPayload] = useState<MappingsIndexPayload | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [details, setDetails] = useState<Record<string, PackageEntry>>({});
  const [loadingDetails, setLoadingDetails] = useState<Set<string>>(new Set());

  useEffect(() => {
    loadMappingsIndex(config.mappingsIndexUrl)
      .then(setPayload)
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);

  const packages = useMemo<MappingPackageIndex[]>(() => {
    if (!payload) return [];
    return packagesAsList(payload);
  }, [payload]);

  const ensurePackageDetail = useCallback(
    async (name: string): Promise<PackageEntry> => {
      const existing = details[name];
      if (existing) return existing;
      const index = payload?.packages[name];
      if (!index) throw new Error(`Unknown mapping package ${name}`);
      setLoadingDetails((prev) => new Set(prev).add(name));
      try {
        const detail = await loadMappingPackageDetail(index);
        setDetails((prev) => ({ ...prev, [name]: detail }));
        setDetailError(null);
        return detail;
      } catch (err) {
        setDetailError(errorMessage(err));
        throw err;
      } finally {
        setLoadingDetails((prev) => {
          const next = new Set(prev);
          next.delete(name);
          return next;
        });
      }
    },
    [details, payload],
  );

  return {
    payload,
    packages,
    loadError,
    detailError,
    details,
    loadingDetails,
    ensurePackageDetail,
  };
}
