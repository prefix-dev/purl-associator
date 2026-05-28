import { useEffect, useState } from "react";
import { config } from "../config";
import { loadMappings, packagesAsList } from "./loader";
import type { MappingsPayload, PackageEntry } from "./types";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function useMappingsData() {
  const [payload, setPayload] = useState<MappingsPayload | null>(null);
  const [packages, setPackages] = useState<PackageEntry[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    loadMappings(config.mappingsUrl)
      .then((data) => {
        setPayload(data);
        setPackages(packagesAsList(data));
      })
      .catch((err) => setLoadError(errorMessage(err)));
  }, []);

  return { payload, packages, loadError };
}
