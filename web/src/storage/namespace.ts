/**
 * Namespace used to prefix all browser storage keys for this app. Centralized
 * here so renaming the project only requires changing one constant.
 */
export const STORAGE_NAMESPACE = "purl-associator";

export function storageKey(name: string): string {
  return `${STORAGE_NAMESPACE}/${name}`;
}
