import { create } from "zustand";
import { persist, type PersistStorage, type StorageValue } from "zustand/middleware";
import type { ReviewEdit } from "../data/cves";
import type { Edit } from "../data/types";

/**
 * Persisted user-owned draft state.
 *
 * These stores use Zustand's persist middleware, which writes JSON to
 * localStorage by default. That is intentional: staged edits are user work that
 * should survive accidental tab/window/browser closes until submitted or reset.
 */
const STORAGE_KEYS = {
  stagedPurlEdits: "purl-associator/staged_edits",
  stagedCveEdits: "purl-associator/staged_cve_edits",
} as const;

type PersistedEdits<T> = { edits: Record<string, T> };

function persistedEditStorage<T>(): PersistStorage<PersistedEdits<T>> {
  return {
    getItem: (name) => {
      try {
        const raw = localStorage.getItem(name);
        if (!raw) return null;
        const parsed = JSON.parse(raw) as
          | StorageValue<PersistedEdits<T>>
          | Record<string, T>;
        if (parsed && typeof parsed === "object" && "state" in parsed) {
          return parsed as StorageValue<PersistedEdits<T>>;
        }
        // Migration path for the pre-Zustand format, where the storage value was
        // the raw edits object under the same key.
        return { state: { edits: parsed as Record<string, T> }, version: 0 };
      } catch {
        return null;
      }
    },
    setItem: (name, value) => {
      try {
        localStorage.setItem(name, JSON.stringify(value));
      } catch {
        // Ignore unavailable/quota-limited storage. The app still works in-memory.
      }
    },
    removeItem: (name) => {
      try {
        localStorage.removeItem(name);
      } catch {
        // ignore
      }
    },
  };
}

type PurlEditState = {
  edits: Record<string, Edit>;
  setEdits: (
    next:
      | Record<string, Edit>
      | ((previous: Record<string, Edit>) => Record<string, Edit>),
  ) => void;
  clearEdits: () => void;
};

export const usePurlEditStore = create<PurlEditState>()(
  persist(
    (set) => ({
      edits: {},
      setEdits: (next) =>
        set((state) => ({
          edits: typeof next === "function" ? next(state.edits) : next,
        })),
      clearEdits: () => set({ edits: {} }),
    }),
    {
      name: STORAGE_KEYS.stagedPurlEdits,
      storage: persistedEditStorage<Edit>(),
      partialize: (state) => ({ edits: state.edits }),
    },
  ),
);

type CveEditState = {
  edits: Record<string, ReviewEdit>;
  setEdits: (
    next:
      | Record<string, ReviewEdit>
      | ((previous: Record<string, ReviewEdit>) => Record<string, ReviewEdit>),
  ) => void;
  clearEdits: () => void;
};

export const useCveEditStore = create<CveEditState>()(
  persist(
    (set) => ({
      edits: {},
      setEdits: (next) =>
        set((state) => ({
          edits: typeof next === "function" ? next(state.edits) : next,
        })),
      clearEdits: () => set({ edits: {} }),
    }),
    {
      name: STORAGE_KEYS.stagedCveEdits,
      storage: persistedEditStorage<ReviewEdit>(),
      partialize: (state) => ({ edits: state.edits }),
    },
  ),
);
