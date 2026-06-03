import { create } from "zustand";
import { persist, type PersistStorage, type StorageValue } from "zustand/middleware";
import type { ReviewEdit } from "../data/cves";
import type { EnqueueItem } from "../github/cve_enqueue_api";
import type { Edit } from "../data/types";
import { storageKey } from "../storage/namespace";

/**
 * Persisted user-owned draft state.
 *
 * These stores use Zustand's persist middleware, which writes JSON to
 * localStorage by default. That is intentional: staged edits are user work that
 * should survive accidental tab/window/browser closes until submitted or reset.
 */
const STORAGE_KEYS = {
  stagedPurlEdits: storageKey("staged_edits"),
  stagedCveEdits: storageKey("staged_cve_edits"),
  stagedCveAiReviews: storageKey("staged_cve_ai_reviews"),
  cveAiWorkListPrefs: storageKey("cve_ai_work_list_prefs"),
} as const;

function safeJsonStorage<T>(
  migrate?: (parsed: unknown) => StorageValue<T>,
): PersistStorage<T> {
  return {
    getItem: (name) => {
      try {
        const raw = localStorage.getItem(name);
        if (!raw) return null;
        const parsed = JSON.parse(raw) as StorageValue<T> | unknown;
        if (parsed && typeof parsed === "object" && "state" in parsed) {
          return parsed as StorageValue<T>;
        }
        return migrate ? migrate(parsed) : null;
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

type PersistedEdits<T> = { edits: Record<string, T> };

function persistedEditStorage<T>(): PersistStorage<PersistedEdits<T>> {
  return safeJsonStorage<PersistedEdits<T>>((parsed) => {
    // Migration path for the pre-Zustand format, where the storage value was
    // the raw edits object under the same key.
    return { state: { edits: parsed as Record<string, T> }, version: 0 };
  });
}

function persistedJsonStorage<T>(): PersistStorage<T> {
  return safeJsonStorage<T>();
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

type CveAiReviewQueueState = {
  items: EnqueueItem[];
  setItems: (
    next: EnqueueItem[] | ((previous: EnqueueItem[]) => EnqueueItem[]),
  ) => void;
  clearItems: () => void;
};

export const useCveAiReviewQueueStore = create<CveAiReviewQueueState>()(
  persist(
    (set) => ({
      items: [],
      setItems: (next) =>
        set((state) => ({
          items: typeof next === "function" ? next(state.items) : next,
        })),
      clearItems: () => set({ items: [] }),
    }),
    {
      name: STORAGE_KEYS.stagedCveAiReviews,
      storage: persistedJsonStorage<CveAiReviewQueueState>(),
      partialize: (state) => ({ items: state.items }) as CveAiReviewQueueState,
    },
  ),
);

type ModePrefs = {
  search: Record<string, string>;
  severity: Record<string, string>;
  statusChange: Record<string, string>;
};

type ModePrefField = keyof ModePrefs;

type CveAiWorkListPrefsState = ModePrefs & {
  setModePref: (field: ModePrefField, mode: string, value: string) => void;
  setSearch: (mode: string, value: string) => void;
  setSeverity: (mode: string, value: string) => void;
  setStatusChange: (mode: string, value: string) => void;
};

function modePrefPatch(
  state: ModePrefs,
  field: ModePrefField,
  mode: string,
  value: string,
): Pick<ModePrefs, ModePrefField> {
  return { [field]: { ...state[field], [mode]: value } } as Pick<ModePrefs, ModePrefField>;
}

export const useCveAiWorkListPrefsStore = create<CveAiWorkListPrefsState>()(
  persist(
    (set) => ({
      search: {},
      severity: {},
      statusChange: {},
      setModePref: (field, mode, value) =>
        set((state) => modePrefPatch(state, field, mode, value)),
      setSearch: (mode, value) =>
        set((state) => modePrefPatch(state, "search", mode, value)),
      setSeverity: (mode, value) =>
        set((state) => modePrefPatch(state, "severity", mode, value)),
      setStatusChange: (mode, value) =>
        set((state) => modePrefPatch(state, "statusChange", mode, value)),
    }),
    {
      name: STORAGE_KEYS.cveAiWorkListPrefs,
      storage: persistedJsonStorage<CveAiWorkListPrefsState>(),
      partialize: (state) => ({
        search: state.search,
        severity: state.severity,
        statusChange: state.statusChange,
      }) as CveAiWorkListPrefsState,
    },
  ),
);
