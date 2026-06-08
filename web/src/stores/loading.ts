import { create } from "zustand";

export type LoadingPhase = "downloading" | "parsing";

export type LoadingTask = {
  id: string;
  label: string;
  phase: LoadingPhase;
  loadedBytes: number;
  totalBytes?: number;
  startedAt: number;
};

type LoadingState = {
  tasks: Record<string, LoadingTask>;
  startTask: (task: Omit<LoadingTask, "startedAt">) => void;
  updateTask: (
    id: string,
    patch: Partial<Omit<LoadingTask, "id" | "startedAt">>,
  ) => void;
  finishTask: (id: string) => void;
};

export const useLoadingStore = create<LoadingState>()((set) => ({
  tasks: {},
  startTask: (task) =>
    set((state) => ({
      tasks: {
        ...state.tasks,
        [task.id]: { ...task, startedAt: Date.now() },
      },
    })),
  updateTask: (id, patch) =>
    set((state) => {
      const current = state.tasks[id];
      if (!current) return state;
      return {
        tasks: {
          ...state.tasks,
          [id]: { ...current, ...patch },
        },
      };
    }),
  finishTask: (id) =>
    set((state) => {
      if (!state.tasks[id]) return state;
      const { [id]: _finished, ...tasks } = state.tasks;
      return { tasks };
    }),
}));

export type LoadingSummary = {
  activeCount: number;
  label: string;
  phase: LoadingPhase;
  loadedBytes: number;
  totalBytes?: number;
  percent?: number;
  allTotalsKnown: boolean;
};

export function summarizeLoadingTasks(
  tasksById: Record<string, LoadingTask>,
): LoadingSummary | null {
  const tasks = Object.values(tasksById).sort((a, b) => a.startedAt - b.startedAt);
  if (tasks.length === 0) return null;

  const loadedBytes = tasks.reduce((sum, task) => sum + task.loadedBytes, 0);
  const knownTotals = tasks.filter((task) => typeof task.totalBytes === "number");
  const allTotalsKnown = knownTotals.length === tasks.length;
  const totalBytes = allTotalsKnown
    ? tasks.reduce((sum, task) => sum + (task.totalBytes ?? 0), 0)
    : undefined;
  const percent =
    totalBytes && totalBytes > 0
      ? Math.min(100, Math.max(0, (loadedBytes / totalBytes) * 100))
      : undefined;
  const anyParsing = tasks.some((task) => task.phase === "parsing");

  return {
    activeCount: tasks.length,
    label: tasks.length === 1 ? tasks[0].label : `${tasks.length} files`,
    phase: anyParsing ? "parsing" : "downloading",
    loadedBytes,
    totalBytes,
    percent,
    allTotalsKnown,
  };
}
