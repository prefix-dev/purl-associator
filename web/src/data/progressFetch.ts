import { useLoadingStore } from "../stores/loading";

export type ProgressFetchOptions = RequestInit & {
  label?: string;
};

function taskId(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `load-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function labelFromPath(path: string): string {
  const clean = path.split("?")[0].split("#")[0];
  return clean.split("/").filter(Boolean).at(-1) || clean || "data";
}

function contentLength(res: Response): number | undefined {
  const header = res.headers.get("content-length");
  if (!header) return undefined;
  const value = Number(header);
  return Number.isFinite(value) && value >= 0 ? value : undefined;
}

async function nextPaint(): Promise<void> {
  if (typeof requestAnimationFrame === "function") {
    // Let subscribers render the parsing phase, then allow the browser a frame to
    // paint it before the synchronous JSON.parse can monopolize the main thread.
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
  // Keep the parsing phase visible long enough to be perceptible and testable.
  await new Promise<void>((resolve) => setTimeout(resolve, 80));
}

async function responseTextWithProgress(
  res: Response,
  id: string,
  totalBytes: number | undefined,
): Promise<string> {
  if (!res.body) {
    const text = await res.text();
    useLoadingStore.getState().updateTask(id, {
      loadedBytes: totalBytes ?? text.length,
      totalBytes: totalBytes ?? text.length,
    });
    return text;
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let loadedBytes = 0;
  let text = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    loadedBytes += value.byteLength;
    text += decoder.decode(value, { stream: true });
    useLoadingStore.getState().updateTask(id, { loadedBytes, totalBytes });
  }
  text += decoder.decode();
  useLoadingStore.getState().updateTask(id, { loadedBytes, totalBytes });
  return text;
}

export async function fetchJsonWithProgress<T>(
  path: string,
  options: ProgressFetchOptions = {},
): Promise<T> {
  const { label = labelFromPath(path), ...fetchOptions } = options;
  const id = taskId();
  const store = useLoadingStore.getState();

  store.startTask({
    id,
    label,
    phase: "downloading",
    loadedBytes: 0,
  });

  try {
    const res = await fetch(path, fetchOptions);
    if (!res.ok) {
      throw new Error(`Failed to load ${path}: ${res.status} ${res.statusText}`);
    }

    const totalBytes = contentLength(res);
    store.updateTask(id, { totalBytes });
    const text = await responseTextWithProgress(res, id, totalBytes);

    store.updateTask(id, {
      phase: "parsing",
      loadedBytes: totalBytes ?? new TextEncoder().encode(text).byteLength,
      totalBytes: totalBytes ?? new TextEncoder().encode(text).byteLength,
    });
    await nextPaint();

    return JSON.parse(text) as T;
  } finally {
    useLoadingStore.getState().finishTask(id);
  }
}
