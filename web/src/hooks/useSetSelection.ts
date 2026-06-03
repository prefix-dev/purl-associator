import { useState } from "react";

export function useSetSelection<T>(keyFor: (item: T) => string) {
  const [selected, setSelected] = useState<Set<string>>(new Set());

  function toggleSelected(key: string): void {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function selectItems(items: T[]): void {
    setSelected((prev) => {
      const next = new Set(prev);
      for (const item of items) next.add(keyFor(item));
      return next;
    });
  }

  function clearSelection(): void {
    setSelected(new Set());
  }

  return { selected, toggleSelected, selectItems, clearSelection };
}
