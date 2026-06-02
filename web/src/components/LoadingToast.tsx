import { useMemo } from "react";
import { summarizeLoadingTasks, useLoadingStore } from "../stores/loading";
import type { Theme } from "./Primitives";

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = units[0];
  for (let i = 1; i < units.length && value >= 1024; i += 1) {
    value /= 1024;
    unit = units[i];
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${unit}`;
}

export function LoadingToast({ theme }: { theme: Theme }) {
  const tasks = useLoadingStore((state) => state.tasks);
  const summary = useMemo(() => summarizeLoadingTasks(tasks), [tasks]);
  if (!summary) return null;

  const t = theme.t;
  const isParsing = summary.phase === "parsing";
  const hasPercent = typeof summary.percent === "number";
  const percent = Math.round(summary.percent ?? 0);
  const title = isParsing
    ? summary.activeCount === 1
      ? `Parsing ${summary.label}…`
      : `Parsing data…`
    : summary.activeCount === 1
      ? `Loading ${summary.label}`
      : `Loading ${summary.label}`;
  const detail = hasPercent
    ? `${percent}%${summary.totalBytes ? ` · ${formatBytes(summary.loadedBytes)} / ${formatBytes(summary.totalBytes)}` : ""}`
    : `${formatBytes(summary.loadedBytes)} loaded`;

  return (
    <div
      role="status"
      aria-live="polite"
      style={{
        position: "fixed",
        right: 18,
        bottom: 18,
        zIndex: 1000,
        width: "min(380px, calc(100vw - 36px))",
        padding: 14,
        borderRadius: 12,
        border: `1px solid ${t.borderStrong}`,
        background: theme.dark ? "rgba(21, 26, 33, 0.96)" : "rgba(255, 255, 255, 0.96)",
        boxShadow: theme.dark
          ? "0 18px 40px rgba(0, 0, 0, 0.45)"
          : "0 18px 40px rgba(0, 29, 56, 0.16)",
        color: t.fg1,
        backdropFilter: "blur(10px)",
      }}
    >
      <style>{`
        @keyframes purl-loading-toast-slide {
          0% { transform: translateX(-110%); }
          100% { transform: translateX(210%); }
        }
      `}</style>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          gap: 12,
          alignItems: "baseline",
          marginBottom: 10,
        }}
      >
        <div
          style={{
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontSize: 13,
            fontWeight: 650,
          }}
        >
          {title}
        </div>
        <div
          style={{
            flexShrink: 0,
            color: t.fg2,
            fontSize: 11,
            fontFamily: "JetBrains Mono, monospace",
          }}
        >
          {detail}
        </div>
      </div>

      <div
        aria-hidden="true"
        style={{
          position: "relative",
          height: 6,
          overflow: "hidden",
          borderRadius: 999,
          background: t.inset,
          border: `1px solid ${t.border}`,
        }}
      >
        {hasPercent ? (
          <div
            style={{
              width: `${summary.percent}%`,
              height: "100%",
              borderRadius: 999,
              background: t.accent,
              transition: "width 140ms ease-out",
            }}
          />
        ) : (
          <div
            style={{
              position: "absolute",
              inset: 0,
              width: "45%",
              borderRadius: 999,
              background: t.accent,
              animation: "purl-loading-toast-slide 1.2s ease-in-out infinite",
            }}
          />
        )}
      </div>
    </div>
  );
}
