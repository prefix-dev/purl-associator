import { CSSProperties, ReactNode, useMemo, useState } from "react";
import { ECOSYSTEMS } from "../data/loader";

export type ThemeShape = {
  page: string;
  surface: string;
  surface2: string;
  inset: string;
  fg1: string;
  fg2: string;
  fg3: string;
  border: string;
  borderStrong: string;
  accent: string;
  accentFg: string;
  link: string;
  rowHover: string;
  rowSelected: string;
  good: string;
  bad: string;
  warn: string;
};

export type Theme = {
  dark: boolean;
  setDark: (v: boolean) => void;
  t: ThemeShape;
};

export function useTheme(): Theme {
  const [dark, setDark] = useState(false);
  const t = useMemo<ThemeShape>(
    () =>
      dark
        ? {
            page: "#0e1217",
            surface: "#151a21",
            surface2: "#1b2028",
            inset: "#0a0d11",
            fg1: "#f1ede4",
            fg2: "#9aa0a8",
            fg3: "#62656a",
            border: "#232830",
            borderStrong: "#2d333c",
            accent: "#ffd432",
            accentFg: "#001d38",
            link: "#9aaaff",
            rowHover: "#1b2028",
            rowSelected: "#1f2631",
            good: "#70c038",
            bad: "#ff6b38",
            warn: "#f7b500",
          }
        : {
            page: "#f8f6f2",
            surface: "#ffffff",
            surface2: "#fbf9f5",
            inset: "#f1ede4",
            fg1: "#001d38",
            fg2: "#62656a",
            fg3: "#8b8e93",
            border: "#ece8df",
            borderStrong: "#d9d4c7",
            accent: "#ffd432",
            accentFg: "#001d38",
            link: "#3957ff",
            rowHover: "#fbf9f5",
            rowSelected: "#fff7d1",
            good: "#5b9b2c",
            bad: "#d94e1f",
            warn: "#b07d00",
          },
    [dark],
  );
  return { dark, setDark, t };
}

const PATHS: Record<string, ReactNode> = {
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.3-4.3" />
    </>
  ),
  close: <path d="M6 6l12 12M18 6L6 18" />,
  chev: <path d="M6 9l6 6 6-6" />,
  plus: <path d="M12 5v14M5 12h14" />,
  check: <path d="M4 12l5 5L20 6" />,
  edit: <path d="M3 21l4-1 12-12-3-3L4 17l-1 4z" />,
  link: (
    <>
      <path d="M10 14a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1" />
      <path d="M14 10a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1" />
    </>
  ),
  alert: (
    <>
      <path d="M12 2L2 21h20L12 2z" />
      <path d="M12 9v5M12 18v.01" />
    </>
  ),
  sparkle: <path d="M12 3l2 5 5 2-5 2-2 5-2-5-5-2 5-2z" />,
  branch: (
    <>
      <circle cx="6" cy="6" r="2" />
      <circle cx="6" cy="18" r="2" />
      <circle cx="18" cy="8" r="2" />
      <path d="M6 8v8M18 10v2a4 4 0 0 1-4 4H6" />
    </>
  ),
  pr: (
    <>
      <circle cx="6" cy="6" r="2" />
      <circle cx="6" cy="18" r="2" />
      <circle cx="18" cy="18" r="2" />
      <path d="M6 8v8M18 6v10M14 6h4" />
    </>
  ),
  undo: (
    <>
      <path d="M9 14L4 9l5-5" />
      <path d="M4 9h11a5 5 0 0 1 0 10h-3" />
    </>
  ),
  eye: (
    <>
      <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
      <circle cx="12" cy="12" r="3" />
    </>
  ),
  github: (
    <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.69c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.46-1.11-1.46-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.53 2.34 1.09 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.69-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2z" />
  ),
  info: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 8v.01M12 11v5" />
    </>
  ),
  db: (
    <>
      <ellipse cx="12" cy="5" rx="9" ry="3" />
      <path d="M3 5v6c0 1.66 4 3 9 3s9-1.34 9-3V5M3 11v6c0 1.66 4 3 9 3s9-1.34 9-3v-6" />
    </>
  ),
  refresh: (
    <>
      <path d="M21 12a9 9 0 1 1-3-6.7" />
      <path d="M21 4v5h-5" />
    </>
  ),
};

export function Glyph({
  name,
  size = 14,
  stroke = 1.6,
}: {
  name: keyof typeof PATHS | string;
  size?: number;
  stroke?: number;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={stroke}
      strokeLinecap="round"
      strokeLinejoin="round"
      style={{ flexShrink: 0 }}
    >
      {PATHS[name] ?? null}
    </svg>
  );
}

export function StatusPill({
  status,
  theme,
}: {
  status: "verified" | "auto-unverified" | "unmapped" | "edited";
  theme: Theme;
}) {
  const map = {
    verified: {
      label: "Verified",
      bg: theme.dark ? "#1a2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    "auto-unverified": {
      label: "Unverified",
      bg: theme.dark ? "#2a2616" : "#fff4d2",
      fg: theme.dark ? "#f5c542" : "#866400",
    },
    unmapped: {
      label: "Unmapped",
      bg: theme.dark ? "#2a1818" : "#ffe1d8",
      fg: theme.dark ? "#ff8e6a" : "#a8401b",
    },
    edited: {
      label: "Edited",
      bg: theme.dark ? "#1a2233" : "#e3ecff",
      fg: theme.dark ? "#9aaaff" : "#3957ff",
    },
  } as const;
  const m = map[status] ?? map["auto-unverified"];
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontSize: 10.5,
        fontWeight: 600,
        padding: "2px 7px",
        borderRadius: 4,
        background: m.bg,
        color: m.fg,
        letterSpacing: "0.02em",
        textTransform: "uppercase",
        fontFamily: "Inter, sans-serif",
      }}
    >
      <span
        style={{ width: 5, height: 5, borderRadius: "50%", background: m.fg }}
      />
      {m.label}
    </span>
  );
}

export function EcosystemChip({ id, theme }: { id: string | null; theme: Theme }) {
  const e =
    ECOSYSTEMS.find((x) => x.id === id) ??
    ECOSYSTEMS.find((x) => x.id === "none")!;
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontSize: 10.5,
        fontWeight: 600,
        padding: "2px 6px",
        borderRadius: 4,
        background: theme.dark ? "#1f2631" : "#f3efe6",
        color: theme.dark ? "#dcdfe4" : "#3a3d44",
        fontFamily: "JetBrains Mono, monospace",
        border: `1px solid ${theme.t.border}`,
      }}
    >
      <span
        style={{ width: 6, height: 6, borderRadius: 1, background: e.color }}
      />
      {e.label}
    </span>
  );
}

export function ConfidenceBar({
  score,
  theme,
  width = 60,
}: {
  score: number;
  theme: Theme;
  width?: number;
}) {
  const pct = Math.round((score || 0) * 100);
  const color =
    score >= 0.85 ? theme.t.good : score >= 0.65 ? theme.t.warn : theme.t.bad;
  return (
    <div
      title={`${pct}% confidence`}
      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
    >
      <div
        style={{
          width,
          height: 4,
          background: theme.dark ? "#1b2028" : "#ece8df",
          borderRadius: 2,
          overflow: "hidden",
        }}
      >
        <div
          style={{ width: `${pct}%`, height: "100%", background: color }}
        />
      </div>
      <span
        style={{
          fontSize: 10.5,
          color: theme.t.fg2,
          fontVariantNumeric: "tabular-nums",
          fontWeight: 600,
          minWidth: 22,
        }}
      >
        {pct}
      </span>
    </div>
  );
}

export function PurlChip({
  purl,
  theme,
  edited = false,
  size = "md",
}: {
  purl: string | null;
  theme: Theme;
  edited?: boolean;
  size?: "md" | "lg";
}) {
  if (!purl)
    return (
      <span style={{ color: theme.t.fg3, fontSize: 12, fontStyle: "italic" }}>
        — no purl —
      </span>
    );
  const m = purl.match(/^(pkg:)([^/]+)\/(.+)$/);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        fontFamily: "JetBrains Mono, monospace",
        fontSize: size === "lg" ? 14 : 12,
        padding: size === "lg" ? "6px 10px" : "3px 7px",
        borderRadius: 6,
        background: edited
          ? theme.dark
            ? "#1a2233"
            : "#e9efff"
          : theme.dark
            ? "#0a0d11"
            : "#f5f1e7",
        border: `1px solid ${
          edited ? (theme.dark ? "#2a3a55" : "#c2d0fb") : theme.t.border
        }`,
        color: theme.t.fg1,
        letterSpacing: "-0.01em",
        whiteSpace: "nowrap",
      }}
    >
      {m ? (
        <>
          <span style={{ color: theme.t.fg3 }}>{m[1]}</span>
          <span
            style={{
              color: edited ? (theme.dark ? "#9aaaff" : "#3957ff") : theme.t.fg1,
              fontWeight: 600,
            }}
          >
            {m[2]}
          </span>
          <span style={{ color: theme.t.fg3 }}>/</span>
          <span style={{ color: theme.t.fg1 }}>{m[3]}</span>
        </>
      ) : (
        <span>{purl}</span>
      )}
    </span>
  );
}

export function Avatar({
  user,
  size = 22,
}: {
  user: { name?: string | null; login: string; avatar_url?: string; color?: string; initial?: string } | null;
  size?: number;
}) {
  if (!user) return null;
  if (user.avatar_url) {
    return (
      <img
        src={user.avatar_url}
        alt={user.name ?? user.login}
        title={user.name ?? user.login}
        width={size}
        height={size}
        style={{ borderRadius: "50%", flexShrink: 0 }}
      />
    );
  }
  return (
    <span
      title={user.name ?? user.login}
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        background: user.color ?? "#ffd432",
        color: "#001d38",
        fontFamily: "Moranga, serif",
        fontWeight: 400,
        fontSize: size * 0.5,
        flexShrink: 0,
      }}
    >
      {user.initial ?? user.login.charAt(0).toUpperCase()}
    </span>
  );
}

export function SourceTag({ source, theme }: { source: string; theme: Theme }) {
  const colors: Record<string, { bg: string; fg: string }> = {
    aboutcode: {
      bg: theme.dark ? "#1d2440" : "#e8eaff",
      fg: theme.dark ? "#a8b3ff" : "#3957ff",
    },
    "osv.dev": {
      bg: theme.dark ? "#3a1f1f" : "#ffe5dc",
      fg: theme.dark ? "#ff8e6a" : "#a8401b",
    },
    "recipe-source": {
      bg: theme.dark ? "#1f2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    "recipe-deps": {
      bg: theme.dark ? "#1f2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    "recipe-source+recipe-deps": {
      bg: theme.dark ? "#1f2a18" : "#eef7e3",
      fg: theme.dark ? "#9adf6d" : "#5b9b2c",
    },
    "github-mirror": {
      bg: theme.dark ? "#252525" : "#eeeae0",
      fg: theme.dark ? "#bbb" : "#444",
    },
  };
  const c = colors[source] ?? { bg: theme.t.inset, fg: theme.t.fg2 };
  return (
    <span
      style={{
        fontSize: 10,
        fontWeight: 600,
        padding: "1.5px 6px",
        borderRadius: 3,
        background: c.bg,
        color: c.fg,
        fontFamily: "Inter",
        letterSpacing: "0.02em",
      }}
    >
      {source}
    </span>
  );
}

type BtnProps = {
  children: ReactNode;
  onClick?: () => void;
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md" | "lg";
  disabled?: boolean;
  theme: Theme;
  style?: CSSProperties;
  title?: string;
  icon?: string;
};

export function Btn({
  children,
  onClick,
  variant = "primary",
  size = "md",
  disabled,
  theme,
  style,
  title,
  icon,
}: BtnProps) {
  const t = theme.t;
  let bg: string;
  let color: string;
  let border: string;
  switch (variant) {
    case "primary":
      bg = t.accent;
      color = t.accentFg;
      border = "transparent";
      break;
    case "secondary":
      if (theme.dark) {
        bg = t.surface2;
        color = t.fg1;
        border = t.borderStrong;
      } else {
        bg = "#001d38";
        color = t.accent;
        border = "transparent";
      }
      break;
    case "ghost":
      bg = "transparent";
      color = t.fg1;
      border = t.border;
      break;
    case "danger":
      bg = t.bad;
      color = "#fff";
      border = "transparent";
      break;
  }
  const sz =
    size === "sm"
      ? { px: 10, py: 5, fs: 12 }
      : size === "lg"
        ? { px: 16, py: 9, fs: 14 }
        : { px: 12, py: 7, fs: 13 };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        background: bg,
        color,
        border: `1.5px solid ${border}`,
        borderRadius: 8,
        padding: `${sz.py}px ${sz.px}px`,
        fontFamily: "Inter, sans-serif",
        fontSize: sz.fs,
        fontWeight: 600,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.5 : 1,
        transition: "background 200ms, border-color 200ms, transform 100ms",
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {icon && <Glyph name={icon} size={14} />}
      {children}
    </button>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  theme,
  mono,
  style,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  theme: Theme;
  mono?: boolean;
  style?: CSSProperties;
}) {
  const t = theme.t;
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      style={{
        background: t.surface,
        color: t.fg1,
        border: `1px solid ${t.border}`,
        borderRadius: 8,
        padding: "8px 10px",
        fontSize: 13,
        width: "100%",
        fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
        outline: "none",
        ...style,
      }}
    />
  );
}

export function Seg<T extends string>({
  options,
  value,
  onChange,
  theme,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  theme: Theme;
}) {
  const t = theme.t;
  return (
    <div
      style={{
        display: "inline-flex",
        background: t.surface2,
        border: `1px solid ${t.border}`,
        borderRadius: 8,
        padding: 2,
      }}
    >
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          style={{
            background: value === o.value ? t.surface : "transparent",
            color: value === o.value ? t.fg1 : t.fg2,
            border: 0,
            borderRadius: 6,
            padding: "5px 10px",
            fontSize: 12,
            fontWeight: value === o.value ? 600 : 500,
            cursor: "pointer",
            boxShadow:
              value === o.value ? "0 1px 2px rgba(0,0,0,.06)" : "none",
            fontFamily: "Inter, sans-serif",
          }}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
