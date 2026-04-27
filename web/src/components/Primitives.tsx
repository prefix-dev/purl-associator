import { CSSProperties, ReactNode, useMemo, useState } from "react";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Database,
  Edit3,
  Eye,
  GitBranch,
  GitPullRequest,
  Info,
  Link as LinkIcon,
  Plus,
  RefreshCw,
  Search,
  Sparkles,
  Undo2,
  X,
  type LucideIcon,
} from "lucide-react";
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

const ICONS: Record<string, LucideIcon> = {
  search: Search,
  close: X,
  chev: ChevronDown,
  plus: Plus,
  check: Check,
  edit: Edit3,
  link: LinkIcon,
  alert: AlertTriangle,
  sparkle: Sparkles,
  branch: GitBranch,
  pr: GitPullRequest,
  undo: Undo2,
  eye: Eye,
  info: Info,
  db: Database,
  refresh: RefreshCw,
};

// GitHub mark from Simple Icons (https://simpleicons.org/icons/github), MIT.
// Lucide dropped brand icons in v1, so we inline the official mark instead.
function GithubMark({ size = 14 }: { size?: number }) {
  return (
    <svg
      role="img"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      style={{ flexShrink: 0 }}
    >
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  );
}

export function Glyph({
  name,
  size = 14,
  stroke = 1.6,
}: {
  name: string;
  size?: number;
  stroke?: number;
}) {
  if (name === "github") return <GithubMark size={size} />;
  const Icon = ICONS[name];
  if (!Icon) return null;
  return <Icon size={size} strokeWidth={stroke} style={{ flexShrink: 0 }} />;
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
