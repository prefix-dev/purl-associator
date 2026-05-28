import { Btn, Glyph, type Theme } from "./Primitives";

type Props = {
  theme: Theme;
  count: number;
  noun: string;
  onReview: () => void;
  onDiscard: () => void;
};

export function LocalDraftBanner({
  theme,
  count,
  noun,
  onReview,
  onDiscard,
}: Props) {
  if (count === 0) return null;

  const t = theme.t;
  const plural = count === 1 ? noun : `${noun}s`;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        gap: 14,
        padding: "8px 18px",
        borderBottom: `1px solid ${theme.dark ? "#4a3b15" : "#e6cf8e"}`,
        background: theme.dark ? "#211a08" : "#fff7d6",
        color: theme.dark ? "#ffe9a3" : "#5f4700",
        flexShrink: 0,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
        <Glyph name="edit" size={13} />
        <span>
          You have <strong>{count}</strong> locally saved staged {plural}.
        </span>
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <Btn theme={theme} variant="ghost" icon="pr" onClick={onReview}>
          Review
        </Btn>
        <button
          onClick={onDiscard}
          style={{
            background: "transparent",
            border: `1px solid ${theme.dark ? "#5e4a18" : "#dcc277"}`,
            borderRadius: 8,
            color: t.fg1,
            fontSize: 11,
            fontWeight: 700,
            padding: "6px 10px",
            cursor: "pointer",
          }}
        >
          Discard all
        </button>
      </div>
    </div>
  );
}
