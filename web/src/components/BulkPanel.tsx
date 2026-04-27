import type { Edit, PackageEntry } from "../data/types";
import { Btn, PurlChip, StatusPill, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  selectedPackages: PackageEntry[];
  edits: Record<string, Edit>;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
  onApproveAll: () => void;
  onMarkUnmappedAll: () => void;
  onResetSelected: () => void;
  onClearSelection: () => void;
};

export function BulkPanel({
  theme,
  selectedPackages,
  edits,
  isLoggedIn,
  onRequestLogin,
  onApproveAll,
  onMarkUnmappedAll,
  onResetSelected,
  onClearSelection,
}: Props) {
  const t = theme.t;
  const n = selectedPackages.length;

  const editedInSelection = selectedPackages.filter((p) => edits[p.name]);
  const approveable = selectedPackages.filter(
    (p) => p.purl !== null && !edits[p.name]?.unmapped,
  );
  const unmappable = selectedPackages.filter((p) => p.purl === null);

  const requireLogin = (fn: () => void) => () => {
    if (!isLoggedIn) {
      onRequestLogin();
      return;
    }
    fn();
  };

  return (
    <div
      style={{
        flex: 1,
        overflowY: "auto",
        background: t.page,
        display: "flex",
        flexDirection: "column",
      }}
    >
      <div
        style={{
          padding: "14px 24px",
          background: t.surface,
          borderBottom: `1px solid ${t.border}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 16,
        }}
      >
        <div>
          <h1
            style={{
              fontFamily: "Moranga, serif",
              fontWeight: 300,
              fontSize: 26,
              margin: 0,
              lineHeight: 1.1,
              color: t.fg1,
            }}
          >
            {n} packages selected
          </h1>
          <div style={{ fontSize: 12, color: t.fg2, marginTop: 4 }}>
            Run the same action across all of them.
          </div>
        </div>
        <Btn
          theme={theme}
          variant="ghost"
          size="sm"
          icon="close"
          onClick={onClearSelection}
        >
          Clear
        </Btn>
      </div>

      <div style={{ maxWidth: 880, margin: "0 auto", padding: "24px 24px 60px", width: "100%" }}>
        <div
          style={{
            display: "grid",
            gap: 12,
            gridTemplateColumns: "repeat(3, 1fr)",
            marginBottom: 24,
          }}
        >
          <Stat
            theme={theme}
            label="Approve as-is"
            count={approveable.length}
            hint="Set primary + alts to the auto-suggested PURLs."
          />
          <Stat
            theme={theme}
            label="Already edited"
            count={editedInSelection.length}
            hint="In the staged-changes drawer."
          />
          <Stat
            theme={theme}
            label="No auto match"
            count={unmappable.length}
            hint="Will be marked unmapped if you bulk-mark below."
          />
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            marginBottom: 24,
          }}
        >
          <Btn
            theme={theme}
            variant="primary"
            icon="check"
            disabled={approveable.length === 0}
            onClick={requireLogin(onApproveAll)}
            style={{ width: "100%", justifyContent: "center" }}
          >
            Approve {approveable.length} mapping{approveable.length === 1 ? "" : "s"}
          </Btn>
          <Btn
            theme={theme}
            variant="ghost"
            icon="alert"
            onClick={requireLogin(onMarkUnmappedAll)}
            style={{ width: "100%", justifyContent: "center" }}
          >
            Mark all {n} as no-PURL (unmapped)
          </Btn>
          {editedInSelection.length > 0 && (
            <Btn
              theme={theme}
              variant="ghost"
              icon="undo"
              onClick={onResetSelected}
              style={{ width: "100%", justifyContent: "center" }}
            >
              Reset {editedInSelection.length} staged edit
              {editedInSelection.length === 1 ? "" : "s"}
            </Btn>
          )}
        </div>

        <div
          style={{
            fontSize: 11,
            fontWeight: 600,
            color: t.fg2,
            letterSpacing: ".04em",
            textTransform: "uppercase",
            marginBottom: 8,
          }}
        >
          Selection
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          {selectedPackages.slice(0, 200).map((p) => {
            const e = edits[p.name];
            const purl = e?.purl ?? p.purl;
            const status = e
              ? "edited"
              : p.status === "unmapped" || p.purl === null
                ? "unmapped"
                : p.status;
            return (
              <div
                key={p.name}
                style={{
                  display: "grid",
                  gridTemplateColumns: "minmax(160px, 1fr) minmax(220px, 2fr) auto",
                  gap: 10,
                  alignItems: "center",
                  padding: "6px 10px",
                  background: t.surface,
                  border: `1px solid ${t.border}`,
                  borderRadius: 8,
                }}
              >
                <code
                  style={{
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 12.5,
                    fontWeight: 600,
                    color: t.fg1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                >
                  {p.name}
                  <span
                    style={{
                      fontWeight: 400,
                      color: t.fg3,
                      marginLeft: 8,
                      fontSize: 11,
                    }}
                  >
                    {p.version}
                  </span>
                </code>
                <span style={{ minWidth: 0 }}>
                  <PurlChip purl={purl} theme={theme} edited={!!e} />
                </span>
                <StatusPill
                  status={status as "verified" | "auto-unverified" | "unmapped" | "edited"}
                  theme={theme}
                />
              </div>
            );
          })}
          {selectedPackages.length > 200 && (
            <div
              style={{
                fontSize: 12,
                color: t.fg3,
                fontStyle: "italic",
                padding: "6px 0",
              }}
            >
              … {selectedPackages.length - 200} more not shown.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Stat({
  theme,
  label,
  count,
  hint,
}: {
  theme: Theme;
  label: string;
  count: number;
  hint: string;
}) {
  const t = theme.t;
  return (
    <div
      style={{
        background: t.surface,
        border: `1px solid ${t.border}`,
        borderRadius: 12,
        padding: 14,
      }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          letterSpacing: ".05em",
          textTransform: "uppercase",
          color: t.fg2,
          marginBottom: 6,
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontFamily: "Moranga, serif",
          fontWeight: 300,
          fontSize: 32,
          color: t.fg1,
          lineHeight: 1,
          marginBottom: 6,
          fontVariantNumeric: "tabular-nums",
        }}
      >
        {count.toLocaleString()}
      </div>
      <div style={{ fontSize: 11.5, color: t.fg2, lineHeight: 1.5 }}>
        {hint}
      </div>
    </div>
  );
}
