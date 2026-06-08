import { useState } from "react";
import { Btn, Glyph, Theme } from "./Primitives";
import {
  enqueueAiReviewAsPR,
  type EnqueueItem,
} from "../github/cve_enqueue_api";

type Props = {
  theme: Theme;
  items: EnqueueItem[];
  onClose: () => void;
  onRemove: (pkg: string, advisoryId: string) => void;
  onClear: () => void;
  onSubmitted: () => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
  token: string | null;
};

/** Drawer for staging "Ask AI to review" clicks and submitting them as one PR.
 *
 * Visually slim by design — the queued list is small (typically 1–10 items)
 * and the submission flow has only two states: idle / posted. The
 * full-featured PR drawer (CvePRDrawer.tsx) handles authoritative OpenVEX
 * submissions; this one only files queue items the AI workflow will pick up.
 */
export function CveEnqueueDrawer({
  theme,
  items,
  onClose,
  onRemove,
  onClear,
  onSubmitted,
  isLoggedIn,
  onRequestLogin,
  token,
}: Props) {
  const t = theme.t;
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);

  async function submit() {
    if (!isLoggedIn) {
      onRequestLogin();
      return;
    }
    if (!token) return;
    setSubmitting(true);
    setError(null);
    try {
      const res = await enqueueAiReviewAsPR({
        token,
        items,
        title: `Queue AI CVE review (${items.length} item${
          items.length === 1 ? "" : "s"
        })`,
      });
      setPrUrl(res.html_url);
      onSubmitted();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.4)",
        zIndex: 100,
        display: "flex",
        justifyContent: "flex-end",
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 440,
          maxWidth: "100%",
          background: t.surface,
          borderLeft: `1px solid ${t.border}`,
          display: "flex",
          flexDirection: "column",
          height: "100%",
        }}
      >
        <div
          style={{
            padding: "12px 16px",
            borderBottom: `1px solid ${t.border}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 16 }}>🤖</span>
            <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: t.fg1 }}>
              Ask AI to review ({items.length})
            </h2>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: 0,
              color: t.fg3,
              cursor: "pointer",
            }}
            title="Close"
          >
            <Glyph name="close" size={14} />
          </button>
        </div>

        <div style={{ padding: "12px 16px", flex: 1, overflowY: "auto" }}>
          {prUrl ? (
            <div style={{ fontSize: 13, color: t.fg1 }}>
              <p>
                ✅ Queue PR opened:{" "}
                <a href={prUrl} target="_blank" rel="noreferrer" style={{ color: t.link }}>
                  {prUrl}
                </a>
              </p>
              <p style={{ color: t.fg2, marginTop: 12 }}>
                Merge this queue PR first. After it lands on <code style={{ fontSize: 12 }}>main</code>,
                the next AI review run (twice daily, or trigger{" "}
                <code style={{ fontSize: 12 }}>cve_ai_review.yml</code> manually) will
                pick these up and open a separate draft PR.
              </p>
            </div>
          ) : items.length === 0 ? (
            <div style={{ fontSize: 13, color: t.fg3, textAlign: "center", padding: 24 }}>
              No advisories queued. Click "🤖 Ask AI" on an advisory in the detail view
              to add it here.
            </div>
          ) : (
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
              {items.map((it) => (
                <li
                  key={`${it.package}::${it.advisory_id}`}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                    padding: "8px 0",
                    borderBottom: `1px solid ${t.border}`,
                    fontSize: 12,
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        color: t.fg1,
                        fontWeight: 600,
                      }}
                    >
                      {it.package}
                    </div>
                    <div
                      style={{
                        fontFamily: "JetBrains Mono, monospace",
                        color: t.fg2,
                        fontSize: 11,
                      }}
                    >
                      {it.advisory_id}
                    </div>
                  </div>
                  <button
                    onClick={() => onRemove(it.package, it.advisory_id)}
                    style={{
                      background: "transparent",
                      border: 0,
                      color: t.fg3,
                      cursor: "pointer",
                    }}
                    title="Remove from batch"
                  >
                    <Glyph name="close" size={11} />
                  </button>
                </li>
              ))}
            </ul>
          )}

          {error && (
            <div
              style={{
                marginTop: 12,
                padding: 10,
                background: theme.dark ? "#3a1f1f" : "#ffe5dc",
                color: t.bad,
                fontSize: 12,
                borderRadius: 4,
              }}
            >
              {error}
            </div>
          )}
        </div>

        {!prUrl && items.length > 0 && (
          <div
            style={{
              padding: "12px 16px",
              borderTop: `1px solid ${t.border}`,
              display: "flex",
              gap: 8,
              justifyContent: "space-between",
            }}
          >
            <Btn theme={theme} variant="ghost" onClick={onClear} disabled={submitting}>
              Clear all
            </Btn>
            <div style={{ display: "flex", gap: 8 }}>
              <Btn theme={theme} variant="ghost" onClick={onClose}>
                Cancel
              </Btn>
              <Btn
                theme={theme}
                variant="primary"
                icon="pr"
                onClick={submit}
                disabled={submitting}
              >
                {submitting ? "Opening PR…" : "Submit batch"}
              </Btn>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
