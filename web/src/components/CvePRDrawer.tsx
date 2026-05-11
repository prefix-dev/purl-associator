import { useState } from "react";
import { repoFullName } from "../config";
import { submitCveReviewsAsPR } from "../github/cve_api";
import type { CvePackage, ReviewEdit } from "../data/cves";
import type { GitHubUser } from "../data/types";
import { Avatar, Btn, Glyph, Theme } from "./Primitives";

type Props = {
  theme: Theme;
  edits: Record<string, ReviewEdit>;
  packages: Record<string, CvePackage>;
  onClose: () => void;
  onCommit: () => void;
  onSelect: (pkg: string, advisoryId: string) => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
  user: GitHubUser | null;
  token: string | null;
};

type Committed = {
  number: number;
  url: string;
  branch: string;
  file: string;
};

const STATUS_LABELS: Record<string, string> = {
  confirmed: "confirmed",
  rejected: "rejected",
  "not-applicable": "not applicable",
  "needs-review": "needs review",
};

export function CvePRDrawer({
  theme,
  edits,
  packages,
  onClose,
  onCommit,
  onSelect,
  isLoggedIn,
  onRequestLogin,
  user,
  token,
}: Props) {
  const t = theme.t;
  const editEntries = Object.entries(edits);
  const editsCount = editEntries.length;

  const [title, setTitle] = useState("Review conda-forge CVE assignments");
  const [body, setBody] = useState("");
  const [committing, setCommitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [committed, setCommitted] = useState<Committed | null>(null);

  function generateBody(): string {
    // Group edits by package for a readable PR body.
    const byPkg = new Map<string, [string, ReviewEdit][]>();
    for (const [key, edit] of editEntries) {
      const sep = key.indexOf("::");
      const pkg = key.slice(0, sep);
      const advisoryId = key.slice(sep + 2);
      if (!byPkg.has(pkg)) byPkg.set(pkg, []);
      byPkg.get(pkg)!.push([advisoryId, edit]);
    }
    const lines = ["This PR reviews CVE assignments for the following packages:", ""];
    for (const [pkg, items] of [...byPkg.entries()].sort()) {
      lines.push(`### ${pkg}`);
      for (const [advisoryId, edit] of items) {
        const adv = packages[pkg]?.advisories.find((a) => a.id === advisoryId);
        const label = adv?.primary_id || advisoryId;
        const status = STATUS_LABELS[edit.status] || edit.status;
        lines.push(`- **${label}**: ${status}`);
        if (edit.version_overrides.affected.length > 0) {
          lines.push(`  - +affected: ${edit.version_overrides.affected.join(", ")}`);
        }
        if (edit.version_overrides.not_affected.length > 0) {
          lines.push(
            `  - −not-affected: ${edit.version_overrides.not_affected.join(", ")}`,
          );
        }
        if (edit.note) lines.push(`  - _${edit.note}_`);
      }
      lines.push("");
    }
    return lines.join("\n");
  }

  async function handleCommit(): Promise<void> {
    if (!isLoggedIn || !token || !user) {
      onRequestLogin();
      return;
    }
    setCommitting(true);
    setError(null);
    try {
      const result = await submitCveReviewsAsPR({
        token,
        edits,
        title,
        body: body.trim() === "" ? generateBody() : body,
      });
      setCommitted({
        number: result.number,
        url: result.html_url,
        branch: result.branch,
        file: result.file,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCommitting(false);
    }
  }

  function handleClose(): void {
    if (committed) onCommit();
    onClose();
  }

  return (
    <>
      <div
        onClick={handleClose}
        style={{
          position: "fixed",
          inset: 0,
          background: "rgba(0,15,36,0.32)",
          zIndex: 50,
          animation: "fadeIn 200ms ease-out",
        }}
      />
      <div
        style={{
          position: "fixed",
          top: 0,
          right: 0,
          bottom: 0,
          width: 560,
          maxWidth: "100vw",
          background: t.surface,
          borderLeft: `1px solid ${t.border}`,
          zIndex: 51,
          display: "flex",
          flexDirection: "column",
          boxShadow: "-12px 0 40px rgba(0,15,36,0.12)",
          animation: "slideIn 280ms cubic-bezier(.2,.8,.2,1)",
        }}
      >
        <div
          style={{
            padding: "16px 20px",
            borderBottom: `1px solid ${t.border}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            background: t.surface,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Glyph name="pr" size={16} />
            <div>
              <div style={{ fontSize: 14, fontWeight: 600, color: t.fg1 }}>
                Staged reviews
              </div>
              <div
                style={{
                  fontSize: 11,
                  color: t.fg2,
                  fontFamily: "JetBrains Mono, monospace",
                }}
              >
                {repoFullName}
              </div>
            </div>
          </div>
          <button onClick={handleClose} style={iconBtn(theme)}>
            <Glyph name="close" size={14} />
          </button>
        </div>

        {committed ? (
          <CommittedView theme={theme} committed={committed} onClose={handleClose} />
        ) : (
          <>
            <div style={{ flex: 1, overflowY: "auto", padding: "12px 20px" }}>
              {editEntries.length === 0 ? (
                <div
                  style={{
                    padding: 30,
                    textAlign: "center",
                    color: t.fg3,
                    fontSize: 13,
                  }}
                >
                  No reviews yet. Mark an advisory below to stage a change.
                </div>
              ) : (
                <div
                  style={{
                    display: "flex",
                    flexDirection: "column",
                    gap: 10,
                  }}
                >
                  <div
                    style={{
                      fontSize: 11,
                      color: t.fg2,
                      fontWeight: 600,
                      letterSpacing: ".04em",
                      textTransform: "uppercase",
                      marginBottom: 2,
                    }}
                  >
                    {editsCount} review{editsCount === 1 ? "" : "s"}
                  </div>
                  {editEntries.map(([key, e]) => {
                    const sep = key.indexOf("::");
                    const pkg = key.slice(0, sep);
                    const advisoryId = key.slice(sep + 2);
                    const adv = packages[pkg]?.advisories.find(
                      (a) => a.id === advisoryId,
                    );
                    return (
                      <div
                        key={key}
                        onClick={() => onSelect(pkg, advisoryId)}
                        style={{
                          background: t.surface2,
                          border: `1px solid ${t.border}`,
                          borderRadius: 10,
                          padding: "10px 12px",
                          cursor: "pointer",
                        }}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            gap: 8,
                            marginBottom: 4,
                            flexWrap: "wrap",
                          }}
                        >
                          <code
                            style={{
                              fontSize: 12.5,
                              fontWeight: 600,
                              color: t.fg1,
                              fontFamily: "JetBrains Mono, monospace",
                            }}
                          >
                            {pkg}
                          </code>
                          <span style={{ fontSize: 11, color: t.fg3 }}>·</span>
                          <code
                            style={{
                              fontSize: 11,
                              fontWeight: 600,
                              color: t.link,
                              fontFamily: "JetBrains Mono, monospace",
                            }}
                          >
                            {adv?.primary_id || advisoryId}
                          </code>
                          <span style={{ flex: 1 }} />
                          <span
                            style={{
                              fontSize: 10.5,
                              fontWeight: 700,
                              padding: "2px 6px",
                              borderRadius: 3,
                              background: theme.dark ? "#1a2233" : "#e3ecff",
                              color: theme.dark ? "#9aaaff" : "#3957ff",
                              textTransform: "uppercase",
                              letterSpacing: ".02em",
                            }}
                          >
                            {STATUS_LABELS[e.status] || e.status}
                          </span>
                        </div>
                        {adv?.summary && (
                          <div
                            style={{
                              fontSize: 11.5,
                              color: t.fg2,
                              marginBottom: 4,
                            }}
                          >
                            {adv.summary}
                          </div>
                        )}
                        {(e.version_overrides.affected.length > 0 ||
                          e.version_overrides.not_affected.length > 0) && (
                          <div
                            style={{
                              fontFamily: "JetBrains Mono, monospace",
                              fontSize: 11,
                              color: t.fg2,
                            }}
                          >
                            {e.version_overrides.not_affected.map((v) => (
                              <span
                                key={`r-${v}`}
                                style={{
                                  display: "inline-block",
                                  marginRight: 4,
                                  marginTop: 3,
                                  color: theme.dark ? "#ff8e6a" : "#a8401b",
                                  background: theme.dark
                                    ? "rgba(255,142,106,.08)"
                                    : "#ffece5",
                                  padding: "1px 6px",
                                  borderRadius: 3,
                                  textDecoration: "line-through",
                                }}
                              >
                                {v}
                              </span>
                            ))}
                            {e.version_overrides.affected.map((v) => (
                              <span
                                key={`a-${v}`}
                                style={{
                                  display: "inline-block",
                                  marginRight: 4,
                                  marginTop: 3,
                                  color: theme.dark ? "#9adf6d" : "#5b9b2c",
                                  background: theme.dark
                                    ? "rgba(154,223,109,.08)"
                                    : "#ecf5dc",
                                  padding: "1px 6px",
                                  borderRadius: 3,
                                }}
                              >
                                +{v}
                              </span>
                            ))}
                          </div>
                        )}
                        {e.note && (
                          <div
                            style={{
                              fontSize: 11.5,
                              color: t.fg2,
                              marginTop: 6,
                              fontStyle: "italic",
                            }}
                          >
                            "{e.note}"
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {editEntries.length > 0 && (
              <div
                style={{
                  borderTop: `1px solid ${t.border}`,
                  padding: "14px 20px",
                  background: t.surface2,
                  display: "flex",
                  flexDirection: "column",
                  gap: 10,
                }}
              >
                <div>
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 600,
                      color: t.fg2,
                      letterSpacing: ".04em",
                      textTransform: "uppercase",
                      marginBottom: 4,
                    }}
                  >
                    PR title
                  </div>
                  <input
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    style={{
                      width: "100%",
                      background: t.surface,
                      color: t.fg1,
                      border: `1px solid ${t.border}`,
                      borderRadius: 8,
                      padding: "8px 10px",
                      fontSize: 13,
                      fontFamily: "Inter, sans-serif",
                      outline: "none",
                    }}
                  />
                </div>
                <div>
                  <div
                    style={{
                      fontSize: 11,
                      fontWeight: 600,
                      color: t.fg2,
                      letterSpacing: ".04em",
                      textTransform: "uppercase",
                      marginBottom: 4,
                      display: "flex",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>PR description</span>
                    <button
                      onClick={() => setBody(generateBody())}
                      style={{
                        background: "transparent",
                        border: 0,
                        color: t.link,
                        fontSize: 11,
                        fontWeight: 600,
                        cursor: "pointer",
                        padding: 0,
                      }}
                    >
                      auto-generate
                    </button>
                  </div>
                  <textarea
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    placeholder="(optional — auto-generated from your reviews if blank)"
                    style={{
                      width: "100%",
                      background: t.surface,
                      color: t.fg1,
                      border: `1px solid ${t.border}`,
                      borderRadius: 8,
                      padding: "8px 10px",
                      fontSize: 12.5,
                      fontFamily: "JetBrains Mono, monospace",
                      outline: "none",
                      minHeight: 80,
                      resize: "vertical",
                    }}
                  />
                </div>

                {error && (
                  <div
                    style={{
                      fontSize: 12,
                      color: t.bad,
                      background: theme.dark ? "#3a1f1f" : "#ffe5dc",
                      padding: "8px 10px",
                      borderRadius: 6,
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {error}
                  </div>
                )}

                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: 10,
                    marginTop: 4,
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 7,
                      fontSize: 11.5,
                      color: t.fg2,
                    }}
                  >
                    {isLoggedIn && user ? (
                      <>
                        <Avatar user={user} size={20} />
                        <span>
                          commits as <strong>@{user.login}</strong>
                        </span>
                      </>
                    ) : (
                      <span
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 5,
                        }}
                      >
                        <Glyph name="github" size={13} />
                        Sign in to push a PR
                      </span>
                    )}
                  </div>
                  <Btn
                    theme={theme}
                    variant="primary"
                    icon="pr"
                    disabled={committing}
                    onClick={handleCommit}
                  >
                    {committing
                      ? "Pushing branch…"
                      : isLoggedIn
                        ? `Create PR with ${editsCount} review${editsCount === 1 ? "" : "s"}`
                        : "Sign in & create PR"}
                  </Btn>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}

function CommittedView({
  theme,
  committed,
  onClose,
}: {
  theme: Theme;
  committed: Committed;
  onClose: () => void;
}) {
  const t = theme.t;
  return (
    <div
      style={{
        flex: 1,
        overflowY: "auto",
        padding: "30px 24px",
        textAlign: "center",
      }}
    >
      <div
        style={{
          width: 56,
          height: 56,
          borderRadius: "50%",
          background: t.accent,
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          marginBottom: 14,
        }}
      >
        <Glyph name="check" size={28} stroke={2} />
      </div>
      <h3
        style={{
          fontFamily: "Moranga, serif",
          fontWeight: 300,
          fontSize: 26,
          margin: "0 0 6px",
        }}
      >
        PR opened!
      </h3>
      <div style={{ fontSize: 13, color: t.fg2, marginBottom: 18 }}>
        Your reviews are pushed and waiting for merge.
      </div>
      <div
        style={{
          background: t.surface2,
          border: `1px solid ${t.border}`,
          borderRadius: 10,
          padding: 14,
          textAlign: "left",
          maxWidth: 400,
          margin: "0 auto 18px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            marginBottom: 8,
          }}
        >
          <Glyph name="pr" size={14} />
          <code style={{ fontSize: 12.5, fontWeight: 600, color: t.fg1 }}>
            #{committed.number}
          </code>
          <span style={{ fontSize: 11, color: t.fg2 }}>open</span>
        </div>
        <div
          style={{
            fontSize: 11,
            color: t.fg2,
            fontFamily: "JetBrains Mono, monospace",
            marginBottom: 4,
          }}
        >
          file
        </div>
        <div
          style={{
            fontSize: 11.5,
            fontFamily: "JetBrains Mono, monospace",
            color: t.fg1,
            wordBreak: "break-all",
          }}
        >
          {committed.file}
        </div>
      </div>
      <div style={{ display: "flex", gap: 10, justifyContent: "center" }}>
        <a
          href={committed.url}
          target="_blank"
          rel="noreferrer"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            background: "#001d38",
            color: t.accent,
            textDecoration: "none",
            padding: "8px 14px",
            borderRadius: 8,
            fontSize: 13,
            fontWeight: 600,
          }}
        >
          <Glyph name="github" size={14} />
          View on GitHub
        </a>
        <Btn theme={theme} variant="ghost" onClick={onClose}>
          Done
        </Btn>
      </div>
    </div>
  );
}

function iconBtn(theme: Theme) {
  const t = theme.t;
  return {
    background: t.surface2,
    border: `1px solid ${t.border}`,
    color: t.fg1,
    borderRadius: 6,
    width: 28,
    height: 28,
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    cursor: "pointer",
  } as const;
}
