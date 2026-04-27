import { useState } from "react";
import { repoFullName } from "../config";
import { submitEditsAsPR } from "../github/api";
import type { Edit, GitHubUser, PackageEntry } from "../data/types";
import {
  Avatar,
  Btn,
  Glyph,
  StatusPill,
  Theme,
} from "./Primitives";

type Props = {
  theme: Theme;
  edits: Record<string, Edit>;
  packages: PackageEntry[];
  onClose: () => void;
  onCommit: () => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
  user: GitHubUser | null;
  onSelect: (id: string) => void;
  token: string | null;
};

type Committed = {
  number: number;
  url: string;
  branch: string;
};

export function PRDrawer({
  theme,
  edits,
  packages,
  onClose,
  onCommit,
  isLoggedIn,
  onRequestLogin,
  user,
  onSelect,
  token,
}: Props) {
  const t = theme.t;
  const editEntries = Object.entries(edits);
  const editsCount = editEntries.length;

  const [title, setTitle] = useState(
    "Update PURL mappings for conda-forge packages",
  );
  const [body, setBody] = useState("");
  const [committing, setCommitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [committed, setCommitted] = useState<Committed | null>(null);

  function generateBody(): string {
    const lines = [
      "This PR updates PURL mappings for the following conda-forge packages:",
      "",
    ];
    for (const [id, e] of editEntries) {
      const pkg = packages.find((p) => p.name === id);
      if (!pkg) continue;
      if (e.unmapped) {
        lines.push(`- **${pkg.name}**: marked as no-PURL`);
      } else {
        const purls = [e.purl, ...e.alternative_purls];
        if (purls.length === 1) {
          const before = pkg.auto?.purl ?? pkg.purl ?? "(none)";
          lines.push(`- **${pkg.name}**: \`${before}\` → \`${e.purl}\``);
        } else {
          lines.push(
            `- **${pkg.name}**: ${purls.length} PURLs — \`${e.purl}\` (primary), ${e.alternative_purls.map((p) => `\`${p}\``).join(", ")}`,
          );
        }
      }
      if (e.note) lines.push(`  - _${e.note}_`);
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
      const result = await submitEditsAsPR({
        token,
        user: { login: user.login },
        packages,
        edits,
        title,
        body: body.trim() === "" ? generateBody() : body,
      });
      setCommitted({
        number: result.pr.number,
        url: result.pr.html_url,
        branch: result.branch,
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
          width: 540,
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
                Staged changes
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
          <CommittedView
            theme={theme}
            committed={committed}
            onClose={handleClose}
          />
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
                  No edits yet. Edit a mapping on the right to stage a change.
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
                    {editsCount} change{editsCount === 1 ? "" : "s"}
                  </div>
                  {editEntries.map(([id, e]) => {
                    const pkg = packages.find((p) => p.name === id);
                    if (!pkg) return null;

                    // "Before" PURLs: whatever the package currently presents
                    // — the auto guess plus its alternatives.
                    const beforePurls: string[] = [];
                    const beforePrimary = pkg.auto?.purl ?? pkg.purl;
                    if (beforePrimary) beforePurls.push(beforePrimary);
                    for (const alt of pkg.auto?.alternative_purls ??
                      pkg.alternative_purls ??
                      []) {
                      if (alt.purl !== beforePrimary) beforePurls.push(alt.purl);
                    }

                    const afterPurls = e.unmapped
                      ? ["(unmapped)"]
                      : [e.purl, ...e.alternative_purls];

                    const beforeSet = new Set(beforePurls);
                    const afterSet = new Set(afterPurls);

                    return (
                      <div
                        key={id}
                        style={{
                          background: t.surface2,
                          border: `1px solid ${t.border}`,
                          borderRadius: 10,
                          padding: "10px 12px",
                          cursor: "pointer",
                        }}
                        onClick={() => onSelect(id)}
                      >
                        <div
                          style={{
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            marginBottom: 6,
                          }}
                        >
                          <div
                            style={{
                              display: "flex",
                              alignItems: "center",
                              gap: 8,
                            }}
                          >
                            <code
                              style={{
                                fontSize: 13,
                                fontWeight: 600,
                                color: t.fg1,
                                fontFamily: "JetBrains Mono, monospace",
                              }}
                            >
                              {pkg.name}
                            </code>
                            <span style={{ fontSize: 10.5, color: t.fg3 }}>
                              v{pkg.version}
                            </span>
                          </div>
                          <StatusPill status="edited" theme={theme} />
                        </div>
                        <div
                          style={{
                            fontFamily: "JetBrains Mono, monospace",
                            fontSize: 11.5,
                            lineHeight: 1.6,
                          }}
                        >
                          {/* Removed: PURLs that were in the auto/old set
                              but won't be in the new set. */}
                          {beforePurls
                            .filter((p) => !afterSet.has(p))
                            .map((purl, i) => (
                              <div
                                key={`b-${i}`}
                                style={{
                                  color: theme.dark ? "#ff8e6a" : "#a8401b",
                                  background: theme.dark
                                    ? "rgba(255,142,106,.08)"
                                    : "#ffece5",
                                  padding: "2px 6px",
                                  borderRadius: 3,
                                  marginBottom: 2,
                                }}
                              >
                                <span style={{ opacity: 0.7 }}>−</span> {purl}
                              </div>
                            ))}
                          {beforePurls.length === 0 && !e.unmapped && (
                            <div
                              style={{
                                color: theme.dark ? "#ff8e6a" : "#a8401b",
                                background: theme.dark
                                  ? "rgba(255,142,106,.08)"
                                  : "#ffece5",
                                padding: "2px 6px",
                                borderRadius: 3,
                                marginBottom: 2,
                                opacity: 0.7,
                                fontStyle: "italic",
                              }}
                            >
                              <span style={{ opacity: 0.7 }}>−</span> (no
                              previous mapping)
                            </div>
                          )}
                          {/* Added / kept: each PURL in the new set with a
                              role badge so it's obvious there are multiple. */}
                          {afterPurls.map((purl, idx) => {
                            const isNew = !beforeSet.has(purl);
                            const isPrimary = idx === 0 && !e.unmapped;
                            return (
                              <div
                                key={`a-${idx}`}
                                style={{
                                  display: "flex",
                                  alignItems: "center",
                                  gap: 6,
                                  color: theme.dark ? "#9adf6d" : "#5b9b2c",
                                  background: theme.dark
                                    ? "rgba(154,223,109,.08)"
                                    : "#ecf5dc",
                                  padding: "2px 6px",
                                  borderRadius: 3,
                                  marginTop: 2,
                                  opacity: isNew ? 1 : 0.7,
                                }}
                              >
                                <span style={{ opacity: 0.7 }}>+</span>
                                <span>{purl}</span>
                                {!e.unmapped && (
                                  <span
                                    style={{
                                      fontSize: 9,
                                      fontWeight: 700,
                                      letterSpacing: ".06em",
                                      textTransform: "uppercase",
                                      color: t.fg3,
                                      marginLeft: "auto",
                                    }}
                                  >
                                    {isPrimary ? "primary" : "alt"}
                                  </span>
                                )}
                              </div>
                            );
                          })}
                        </div>
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
                    placeholder="(optional — auto-generated from your changes if blank)"
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
                        ? `Create PR with ${editsCount} change${editsCount === 1 ? "" : "s"}`
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
        Your changes are pushed and waiting for review.
      </div>
      <div
        style={{
          background: t.surface2,
          border: `1px solid ${t.border}`,
          borderRadius: 10,
          padding: 14,
          textAlign: "left",
          maxWidth: 380,
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
          <code
            style={{ fontSize: 12.5, fontWeight: 600, color: t.fg1 }}
          >
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
          branch
        </div>
        <div
          style={{
            fontSize: 12,
            fontFamily: "JetBrains Mono, monospace",
            color: t.fg1,
            wordBreak: "break-all",
          }}
        >
          {committed.branch}
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
