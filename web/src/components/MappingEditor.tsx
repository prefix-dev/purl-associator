import { ReactNode, useState } from "react";
import { PURL_TYPES } from "../data/loader";
import type { Edit, PackageEntry } from "../data/types";
import {
  Btn,
  ConfidenceBar,
  Glyph,
  PurlChip,
  SourceTag,
  StatusPill,
  TextInput,
  Theme,
} from "./Primitives";

type Props = {
  theme: Theme;
  pkg: PackageEntry | null;
  edit: Edit | undefined;
  onEdit: (e: Edit) => void;
  onApprove: () => void;
  onResetAuto: () => void;
  isLoggedIn: boolean;
  onRequestLogin: () => void;
};

function buildPurl(type: string, ns: string, name: string): string {
  if (!type || !name) return "";
  return ns ? `pkg:${type}/${ns}/${name}` : `pkg:${type}/${name}`;
}

export function MappingEditor({
  theme,
  pkg,
  edit,
  onEdit,
  onApprove,
  onResetAuto,
  isLoggedIn,
  onRequestLogin,
}: Props) {
  const t = theme.t;
  if (!pkg) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: t.fg3,
          background: t.page,
        }}
      >
        <div style={{ textAlign: "center", maxWidth: 380 }}>
          <div
            style={{
              fontFamily: "Moranga, serif",
              fontSize: 28,
              color: t.fg2,
              marginBottom: 8,
              fontWeight: 300,
            }}
          >
            No package selected
          </div>
          <div style={{ fontSize: 13, color: t.fg3 }}>
            Pick a conda-forge package on the left to view or edit its PURL mapping.
          </div>
        </div>
      </div>
    );
  }

  // After the early return above, pkg is non-null. Capture into a const so
  // the narrowing flows into closures (promoteAlt, addAlt, …).
  const p: PackageEntry = pkg;
  const auto = p.auto ?? {
    purl: p.purl,
    type: p.type,
    namespace: p.namespace,
    pkg_name: p.pkg_name,
    confidence: p.confidence,
    sources: p.sources,
  };

  const autoAlts = (p.auto?.alternative_purls ?? p.alternative_purls ?? []).map(
    (a) => a.purl,
  );
  const eff: Edit = {
    type: edit?.type ?? auto.type ?? p.type ?? "pypi",
    namespace: edit?.namespace ?? auto.namespace ?? p.namespace ?? "",
    pkgName: edit?.pkgName ?? auto.pkg_name ?? p.pkg_name ?? p.name,
    purl: edit?.purl ?? auto.purl ?? p.purl ?? "",
    alternative_purls: edit?.alternative_purls ?? autoAlts,
    unmapped: edit?.unmapped ?? p.unmapped ?? p.purl === null,
    note: edit?.note ?? "",
  };

  const isEdited = !!edit;
  const isVerified = p.status === "verified" && !isEdited;

  function updatePart(patch: Partial<Edit>): void {
    const next: Edit = { ...eff, ...patch };
    if (!("purl" in patch)) next.purl = buildPurl(next.type, next.namespace, next.pkgName);
    onEdit(next);
  }

  function promoteAlt(purl: string): void {
    const alt = (p.alternative_purls ?? p.auto?.alternative_purls ?? []).find(
      (a) => a.purl === purl,
    );
    if (!alt) return;
    // Promoting an alternative: it becomes the primary; the previous primary
    // demotes into the alternatives list.
    const newAlternates = [
      ...eff.alternative_purls.filter((p) => p !== purl),
    ];
    if (eff.purl && eff.purl !== purl) newAlternates.unshift(eff.purl);
    onEdit({
      ...eff,
      purl: alt.purl,
      type: alt.type,
      namespace: alt.namespace ?? "",
      pkgName: alt.pkg_name,
      alternative_purls: newAlternates,
    });
  }

  function removeAlt(purl: string): void {
    onEdit({
      ...eff,
      alternative_purls: eff.alternative_purls.filter((p) => p !== purl),
    });
  }

  function addAlt(purl: string): void {
    if (!purl.startsWith("pkg:")) return;
    if (eff.alternative_purls.includes(purl) || eff.purl === purl) return;
    onEdit({ ...eff, alternative_purls: [...eff.alternative_purls, purl] });
  }

  function updatePurlString(str: string): void {
    const m = str.match(/^pkg:([^/]+)\/(?:([^/]+)\/)?(.+)$/);
    const next: Edit = { ...eff, purl: str };
    if (m) {
      next.type = m[1];
      next.namespace = m[2] ?? "";
      next.pkgName = m[3];
    }
    onEdit(next);
  }

  return (
    <div style={{ flex: 1, overflowY: "auto", background: t.page }}>
      <div
        style={{
          position: "sticky",
          top: 0,
          zIndex: 5,
          background: t.surface,
          borderBottom: `1px solid ${t.border}`,
          padding: "14px 24px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          <div style={{ minWidth: 0, flex: 1 }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                marginBottom: 6,
                flexWrap: "wrap",
              }}
            >
              <h1
                style={{
                  fontFamily: "Moranga, serif",
                  fontWeight: 300,
                  fontSize: 28,
                  color: t.fg1,
                  margin: 0,
                  lineHeight: 1.1,
                }}
              >
                {p.name}
              </h1>
              <span
                style={{
                  fontFamily: "JetBrains Mono, monospace",
                  fontSize: 12,
                  color: t.fg2,
                  background: t.inset,
                  padding: "2px 7px",
                  borderRadius: 4,
                }}
              >
                v{p.version}
              </span>
              <StatusPill
                status={
                  isEdited
                    ? "edited"
                    : p.status === "unmapped" || p.purl === null
                      ? "unmapped"
                      : p.status
                }
                theme={theme}
              />
            </div>
            {p.summary && (
              <div
                style={{
                  fontSize: 13,
                  color: t.fg2,
                  lineHeight: 1.5,
                  maxWidth: 720,
                }}
              >
                {p.summary}
              </div>
            )}
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 4,
                marginTop: 10,
                fontSize: 11.5,
              }}
            >
              {p.source_url && (
                <UrlRow label="Source" url={p.source_url} theme={theme} />
              )}
              {p.homepage && (
                <UrlRow label="Homepage" url={p.homepage} theme={theme} />
              )}
              {p.repo && p.repo !== p.source_url && (
                <UrlRow label="Repository" url={p.repo} theme={theme} />
              )}
              {p.recipe_url && (
                <UrlRow label="Recipe" url={p.recipe_url} theme={theme} />
              )}
              {p.url && (
                <UrlRow label="Artifact" url={p.url} theme={theme} />
              )}
            </div>
          </div>

          <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
            {isEdited && (
              <Btn
                theme={theme}
                variant="ghost"
                size="sm"
                icon="undo"
                onClick={onResetAuto}
              >
                Reset
              </Btn>
            )}
            {!isVerified && !eff.unmapped && (
              <Btn
                theme={theme}
                variant="primary"
                icon="check"
                onClick={isLoggedIn ? onApprove : onRequestLogin}
              >
                Approve mapping
              </Btn>
            )}
          </div>
        </div>
      </div>

      <div style={{ maxWidth: 880, margin: "0 auto", padding: "24px 24px 60px" }}>
        <Section
          title="Automatic match"
          subtitle="Derived from rendered recipe + heuristics."
        >
          {auto.purl ? (
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
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  marginBottom: 10,
                  flexWrap: "wrap",
                }}
              >
                <Glyph name="sparkle" size={14} />
                <PurlChip purl={auto.purl} theme={theme} size="lg" />
                <ConfidenceBar
                  score={auto.confidence}
                  theme={theme}
                  width={80}
                />
              </div>
              {auto.sources.length > 0 && (
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: 11.5,
                    color: t.fg2,
                    flexWrap: "wrap",
                  }}
                >
                  <span>Sources:</span>
                  {auto.sources.map((s) => (
                    <SourceTag key={s} source={s} theme={theme} />
                  ))}
                </div>
              )}
              {p.note && (
                <div
                  style={{
                    marginTop: 10,
                    padding: "8px 10px",
                    background: theme.dark ? "#2a2616" : "#fff7d6",
                    border: `1px solid ${theme.dark ? "#3a3416" : "#f0e2a3"}`,
                    borderRadius: 6,
                    fontSize: 12,
                    color: t.fg1,
                    display: "flex",
                    gap: 8,
                    alignItems: "flex-start",
                  }}
                >
                  <span
                    style={{ color: t.warn, display: "flex", marginTop: 2 }}
                  >
                    <Glyph name="info" size={12} />
                  </span>
                  <span>{p.note}</span>
                </div>
              )}
            </div>
          ) : (
            <div
              style={{
                background: theme.dark ? "#2a1818" : "#fff1ec",
                border: `1px dashed ${theme.dark ? "#5a2a1a" : "#f3c3b0"}`,
                borderRadius: 12,
                padding: 14,
                fontSize: 13,
                color: t.fg1,
              }}
            >
              <div
                style={{
                  display: "flex",
                  gap: 8,
                  alignItems: "center",
                  marginBottom: 4,
                }}
              >
                <Glyph name="alert" size={14} />
                <strong>No automatic match found.</strong>
              </div>
              {p.note && (
                <div
                  style={{ color: t.fg2, fontSize: 12, marginTop: 4 }}
                >
                  {p.note}
                </div>
              )}
            </div>
          )}
        </Section>

        <Section
          title="PURL mapping"
          subtitle="Edit any field to override the automatic match."
        >
          <div
            style={{
              background: t.surface,
              border: `1px solid ${t.border}`,
              borderRadius: 12,
              padding: 14,
              marginBottom: 14,
            }}
          >
            <div
              style={{
                fontSize: 11,
                color: t.fg2,
                fontWeight: 600,
                marginBottom: 7,
                letterSpacing: ".04em",
                textTransform: "uppercase",
              }}
            >
              Resulting PURL
            </div>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                flexWrap: "wrap",
              }}
            >
              <PurlChip
                purl={eff.unmapped ? null : eff.purl}
                theme={theme}
                edited={isEdited}
                size="lg"
              />
              {isEdited &&
                !eff.unmapped &&
                auto.purl &&
                eff.purl !== auto.purl && (
                  <span style={{ fontSize: 11, color: t.fg2 }}>
                    was{" "}
                    <span
                      style={{
                        textDecoration: "line-through",
                        fontFamily: "JetBrains Mono, monospace",
                      }}
                    >
                      {auto.purl}
                    </span>
                  </span>
                )}
            </div>
          </div>

          <div
            style={{
              display: "grid",
              gap: 14,
              gridTemplateColumns: "200px 1fr 1fr",
              opacity: eff.unmapped ? 0.4 : 1,
              pointerEvents: eff.unmapped ? "none" : "auto",
              transition: "opacity 200ms",
            }}
          >
            <Field label="Type">
              <select
                value={eff.type}
                onChange={(e) => updatePart({ type: e.target.value })}
                style={selectStyle(theme)}
              >
                {PURL_TYPES.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field
              label="Namespace"
              hint="Optional. e.g. owner for github, scope for npm."
            >
              <TextInput
                value={eff.namespace}
                onChange={(v) => updatePart({ namespace: v })}
                theme={theme}
                mono
                placeholder="(none)"
              />
            </Field>
            <Field label="Package name">
              <TextInput
                value={eff.pkgName}
                onChange={(v) => updatePart({ pkgName: v })}
                theme={theme}
                mono
                placeholder={p.name}
              />
            </Field>
          </div>

          <div style={{ marginTop: 14 }}>
            <Field label="Raw PURL" hint="Edit directly — fields above will sync.">
              <TextInput
                value={eff.purl}
                onChange={updatePurlString}
                theme={theme}
                mono
                placeholder="pkg:type/namespace/name"
              />
            </Field>
          </div>

          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 9,
              marginTop: 14,
              padding: "10px 12px",
              background: t.surface,
              border: `1px solid ${t.border}`,
              borderRadius: 8,
              cursor: "pointer",
              userSelect: "none",
            }}
          >
            <input
              type="checkbox"
              checked={eff.unmapped}
              onChange={(e) => onEdit({ ...eff, unmapped: e.target.checked })}
              style={{ accentColor: t.accent, width: 14, height: 14 }}
            />
            <span style={{ fontSize: 13, color: t.fg1 }}>
              No PURL exists for this package
              <span
                style={{ fontSize: 11.5, color: t.fg2, marginLeft: 6 }}
              >
                (mark as intentionally unmapped — won't appear as missing)
              </span>
            </span>
          </label>

          <AlternativePurls
            theme={theme}
            primary={eff.purl}
            current={eff.alternative_purls}
            sourced={p.alternative_purls ?? p.auto?.alternative_purls ?? []}
            disabled={eff.unmapped}
            onPromote={promoteAlt}
            onRemove={removeAlt}
            onAdd={addAlt}
          />

          <div style={{ marginTop: 14 }}>
            <Field label="Note" hint="Optional context — shown on the PR.">
              <textarea
                value={eff.note}
                onChange={(e) => onEdit({ ...eff, note: e.target.value })}
                placeholder="e.g. 'Upstream uses fossil, not git — mapping to pkg:generic.'"
                style={{
                  background: t.surface,
                  color: t.fg1,
                  border: `1px solid ${t.border}`,
                  borderRadius: 8,
                  padding: "8px 10px",
                  fontSize: 13,
                  width: "100%",
                  fontFamily: "Inter, sans-serif",
                  outline: "none",
                  minHeight: 64,
                  resize: "vertical",
                }}
              />
            </Field>
          </div>
        </Section>

        {p.status === "verified" && p.approved_by && !isEdited && (
          <Section title="Verification">
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: 12,
                background: t.surface,
                border: `1px solid ${t.border}`,
                borderRadius: 12,
              }}
            >
              <Glyph name="check" size={16} />
              <div style={{ fontSize: 13 }}>
                Verified by <strong>@{p.approved_by}</strong>
                {p.approved_at && ` on ${p.approved_at.slice(0, 10)}`}
              </div>
            </div>
          </Section>
        )}
      </div>
    </div>
  );
}

function Section({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <section style={{ marginBottom: 28 }}>
      <div style={{ marginBottom: 12 }}>
        <h3
          style={{
            fontFamily: "Moranga, serif",
            fontWeight: 300,
            fontSize: 22,
            margin: 0,
            lineHeight: 1.2,
          }}
        >
          {title}
        </h3>
        {subtitle && (
          <div style={{ fontSize: 12.5, color: "var(--fg-2)", marginTop: 3 }}>
            {subtitle}
          </div>
        )}
      </div>
      {children}
    </section>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          marginBottom: 5,
          letterSpacing: ".04em",
          textTransform: "uppercase",
          opacity: 0.7,
        }}
      >
        {label}
      </div>
      {children}
      {hint && (
        <div style={{ fontSize: 11, marginTop: 4, opacity: 0.55 }}>{hint}</div>
      )}
    </div>
  );
}

function selectStyle(theme: Theme) {
  const t = theme.t;
  return {
    width: "100%",
    background: t.surface,
    color: t.fg1,
    border: `1px solid ${t.border}`,
    borderRadius: 8,
    padding: "8px 10px",
    fontSize: 13,
    fontFamily: "Inter, sans-serif",
    cursor: "pointer",
    outline: "none",
  } as const;
}

function AlternativePurls({
  theme,
  primary,
  current,
  sourced,
  disabled,
  onPromote,
  onRemove,
  onAdd,
}: {
  theme: Theme;
  primary: string;
  current: string[];
  sourced: { purl: string; confidence: number; source: string }[];
  disabled: boolean;
  onPromote: (purl: string) => void;
  onRemove: (purl: string) => void;
  onAdd: (purl: string) => void;
}) {
  const t = theme.t;
  const [draft, setDraft] = useState("");
  const sourcedByPurl = new Map(sourced.map((s) => [s.purl, s]));
  return (
    <div style={{ marginTop: 14 }}>
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          marginBottom: 5,
          letterSpacing: ".04em",
          textTransform: "uppercase",
          opacity: 0.7,
        }}
      >
        Alternative PURLs
      </div>
      <div style={{ fontSize: 11, opacity: 0.55, marginBottom: 8 }}>
        Same package in another ecosystem (e.g. pypi primary + github alt). Used
        to broaden CVE matching across feeds.
      </div>

      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 6,
          opacity: disabled ? 0.4 : 1,
          pointerEvents: disabled ? "none" : "auto",
        }}
      >
        {current.length === 0 && (
          <div
            style={{
              fontSize: 12,
              color: t.fg3,
              fontStyle: "italic",
              padding: "6px 0",
            }}
          >
            No alternatives.
          </div>
        )}
        {current.map((purl) => {
          const meta = sourcedByPurl.get(purl);
          return (
            <div
              key={purl}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "7px 10px",
                background: t.surface,
                border: `1px solid ${t.border}`,
                borderRadius: 8,
              }}
            >
              <PurlChip purl={purl} theme={theme} />
              {meta && <ConfidenceBar score={meta.confidence} theme={theme} width={50} />}
              {meta && <SourceTag source={meta.source} theme={theme} />}
              <div style={{ flex: 1 }} />
              <button
                onClick={() => onPromote(purl)}
                style={{
                  background: "transparent",
                  border: `1px solid ${t.border}`,
                  borderRadius: 6,
                  color: t.fg1,
                  fontSize: 11,
                  fontWeight: 600,
                  padding: "3px 8px",
                  cursor: "pointer",
                }}
              >
                Make primary
              </button>
              <button
                onClick={() => onRemove(purl)}
                title="Remove"
                style={{
                  background: "transparent",
                  border: `1px solid ${t.border}`,
                  borderRadius: 6,
                  color: t.fg2,
                  width: 24,
                  height: 24,
                  display: "inline-flex",
                  alignItems: "center",
                  justifyContent: "center",
                  cursor: "pointer",
                }}
              >
                <Glyph name="close" size={11} />
              </button>
            </div>
          );
        })}

        {/* Suggested but not currently chosen */}
        {sourced
          .filter((s) => s.purl !== primary && !current.includes(s.purl))
          .map((s) => (
            <div
              key={s.purl}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 10,
                padding: "7px 10px",
                background: t.surface2,
                border: `1px dashed ${t.border}`,
                borderRadius: 8,
                opacity: 0.85,
              }}
            >
              <PurlChip purl={s.purl} theme={theme} />
              <ConfidenceBar score={s.confidence} theme={theme} width={50} />
              <SourceTag source={s.source} theme={theme} />
              <div style={{ flex: 1 }} />
              <button
                onClick={() => onAdd(s.purl)}
                style={{
                  background: "transparent",
                  border: `1px solid ${t.border}`,
                  borderRadius: 6,
                  color: t.link,
                  fontSize: 11,
                  fontWeight: 600,
                  padding: "3px 8px",
                  cursor: "pointer",
                }}
              >
                + Add
              </button>
            </div>
          ))}

        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (draft.trim()) {
              onAdd(draft.trim());
              setDraft("");
            }
          }}
          style={{ display: "flex", gap: 6, marginTop: 4 }}
        >
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="pkg:type/namespace/name"
            style={{
              flex: 1,
              background: t.surface,
              color: t.fg1,
              border: `1px solid ${t.border}`,
              borderRadius: 8,
              padding: "6px 10px",
              fontSize: 12,
              fontFamily: "JetBrains Mono, monospace",
              outline: "none",
            }}
          />
          <button
            type="submit"
            disabled={!draft.trim().startsWith("pkg:")}
            style={{
              background: t.surface2,
              border: `1px solid ${t.border}`,
              borderRadius: 8,
              color: t.fg1,
              fontSize: 12,
              fontWeight: 600,
              padding: "0 12px",
              cursor: draft.trim().startsWith("pkg:") ? "pointer" : "not-allowed",
              opacity: draft.trim().startsWith("pkg:") ? 1 : 0.5,
            }}
          >
            Add
          </button>
        </form>
      </div>
    </div>
  );
}

function UrlRow({
  label,
  url,
  theme,
}: {
  label: string;
  url: string;
  theme: Theme;
}) {
  const t = theme.t;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "baseline",
        gap: 8,
        minWidth: 0,
        fontSize: 11.5,
      }}
    >
      <span
        style={{
          fontSize: 10,
          fontWeight: 600,
          color: t.fg3,
          letterSpacing: ".04em",
          textTransform: "uppercase",
          minWidth: 70,
          flexShrink: 0,
        }}
      >
        {label}
      </span>
      <a
        href={url}
        target="_blank"
        rel="noreferrer"
        title={url}
        style={{
          color: t.link,
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 11.5,
          textDecoration: "none",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          minWidth: 0,
          flex: 1,
        }}
      >
        {url}
      </a>
    </div>
  );
}
