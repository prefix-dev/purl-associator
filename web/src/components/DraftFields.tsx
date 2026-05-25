import type { ChangeEvent, CSSProperties, FormEvent, ReactNode } from "react";
import { Btn, TextInput, type Theme } from "./Primitives";

/**
 * Local draft editing primitives.
 *
 * Components in this file are deliberately auth-agnostic: editing always writes
 * to the local persisted draft store. Authentication is only a submit concern
 * and must stay in the PR drawers. When adding a new editable field, prefer one
 * of these wrappers instead of wiring DOM events inline; that keeps the
 * anonymous-drafting behavior consistent.
 */
export type DraftChange<T> = (value: T) => void;
export type DraftAction = () => void;

export function draftClick(onDraft: DraftAction): DraftAction {
  return onDraft;
}

export function DraftTextInput({
  value,
  onDraftChange,
  placeholder,
  theme,
  mono,
  style,
}: {
  value: string;
  onDraftChange: DraftChange<string>;
  placeholder?: string;
  theme: Theme;
  mono?: boolean;
  style?: CSSProperties;
}) {
  return (
    <TextInput
      value={value}
      onChange={onDraftChange}
      placeholder={placeholder}
      theme={theme}
      mono={mono}
      style={style}
    />
  );
}

export function DraftTextArea({
  value,
  onDraftChange,
  placeholder,
  theme,
  rows,
  mono,
  style,
}: {
  value: string;
  onDraftChange: DraftChange<string>;
  placeholder?: string;
  theme: Theme;
  rows?: number;
  mono?: boolean;
  style?: CSSProperties;
}) {
  const t = theme.t;
  return (
    <textarea
      value={value}
      onChange={(e: ChangeEvent<HTMLTextAreaElement>) =>
        onDraftChange(e.target.value)
      }
      placeholder={placeholder}
      rows={rows}
      style={{
        width: "100%",
        resize: "vertical",
        background: t.surface,
        color: t.fg1,
        border: `1px solid ${t.border}`,
        borderRadius: 8,
        padding: 10,
        fontSize: 12.5,
        lineHeight: 1.5,
        fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif",
        outline: "none",
        ...style,
      }}
    />
  );
}

export function DraftCheckbox({
  checked,
  onDraftChange,
  style,
}: {
  checked: boolean;
  onDraftChange: DraftChange<boolean>;
  style?: CSSProperties;
}) {
  return (
    <input
      type="checkbox"
      checked={checked}
      onChange={(e) => onDraftChange(e.target.checked)}
      style={style}
    />
  );
}

export function DraftSelect<T extends string>({
  value,
  onDraftChange,
  children,
  style,
}: {
  value: T;
  onDraftChange: DraftChange<T>;
  children: ReactNode;
  style?: CSSProperties;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onDraftChange(e.target.value as T)}
      style={style}
    >
      {children}
    </select>
  );
}

export function DraftButton({
  theme,
  onDraft,
  children,
  variant = "ghost",
  size,
  icon,
  disabled,
  title,
  style,
}: {
  theme: Theme;
  onDraft: () => void;
  children: ReactNode;
  variant?: "primary" | "secondary" | "ghost";
  size?: "sm" | "lg";
  icon?: string;
  disabled?: boolean;
  title?: string;
  style?: CSSProperties;
}) {
  return (
    <Btn
      theme={theme}
      variant={variant}
      size={size}
      icon={icon}
      disabled={disabled}
      title={title}
      style={style}
      onClick={onDraft}
    >
      {children}
    </Btn>
  );
}

export function handleDraftSubmit(
  event: FormEvent<HTMLFormElement>,
  onDraft: () => void,
): void {
  event.preventDefault();
  onDraft();
}
