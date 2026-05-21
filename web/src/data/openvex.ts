import type { ReviewEdit, VexStatus } from "./cves";
import { condaPurl } from "./condaPurl";

export const DEFAULT_ACTION_STATEMENT =
  "Update to a fixed conda-forge build of the package.";

/** One OpenVEX 0.2.0 statement. The Worker supplies the document envelope. */
export type OpenVexStatement = {
  vulnerability: { name: string };
  products: { "@id": string }[];
  status: VexStatus;
  justification?: string;
  action_statement?: string;
  status_notes?: string;
};

export function requiresJustification(status: VexStatus): boolean {
  return status === "not_affected";
}

export function requiresActionStatement(status: VexStatus): boolean {
  return status === "affected";
}

export function buildPackageStatement(
  pkg: string,
  advisoryId: string,
  edit: ReviewEdit,
): OpenVexStatement {
  const stmt: OpenVexStatement = {
    vulnerability: { name: advisoryId },
    products: [{ "@id": condaPurl(pkg) }],
    status: edit.status,
  };
  applyStatusFields(stmt, edit, true);
  return stmt;
}

export function buildVersionOverrideStatement(
  pkg: string,
  advisoryId: string,
  versions: string[],
  status: "affected" | "not_affected",
  edit: ReviewEdit,
): OpenVexStatement {
  const stmt: OpenVexStatement = {
    vulnerability: { name: advisoryId },
    products: versions.map((v) => ({ "@id": condaPurl(pkg, v) })),
    status,
  };
  applyStatusFields(stmt, edit, false);
  return stmt;
}

function applyStatusFields(
  stmt: OpenVexStatement,
  edit: ReviewEdit,
  includeNotes: boolean,
): void {
  if (requiresJustification(stmt.status)) {
    stmt.justification = edit.justification;
  } else if (requiresActionStatement(stmt.status)) {
    stmt.action_statement =
      edit.action_statement.trim() || DEFAULT_ACTION_STATEMENT;
  }
  if (includeNotes) {
    const notes = edit.notes.trim();
    if (notes) stmt.status_notes = notes;
  }
}
