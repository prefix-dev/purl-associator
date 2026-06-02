"""Promote an AI draft into ``mappings/cve_contributions/`` as authoritative OpenVEX.

This is the CLI escape hatch — the primary promotion path is the web UI's
"Use as starting point" button. Both routes write the same file shape: a
**pure OpenVEX 0.2.0** document. The audit trail (which AI draft this came
from) lives in the commit message / PR body the maintainer writes, not in
the OpenVEX body.

Usage::

    pixi run promote-ai-draft --package requests --advisory GHSA-9wx4-h78v-vm56
    # Review in $EDITOR before writing:
    pixi run promote-ai-draft --package requests --advisory GHSA-... --edit
    # Non-interactive automation must opt in explicitly:
    pixi run promote-ai-draft --package requests --advisory GHSA-... --yes
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import typer

from scripts.cve_common import parse_conda_purl

# Mirror worker/src/index.ts's filename sanitizer: only [A-Za-z0-9._-] survives.
# Keeps contribution filenames consistent whether the doc came via the Worker
# (web UI submission) or this CLI.
_USER_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]")

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DRAFTS_DIR = ROOT / "mappings" / "cve_ai_drafts"
DEFAULT_CONTRIB_DIR = ROOT / "mappings" / "cve_contributions"


def _find_newest_draft(
    drafts_dir: Path, package: str, advisory: str
) -> tuple[Path, dict] | None:
    """Return (path, doc) for the newest draft containing the given pair."""
    if not drafts_dir.exists():
        return None
    best: tuple[Path, dict, str] | None = None
    for path in sorted(drafts_dir.glob("*.json")):
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if doc.get("draft") is not True:
            continue
        assessments = doc.get("assessments") or {}
        if not any(
            isinstance(a, dict)
            and a.get("package") == package
            and a.get("advisory_id") == advisory
            for a in assessments.values()
        ):
            continue
        ts = doc.get("generated_at") or ""
        if best is None or ts > best[2]:
            best = (path, doc, ts)
    return (best[0], best[1]) if best else None


def _filter_statements_for(statements: list, package: str, advisory: str) -> list[dict]:
    """Pick statements targeting (package, advisory_id)."""
    out: list[dict] = []
    for stmt in statements or []:
        if not isinstance(stmt, dict):
            continue
        vuln = stmt.get("vulnerability") or {}
        if vuln.get("name") != advisory:
            continue
        targets = []
        for product in stmt.get("products") or []:
            if not isinstance(product, dict):
                continue
            parsed = parse_conda_purl(product.get("@id") or "")
            if parsed is None:
                continue
            if parsed[0] == package:
                targets.append(product)
        if not targets:
            continue
        new_stmt = {k: v for k, v in stmt.items() if k != "products"}
        new_stmt["products"] = targets
        out.append(new_stmt)
    return out


def _git_user_name() -> str:
    proc = subprocess.run(
        ["git", "config", "user.name"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or os.environ.get("USER") or "unknown"


def _filename_safe(name: str) -> str:
    """Sanitize a name for use inside a contribution filename. Matches the
    Worker's regex (see worker/src/index.ts::cveContributionFilename) so a
    file produced here is indistinguishable from one produced via the UI."""
    safe = _USER_SAFE_RE.sub("_", name)
    return safe or "unknown"


def _edit(content: str) -> str:
    editor = os.environ.get("EDITOR") or "vi"
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as tf:
        tf.write(content)
        tmp = Path(tf.name)
    try:
        subprocess.run([editor, str(tmp)], check=True)
        return tmp.read_text()
    finally:
        tmp.unlink(missing_ok=True)


def main(
    package: str = typer.Option(..., "--package"),
    advisory: str = typer.Option(..., "--advisory"),
    draft_file: Path = typer.Option(
        None,
        "--draft-file",
        help="Specific draft file to promote from (default: newest matching)",
    ),
    edit: bool = typer.Option(
        False, "--edit", help="Open $EDITOR on the OpenVEX body before writing"
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        help="Write without interactive confirmation (for automation only)",
    ),
    drafts_dir: Path = typer.Option(DEFAULT_DRAFTS_DIR, "--drafts-dir"),
    contributions_dir: Path = typer.Option(DEFAULT_CONTRIB_DIR, "--contributions-dir"),
) -> None:
    if draft_file:
        if not draft_file.exists():
            print(f"error: {draft_file} does not exist")
            sys.exit(2)
        try:
            doc = json.loads(draft_file.read_text())
        except json.JSONDecodeError as exc:
            print(f"error: {draft_file} is not valid JSON: {exc}")
            sys.exit(2)
        match = (draft_file, doc)
    else:
        match = _find_newest_draft(drafts_dir, package, advisory)
        if match is None:
            print(
                f"error: no AI draft found for ({package}, {advisory}) in {drafts_dir}"
            )
            sys.exit(2)

    src_path, draft = match
    openvex = draft.get("openvex") or {}
    statements = _filter_statements_for(
        openvex.get("statements") or [], package, advisory
    )
    if not statements:
        print(
            f"error: draft {src_path.name} carries no statements for "
            f"({package}, {advisory}) — nothing to promote"
        )
        sys.exit(2)

    now = datetime.now(UTC).isoformat(timespec="seconds")
    author = _git_user_name()
    author_safe = _filename_safe(author)
    rand = secrets.token_hex(3)
    ts_filename = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S-%fZ")
    # Filename convention mirrors worker-generated cve_contributions/ files.
    out_path = contributions_dir / f"{ts_filename}--{author_safe}--{rand}.json"

    doc_out = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/prefix-dev/purl-associator/promote/{rand}",
        "author": author,
        "tooling": "purl-associator/scripts.promote_ai_draft",
        "timestamp": now,
        "version": 1,
        "statements": statements,
    }
    text = json.dumps(doc_out, indent=2) + "\n"
    if edit:
        text = _edit(text)
        # Re-parse to keep validators happy.
        try:
            doc_out = json.loads(text)
            text = json.dumps(doc_out, indent=2) + "\n"
        except json.JSONDecodeError as exc:
            print(f"error: edited file is not valid JSON: {exc}")
            sys.exit(2)
    elif not yes:
        print(
            "About to write an authoritative OpenVEX contribution from an AI draft.\n"
            "Review the source draft and generated statement before continuing; "
            "use --edit to inspect/change it first or --yes for non-interactive runs."
        )
        if not typer.confirm("Write this promoted OpenVEX contribution?"):
            print("aborted")
            sys.exit(1)

    contributions_dir.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text)
    print(f"promoted {package} / {advisory}")
    print(f"  from: {src_path.relative_to(ROOT)}")
    print(f"  to:   {out_path.relative_to(ROOT)}")
    print()
    print("Suggested commit message:")
    print(f"  promote AI draft for {package} / {advisory} (run {draft.get('run_id')})")


if __name__ == "__main__":
    typer.run(main)
