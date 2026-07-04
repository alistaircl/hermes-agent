#!/usr/bin/env python3
"""Balanced marker check for hermes-agent fork sync customizations.

Companion to scripts/verify_fork_patches.py — that script verifies *marker
strings* are still present (e.g. "Phase 2.8 still in tools/approval.py").
This script verifies *symbol balance*: every custom symbol USED in the file
must also be DEFINED. A patch can be half-reverted when upstream keeps the
call sites but drops the defining assignment — that's the bug class that
brought this script into existence (Jul 2026 second-occurrence of the
approval-justification-gate failure mode).

Exit status:
  0  - all USE counts are matched by DEF counts
  1  - at least one symbol is USE>0, DEF=0 (i.e. half-reverted patch)
  2  - usage error (bad args, missing file, etc.)
"""
from __future__ import annotations
import argparse
import re
import sys
from pathlib import Path
from typing import Generator, Tuple, Union

# Patches the sync skill tracks, with the symbols each one introduces.
# Each entry is (name, def_regex) where name is a Python identifier that
# must have BOTH a defining line and at least one corresponding use.
# For dict-key markers (e.g. cron header meta writes ``job["_xxx"] = …``),
# there is no module-level name to def-match — those are NOT registered
# here and instead are checked by `verify_fork_patches.py` for the
# string marker. Adding them to this gate causes spurious
# "half-reverted" findings.
SYMBOL_REGISTRY = {
    "tools/approval.py": [
        # Approval justification gate (dc815e64c)
        ("_get_pending_justification",     re.compile(r"^def _get_pending_justification\(")),
        ("_pending_approvals",             re.compile(r"^_pending_approvals\s*[:=]")),
        ("_pending_justifications",        re.compile(r"^_pending_justifications\s*[:=]")),
        ("_MAX_JUSTIFICATION_RETRIES",     re.compile(r"^_MAX_JUSTIFICATION_RETRIES\s*=")),
        # Yolo freeze (security: prevents prompt injection from flipping mid-session)
        ("_YOLO_MODE_FROZEN",              re.compile(r"^_YOLO_MODE_FROZEN\s*[:=]")),
        # Gateway session detection (renamed impl OK; we just need *a* def)
        ("_is_gateway_approval_context",   re.compile(r"^def _is_gateway_approval_context\(")),
    ],
    "cron/scheduler.py": [
        # Cron report header meta (dc815e64c). NOTE: these are dict-key markers
        # (job["_elapsed_seconds"] = …), not Python symbols. Tracked here for
        # the *local* helper that produces them — _job_start_time, which is a
        # function-local variable closed over by the wrapping function. The
        # key markers themselves are checked by verify_fork_patches.py.
        ("_job_start_time",                re.compile(r"^\s*_job_start_time\s*=")),
    ],
    "tools/terminal_tool.py": [
        # Justification gate keeps its parameter on the tool signature.
        # This is a function-parameter marker — count_uses treats ``def name(``
        # as def (skip), and ``justification=justification`` or
        # ``justification=args.get(...)`` are the uses that prove the patch
        # is wired in.
        ("justification",                  re.compile(r"^\s*justification\s*[:=]")),
    ],
}


def count_uses(text: str, name: str) -> int:
    """Count non-defining occurrences of ``name`` in ``text``.

    A "use" is any occurrence that's NOT a defining line. We approximate by
    excluding the obviously-defining line shapes (function definition,
    module-level assignment, function parameter declaration, dict-key
    subscript). It's good enough for the gap-detecting role this script
    plays — re-pinning per-line would make the script's parser harder to
    read than a small set of skip-patterns. If a registry entry falls into
    the gap, mark it explicitly with ``key_marker=True`` so we use the
    ``["_marker_name"]`` key-grep instead of name-grep.
    """
    count = 0
    pat = re.compile(rf"\b{re.escape(name)}\b")
    for line in text.splitlines():
        stripped = line.lstrip()
        # Skip pure comment lines — they don't actually invoke the symbol.
        if stripped.startswith("#"):
            continue
        # Skip function/method definitions:  ``def name(`` / ``class name:``
        if re.match(rf"^(def|class)\s+{re.escape(name)}\b", stripped):
            continue
        # Skip module-level assignment: ``name: type = ...`` / ``name = ...``
        # (no leading whitespace). Function-parameter declarations that
        # start a line are kept (treated as uses of the parameter name).
        if not line[:1].isspace() and re.match(rf"^{re.escape(name)}\s*[:=]", stripped):
            continue
        # Skip dict-key subscripts of the form ["name"] or ['name'] — those
        # are storage keys, not symbol references.
        if re.search(rf"\[\s*['\"]{re.escape(name)}['\"]\s*\]", line):
            continue
        if pat.search(line):
            count += 1
    return count


def count_defs(text: str, def_regex: re.Pattern) -> int:
    return sum(1 for line in text.splitlines() if def_regex.search(line))


Finding = Tuple[str, str, Union[int, str], int, str]


def check_file(repo_root: Path, rel_path: str, symbols: list) -> Generator[Finding, None, None]:
    """Yield (rel_path, name, use_count, def_count, status) tuples."""
    Finding = tuple  # noqa: F841  (re-annotated locally for clarity)
    abs_path = repo_root / rel_path
    if not abs_path.exists():
        # File may have legitimately moved upstream. Surface that as a "missing"
        # finding rather than silently passing — operator must look at it.
        for name, _def_regex in symbols:
            yield (rel_path, name, "MISSING-FILE", 0, "missing-file")
        return

    text = abs_path.read_text()
    for name, def_regex in symbols:
        uses = count_uses(text, name)
        defs = count_defs(text, def_regex)
        if uses > 0 and defs == 0:
            status = "half-reverted"
        elif uses == 0 and defs > 0:
            status = "orphan-definition"
        elif uses == 0 and defs == 0:
            status = "absent"
        else:
            status = "ok"
        yield (rel_path, name, uses, defs, status)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".",
                        help="Path to hermes-agent repository root (default: cwd)")
    args = parser.parse_args()
    repo_root = Path(args.repo).resolve()

    any_failure = False
    print(f"Balanced marker check — repo: {repo_root}")
    print(f"{'file':32s}  {'symbol':35s}  {'USE':>4s}  {'DEF':>4s}  status")
    print("-" * 90)
    for rel_path, symbols in SYMBOL_REGISTRY.items():
        for rel, name, uses, defs, status in check_file(repo_root, rel_path, symbols):
            print(f"{rel:32s}  {name:35s}  {str(uses):>4s}  {str(defs):>4s}  {status}")
            if status in ("half-reverted", "missing-file", "orphan-definition"):
                any_failure = True

    print("-" * 90)
    if any_failure:
        print("FAIL: at least one custom symbol is unbalanced (USE>0, DEF=0).")
        print("       See docs/sync-fork-with-upstream-selectively/SKILL.md step 9.5.")
        return 1
    print("OK: all custom symbols are balanced.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
