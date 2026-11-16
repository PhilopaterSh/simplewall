#!/usr/bin/env python
# check-chain-artifacts — artifact-completeness gate for the goldfish-gate
# chains (process-audit roadmap item 1, cross-exam-ranked "best buy").
#
# WHY THIS EXISTS: `goldfish check` validates traceability across exactly
# four files (design/spec/plan/tasks) — it cannot see handoff.md or
# verification.md, so a chain can pass the gate with an unfilled handoff
# template and NO verification.md at all (verified incident: the tooling
# chain reached implementation + merged PR #10 in exactly that state).
# This checker closes that gap: a chain that still contains template
# placeholders or lacks its verification record FAILS.
#
# Usage: python tools/check-chain-artifacts.py [docs/specs]  (default)
# Exit 0 = every chain is artifact-complete. Exit 1 = list of violations.
import os
import re
import sys

TEMPLATE_MARKERS = [
    "<feature name>",
    "<functional requirement>",
    "<approved decision>",
    "<quality attribute>",
    "<security requirement>",
]

# chains whose verification.md is explicitly planned but not yet due
# (documented exception — the composite chain's T013 owns it)
PENDING_VERIFICATION_OK = {}


def is_template_text(text):
    lowered = text.lower()
    for marker in TEMPLATE_MARKERS:
        if marker.lower() in lowered:
            return True, marker
    return False, None


def check_chain(chain_dir):
    problems = []
    name = os.path.basename(chain_dir)

    handoff = os.path.join(chain_dir, "handoff.md")
    if not os.path.isfile(handoff):
        problems.append("handoff.md missing entirely")
    else:
        text = open(handoff, encoding="utf-8", errors="ignore").read()
        if len(text.strip()) < 80:
            problems.append("handoff.md is effectively empty")
        else:
            templ, marker = is_template_text(text)
            if templ:
                problems.append(f"handoff.md still contains template placeholder: {marker}")

    verification = os.path.join(chain_dir, "verification.md")
    if not os.path.isfile(verification):
        if name in PENDING_VERIFICATION_OK:
            pass  # documented exception
        else:
            problems.append("verification.md missing (chains must record how they were verified)")
    else:
        text = open(verification, encoding="utf-8", errors="ignore").read()
        if len(text.strip()) < 80:
            problems.append("verification.md is effectively empty")

    return name, problems


# ---------------------------------------------------------------------------
# Governance-marker gate (process-audit improvement 1): the AGENTS.md
# governance file was silently clobbered by a lane merge on 2026-11-10
# (the rule that kept humans writing the ledger lived in the file the
# merge machine ate). These markers MUST always be present.
GOVERNANCE_MARKERS = [
    "retrospective-ledger",
    "empirical-arbiter",
    "goldfish check",
    "RSK-01",
    "RESUME.md",
    "EGM cycle",
]

TREE_FORBIDDEN_EXTS = {".exe", ".map", ".obj", ".pdb", ".lib", ".dll", ".ilk"}
TREE_ALLOWLIST = {
    "bin/profile_internal.bin",   # compiled-in blocklist source (build input)
}


def check_governance(repo_root):
    problems = []
    agents_md = os.path.join(repo_root, "AGENTS.md")
    if not os.path.isfile(agents_md):
        return ["AGENTS.md missing at repo root - the governance surface is gone"]
    text = open(agents_md, encoding="utf-8", errors="ignore").read()
    lowered = text.lower()
    for marker in GOVERNANCE_MARKERS:
        if marker.lower() not in lowered:
            problems.append(f"AGENTS.md lost governance marker: '{marker}' (clobber class - restore from git history)")
    return problems


def check_tree_hygiene(repo_root):
    # git-tracked files only: local build outputs are untracked and legal
    import subprocess
    try:
        out = subprocess.run(["git", "ls-files"], cwd=repo_root, capture_output=True, text=True, timeout=60).stdout
    except Exception as exc:
        return [f"git ls-files failed: {exc}"]
    problems = []
    for rel in out.splitlines():
        rel_norm = rel.replace("\\", "/")
        if rel_norm in TREE_ALLOWLIST:
            continue
        ext = os.path.splitext(rel_norm)[1].lower()
        base = os.path.basename(rel_norm)
        if ext in TREE_FORBIDDEN_EXTS:
            problems.append(f"forbidden committed artifact: {rel}")
        elif base.startswith("dbg") and ext in (".c", ".cpp"):
            problems.append(f"scratch file committed: {rel}")
        elif not rel_norm.startswith(('vendor/', 'tools/vendor/')):
            # vendored trees are intentionally large text sources - exempt
            try:
                size = os.path.getsize(os.path.join(repo_root, rel))
                if size > 256 * 1024:
                    problems.append(f'oversize committed file ({size} bytes): {rel}')
            except OSError:
                pass
    return problems


def main():
    specs_root = sys.argv[1] if len(sys.argv) > 1 else os.path.join("docs", "specs")
    if not os.path.isdir(specs_root):
        print(f"FAIL: specs root not found: {specs_root}")
        return 1

    failures = 0
    for entry in sorted(os.listdir(specs_root)):
        chain_dir = os.path.join(specs_root, entry)
        if not os.path.isdir(chain_dir):
            continue
        if not os.path.isfile(os.path.join(chain_dir, "design.md")):
            continue  # not a chain (review artifacts etc.)
        name, problems = check_chain(chain_dir)
        if problems:
            failures += len(problems)
            for p in problems:
                print(f"FAIL: {name}: {p}")
        else:
            print(f"PASS: {name}: artifact-complete")

    repo_root = os.path.abspath(os.path.join(specs_root, os.pardir, os.pardir)) if os.path.basename(os.path.abspath(specs_root)) == "specs" else os.path.abspath(specs_root)
    for problem in check_governance(repo_root):
        failures += 1
        print(f"FAIL: governance: {problem}")
    if os.path.isfile(os.path.join(repo_root, "AGENTS.md")) or os.path.isdir(repo_root):
        for problem in check_tree_hygiene(repo_root):
            failures += 1
            print(f"FAIL: tree-hygiene: {problem}")

    print(f"check-chain-artifacts: {failures} violation(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
