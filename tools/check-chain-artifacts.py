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

    print(f"check-chain-artifacts: {failures} violation(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
