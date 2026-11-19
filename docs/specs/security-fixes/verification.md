# Verification: Security Fixes (r2)

## Gates

- goldfish check (design/spec/plan/tasks) exit 0 at the freeze.
- check-chain-artifacts: 0 violations (this file + the filled handoff close
  the gate's own findings).

## Per-fix evidence (to be updated by T006)

- FIX-1: build clean + the CI launch test exercises the updater path shape;
  hash-required fail-closed asserted by code review + the sandbox NSIS round
  owed before re-release (RSK-1).
- FIX-2: compile-level correctness per the review-confirmed rewrite shape;
  runtime DACL read-back rides the owner interactive round.
- FIX-3: parity vs the sibling-branch gate condition (AS6).
- FIX-4: comment matches rapp.c + the bench (AS7).
- CI: dispatch-then-merge on feat/security-fixes (ledger row 34 protocol).
