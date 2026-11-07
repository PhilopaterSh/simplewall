# AGENTS.md — simplewall hardened fork: repository-wide agent instructions

> This file replaced upstream's placeholder content (inherited commit
> `8f625967`). It is the canonical workflow for EVERY AI agent (and human)
> working in this repository. The pointer files (CLAUDE.md, GROK.md)
> reference this file.

## What this fork is

Security-hardened, self-verified fork of henrypp/simplewall (GPL-3.0 WFP
firewall), built on the latest upstream master plus: two hardening rounds,
a signed ECDSA P-256 update feed, a composite Phase-1 skeleton, and a
gated C tool suite (release-preflight / dnsrig / feedserver). All work is
governed by the **goldfish-gate EGM workflow** defined below. The gate
tool lives at github.com/PhilopaterSh/goldfish-gate (installed via pip).

## The EGM cycle — MANDATORY for every feature/fix

1. **Elephant drafts** `docs/specs/<chain>/design.md` (revision header).
2. **Fresh-context goldfish review** — a NEW agent with zero conversation
   history returns VERDICT APPROVE / APPROVE-WITH-CHANGES / BLOCK.
3. **Owner approval recorded verbatim** (Arabic quote + date) in the
   design header. No implementation before it exists.
4. **spec.md / plan.md / tasks.md generated** from the approved design.
5. **Mechanical gate MUST exit 0** before any implementation commit:
   `goldfish check design.md spec.md plan.md tasks.md`
   (run inside the chain directory; CI runs it too — see smoke-test.yml).
6. **Implement only chain tasks**, in task order, then re-run the gate.
7. **PR → CI green (build + launch + preflight + gate) → merge.**

## Standing rules (each earned by a recorded incident — see the ledger)

- **Empirical-arbiter-first**: any BLOCKING finding about observable
  behavior must attach a reproduction (bench/script/command output) at
  review time; otherwise it is labeled `hypothesis — non-gating`.
  Precedent: a wrong BLOCKING ("CNG wants little-endian") came within one
  accepted review of ratifying a regression; the bench refuted it in
  seconds (tools/cng-signature-bench.py — exit 0 REQUIRED before any
  feed/signature change ships).
- **Owner adversarial question per round**: the owner's unsolicited
  challenge is a formal detection mechanism (it caught the one gate
  bypass and spawned the entire supply-chain round). Log it in
  docs/specs/tooling/retrospective-ledger.md when it fires.
- **Never trust docs/memory for API byte-order or ABI claims** — prove
  against the real API (bench or test) before coding.
- **Lanes**: one worktree per lane; NEVER commit across lanes; the
  tools lane never refactors vendor/ — tools adapt to vendor, never the
  reverse; vendor changes are minimal diffs acked against the vendor
  lane's live state (measure mtime + git log before racing).
- **Amendment propagation**: when a revision header CORRECTS an earlier
  statement, grep the body for the superseded term and rewrite it in the
  same revision (incident: DEC-05 body contradicted the r4 header).
- **Artifact completeness**: no implementation task starts while any
  chain file is still a template (unfilled handoff.md, missing
  verification.md). CI enforces via tools/check-chain-artifacts.py.
- **Retrospective ledger is append-only**: every gate catch, review
  finding (REAL/WRONG + arbitration), and bypass gets a row in
  docs/specs/tooling/retrospective-ledger.md. Effectiveness is measured
  from that ledger, not from memory.
- **Sign after every rebuild** (SAC): signtool /fd SHA256 /f
  D:/CV/Github/.keys/fork-codesign.pfx /p fork-local-only bin\64\<exe>.
  NEVER commit private key material — the release profile/owner machine
  split (tooling DEC-07) exists precisely for this.
- **Parity constants live in tools/preflight-ground-truth/*.json with
  provenance headers**; update ONLY with a commit citing the diff that
  changed the underlying binary (RSK-01). In-tree key material is never
  trusted — it is cross-checked against the off-repo JSON by the
  preflight release profile (b2).

## Gate commands quick reference

    cd docs/specs/<chain>
    goldfish check design.md spec.md plan.md tasks.md     # exit 0 required
    python tools/cng-signature-bench.py                   # 4/4 PASS required
    python tools/release-preflight.py bin/64/simplewall.exe          # release
    python tools/release-preflight.py bin/64/simplewall.exe --ci     # CI profile

## Merge discipline

Linear: feature branch → sequential PRs → merge commits. CI green
(build + 20s lifetime + C preflight --ci + dnsrig self-test + goldfish
checks) before merge. PR-number gaps and unexpanded $VARS in merge
messages are silent-automation-failure symptoms — note them in the
ledger when seen (precedents: missing PR #9, "Merge PR #$PR2").
