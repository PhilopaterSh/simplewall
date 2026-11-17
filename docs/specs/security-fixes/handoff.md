# Handoff: Security Fixes — the 2026-11-17 audit remediation (r2)

> Generated from design.md r2 (owner directive recorded; goldfish review
> APPROVE-WITH-CHANGES integrated). This handoff closes the artifact gate's
> own requirement — no chain proceeds on a template.

## Problem

The owner-commissioned 3-agent full-scope audit (2026-11-17) found 3 MAJOR
security gaps in the merged product: the updater installs an elevated
executable from a user-writable cache with no re-verification at exec time
(released exe affected); the FR-12 config-dir ACL hardening is runtime-broken
(PACL passed as an SD, no user ACE, no PROTECTED flag — silent no-op); and
the notification IDM_OPENRULESEDITOR branch mints+applies a PERMIT rule
without the safety gate every sibling branch has.

## Intended outcomes

1. The verify→execute window of the updater is closed by write-excluding
   share-mode + in-handle sha256 re-verification + hash-required fail-closed
   (FR-1, FR-2, DEC-1, DEC-2).
2. The composite config-dir DACL applies the intended policy correctly at
   every startup (FR-3, DEC-3).
3. The notification editor command is gated exactly like its siblings
   (FR-4, DEC-4).
4. The endianness documentation matches the bench (FR-5, DEC-5).

## Decisions carried

DEC-01..DEC-06 + RSK-01..RSK-04 per design.md r2 (review-integrated).

## Owner approval

- Owner directive recorded verbatim (2026-11-17): «اكمل العمل عليها من فضلك
  بالشكل الصحيح واعمل بالخطة وبالشكل المناسب goldfish-gate» — commissioning
  the remediation through the gate.
