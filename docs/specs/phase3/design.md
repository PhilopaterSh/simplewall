# Phase 3 design — domain layer, r2 (goldfish round 1: NEEDS-REVISION integrated; consumes FR-13/FR-14/SEC-04/DATA-04 verbatim)

> Umbrella: ../composite/design.md r5. Owner directive to open the round
> recorded 2026-11-11 (chat "اكمل" continuation on the phase roadmap).

## Contracts (verbatim keys, unchanged)

- FR-13 domain layer interface: resolver-ownership + ETW DNS attribution +
  TTL-clamped IP<->domain cache; no driver, no service.
- FR-14 secure DNS: DoH/DoT upstream via the same resolver; DNS-leak
  prevention = detect and block apps bypassing the resolver.
- SEC-04: domain data local-only; no telemetry egress; opt-out removes
  stored data.
- DATA-04 cache: TTL clamp (floor 17 s), bounded retention past expiry,
  CNAME-chain retention — exact numbers set by THIS round (ratified
  below).

## DATA-04 numbers (ratified by this design)

- TTL clamp floor: **17 s** (given), clamp ceiling: **86400 s** (1 day —
  no entry may outlive a day regardless of the server's TTL).
- Retention past expiry: **60 s** grace, entries stay queryable with a
  stale flag, then hard-evict.
- CNAME chain: retain the full chain (up to **8** links) with each
  link's own TTL; the chain resolves to the terminal A/AAAA set.
- Cache capacity: **64k entries** LRU; hard-evict oldest past expiry
  first.

## Architecture decisions (P3-level)

- P3-A: cache module `composite_dnscache.c/.h` — dependency-free
  (NFR-06 headless testing), hash-keyed (domain string) with per-entry
  TTL clamp + stale-grace + LRU eviction; verdict helpers resolve
  ip->domain for the log/audit surfaces. (r2 per goldfish soft notes):
  memory budget = 64k entries x ~256 B ~= **~16 MB worst case**,
  asserted by the NFR-03-equivalent job; the cache keys BOTH A (IPv4)
  and AAAA (IPv6) records — v6 entries ride the same structure with the
  address stored as a 16-byte blob (the zones IPv6 punt does not apply
  here because the cache never builds filters).
- P3-B: ETW DNS attribution (Microsoft-Windows-DNS-Client ETW session)
  feeds the cache from observed resolutions; runs inside the existing
  process (SEC-05), off by default behind
  `IsCompositeDomainLayerEnabled`.
- P3-C (r2, rewritten per goldfish finding 4): resolver ownership = a
  GUARDED machine-wide action with the full safety contract:
  1. **Snapshot before any change**: per-interface prior DNS settings
     recorded in the lockdown-pattern sidecar BEFORE any machine write
     (SEC-03 exact-revert discipline).
  2. **Verify-then-commit**: the local resolver must answer (alive + a
     test resolution) BEFORE any interface is flipped (DEC-04
     verify-then-commit precedent).
  3. **Exact revert on disable/opt-out/uninstall**; the never-silently-
     ALLOW principle mirrors the lockdown rollback (never an unconditional
     DNS reset).
  4. **Crash-residue startup check**: if the app died while owning DNS,
     startup restores the recorded snapshot (the machine is never left
     pointing at a dead resolver).
  5. **Resolver-death while owned**: if the owned resolver stops
     answering, interfaces auto-revert to the snapshot within one
     watchdog cycle (default 10 s) — the machine falls back to working
     DNS, never to none.
  6. **INVARIANT: the app never leaves DNS broken** — stated as the
     acceptance surface for the whole feature.
  7. **Explicit opt-in per interface** (never default-on; the
     machine-wide-change killer-4 pattern).
  8. **RSK-04 ownership lands here**: port-53 conflict detected and
     REPORTED, never silently overridden (DEC-06).
  - Split: T033 = ownership safety machinery; T033b = bypass detection
    (diffed from ownership because the safety contract justifies its own
    task).
- P3-D: FR-14 DoH/DoT upstream = the local resolver's transport; leak
  prevention = block-with-log for apps connecting to external
  resolvers (port 53/853 beyond the owned one) — pack-style rules
  generated as data, never as hardcoded filters.
- P3-E: FR-14's "detect and block apps with embedded DoH" is
  ASPIRATIONAL (review-external-senior-2026-11-10 finding): embedded-DoH
  egress cannot be reliably attributed at user-mode; it is detected only
  statistically (SNI/name-pattern heuristics) and documented as such.

## Task breakdown

- T031 cache core (DATA-04 numbers, LRU, CNAME chains) + headless suite.
- T032 ETW DNS attribution session feeding the cache (P3-B).
- T033 resolver ownership + bypass detection (P3-C).
- T034 DoH/DoT upstream + leak-prevention rules-as-data (P3-D).
- T035 verification: probes + manual procedures + SEC-04 opt-out purge.

## Inherited keys (verbatim from ../composite/design.md r5)

- FR-08 signed rule packs: versioned JSON pack + detached signature
  verified against an embedded public key before parsing; packs
  enable/disable/update as a unit; sidecars hash-checked at load —
  Phase 3 leak-prevention rules ride this machinery as data (no
  hardcoded filters).
- NFR-02 MSVC build green at /W4 + /analyze with system libraries only,
  no new package dependencies.
- NFR-06 every new module carries automated tests runnable without
  elevation; the gate must be green to merge.
- OPS-01 every composite implementation round runs `goldfish check`
  (CI where available; local pre-merge recorded otherwise); failing
  gate blocks merge.
- SEC-04/SEC-05/DATA-01/NFR-03/NFR-05: as defined in the umbrella
  (local-only data + opt-out purge; no new processes/binaries; sidecars
  namespaced outside profile.xml; <= 8 MB; localized strings).
