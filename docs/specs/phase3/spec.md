# Phase 3 spec

Functional: FR-13 (cache + attribution + resolver ownership), FR-14
(DoH/DoT upstream, leak prevention; embedded-DoH detection documented
aspirational per P3-E). Non-functional: NFR-02/03/05/06 inherited, SEC-04
(local-only, opt-out purge), DATA-04 (numbers ratified: floor 17 s,
ceiling 86400 s, stale grace 60 s, chain depth 8, capacity 64k LRU),
SEC-05 (no new processes). Deferred explicitly: nothing in this chain is
enabled by default — every P3 feature ships behind a config gate.

Inherited keys covered:
- NFR-06: headless cache suite (no elevation).
- NFR-02: /W4+/analyze clean, system libraries only.
- NFR-03: footprint budget asserted (cache bounded: 64k entries).
- NFR-05: localized surfaces for any domain-layer UI strings.
- OPS-01: goldfish gate pre-merge, recorded.
- SEC-05: no new processes (ETW session in-process).
- SEC-04: local-only data + opt-out purge (T035 probe).
- DATA-01: cache persists (if ever) in a namespaced sidecar, never
  profile.xml; runtime cache is memory-only this round.
- FR-08: leak-prevention rules are packs-data consumed by the existing
  signed-pack machinery (T034) — no hardcoded filters.
