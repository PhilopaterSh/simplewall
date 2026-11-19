# Phase 3 plan

- `composite_dnscache.c/.h`: dependency-free cache core (T031) — hash
  table keyed by domain, doubly-linked LRU, per-entry TTL clamp + stale
  grace + chain links; headless test suite with a fake clock.
- ETW session (T032) rides the existing eventlog module patterns
  (EvtSubscribe-class); resolver ownership (T033) and DoH upstream (T034)
  integrate with the firewall verdict path as rules-as-data (FR-08
  machinery reused, no hardcoded filters).
- Verification (T035): headless cache suite (clamp/grace/chain/LRU), ETW
  probe script, SEC-04 purge probe; goldfish gate pre-merge.

## Design decisions honored by this plan

- DEC-04 (verify-then-commit) governs T033's resolver-ownership sequence.
- DEC-06 (port-53 conflicts detected and reported, never silently
  overridden) is enforced in T033b; RSK-04 (elevated negation of the
  seal, and the port-53 conflict risk) is the accepted residual risk
  owned by this chain — acknowledged here and in spec.
