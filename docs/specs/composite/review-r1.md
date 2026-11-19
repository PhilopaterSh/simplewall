# Goldfish Review — composite/design.md (rev 2026-11-06-r1)

Reviewer: fresh-context goldfish (no teardown context; read design.md +
hardening-round-1/design.md for inherited-contract checks only). 2026-11-06.

**VERDICT: needs-revision (8 blocking, 12 suggestions)**

Positive: no invented keys; FR-11 preserves the hardening tri-state
contract verbatim; compiled-in internal rules not regressed; audit-policy
caution present (SEC-03).

## Blocking

1. Journey 5 cites DATA-04 (Phase 3 DNS cache) for the ledger baseline —
   intended key is DATA-03 (ledger baseline); DATA-03 had zero body refs.
2. Ten orphan keys defined but never consumed in body: SEC-05, DATA-03,
   NFR-01/02/03/04/06, OPS-01/03/04. OPS-03 duplicates DEC-09; OPS-01
   duplicates DEC-08 prose but is wired to nothing.
3. FR-02, FR-04, FR-09, FR-12, SEC-05 have no acceptance route in either
   verification lane. FR-12 is a headline Phase 2 outcome with zero path.
4. Tests undershoot: FR-07 test loads 1M vs required ≥2M/32 zones;
   FR-10 test lacks the quarantine+exact-restore path; FR-01's primary
   Security-audit pipeline is never tested in either lane; FR-07
   equivalence and FR-08 unit enable/disable/update untested.
5. DEC-05 publisher rules cannot deliver journey 1 as stated: WFP ALE
   conditions match app-path blobs; no signer-hash match condition without
   AppID driver (excluded by DEC-02). Enforcement machinery unstated;
   SEC-02's "stops matching" has no trigger between applies.
6. Lockdown semantics undefined vs the app's own default-deny engine;
   DEC-04 halves imply opposite WFP-arbitration assumptions (either the
   WFAS block is shadowed and survival rules are dead weight, or it
   governs and silently blocks user-allowed apps).
7. DEC-07 self-contradiction: admits code from "Portmaster" (GPL-3) while
   bucketing AGPL as ideas-only — reviewer asserted Portmaster is AGPL.
   Resolution (owner, GitHub-API verified 2026-11-06): safing/portmaster
   core = GPL-3.0; safing/spn module = AGPL-3.0 (archived) — excluded.
8. RSK-03 claims "hardening already removed the wufix path" but hardening
   RSK-03 explicitly kept wufix (only ImagePath preservation landed).

## Suggestions (all incorporated in r2 unless noted)

9. 5156 (success auditing) = machine-wide flood; prompts need only 5157.
10. Runtime audit-policy reversion undetected → silent prompt degradation
    (violates the hardening visible-as-a-state principle).
11. Missing risks: GPO/Intune-managed rules vs ledger quarantine; pack
    key rotation/anti-rollback; crash residue of audit changes; Lockdown
    negatable by another elevated process.
12. GPG does not mitigate SmartScreen (Authenticode-based).
13. RSK-04 owned by a future document, not a person.
14. Key collisions with hardening chain unnamespaced; OPS-01 would
    false-fail hardening rounds.
15. DEC-08 has no amendment mechanism (deadlocks on first new key).
16. Broken cross-ref: "see DEC-02 hardening precedent" points wrong.
17. Phase 1 ships pack sidecars before integrity guarantee (FR-12 is
    Phase 2).
18. FR-05 default action undefined when configured default is "ask".
19. In-scope API list tensions ("already linked" vs dynamic resolve;
    dnsapi listed while Phase 3 internals out of scope).
