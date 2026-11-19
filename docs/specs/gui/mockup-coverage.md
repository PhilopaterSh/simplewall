# GUI mockup r1 — feature coverage matrix (visual blueprint)

> Mockup: `mockup-r1.html` (interactive; open in a browser). Authority:
> design-gui-draft.md r2 (DEC-11 approved). Every implemented composite
> capability maps 1:1 to a UI surface — a capability without a surface is
> a spec violation (FR-15).

| Capability (module) | UI surface in the mockup |
|---|---|
| T003 auto-tiers | prompt tier line + Settings gate |
| T004 publisher anchors | app badges + Rules anchors table (valid/revoked SEC-02) |
| T005 session durations | Apps card countdown + Rules session table + prompt duration buttons |
| T006 single-flight | prompt held-line + Log held rows + tray held badge |
| T007 lockdown | Lockdown page (state, pre-flight, survival rules, keep-or-release, RSK-04) + tray [LOCKDOWN] |
| T008/T009 signed packs | Packs page (version, epoch, watermark anti-rollback, delta, safe-refuse state) |
| P2-1/P2-5 ledger | Log quarantined rows + decide (restore/reject) + Settings gate |
| P2-4 zones | engine-side; verdicts surface via Log (no direct control) |
| T031 dnscache | resolveip feeds Log domain names (enrichment) |
| T032 ETW attribution | Settings gate (default OFF) |
| T033b bypass detection | Log BYPASS flagged rows + rules-as-data emission |
| T033 resolver ownership | Lockdown page P3-C panel (opt-in, watchdog, invariant) |
| T011 tray states | rail foot: [LOCKDOWN] / degraded / held chips |
| NFR-05 i18n + RTL | mockup is RTL Arabic; EN toggle in Settings |
| NFR-07 budgets | idle footprint chip (~16 MB measured) on Settings |
| Upstream editor (NFR-01) | app card expands to full rule editor (button per card) |
| Import wizard | Rules page (SWC container + WFC .wpw, schemas verified round-3) |
