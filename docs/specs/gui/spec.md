# GUI spec

- Shell: left navigation rail (Apps / Rules / Packs / Lockdown / Log /
  Settings), dark/light owner-selectable theme, per-monitor DPI, global
  search; upstream per-app editor re-homed inside app cards (zero UX
  regression, NFR-01).
- Pages consume ONLY the module query APIs (DEC-11 contract): no WFP
  behavior changes; new read-only enumerators are additive composite
  modules (in scope).
- Prompting: same-process popup, redesigned with tier + duration +
  held-count (S4 lock discipline restated as invariant).
- Log page: row schema fixed now (app, endpoint, verdict, tier,
  timestamp); held rows carry decide actions (FR-05 loop closes).
- i18n (NFR-05): every string localized from day one; RTL/Arabic mirror
  layout designed in M1.
- Rendering budget (NFR-07): virtualized card lists; bitmaps released
  on page hide.

- FR-15 coverage: every page maps 1:1 to a composite capability (Apps ->
  apps table; Rules -> publisher anchors + session decisions; Packs ->
  packs module; Lockdown -> lockdown module; Log -> ledger + held
  records; Settings -> config gates). A capability without a page is a
  spec violation.
