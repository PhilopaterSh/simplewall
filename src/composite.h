// composite fork umbrella (Phase 1) — docs/specs/composite/.
// Fork-namespaced: every composite entry point is prefixed _app_c* /
// lives in a composite_*.c module, keeping upstream rebases cheap (DEC-09).

#pragma once

// sidecar state files (namespaced, never inside profile.xml — DATA-01)
#define COMPOSITE_SIDECAR_PACKSTATE L"composite_packstate.json"   // FR-08, DATA-02
#define COMPOSITE_SIDECAR_LEDGER    L"composite_ledger.json"      // Phase 2, DATA-03
#define COMPOSITE_SIDECAR_AUDIT     L"composite_audit.json"       // SEC-03, DATA-01
