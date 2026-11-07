// composite_state: namespaced sidecar state IO (DATA-01).
// Sidecar files live beside the profile directory (pack state, ledger
// baseline, audit-policy inventory) — never inside profile.xml; hash-
// checked at load from Phase 1 (FR-08) with ledger integrity in Phase 2
// (FR-12). Implemented in T009.

#pragma once

#include <windows.h>

NTSTATUS _app_state_initialize (VOID);
VOID _app_state_uninitialize (VOID);
