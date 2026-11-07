// composite_eventlog: Security-audit event prompt pipeline (FR-01, DEC-03).
// EvtSubscribe on channel "Security" for EventID 5157 only (success
// auditing/5156 rejected as a machine-wide flood), culture-invariant
// parsing (raw LayerRTID ints), port-merge dedup, single-flight window
// (FR-05), session durations (FR-04), subscription-health monitor driving
// the prompt-degradation state with automatic fallback to the existing
// FwpmNetEventSubscribe pipeline. wevtapi resolved dynamically (same
// pattern as src/log.c) for OS-degradation parity. Implemented in T002.

#pragma once

#include <windows.h>

NTSTATUS _app_eventlog_start (_In_ HWND hwnd);
VOID _app_eventlog_stop (VOID);
BOOLEAN _app_eventlog_ishealthy (VOID);
BOOLEAN _app_eventlog_ispromptdegraded (VOID); // RSK-08: prompt-pipeline degradation surfaced on the UI (T002)
