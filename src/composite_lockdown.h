// composite_lockdown: WFAS-layer defense-in-depth seal (FR-06, DEC-04).
// Recipe: record per-profile defaults + outbound-allow set -> verify the
// audit subcategory (or the logged confirm-without-prompts path under
// GPO) -> service-scoped survival rules (svchost + Dhcp/CryptSvc;
// WSL/ICS; port-wide allows rejected) -> default-outbound BLOCK +
// allow-set disable (survival and app-own rules excluded) -> rollback to
// the recorded snapshot on any failure; exact disable restore;
// keep-or-release uninstall. Implemented in T007.

#pragma once

#include <windows.h>

// module-local status: enable() refused because the audit subcategory is
// unavailable (or the engine is down) and no owner confirmation was given;
// re-call with is_confirmed = TRUE to proceed without prompts
#define STATUS_LOCKDOWN_CONFIRM ((NTSTATUS)0xC05D0001L)

NTSTATUS _app_lockdown_enable (
	_In_ BOOLEAN is_confirmed
);

NTSTATUS _app_lockdown_disable (
	VOID
);

BOOLEAN _app_lockdown_isactive (
	VOID
);

VOID _app_lockdown_startupcheck (
	VOID
);

BOOLEAN _app_lockdown_uninstallhook (
	_In_opt_ HWND hwnd
);
