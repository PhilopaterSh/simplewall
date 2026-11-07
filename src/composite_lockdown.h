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

NTSTATUS _app_lockdown_enable (_In_ HWND hwnd);
NTSTATUS _app_lockdown_disable (_In_ HWND hwnd);
BOOLEAN _app_lockdown_isactive (VOID);
