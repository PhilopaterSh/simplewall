// composite_audit: machine-wide audit-policy lifecycle (SEC-03, DEC-03).
// Enables the WFP connection-audit subcategory at install/enable and
// reverts it exactly at uninstall/disable, with a startup crash-residue
// check and an inventory sidecar (DATA-01). In-process Audit* APIs only —
// no auditpol.exe child process (SEC-05). Implemented in T001.

#pragma once

#include <windows.h>

NTSTATUS _app_audit_enable (VOID);
NTSTATUS _app_audit_revert (VOID);
VOID _app_audit_startupcheck (VOID);
BOOLEAN _app_audit_issubcategoryenabled (VOID);
