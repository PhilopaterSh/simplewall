#include "global.h"
#include "composite_audit.h"

// T001: inventory prior state via AuditQuerySystemPolicy into the audit
// sidecar, enable subcategory {0CCE9226-69AE-11D9-BED3-505054503030}
// (+ SCENoApplyLegacyAuditPolicy), verify before any Lockdown commit
// (DEC-04 step 2), revert exactly on disable/uninstall; lost inventory
// downgrades revert to warn-and-leave (SEC-03).

NTSTATUS _app_audit_enable (VOID)
{
	return STATUS_NOT_IMPLEMENTED; // T001
}

NTSTATUS _app_audit_revert (VOID)
{
	return STATUS_NOT_IMPLEMENTED; // T001
}

VOID _app_audit_startupcheck (VOID)
{
}

BOOLEAN _app_audit_issubcategoryenabled (VOID)
{
	return FALSE; // T001
}
