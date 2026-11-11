// composite_integrity: FR-12 config-directory ACL hardening (P2-2).
#pragma once

#include <windows.h>

// harden the profile directory DACL: SYSTEM + Administrators FULL,
// interactive user READ; non-fatal on failure (logged)
NTSTATUS _app_integrity_hardenacl (
	VOID
);
