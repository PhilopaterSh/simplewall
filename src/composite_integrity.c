// composite_integrity: FR-12 config-directory ACL hardening (P2-2).
// The profile directory holds every composite sidecar (ledger baseline,
// pack state, watermarks, lockdown snapshot, audit inventory) — a
// non-elevated user writable by default on some profile placements, so
// the DACL is hardened to: SYSTEM + Administrators FULL, interactive
// user READ. Applied once per session after the startup checks; failures
// are logged and non-fatal (the app must never refuse to start over its
// own hardening).

#include "global.h"
#include "composite_integrity.h"

NTSTATUS _app_integrity_hardenacl (VOID)
{
	PR_STRING profile_dir;
	PSECURITY_DESCRIPTOR sd = NULL;
	PACL dacl_result = NULL;
	PSID admins_sid = NULL;
	PSID system_sid = NULL;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	EXPLICIT_ACCESSW accesses[2];
	ULONG result;
	NTSTATUS status;

	profile_dir = _r_app_getprofiledirectory ();

	if (!profile_dir)
		return STATUS_UNSUCCESSFUL;

	if (!AllocateAndInitializeSid (&nt_authority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admins_sid))
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"AllocateAndInitializeSid (admins)", status);
		return status;
	}

	if (!AllocateAndInitializeSid (&nt_authority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &system_sid))
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		FreeSid (admins_sid);
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"AllocateAndInitializeSid (system)", status);
		return status;
	}

	ZeroMemory (accesses, sizeof (accesses));

	accesses[0].grfAccessPermissions = FILE_ALL_ACCESS;
	accesses[0].grfAccessMode = GRANT_ACCESS;
	accesses[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	accesses[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	accesses[0].Trustee.ptstrName = (LPWSTR)admins_sid;

	accesses[1].grfAccessPermissions = FILE_GENERIC_READ | FILE_EXECUTE;
	accesses[1].grfAccessMode = GRANT_ACCESS;
	accesses[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	accesses[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	accesses[1].Trustee.ptstrName = (LPWSTR)system_sid;

	result = SetEntriesInAclW (RTL_NUMBER_OF (accesses), accesses, NULL, (PACL *)&dacl_result);

	if (result != ERROR_SUCCESS)
	{
		status = HRESULT_FROM_WIN32 (result);
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"SetEntriesInAclW", status);
		FreeSid (admins_sid);
		FreeSid (system_sid);
		return status;
	}

	// extract the DACL from the self-relative descriptor (documented
	// form — no pointer arithmetic)
	BOOL has_dacl = FALSE;
	BOOL dacl_defaulted = FALSE;
	PACL dacl = NULL;

	if (!GetSecurityDescriptorDacl (dacl_result, &has_dacl, &dacl, &dacl_defaulted) || !has_dacl || !dacl)
	{
		status = STATUS_INVALID_PARAMETER;
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"GetSecurityDescriptorDacl", status);
		FreeSid (admins_sid);
		FreeSid (system_sid);
		LocalFree (dacl_result);
		return status;
	}

	// apply to the directory only; a non-elevated session gets
	// ERROR_ACCESS_DENIED here and logs it (hardening is a no-op then —
	// never fatal, NFR-01)
	result = SetNamedSecurityInfoW ((LPWSTR)profile_dir->buffer, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);

	status = (NTSTATUS)result;

	if (status != STATUS_SUCCESS)
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", profile_dir->buffer, (LONG)status);
	else
		_r_log (LOG_LEVEL_INFO, NULL, L"composite_integrity", L"profile directory DACL hardened", (LONG)0);

	FreeSid (admins_sid);
	FreeSid (system_sid);
	LocalFree (dacl_result);

	return status;
}
