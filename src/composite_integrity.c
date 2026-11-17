// composite_integrity: FR-12 config-directory ACL hardening (P2-2).
// The profile directory holds every composite sidecar (ledger baseline,
// pack state, watermarks, lockdown snapshot, audit inventory)  —  writable by
// default, so the DACL is hardened to the DEC-03 policy: Administrators FULL,
// SYSTEM FULL, process-token user READ, applied PROTECTED (inherited
// user-writable ACEs are stripped). Applied once per session after the
// startup checks; failures are logged and non-fatal (the app must never
// refuse to start over its own hardening). Note: simplewall self-elevates at
// startup (APP_NO_GUEST), so all config writers run elevated; the one
// exception is the declined-UAC debug-log write, which fails silently here
// once hardened (non-fatal, documented RSK-2).

#include "global.h"
#include "composite_integrity.h"

NTSTATUS _app_integrity_hardenacl (VOID)
{
	PR_STRING profile_dir;
	PACL dacl_result = NULL;
	PSID admins_sid = NULL;
	PSID system_sid = NULL;
	PSID user_sid = NULL;
	HANDLE token_handle = NULL;
	PTOKEN_USER token_user = NULL;
	ULONG token_user_size = 0;
	SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
	EXPLICIT_ACCESSW accesses[3];
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

	// DEC-03: the interactive-user READ ACE is pinned to the PROCESS-TOKEN
	// user (not the Interactive well-known group  —  shared-host widening);
	// review-corrected: SYSTEM is granted FULL (the previous code granted
	// READ|EXECUTE against its own header)
	if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY, &token_handle))
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		FreeSid (admins_sid);
		FreeSid (system_sid);
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"OpenProcessToken", status);
		return status;
	}

	if (!GetTokenInformation (token_handle, TokenUser, NULL, 0, &token_user_size) && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		CloseHandle (token_handle);
		FreeSid (admins_sid);
		FreeSid (system_sid);
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"GetTokenInformation (size)", status);
		return status;
	}

	token_user = (PTOKEN_USER)_r_mem_allocate ((SIZE_T)token_user_size);

	if (!GetTokenInformation (token_handle, TokenUser, token_user, token_user_size, &token_user_size))
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_mem_free (token_user);
		CloseHandle (token_handle);
		FreeSid (admins_sid);
		FreeSid (system_sid);
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"GetTokenInformation", status);
		return status;
	}

	user_sid = token_user->User.Sid;

	ZeroMemory (accesses, sizeof (accesses));

	accesses[0].grfAccessPermissions = FILE_ALL_ACCESS;
	accesses[0].grfAccessMode = GRANT_ACCESS;
	accesses[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	accesses[0].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
	accesses[0].Trustee.ptstrName = (LPWSTR)admins_sid;

	accesses[1].grfAccessPermissions = FILE_ALL_ACCESS;
	accesses[1].grfAccessMode = GRANT_ACCESS;
	accesses[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	accesses[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	accesses[1].Trustee.ptstrName = (LPWSTR)system_sid;

	accesses[2].grfAccessPermissions = FILE_GENERIC_READ;
	accesses[2].grfAccessMode = GRANT_ACCESS;
	accesses[2].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
	accesses[2].Trustee.TrusteeType = TRUSTEE_IS_USER;
	accesses[2].Trustee.ptstrName = (LPWSTR)user_sid;

	result = SetEntriesInAclW (RTL_NUMBER_OF (accesses), accesses, NULL, &dacl_result);

	if (result != ERROR_SUCCESS)
	{
		status = HRESULT_FROM_WIN32 (result);
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", L"SetEntriesInAclW", status);
		_r_mem_free (token_user);
		CloseHandle (token_handle);
		FreeSid (admins_sid);
		FreeSid (system_sid);
		return status;
	}

	// security-fixes (FR-3/DEC-03): the SetEntriesInAclW result IS the PACL -
	// it is passed DIRECTLY to SetNamedSecurityInfoW (the previous code passed
	// it to GetSecurityDescriptorDacl, which expects a self-relative SECURITY
	// DESCRIPTOR  —  type confusion, hardening silently never applied); the
	// PROTECTED flag strips inherited user-writable ACEs; failures are logged
	// and non-fatal (NFR-01) - an unexpected ACL failure means the hardening
	// did not apply, never that the app refuses to start
	result = SetNamedSecurityInfoW (
		(LPWSTR)profile_dir->buffer,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
		NULL,
		NULL,
		dacl_result,
		NULL
	);

	status = (NTSTATUS)result;

	if (status != STATUS_SUCCESS)
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_integrity", profile_dir->buffer, (LONG)status);
	else
		_r_log (LOG_LEVEL_INFO, NULL, L"composite_integrity", L"profile directory DACL hardened (PROTECTED, three-ACE policy)", (LONG)0);

	_r_mem_free (token_user);
	CloseHandle (token_handle);
	FreeSid (admins_sid);
	FreeSid (system_sid);
	LocalFree (dacl_result);

	return status;
}
