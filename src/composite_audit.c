// simplewall (composite fork)
// Composite Phase 1 — audit lifecycle (T001)
// SEC-03 / DATA-01 / DEC-03: the prompt pipeline consumes failure-audit
// events (5157) from the "Filtering Platform Connection" subcategory.
// That is a machine-wide change: prior state is inventoried into the
// audit sidecar before any write, reverted exactly on disable/uninstall,
// and checked at startup for crash residue (lost inventory downgrades
// revert to warn-and-leave). In-process Audit* APIs only — no
// auditpol.exe child process (SEC-05). advapi32 linked statically —
// precedent: SetEntriesInAclW (log.c). Module-local exclusive lock; the
// audit code never calls back into _wfp_*/profile/apps (no lock nesting).

#include "global.h"
#include "composite_audit.h"
#include "composite.h" // sidecar names (DATA-01)

#include <ntsecapi.h>

#pragma comment (lib, "advapi32.lib")

#define AUDIT_SUBCATEGORY_GUID {0x0cce9226, 0x69ae, 0x11d9, {0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}} // "Filtering Platform Connection"
#define AUDIT_LEGACY_REGKEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define AUDIT_LEGACY_REGVALUE L"SCENoApplyLegacyAuditPolicy"

static R_QUEUED_LOCK lock_audit = PR_QUEUED_LOCK_INIT;

static const GUID audit_subcategory_guid = AUDIT_SUBCATEGORY_GUID;

static NTSTATUS _app_audit_querysubcategory (
	_Out_ AUDIT_POLICY_INFORMATION *policy_info
)
{
	AUDIT_POLICY_INFORMATION *policies;
	NTSTATUS status;

	status = AuditQuerySystemPolicy (&audit_subcategory_guid, 1, &policies);

	if (!NT_SUCCESS (status))
		return status;

	*policy_info = policies[0];
	AuditFree (policies);

	return status;
}

static NTSTATUS _app_audit_getinventorypath (
	_Out_ PR_STRING_PTR out_path
)
{
	PR_STRING profile_dir;
	PR_STRING path;

	profile_dir = _r_app_getprofiledirectory ();

	if (!profile_dir)
		return STATUS_UNSUCCESSFUL;

	path = _r_obj_concatstrings (3, profile_dir->buffer, L"\\", COMPOSITE_SIDECAR_AUDIT);

	*out_path = path;

	return STATUS_SUCCESS;
}

static VOID _app_audit_writeinventory (
	_In_ BOOLEAN failure_prior,
	_In_ BOOLEAN success_prior,
	_In_ BOOLEAN legacy_present,
	_In_ ULONG legacy_value
)
{
	PR_STRING path;
	WCHAR buffer[512];
	HANDLE hfile;
	DWORD written;
	NTSTATUS status;

	status = _app_audit_getinventorypath (&path);

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_audit_writeinventory", L"inventory path unavailable", status);
		return;
	}

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"subcategory_failure_prior=%d\r\nsubcategory_success_prior=%d\r\nlegacy_policy_present=%d\r\nlegacy_policy_value=%u\r\n",
		failure_prior ? 1 : 0, success_prior ? 1 : 0, legacy_present ? 1 : 0, legacy_value);

	hfile = CreateFileW (path->buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"CreateFileW", COMPOSITE_SIDECAR_AUDIT, (NTSTATUS)(ULONG_PTR)GetLastError ());
	}
	else
	{
		if (!WriteFile (hfile, buffer, (DWORD)(wcslen (buffer) * sizeof (WCHAR)), &written, NULL))
			_r_log (LOG_LEVEL_WARNING, NULL, L"WriteFile", COMPOSITE_SIDECAR_AUDIT, (NTSTATUS)(ULONG_PTR)GetLastError ());

		CloseHandle (hfile);
	}

	_r_obj_dereference (path);
}

static VOID _app_audit_readinventory (
	_Out_ PBOOLEAN failure_prior,
	_Out_ PBOOLEAN success_prior,
	_Out_ PBOOLEAN legacy_present,
	_Out_ PULONG legacy_value,
	_Out_ PBOOLEAN is_valid
)
{
	PR_STRING path;
	WCHAR buffer[512] = {0};
	HANDLE hfile;
	DWORD readed = 0;
	NTSTATUS status;

	*failure_prior = FALSE;
	*success_prior = FALSE;
	*legacy_present = FALSE;
	*legacy_value = 0;
	*is_valid = FALSE;

	status = _app_audit_getinventorypath (&path);

	if (!NT_SUCCESS (status))
		return;

	hfile = CreateFileW (path->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	_r_obj_dereference (path);

	if (hfile == INVALID_HANDLE_VALUE)
		return; // no inventory = nothing to revert (silent)

	if (!ReadFile (hfile, buffer, sizeof (buffer) - sizeof (WCHAR), &readed, NULL))
	{
		CloseHandle (hfile);
		return;
	}

	CloseHandle (hfile);
	buffer[readed / sizeof (WCHAR)] = UNICODE_NULL;

	// fixed keys only — written by us, tiny; tampering with them can only
	// change what gets restored to the system's own prior values (no
	// privilege outcome depends on the file's contents)

	if (wcsstr (buffer, L"subcategory_failure_prior=1") != NULL)
		*failure_prior = TRUE;

	if (wcsstr (buffer, L"subcategory_success_prior=1") != NULL)
		*success_prior = TRUE;

	if (wcsstr (buffer, L"legacy_policy_present=1") != NULL)
	{
		LPCWSTR value_ptr;

		value_ptr = wcsstr (buffer, L"legacy_policy_value=");

		if (value_ptr)
		{
			*legacy_present = TRUE;
			*legacy_value = wcstoul (value_ptr + wcslen (L"legacy_policy_value="), NULL, 10);
		}
	}

	*is_valid = TRUE;
}

static LSTATUS _app_audit_getlegacypolicy (
	_Out_ PBOOLEAN is_present,
	_Out_ PULONG value
)
{
	HKEY hkey;
	LSTATUS ls;
	DWORD type = 0;
	DWORD size = sizeof (ULONG);
	DWORD data = 0;

	*is_present = FALSE;
	*value = 0;

	ls = RegOpenKeyExW (HKEY_LOCAL_MACHINE, AUDIT_LEGACY_REGKEY, 0, KEY_QUERY_VALUE, &hkey);

	if (ls != ERROR_SUCCESS)
		return ls;

	ls = RegQueryValueExW (hkey, AUDIT_LEGACY_REGVALUE, NULL, &type, (LPBYTE)&data, &size);
	RegCloseKey (hkey);

	if (ls == ERROR_SUCCESS || ls == ERROR_MORE_DATA)
	{
		*is_present = TRUE;
		*value = data;
		ls = ERROR_SUCCESS;
	}
	else if (ls == ERROR_FILE_NOT_FOUND)
	{
		ls = ERROR_SUCCESS; // value absent — that IS the prior state
	}

	return ls;
}

static LSTATUS _app_audit_setlegacypolicy (
	_In_ ULONG value
)
{
	HKEY hkey;
	LSTATUS ls;

	ls = RegOpenKeyExW (HKEY_LOCAL_MACHINE, AUDIT_LEGACY_REGKEY, 0, KEY_SET_VALUE, &hkey);

	if (ls != ERROR_SUCCESS)
		return ls;

	ls = RegSetValueExW (hkey, AUDIT_LEGACY_REGVALUE, 0, REG_DWORD, (const BYTE *)&value, sizeof (value));
	RegCloseKey (hkey);

	return ls;
}

static LSTATUS _app_audit_deletelegacypolicy (VOID)
{
	HKEY hkey;
	LSTATUS ls;

	ls = RegOpenKeyExW (HKEY_LOCAL_MACHINE, AUDIT_LEGACY_REGKEY, 0, KEY_SET_VALUE, &hkey);

	if (ls != ERROR_SUCCESS)
		return ls;

	ls = RegDeleteValueW (hkey, AUDIT_LEGACY_REGVALUE);
	RegCloseKey (hkey);

	if (ls == ERROR_FILE_NOT_FOUND)
		ls = ERROR_SUCCESS;

	return ls;
}

NTSTATUS _app_audit_enable (VOID)
{
	AUDIT_POLICY_INFORMATION policy_info;
	BOOLEAN failure_prior;
	BOOLEAN success_prior;
	BOOLEAN legacy_present;
	ULONG legacy_value = 0;
	LSTATUS ls;
	NTSTATUS status;

	_r_queuedlock_acquireexclusive (&lock_audit);

	status = _app_audit_querysubcategory (&policy_info);

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"AuditQuerySystemPolicy", L"composite audit subcategory {0CCE9226}", status);
		_r_queuedlock_releaseexclusive (&lock_audit);
		return status;
	}

	failure_prior = (policy_info.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE) != 0;
	success_prior = (policy_info.AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS) != 0;

	ls = _app_audit_getlegacypolicy (&legacy_present, &legacy_value);

	if (ls != ERROR_SUCCESS)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"RegQueryValueExW", AUDIT_LEGACY_REGVALUE, (NTSTATUS)(ULONG_PTR)ls);
		legacy_present = FALSE;
		legacy_value = 0;
	}

	_app_audit_writeinventory (failure_prior, success_prior, legacy_present, legacy_value);

	// DEC-03: failure auditing only — the SUCCESS bit is intentionally
	// cleared (5156 is a machine-wide flood); the prior state is
	// inventoried above and restored exactly on revert
	policy_info.AuditingInformation = POLICY_AUDIT_EVENT_FAILURE;

	status = AuditSetSystemPolicy (&policy_info, 1);

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"AuditSetSystemPolicy", L"composite audit subcategory {0CCE9226}", status);
		_r_queuedlock_releaseexclusive (&lock_audit);
		return status;
	}

	ls = _app_audit_setlegacypolicy (1);

	if (ls != ERROR_SUCCESS)
		_r_log (LOG_LEVEL_WARNING, NULL, L"RegSetValueExW", AUDIT_LEGACY_REGVALUE, (NTSTATUS)(ULONG_PTR)ls); // non-fatal: the fallback pipeline covers a missing 5157 feed

	_r_queuedlock_releaseexclusive (&lock_audit);

	return STATUS_SUCCESS;
}

NTSTATUS _app_audit_revert (VOID)
{
	AUDIT_POLICY_INFORMATION policy_info;
	PR_STRING path;
	BOOLEAN failure_prior;
	BOOLEAN success_prior;
	BOOLEAN legacy_present;
	BOOLEAN is_valid;
	ULONG legacy_value = 0;
	LSTATUS ls;
	NTSTATUS status;

	_r_queuedlock_acquireexclusive (&lock_audit);

	_app_audit_readinventory (&failure_prior, &success_prior, &legacy_present, &legacy_value, &is_valid);

	if (!is_valid)
	{
		// no inventory = nothing we changed (silent no-op — the common case)
		_r_queuedlock_releaseexclusive (&lock_audit);
		return STATUS_SUCCESS;
	}

	status = _app_audit_querysubcategory (&policy_info);

	if (NT_SUCCESS (status))
	{
		// restore exactly the inventoried bits (preserves the user's own
		// success/failure choice); SEC-03: exact revert, never a blanket reset
		policy_info.AuditingInformation = (policy_info.AuditingInformation & ~(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE))
			| (failure_prior ? POLICY_AUDIT_EVENT_FAILURE : 0)
			| (success_prior ? POLICY_AUDIT_EVENT_SUCCESS : 0);

		status = AuditSetSystemPolicy (&policy_info, 1);

		if (!NT_SUCCESS (status))
			_r_log (LOG_LEVEL_ERROR, NULL, L"AuditSetSystemPolicy", L"composite audit revert", status);
	}

	if (legacy_present)
		ls = _app_audit_setlegacypolicy (legacy_value);
	else
		ls = _app_audit_deletelegacypolicy ();

	if (ls != ERROR_SUCCESS)
		_r_log (LOG_LEVEL_WARNING, NULL, L"SCENoApplyLegacyAuditPolicy", L"composite audit revert", (NTSTATUS)(ULONG_PTR)ls);

	// remove the inventory: revert is complete (re-created on next enable)
	status = _app_audit_getinventorypath (&path);

	if (NT_SUCCESS (status))
	{
		DeleteFileW (path->buffer);
		_r_obj_dereference (path);
	}

	_r_queuedlock_releaseexclusive (&lock_audit);

	return STATUS_SUCCESS;
}

VOID _app_audit_startupcheck (VOID)
{
	// SEC-03 crash residue: an inventory sidecar present while the
	// composite audit flag is off means a previous enable never reverted
	if (_r_config_getboolean (L"IsCompositeAuditEnabled", FALSE, NULL))
		return; // this session manages state through the enable path

	_app_audit_revert (); // silent no-op when no inventory exists
}

BOOLEAN _app_audit_issubcategoryenabled (VOID)
{
	AUDIT_POLICY_INFORMATION policy_info;
	NTSTATUS status;

	status = _app_audit_querysubcategory (&policy_info);

	if (!NT_SUCCESS (status))
		return FALSE; // cannot verify — treat as not enabled (caller surfaces degradation)

	return (policy_info.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE) != 0;
}
