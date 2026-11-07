// simplewall (composite fork)
// Composite Phase 1 — audit lifecycle (T001, rev2 after goldfish review)
// SEC-03 / DATA-01 / DEC-03: the prompt pipeline consumes failure-audit
// events (5157) from the "Filtering Platform Connection" subcategory.
// That is a machine-wide change: the PRIOR state is inventoried into the
// audit sidecar exactly once (before the first write), reverted exactly
// on disable/uninstall, and checked at startup for crash residue.
// In-process Audit* APIs only — no auditpol.exe child process (SEC-05).
// NOTE: AuditQuerySystemPolicy/AuditSetSystemPolicy return BOOLEAN and
// report errors via GetLastError (NTSecAPI.h) — every failure maps to a
// failure HRESULT so NT_SUCCESS plumbing stays honest.
// Module-local exclusive lock; audit code never calls back into
// _wfp_*/profile/apps (no lock nesting).

#include "global.h"
#include "composite_audit.h"
#include "composite.h"

#include <ntsecapi.h>

#pragma comment (lib, "advapi32.lib")

#define AUDIT_SUBCATEGORY_GUID {0x0cce9226, 0x69ae, 0x11d9, {0xbe, 0xd3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30}} // "Filtering Platform Connection"
#define AUDIT_LEGACY_REGKEY L"SYSTEM\\CurrentControlSet\\Control\\Lsa"
#define AUDIT_LEGACY_REGVALUE L"SCENoApplyLegacyAuditPolicy"
#define AUDIT_INVENTORY_MAGIC L"composite_audit_inventory_v1"

// single source for the config key (SEC-03 gates + hooks)
#define COMPOSITE_CONFIG_AUDIT L"IsCompositeAuditEnabled"

static R_QUEUED_LOCK lock_audit = PR_QUEUED_LOCK_INIT;

static const GUID audit_subcategory_guid = AUDIT_SUBCATEGORY_GUID;

static NTSTATUS _app_audit_querysubcategory (
	_Out_ AUDIT_POLICY_INFORMATION *policy_info
)
{
	AUDIT_POLICY_INFORMATION *policies = NULL;

	// NOTE: returns BOOLEAN; failures surface through GetLastError
	if (!AuditQuerySystemPolicy (&audit_subcategory_guid, 1, &policies))
		return HRESULT_FROM_WIN32 (GetLastError ());

	*policy_info = policies[0];
	AuditFree (policies);

	return STATUS_SUCCESS;
}

static NTSTATUS _app_audit_setsubcategory (
	_In_ const AUDIT_POLICY_INFORMATION *policy_info
)
{
	// NOTE: returns BOOLEAN; failures surface through GetLastError
	if (!AuditSetSystemPolicy ((PAUDIT_POLICY_INFORMATION)policy_info, 1))
		return HRESULT_FROM_WIN32 (GetLastError ());

	return STATUS_SUCCESS;
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

// inventory format: magic line + 4 fixed key=value lines (our own writer;
// anything else is treated as corrupt and never drives a restore — SEC-03
// warn-and-leave, the sidecar can only ever change what is restored to the
// system's OWN prior values)

static NTSTATUS _app_audit_writeinventory (
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
		return status;
	}

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%s\r\nsubcategory_failure_prior=%d\r\nsubcategory_success_prior=%d\r\nlegacy_policy_present=%d\r\nlegacy_policy_value=%u\r\n",
		AUDIT_INVENTORY_MAGIC, failure_prior ? 1 : 0, success_prior ? 1 : 0, legacy_present ? 1 : 0, legacy_value);

	hfile = CreateFileW (path->buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_log (LOG_LEVEL_WARNING, NULL, L"CreateFileW", COMPOSITE_SIDECAR_AUDIT, status);
	}
	else
	{
		if (!WriteFile (hfile, buffer, (DWORD)(wcslen (buffer) * sizeof (WCHAR)), &written, NULL))
		{
			status = HRESULT_FROM_WIN32 (GetLastError ());
			_r_log (LOG_LEVEL_WARNING, NULL, L"WriteFile", COMPOSITE_SIDECAR_AUDIT, status);
		}

		CloseHandle (hfile);
	}

	_r_obj_dereference (path);

	return status;
}

static VOID _app_audit_readinventory (
	_Out_ PBOOLEAN failure_prior,
	_Out_ PBOOLEAN success_prior,
	_Out_ PBOOLEAN legacy_present,
	_Out_ PULONG legacy_value,
	_Out_ PBOOLEAN is_present,   // file exists (readable or not)
	_Out_ PBOOLEAN is_valid      // file exists and matches our format exactly
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
	*is_present = FALSE;
	*is_valid = FALSE;

	status = _app_audit_getinventorypath (&path);

	if (!NT_SUCCESS (status))
		return;

	hfile = CreateFileW (path->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	_r_obj_dereference (path);

	if (hfile == INVALID_HANDLE_VALUE)
		return; // absent — the common no-inventory case

	*is_present = TRUE;

	if (!ReadFile (hfile, buffer, sizeof (buffer) - sizeof (WCHAR), &readed, NULL))
	{
		CloseHandle (hfile);
		return;
	}

	CloseHandle (hfile);
	buffer[readed / sizeof (WCHAR)] = UNICODE_NULL;

	// strict format: magic + all four keys — anything else is corrupt
	// (truncated write, tamper) and MUST NOT drive a restore (SEC-03
	// warn-and-leave; a 0-byte file from a crashed write is realistic)

	if (wcsstr (buffer, AUDIT_INVENTORY_MAGIC) == NULL)
		return;

	if (wcsstr (buffer, L"subcategory_failure_prior=") == NULL
		|| wcsstr (buffer, L"subcategory_success_prior=") == NULL
		|| wcsstr (buffer, L"legacy_policy_present=") == NULL
		|| wcsstr (buffer, L"legacy_policy_value=") == NULL)
		return;

	if (wcsstr (buffer, L"subcategory_failure_prior=1") != NULL)
		*failure_prior = TRUE;

	if (wcsstr (buffer, L"subcategory_success_prior=1") != NULL)
		*success_prior = TRUE;

	if (wcsstr (buffer, L"legacy_policy_present=1") != NULL)
	{
		LPCWSTR value_ptr;

		value_ptr = wcsstr (buffer, L"legacy_policy_value=");

		if (value_ptr)
			*legacy_value = wcstoul (value_ptr + wcslen (L"legacy_policy_value="), NULL, 10);

		*legacy_present = TRUE;
	}

	*is_valid = TRUE;
}

static LSTATUS _app_audit_getlegacypolicy (
	_Out_ PBOOLEAN is_present,
	_Out_ PULONG value,
	_Out_ PBOOLEAN is_dword
)
{
	HKEY hkey;
	LSTATUS ls;
	DWORD type = 0;
	DWORD size = sizeof (ULONG);
	DWORD data = 0;

	*is_present = FALSE;
	*value = 0;
	*is_dword = FALSE;

	ls = RegOpenKeyExW (HKEY_LOCAL_MACHINE, AUDIT_LEGACY_REGKEY, 0, KEY_QUERY_VALUE, &hkey);

	if (ls != ERROR_SUCCESS)
		return ls;

	ls = RegQueryValueExW (hkey, AUDIT_LEGACY_REGVALUE, NULL, &type, (LPBYTE)&data, &size);
	RegCloseKey (hkey);

	if (ls == ERROR_FILE_NOT_FOUND)
		return ERROR_SUCCESS; // absent — that IS the prior state

	if (ls != ERROR_SUCCESS)
		return ls;

	if (type != REG_DWORD || size != sizeof (ULONG))
		return ERROR_INVALID_DATATYPE; // exact restore requires same type — warn-and-leave upstream

	*is_present = TRUE;
	*value = data;
	*is_dword = TRUE;

	return ERROR_SUCCESS;
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

static VOID _app_audit_deleteinventory (VOID)
{
	PR_STRING path;
	NTSTATUS status;

	status = _app_audit_getinventorypath (&path);

	if (NT_SUCCESS (status))
	{
		DeleteFileW (path->buffer);
		_r_obj_dereference (path);
	}
}

NTSTATUS _app_audit_enable (VOID)
{
	AUDIT_POLICY_INFORMATION policy_info;
	BOOLEAN inventory_is_present;
	BOOLEAN inventory_is_valid;
	BOOLEAN failure_prior;
	BOOLEAN success_prior;
	BOOLEAN legacy_present;
	BOOLEAN legacy_is_dword;
	BOOLEAN inventory_secured;
	ULONG legacy_value = 0;
	LSTATUS ls;
	NTSTATUS status;

	_r_queuedlock_acquireexclusive (&lock_audit);

	// goldfish finding 2: the GUI re-applies filters constantly —
	// re-inventorying on every apply would destroy the ORIGINAL prior
	// state. Inventory exactly once: if a valid sidecar already exists,
	// keep it and only re-assert the failure bit.
	_app_audit_readinventory (&failure_prior, &success_prior, &legacy_present, &legacy_value, &inventory_is_present, &inventory_is_valid);

	if (inventory_is_present && !inventory_is_valid)
	{
		// corrupt sidecar — never proceed on unknown prior state (SEC-03
		// warn-and-leave); refuse the machine-wide change entirely
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_audit_enable", L"corrupt audit inventory — refusing to change machine audit state", STATUS_INVALID_PARAMETER);
		_r_queuedlock_releaseexclusive (&lock_audit);
		return STATUS_INVALID_PARAMETER;
	}

	inventory_secured = inventory_is_valid; // original priors already on disk

	if (!inventory_secured)
	{
		// first-ever enable: query + inventory BEFORE any machine write.
		// Any failure here aborts the enable (finding 4: never a machine
		// change without revert data).
		status = _app_audit_querysubcategory (&policy_info);

		if (!NT_SUCCESS (status))
		{
			_r_log (LOG_LEVEL_ERROR, NULL, L"AuditQuerySystemPolicy", L"composite audit subcategory {0CCE9226}", status);
			_r_queuedlock_releaseexclusive (&lock_audit);
			return status;
		}

		failure_prior = (policy_info.AuditingInformation & POLICY_AUDIT_EVENT_FAILURE) != 0;
		success_prior = (policy_info.AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS) != 0;

		ls = _app_audit_getlegacypolicy (&legacy_present, &legacy_value, &legacy_is_dword);

		if (ls != ERROR_SUCCESS || (legacy_present && !legacy_is_dword))
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"RegQueryValueExW", AUDIT_LEGACY_REGVALUE, (NTSTATUS)(ULONG_PTR)ls);
			_r_queuedlock_releaseexclusive (&lock_audit);
			return HRESULT_FROM_WIN32 (ls); // destructive-on-uncertainty refused (finding 8)
		}

		status = _app_audit_writeinventory (failure_prior, success_prior, legacy_present, legacy_value);

		if (!NT_SUCCESS (status))
		{
			_r_queuedlock_releaseexclusive (&lock_audit);
			return status; // no inventory = no machine write (finding 4)
		}

		inventory_secured = TRUE;
	}

	// (re-)assert the DEC-03 posture: failure-only (SUCCESS stays cleared —
	// 5156 is a machine-wide flood; the inventoried prior is what revert restores)
	policy_info.AuditSubCategoryGuid = audit_subcategory_guid;
	policy_info.AuditingInformation = POLICY_AUDIT_EVENT_FAILURE;

	status = _app_audit_setsubcategory (&policy_info);

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"AuditSetSystemPolicy", L"composite audit subcategory {0CCE9226}", status);

		if (inventory_secured && !inventory_is_valid)
			_app_audit_deleteinventory (); // written this call, no change made — remove it

		_r_queuedlock_releaseexclusive (&lock_audit);
		return status;
	}

	ls = _app_audit_setlegacypolicy (1);

	if (ls != ERROR_SUCCESS)
		_r_log (LOG_LEVEL_WARNING, NULL, L"RegSetValueExW", AUDIT_LEGACY_REGVALUE, (NTSTATUS)(ULONG_PTR)ls); // non-fatal: fallback pipeline covers a missing 5157 feed

	_r_queuedlock_releaseexclusive (&lock_audit);

	return STATUS_SUCCESS;
}

NTSTATUS _app_audit_revert (VOID)
{
	AUDIT_POLICY_INFORMATION policy_info;
	BOOLEAN failure_prior;
	BOOLEAN success_prior;
	BOOLEAN legacy_present;
	BOOLEAN inventory_is_present;
	BOOLEAN inventory_is_valid;
	BOOLEAN audit_restored;
	BOOLEAN legacy_restored;
	ULONG legacy_value = 0;
	LSTATUS ls;
	NTSTATUS status;
	NTSTATUS result;

	_r_queuedlock_acquireexclusive (&lock_audit);

	_app_audit_readinventory (&failure_prior, &success_prior, &legacy_present, &legacy_value, &inventory_is_present, &inventory_is_valid);

	if (!inventory_is_present)
	{
		// no inventory = nothing we changed (silent no-op — the common case)
		_r_queuedlock_releaseexclusive (&lock_audit);
		return STATUS_SUCCESS;
	}

	if (!inventory_is_valid)
	{
		// SEC-03 warn-and-leave: corrupt inventory never drives a restore,
		// and the file is KEPT for manual inspection (finding 3)
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_audit_revert", L"corrupt audit inventory — leaving machine audit state untouched, file kept", STATUS_INVALID_PARAMETER);
		_r_queuedlock_releaseexclusive (&lock_audit);
		return STATUS_INVALID_PARAMETER;
	}

	result = STATUS_SUCCESS;
	audit_restored = TRUE;
	legacy_restored = TRUE;

	status = _app_audit_querysubcategory (&policy_info);

	if (NT_SUCCESS (status))
	{
		// restore exactly the inventoried bits (preserves the user's own
		// success/failure choice); SEC-03: exact revert, never a blanket reset
		policy_info.AuditingInformation = (policy_info.AuditingInformation & ~(POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE))
			| (failure_prior ? POLICY_AUDIT_EVENT_FAILURE : 0)
			| (success_prior ? POLICY_AUDIT_EVENT_SUCCESS : 0);

		status = _app_audit_setsubcategory (&policy_info);

		if (!NT_SUCCESS (status))
		{
			audit_restored = FALSE;
			result = status;
			_r_log (LOG_LEVEL_ERROR, NULL, L"AuditSetSystemPolicy", L"composite audit revert", status);
		}
	}
	else
	{
		audit_restored = FALSE;
		result = status;
		_r_log (LOG_LEVEL_ERROR, NULL, L"AuditQuerySystemPolicy", L"composite audit revert", status);
	}

	if (legacy_present)
	{
		ls = _app_audit_setlegacypolicy (legacy_value);
	}
	else
	{
		ls = _app_audit_deletelegacypolicy ();
	}

	if (ls != ERROR_SUCCESS)
	{
		legacy_restored = FALSE;
		result = HRESULT_FROM_WIN32 (ls);
		_r_log (LOG_LEVEL_WARNING, NULL, L"SCENoApplyLegacyAuditPolicy", L"composite audit revert", (NTSTATUS)(ULONG_PTR)ls);
	}

	// goldfish finding 5: the inventory is deleted ONLY when both restores
	// verifiably succeeded — otherwise residue stays recoverable
	// (warn-and-keep), e.g. the unelevated startupcheck path
	if (audit_restored && legacy_restored)
	{
		_app_audit_deleteinventory ();
	}
	else
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_audit_revert", L"inventory kept — revert incomplete, retry later", result);
	}

	_r_queuedlock_releaseexclusive (&lock_audit);

	return result;
}

VOID _app_audit_startupcheck (VOID)
{
	// SEC-03 crash residue: an inventory sidecar present while the
	// composite audit flag is off means a previous enable never reverted
	if (_r_config_getboolean (COMPOSITE_CONFIG_AUDIT, FALSE, NULL))
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
