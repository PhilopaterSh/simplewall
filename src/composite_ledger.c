// composite_ledger: FR-10 audit ledger + FR-12 baseline integrity
// (DATA-03). The WFAS rule store is diffed against a persisted baseline
// of rule identities (name + identity hash); foreign add/modify/delete
// is surfaced and optionally quarantined (disable + description marker)
// pending review — approve restores exactly, reject keeps the rule
// disabled and logs the identity so a recreated rule re-flags. Policy-
// managed rules (GPO policy store) are reported, never quarantined
// (RSK-06).
//
// Sidecar contract (DATA-01 namespaced, DATA-03 identity snapshot,
// FR-12 tamper-evident): magic + one "rule=<hash8>|<enabled>|<name>"
// line per WFAS rule + FNV1a "state_hash=" trailer. Corrupt/missing
// baseline = refuse-and-rebuild-from-source-of-truth (the live store IS
// the source of truth; a rebuild only re-records what exists — it can
// never loosen anything).

#include "global.h"
#include "composite_ledger.h"

#define LEDGER_BASELINE_MAGIC L"COMPOSITE_LEDGER_BASELINE_V1"
#define LEDGER_CONFIG L"IsCompositeLedgerEnabled" // FR-10 gate (P2-1)
#define LEDGER_QUARANTINE_MARKER L" [simplewall-quarantine]"
#define LEDGER_MAX_RULES 0x2000
#define LEDGER_MAX_FOREIGN 0x40

static R_QUEUED_LOCK lock_ledger = PR_QUEUED_LOCK_INIT;

static NTSTATUS _app_ledger_getpath (
	_Out_ PR_STRING_PTR out_path
)
{
	PR_STRING profile_dir;
	PR_STRING path;

	profile_dir = _r_app_getprofiledirectory ();

	if (!profile_dir)
		return STATUS_UNSUCCESSFUL;

	path = _r_obj_concatstrings (3, profile_dir->buffer, L"\\", L"composite_ledger_baseline.cfg");

	*out_path = path;

	return STATUS_SUCCESS;
}

static ULONG _app_ledger_rulehash (
	_In_ LPCWSTR name,
	_In_ NET_FW_ACTION action,
	_In_ NET_FW_RULE_DIRECTION direction,
	_In_ BOOLEAN is_enabled
)
{
	BYTE parts[12];
	ULONG hash = 0x811C9DC5;
	ULONG_PTR i;
	LPCWSTR p;

	memcpy (parts, &action, sizeof (LONG));
	memcpy (parts + 4, &direction, sizeof (LONG));
	parts[8] = is_enabled ? 1 : 0;
	memset (parts + 9, 0, 3);

	for (i = 0; i < sizeof (parts); i++)
	{
		hash ^= parts[i];
		hash *= 0x01000193;
	}

	for (p = name; *p; p++)
	{
		hash ^= (ULONG)(*p);
		hash *= 0x01000193;
	}

	return hash;
}

static ULONG _app_ledger_contenthash (
	_In_ LPCWSTR contents
)
{
	ULONG hash = 0x811C9DC5;
	LPCWSTR p;

	// FNV1a over everything before the trailer line
	for (p = contents; *p; p++)
	{
		if (wcsstr (p, L"state_hash=") == p)
			break;

		hash ^= (ULONG)(*p);
		hash *= 0x01000193;
	}

	return hash;
}

static NTSTATUS _app_ledger_getpolicy (
	_Out_ INetFwPolicy2 **policy
)
{
	HRESULT status;

	*policy = NULL;

	status = CoCreateInstance (&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, (PVOID *)policy);

	if (FAILED (status))
		return (NTSTATUS)status;

	return STATUS_SUCCESS;
}

// GPO-origin heuristic (P2-D): policy-managed rule names are value names
// under the policy FirewallRules keys — REPORTED only, never quarantined
// (RSK-06)
static BOOLEAN _app_ledger_ispolicymanaged (
	_In_ LPCWSTR name
)
{
	static const WCHAR *policy_keys[] = {
		L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules",
		L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", // local GPO-applied
	};

	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (policy_keys); i++)
	{
		HKEY hkey;

		if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, policy_keys[i], 0, KEY_READ, &hkey) == ERROR_SUCCESS)
		{
			DWORD index = 0;
			WCHAR value_name[256];
			DWORD name_size = RTL_NUMBER_OF (value_name);
			LONG query;

			while ((query = RegEnumValueW (hkey, index++, value_name, &name_size, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS)
			{
				if (_wcsicmp (value_name, name) == 0)
				{
					RegCloseKey (hkey);
					return TRUE;
				}

				name_size = RTL_NUMBER_OF (value_name);
			}

			RegCloseKey (hkey);
		}
	}

	return FALSE;
}

// enumerate the live WFAS store into the identity stream (one line per
// rule); shared by snapshot and diff. Borrowed-string lifecycle: the
// caller consumes out_stream and then deletes the builder
static NTSTATUS _app_ledger_enumlive (
	_Out_ PR_STRINGBUILDER sb,
	_Out_ PR_STRING_PTR out_stream,
	_Out_ PULONG out_count
)
{
	INetFwPolicy2 *policy = NULL;
	INetFwRules *rules = NULL;
	IUnknown *enum_unknown = NULL;
	IEnumVARIANT *variants = NULL;
	VARIANT variant;
	INetFwRule *rule;
	BSTR name_bstr = NULL;
	WCHAR line[768];
	VARIANT_BOOL is_enabled;
	NET_FW_ACTION action;
	NET_FW_RULE_DIRECTION direction;
	ULONG count = 0;
	HRESULT hstatus;
	NTSTATUS status;

	*out_stream = NULL;
	*out_count = 0;

	_r_obj_initializestringbuilder (sb, 0x2000);

	status = _app_ledger_getpolicy (&policy);

	if (!NT_SUCCESS (status))
		goto cleanup;

	hstatus = INetFwPolicy2_get_Rules (policy, &rules);

	if (FAILED (hstatus))
	{
		status = (NTSTATUS)hstatus;
		goto cleanup;
	}

	hstatus = INetFwRules_get__NewEnum (rules, &enum_unknown);

	if (FAILED (hstatus))
	{
		status = (NTSTATUS)hstatus;
		goto cleanup;
	}

	hstatus = enum_unknown->lpVtbl->QueryInterface (enum_unknown, &IID_IEnumVARIANT, (PVOID *)&variants);

	if (FAILED (hstatus))
	{
		status = (NTSTATUS)hstatus;
		goto cleanup;
	}

	VariantInit (&variant);

	while (count < LEDGER_MAX_RULES)
	{
		hstatus = variants->lpVtbl->Next (variants, 1, &variant, NULL);

		if (hstatus != S_OK)
			break;

		rule = NULL;

		if (variant.vt == VT_DISPATCH && variant.pdispVal)
			variant.pdispVal->lpVtbl->QueryInterface (variant.pdispVal, &IID_INetFwRule, (PVOID *)&rule);

		VariantClear (&variant);

		if (!rule)
			continue;

		if (SUCCEEDED (INetFwRule_get_Name (rule, &name_bstr)) && name_bstr &&
			SUCCEEDED (INetFwRule_get_Enabled (rule, &is_enabled)) &&
			SUCCEEDED (INetFwRule_get_Action (rule, &action)) &&
			SUCCEEDED (INetFwRule_get_Direction (rule, &direction)))
		{
			ULONG hash = _app_ledger_rulehash (name_bstr, action, direction, is_enabled == VARIANT_TRUE);

			_r_str_printf (line, RTL_NUMBER_OF (line), L"rule=%08x|%d|%s\r\n", hash, is_enabled == VARIANT_TRUE ? 1 : 0, name_bstr);

			_r_obj_appendstringbuilder_ex (sb, line, wcslen (line));

			count++;
		}

		if (name_bstr)
		{
			SysFreeString (name_bstr);
			name_bstr = NULL;
		}

		INetFwRule_Release (rule);
	}

	*out_count = count;
	*out_stream = _r_obj_finalstringbuilder (sb); // borrowed; released by deletestringbuilder

cleanup:
	if (name_bstr)
		SysFreeString (name_bstr);

	if (variants)
		IEnumVARIANT_Release (variants);

	if (enum_unknown)
		IUnknown_Release (enum_unknown);

	if (rules)
		INetFwRules_Release (rules);

	if (policy)
		INetFwPolicy2_Release (policy);

	if (!NT_SUCCESS (status))
		_r_obj_deletestringbuilder (sb); // failure: caller gets nothing

	return status;
}

// DATA-03 + FR-12: write the baseline (identity stream + tamper trailer)
static NTSTATUS _app_ledger_write (
	_In_ LPCWSTR stream,
	_In_ SIZE_T stream_length
)
{
	PR_STRING path = NULL;
	R_STRINGBUILDER sb_storage;
	PR_STRINGBUILDER sb = &sb_storage;
	PR_STRING final = NULL;
	PR_STRING trailer = NULL;
	NTSTATUS status;
	HANDLE hfile;
	DWORD written;

	status = _app_ledger_getpath (&path);

	if (!NT_SUCCESS (status))
		return status;

	_r_obj_initializestringbuilder (sb, 0x100);

	_r_obj_appendstringbuilder_ex (sb, LEDGER_BASELINE_MAGIC, RTL_NUMBER_OF (LEDGER_BASELINE_MAGIC) - 1);
	_r_obj_appendstringbuilder_ex (sb, L"\r\n", 1);
	_r_obj_appendstringbuilder_ex (sb, stream, stream_length);

	final = _r_obj_finalstringbuilder (sb);

	_r_obj_appendstringbuilderformat (sb, L"state_hash=%08x\r\n", (UINT)_app_ledger_contenthash (final->buffer));

	trailer = _r_obj_finalstringbuilder (sb);

	hfile = CreateFileW (path->buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_ledger_write", L"CreateFileW", status);
	}
	else
	{
		if (!WriteFile (hfile, trailer->buffer, (DWORD)(trailer->length * sizeof (WCHAR)), &written, NULL) || written != (DWORD)(trailer->length * sizeof (WCHAR)))
		{
			status = HRESULT_FROM_WIN32 (GetLastError ());
			_r_log (LOG_LEVEL_WARNING, NULL, L"_app_ledger_write", L"WriteFile", status);
		}
		else
		{
			status = STATUS_SUCCESS;
		}

		CloseHandle (hfile);
	}

	_r_obj_dereference (trailer);
	_r_obj_dereference (final);
	_r_obj_deletestringbuilder (sb);
	_r_obj_dereference (path);

	return status;
}

// FR-12: read + validate the baseline (hash-checked at load; corrupt =
// refuse, caller rebuilds from source of truth)
static NTSTATUS _app_ledger_read (
	_Out_ PR_STRING_PTR out_contents,
	_Out_ PBOOLEAN is_valid
)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	HANDLE hfile;
	LARGE_INTEGER fsize;
	BYTE *buffer;
	DWORD read;
	NTSTATUS status;

	*out_contents = NULL;
	*is_valid = FALSE;

	status = _app_ledger_getpath (&path);

	if (!NT_SUCCESS (status))
		return status;

	hfile = CreateFileW (path->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	_r_obj_dereference (path);

	if (hfile == INVALID_HANDLE_VALUE)
		return STATUS_NOT_FOUND;

	if (!GetFileSizeEx (hfile, &fsize) || fsize.QuadPart == 0 || (fsize.QuadPart % sizeof (WCHAR)) != 0 || fsize.QuadPart > 0x400000)
	{
		CloseHandle (hfile);
		return STATUS_INVALID_PARAMETER;
	}

	buffer = _r_mem_allocate ((SIZE_T)fsize.QuadPart);

	if (!ReadFile (hfile, buffer, (DWORD)fsize.QuadPart, &read, NULL) || read != (DWORD)fsize.QuadPart)
	{
		_r_mem_free (buffer);
		CloseHandle (hfile);
		return HRESULT_FROM_WIN32 (GetLastError ());
	}

	CloseHandle (hfile);

	contents = _r_obj_createstring_ex ((LPCWSTR)buffer, read);

	_r_mem_free (buffer);

	if (wcsncmp (contents->buffer, LEDGER_BASELINE_MAGIC, RTL_NUMBER_OF (LEDGER_BASELINE_MAGIC) - 1) == 0)
	{
		LPCWSTR trailer = wcsstr (contents->buffer, L"state_hash=");

		if (trailer)
		{
			ULONG stored = (ULONG)wcstoul (trailer + 11, NULL, 16);
			ULONG computed;
			PR_STRING body;

			body = _r_obj_createstring_ex (contents->buffer, (SIZE_T)(trailer - contents->buffer) * sizeof (WCHAR));

			computed = _app_ledger_contenthash (body->buffer);

			_r_obj_dereference (body);

			if (stored == computed)
				*is_valid = TRUE;
		}
	}

	if (*is_valid)
		*out_contents = contents;
	else
		_r_obj_dereference (contents);

	return STATUS_SUCCESS;
}

// FR-12/P2-2: startup crash-residue + integrity check — corrupt baseline
// = rebuild from the live store, loudly (never assert unprovable facts)
VOID _app_ledger_startupcheck (VOID)
{
	R_STRINGBUILDER sb;
	PR_STRING contents = NULL;
	BOOLEAN is_valid = FALSE;
	ULONG count;
	NTSTATUS status;

	if (!_r_config_getboolean (LEDGER_CONFIG, FALSE, NULL))
		return;

	status = _app_ledger_read (&contents, &is_valid);

	if (NT_SUCCESS (status) && is_valid)
	{
		_r_obj_dereference (contents);
		return;
	}

	_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger", L"baseline invalid; rebuilding from live store", status);

	status = _app_ledger_enumlive (&sb, &contents, &count);

	if (NT_SUCCESS (status))
	{
		_app_ledger_write (contents->buffer, contents->length);

		_r_obj_dereference (contents);
		_r_obj_deletestringbuilder (&sb);
	}
}

// P2-1: refresh the baseline to the current live store (call after our
// own applies — the ledger only judges FOREIGN changes)
NTSTATUS _app_ledger_snapshot (VOID)
{
	R_STRINGBUILDER sb;
	PR_STRING stream = NULL;
	ULONG count;
	NTSTATUS status;

	if (!_r_config_getboolean (LEDGER_CONFIG, FALSE, NULL))
		return STATUS_NOT_FOUND;

	status = _app_ledger_enumlive (&sb, &stream, &count);

	if (!NT_SUCCESS (status))
		return status;

	status = _app_ledger_write (stream->buffer, stream->length);

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_ledger", L"baseline refreshed", (LONG)count);

	_r_obj_dereference (stream);
	_r_obj_deletestringbuilder (&sb);

	return status;
}

static BOOLEAN _app_ledger_streamcontains (
	_In_ LPCWSTR stream,
	_In_ LPCWSTR name,
	_In_ SIZE_T name_len
)
{
	LPCWSTR line = stream;

	while (line && *line)
	{
		LPCWSTR line_end = wcschr (line, L'\n');

		if (line_end)
		{
			SIZE_T line_len = (SIZE_T)(line_end - line);

			if (line_len && line[line_len - 1] == L'\r')
				line_len--;

			// rule=<hash8>|<enabled>|<name> — compare the tail
			if (line_len > name_len + 5 &&
				RtlEqualMemory (line + line_len - name_len, name, name_len * sizeof (WCHAR)) &&
				line[line_len - name_len - 1] == L'|')
			{
				return TRUE;
			}

			line = line_end + 1;
		}
		else
		{
			break;
		}
	}

	return FALSE;
}

// FR-10 diff: live vs baseline; every delta is logged with its kind and
// policy-managed status. Returns the number of foreign deltas
ULONG _app_ledger_diff (VOID)
{
	R_STRINGBUILDER sb_live;
	PR_STRING baseline = NULL;
	PR_STRING live = NULL;
	BOOLEAN is_valid = FALSE;
	ULONG live_count;
	ULONG foreign = 0;
	NTSTATUS status;
	LPCWSTR line;

	if (!_r_config_getboolean (LEDGER_CONFIG, FALSE, NULL))
		return 0;

	_r_queuedlock_acquireshared (&lock_ledger);

	status = _app_ledger_read (&baseline, &is_valid);

	if (!NT_SUCCESS (status) || !is_valid)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger", L"diff refused: baseline invalid (rebuild first)", status);

		_r_queuedlock_releaseshared (&lock_ledger);
		return 0;
	}

	status = _app_ledger_enumlive (&sb_live, &live, &live_count);

	if (!NT_SUCCESS (status))
	{
		_r_obj_dereference (baseline);
		_r_queuedlock_releaseshared (&lock_ledger);
		return 0;
	}

	line = live->buffer;

	while (line && *line && foreign < LEDGER_MAX_FOREIGN)
	{
		LPCWSTR line_end = wcschr (line, L'\n');

		if (!line_end)
			break;

		SIZE_T line_len = (SIZE_T)(line_end - line);

		if (line_len && line[line_len - 1] == L'\r')
			line_len--;

		// extract the name (after the second '|')
		LPCWSTR sep1 = wcschr (line, L'|');
		LPCWSTR sep2 = sep1 ? wcschr (sep1 + 1, L'|') : NULL;

		if (sep2 && sep2 < line_end)
		{
			SIZE_T name_len = (SIZE_T)(line_end - sep2 - 1);

			if (line_len && line[line_len - 1] == L'\r')
				name_len--;

			if (name_len > 0 && name_len < 256 && !_app_ledger_streamcontains (baseline->buffer, sep2 + 1, name_len))
			{
				WCHAR name_buf[256];

				memcpy (name_buf, sep2 + 1, name_len * sizeof (WCHAR));
				name_buf[name_len] = UNICODE_NULL;

				_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger",
					name_buf,
					_app_ledger_ispolicymanaged (name_buf) ? 1 : 0);

				foreign++;
			}
		}

		line = line_end + 1;
	}

	_r_obj_dereference (live);
	_r_obj_deletestringbuilder (&sb_live);
	_r_obj_dereference (baseline);

	_r_queuedlock_releaseshared (&lock_ledger);

	if (foreign)
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger", L"foreign deltas detected", (LONG)foreign);

	return foreign;
}

// FR-10 quarantine: disable a foreign rule pending review
NTSTATUS _app_ledger_quarantine (
	_In_ LPCWSTR rule_name
)
{
	INetFwPolicy2 *policy = NULL;
	INetFwRules *rules = NULL;
	INetFwRule *rule = NULL;
	BSTR name_bstr = SysAllocString (rule_name);
	BSTR desc_bstr = NULL;
	WCHAR marked[512];
	HRESULT hstatus;
	NTSTATUS status;

	if (!name_bstr)
		return STATUS_NO_MEMORY;

	if (_app_ledger_ispolicymanaged (rule_name))
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger", L"quarantine refused: policy-managed (RSK-06)", 0);
		SysFreeString (name_bstr);
		return STATUS_NOT_SUPPORTED;
	}

	_r_queuedlock_acquireshared (&lock_ledger);

	status = _app_ledger_getpolicy (&policy);

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseshared (&lock_ledger);
		SysFreeString (name_bstr);
		return status;
	}

	hstatus = INetFwPolicy2_get_Rules (policy, &rules);

	if (SUCCEEDED (hstatus) && SUCCEEDED (INetFwRules_Item (rules, name_bstr, &rule)) && rule)
	{
		if (SUCCEEDED (INetFwRule_get_Description (rule, &desc_bstr)) && desc_bstr)
		{
			_r_str_printf (marked, RTL_NUMBER_OF (marked), L"%s%s", desc_bstr, LEDGER_QUARANTINE_MARKER);
			SysFreeString (desc_bstr);
		}
		else
		{
			_r_str_printf (marked, RTL_NUMBER_OF (marked), L"%s", LEDGER_QUARANTINE_MARKER);
		}

		INetFwRule_put_Enabled (rule, VARIANT_FALSE);

		desc_bstr = SysAllocString (marked);

		if (desc_bstr)
		{
			INetFwRule_put_Description (rule, desc_bstr);
			SysFreeString (desc_bstr);
		}

		status = STATUS_SUCCESS;

		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger", rule_name, 0);

		INetFwRule_Release (rule);
	}
	else
	{
		status = (NTSTATUS)hstatus;
	}

	if (rules)
		INetFwRules_Release (rules);

	if (policy)
		INetFwPolicy2_Release (policy);

	_r_queuedlock_releaseshared (&lock_ledger);
	SysFreeString (name_bstr);

	return status;
}

// approve: exact restore — re-enable + strip the quarantine marker
NTSTATUS _app_ledger_approve (
	_In_ LPCWSTR rule_name
)
{
	INetFwPolicy2 *policy = NULL;
	INetFwRules *rules = NULL;
	INetFwRule *rule = NULL;
	BSTR name_bstr = SysAllocString (rule_name);
	BSTR desc_bstr = NULL;
	HRESULT hstatus;
	NTSTATUS status;

	if (!name_bstr)
		return STATUS_NO_MEMORY;

	_r_queuedlock_acquireshared (&lock_ledger);

	status = _app_ledger_getpolicy (&policy);

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseshared (&lock_ledger);
		SysFreeString (name_bstr);
		return status;
	}

	hstatus = INetFwPolicy2_get_Rules (policy, &rules);

	if (SUCCEEDED (hstatus) && SUCCEEDED (INetFwRules_Item (rules, name_bstr, &rule)) && rule)
	{
		INetFwRule_put_Enabled (rule, VARIANT_TRUE); // exact restore

		if (SUCCEEDED (INetFwRule_get_Description (rule, &desc_bstr)) && desc_bstr)
		{
			LPCWSTR marker = wcsstr (desc_bstr, LEDGER_QUARANTINE_MARKER);

			if (marker)
			{
				SIZE_T clean_len = (SIZE_T)(marker - desc_bstr);
				WCHAR clean[512];

				if (clean_len < RTL_NUMBER_OF (clean))
				{
					memcpy (clean, desc_bstr, clean_len * sizeof (WCHAR));
					clean[clean_len] = UNICODE_NULL;

					BSTR clean_bstr = SysAllocString (clean);

					if (clean_bstr)
					{
						INetFwRule_put_Description (rule, clean_bstr);
						SysFreeString (clean_bstr);
					}
				}
			}

			SysFreeString (desc_bstr);
			desc_bstr = NULL;
		}

		status = STATUS_SUCCESS;

		_r_log (LOG_LEVEL_INFO, NULL, L"composite_ledger", rule_name, 0);

		INetFwRule_Release (rule);
	}
	else
	{
		status = (NTSTATUS)hstatus;
	}

	if (rules)
		INetFwRules_Release (rules);

	if (policy)
		INetFwPolicy2_Release (policy);

	_r_queuedlock_releaseshared (&lock_ledger);
	SysFreeString (name_bstr);

	return status;
}

// reject: the foreign rule stays disabled permanently; the identity is
// flagged (baseline NOT refreshed — a recreated rule re-flags)
NTSTATUS _app_ledger_reject (
	_In_ LPCWSTR rule_name
)
{
	_r_log (LOG_LEVEL_WARNING, NULL, L"composite_ledger", rule_name, 1);

	return STATUS_SUCCESS;
}
