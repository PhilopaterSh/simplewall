#include "global.h"
#include "composite_lockdown.h"
#include "composite_audit.h" // audit pre-flight (FR-06 step 2)

// composite T007 (FR-06, DEC-04): Lockdown = WFAS-layer defense-in-depth
// backstop. While simplewall's own WFP sublayer (FWW_SUBLAYER weight) is
// healthy its verdicts govern; when the engine degrades, is disabled, or
// the app is stopped, the WFAS seal governs instead. Enable sequence
// (exact order per DEC-04): (1) record per-profile defaults + existing
// outbound-allow rule set + sublayer weight into the sidecar BEFORE any
// machine change, (2) audit pre-flight — if the 5157 subcategory cannot
// be enabled the caller must have confirmed running without connection
// prompts (the seal itself does not depend on audit), (3) pre-create
// service-scoped survival rules (svchost + Dhcp/CryptSvc + WSL/Hyper-V
// ICS; port-wide allows are rejected by design because they dissolve the
// seal), (4) DefaultOutboundAction = BLOCK per profile, (5) disable the
// recorded outbound-allow set (survival + app-own excluded). Any failure
// rolls back to the recorded snapshot — never an unconditional ALLOW, so
// a host already sealed tighter is never loosened. Disable restores the
// snapshot exactly. Uninstall while engaged asks keep-or-release
// (default release). Residual risk accepted by threat model (RSK-07):
// another elevated process can flip these flags back.

#define LOCKDOWN_SNAPSHOT_MAGIC L"COMPOSITE_LOCKDOWN_SNAPSHOT_V1"
#define LOCKDOWN_CONFIG L"IsCompositeLockdownEngaged" // FR-06 gate (T007)
#define LOCKDOWN_SURVIVAL_PREFIX L"simplewall-composite-survival-"
#define LOCKDOWN_OWN_PREFIX L"simplewall" // app-own WFAS rules are never touched (FR-06)
#define LOCKDOWN_MAX_RULES 0x800          // sanity bound on recorded allow rules

static R_QUEUED_LOCK lock_lockdown = PR_QUEUED_LOCK_INIT;

static const WCHAR *lockdown_survival_names[] = {
	LOCKDOWN_SURVIVAL_PREFIX L"dhcp",
	LOCKDOWN_SURVIVAL_PREFIX L"cryptsvc",
	LOCKDOWN_SURVIVAL_PREFIX L"ics",
};

static const WCHAR *lockdown_survival_services[] = {
	L"Dhcp",
	L"CryptSvc",
	L"SharedAccess", // WSL/Hyper-V Internet Connection Sharing
};

static BOOLEAN _app_lockdown_lineis (
	_In_ LPCWSTR line,
	_In_ SIZE_T line_length,
	_In_ LPCWSTR prefix
)
{
	SIZE_T prefix_length = wcslen (prefix);

	if (line_length < prefix_length)
		return FALSE;

	return RtlEqualMemory (line, prefix, prefix_length * sizeof (WCHAR));
}

static NTSTATUS _app_lockdown_getpolicy (
	_Out_ INetFwPolicy2 **policy
)
{
	HRESULT status;

	*policy = NULL;

	status = CoCreateInstance (&CLSID_NetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwPolicy2, (PVOID *)policy);

	if (FAILED (status))
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_lockdown_getpolicy", L"CoCreateInstance INetFwPolicy2", status);
		return (NTSTATUS)status;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS _app_lockdown_getdefoutbound (
	_In_ INetFwPolicy2 *policy,
	_In_ NET_FW_PROFILE_TYPE2 profile,
	_Out_ NET_FW_ACTION *action
)
{
	HRESULT status;

	status = INetFwPolicy2_get_DefaultOutboundAction (policy, profile, action);

	if (FAILED (status))
		_r_log_v (LOG_LEVEL_WARNING, NULL, L"get_DefaultOutboundAction", status, L"%d", (INT)profile);

	return (NTSTATUS)status;
}

static NTSTATUS _app_lockdown_setdefoutbound (
	_In_ INetFwPolicy2 *policy,
	_In_ NET_FW_PROFILE_TYPE2 profile,
	_In_ NET_FW_ACTION action
)
{
	HRESULT status;

	status = INetFwPolicy2_put_DefaultOutboundAction (policy, profile, action);

	if (FAILED (status))
		_r_log_v (LOG_LEVEL_WARNING, NULL, L"put_DefaultOutboundAction", status, L"%d", (INT)profile);

	return (NTSTATUS)status;
}

static NTSTATUS _app_lockdown_getsnapshotpath (
	_Out_ PR_STRING_PTR out_path
)
{
	PR_STRING profile_dir;
	PR_STRING path;

	profile_dir = _r_app_getprofiledirectory ();

	if (!profile_dir)
		return STATUS_UNSUCCESSFUL;

	path = _r_obj_concatstrings (3, profile_dir->buffer, L"\\", L"composite_lockdown.cfg");

	*out_path = path;

	return STATUS_SUCCESS;
}

// read the whole snapshot file into a string; caller derefs
static NTSTATUS _app_lockdown_reads (
	_Out_ PR_STRING_PTR out_contents,
	_Out_ PBOOLEAN is_present
)
{
	PR_STRING path;
	PR_STRING contents;
	HANDLE hfile;
	LARGE_INTEGER fsize;
	BYTE *buffer;
	DWORD read;
	NTSTATUS status;

	*out_contents = NULL;
	*is_present = FALSE;

	status = _app_lockdown_getsnapshotpath (&path);

	if (!NT_SUCCESS (status))
		return status;

	hfile = CreateFileW (path->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		_r_obj_dereference (path);
		return STATUS_NOT_FOUND;
	}

	*is_present = TRUE;

	if (!GetFileSizeEx (hfile, &fsize) || fsize.QuadPart == 0 || (fsize.QuadPart % sizeof (WCHAR)) != 0 || fsize.QuadPart > 0x100000)
	{
		CloseHandle (hfile);
		_r_obj_dereference (path);
		return STATUS_INVALID_PARAMETER; // wrong size class = corrupt
	}

	buffer = _r_mem_allocate ((SIZE_T)fsize.QuadPart);

	if (!ReadFile (hfile, buffer, (DWORD)fsize.QuadPart, &read, NULL) || read != (DWORD)fsize.QuadPart)
	{
		_r_mem_free (buffer);
		CloseHandle (hfile);
		_r_obj_dereference (path);
		return HRESULT_FROM_WIN32 (GetLastError ());
	}

	CloseHandle (hfile);

	contents = _r_obj_createstring_ex ((LPCWSTR)buffer, (SIZE_T)read);

	_r_mem_free (buffer);
	_r_obj_dereference (path);

	*out_contents = contents;

	return STATUS_SUCCESS;
}

// snapshot format: magic line, then fixed "key=value" lines, then one
// line per recorded outbound-allow rule: "ruleN=<enabled>|<name>".
// Anything else is corrupt and never drives a restore (same warn-and-
// leave contract as the audit inventory: the sidecar can only restore
// the system's OWN prior values, never an unconditional ALLOW)
static NTSTATUS _app_lockdown_writesnapshot (
	_In_ INetFwPolicy2 *policy,
	_In_ LONG sublayer_prior
)
{
	NET_FW_PROFILE_TYPE2 profile_types[] = {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
	LPCWSTR profile_names[] = {L"domain", L"private", L"public"};
	INetFwRules *rules = NULL;
	IUnknown *rules_enum_unknown = NULL;
	IEnumVARIANT *rules_enum = NULL;
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	PR_STRINGBUILDER sb;
	VARIANT variant;
	INetFwRule *rule;
	BSTR name_bstr = NULL;
	VARIANT_BOOL is_enabled;
	NET_FW_ACTION action;
	NET_FW_RULE_DIRECTION direction;
	NET_FW_ACTION default_action;
	ULONG snapshot_count;
	HRESULT hstatus;
	NTSTATUS status;
	HANDLE hfile;
	DWORD written;
	ULONG_PTR i;

	status = _app_lockdown_getsnapshotpath (&path);

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_lockdown_writesnapshot", L"snapshot path unavailable", status);
		return status;
	}

	_r_obj_initializestringbuilder (sb, 0x1000);

	_r_obj_appendstringbuilder_ex (sb, LOCKDOWN_SNAPSHOT_MAGIC, RTL_NUMBER_OF (LOCKDOWN_SNAPSHOT_MAGIC) - 1);

	// per-profile defaults (FR-06 step 1)
	for (i = 0; i < RTL_NUMBER_OF (profile_types); i++)
	{
		status = _app_lockdown_getdefoutbound (policy, profile_types[i], &default_action);

		if (!NT_SUCCESS (status))
			goto cleanup;

		_r_obj_appendstringbuilderformat (sb, L"defaultoutbound_%s=%ld\r\n", profile_names[i], default_action);
	}

	_r_obj_appendstringbuilderformat (sb, L"sublayer_prior=%ld\r\n", sublayer_prior);

	// record the enabled outbound-allow rule set
	hstatus = INetFwPolicy2_get_Rules (policy, &rules);

	if (FAILED (hstatus))
	{
		status = (NTSTATUS)hstatus;
		goto cleanup;
	}

	hstatus = INetFwRules_get__NewEnum (rules, &rules_enum_unknown);

	if (FAILED (hstatus))
	{
		status = (NTSTATUS)hstatus;
		goto cleanup;
	}

	hstatus = rules_enum_unknown->lpVtbl->QueryInterface (rules_enum_unknown, &IID_IEnumVARIANT, (PVOID *)&rules_enum);

	if (FAILED (hstatus))
	{
		status = (NTSTATUS)hstatus;
		goto cleanup;
	}

	snapshot_count = 0;

	VariantInit (&variant);

	while (snapshot_count < LOCKDOWN_MAX_RULES)
	{
		hstatus = rules_enum->lpVtbl->Next (rules_enum, 1, &variant, NULL);

		if (hstatus != S_OK)
			break;

		rule = NULL;

		if (variant.vt == VT_DISPATCH && variant.pdispVal)
			variant.pdispVal->lpVtbl->QueryInterface (variant.pdispVal, &IID_INetFwRule, (PVOID *)&rule);

		VariantClear (&variant);

		if (!rule)
			continue;

		if (SUCCEEDED (INetFwRule_get_Enabled (rule, &is_enabled)) && is_enabled == VARIANT_TRUE &&
			SUCCEEDED (INetFwRule_get_Action (rule, &action)) && action == NET_FW_ACTION_ALLOW &&
			SUCCEEDED (INetFwRule_get_Direction (rule, &direction)) && direction == NET_FW_RULE_DIR_OUT &&
			SUCCEEDED (INetFwRule_get_Name (rule, &name_bstr)) && name_bstr)
		{
			// survival rules (created later, same prefix family) and our
			// own WFAS rules are never recorded (FR-06 exclusions)
			if (wcsncmp (name_bstr, LOCKDOWN_OWN_PREFIX, RTL_NUMBER_OF (LOCKDOWN_OWN_PREFIX) - 1) != 0)
			{
				_r_obj_appendstringbuilderformat (sb, L"rule%u=1|%s\r\n", (UINT)snapshot_count, name_bstr);
				snapshot_count++;
			}

			SysFreeString (name_bstr);
			name_bstr = NULL;
		}

		INetFwRule_Release (rule);
	}

	// write the sidecar BEFORE any machine change (inventory-before-
	// any-machine-write, same contract as SEC-03)
	contents = _r_obj_finalstringbuilder (sb);

	hfile = CreateFileW (path->buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_lockdown_writesnapshot", L"CreateFileW", status);
		goto cleanup;
	}

	if (!WriteFile (hfile, contents->buffer, (DWORD)(contents->length * sizeof (WCHAR)), &written, NULL) || written != (DWORD)(contents->length * sizeof (WCHAR)))
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_lockdown_writesnapshot", L"WriteFile", status);
	}
	else
	{
		status = STATUS_SUCCESS;
	}

	CloseHandle (hfile);

cleanup:
	_r_obj_deletestringbuilder (sb);

	if (contents)
		_r_obj_dereference (contents);

	if (name_bstr)
		SysFreeString (name_bstr);

	if (rules_enum)
		IEnumVARIANT_Release (rules_enum);

	if (rules_enum_unknown)
		IUnknown_Release (rules_enum_unknown);

	if (rules)
		INetFwRules_Release (rules);

	_r_obj_dereference (path);

	return status;
}

// FR-06 step 3: service-scoped survival rules (svchost + service name);
// they exist for exactly the degraded/absent case where our own permits
// are gone. Port-wide app rules are deliberately NOT created
static NTSTATUS _app_lockdown_createsurvival (
	_In_ INetFwPolicy2 *policy
)
{
	WCHAR svchost_path[MAX_PATH];
	WCHAR description[256];
	INetFwRules *rules = NULL;
	INetFwRule *rule = NULL;
	BSTR name_bstr = NULL;
	BSTR desc_bstr = NULL;
	BSTR app_bstr = NULL;
	BSTR service_bstr = NULL;
	HRESULT hstatus;
	NTSTATUS status = STATUS_SUCCESS;
	UINT length;
	ULONG_PTR i;

	if (!GetSystemDirectoryW (svchost_path, RTL_NUMBER_OF (svchost_path)))
		return HRESULT_FROM_WIN32 (GetLastError ());

	length = (UINT)wcslen (svchost_path);

	if (length + 1 + 12 + 1 > RTL_NUMBER_OF (svchost_path)) // + "\svchost.exe"
		return STATUS_NAME_TOO_LONG;

	wcscat_s (svchost_path, RTL_NUMBER_OF (svchost_path), L"\\svchost.exe");

	hstatus = INetFwPolicy2_get_Rules (policy, &rules);

	if (FAILED (hstatus))
		return (NTSTATUS)hstatus;

	for (i = 0; i < RTL_NUMBER_OF (lockdown_survival_names); i++)
	{
		// idempotent: a leftover survival rule from an unfinished round is
		// reused, not duplicated
		hstatus = INetFwRules_Item (rules, (BSTR)lockdown_survival_names[i], &rule);

		if (SUCCEEDED (hstatus) && rule)
		{
			INetFwRule_Release (rule);
			rule = NULL;
			continue;
		}

		hstatus = CoCreateInstance (&CLSID_NetFwRule, NULL, CLSCTX_INPROC_SERVER, &IID_INetFwRule, (PVOID *)&rule);

		if (FAILED (hstatus))
		{
			status = (NTSTATUS)hstatus;
			goto cleanup;
		}

		_r_str_printf (description, RTL_NUMBER_OF (description), L"simplewall composite survival rule (%s)", lockdown_survival_services[i]);

		name_bstr = SysAllocString (lockdown_survival_names[i]);
		desc_bstr = SysAllocString (description);
		app_bstr = SysAllocString (svchost_path);
		service_bstr = SysAllocString (lockdown_survival_services[i]);

		if (!name_bstr || !desc_bstr || !app_bstr || !service_bstr)
		{
			status = STATUS_NO_MEMORY;
			goto cleanup_loop;
		}

		INetFwRule_put_Name (rule, name_bstr);
		INetFwRule_put_Description (rule, desc_bstr);
		INetFwRule_put_ApplicationName (rule, app_bstr);
		INetFwRule_put_ServiceName (rule, service_bstr);
		INetFwRule_put_Direction (rule, NET_FW_RULE_DIR_OUT);
		INetFwRule_put_Action (rule, NET_FW_ACTION_ALLOW);
		INetFwRule_put_Enabled (rule, VARIANT_TRUE);
		INetFwRule_put_Profiles (rule, NET_FW_PROFILE2_ALL);

		hstatus = INetFwRules_Add (rules, rule);

		if (FAILED (hstatus))
		{
			status = (NTSTATUS)hstatus;
			goto cleanup_loop;
		}

cleanup_loop:
		if (name_bstr)
		{
			SysFreeString (name_bstr);
			name_bstr = NULL;
		}

		if (desc_bstr)
		{
			SysFreeString (desc_bstr);
			desc_bstr = NULL;
		}

		if (app_bstr)
		{
			SysFreeString (app_bstr);
			app_bstr = NULL;
		}

		if (service_bstr)
		{
			SysFreeString (service_bstr);
			service_bstr = NULL;
		}

		if (rule)
		{
			INetFwRule_Release (rule);
			rule = NULL;
		}

		if (!NT_SUCCESS (status))
			goto cleanup;
	}

cleanup:
	if (name_bstr)
		SysFreeString (name_bstr);

	if (desc_bstr)
		SysFreeString (desc_bstr);

	if (app_bstr)
		SysFreeString (app_bstr);

	if (service_bstr)
		SysFreeString (service_bstr);

	if (rule)
		INetFwRule_Release (rule);

	if (rules)
		INetFwRules_Release (rules);

	return status;
}

// FR-06 step 5: disable every currently-enabled outbound-allow rule that
// is neither app-own nor a survival rule — exactly the set the snapshot
// recorded (re-derived live so there is no name-list drift)
static VOID _app_lockdown_disablerecorded (
	_In_ INetFwPolicy2 *policy
)
{
	INetFwRules *rules = NULL;
	IUnknown *rules_enum_unknown = NULL;
	IEnumVARIANT *rules_enum = NULL;
	VARIANT variant;
	INetFwRule *rule;
	BSTR name_bstr = NULL;
	VARIANT_BOOL is_enabled;
	NET_FW_ACTION action;
	NET_FW_RULE_DIRECTION direction;
	HRESULT hstatus;

	hstatus = INetFwPolicy2_get_Rules (policy, &rules);

	if (FAILED (hstatus))
		return;

	hstatus = INetFwRules_get__NewEnum (rules, &rules_enum_unknown);

	if (FAILED (hstatus))
	{
		INetFwRules_Release (rules);
		return;
	}

	hstatus = rules_enum_unknown->lpVtbl->QueryInterface (rules_enum_unknown, &IID_IEnumVARIANT, (PVOID *)&rules_enum);

	if (FAILED (hstatus))
	{
		IUnknown_Release (rules_enum_unknown);
		INetFwRules_Release (rules);
		return;
	}

	VariantInit (&variant);

	while (rules_enum->lpVtbl->Next (rules_enum, 1, &variant, NULL) == S_OK)
	{
		rule = NULL;

		if (variant.vt == VT_DISPATCH && variant.pdispVal)
			variant.pdispVal->lpVtbl->QueryInterface (variant.pdispVal, &IID_INetFwRule, (PVOID *)&rule);

		VariantClear (&variant);

		if (!rule)
			continue;

		if (SUCCEEDED (INetFwRule_get_Enabled (rule, &is_enabled)) && is_enabled == VARIANT_TRUE &&
			SUCCEEDED (INetFwRule_get_Action (rule, &action)) && action == NET_FW_ACTION_ALLOW &&
			SUCCEEDED (INetFwRule_get_Direction (rule, &direction)) && direction == NET_FW_RULE_DIR_OUT &&
			SUCCEEDED (INetFwRule_get_Name (rule, &name_bstr)) && name_bstr)
		{
			if (wcsncmp (name_bstr, LOCKDOWN_OWN_PREFIX, RTL_NUMBER_OF (LOCKDOWN_OWN_PREFIX) - 1) != 0)
				INetFwRule_put_Enabled (rule, VARIANT_FALSE); // best-effort; failures leave the rule recorded in the snapshot for restore

			SysFreeString (name_bstr);
			name_bstr = NULL;
		}

		INetFwRule_Release (rule);
	}

	IEnumVARIANT_Release (rules_enum);
	IUnknown_Release (rules_enum_unknown);
	INetFwRules_Release (rules);
}

// restore from the sidecar: per-profile defaults, sublayer weight, the
// recorded rules' enabled state, and survival-rule removal. Corrupt or
// missing snapshot = refuse (warn-and-leave), never an unconditional
// ALLOW (FR-06/DEC-04)
static NTSTATUS _app_lockdown_rollback (
	_In_ INetFwPolicy2 *policy
)
{
	PR_STRING contents = NULL;
	PR_STRING path = NULL;
	PR_STRING name_string;
	BSTR name_bstr = NULL;
	INetFwRules *rules = NULL;
	INetFwRule *rule = NULL;
	VARIANT_BOOL is_enabled;
	LONG sublayer_prior;
	LONG value;
	BOOLEAN is_present;
	NTSTATUS status;
	LPCWSTR line;
	LPCWSTR line_end;
	SIZE_T line_length;
	WCHAR name_buffer[512];
	ULONG_PTR i;

	status = _app_lockdown_reads (&contents, &is_present);

	if (!NT_SUCCESS (status) || !is_present)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_lockdown", L"rollback refused: snapshot missing", status);
		return STATUS_INVALID_PARAMETER;
	}

	if (wcsncmp (contents->buffer, LOCKDOWN_SNAPSHOT_MAGIC, RTL_NUMBER_OF (LOCKDOWN_SNAPSHOT_MAGIC) - 1) != 0)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_lockdown", L"rollback refused: snapshot corrupt", (LONG)0);
		_r_obj_dereference (contents);
		return STATUS_INVALID_PARAMETER;
	}

	// parse key=value lines
	line = contents->buffer;

	while (line && *line)
	{
		line_end = wcschr (line, L'\n');

		line_length = line_end ? (SIZE_T)(line_end - line) : wcslen (line);

		if (line_length && line[line_length - 1] == L'\r')
			line_length--;

		name_string = NULL;

		if (_app_lockdown_lineis (line, line_length, L"defaultoutbound_domain="))
		{
			value = wcstol (line + wcslen (L"defaultoutbound_domain="), NULL, 10);
			_app_lockdown_setdefoutbound (policy, NET_FW_PROFILE2_DOMAIN, (NET_FW_ACTION)value);
		}
		else if (_app_lockdown_lineis (line, line_length, L"defaultoutbound_private="))
		{
			value = wcstol (line + wcslen (L"defaultoutbound_private="), NULL, 10);
			_app_lockdown_setdefoutbound (policy, NET_FW_PROFILE2_PRIVATE, (NET_FW_ACTION)value);
		}
		else if (_app_lockdown_lineis (line, line_length, L"defaultoutbound_public="))
		{
			value = wcstol (line + wcslen (L"defaultoutbound_public="), NULL, 10);
			_app_lockdown_setdefoutbound (policy, NET_FW_PROFILE2_PUBLIC, (NET_FW_ACTION)value);
		}
		else if (_app_lockdown_lineis (line, line_length, L"sublayer_prior="))
		{
			sublayer_prior = wcstol (line + wcslen (L"sublayer_prior="), NULL, 10);
			_r_config_setlong (L"SublayerWeight", sublayer_prior, NULL);
		}
		else if (line_length > 5 && RtlEqualMemory (line, L"rule", 4 * sizeof (WCHAR)))
		{
			// ruleN=<enabled>|<name>
			LPCWSTR sep = wcschr (line, L'|');

			if (sep && sep < line + line_length)
			{
				value = wcstol (&line[5], NULL, 10);

				SIZE_T name_length = (SIZE_T)(line + line_length - sep - 1);

				if (name_length > 0 && name_length < RTL_NUMBER_OF (name_buffer))
				{
					memcpy (name_buffer, sep + 1, name_length * sizeof (WCHAR));
					name_buffer[name_length] = UNICODE_NULL;

					name_string = _r_obj_createstring (name_buffer);
				}
			}
		}

		if (name_string)
		{
			// restore on first use of the rules collection
			if (!rules)
			{
				if (FAILED (INetFwPolicy2_get_Rules (policy, &rules)))
				{
					_r_obj_dereference (name_string);
					break;
				}
			}

			name_bstr = SysAllocString (name_string->buffer);

			if (name_bstr)
			{
				if (SUCCEEDED (INetFwRules_Item (rules, name_bstr, &rule)) && rule)
				{
					is_enabled = value ? VARIANT_TRUE : VARIANT_FALSE;

					INetFwRule_put_Enabled (rule, is_enabled); // best-effort

					INetFwRule_Release (rule);
				}

				SysFreeString (name_bstr);
			}

			_r_obj_dereference (name_string);
		}

		line = line_end ? line_end + 1 : NULL;
	}

	// survival rules are removed last (exact-revert-only contract)
	if (rules)
	{
		for (i = 0; i < RTL_NUMBER_OF (lockdown_survival_names); i++)
		{
			name_bstr = SysAllocString (lockdown_survival_names[i]);

			if (name_bstr)
			{
				INetFwRules_Remove (rules, name_bstr); // best-effort exact removal

				SysFreeString (name_bstr);
			}
		}

		INetFwRules_Release (rules);
	}

	// snapshot deleted only after restore (hardening r1 contract)
	status = _app_lockdown_getsnapshotpath (&path);

	if (NT_SUCCESS (status))
	{
		DeleteFileW (path->buffer);
		_r_obj_dereference (path);
	}

	_r_obj_dereference (contents);

	return STATUS_SUCCESS;
}

NTSTATUS _app_lockdown_enable (
	_In_ BOOLEAN is_confirmed
)
{
	NET_FW_PROFILE_TYPE2 profile_types[] = {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
	INetFwPolicy2 *policy = NULL;
	NTSTATUS status;
	LONG sublayer_prior;
	NET_FW_ACTION default_action;

	_r_queuedlock_acquireexclusive (&lock_lockdown);

	if (_r_config_getboolean (LOCKDOWN_CONFIG, FALSE, NULL))
	{
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return STATUS_ALREADY_REGISTERED; // already engaged
	}

	status = _app_lockdown_getpolicy (&policy);

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return status;
	}

	// refuse to engage over an engine that cannot govern (arbitration
	// contract: healthy engine outranks the seal; without the engine the
	// seal is the ONLY protection, which the design allows but the caller
	// must have confirmed)
	if (!_wfp_isfiltersinstalled () && !is_confirmed)
	{
		INetFwPolicy2_Release (policy);
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return STATUS_LOCKDOWN_CONFIRM;
	}

	// FR-06 step 2 (audit pre-flight) before the snapshot so an aborted
	// confirmation leaves NO sidecar behind
	status = _app_audit_enable ();

	if (!NT_SUCCESS (status) && !is_confirmed)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_lockdown", L"audit subcategory unavailable; owner confirmation required to run without prompts", status);
		INetFwPolicy2_Release (policy);
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return STATUS_LOCKDOWN_CONFIRM;
	}

	// FR-06 step 1: snapshot BEFORE any machine change
	sublayer_prior = _r_config_getlong (L"SublayerWeight", FWW_SUBLAYER, NULL);

	status = _app_lockdown_writesnapshot (policy, sublayer_prior);

	if (!NT_SUCCESS (status))
	{
		INetFwPolicy2_Release (policy); // enable aborts without revert data
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return status;
	}

	// FR-06 step 3: pre-create the service-scoped survival rules
	status = _app_lockdown_createsurvival (policy);

	if (!NT_SUCCESS (status))
	{
		_app_lockdown_rollback (policy); // pre-commit abort
		INetFwPolicy2_Release (policy);
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return status;
	}

	// FR-06 step 4: the seal
	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (profile_types); i++)
	{
		status = _app_lockdown_setdefoutbound (policy, profile_types[i], NET_FW_ACTION_BLOCK);

		if (!NT_SUCCESS (status))
		{
			_app_lockdown_rollback (policy); // post-commit rollback path
			INetFwPolicy2_Release (policy);
			_r_queuedlock_releaseexclusive (&lock_lockdown);
			return status;
		}
	}

	// FR-06 step 5: disable the recorded outbound-allow set (survival and
	// app-own rules excluded)
	_app_lockdown_disablerecorded (policy);

	// pin our sublayer weight while engaged so the arbitration contract
	// (healthy engine governs) cannot be lost to a config edit
	_r_config_setlong (L"SublayerWeight", FWW_SUBLAYER, NULL);

	// verify the seal landed before claiming engagement (record-verify-
	// commit recipe)
	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (profile_types); i++)
	{
		if (!NT_SUCCESS (_app_lockdown_getdefoutbound (policy, profile_types[i], &default_action)) || default_action != NET_FW_ACTION_BLOCK)
		{
			_app_lockdown_rollback (policy);
			INetFwPolicy2_Release (policy);
			_r_queuedlock_releaseexclusive (&lock_lockdown);
			return STATUS_INVALID_PARAMETER;
		}
	}

	_r_config_setboolean (LOCKDOWN_CONFIG, TRUE, NULL);

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_lockdown", L"engaged", (LONG)0);

	INetFwPolicy2_Release (policy);
	_r_queuedlock_releaseexclusive (&lock_lockdown);

	return STATUS_SUCCESS;
}

NTSTATUS _app_lockdown_disable (VOID)
{
	INetFwPolicy2 *policy = NULL;
	NTSTATUS status;

	_r_queuedlock_acquireexclusive (&lock_lockdown);

	if (!_r_config_getboolean (LOCKDOWN_CONFIG, FALSE, NULL))
	{
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return STATUS_NOT_FOUND;
	}

	status = _app_lockdown_getpolicy (&policy);

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return status;
	}

	status = _app_lockdown_rollback (policy);

	INetFwPolicy2_Release (policy);

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseexclusive (&lock_lockdown);
		return status; // keep the engaged flag: a partial restore must not lie
	}

	_r_config_setboolean (LOCKDOWN_CONFIG, FALSE, NULL);

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_lockdown", L"released", (LONG)0);

	_r_queuedlock_releaseexclusive (&lock_lockdown);

	return STATUS_SUCCESS;
}

BOOLEAN _app_lockdown_isactive (VOID)
{
	return _r_config_getboolean (LOCKDOWN_CONFIG, FALSE, NULL);
}

// startup crash-residue consistency check (mirrors _app_audit_startupcheck)
VOID _app_lockdown_startupcheck (VOID)
{
	NET_FW_PROFILE_TYPE2 profile_types[] = {NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC};
	INetFwPolicy2 *policy = NULL;
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	BOOLEAN is_present = FALSE;
	NET_FW_ACTION default_action;
	NTSTATUS status;

	if (!_r_config_getboolean (LOCKDOWN_CONFIG, FALSE, NULL))
		return;

	status = _app_lockdown_reads (&contents, &is_present);

	if (!is_present || !NT_SUCCESS (status) || !contents ||
		wcsncmp (contents->buffer, LOCKDOWN_SNAPSHOT_MAGIC, RTL_NUMBER_OF (LOCKDOWN_SNAPSHOT_MAGIC) - 1) != 0)
	{
		// engaged but no valid snapshot = crash residue during enable;
		// never leave the flag claiming a seal we cannot prove or restore
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_lockdown", L"engaged without valid snapshot; clearing flag", status);

		_r_config_setboolean (LOCKDOWN_CONFIG, FALSE, NULL);

		if (contents)
			_r_obj_dereference (contents);

		return;
	}

	if (contents)
		_r_obj_dereference (contents);

	// verify the seal still holds; a flipped profile is logged (another
	// elevated process may have reverted it — RSK-07, accepted)
	if (NT_SUCCESS (_app_lockdown_getpolicy (&policy)))
	{
		for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (profile_types); i++)
		{
			if (NT_SUCCESS (_app_lockdown_getdefoutbound (policy, profile_types[i], &default_action)) && default_action != NET_FW_ACTION_BLOCK)
				_r_log_v (LOG_LEVEL_WARNING, NULL, L"composite_lockdown", 0, L"profile %d no longer sealed", (INT)profile_types[i]);
		}

		INetFwPolicy2_Release (policy);
	}
}

// uninstall keep-or-release hook (FR-06/DEC-04): returns TRUE when the
// caller may proceed; the default is release (full revert)
BOOLEAN _app_lockdown_uninstallhook (
	_In_opt_ HWND hwnd
)
{
	INT result;

	if (!_app_lockdown_isactive ())
		return TRUE;

	result = _r_show_message (hwnd, MB_YESNO | MB_ICONWARNING, NULL,
		L"Lockdown mode is engaged.\r\n\r\n"
		L"Yes: keep the system sealed (WFAS default-outbound BLOCK stays; the snapshot is kept for a later restore)\r\n"
		L"No: release Lockdown and restore your previous firewall settings (default)");

	if (result != IDYES)
		return NT_SUCCESS (_app_lockdown_disable ());

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_lockdown", L"kept across uninstall (owner choice)", (LONG)0);

	return TRUE;
}
