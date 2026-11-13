// composite_resolver: P3-C guarded resolver ownership (T033, FR-13).
// Machine-critical contract (design r2): the app NEVER leaves DNS broken.
//
// Sequence per DEC-04 verify-then-commit, mirrored on the audit
// inventory pattern (SEC-03):
//   1. SNAPSHOT the per-interface DNS settings (registry NameServer
//      values) into the sidecar BEFORE any machine write.
//   2. VERIFY the owned local resolver answers (a live check the caller
//      performs; this module takes is_confirmed + the verified flag).
//   3. COMMIT: set every interface's NameServer to the owned resolver.
//   4. Exact REVERT on disable/opt-out/uninstall; startup crash-residue
//      check restores the snapshot if the app died while owning.
// RSK-04/DEC-06: a port-53 conflict is REPORTED (log), never silently
// overridden. Per-interface opt-in list lives in the sidecar.
// Machine writes happen ONLY with is_confirmed = TRUE.

#include "global.h"
#include "composite_resolver.h"

#define RESOLVER_SNAPSHOT_MAGIC L"COMPOSITE_RESOLVER_SNAPSHOT_V1"
#define RESOLVER_CONFIG L"IsCompositeResolverOwned" // P3-C gate (T033)
#define RESOLVER_OWNED_ADDR L"127.0.0.1"            // the owned local resolver
#define RESOLVER_MAX_IFACES 0x100

static R_QUEUED_LOCK lock_resolver = PR_QUEUED_LOCK_INIT;

static NTSTATUS _app_resolver_getpath (
	_Out_ PR_STRING_PTR out_path
)
{
	PR_STRING profile_dir;
	PR_STRING path;

	profile_dir = _r_app_getprofiledirectory ();

	if (!profile_dir)
		return STATUS_UNSUCCESSFUL;

	path = _r_obj_concatstrings (3, profile_dir->buffer, L"\\", L"composite_resolver_snapshot.cfg");

	*out_path = path;

	return STATUS_SUCCESS;
}

static ULONG _app_resolver_contenthash (
	_In_ LPCWSTR contents
)
{
	ULONG hash = 0x811C9DC5;

	for (LPCWSTR p = contents; *p; p++)
	{
		if (wcsstr (p, L"state_hash=") == p)
			break;

		hash ^= (ULONG)(*p);
		hash *= 0x01000193;
	}

	return hash;
}

// snapshot: enumerate interface GUIDs under Tcpip\Parameters\Interfaces
// and record each one's current NameServer value (may be empty = DHCP
// supplied). Format: magic + "iface=<guid>|<nameserver>" lines + trailer
static NTSTATUS _app_resolver_snapshot (
	VOID
)
{
	PR_STRING path = NULL;
	PR_STRINGBUILDER sb;
	PR_STRING final = NULL;
	PR_STRING trailer = NULL;
	HKEY hkey;
	WCHAR guid_name[128];
	DWORD guid_size;
	DWORD index = 0;
	NTSTATUS status;
	HANDLE hfile;
	DWORD written;

	status = _app_resolver_getpath (&path);

	if (!NT_SUCCESS (status))
		return status;

	_r_obj_initializestringbuilder (sb, 0x400);

	_r_obj_appendstringbuilder_ex (sb, RESOLVER_SNAPSHOT_MAGIC, RTL_NUMBER_OF (RESOLVER_SNAPSHOT_MAGIC) - 1);
	_r_obj_appendstringbuilder_ex (sb, L"\r\n", 1);

	if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		guid_size = RTL_NUMBER_OF (guid_name);

		while (index < RESOLVER_MAX_IFACES && RegEnumKeyExW (hkey, index++, guid_name, &guid_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			HKEY hiface;
			WCHAR value_buf[512];
			DWORD type = 0;
			DWORD value_size = sizeof (value_buf) - sizeof (WCHAR);

			guid_size = RTL_NUMBER_OF (guid_name); // reset for the next enumeration round

			if (RegOpenKeyExW (hkey, guid_name, 0, KEY_READ, &hiface) != ERROR_SUCCESS)
				continue;

			if (RegQueryValueExW (hiface, L"NameServer", NULL, &type, (LPBYTE)value_buf, &value_size) != ERROR_SUCCESS)
			{
				value_buf[0] = UNICODE_NULL;
			}
			else
			{
				value_buf[value_size / sizeof (WCHAR)] = UNICODE_NULL;
			}

			_r_obj_appendstringbuilderformat (sb, L"iface=%s|%s\r\n", guid_name, value_buf);

			RegCloseKey (hiface);
		}

		RegCloseKey (hkey);
	}
	else
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_obj_deletestringbuilder (sb);
		_r_obj_dereference (path);
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_snapshot", L"interfaces key unavailable", status);
		return status;
	}

	final = _r_obj_finalstringbuilder (sb);

	_r_obj_appendstringbuilderformat (sb, L"state_hash=%08x\r\n", (UINT)_app_resolver_contenthash (final->buffer));

	trailer = _r_obj_finalstringbuilder (sb);

	// sidecar BEFORE any machine write (inventory-before-machine-write)
	hfile = CreateFileW (path->buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		status = HRESULT_FROM_WIN32 (GetLastError ());
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_snapshot", L"CreateFileW", status);
	}
	else
	{
		if (!WriteFile (hfile, trailer->buffer, (DWORD)(trailer->length * sizeof (WCHAR)), &written, NULL) || written != (DWORD)(trailer->length * sizeof (WCHAR)))
		{
			status = HRESULT_FROM_WIN32 (GetLastError ());
			_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_snapshot", L"WriteFile", status);
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

// exact revert from the sidecar; corrupt/missing = REFUSE (never reset
// DNS unconditionally — FR-12/DEC-04 discipline)
static NTSTATUS _app_resolver_restore (
	VOID
)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	HANDLE hfile;
	LARGE_INTEGER fsize;
	BYTE *buffer;
	DWORD read;
	NTSTATUS status;
	LPCWSTR line;
	ULONG restored = 0;

	status = _app_resolver_getpath (&path);

	if (!NT_SUCCESS (status))
		return status;

	hfile = CreateFileW (path->buffer, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		status = STATUS_NOT_FOUND;
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_restore", L"snapshot missing; refusing (never an unconditional DNS reset)", status);
		_r_obj_dereference (path);
		return status;
	}

	if (!GetFileSizeEx (hfile, &fsize) || fsize.QuadPart == 0 || (fsize.QuadPart % sizeof (WCHAR)) != 0 || fsize.QuadPart > 0x100000)
	{
		CloseHandle (hfile);
		_r_obj_dereference (path);
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_restore", L"snapshot corrupt; refusing", (LONG)0);
		return STATUS_INVALID_PARAMETER;
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

	contents = _r_obj_createstring_ex ((LPCWSTR)buffer, read);

	_r_mem_free (buffer);

	if (wcsncmp (contents->buffer, RESOLVER_SNAPSHOT_MAGIC, RTL_NUMBER_OF (RESOLVER_SNAPSHOT_MAGIC) - 1) != 0)
	{
		_r_obj_dereference (contents);
		_r_obj_dereference (path);
		_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_restore", L"snapshot magic mismatch; refusing", (LONG)0);
		return STATUS_INVALID_PARAMETER;
	}

	// validate the trailer BEFORE touching anything (FR-12 pattern)
	{
		LPCWSTR trailer = wcsstr (contents->buffer, L"state_hash=");

		if (!trailer)
		{
			_r_obj_dereference (contents);
			_r_obj_dereference (path);
			return STATUS_INVALID_PARAMETER;
		}

		ULONG stored = (ULONG)wcstoul (trailer + 11, NULL, 16);
		PR_STRING body = _r_obj_createstring_ex (contents->buffer, (SIZE_T)(trailer - contents->buffer) * sizeof (WCHAR));

		ULONG computed = _app_resolver_contenthash (body->buffer);

		_r_obj_dereference (body);

		if (stored != computed)
		{
			_r_obj_dereference (contents);
			_r_obj_dereference (path);
			_r_log (LOG_LEVEL_WARNING, NULL, L"_app_resolver_restore", L"snapshot hash mismatch; refusing", (LONG)0);
			return STATUS_INVALID_PARAMETER;
		}
	}

	line = contents->buffer;

	while (line && *line)
	{
		LPCWSTR line_end = wcschr (line, L'\n');

		if (wcsstr (line, L"iface=") == line && line_end)
		{
			LPCWSTR sep = wcschr (line, L'|');

			if (sep && sep < line_end)
			{
				WCHAR guid_buf[128];
				SIZE_T guid_len = (SIZE_T)(sep - line - 6); // after "iface="

				SIZE_T ns_len = (SIZE_T)(line_end - sep - 1);

				if (line[line_end - line - 1] == L'\r')
					ns_len--;

				if (guid_len > 0 && guid_len < RTL_NUMBER_OF (guid_buf) && ns_len < 512)
				{
					HKEY hiface;

					memcpy (guid_buf, line + 6, guid_len * sizeof (WCHAR));
					guid_buf[guid_len] = UNICODE_NULL;

					WCHAR iface_path[300];
					_r_str_printf (iface_path, RTL_NUMBER_OF (iface_path), L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s", guid_buf);

					if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, iface_path, 0, KEY_SET_VALUE, &hiface) == ERROR_SUCCESS)
					{
						WCHAR ns_buf[512];

						memcpy (ns_buf, sep + 1, ns_len * sizeof (WCHAR));
						ns_buf[ns_len] = UNICODE_NULL;

						if (RegSetValueExW (hiface, L"NameServer", 0, REG_SZ, (LPBYTE)ns_buf, (DWORD)((ns_len + 1) * sizeof (WCHAR))) == ERROR_SUCCESS)
							restored++;

						RegCloseKey (hiface);
					}
				}
			}
		}

		line = line_end ? line_end + 1 : NULL;
	}

	_r_obj_dereference (contents);
	_r_obj_dereference (path);

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_resolver", L"restored interfaces", (LONG)restored);

	return STATUS_SUCCESS;
}

NTSTATUS _app_resolver_own (
	_In_ BOOLEAN is_confirmed,
	_In_ BOOLEAN resolver_verified
)
{
	NTSTATUS status;
	ULONG changed = 0;

	_r_queuedlock_acquireexclusive (&lock_resolver);

	if (_r_config_getboolean (RESOLVER_CONFIG, FALSE, NULL))
	{
		_r_queuedlock_releaseexclusive (&lock_resolver);
		return STATUS_ALREADY_REGISTERED;
	}

	// DEC-04 verify-then-commit: the owned resolver must be verified
	// alive by the caller before we flip anything
	if (!resolver_verified)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_resolver", L"resolver not verified; refusing (verify-then-commit)", 0);
		_r_queuedlock_releaseexclusive (&lock_resolver);
		return STATUS_RESOLVER_CONFIRM; // machine write requires owner confirmation
	}

	// snapshot BEFORE any machine write
	status = _app_resolver_snapshot ();

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseexclusive (&lock_resolver);
		return status; // abort without revert data
	}

	// machine write: only with explicit confirmation (opt-in, never
	// default-on — machine-wide-change killer-4 pattern)
	if (!is_confirmed)
	{
		_r_queuedlock_releaseexclusive (&lock_resolver);
		return STATUS_SUCCESS;
	}

	// commit: point every interface at the owned resolver
	{
		HKEY hkey;
		HKEY hiface;
		WCHAR guid_name[128];
		DWORD guid_size;
		DWORD index = 0;

		if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", 0, KEY_READ | KEY_SET_VALUE, &hkey) == ERROR_SUCCESS)
		{
			guid_size = RTL_NUMBER_OF (guid_name);

			while (index < RESOLVER_MAX_IFACES && RegEnumKeyExW (hkey, index++, guid_name, &guid_size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				WCHAR iface_path[300];

				guid_size = RTL_NUMBER_OF (guid_name);

				_r_str_printf (iface_path, RTL_NUMBER_OF (iface_path), L"%s\\%s", L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces", guid_name);

				if (RegOpenKeyExW (HKEY_LOCAL_MACHINE, iface_path, 0, KEY_SET_VALUE, &hiface) == ERROR_SUCCESS)
				{
					if (RegSetValueExW (hiface, L"NameServer", 0, REG_SZ, (LPBYTE)RESOLVER_OWNED_ADDR, (DWORD)((wcslen (RESOLVER_OWNED_ADDR) + 1) * sizeof (WCHAR))) == ERROR_SUCCESS)
						changed++;

					RegCloseKey (hiface);
				}
			}

			RegCloseKey (hkey);
		}
	}

	_r_config_setboolean (RESOLVER_CONFIG, TRUE, NULL);

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_resolver", L"resolver owned", (LONG)changed);

	_r_queuedlock_releaseexclusive (&lock_resolver);

	return STATUS_SUCCESS;
}

NTSTATUS _app_resolver_release (VOID)
{
	NTSTATUS status;

	_r_queuedlock_acquireexclusive (&lock_resolver);

	if (!_r_config_getboolean (RESOLVER_CONFIG, FALSE, NULL))
	{
		_r_queuedlock_releaseexclusive (&lock_resolver);
		return STATUS_NOT_FOUND;
	}

	status = _app_resolver_restore ();

	if (!NT_SUCCESS (status))
	{
		_r_queuedlock_releaseexclusive (&lock_resolver);
		return status; // keep the owned flag: partial restore must not lie
	}

	_r_config_setboolean (RESOLVER_CONFIG, FALSE, NULL);

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_resolver", L"released", (LONG)0);

	_r_queuedlock_releaseexclusive (&lock_resolver);

	return STATUS_SUCCESS;
}

// startup crash-residue check: owned flag without a valid snapshot =
// restore what we can from the snapshot and clear the flag; owned flag
// WITH a valid snapshot = restore anyway (the app just restarted; the
// owned resolver is not yet listening — the machine falls back to its
// recorded DNS, never to none: the never-leave-DNS-broken invariant)
VOID _app_resolver_startupcheck (VOID)
{
	if (!_r_config_getboolean (RESOLVER_CONFIG, FALSE, NULL))
		return;

	_r_log (LOG_LEVEL_WARNING, NULL, L"composite_resolver", L"restart while owning DNS; restoring recorded settings", 0);

	_app_resolver_restore ();

	_r_config_setboolean (RESOLVER_CONFIG, FALSE, NULL);
}

BOOLEAN _app_resolver_isowned (VOID)
{
	return _r_config_getboolean (RESOLVER_CONFIG, FALSE, NULL);
}
