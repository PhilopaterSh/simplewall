// simplewall (composite fork)
// Composite Phase 1 — signed rule packs (T008, FR-08 / SEC-01 / DATA-02).
//
// A pack is a directory with pack.json (UTF-8, canonical machine-generated)
// plus pack.sig (raw 64-byte r||s ECDSA P-256 signature over the EXACT
// pack.json bytes). The signature is verified against the embedded public
// key BEFORE any rule parses (SEC-01: an unsigned/tampered pack can never
// contribute a filter — there is no code path from unverified bytes to
// FwpmFilterAdd0).
//
// Sidecars (DATA-01: namespaced, never inside profile.xml):
//   composite_packstate.json  — per enabled pack: a "pack=" section plus
//     the exact filter GUID delta, tamper-evident via an FNV1a-32 trailer
//     over all preceding text. Corrupt state = packs treated as disabled
//     until re-import; the file is never silently rebuilt (DATA-02).
//   pack_watermarks.json      — per-pack version high-water for
//     anti-rollback. Corrupt = import refused forever; the store is never
//     overwritten or rebuilt (DATA-02: it is the only rollback evidence).
//
// Filter application mirrors _app_state_deploy's transaction pattern
// (shared lock_transaction + tri-state _wfp_transact_start). Pack filters
// sit at weight 0xE0 — deliberately below every user rule weight (the
// user rule band starts at FWW_RULE_USER_BLOCK/FWW_RULE_USER and above):
// an explicit user consent rule always outranks a shipped pack block.
// Pack rules are BLOCK-only, so the reverse (a pack allow shadowing a
// user block) cannot exist by construction.

#include "global.h"
#include "composite_packs.h"
#include "composite.h"

#define PACKS_KEY_ID L"qw-packs-2026-11"             // key-epoch gate: packs signed under any other epoch refuse
#define PACKS_KEY_ID_UTF8 "qw-packs-2026-11"         // same epoch as UTF-8 bytes (pack.json is UTF-8; keep both in lockstep)

#define PACKS_STATE_MAGIC L"COMPOSITE_PACKSTATE_V1"
#define PACKS_WATERMARK_MAGIC L"COMPOSITE_PACKWATERMARKS_V1"
#define PACKS_WATERMARK_FILE L"pack_watermarks.json"

#define PACKS_FILTER_WEIGHT 0xE0                     // below user rules: user consent outranks packs (header comment)
#define PACKS_MAX_RULES 0x2000                       // sanity bound on rules per pack
#define PACKS_MAX_FILTERS (PACKS_MAX_RULES * 2)      // "both" directions can double the filter count
#define PACKS_MAX_PACKID 64                          // pack id bound (also sizes state-line buffers)
#define PACKS_VERSION_LENGTH 16                      // "<major>.<minor>.<patch>" bound
#define PACKS_MAX_FILE 0x100000                      // sidecar/pack.json size class (same bound as lockdown snapshot)
#define PACKS_SIG_LENGTH 64                          // raw r||s ECDSA P-256 signature length

typedef enum _PACK_RULE_KIND
{
	PACK_RULE_INVALID = 0,
	PACK_RULE_PATH,                                  // per-app block (win32 path)
	PACK_RULE_PORT,                                  // port + protocol block
	PACK_RULE_ADDRESS,                               // remote address block (v4 or v6)
} PACK_RULE_KIND;

typedef enum _PACK_RULE_DIRECTION
{
	PACK_DIRECTION_OUT = 0,
	PACK_DIRECTION_IN,
	PACK_DIRECTION_BOTH,
} PACK_RULE_DIRECTION;

// one validated rule; the parser guarantees exactly one of
// path / port+protocol / address is set (kind discriminates)
typedef struct _PACK_RULE
{
	PR_STRING path;                                  // wide win32 path (PACK_RULE_PATH only)
	BYTE address[16];                                // big-endian address bytes (PACK_RULE_ADDRESS only)
	UINT16 port;                                     // PACK_RULE_PORT only
	UINT8 protocol;                                  // IPPROTO_TCP / IPPROTO_UDP (PACK_RULE_PORT only)
	UINT8 af;                                        // AF_INET / AF_INET6 (PACK_RULE_ADDRESS only)
	UINT8 direction;                                 // PACK_RULE_DIRECTION_*
	UINT8 kind;                                      // PACK_RULE_KIND_*
} PACK_RULE, *PPACK_RULE;

typedef struct _PACK_INFO
{
	WCHAR pack_id[PACKS_MAX_PACKID + 1];
	ULONG version[3];                                // major.minor.patch
	ULONG rules_hash;                                // FNV1a-32 over the exact pack.json bytes (rule content identity)
	PPACK_RULE rules;                                // allocated rule array (rule_count entries)
	ULONG rule_count;
} PACK_INFO, *PPACK_INFO;

// one parsed pack section of the packstate sidecar; the GUID array is the
// exact filter delta recorded at apply time and is the ONLY removal source
typedef struct _PACK_STATE_ENTRY
{
	WCHAR pack_id[PACKS_MAX_PACKID + 1];
	WCHAR version[PACKS_VERSION_LENGTH];
	ULONG rules_hash;
	PR_ARRAY guids;                                  // array of GUID
} PACK_STATE_ENTRY, *PPACK_STATE_ENTRY;

// minimal UTF-8 JSON cursor for the strict targeted scanner; the producer
// is canonical (CI schema-validated) so the scanner targets fixed keys,
// but every value consumed into a filter is fully validated
typedef struct _PACK_JSON
{
	const BYTE *ptr;
	const BYTE *end;
} PACK_JSON;

// SEC-01 release gate: the fork's ECDSA P-256 public key (raw 64-byte
// X||Y, big-endian, same convention as update_key.h / RSK-04). The
// placeholder is all-zero = every pack refuses until the owner embeds the
// release key here. This is deliberate: a fork built without the release
// key must never be able to load a pack at all (safe default).
static const BYTE packs_public_key[PACKS_SIG_LENGTH] = {0};

// module-local exclusive lock; packs code never calls back into
// profile/apps (no lock nesting) and takes lock_transaction shared only
// around its own WFP transaction windows
static R_QUEUED_LOCK lock_packs = PR_QUEUED_LOCK_INIT;

static VOID NTAPI _app_packs_stateentrycleanup (
	_In_ PVOID object_body
)
{
	PPACK_STATE_ENTRY ptr_entry = (PPACK_STATE_ENTRY)object_body;

	// list cleanup owns both the entry allocation and its GUID array ref
	if (ptr_entry->guids)
		_r_obj_dereference (ptr_entry->guids);

	_r_mem_free (ptr_entry);
}

static VOID _app_packs_freepack (
	_Inout_ PPACK_INFO ptr_pack
)
{
	ULONG_PTR i;

	if (ptr_pack->rules)
	{
		for (i = 0; i < ptr_pack->rule_count; i++)
		{
			if (ptr_pack->rules[i].path)
				_r_obj_dereference (ptr_pack->rules[i].path);
		}

		_r_mem_free (ptr_pack->rules);

		ptr_pack->rules = NULL;
	}
}

static VOID _app_packs_getpath (
	_In_ LPCWSTR file_name,
	_Out_ PR_STRING_PTR out_path
)
{
	PR_STRING profile_dir;
	PR_STRING path;

	*out_path = NULL;

	profile_dir = _r_app_getprofiledirectory ();

	if (!profile_dir)
		return;

	path = _r_obj_concatstrings (3, profile_dir->buffer, L"\\", file_name);

	_r_obj_dereference (profile_dir);

	*out_path = path;
}

// FNV1a-32 over raw bytes; used for both the packstate tamper-evident
// trailer and the pack rules-hash (content identity across re-imports)
static ULONG _app_packs_fnv1a32 (
	_In_reads_bytes_ (length) const BYTE *buffer,
	_In_ SIZE_T length
)
{
	ULONG hash = 2166136261;
	SIZE_T i;

	for (i = 0; i < length; i++)
	{
		hash ^= (ULONG)buffer[i];
		hash *= 16777619;
	}

	return hash;
}

// strict semver "M.m.p" parse over ASCII; every component is digits-only
// and bounded (a malformed version string refuses the pack rather than
// comparing to zero, which would silently bypass anti-rollback)
static BOOLEAN _app_packs_parseversion (
	_In_reads_bytes_ (length) const CHAR *string,
	_In_ SIZE_T length,
	_Out_ ULONG version[3]
)
{
	ULONG component = 0;
	SIZE_T i;

	version[0] = 0;
	version[1] = 0;
	version[2] = 0;

	for (i = 0; i < length; i++)
	{
		if (string[i] == '.')
		{
			if (component >= 2)
				return FALSE;

			component++;
			continue;
		}

		if (string[i] < '0' || string[i] > '9')
			return FALSE;

		if (version[component] > 0xFFFF)
			return FALSE; // bound first so the multiply cannot wrap

		version[component] = version[component] * 10 + (ULONG)(string[i] - '0');
	}

	return component == 2; // exactly three components
}

// GUID string parser for the packstate delta (the 8-4-4-4-12 form, braces
// tolerated because _r_str_fromguid emits them); swscanf_s into the raw
// GUID fields keeps the state sidecar self-contained (no guid-parsing
// dependency added for the round-trip)
static BOOLEAN _app_packs_toguid (
	_In_ LPCWSTR string,
	_Out_ LPGUID guid
)
{
	UINT data1;
	UINT data2;
	UINT data3;
	UINT b[8];
	INT parsed;

	while (*string == L'{' || *string == L' ')
		string++;

	parsed = swscanf_s (string, L"%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
		&data1, &data2, &data3, &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]);

	if (parsed != 11)
		return FALSE;

	guid->Data1 = data1;
	guid->Data2 = (USHORT)data2;
	guid->Data3 = (USHORT)data3;
	guid->Data4[0] = (BYTE)b[0];
	guid->Data4[1] = (BYTE)b[1];
	guid->Data4[2] = (BYTE)b[2];
	guid->Data4[3] = (BYTE)b[3];
	guid->Data4[4] = (BYTE)b[4];
	guid->Data4[5] = (BYTE)b[5];
	guid->Data4[6] = (BYTE)b[6];
	guid->Data4[7] = (BYTE)b[7];

	return TRUE;
}

static BOOLEAN _app_packs_ispackidchar (
	_In_ WCHAR value
)
{
	// state lines are "|"-delimited: the delimiter itself can never be
	// part of an id, and the sidecars stay ASCII by construction
	if (value >= L'a' && value <= L'z')
		return TRUE;

	if (value >= L'A' && value <= L'Z')
		return TRUE;

	if (value >= L'0' && value <= L'9')
		return TRUE;

	return value == L'.' || value == L'-' || value == L'_';
}

//
// Strict targeted JSON scanner (UTF-8, canonical producer)
//

static VOID _app_packs_jsonskipws (
	_Inout_ PACK_JSON *json
)
{
	while (json->ptr < json->end)
	{
		if (json->ptr[0] != ' ' && json->ptr[0] != '\t' && json->ptr[0] != '\r' && json->ptr[0] != '\n')
			break;

		json->ptr++;
	}
}

static BOOLEAN _app_packs_jsonconsume (
	_Inout_ PACK_JSON *json,
	_In_ BYTE value
)
{
	_app_packs_jsonskipws (json);

	if (json->ptr >= json->end || json->ptr[0] != value)
		return FALSE;

	json->ptr++;

	return TRUE;
}

// string value scan: canonical producer, so the only accepted escapes are
// \\ and \" (both appear in win32 path JSON); any other escape or control
// character rejects the pack outright (strict parser contract)
static BOOLEAN _app_packs_jsonstring (
	_Inout_ PACK_JSON *json,
	_Out_writes_ (buffer_size) CHAR *buffer,
	_In_ SIZE_T buffer_size,
	_Out_ SIZE_T *out_length
)
{
	SIZE_T length = 0;
	BYTE value;

	_app_packs_jsonskipws (json);

	if (json->ptr >= json->end || json->ptr[0] != '"')
		return FALSE;

	json->ptr++;

	while (json->ptr < json->end)
	{
		value = json->ptr[0];
		json->ptr++;

		if (value == '"')
		{
			*out_length = length;
			return TRUE;
		}

		if (value == '\\')
		{
			if (json->ptr >= json->end)
				return FALSE;

			if (json->ptr[0] == '\\' || json->ptr[0] == '"')
			{
				value = json->ptr[0];
				json->ptr++;
			}
			else
			{
				return FALSE; // unknown escape = malformed input
			}
		}

		if (value < 0x20 || value >= 0x7F)
			return FALSE; // ASCII-only canonical form; non-ASCII rejects

		if (length + 1 >= buffer_size)
			return FALSE;

		buffer[length++] = (CHAR)value;
	}

	return FALSE; // unterminated
}

static BOOLEAN _app_packs_jsonnumber (
	_Inout_ PACK_JSON *json,
	_Out_ PULONG value
)
{
	ULONG result = 0;
	BYTE current;

	_app_packs_jsonskipws (json);

	if (json->ptr >= json->end)
		return FALSE;

	current = json->ptr[0];

	if (current < '0' || current > '9')
		return FALSE;

	while (json->ptr < json->end)
	{
		current = json->ptr[0];

		if (current < '0' || current > '9')
			break;

		if (result > 0xFFFF)
			return FALSE; // bound first so the multiply cannot wrap

		result = result * 10 + (ULONG)(current - '0');
		json->ptr++;
	}

	*value = result;

	return TRUE;
}

static BOOLEAN _app_packs_jsonmatches (
	_In_reads_bytes_ (length) const BYTE *ptr,
	_In_ SIZE_T length,
	_In_ LPCSTR literal
)
{
	SIZE_T literal_length = strlen (literal);

	if (length != literal_length)
		return FALSE;

	return RtlEqualMemory (ptr, literal, length);
}

static BOOLEAN _app_packs_parseipv4 (
	_In_reads_bytes_ (length) const CHAR *string,
	_In_ SIZE_T length,
	_Out_writes_ (4) BYTE address[4]
)
{
	ULONG octet = 0;
	ULONG index = 0;
	SIZE_T i;

	for (i = 0; i < length; i++)
	{
		if (string[i] == '.')
		{
			if (index >= 3)
				return FALSE;

			address[index++] = (BYTE)octet;
			octet = 0;
			continue;
		}

		if (string[i] < '0' || string[i] > '9')
			return FALSE;

		octet = octet * 10 + (ULONG)(string[i] - '0');

		if (octet > 255)
			return FALSE;
	}

	if (index != 3 || length == 0)
		return FALSE;

	address[3] = (BYTE)octet;

	return TRUE;
}

// compact IPv6 literal parser (the canonical producer emits simple
// literals): groups of 1-4 hex digits separated by ':', at most one "::"
// gap, no embedded IPv4 tail (a '.' anywhere rejects). The gap stays
// zero-filled; right-side groups are right-aligned inside the 128 bits.
static BOOLEAN _app_packs_parseipv6 (
	_In_reads_bytes_ (length) const CHAR *string,
	_In_ SIZE_T length,
	_Out_writes_ (16) BYTE address[16]
)
{
	ULONG groups[8];
	ULONG group_count = 0;
	ULONG gap_index = 0;
	ULONG value = 0;
	ULONG digits = 0;
	BOOLEAN has_gap = FALSE;
	ULONG i;
	SIZE_T pos;

	RtlZeroMemory (groups, sizeof (groups));

	for (pos = 0; pos < length; pos++)
	{
		CHAR value_char = string[pos];

		if (value_char == ':')
		{
			if (pos + 1 < length && string[pos + 1] == ':')
			{
				if (has_gap)
					return FALSE; // more than one "::"

				if (digits)
				{
					if (group_count >= 8)
						return FALSE;

					groups[group_count++] = value;
					value = 0;
					digits = 0;
				}

				has_gap = TRUE;
				gap_index = group_count;
				pos++; // consume the second colon
				continue;
			}

			if (digits == 0)
				return FALSE; // empty group (single leading/trailing colon)

			if (group_count >= 8)
				return FALSE;

			groups[group_count++] = value;
			value = 0;
			digits = 0;
			continue;
		}

		if (value_char == '.')
			return FALSE; // embedded IPv4 tail is out of the canonical form

		if (!((value_char >= '0' && value_char <= '9') || (value_char >= 'a' && value_char <= 'f') || (value_char >= 'A' && value_char <= 'F')))
			return FALSE;

		value = value * 16;

		if (value_char <= '9')
			value += (ULONG)(value_char - '0');
		else if (value_char >= 'a')
			value += (ULONG)(value_char - 'a' + 10);
		else
			value += (ULONG)(value_char - 'A' + 10);

		if (++digits > 4)
			return FALSE;
	}

	// flush the final group
	if (digits)
	{
		if (group_count >= 8)
			return FALSE;

		groups[group_count++] = value;
	}

	if (!has_gap && group_count != 8)
		return FALSE;

	if (has_gap && group_count > 7)
		return FALSE;

	RtlZeroMemory (address, 16);

	if (has_gap)
	{
		// left groups fill from the head, right groups from the tail
		ULONG tail_count = group_count - gap_index;

		for (i = 0; i < gap_index; i++)
		{
			address[i * 2] = (BYTE)(groups[i] >> 8);
			address[i * 2 + 1] = (BYTE)(groups[i] & 0xFF);
		}

		for (i = 0; i < tail_count; i++)
		{
			ULONG index = 8 - tail_count + i;

			address[index * 2] = (BYTE)(groups[gap_index + i] >> 8);
			address[index * 2 + 1] = (BYTE)(groups[gap_index + i] & 0xFF);
		}
	}
	else
	{
		for (i = 0; i < group_count; i++)
		{
			address[i * 2] = (BYTE)(groups[i] >> 8);
			address[i * 2 + 1] = (BYTE)(groups[i] & 0xFF);
		}
	}

	return TRUE;
}

static BOOLEAN _app_packs_parseaddress (
	_In_reads_bytes_ (length) const CHAR *string,
	_In_ SIZE_T length,
	_Inout_ PPACK_RULE ptr_rule
)
{
	if (length == 0)
		return FALSE;

	if (memchr (string, ':', length))
	{
		ptr_rule->af = AF_INET6;

		return _app_packs_parseipv6 (string, length, ptr_rule->address);
	}

	ptr_rule->af = AF_INET;

	return _app_packs_parseipv4 (string, length, ptr_rule->address);
}

// strict rule-object scan: every key must be one of the five schema keys,
// exactly one of path / port+protocol / address must be present, and
// direction is mandatory. Anything else rejects the pack (strict parser).
static BOOLEAN _app_packs_parserule (
	_Inout_ PACK_JSON *json,
	_Inout_ PPACK_RULE ptr_rule
)
{
	CHAR value_buffer[256];
	SIZE_T value_length;
	BOOLEAN has_path = FALSE;
	BOOLEAN has_port = FALSE;
	BOOLEAN has_protocol = FALSE;
	BOOLEAN has_address = FALSE;
	BOOLEAN has_direction = FALSE;
	BYTE value;
	ULONG port_value;

	if (!json->ptr || json->ptr >= json->end || json->ptr[0] != '{')
		return FALSE;

	json->ptr++;

	for (;;)
	{
		const BYTE *key_ptr;
		SIZE_T key_length;
		BOOLEAN is_key_end = FALSE;

		_app_packs_jsonskipws (json);

		if (json->ptr >= json->end || json->ptr[0] != '"')
			return FALSE;

		json->ptr++;

		key_ptr = json->ptr;
		key_length = 0;

		while (json->ptr < json->end && json->ptr[0] != '"')
		{
			if (json->ptr[0] < 0x20 || json->ptr[0] >= 0x7F)
				return FALSE;

			json->ptr++;
			key_length++;
		}

		if (json->ptr >= json->end)
			return FALSE;

		json->ptr++; // closing quote

		if (!_app_packs_jsonconsume (json, ':'))
			return FALSE;

		if (_app_packs_jsonmatches (key_ptr, key_length, "path"))
		{
			if (has_path || has_port || has_address)
				return FALSE; // duplicates and mixed kinds reject

			if (!_app_packs_jsonstring (json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length) || value_length == 0)
				return FALSE;

			{
				WCHAR wide_path[520];
				INT converted;

				converted = MultiByteToWideChar (CP_UTF8, MB_ERR_INVALID_CHARS, value_buffer, (INT)value_length, wide_path, RTL_NUMBER_OF (wide_path) - 1);

				if (converted <= 0)
					return FALSE;

				wide_path[converted] = UNICODE_NULL;

				ptr_rule->path = _r_obj_createstring (wide_path);
			}

			has_path = TRUE;
			ptr_rule->kind = PACK_RULE_PATH;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "port"))
		{
			if (has_path || has_port || has_address)
				return FALSE;

			if (!_app_packs_jsonnumber (json, &port_value) || port_value > 0xFFFF)
				return FALSE;

			ptr_rule->port = (UINT16)port_value;
			has_port = TRUE;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "protocol"))
		{
			if (has_path || has_address || has_protocol)
				return FALSE;

			if (!_app_packs_jsonstring (json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length))
				return FALSE;

			if (_app_packs_jsonmatches ((const BYTE *)value_buffer, value_length, "tcp"))
				ptr_rule->protocol = IPPROTO_TCP;
			else if (_app_packs_jsonmatches ((const BYTE *)value_buffer, value_length, "udp"))
				ptr_rule->protocol = IPPROTO_UDP;
			else
				return FALSE;

			has_protocol = TRUE;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "address"))
		{
			if (has_path || has_port || has_address)
				return FALSE;

			if (!_app_packs_jsonstring (json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length))
				return FALSE;

			if (!_app_packs_parseaddress (value_buffer, value_length, ptr_rule))
				return FALSE;

			has_address = TRUE;
			ptr_rule->kind = PACK_RULE_ADDRESS;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "direction"))
		{
			if (has_direction)
				return FALSE;

			if (!_app_packs_jsonstring (json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length))
				return FALSE;

			if (_app_packs_jsonmatches ((const BYTE *)value_buffer, value_length, "out"))
				ptr_rule->direction = PACK_DIRECTION_OUT;
			else if (_app_packs_jsonmatches ((const BYTE *)value_buffer, value_length, "in"))
				ptr_rule->direction = PACK_DIRECTION_IN;
			else if (_app_packs_jsonmatches ((const BYTE *)value_buffer, value_length, "both"))
				ptr_rule->direction = PACK_DIRECTION_BOTH;
			else
				return FALSE;

			has_direction = TRUE;
		}
		else
		{
			return FALSE; // unknown key = unknown structure = refuse
		}

		// member separator or object end
		if (!json->ptr || json->ptr >= json->end)
			return FALSE;

		value = json->ptr[0];
		json->ptr++;

		if (value == '}')
		{
			is_key_end = TRUE;
		}
		else if (value != ',')
		{
			return FALSE;
		}

		if (is_key_end)
			break;
	}

	// schema verdict: port requires protocol; direction is mandatory; the
	// kind discriminator was set as the exclusive key was consumed
	if (ptr_rule->kind == PACK_RULE_PORT && !has_protocol)
		return FALSE;

	if (!has_direction || ptr_rule->kind == PACK_RULE_INVALID)
		return FALSE;

	return TRUE;
}

// strict root scan: exactly the four schema members, no duplicates, no
// unknown structure; rules array is bounded by PACKS_MAX_RULES
static BOOLEAN _app_packs_parsepack (
	_In_reads_bytes_ (data_length) const BYTE *data,
	_In_ SIZE_T data_length,
	_Inout_ PPACK_INFO ptr_pack
)
{
	PACK_JSON json;
	CHAR value_buffer[256];
	SIZE_T value_length;
	PPACK_RULE rules = NULL;
	ULONG rule_count = 0;
	BOOLEAN has_id = FALSE;
	BOOLEAN has_version = FALSE;
	BOOLEAN has_keyid = FALSE;
	BOOLEAN has_rules = FALSE;
	BOOLEAN is_success = FALSE;
	BYTE value;
	SIZE_T i;

	json.ptr = data;
	json.end = data + data_length;

	if (!_app_packs_jsonconsume (&json, '{'))
		return FALSE;

	for (;;)
	{
		const BYTE *key_ptr;
		SIZE_T key_length;
		BOOLEAN is_object_end = FALSE;

		_app_packs_jsonskipws (&json);

		if (json.ptr < json.end && json.ptr[0] == '}')
		{
			json.ptr++;
			break;
		}

		if (json.ptr >= json.end || json.ptr[0] != '"')
			goto cleanup_exit;

		json.ptr++;

		key_ptr = json.ptr;
		key_length = 0;

		while (json.ptr < json.end && json.ptr[0] != '"')
		{
			if (json.ptr[0] < 0x20 || json.ptr[0] >= 0x7F)
				goto cleanup_exit;

			json.ptr++;
			key_length++;
		}

		if (json.ptr >= json.end)
			goto cleanup_exit;

		json.ptr++; // closing quote

		if (!_app_packs_jsonconsume (&json, ':'))
			goto cleanup_exit;

		if (_app_packs_jsonmatches (key_ptr, key_length, "id"))
		{
			if (has_id)
				goto cleanup_exit;

			if (!_app_packs_jsonstring (&json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length) || value_length == 0 || value_length > PACKS_MAX_PACKID)
				goto cleanup_exit;

			for (i = 0; i < value_length; i++)
			{
				if (!_app_packs_ispackidchar ((WCHAR)(BYTE)value_buffer[i]))
					goto cleanup_exit;
			}

			for (i = 0; i < value_length; i++)
				ptr_pack->pack_id[i] = (WCHAR)(BYTE)value_buffer[i];

			ptr_pack->pack_id[value_length] = UNICODE_NULL;

			has_id = TRUE;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "version"))
		{
			if (has_version)
				goto cleanup_exit;

			if (!_app_packs_jsonstring (&json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length))
				goto cleanup_exit;

			if (!_app_packs_parseversion (value_buffer, value_length, ptr_pack->version))
				goto cleanup_exit;

			has_version = TRUE;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "key_id"))
		{
			if (has_keyid)
				goto cleanup_exit;

			if (!_app_packs_jsonstring (&json, value_buffer, RTL_NUMBER_OF (value_buffer), &value_length))
				goto cleanup_exit;

			if (!_app_packs_jsonmatches ((const BYTE *)value_buffer, value_length, PACKS_KEY_ID_UTF8))
				goto cleanup_exit; // key-epoch mismatch refuses

			has_keyid = TRUE;
		}
		else if (_app_packs_jsonmatches (key_ptr, key_length, "rules"))
		{
			if (has_rules)
				goto cleanup_exit;

			if (!_app_packs_jsonconsume (&json, '['))
				goto cleanup_exit;

			for (;;)
			{
				_app_packs_jsonskipws (&json);

				if (json.ptr < json.end && json.ptr[0] == ']')
				{
					json.ptr++;
					break;
				}

				if (rule_count >= PACKS_MAX_RULES)
					goto cleanup_exit;

				if (!rules)
				{
					// allocate the bounded array once; zero-filled so the
					// cleanup walker can deref paths without a count
					rules = _r_mem_allocate (sizeof (PACK_RULE) * PACKS_MAX_RULES);

					RtlZeroMemory (rules, sizeof (PACK_RULE) * PACKS_MAX_RULES);
				}

				if (!_app_packs_parserule (&json, &rules[rule_count]))
					goto cleanup_exit;

				rule_count++;

				_app_packs_jsonskipws (&json);

				if (json.ptr >= json.end)
					goto cleanup_exit;

				value = json.ptr[0];
				json.ptr++;

				if (value == ']')
					break;

				if (value != ',')
					goto cleanup_exit;
			}

			has_rules = TRUE;
		}
		else
		{
			goto cleanup_exit; // unknown root member = unknown structure
		}

		// member separator or object end
		_app_packs_jsonskipws (&json);

		if (json.ptr >= json.end)
			goto cleanup_exit;

		value = json.ptr[0];
		json.ptr++;

		if (value == '}')
		{
			is_object_end = TRUE;
		}
		else if (value != ',')
		{
			goto cleanup_exit;
		}

		if (is_object_end)
			break;
	}

	if (!has_id || !has_version || !has_keyid || !has_rules || rule_count == 0)
		goto cleanup_exit;

	ptr_pack->rule_count = rule_count;
	ptr_pack->rules = rules;
	rules = NULL;

	is_success = TRUE;

cleanup_exit:
	if (rules)
	{
		for (i = 0; i < PACKS_MAX_RULES; i++)
		{
			if (rules[i].path)
				_r_obj_dereference (rules[i].path);
		}

		_r_mem_free (rules);
	}

	return is_success;
}

//
// Signature verification (CNG core, mirrors _r_update_verifysignature)
//

static NTSTATUS _app_packs_verifysignature (
	_In_reads_bytes_ (data_length) const BYTE *data,
	_In_ SIZE_T data_length,
	_In_reads_bytes_ (PACKS_SIG_LENGTH) const BYTE *signature
)
{
	BCRYPT_ALG_HANDLE halg_ecdsa = NULL;
	BCRYPT_ALG_HANDLE halg_sha = NULL;
	BCRYPT_KEY_HANDLE hkey = NULL;
	BCRYPT_HASH_HANDLE hhash = NULL;
	BCRYPT_ECCKEY_BLOB *public_blob = NULL;
	BYTE digest[32];
	ULONG blob_length;
	BOOLEAN is_placeholder = TRUE;
	NTSTATUS status;
	ULONG i;

	// placeholder key = refuse everything before any CNG call (see the
	// packs_public_key comment); the refusal is loud so the owner knows
	// the release key must be embedded before packs can ever load
	for (i = 0; i < RTL_NUMBER_OF (packs_public_key); i++)
	{
		if (packs_public_key[i])
		{
			is_placeholder = FALSE;
			break;
		}
	}

	if (is_placeholder)
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"composite_packs", L"release public key not embedded; pack refused (safe default)", (LONG)0);

		return STATUS_INVALID_PARAMETER;
	}

	// BCRYPT_ECDSA_PUBLIC_BLOB layout: magic + cbKey + X + Y; CNG ECC
	// blobs and P1363 r||s signatures are big-endian and the embedded key
	// stores X||Y big-endian, so the bytes are copied verbatim (RSK-04
	// bench-proven convention, same as the update feed core)
	blob_length = sizeof (BCRYPT_ECCKEY_BLOB) + sizeof (packs_public_key);

	public_blob = _r_mem_allocate (blob_length);

	public_blob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
	public_blob->cbKey = 32;

	RtlCopyMemory (public_blob + 1, packs_public_key, sizeof (packs_public_key));

	status = BCryptOpenAlgorithmProvider (&halg_ecdsa, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);

	if (!NT_SUCCESS (status))
		goto cleanup_exit;

	status = BCryptImportKeyPair (halg_ecdsa, NULL, BCRYPT_ECCPUBLIC_BLOB, &hkey, (PUCHAR)public_blob, blob_length, 0);

	if (!NT_SUCCESS (status))
		goto cleanup_exit;

	status = BCryptOpenAlgorithmProvider (&halg_sha, BCRYPT_SHA256_ALGORITHM, NULL, 0);

	if (!NT_SUCCESS (status))
		goto cleanup_exit;

	status = BCryptCreateHash (halg_sha, &hhash, NULL, 0, NULL, 0, 0);

	if (!NT_SUCCESS (status))
		goto cleanup_exit;

	status = BCryptHashData (hhash, (PUCHAR)data, (ULONG)data_length, 0);

	if (!NT_SUCCESS (status))
		goto cleanup_exit;

	status = BCryptFinishHash (hhash, digest, sizeof (digest), 0);

	if (!NT_SUCCESS (status))
		goto cleanup_exit;

	status = BCryptVerifySignature (hkey, NULL, digest, sizeof (digest), (PUCHAR)signature, PACKS_SIG_LENGTH, 0);

cleanup_exit:
	if (hhash)
		BCryptDestroyHash (hhash);

	if (halg_sha)
		BCryptCloseAlgorithmProvider (halg_sha, 0);

	if (hkey)
		BCryptDestroyKey (hkey);

	if (halg_ecdsa)
		BCryptCloseAlgorithmProvider (halg_ecdsa, 0);

	if (public_blob)
		_r_mem_free (public_blob);

	return status;
}

//
// Raw + wide file readers/writers (sidecar IO pattern, warn-and-leave)
//

static NTSTATUS _app_packs_readraw (
	_In_ LPCWSTR path,
	_Out_ PBYTE *out_buffer,
	_Out_ SIZE_T *out_length
)
{
	HANDLE hfile;
	LARGE_INTEGER fsize;
	BYTE *buffer;
	DWORD read;

	*out_buffer = NULL;
	*out_length = 0;

	hfile = CreateFileW (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
		return HRESULT_FROM_WIN32 (GetLastError ());

	if (!GetFileSizeEx (hfile, &fsize) || fsize.QuadPart == 0 || fsize.QuadPart > PACKS_MAX_FILE)
	{
		CloseHandle (hfile);
		return STATUS_INVALID_PARAMETER; // empty or oversized = wrong size class
	}

	buffer = _r_mem_allocate ((SIZE_T)fsize.QuadPart);

	if (!ReadFile (hfile, buffer, (DWORD)fsize.QuadPart, &read, NULL) || read != (DWORD)fsize.QuadPart)
	{
		NTSTATUS status = HRESULT_FROM_WIN32 (GetLastError ());

		_r_mem_free (buffer);
		CloseHandle (hfile);
		return status;
	}

	CloseHandle (hfile);

	*out_buffer = buffer;
	*out_length = (SIZE_T)fsize.QuadPart;

	return STATUS_SUCCESS;
}

static NTSTATUS _app_packs_readwide (
	_In_ LPCWSTR path,
	_Out_ PR_STRING_PTR out_contents,
	_Out_ PBOOLEAN is_present
)
{
	HANDLE hfile;
	LARGE_INTEGER fsize;
	BYTE *buffer;
	PR_STRING contents;
	DWORD read;

	*out_contents = NULL;
	*is_present = FALSE;

	hfile = CreateFileW (path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
		return STATUS_NOT_FOUND;

	*is_present = TRUE;

	if (!GetFileSizeEx (hfile, &fsize) || fsize.QuadPart == 0 || (fsize.QuadPart % sizeof (WCHAR)) != 0 || fsize.QuadPart > PACKS_MAX_FILE)
	{
		CloseHandle (hfile);
		return STATUS_INVALID_PARAMETER; // wrong size class = corrupt
	}

	buffer = _r_mem_allocate ((SIZE_T)fsize.QuadPart);

	if (!ReadFile (hfile, buffer, (DWORD)fsize.QuadPart, &read, NULL) || read != (DWORD)fsize.QuadPart)
	{
		NTSTATUS status = HRESULT_FROM_WIN32 (GetLastError ());

		_r_mem_free (buffer);
		CloseHandle (hfile);
		return status;
	}

	CloseHandle (hfile);

	contents = _r_obj_createstring_ex ((LPCWSTR)buffer, (SIZE_T)read);

	_r_mem_free (buffer);

	*out_contents = contents;

	return STATUS_SUCCESS;
}

static NTSTATUS _app_packs_writewide (
	_In_ LPCWSTR path,
	_In_ PR_STRING contents
)
{
	HANDLE hfile;
	DWORD written;

	hfile = CreateFileW (path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hfile == INVALID_HANDLE_VALUE)
	{
		NTSTATUS status = HRESULT_FROM_WIN32 (GetLastError ());

		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_packs", L"sidecar CreateFileW", status);

		return status;
	}

	if (!WriteFile (hfile, contents->buffer, (DWORD)(contents->length * sizeof (WCHAR)), &written, NULL) || written != (DWORD)(contents->length * sizeof (WCHAR)))
	{
		NTSTATUS status = HRESULT_FROM_WIN32 (GetLastError ());

		CloseHandle (hfile);

		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_packs", L"sidecar WriteFile", status);

		return status;
	}

	CloseHandle (hfile);

	return STATUS_SUCCESS;
}

//
// Line walker shared by both sidecar parsers (does NOT advance; the
// caller drives line = next)
//

static VOID _app_packs_nextline (
	_In_ LPCWSTR line,
	_Out_ SIZE_T *line_length,
	_Out_ LPCWSTR *next
)
{
	LPCWSTR line_end = wcschr (line, L'\n');

	*next = line_end ? line_end + 1 : NULL;

	*line_length = line_end ? (SIZE_T)(line_end - line) : wcslen (line);

	if (*line_length && line[*line_length - 1] == L'\r')
		(*line_length)--;
}

static BOOLEAN _app_packs_lineis (
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

static VOID _app_packs_logpack (
	_In_ R_LOG_LEVEL level,
	_In_ LPCWSTR description,
	_In_ LONG error_code
)
{
	_r_log (level, NULL, L"composite_packs", description, error_code);
}

//
// Watermark store (anti-rollback high-water; DATA-02: never rebuilt)
//

// returns the recorded high-water for one pack; STATUS_NOT_FOUND = no
// line yet (first import); any structural defect = corruption and the
// caller must refuse import (never overwrite, never rebuild)
static NTSTATUS _app_packs_watermarkread (
	_In_ PR_STRING contents,
	_In_ LPCWSTR pack_id,
	_Out_ ULONG watermark[3]
)
{
	CHAR narrow[32];
	LPCWSTR line;
	LPCWSTR next;
	SIZE_T line_length;
	SIZE_T id_length;
	SIZE_T version_length;
	SIZE_T i;

	id_length = wcslen (pack_id);

	line = contents->buffer;
	next = NULL;

	while (line && *line)
	{
		_app_packs_nextline (line, &line_length, &next);

		if (!line_length)
			break;

		if (_app_packs_lineis (line, line_length, PACKS_WATERMARK_MAGIC))
		{
			line = next;
			continue; // magic line
		}

		if (line_length > id_length && RtlEqualMemory (line, pack_id, id_length * sizeof (WCHAR)) && line[id_length] == L'|')
		{
			// "<id>|<major>.<minor>.<patch>": version chars are ASCII by
			// construction; anything else is a corrupt store
			version_length = line_length - id_length - 1;

			if (version_length == 0 || version_length >= RTL_NUMBER_OF (narrow))
				return STATUS_INVALID_PARAMETER;

			for (i = 0; i < version_length; i++)
			{
				WCHAR value_char = line[id_length + 1 + i];

				if (value_char > 0x7F)
					return STATUS_INVALID_PARAMETER;

				narrow[i] = (CHAR)value_char;
			}

			narrow[version_length] = 0;

			if (!_app_packs_parseversion (narrow, version_length, watermark))
				return STATUS_INVALID_PARAMETER;

			return STATUS_SUCCESS;
		}

		if (!wcschr (line, L'|'))
			return STATUS_INVALID_PARAMETER; // a line without the delimiter cannot be a watermark record

		line = next;
	}

	return STATUS_NOT_FOUND;
}

// anti-rollback gate: *compare receives 0 = below high-water (refuse),
// 1 = equal, 2 = above/absent; a corrupt store refuses unconditionally
static NTSTATUS _app_packs_watermarkcheck (
	_In_ const PPACK_INFO ptr_pack,
	_Out_ PULONG_PTR compare
)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	BOOLEAN is_present = FALSE;
	ULONG watermark[3] = {0, 0, 0};
	NTSTATUS status;

	_app_packs_getpath (PACKS_WATERMARK_FILE, &path);

	if (!path)
		return STATUS_UNSUCCESSFUL;

	status = _app_packs_readwide (path->buffer, &contents, &is_present);

	if (!is_present)
	{
		*compare = 2; // no store yet = everything is a first import

		if (contents)
			_r_obj_dereference (contents);

		_r_obj_dereference (path);

		return STATUS_SUCCESS;
	}

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"composite_packs", L"watermark store corrupt; import refused (never rebuilt)", status);

		_r_obj_dereference (contents);
		_r_obj_dereference (path);

		return STATUS_INVALID_PARAMETER;
	}

	if (wcsncmp (contents->buffer, PACKS_WATERMARK_MAGIC, RTL_NUMBER_OF (PACKS_WATERMARK_MAGIC) - 1) != 0)
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"composite_packs", L"watermark store magic mismatch; import refused (never rebuilt)", (LONG)0);

		_r_obj_dereference (contents);
		_r_obj_dereference (path);

		return STATUS_INVALID_PARAMETER;
	}

	status = _app_packs_watermarkread (contents, ptr_pack->pack_id, watermark);

	_r_obj_dereference (contents);
	_r_obj_dereference (path);

	if (status == STATUS_NOT_FOUND)
	{
		*compare = 2;
		return STATUS_SUCCESS;
	}

	if (!NT_SUCCESS (status))
	{
		_r_log (LOG_LEVEL_ERROR, NULL, L"composite_packs", L"watermark record corrupt; import refused (never rebuilt)", status);

		return STATUS_INVALID_PARAMETER;
	}

	if (ptr_pack->version[0] < watermark[0] ||
		(ptr_pack->version[0] == watermark[0] && ptr_pack->version[1] < watermark[1]) ||
		(ptr_pack->version[0] == watermark[0] && ptr_pack->version[1] == watermark[1] && ptr_pack->version[2] < watermark[2]))
	{
		*compare = 0;
	}
	else if (ptr_pack->version[0] == watermark[0] && ptr_pack->version[1] == watermark[1] && ptr_pack->version[2] == watermark[2])
	{
		*compare = 1;
	}
	else
	{
		*compare = 2;
	}

	return STATUS_SUCCESS;
}

static NTSTATUS _app_packs_watermarkwrite (
	_In_ const PPACK_INFO ptr_pack
)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	BOOLEAN is_present = FALSE;
	BOOLEAN found = FALSE;
	PR_STRINGBUILDER sb;
	NTSTATUS status;
	LPCWSTR line;
	LPCWSTR next;
	SIZE_T line_length;
	SIZE_T id_length;

	_app_packs_getpath (PACKS_WATERMARK_FILE, &path);

	if (!path)
		return STATUS_UNSUCCESSFUL;

	status = _app_packs_readwide (path->buffer, &contents, &is_present);

	if (is_present && !NT_SUCCESS (status))
	{
		// corrupt store: refuse to touch it (DATA-02)
		_r_log (LOG_LEVEL_ERROR, NULL, L"composite_packs", L"watermark store corrupt; write refused (never rebuilt)", status);

		_r_obj_dereference (path);

		return STATUS_INVALID_PARAMETER;
	}

	_r_obj_initializestringbuilder (sb, 0x400);

	if (is_present && contents)
	{
		// replay all records except this pack's line (source was
		// magic-validated by the check call immediately before)
		id_length = wcslen (ptr_pack->pack_id);

		line = contents->buffer;
		next = NULL;

		while (line && *line)
		{
			BOOLEAN is_target;

			_app_packs_nextline (line, &line_length, &next);

			if (!line_length)
				break;

			is_target = (line_length > id_length &&
				RtlEqualMemory (line, ptr_pack->pack_id, id_length * sizeof (WCHAR)) &&
				line[id_length] == L'|');

			if (!found && is_target)
				found = TRUE; // drop only the first record for the pack

			if (!is_target)
			{
				_r_obj_appendstringbuilder_ex (sb, line, line_length * sizeof (WCHAR));
				_r_obj_appendstringbuilder_ex (sb, L"\r\n", 2 * sizeof (WCHAR));
			}

			line = next;
		}
	}
	else
	{
		_r_obj_appendstringbuilder_ex (sb, PACKS_WATERMARK_MAGIC, RTL_NUMBER_OF (PACKS_WATERMARK_MAGIC) - 1);
		_r_obj_appendstringbuilder_ex (sb, L"\r\n", 2 * sizeof (WCHAR));
	}

	_r_obj_appendstringbuilderformat (sb, L"%s|%lu.%lu.%lu\r\n",
		ptr_pack->pack_id, ptr_pack->version[0], ptr_pack->version[1], ptr_pack->version[2]);

	contents = _r_obj_finalstringbuilder (sb);

	status = _app_packs_writewide (path->buffer, contents);

	if (NT_SUCCESS (status))
		_r_log (LOG_LEVEL_INFO, NULL, L"composite_packs", L"watermark advanced", (LONG)0);

	_r_obj_deletestringbuilder (sb);

	_r_obj_dereference (contents);
	_r_obj_dereference (path);

	return status;
}

//
// Packstate sidecar (verify / parse / query / write)
//

// verify magic + tamper-evident trailer (FNV1a-32 over all preceding
// text); returns STATUS_SUCCESS only for a provably intact store
static NTSTATUS _app_packs_stateverify (
	_In_ PR_STRING contents
)
{
	LPCWSTR trailer = NULL;
	LPCWSTR line;
	LPCWSTR next;
	SIZE_T line_length;
	SIZE_T prefix_length;
	ULONG hash_stored = 0;
	ULONG hash_actual;
	BYTE *prefix_bytes;

	if (wcsncmp (contents->buffer, PACKS_STATE_MAGIC, RTL_NUMBER_OF (PACKS_STATE_MAGIC) - 1) != 0)
		return STATUS_INVALID_PARAMETER;

	// locate the trailer line (the last "state_hash=" line-start)
	line = contents->buffer;
	next = NULL;

	while (line && *line)
	{
		_app_packs_nextline (line, &line_length, &next);

		if (!line_length)
			break;

		if (_app_packs_lineis (line, line_length, L"state_hash="))
			trailer = line;

		line = next;
	}

	if (!trailer)
		return STATUS_INVALID_PARAMETER;

	// the hash covers every WCHAR byte written before the trailer line
	prefix_bytes = (BYTE *)contents->buffer;
	prefix_length = (SIZE_T)(trailer - contents->buffer) * sizeof (WCHAR);

	hash_actual = _app_packs_fnv1a32 (prefix_bytes, prefix_length);

	if (swscanf_s (trailer, L"state_hash=%8x", &hash_stored) != 1)
		return STATUS_INVALID_PARAMETER;

	if (hash_stored != hash_actual)
		return STATUS_INVALID_PARAMETER;

	return STATUS_SUCCESS;
}

// parse a hash-verified store into pack entries; on any structural
// defect the list is released and an error returned (corrupt stores are
// never repaired in place — DATA-02)
static PR_LIST _app_packs_stateparse (
	_In_ PR_STRING contents,
	_Out_ NTSTATUS *out_status
)
{
	PR_LIST list;
	PPACK_STATE_ENTRY ptr_entry = NULL;
	LPCWSTR line;
	LPCWSTR next;
	SIZE_T line_length;

	*out_status = STATUS_SUCCESS;

	list = _r_obj_createlist (0x08, _app_packs_stateentrycleanup);

	line = contents->buffer;
	next = NULL;

	while (line && *line)
	{
		_app_packs_nextline (line, &line_length, &next);

		if (!line_length)
			break;

		if (_app_packs_lineis (line, line_length, PACKS_STATE_MAGIC) || _app_packs_lineis (line, line_length, L"state_hash="))
		{
			line = next;
			continue;
		}

		if (_app_packs_lineis (line, line_length, L"pack="))
		{
			LPCWSTR sep1;
			LPCWSTR sep2;
			SIZE_T id_length;
			SIZE_T version_length;

			if (ptr_entry)
			{
				*out_status = STATUS_INVALID_PARAMETER; // pack section opened twice
				break;
			}

			sep1 = wcschr (line + 5, L'|');
			sep2 = sep1 ? wcschr (sep1 + 1, L'|') : NULL;

			if (!sep1 || !sep2 || sep2 >= line + line_length)
			{
				*out_status = STATUS_INVALID_PARAMETER;
				break;
			}

			id_length = (SIZE_T)(sep1 - (line + 5));
			version_length = (SIZE_T)(sep2 - sep1 - 1);

			if (id_length == 0 || id_length > PACKS_MAX_PACKID || version_length == 0 || version_length >= PACKS_VERSION_LENGTH)
			{
				*out_status = STATUS_INVALID_PARAMETER;
				break;
			}

			ptr_entry = _r_mem_allocate (sizeof (PACK_STATE_ENTRY));

			RtlZeroMemory (ptr_entry, sizeof (PACK_STATE_ENTRY));

			memcpy (ptr_entry->pack_id, line + 5, id_length * sizeof (WCHAR));
			ptr_entry->pack_id[id_length] = UNICODE_NULL;

			memcpy (ptr_entry->version, sep1 + 1, version_length * sizeof (WCHAR));
			ptr_entry->version[version_length] = UNICODE_NULL;

			if (swscanf_s (sep2 + 1, L"%8x", &ptr_entry->rules_hash) != 1)
			{
				_r_mem_free (ptr_entry);
				ptr_entry = NULL;

				*out_status = STATUS_INVALID_PARAMETER;
				break;
			}

			ptr_entry->guids = _r_obj_createarray (sizeof (GUID), 0x10, NULL);

			_r_obj_addlistitem (list, ptr_entry, NULL); // list owns the entry from here on
		}
		else if (_app_packs_lineis (line, line_length, L"filter="))
		{
			GUID guid;

			if (!ptr_entry)
			{
				*out_status = STATUS_INVALID_PARAMETER; // filter line outside a pack section
				break;
			}

			if (!_app_packs_toguid (line + 7, &guid))
			{
				*out_status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (_r_obj_getarraysize (ptr_entry->guids) >= PACKS_MAX_FILTERS)
			{
				*out_status = STATUS_INVALID_PARAMETER; // bound integrity
				break;
			}

			_r_obj_addarrayitem (ptr_entry->guids, &guid, NULL);
		}
		else
		{
			*out_status = STATUS_INVALID_PARAMETER; // unknown line = corrupt
			break;
		}

		line = next;
	}

	if (!NT_SUCCESS (*out_status))
	{
		_r_obj_dereference (list); // cleanup callback releases entries + guids

		return NULL;
	}

	return list;
}

// query: pack enabled? (and its recorded rules-hash when present)
static BOOLEAN _app_packs_statelookup (
	_In_ PR_LIST list,
	_In_ LPCWSTR pack_id,
	_Out_opt_ PULONG out_hash,
	_Outptr_result_maybenull_ PPACK_STATE_ENTRY *out_entry
)
{
	PPACK_STATE_ENTRY ptr_entry;
	ULONG_PTR i;

	*out_entry = NULL;

	if (out_hash)
		*out_hash = 0;

	for (i = 0; i < _r_obj_getlistsize (list); i++)
	{
		ptr_entry = (PPACK_STATE_ENTRY)_r_obj_getlistitem (list, i);

		if (ptr_entry && wcscmp (ptr_entry->pack_id, pack_id) == 0)
		{
			if (out_hash)
				*out_hash = ptr_entry->rules_hash;

			*out_entry = ptr_entry;

			return TRUE;
		}
	}

	return FALSE;
}

// serialize the parsed state back to the sidecar with a fresh trailer;
// the source must have passed _app_packs_stateverify (a corrupt store is
// never rewritten — DATA-02)
static NTSTATUS _app_packs_statewrite (
	_In_ PR_LIST list
)
{
	PR_STRING path = NULL;
	PR_STRING contents;
	PR_STRING guid_string;
	PR_STRINGBUILDER sb;
	PPACK_STATE_ENTRY ptr_entry;
	ULONG hash;
	NTSTATUS status;
	LPCGUID guid;
	ULONG_PTR i;
	ULONG_PTR j;

	_app_packs_getpath (COMPOSITE_SIDECAR_PACKSTATE, &path);

	if (!path)
		return STATUS_UNSUCCESSFUL;

	_r_obj_initializestringbuilder (sb, 0x1000);

	_r_obj_appendstringbuilder_ex (sb, PACKS_STATE_MAGIC, RTL_NUMBER_OF (PACKS_STATE_MAGIC) - 1);

	_r_obj_appendstringbuilder_ex (sb, L"\r\n", 2 * sizeof (WCHAR));

	for (i = 0; i < _r_obj_getlistsize (list); i++)
	{
		ptr_entry = (PPACK_STATE_ENTRY)_r_obj_getlistitem (list, i);

		if (!ptr_entry)
			continue;

		_r_obj_appendstringbuilderformat (sb, L"pack=%s|%s|%08x\r\n", ptr_entry->pack_id, ptr_entry->version, ptr_entry->rules_hash);

		for (j = 0; j < _r_obj_getarraysize (ptr_entry->guids); j++)
		{
			guid = (LPCGUID)_r_obj_getarrayitem (ptr_entry->guids, j);

			if (!guid)
				continue;

			guid_string = NULL;

			if (NT_SUCCESS (_r_str_fromguid (&guid_string, guid, TRUE)) && guid_string)
			{
				_r_obj_appendstringbuilderformat (sb, L"filter=%s|%s\r\n", ptr_entry->pack_id, guid_string->buffer);

				_r_obj_dereference (guid_string);
			}
		}
	}

	// tamper-evident trailer: FNV1a-32 over everything written so far;
	// the hash is computed over the finalized bytes, then the trailer is
	// appended to the same builder
	contents = _r_obj_finalstringbuilder (sb);

	hash = _app_packs_fnv1a32 ((const BYTE *)contents->buffer, contents->length * sizeof (WCHAR));

	_r_obj_dereference (contents);

	_r_obj_appendstringbuilderformat (sb, L"state_hash=%08x\r\n", hash);

	contents = _r_obj_finalstringbuilder (sb);

	status = _app_packs_writewide (path->buffer, contents);

	_r_obj_deletestringbuilder (sb);

	_r_obj_dereference (contents);
	_r_obj_dereference (path);

	return status;
}

//
// Filter application (transaction pattern mirrors _app_state_deploy)
//

static ULONG _app_packs_createfilter (
	_In_ HANDLE engine_handle,
	_In_ LPCWSTR pack_id,
	_In_ LPCGUID layer_id,
	_In_reads_ (count) FWPM_FILTER_CONDITION0 *conditions,
	_In_ UINT32 count,
	_Inout_ PR_ARRAY guids
)
{
	FWPM_FILTER0 filter = {0};
	WCHAR filter_description[0x80];
	GUID filter_key;
	ULONG status;

	// contract: pack filter GUIDs come from CoCreateGuid so the recorded
	// delta is exactly what BFE generated (never reused across imports)
	if (FAILED (CoCreateGuid (&filter_key)))
		return (ULONG)E_FAIL;

	filter.filterKey = filter_key;

	filter.displayData.name = L"simplewall composite pack";

	_r_str_printf (filter_description, RTL_NUMBER_OF (filter_description), L"pack\\%s", pack_id);

	filter.displayData.description = filter_description;

	RtlCopyMemory (&filter.providerKey, &GUID_WfpProvider, sizeof (GUID));
	RtlCopyMemory (&filter.subLayerKey, &GUID_WfpSublayer, sizeof (GUID));
	RtlCopyMemory (&filter.layerKey, layer_id, sizeof (GUID));

	// weight 0xE0: below every user rule weight — user consent outranks
	// packs (header comment); packs are BLOCK-only so no pack allow can
	// ever shadow a user block
	filter.weight.type = FWP_UINT8;
	filter.weight.uint8 = PACKS_FILTER_WEIGHT;

	filter.action.type = FWP_ACTION_BLOCK;

	// packs are durable installs: the filters must survive reboot; the
	// packstate GUID delta is the exact removal source afterwards
	filter.flags = FWPM_FILTER_FLAG_PERSISTENT;

	filter.numFilterConditions = count;
	filter.filterCondition = conditions;

	status = FwpmFilterAdd0 (engine_handle, &filter, NULL, NULL);

	if (status == ERROR_SUCCESS)
		_r_obj_addarrayitem (guids, &filter_key, NULL);
	else
		_r_log (LOG_LEVEL_ERROR, NULL, L"composite_packs", L"FwpmFilterAdd0 (pack rule)", (LONG)status);

	return status;
}

// apply one validated rule to the layer pair its kind/direction select
static BOOLEAN _app_packs_applyrule (
	_In_ HANDLE engine_handle,
	_In_ LPCWSTR pack_id,
	_In_ const PPACK_RULE ptr_rule,
	_Inout_ PR_ARRAY guids
)
{
	FWPM_FILTER_CONDITION0 conditions[2];
	FWP_BYTE_BLOB *app_blob = NULL;
	ULONG status;
	BOOLEAN is_success = TRUE;
	ULONG_PTR i;

	// layer selection: pack traffic rides the ALE auth layers; the V6
	// pair is used only for IPv6 address rules (contract), everything
	// else lands on the V4 pair
	LPCGUID layer_out = (ptr_rule->kind == PACK_RULE_ADDRESS && ptr_rule->af == AF_INET6) ? &FWPM_LAYER_ALE_AUTH_CONNECT_V6 : &FWPM_LAYER_ALE_AUTH_CONNECT_V4;
	LPCGUID layer_in = (ptr_rule->kind == PACK_RULE_ADDRESS && ptr_rule->af == AF_INET6) ? &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 : &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

	RtlZeroMemory (conditions, sizeof (conditions));

	// build conditions once; the same set is applied to every layer the
	// direction selects
	if (ptr_rule->kind == PACK_RULE_PATH)
	{
		if (FAILED (FwpmGetAppIdFromFileName0 (ptr_rule->path->buffer, &app_blob)) || !app_blob)
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_packs", L"FwpmGetAppIdFromFileName0 failed", (LONG)0);

			return FALSE;
		}

		conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
		conditions[0].matchType = FWP_MATCH_EQUAL;
		conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
		conditions[0].conditionValue.byteBlob = app_blob;
	}
	else if (ptr_rule->kind == PACK_RULE_PORT)
	{
		// port + protocol ride the same ALE auth layers (tcp/udp both do)
		conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		conditions[0].matchType = FWP_MATCH_EQUAL;
		conditions[0].conditionValue.type = FWP_UINT16;
		conditions[0].conditionValue.uint16 = ptr_rule->port;

		conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		conditions[1].matchType = FWP_MATCH_EQUAL;
		conditions[1].conditionValue.type = FWP_UINT8;
		conditions[1].conditionValue.uint8 = ptr_rule->protocol;
	}
	else if (ptr_rule->kind == PACK_RULE_ADDRESS)
	{
		conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
		conditions[0].matchType = FWP_MATCH_EQUAL;

		if (ptr_rule->af == AF_INET6)
		{
			conditions[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
			conditions[0].conditionValue.byteArray16 = (FWP_BYTE_ARRAY16 *)ptr_rule->address;
		}
		else
		{
			// FWP_UINT32 v4 addresses are host byte order
			conditions[0].conditionValue.type = FWP_UINT32;
			conditions[0].conditionValue.uint32 = ((ULONG)ptr_rule->address[0] << 24) | ((ULONG)ptr_rule->address[1] << 16) |
				((ULONG)ptr_rule->address[2] << 8) | (ULONG)ptr_rule->address[3];
		}
	}

	// direction → layer pair ("both" = both layers)
	for (i = 0; i < 2; i++)
	{
		if (i == 0 && ptr_rule->direction == PACK_DIRECTION_IN)
			continue;

		if (i == 1 && ptr_rule->direction == PACK_DIRECTION_OUT)
			continue;

		status = _app_packs_createfilter (engine_handle, pack_id, i == 0 ? layer_out : layer_in, conditions, (ptr_rule->kind == PACK_RULE_PORT) ? 2 : 1, guids);

		if (status != ERROR_SUCCESS)
			is_success = FALSE; // logged in _app_packs_createfilter
	}

	if (ptr_rule->kind == PACK_RULE_PATH && app_blob)
		FwpmFreeMemory0 ((PVOID *)&app_blob);

	return is_success;
}

static NTSTATUS _app_packs_apply (
	_In_ HANDLE engine_handle,
	_In_ LPCWSTR pack_id,
	_In_ const PPACK_INFO ptr_pack,
	_Inout_ PR_ARRAY guids
)
{
	ENUM_TRANSACT_STATE transact_state;
	BOOLEAN is_intransact;
	BOOLEAN is_locked = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR i;

	if (_r_obj_getarraysize (guids) >= PACKS_MAX_FILTERS)
		return STATUS_INVALID_PARAMETER;

	if (_wfp_isfiltersapplying ())
	{
		// an apply is in flight on this session — our adds join its
		// transaction (BFE transactions are session-wide); never commit
		// what we do not own
		is_intransact = TRUE;
	}
	else
	{
		_r_queuedlock_acquireshared (&lock_transaction);

		is_locked = TRUE;

		transact_state = _wfp_transact_start (engine_handle, DBG_ARG);

		if (transact_state == TXN_FAILED)
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_packs", L"transaction unavailable; pack import aborted", (LONG)transact_state);

			_r_queuedlock_releaseshared (&lock_transaction);

			return STATUS_UNSUCCESSFUL;
		}

		is_intransact = (transact_state == TXN_IN_PROGRESS);
	}

	for (i = 0; i < ptr_pack->rule_count; i++)
	{
		if (!_app_packs_applyrule (engine_handle, pack_id, &ptr_pack->rules[i], guids))
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
	}

	if (!is_intransact)
		_wfp_transact_commit (engine_handle, DBG_ARG);

	if (is_locked)
		_r_queuedlock_releaseshared (&lock_transaction);

	// a partial apply leaves recorded GUIDs behind for exact removal; the
	// caller decides between keeping (state write) or cleaning up
	return status;
}

// remove an exact GUID delta inside the standard transaction window
static NTSTATUS _app_packs_removedelta (
	_In_ HANDLE engine_handle,
	_In_ PR_ARRAY guids
)
{
	ENUM_TRANSACT_STATE transact_state;
	BOOLEAN is_intransact;
	BOOLEAN is_locked = FALSE;
	NTSTATUS status = STATUS_SUCCESS;
	LPCGUID guid;
	ULONG_PTR i;

	if (_r_obj_isempty2 (guids))
		return STATUS_SUCCESS;

	if (_wfp_isfiltersapplying ())
	{
		is_intransact = TRUE;
	}
	else
	{
		_r_queuedlock_acquireshared (&lock_transaction);

		is_locked = TRUE;

		transact_state = _wfp_transact_start (engine_handle, DBG_ARG);

		if (transact_state == TXN_FAILED)
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_packs", L"transaction unavailable; pack removal aborted", (LONG)transact_state);

			_r_queuedlock_releaseshared (&lock_transaction);

			return STATUS_UNSUCCESSFUL;
		}

		is_intransact = (transact_state == TXN_IN_PROGRESS);
	}

	for (i = 0; i < _r_obj_getarraysize (guids); i++)
	{
		guid = (LPCGUID)_r_obj_getarrayitem (guids, i);

		if (guid && !_wfp_deletefilter (engine_handle, guid, DBG_ARG))
			status = STATUS_UNSUCCESSFUL; // best-effort exact removal; failures logged upstream
	}

	if (!is_intransact)
		_wfp_transact_commit (engine_handle, DBG_ARG);

	if (is_locked)
		_r_queuedlock_releaseshared (&lock_transaction);

	return status;
}

//
// Public API
//

BOOLEAN _app_packs_isenabled (
	_In_ LPCWSTR pack_id
)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	BOOLEAN is_present = FALSE;
	PR_LIST list;
	BOOLEAN is_enabled = FALSE;
	NTSTATUS status;

	if (!pack_id || !pack_id[0])
		return FALSE;

	_app_packs_getpath (COMPOSITE_SIDECAR_PACKSTATE, &path);

	if (!path)
		return FALSE;

	status = _app_packs_readwide (path->buffer, &contents, &is_present);

	if (!is_present || !NT_SUCCESS (status))
	{
		if (contents)
			_r_obj_dereference (contents);

		_r_obj_dereference (path);

		return FALSE; // missing/corrupt state = no packs enabled
	}

	if (!NT_SUCCESS (_app_packs_stateverify (contents)))
	{
		_r_obj_dereference (contents);
		_r_obj_dereference (path);

		return FALSE; // corrupt state = packs treated as disabled
	}

	list = _app_packs_stateparse (contents, &status);

	if (NT_SUCCESS (status))
	{
		PPACK_STATE_ENTRY ptr_entry;

		is_enabled = _app_packs_statelookup (list, pack_id, NULL, &ptr_entry);
	}

	if (list)
		_r_obj_dereference (list);

	_r_obj_dereference (contents);
	_r_obj_dereference (path);

	return is_enabled;
}

NTSTATUS _app_packs_import (
	_In_ LPCWSTR pack_dir
)
{
	PR_STRING path_json = NULL;
	PR_STRING path_sig = NULL;
	PR_STRING path_state = NULL;
	PR_STRING json_string = NULL;
	PR_STRING state_contents = NULL;
	BOOLEAN state_present = FALSE;
	BYTE *sig_bytes = NULL;
	SIZE_T sig_length = 0;
	PACK_INFO pack = {0};
	PR_LIST state_list = NULL;
	PPACK_STATE_ENTRY state_entry = NULL;
	PR_ARRAY guids = NULL;
	ULONG_PTR watermark_compare = 0;
	HANDLE engine_handle;
	BOOLEAN has_old = FALSE;
	NTSTATUS status;

	_r_queuedlock_acquireexclusive (&lock_packs);

	engine_handle = _wfp_getenginehandle ();

	// import requires a running engine: a verified pack must be able to
	// either fully apply or fail loudly — never verify now, apply never
	if (!engine_handle || !_wfp_isfiltersinstalled ())
	{
		_app_packs_logpack (LOG_LEVEL_WARNING, L"import refused: engine unavailable", (LONG)STATUS_DEVICE_NOT_READY);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_DEVICE_NOT_READY;
	}

	if (!pack_dir || !pack_dir[0])
	{
		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_INVALID_PARAMETER;
	}

	path_json = _r_obj_concatstrings (3, pack_dir, L"\\", L"pack.json");
	path_sig = _r_obj_concatstrings (3, pack_dir, L"\\", L"pack.sig");

	if (!path_json || !path_sig)
	{
		status = STATUS_NO_MEMORY;
		goto cleanup_exit;
	}

	// pack.json: binary-preserving load — the signature covers the EXACT
	// bytes on disk, so no text normalization may ever touch them
	{
		BYTE *json_bytes = NULL;
		SIZE_T json_length = 0;

		status = _app_packs_readraw (path_json->buffer, &json_bytes, &json_length);

		if (!NT_SUCCESS (status))
		{
			_app_packs_logpack (LOG_LEVEL_WARNING, L"pack.json unreadable", (LONG)status);
			goto cleanup_exit;
		}

		json_string = _r_obj_createstring_ex ((LPCWSTR)json_bytes, json_length);

		_r_mem_free (json_bytes);

		if (!json_string)
		{
			status = STATUS_NO_MEMORY;
			goto cleanup_exit;
		}
	}

	status = _app_packs_readraw (path_sig->buffer, &sig_bytes, &sig_length);

	if (!NT_SUCCESS (status) || sig_length != PACKS_SIG_LENGTH)
	{
		_app_packs_logpack (LOG_LEVEL_WARNING, L"pack.sig missing or not a 64-byte r||s signature", (LONG)status);

		if (NT_SUCCESS (status))
			status = STATUS_INVALID_PARAMETER;

		goto cleanup_exit;
	}

	// SEC-01: verify BEFORE any rule parses — the parser only ever sees
	// signature-covered bytes
	status = _app_packs_verifysignature ((const BYTE *)json_string->buffer, json_string->length, sig_bytes);

	if (!NT_SUCCESS (status))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"signature verification failed; pack refused", (LONG)status);

		status = STATUS_INVALID_PARAMETER;
		goto cleanup_exit;
	}

	// strict parse (signature already verified; the key-id epoch check
	// lives inside the parser against PACKS_KEY_ID_UTF8)
	RtlZeroMemory (&pack, sizeof (pack));

	if (!_app_packs_parsepack ((const BYTE *)json_string->buffer, json_string->length, &pack))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"pack schema violation; pack refused", (LONG)0);

		status = STATUS_INVALID_PARAMETER;
		goto cleanup_exit;
	}

	pack.rules_hash = _app_packs_fnv1a32 ((const BYTE *)json_string->buffer, json_string->length);

	// anti-rollback: read the high-water store; corrupt = refuse forever
	status = _app_packs_watermarkcheck (&pack, &watermark_compare);

	if (!NT_SUCCESS (status))
	{
		status = STATUS_INVALID_PARAMETER;
		goto cleanup_exit;
	}

	if (watermark_compare == 0)
	{
		_app_packs_logpack (LOG_LEVEL_WARNING, L"version below high-water mark; pack refused (anti-rollback)", (LONG)0);

		status = STATUS_REVISION_MISMATCH;
		goto cleanup_exit;
	}

	// current enable state (from the hash-verified sidecar only)
	_app_packs_getpath (COMPOSITE_SIDECAR_PACKSTATE, &path_state);

	if (!path_state)
	{
		status = STATUS_UNSUCCESSFUL;
		goto cleanup_exit;
	}

	status = _app_packs_readwide (path_state->buffer, &state_contents, &state_present);

	if (state_present && !NT_SUCCESS (status))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate corrupt; import refused (never rebuilt)", status);

		status = STATUS_INVALID_PARAMETER;
		goto cleanup_exit;
	}

	has_old = FALSE;

	if (state_present)
	{
		if (!NT_SUCCESS (_app_packs_stateverify (state_contents)))
		{
			_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate corrupt; import refused (never rebuilt)", (LONG)0);

			status = STATUS_INVALID_PARAMETER;
			goto cleanup_exit;
		}

		state_list = _app_packs_stateparse (state_contents, &status);

		if (!state_list)
		{
			_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate parse failed; import refused (never rebuilt)", (LONG)status);

			status = STATUS_INVALID_PARAMETER;
			goto cleanup_exit;
		}

		has_old = _app_packs_statelookup (state_list, pack.pack_id, NULL, &state_entry);
	}

	// idempotent no-op: already enabled at the high-water version with
	// the identical rule content
	if (has_old && watermark_compare == 1 && state_entry && state_entry->rules_hash == pack.rules_hash)
	{
		_app_packs_logpack (LOG_LEVEL_INFO, L"pack already enabled with identical rules; no-op", (LONG)0);

		status = STATUS_SUCCESS;
		goto cleanup_exit;
	}

	guids = _r_obj_createarray (sizeof (GUID), 0x10, NULL);

	// update path: remove the old pack's exact filter delta first; a
	// failed removal aborts the import BEFORE the new filters land, so
	// the recorded delta is never lost
	if (has_old && state_entry)
	{
		if (!NT_SUCCESS (_app_packs_removedelta (engine_handle, state_entry->guids)))
		{
			_app_packs_logpack (LOG_LEVEL_ERROR, L"old filter delta removal failed; import aborted", (LONG)0);

			status = STATUS_UNSUCCESSFUL;
			goto cleanup_exit;
		}
	}

	// apply the new pack inside the standard transaction window
	status = _app_packs_apply (engine_handle, pack.pack_id, &pack, guids);

	if (!NT_SUCCESS (status) || _r_obj_isempty2 (guids))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"pack filter apply failed", (LONG)status);

		// the old delta (if any) is already gone: drop the old section
		// from the state so the sidecar never points at removed filters
		// (honest ledger; the pack is simply not enabled)
		if (has_old && state_entry && state_list)
		{
			for (ULONG_PTR i = 0; i < _r_obj_getlistsize (state_list); i++)
			{
				if ((PPACK_STATE_ENTRY)_r_obj_getlistitem (state_list, i) == state_entry)
				{
					_r_obj_removelistitem (state_list, i); // list cleanup frees entry + guids ref

					break;
				}
			}

			_app_packs_statewrite (state_list);
		}

		status = STATUS_UNSUCCESSFUL;
		goto cleanup_exit;
	}

	// rewrite the packstate: drop the old section, add the new one, and
	// recompute the tamper-evident trailer (source was hash-verified)
	if (!state_list)
		state_list = _r_obj_createlist (0x08, _app_packs_stateentrycleanup);

	if (has_old && state_entry)
	{
		for (ULONG_PTR i = 0; i < _r_obj_getlistsize (state_list); i++)
		{
			if ((PPACK_STATE_ENTRY)_r_obj_getlistitem (state_list, i) == state_entry)
			{
				_r_obj_removelistitem (state_list, i); // list cleanup frees entry + guids ref

				break;
			}
		}
	}

	state_entry = _r_mem_allocate (sizeof (PACK_STATE_ENTRY));

	RtlZeroMemory (state_entry, sizeof (PACK_STATE_ENTRY));

	wcscpy_s (state_entry->pack_id, RTL_NUMBER_OF (state_entry->pack_id), pack.pack_id);

	_r_str_printf (state_entry->version, RTL_NUMBER_OF (state_entry->version), L"%lu.%lu.%lu",
		pack.version[0], pack.version[1], pack.version[2]);

	state_entry->rules_hash = pack.rules_hash;
	state_entry->guids = guids; // transfer ownership (list cleanup derefs)
	guids = NULL;

	_r_obj_addlistitem (state_list, state_entry, NULL);

	status = _app_packs_statewrite (state_list);

	if (!NT_SUCCESS (status))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate write failed; pack filters remain but state is stale", (LONG)status);

		goto cleanup_exit;
	}

	// watermark AFTER a fully successful apply (an aborted apply must
	// never raise the high-water: the same version could then never be
	// legitimately re-imported)
	if (watermark_compare == 2)
	{
		status = _app_packs_watermarkwrite (&pack);

		if (!NT_SUCCESS (status))
			goto cleanup_exit;
	}

	_app_packs_logpack (LOG_LEVEL_INFO, L"pack imported and enabled", (LONG)0);

	status = STATUS_SUCCESS;

cleanup_exit:
	// filter GUIDs that never reached the state file are exact garbage:
	// remove them so a failed import cannot leak applied filters
	if (guids && !_r_obj_isempty2 (guids) && _wfp_isfiltersinstalled ())
		_wfp_destroyfilters_array (engine_handle, guids, DBG_ARG);

	if (guids)
		_r_obj_dereference (guids);

	if (state_list)
		_r_obj_dereference (state_list);

	if (sig_bytes)
		_r_mem_free (sig_bytes);

	if (json_string)
		_r_obj_dereference (json_string);

	_app_packs_freepack (&pack);

	if (state_contents)
		_r_obj_dereference (state_contents);

	if (path_state)
		_r_obj_dereference (path_state);

	if (path_sig)
		_r_obj_dereference (path_sig);

	if (path_json)
		_r_obj_dereference (path_json);

	_r_queuedlock_releaseexclusive (&lock_packs);

	return status;
}

NTSTATUS _app_packs_disable (
	_In_ LPCWSTR pack_id
)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	BOOLEAN is_present = FALSE;
	PR_LIST list = NULL;
	PPACK_STATE_ENTRY ptr_entry = NULL;
	BOOLEAN has_pack;
	NTSTATUS status;
	HANDLE engine_handle;

	if (!pack_id || !pack_id[0])
		return STATUS_INVALID_PARAMETER;

	_r_queuedlock_acquireexclusive (&lock_packs);

	engine_handle = _wfp_getenginehandle ();

	if (!engine_handle || !_wfp_isfiltersinstalled ())
	{
		_app_packs_logpack (LOG_LEVEL_WARNING, L"disable refused: engine unavailable", (LONG)STATUS_DEVICE_NOT_READY);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_DEVICE_NOT_READY;
	}

	_app_packs_getpath (COMPOSITE_SIDECAR_PACKSTATE, &path);

	if (!path)
	{
		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_UNSUCCESSFUL;
	}

	status = _app_packs_readwide (path->buffer, &contents, &is_present);

	if (!is_present)
	{
		_r_obj_dereference (path);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_NOT_FOUND;
	}

	if (!NT_SUCCESS (status))
	{
		// corrupt state = refuse (the filter delta is unprovable — DATA-02)
		_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate corrupt; disable refused (never rebuilt)", status);

		if (contents)
			_r_obj_dereference (contents);

		_r_obj_dereference (path);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_INVALID_PARAMETER;
	}

	status = _app_packs_stateverify (contents);

	if (!NT_SUCCESS (status))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate hash mismatch; disable refused (never rebuilt)", (LONG)status);

		_r_obj_dereference (contents);
		_r_obj_dereference (path);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_INVALID_PARAMETER;
	}

	list = _app_packs_stateparse (contents, &status);

	_r_obj_dereference (contents);
	contents = NULL;

	if (!list)
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"packstate parse failed; disable refused (never rebuilt)", (LONG)status);

		_r_obj_dereference (path);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_INVALID_PARAMETER;
	}

	has_pack = _app_packs_statelookup (list, pack_id, NULL, &ptr_entry);

	if (!has_pack || !ptr_entry)
	{
		_r_obj_dereference (list);
		_r_obj_dereference (path);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return STATUS_NOT_FOUND;
	}

	// exact delta removal: only the GUIDs recorded at apply time
	status = _app_packs_removedelta (engine_handle, ptr_entry->guids);

	if (!NT_SUCCESS (status))
	{
		_app_packs_logpack (LOG_LEVEL_ERROR, L"filter delta removal failed; pack state unchanged", (LONG)status);

		_r_obj_dereference (list);
		_r_obj_dereference (path);

		_r_queuedlock_releaseexclusive (&lock_packs);
		return status;
	}

	// rewrite state without the section (recomputed trailer)
	for (ULONG_PTR i = 0; i < _r_obj_getlistsize (list); i++)
	{
		if ((PPACK_STATE_ENTRY)_r_obj_getlistitem (list, i) == ptr_entry)
		{
			_r_obj_removelistitem (list, i); // list cleanup frees entry + guids ref

			break;
		}
	}

	status = _app_packs_statewrite (list);

	if (NT_SUCCESS (status))
		_app_packs_logpack (LOG_LEVEL_INFO, L"pack disabled", (LONG)0);

	_r_obj_dereference (list);
	_r_obj_dereference (path);

	_r_queuedlock_releaseexclusive (&lock_packs);

	return status;
}

VOID _app_packs_startupcheck (VOID)
{
	PR_STRING path = NULL;
	PR_STRING contents = NULL;
	BOOLEAN is_present = FALSE;
	NTSTATUS status;

	_app_packs_getpath (COMPOSITE_SIDECAR_PACKSTATE, &path);

	if (!path)
		return;

	status = _app_packs_readwide (path->buffer, &contents, &is_present);

	if (!is_present)
	{
		// no state file = no packs ever enabled: nothing to check
		if (contents)
			_r_obj_dereference (contents);

		_r_obj_dereference (path);
		return;
	}

	status = _app_packs_stateverify (contents);

	if (!NT_SUCCESS (status))
	{
		// corrupt state = CRITICAL: packs are treated as disabled until a
		// re-import; the file is LEFT IN PLACE for forensics (DATA-02
		// forbids silent rebuilds, and isenabled refuses via the same check)
		_app_packs_logpack (LOG_LEVEL_CRITICAL, L"packstate corrupt; packs treated as disabled until re-import (file kept for forensics)", (LONG)status);
	}
	else
	{
		_r_log_v (LOG_LEVEL_INFO, NULL, L"composite_packs", 0, L"packstate verified at startup (%u bytes)", (UINT)contents->length);
	}

	_r_obj_dereference (contents);
	_r_obj_dereference (path);
}
