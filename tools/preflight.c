// preflight.c
// gated release preflight for the simplewall fork (C edition)
//
// Attribution / lineage (NFR-01, DEC-06): implemented per
// docs/specs/tooling/design.md r3 (DEC-08/09/10/11, FR-07/FR-02/SEC-02,
// NFR-02/NFR-03) and docs/specs/tooling/plan.md "C unification approach".
// LOGIC-PARITY TARGET: tools/release-preflight.py — same check order
// (ground-truth-load, pe/app-h parse, a, b1, b2, c, d, e, f), same evidence
// lines, same --ci SKIP labels, same --json shape, same exit semantics,
// same fail-closed ground-truth handling. Reuses the vendored routine
// library exclusively (console/fs/crypt/res/xml/sys APIs + APP_CONSOLE
// bootstrap) and the PRODUCTION feed-signature verifier
// _r_update_verifysignature (DEC-09, T008 vendor export) — no verification
// logic is reimplemented. Authenticode authority is Windows itself via the
// SAME PowerShell Get-AuthenticodeSignature subprocess the python reference
// uses (disclosed OS-provided binary per SEC-01). The check set and parity
// constants come from the 2026-11-07 hardening sessions;
// tools/cng-signature-bench.py remains the separate owner-side gate and is
// NOT called here.
//
// Output mechanism note: the routine console writers target the PE loader's
// StandardOutput handle and only succeed on a real console. When stdout is
// redirected (pipes, `--json > preflight.json` CI capture, git-bash), this
// tool falls back to WriteFile with UTF-8 — required for the CI artifact
// journey; console output still goes through _r_console_writestring_ex.
//
// Usage:
//   preflight.exe <exe>                       full profile
//   preflight.exe <exe> --ci                  CI profile (skips (a) and (b2))
//   preflight.exe <exe> --json                machine-readable output
//   preflight.exe <exe> --thumbprint <hex>    (a) thumbprint override
//   preflight.exe <exe> --app-h <path>        (d) src/app.h override
//   preflight.exe <exe> --ground-truth-dir <dir>
//   preflight.exe <exe> --feed-dir <dir>      (b-feed) override (default:
//                                             repo root, i.e. exe\..\..)
//
// Exit 0 only when every SELECTED check passes. Missing/unparseable inputs
// fail closed (FR-02/SEC-02) — never a silent skip.

#include "rapp.h"

#include <stdarg.h>
#include <shellapi.h>
#include <wchar.h>

#pragma comment(lib, "shell32.lib")


//
// Constants (parity with tools/release-preflight.py)
//

#define DEFAULT_THUMBPRINT L"DC91477AF1415F6D7C3B181B1EB2EC45FF907ED0"

// Known-bad artifacts that must never reappear in any shipped binary
// (docs/specs/routine-hardening/design.md r2: the transcription-corrupted
// public key from commit db1ef855) — the historical corrupted Y half.
static const BYTE CORRUPTED_KEY_Y[32] = {
	0xfa, 0xf3, 0xcf, 0xcb, 0x0e, 0x44, 0x87, 0x42,
	0x71, 0xc3, 0xe4, 0x2d, 0xcf, 0xfb, 0xb2, 0xf4,
	0x29, 0x24, 0xca, 0x61, 0xa8, 0x31, 0x5d, 0x84,
	0xef, 0x2e, 0xc0, 0x72, 0x3e, 0x02, 0xc6, 0xf0,
};

// owner-side off-repo key ground truth (same hardcoded path as the python
// reference; release profile only — the JSON never leaves the owner machine)
#define KEY_JSON_PATH L"D:\\CV\\Github\\.keys\\simplewall-signing.json"

#define PS_TIMEOUT 60000 // ms (python: subprocess timeout=60)

#define EVIDENCE_MAX 1200
#define MAX_RESULTS 12
#define MAX_GT_STRINGS 96
#define MAX_GT_FLAGS 16
#define PS_OUTPUT_MAX (64 * 1024)

//
// Bounded wide-string builder
//

typedef struct _STRB
{
	WCHAR buf[2048];
	SIZE_T len;
} STRB;

static VOID strb_reset (STRB *sb)
{
	sb->len = 0;
	sb->buf[0] = UNICODE_NULL;
}

static VOID strb_add (STRB *sb, LPCWSTR string)
{
	while (*string)
	{
		if (sb->len >= (RTL_NUMBER_OF (sb->buf) - 1))
			break;

		sb->buf[sb->len++] = *string++;
	}

	sb->buf[sb->len] = UNICODE_NULL;
}

static VOID strb_addformat (STRB *sb, LPCWSTR format, ...)
{
	WCHAR tmp[512];
	va_list arg_ptr;

	va_start (arg_ptr, format);
	_vsnwprintf_s (tmp, RTL_NUMBER_OF (tmp), _TRUNCATE, format, arg_ptr);
	va_end (arg_ptr);

	strb_add (sb, tmp);
}

static VOID copy_bounded (WCHAR *dst, SIZE_T dst_cch, LPCWSTR src)
{
	SIZE_T i = 0;

	if (!dst_cch)
		return;

	while (src && src[i] && i < (dst_cch - 1))
	{
		dst[i] = src[i];
		i += 1;
	}

	dst[i] = UNICODE_NULL;
}

//
// Console output (routine writer + UTF-8 fallback for redirected stdout)
//

// length is in BYTES (the routine's R_STRINGREF convention); convert to
// characters internally for WriteConsoleW/WideCharToMultiByte
// length is in BYTES (the routine's R_STRINGREF convention); convert to
// characters internally for WriteConsoleW/WideCharToMultiByte
static VOID out_write (LPCWSTR string, ULONG_PTR length)
{
	HANDLE hconsole;
	ULONG mode;
	ULONG chars = (ULONG)(length / sizeof (WCHAR));
	BOOL console_written = FALSE;

	hconsole = NtCurrentPeb ()->ProcessParameters->StandardOutput;

	if (hconsole && hconsole != INVALID_HANDLE_VALUE)
	{
		// real console: the routine writer serves this handle (checked via
		// the actual write result — pseudo-console handles fail here)
		console_written = (GetConsoleMode (hconsole, &mode) != FALSE) &&
			(WriteConsoleW (hconsole, string, chars, NULL, NULL) != FALSE) &&
			(WriteConsoleW (hconsole, L"\r\n", 2, NULL, NULL) != FALSE);
	}

	if (console_written)
		return;

	// redirected stdout (pipe/file): convert to UTF-8 so --json capture,
	// pipes and git-bash receive the output (WriteConsoleW cannot serve
	// non-console handles)
	{
		PCHAR buffer;
		INT buffer_length;
		DWORD written = 0;
		static const CHAR newline[] = "\n";

		if (!hconsole || hconsole == INVALID_HANDLE_VALUE)
			hconsole = GetStdHandle (STD_OUTPUT_HANDLE);

		buffer_length = WideCharToMultiByte (CP_UTF8, 0, string, (INT)chars, NULL, 0, NULL, NULL);

		if (buffer_length > 0)
		{
			buffer = (PCHAR)_r_mem_allocate ((SIZE_T)buffer_length);

			if (WideCharToMultiByte (CP_UTF8, 0, string, (INT)chars, buffer, buffer_length, NULL, NULL) > 0)
				WriteFile (hconsole, buffer, (DWORD)buffer_length, &written, NULL);

			_r_mem_free (buffer);
		}

		WriteFile (hconsole, newline, (DWORD)(RTL_NUMBER_OF (newline) - 1), &written, NULL);
	}
}

//
// Check records
//

typedef struct _CHECK_RECORD
{
	WCHAR name[96];
	WCHAR status[8];
	WCHAR evidence[EVIDENCE_MAX];
} CHECK_RECORD;

static CHECK_RECORD check_results[MAX_RESULTS];
static ULONG check_count;

#define CHECK_STATE_FAIL 0
#define CHECK_STATE_PASS 1
#define CHECK_STATE_SKIP 2

static BOOLEAN record (LPCWSTR name, INT state, LPCWSTR format, ...)
{
	CHECK_RECORD *rec;
	PR_STRING string;
	va_list arg_ptr;
	PR_STRING line;

	if (check_count >= RTL_NUMBER_OF (check_results))
		return (state != CHECK_STATE_FAIL);

	rec = &check_results[check_count++];

	copy_bounded (rec->name, RTL_NUMBER_OF (rec->name), name);
	copy_bounded (rec->status, RTL_NUMBER_OF (rec->status), state == CHECK_STATE_SKIP ? L"SKIP" : (state == CHECK_STATE_PASS ? L"PASS" : L"FAIL"));

	va_start (arg_ptr, format);
	string = _r_format_string_v (format, arg_ptr);
	va_end (arg_ptr);

	copy_bounded (rec->evidence, RTL_NUMBER_OF (rec->evidence), string->sr.buffer);

	line = _r_format_string (L"%ls: %ls %ls %ls", rec->status, rec->name, L"\u2014", rec->evidence);

	out_write (line->buffer, line->length);

	_r_obj_dereference (line);
	_r_obj_dereference (string);

	return (state != CHECK_STATE_FAIL);
}

//
// Ground-truth storage (DEC-11 minimal-JSON-subset reader)
//

typedef struct _GT_DATA
{
	BOOLEAN has_provenance;
	WCHAR prov_source[192];
	WCHAR prov_sha256[128];
	WCHAR prov_captured[64];
	WCHAR prov_note[512];

	WCHAR dlls[MAX_GT_STRINGS][64];
	ULONG dlls_count;

	WCHAR flags[MAX_GT_FLAGS][48];
	ULONG flags_count;

	LONG64 count;
	BOOLEAN has_count;

	LONG64 value;
	BOOLEAN has_value;
} GT_DATA;

static GT_DATA gt_imports_data;
static GT_DATA gt_blocklist_data;
static GT_DATA gt_peflags_data;
static WCHAR key_sha_pinned[128];

//
// Minimal-JSON-subset ground-truth reader (DEC-11)
//
// Handles EXACTLY the ground-truth format: top-level object with
// "provenance" (flat string keys), "dlls": [strings], "flags": [strings],
// "count": integer, "value": integer. Any syntax outside the subset fails
// closed (SEC-02) with an explicit error naming the file. Fixed buffers,
// no dynamic allocation.
//

#define GT_ERR_MAX 192

typedef struct _GT_PARSER
{
	const CHAR *p;
	const CHAR *end;
	WCHAR err[GT_ERR_MAX];
} GT_PARSER;

static VOID gt_seterr (GT_PARSER *gp, LPCWSTR message)
{
	if (!gp->err[0])
		copy_bounded (gp->err, GT_ERR_MAX, message);
}

static VOID gt_seterrfmt (GT_PARSER *gp, LPCWSTR format, ...)
{
	WCHAR tmp[128];
	va_list arg_ptr;

	if (gp->err[0])
		return;

	va_start (arg_ptr, format);
	_vsnwprintf_s (tmp, RTL_NUMBER_OF (tmp), _TRUNCATE, format, arg_ptr);
	va_end (arg_ptr);

	copy_bounded (gp->err, GT_ERR_MAX, tmp);
}

static VOID gt_skipws (GT_PARSER *gp)
{
	while (gp->p < gp->end)
	{
		CHAR ch = *gp->p;

		if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n')
			break;

		gp->p += 1;
	}
}

static BOOLEAN gt_expect (GT_PARSER *gp, CHAR ch)
{
	gt_skipws (gp);

	if (gp->p >= gp->end || *gp->p != ch)
	{
		gt_seterrfmt (gp, L"JSON parse error: expected '%c'", (WCHAR)ch);
		return FALSE;
	}

	gp->p += 1;

	return TRUE;
}

static BOOLEAN gt_is_hex (CHAR ch)
{
	return ((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'));
}

static INT gt_hexval (CHAR ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';

	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;

	return ch - 'A' + 10;
}

static BOOLEAN gt_parse_hex4 (GT_PARSER *gp, WCHAR *out)
{
	INT value = 0;
	ULONG i;

	for (i = 0; i < 4; i++)
	{
		if (gp->p >= gp->end || !gt_is_hex (*gp->p))
		{
			gt_seterr (gp, L"JSON parse error: bad \\u escape");
			return FALSE;
		}

		value = (value << 4) | gt_hexval (*gp->p);
		gp->p += 1;
	}

	*out = (WCHAR)value;

	return TRUE;
}

static BOOLEAN gt_parse_string (GT_PARSER *gp, WCHAR *out, ULONG out_cch)
{
	ULONG pos = 0;

	gt_skipws (gp);

	if (gp->p >= gp->end || *gp->p != '"')
	{
		gt_seterr (gp, L"JSON parse error: expected string");
		return FALSE;
	}

	gp->p += 1;

	while (gp->p < gp->end)
	{
		CHAR ch = *gp->p;
		WCHAR wc;

		if (ch == '"')
		{
			if (pos >= out_cch)
			{
				gt_seterr (gp, L"JSON parse error: string too long");
				return FALSE;
			}

			out[pos] = UNICODE_NULL;
			gp->p += 1;

			return TRUE;
		}

		if ((BYTE)ch < 0x20)
		{
			gt_seterr (gp, L"JSON parse error: raw control char in string");
			return FALSE;
		}

		if (pos >= (out_cch - 1))
		{
			gt_seterr (gp, L"JSON parse error: string too long");
			return FALSE;
		}

		if (ch != '\\')
		{
			// provenance strings are ASCII; tolerate 2-byte UTF-8
			if ((BYTE)ch < 0x80)
			{
				out[pos++] = (WCHAR)(BYTE)ch;
				gp->p += 1;
			}
			else if (((BYTE)ch & 0xE0) == 0xC0 && ((gp->end - gp->p) >= 2) && ((BYTE)gp->p[1] & 0xC0) == 0x80)
			{
				out[pos++] = (WCHAR)((((BYTE)ch & 0x1F) << 6) | ((BYTE)gp->p[1] & 0x3F));
				gp->p += 2;
			}
			else
			{
				gt_seterr (gp, L"JSON parse error: unsupported UTF-8 sequence");
				return FALSE;
			}

			continue;
		}

		// escape
		gp->p += 1;

		if (gp->p >= gp->end)
			break;

		ch = *gp->p;

		switch (ch)
		{
			case '"':
			case '\\':
			case '/':
			{
				wc = (WCHAR)(BYTE)ch;
				gp->p += 1;
				break;
			}

			case 'b':
			{
				wc = L'\b';
				gp->p += 1;
				break;
			}

			case 'f':
			{
				wc = L'\f';
				gp->p += 1;
				break;
			}

			case 'n':
			{
				wc = L'\n';
				gp->p += 1;
				break;
			}

			case 'r':
			{
				wc = L'\r';
				gp->p += 1;
				break;
			}

			case 't':
			{
				wc = L'\t';
				gp->p += 1;
				break;
			}

			case 'u':
			{
				gp->p += 1;

				if (!gt_parse_hex4 (gp, &wc))
					return FALSE;

				if (wc >= 0xD800 && wc <= 0xDBFF)
				{
					WCHAR low;

					// surrogate pair required (fail closed on lone surrogate)
					if ((gp->end - gp->p) < 6 || gp->p[0] != '\\' || gp->p[1] != 'u')
					{
						gt_seterr (gp, L"JSON parse error: lone surrogate escape");
						return FALSE;
					}

					gp->p += 2;

					if (!gt_parse_hex4 (gp, &low))
						return FALSE;

					if (low < 0xDC00 || low > 0xDFFF)
					{
						gt_seterr (gp, L"JSON parse error: bad surrogate pair");
						return FALSE;
					}

					if (pos >= (out_cch - 2))
					{
						gt_seterr (gp, L"JSON parse error: string too long");
						return FALSE;
					}

					out[pos++] = wc;
					out[pos++] = low;

					continue;
				}

				if (wc >= 0xDC00 && wc <= 0xDFFF)
				{
					gt_seterr (gp, L"JSON parse error: lone surrogate escape");
					return FALSE;
				}

				break;
			}

			default:
			{
				gt_seterr (gp, L"JSON parse error: unsupported escape");
				return FALSE;
			}
		}

		out[pos++] = wc;
	}

	gt_seterr (gp, L"JSON parse error: unterminated string");

	return FALSE;
}

static BOOLEAN gt_parse_int (GT_PARSER *gp, LONG64 *out)
{
	BOOLEAN is_negative = FALSE;
	ULONG64 value = 0;

	gt_skipws (gp);

	if (gp->p < gp->end && *gp->p == '-')
	{
		is_negative = TRUE;
		gp->p += 1;
	}

	if (gp->p >= gp->end || *gp->p < '0' || *gp->p > '9')
	{
		gt_seterr (gp, L"JSON parse error: expected integer");
		return FALSE;
	}

	while (gp->p < gp->end && *gp->p >= '0' && *gp->p <= '9')
	{
		value = (value * 10) + (ULONG64)(*gp->p - '0');

		if (value > 0x8000000000000000ULL)
		{
			gt_seterr (gp, L"JSON parse error: integer overflow");
			return FALSE;
		}

		gp->p += 1;
	}

	if (gp->p < gp->end && (*gp->p == '.' || *gp->p == 'e' || *gp->p == 'E'))
	{
		gt_seterr (gp, L"JSON parse error: only integers are supported");
		return FALSE;
	}

	if (is_negative && value > 0x8000000000000000ULL)
	{
		gt_seterr (gp, L"JSON parse error: integer overflow");
		return FALSE;
	}

	*out = is_negative ? -(LONG64)value : (LONG64)value;

	return TRUE;
}

static BOOLEAN gt_parse_string_array (GT_PARSER *gp, WCHAR *arr, ULONG arr_width, ULONG arr_max, ULONG *count)
{
	WCHAR *slot;

	*count = 0;

	if (!gt_expect (gp, '['))
		return FALSE;

	gt_skipws (gp);

	if (gp->p < gp->end && *gp->p == ']')
	{
		gp->p += 1;
		return TRUE;
	}

	while (TRUE)
	{
		if (*count >= arr_max)
		{
			gt_seterr (gp, L"JSON parse error: too many entries");
			return FALSE;
		}

		slot = arr + ((SIZE_T)*count) * arr_width;

		if (!gt_parse_string (gp, slot, arr_width))
			return FALSE;

		*count += 1;

		gt_skipws (gp);

		if (gp->p < gp->end && *gp->p == ',')
		{
			gp->p += 1;
			continue;
		}

		break;
	}

	return gt_expect (gp, ']');
}

static BOOLEAN gt_parse_provenance (GT_PARSER *gp, GT_DATA *out)
{
	WCHAR key[64];
	WCHAR value[512]; // matches the largest member buffer (prov_note[512]) - a 256 temp tripped "string too long" on legitimate provenance notes (CI run 42380633221)

	out->has_provenance = TRUE;

	if (!gt_expect (gp, '{'))
		return FALSE;

	gt_skipws (gp);

	if (gp->p < gp->end && *gp->p == '}')
	{
		gp->p += 1;
		return TRUE;
	}

	while (TRUE)
	{
		if (!gt_parse_string (gp, key, RTL_NUMBER_OF (key)))
			return FALSE;

		if (!gt_expect (gp, ':'))
			return FALSE;

		if (!gt_parse_string (gp, value, RTL_NUMBER_OF (value)))
			return FALSE;

		// flat string keys (DEC-11); the recorded source identifiers are
		// stored for the equality check, other flat keys are accepted
		if (_wcsicmp (key, L"source") == 0)
		{
			copy_bounded (out->prov_source, RTL_NUMBER_OF (out->prov_source), value);
		}
		else if (_wcsicmp (key, L"sha256_of_archive") == 0)
		{
			copy_bounded (out->prov_sha256, RTL_NUMBER_OF (out->prov_sha256), value);
		}
		else if (_wcsicmp (key, L"captured") == 0)
		{
			copy_bounded (out->prov_captured, RTL_NUMBER_OF (out->prov_captured), value);
		}
		else if (_wcsicmp (key, L"note") == 0)
		{
			copy_bounded (out->prov_note, RTL_NUMBER_OF (out->prov_note), value);
		}

		gt_skipws (gp);

		if (gp->p < gp->end && *gp->p == ',')
		{
			gp->p += 1;
			continue;
		}

		break;
	}

	return gt_expect (gp, '}');
}

static BOOLEAN gt_parse_document (GT_PARSER *gp, GT_DATA *out)
{
	WCHAR key[64];

	// optional UTF-8 BOM
	if ((gp->end - gp->p) >= 3 && (BYTE)gp->p[0] == 0xEF && (BYTE)gp->p[1] == 0xBB && (BYTE)gp->p[2] == 0xBF)
		gp->p += 3;

	if (!gt_expect (gp, '{'))
		return FALSE;

	gt_skipws (gp);

	if (gp->p < gp->end && *gp->p == '}')
	{
		gp->p += 1;
	}
	else
	{
		while (TRUE)
		{
			if (!gt_parse_string (gp, key, RTL_NUMBER_OF (key)))
				return FALSE;

			if (!gt_expect (gp, ':'))
				return FALSE;

			gt_skipws (gp);

			if (gp->p >= gp->end)
			{
				gt_seterr (gp, L"JSON parse error: unexpected end of input");
				return FALSE;
			}

			if (_wcsicmp (key, L"provenance") == 0)
			{
				if (*gp->p != '{')
				{
					gt_seterr (gp, L"JSON parse error: provenance must be an object");
					return FALSE;
				}

				if (!gt_parse_provenance (gp, out))
					return FALSE;
			}
			else if (_wcsicmp (key, L"dlls") == 0)
			{
				if (*gp->p != '[')
				{
					gt_seterr (gp, L"JSON parse error: dlls must be a string array");
					return FALSE;
				}

				if (!gt_parse_string_array (gp, &out->dlls[0][0], 64, MAX_GT_STRINGS, &out->dlls_count))
					return FALSE;
			}
			else if (_wcsicmp (key, L"flags") == 0)
			{
				if (*gp->p != '[')
				{
					gt_seterr (gp, L"JSON parse error: flags must be a string array");
					return FALSE;
				}

				if (!gt_parse_string_array (gp, &out->flags[0][0], 48, MAX_GT_FLAGS, &out->flags_count))
					return FALSE;
			}
			else if (_wcsicmp (key, L"count") == 0)
			{
				if (!gt_parse_int (gp, &out->count))
					return FALSE;

				out->has_count = TRUE;
			}
			else if (_wcsicmp (key, L"value") == 0)
			{
				if (!gt_parse_int (gp, &out->value))
					return FALSE;

				out->has_value = TRUE;
			}
			else
			{
				gt_seterrfmt (gp, L"JSON parse error: unsupported key '%ls' (outside the DEC-11 subset)", key);
				return FALSE;
			}

			gt_skipws (gp);

			if (gp->p < gp->end && *gp->p == ',')
			{
				gp->p += 1;
				continue;
			}

			break;
		}

		if (!gt_expect (gp, '}'))
			return FALSE;
	}

	gt_skipws (gp);

	if (gp->p != gp->end)
	{
		gt_seterr (gp, L"JSON parse error: trailing data after object");
		return FALSE;
	}

	return TRUE;
}

//
// Scan-based JSON member extractor (flat objects) — used for the PowerShell
// ConvertTo-Json output and the off-repo key JSON ("x"/"y"), i.e. the same
// members python reads with json.loads. Escaped quotes protect against
// false matches inside string values.
//

static BOOLEAN json_scan_member (LPCWSTR text, LPCWSTR key, WCHAR *out, ULONG out_cch)
{
	SIZE_T key_length;
	SIZE_T needle_length;
	WCHAR needle[40];
	LPCWSTR p;

	key_length = wcslen (key);

	if (!key_length || key_length >= (RTL_NUMBER_OF (needle) - 3))
		return FALSE;

	needle[0] = L'"';
	memcpy (&needle[1], key, key_length * sizeof (WCHAR));
	needle[key_length + 1] = L'"';
	needle[key_length + 2] = UNICODE_NULL;

	needle_length = key_length + 2;
	p = text;

	while ((p = wcsstr (p, needle)) != NULL)
	{
		LPCWSTR q = p + needle_length;

		while (*q == L' ' || *q == L'\t' || *q == L'\r' || *q == L'\n')
			q += 1;

		if (*q != L':')
		{
			p += 1;
			continue;
		}

		q += 1;

		while (*q == L' ' || *q == L'\t' || *q == L'\r' || *q == L'\n')
			q += 1;

		if (*q == L'"')
		{
			ULONG pos = 0;

			q += 1;

			while (*q && *q != L'"')
			{
				WCHAR wc = *q;

				if (wc == L'\\' && q[1])
				{
					q += 1;

					switch (*q)
					{
						case L'"':
						case L'\\':
						case L'/':
						{
							wc = *q;
							break;
						}

						case L'b':
						{
							wc = L'\b';
							break;
						}

						case L'f':
						{
							wc = L'\f';
							break;
						}

						case L'n':
						{
							wc = L'\n';
							break;
						}

						case L'r':
						{
							wc = L'\r';
							break;
						}

						case L't':
						{
							wc = L'\t';
							break;
						}

						case L'u':
						{
							INT value = 0;
							ULONG i;

							q += 1;

							for (i = 0; i < 4; i++)
							{
								WCHAR hc = q[i];

								value <<= 4;

								if (hc >= L'0' && hc <= L'9')
									value |= (hc - L'0');
								else if (hc >= L'a' && hc <= L'f')
									value |= (hc - L'a' + 10);
								else if (hc >= L'A' && hc <= L'F')
									value |= (hc - L'A' + 10);
								else
									return FALSE; // malformed escape
							}

							q += 3;
							wc = (WCHAR)value;
							break;
						}

						default:
						{
							return FALSE; // malformed escape
						}
					}
				}

				if (pos >= (out_cch - 1))
					return FALSE;

				out[pos++] = wc;
				q += 1;
			}

			out[pos] = UNICODE_NULL;

			return TRUE;
		}
		else if (*q == L'{' || *q == L'[')
		{
			// balanced raw span (PS 5.1 serializes NotAfter as an object)
			INT depth = 0;
			ULONG pos = 0;
			BOOLEAN in_string = FALSE;

			while (*q)
			{
				WCHAR wc = *q;

				if (pos >= (out_cch - 1))
					return FALSE;

				out[pos++] = wc;

				if (in_string)
				{
					if (wc == L'\\' && q[1])
					{
						out[pos++] = q[1];
						q += 1;
					}
					else if (wc == L'"')
					{
						in_string = FALSE;
					}
				}
				else
				{
					if (wc == L'"')
					{
						in_string = TRUE;
					}
					else if (wc == L'{' || wc == L'[')
					{
						depth += 1;
					}
					else if (wc == L'}' || wc == L']')
					{
						depth -= 1;

						if (!depth)
						{
							out[pos] = UNICODE_NULL;
							return TRUE;
						}
					}
				}

				q += 1;
			}

			return FALSE;
		}
		else
		{
			// bare token (number / null / true / false)
			ULONG pos = 0;

			while (*q && *q != L',' && *q != L'}' && *q != L']' && *q != L' ' && *q != L'\t' && *q != L'\r' && *q != L'\n')
			{
				if (pos >= (out_cch - 1))
					return FALSE;

				out[pos++] = *q;
				q += 1;
			}

			out[pos] = UNICODE_NULL;

			return TRUE;
		}
	}

	return FALSE;
}

//
// base64
//

static BOOLEAN base64_decode (LPCWSTR input, BYTE *out, ULONG out_max, ULONG *out_len)
{
	static const WCHAR alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	ULONG acc = 0;
	INT bits = 0;
	ULONG out_pos = 0;

	*out_len = 0;

	while (*input)
	{
		WCHAR ch = *input++;

		if (ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n')
			continue;

		if (ch == L'=')
			break;

		{
			LPCWSTR found = wcschr (alphabet, ch);

			if (!found)
				return FALSE;

			acc = (acc << 6) | (ULONG)(found - alphabet);
			bits += 6;

			if (bits >= 8)
			{
				bits -= 8;

				if (out_pos >= out_max)
					return FALSE;

				out[out_pos++] = (BYTE)((acc >> bits) & 0xFF);
			}
		}
	}

	while (*input)
	{
		if (*input != L'=' && *input != L' ' && *input != L'\t' && *input != L'\r' && *input != L'\n')
			return FALSE;

		input += 1;
	}

	*out_len = out_pos;

	return TRUE;
}

static BOOLEAN base64_encode (const BYTE *data, SIZE_T length, WCHAR *out, ULONG out_cch)
{
	static const WCHAR alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	SIZE_T out_pos = 0;
	SIZE_T i;

	for (i = 0; i < length; i += 3)
	{
		ULONG v = (ULONG)data[i] << 16;

		if ((i + 1) < length)
			v |= (ULONG)data[i + 1] << 8;

		if ((i + 2) < length)
			v |= (ULONG)data[i + 2];

		if (out_pos + 4 >= out_cch)
			return FALSE;

		out[out_pos++] = alphabet[(v >> 18) & 0x3F];
		out[out_pos++] = alphabet[(v >> 12) & 0x3F];
		out[out_pos++] = ((i + 1) < length) ? alphabet[(v >> 6) & 0x3F] : L'=';
		out[out_pos++] = ((i + 2) < length) ? alphabet[v & 0x3F] : L'=';
	}

	out[out_pos] = UNICODE_NULL;

	return TRUE;
}

//
// File helpers
//

static NTSTATUS read_file_bytes (LPCWSTR path, PR_BYTE_PTR out_bytes)
{
	R_STRINGREF sr;
	HANDLE hfile = NULL;
	NTSTATUS status;

	*out_bytes = NULL;

	_r_obj_initializestringref (&sr, path);

	status = _r_fs_openfile (&hfile, &sr, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, 0, FALSE);

	if (!NT_SUCCESS (status))
		return status;

	status = _r_fs_readbytes (hfile, out_bytes);

	CloseHandle (hfile);

	return status;
}

// read a small text file into a bounded NUL-terminated ANSI buffer
static BOOLEAN read_file_text (LPCWSTR path, CHAR *buffer, SIZE_T buffer_max, ULONG_PTR *out_len)
{
	PR_BYTE bytes;
	NTSTATUS status;

	*out_len = 0;
	buffer[0] = 0;

	status = read_file_bytes (path, &bytes);

	if (!NT_SUCCESS (status))
		return FALSE;

	if (bytes->length >= buffer_max)
	{
		_r_obj_dereference (bytes);

		return FALSE;
	}

	memcpy (buffer, bytes->buffer, bytes->length);
	buffer[bytes->length] = 0;
	*out_len = bytes->length;

	_r_obj_dereference (bytes);

	return TRUE;
}

static BOOLEAN path_exists (LPCWSTR path, BOOLEAN is_dir)
{
	DWORD attributes = GetFileAttributesW (path);

	if (attributes == INVALID_FILE_ATTRIBUTES)
		return FALSE;

	if (is_dir && !(attributes & FILE_ATTRIBUTE_DIRECTORY))
		return FALSE;

	if (!is_dir && (attributes & FILE_ATTRIBUTE_DIRECTORY))
		return FALSE;

	return TRUE;
}

// resolve repo-relative paths the way the python tool resolves them relative
// to its own script directory: primary candidate is exe-relative (<exe>\..\
// = repo root for the stock OutDir), fallback is CWD-relative
static PR_STRING resolve_path (LPCWSTR base_dir, LPCWSTR relative_a, LPCWSTR relative_b, BOOLEAN is_dir)
{
	WCHAR full[4096];
	PR_STRING candidate;

	// candidate A: <exe_dir>\<relative_a> (base_dir ends with a backslash)
	candidate = _r_format_string (L"%ls%ls", base_dir, relative_a);

	if (GetFullPathNameW (candidate->buffer, RTL_NUMBER_OF (full), full, NULL) && full[0] && path_exists (full, is_dir))
	{
		_r_obj_dereference (candidate);

		return _r_obj_createstring (full);
	}

	_r_obj_dereference (candidate);

	// candidate B: CWD-relative
	if (GetFullPathNameW (relative_b, RTL_NUMBER_OF (full), full, NULL) && full[0] && path_exists (full, is_dir))
		return _r_obj_createstring (full);

	// neither exists: return candidate A (normalized) for the FAIL message
	candidate = _r_format_string (L"%ls%ls", base_dir, relative_a);

	if (GetFullPathNameW (candidate->buffer, RTL_NUMBER_OF (full), full, NULL) && full[0])
	{
		_r_obj_dereference (candidate);

		return _r_obj_createstring (full);
	}

	return candidate;
}

//
// Binary search
//

static ULONG_PTR memfind (const BYTE *haystack, SIZE_T haystack_len, const BYTE *needle, SIZE_T needle_len)
{
	if (!needle_len || needle_len > haystack_len)
		return (ULONG_PTR)-1;

	for (SIZE_T i = 0; i <= (haystack_len - needle_len); i++)
	{
		if (haystack[i] == needle[0] && memcmp (&haystack[i], needle, needle_len) == 0)
			return i;
	}

	return (ULONG_PTR)-1;
}

//
// PE parsing (native; mirrors tools/release-preflight.py read_pe semantics)
//

typedef struct _PE_INFO
{
	const BYTE *base;
	SIZE_T size;
	ULONG nsec;
	ULONG optsz;
	ULONG_PTR sec_off;
	ULONG imp_rva;
	ULONG rsrc_rva;
	USHORT dllchar;
} PE_INFO;

static ULONG pe_rd16 (const BYTE *p)
{
	return (ULONG)p[0] | ((ULONG)p[1] << 8);
}

static ULONG pe_rd32 (const BYTE *p)
{
	return (ULONG)p[0] | ((ULONG)p[1] << 8) | ((ULONG)p[2] << 16) | ((ULONG)p[3] << 24);
}

// error messages mirror python's ValueError strings
static BOOLEAN pe_parse (const BYTE *data, SIZE_T size, PE_INFO *pi, LPCWSTR *error)
{
	ULONG pe_off;

	memset (pi, 0, sizeof (PE_INFO));

	pi->base = data;
	pi->size = size;

	*error = L"not a PE image";

	if (size < 0x40 || size < (0x3C + 4))
		return FALSE;

	pe_off = pe_rd32 (data + 0x3C);

	if (pe_off > size || (pe_off + 4) > size)
		return FALSE;

	if (data[pe_off] != 'P' || data[pe_off + 1] != 'E' || data[pe_off + 2] != 0 || data[pe_off + 3] != 0)
		return FALSE;

	{
		ULONG_PTR coff = pe_off + 4;
		ULONG_PTR opt;

		if ((coff + 20) > size)
			return FALSE;

		pi->nsec = pe_rd16 (data + coff + 2);
		pi->optsz = pe_rd16 (data + coff + 16);
		opt = coff + 20;

		if ((opt + 2) > size)
			return FALSE;

		if (pe_rd16 (data + opt) != 0x20B) // PE32+ only (x64), like python
		{
			*error = L"not PE32+ (x64)";
			return FALSE;
		}

		if (pi->optsz < 128 || (opt + pi->optsz) > size)
			return FALSE;

		{
			ULONG_PTR dd = opt + 112;

			pi->imp_rva = pe_rd32 (data + dd + 8);
			pi->rsrc_rva = pe_rd32 (data + dd + 16);
		}

		pi->dllchar = (USHORT)pe_rd16 (data + opt + 70);
		pi->sec_off = opt + pi->optsz;

		if ((pi->sec_off + (SIZE_T)pi->nsec * 40) > size)
			return FALSE;
	}

	*error = NULL;

	return TRUE;
}

static const BYTE *pe_rva2off (const PE_INFO *pi, ULONG rva)
{
	for (ULONG i = 0; i < pi->nsec; i++)
	{
		const BYTE *entry = pi->base + pi->sec_off + (SIZE_T)i * 40;
		ULONG64 vsz = pe_rd32 (entry + 8);
		ULONG64 va = pe_rd32 (entry + 12);
		ULONG64 rsz = pe_rd32 (entry + 16);
		ULONG64 ro = pe_rd32 (entry + 20);
		ULONG64 span = (vsz > rsz) ? vsz : rsz;

		if (rva >= va && (ULONG64)rva < (va + span))
		{
			ULONG64 offset = ro + ((ULONG64)rva - va);

			if (offset < pi->size)
				return pi->base + (SIZE_T)offset;

			return NULL;
		}
	}

	return NULL;
}

#define MAX_IMPORTS 96

static BOOLEAN pe_import_dlls (const PE_INFO *pi, WCHAR dlls[][64], ULONG *count, LPCWSTR *error)
{
	const BYTE *entry;
	ULONG i = 0;

	*count = 0;
	*error = NULL;

	entry = pe_rva2off (pi, pi->imp_rva);

	if (!entry)
	{
		*error = L"import directory RVA unresolvable";
		return FALSE;
	}

	while (TRUE)
	{
		ULONG name_rva;
		const BYTE *name;
		ULONG length = 0;

		if ((SIZE_T)(entry - pi->base) + 20 > pi->size)
		{
			*error = L"import directory truncated";
			return FALSE;
		}

		name_rva = pe_rd32 (entry + 12);

		if (!name_rva)
			break;

		if (i >= MAX_IMPORTS)
		{
			*error = L"import table too large (fail-closed)";
			return FALSE;
		}

		name = pe_rva2off (pi, name_rva);

		if (!name)
		{
			*error = L"import name RVA unresolvable";
			return FALSE;
		}

		while (((SIZE_T)(name - pi->base) + length) < pi->size && name[length] != 0)
			length += 1;

		if (((SIZE_T)(name - pi->base) + length) >= pi->size)
		{
			*error = L"import name unterminated";
			return FALSE;
		}

		if (length >= 64)
		{
			*error = L"import name too long";
			return FALSE;
		}

		for (ULONG j = 0; j < length; j++)
			dlls[i][j] = (WCHAR)name[j];

		dlls[i][length] = UNICODE_NULL;

		i += 1;
		entry += 20;
	}

	*count = i;

	return TRUE;
}

// python sorted() over ASCII strings == codepoint sort
static VOID sort_names (WCHAR dlls[][64], ULONG count)
{
	for (ULONG i = 0; (i + 1) < count; i++)
	{
		for (ULONG j = 0; (j + 1 + i) < count; j++)
		{
			if (wcscmp (dlls[j], dlls[j + 1]) > 0)
			{
				WCHAR tmp[64];

				copy_bounded (tmp, RTL_NUMBER_OF (tmp), dlls[j]);
				copy_bounded (dlls[j], 64, dlls[j + 1]);
				copy_bounded (dlls[j + 1], 64, tmp);
			}
		}
	}
}

//
// tree parsers (update_key.h / app.h)
//

static BOOLEAN parse_update_key_h (LPCWSTR path, BYTE key[64])
{
	CHAR text[8192];
	ULONG_PTR length;
	const CHAR *anchor;
	const CHAR *p;
	const CHAR *end;
	ULONG count = 0;

	if (!read_file_text (path, text, RTL_NUMBER_OF (text), &length))
		return FALSE;

	// python: re.search(r"UPDATE_PUBLIC_KEY\[64\]\s*=\s*\{([^}]+)\}", ...)
	anchor = strstr (text, "UPDATE_PUBLIC_KEY[64]");

	if (!anchor)
		return FALSE;

	p = anchor + strlen ("UPDATE_PUBLIC_KEY[64]");
	end = text + length;

	while (p < end && *p != '{')
	{
		if (*p != '=' && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
			return FALSE;

		p += 1;
	}

	if (p >= end)
		return FALSE;

	p += 1; // skip '{'

	while (p < end && count < 64)
	{
		while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ','))
			p += 1;

		if (p >= end || *p == '}')
			break;

		if ((end - p) > 1 && *p == '0' && (p[1] == 'x' || p[1] == 'X'))
			p += 2;

		if ((end - p) < 2 || !gt_is_hex (p[0]) || !gt_is_hex (p[1]))
			return FALSE;

		key[count++] = (BYTE)((gt_hexval (p[0]) << 4) | gt_hexval (p[1]));
		p += 2;
	}

	return (count == 64);
}

static BOOLEAN parse_app_version (LPCWSTR path, WCHAR version[32])
{
	CHAR text[65536];
	ULONG_PTR length;
	const CHAR *anchor;
	const CHAR *p;
	ULONG pos = 0;

	version[0] = UNICODE_NULL;

	if (!read_file_text (path, text, RTL_NUMBER_OF (text), &length))
		return FALSE;

	// python: re.search(r'#define\s+APP_VERSION\s+L"([^"]+)"', text)
	anchor = strstr (text, "#define");

	while (anchor)
	{
		const CHAR *line_end = strchr (anchor, '\n');

		if (!line_end)
			line_end = text + length;

		p = strstr (anchor, "APP_VERSION");

		if (p && p < line_end)
		{
			p += strlen ("APP_VERSION");

			while (p < line_end && (*p == ' ' || *p == '\t'))
				p += 1;

			if ((line_end - p) > 2 && p[0] == 'L' && p[1] == '"')
			{
				p += 2;

				while (p < line_end && *p != '"' && pos < 31)
					version[pos++] = (WCHAR)(BYTE)*p++;

				version[pos] = UNICODE_NULL;

				return (pos != 0);
			}
		}

		anchor = (line_end < text + length) ? strstr (line_end, "#define") : NULL;
	}

	return FALSE;
}

//
// Authenticode via PowerShell (python-parity: same snippet, same members)
//

static BOOLEAN ps_query (LPCWSTR exe_path, WCHAR *status_tok, ULONG status_cch, WCHAR *message, ULONG message_cch, WCHAR *thumbprint, ULONG thumbprint_cch, WCHAR *not_after, ULONG not_after_cch, WCHAR *err, ULONG err_cch)
{
	static CHAR output[PS_OUTPUT_MAX];
	static WCHAR wide_output[PS_OUTPUT_MAX];
	PR_STRING escaped_path = NULL;
	PR_STRING snippet = NULL;
	WCHAR encoded[1600];
	WCHAR cmdline[2048];
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	HANDLE pipe_read = NULL;
	HANDLE pipe_write = NULL;
	DWORD output_len = 0;
	BOOLEAN result = FALSE;

	status_tok[0] = UNICODE_NULL;
	message[0] = UNICODE_NULL;
	thumbprint[0] = UNICODE_NULL;
	not_after[0] = UNICODE_NULL;
	err[0] = UNICODE_NULL;

	memset (&pi, 0, sizeof (pi));

	// python: exe.replace("'", "''")
	{
		STRB sb;

		strb_reset (&sb);

		for (LPCWSTR p = exe_path; *p; p++)
		{
			WCHAR tmp[2];

			if (*p == L'\'')
				strb_add (&sb, L"''");

			tmp[0] = *p;
			tmp[1] = UNICODE_NULL;
			strb_add (&sb, tmp);
		}

		escaped_path = _r_obj_createstring (sb.buf);
	}

	// EXACT python snippet (same property order)
	snippet = _r_format_string (
		L"Get-AuthenticodeSignature -FilePath '%ls' | Select-Object Status, StatusMessage, @{n='Thumbprint';e={$_.SignerCertificate.Thumbprint}}, @{n='NotAfter';e={$_.SignerCertificate.NotAfter}} | ConvertTo-Json",
		escaped_path->buffer);

	_r_obj_dereference (escaped_path);
	escaped_path = NULL;

	{
		BYTE utf16le[2048];
		ULONG chars = (ULONG)(snippet->length / sizeof (WCHAR)); // length is BYTES
		ULONG byte_length = chars * 2;

		if (!chars || byte_length >= RTL_NUMBER_OF (utf16le))
			goto CleanupExit;

		// base64 of UTF-16LE (python: ps.encode("utf-16-le"))
		for (ULONG i = 0; i < chars; i++)
		{
			utf16le[i * 2] = (BYTE)snippet->buffer[i];
			utf16le[i * 2 + 1] = (BYTE)(snippet->buffer[i] >> 8);
		}

		if (!base64_encode (utf16le, byte_length, encoded, RTL_NUMBER_OF (encoded)))
			goto CleanupExit;

		_snwprintf_s (cmdline, RTL_NUMBER_OF (cmdline), _TRUNCATE,
			L"powershell.exe -NoProfile -EncodedCommand %ls", encoded);
	}

	_r_obj_dereference (snippet);
	snippet = NULL;

	// spawn powershell with a stdout pipe (python: subprocess capture_output)
	memset (&sa, 0, sizeof (sa));
	sa.nLength = sizeof (sa);
	sa.bInheritHandle = TRUE;

	if (!CreatePipe (&pipe_read, &pipe_write, &sa, 0))
	{
		_snwprintf_s (err, err_cch, _TRUNCATE, L"CreatePipe failed (error %lu)", GetLastError ());
		goto CleanupExit;
	}

	SetHandleInformation (pipe_read, HANDLE_FLAG_INHERIT, 0);

	memset (&si, 0, sizeof (si));
	si.cb = sizeof (si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = NULL;
	si.hStdOutput = pipe_write;
	si.hStdError = pipe_write; // stderr discarded (python captures stdout only)

	if (!CreateProcessW (NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		_snwprintf_s (err, err_cch, _TRUNCATE, L"CreateProcess failed (error %lu)", GetLastError ());
		goto CleanupExit;
	}

	CloseHandle (pipe_write);
	pipe_write = NULL;

	if (WaitForSingleObject (pi.hProcess, PS_TIMEOUT) != WAIT_OBJECT_0)
	{
		TerminateProcess (pi.hProcess, 1);
		_snwprintf_s (err, err_cch, _TRUNCATE, L"powershell timed out after %d seconds", PS_TIMEOUT / 1000);
		goto CleanupExit;
	}

	{
		DWORD readed = 0;

		while (ReadFile (pipe_read, &output[output_len], RTL_NUMBER_OF (output) - output_len - 1, &readed, NULL) && readed)
		{
			output_len += readed;

			if (output_len >= (RTL_NUMBER_OF (output) - 1))
				break;
		}
	}

	output[output_len] = 0;

	// python json.loads(raw) — here: scan-based flat member extraction
	{
		INT wide_len = MultiByteToWideChar (CP_UTF8, 0, output, (INT)output_len, wide_output, RTL_NUMBER_OF (wide_output));

		if (wide_len <= 0)
		{
			_snwprintf_s (err, err_cch, _TRUNCATE, L"malformed output encoding");
			goto CleanupExit;
		}

		wide_output[wide_len] = UNICODE_NULL;

		if (!json_scan_member (wide_output, L"Status", status_tok, status_cch) ||
			!json_scan_member (wide_output, L"StatusMessage", message, message_cch) ||
			!json_scan_member (wide_output, L"Thumbprint", thumbprint, thumbprint_cch) ||
			!json_scan_member (wide_output, L"NotAfter", not_after, not_after_cch))
		{
			_snwprintf_s (err, err_cch, _TRUNCATE, L"malformed JSON output");
			goto CleanupExit;
		}
	}

	result = TRUE;

CleanupExit:

	if (snippet)
		_r_obj_dereference (snippet);

	if (pipe_write)
		CloseHandle (pipe_write);

	if (pipe_read)
		CloseHandle (pipe_read);

	if (pi.hProcess)
		CloseHandle (pi.hProcess);

	if (pi.hThread)
		CloseHandle (pi.hThread);

	if (!result && !err[0])
		_snwprintf_s (err, err_cch, _TRUNCATE, L"powershell query failed");

	return result;
}

// (a) Authenticode — full profile only (runner builds are unsigned;
// DEC-05/DEC-07: the release engineer is the authority for (a)/(b2))
static BOOLEAN check_authenticode (LPCWSTR exe_path, LPCWSTR thumbprint_expected, BOOLEAN is_ci)
{
	WCHAR status_tok[64];
	WCHAR status_message[1024];
	WCHAR thumbprint[128];
	WCHAR not_after[512];
	WCHAR err[256];

	if (is_ci)
		return record (L"(a) authenticode", CHECK_STATE_SKIP, L"release profile \u2014 runner builds are unsigned");

	if (!ps_query (exe_path, status_tok, RTL_NUMBER_OF (status_tok), status_message, RTL_NUMBER_OF (status_message), thumbprint, RTL_NUMBER_OF (thumbprint), not_after, RTL_NUMBER_OF (not_after), err, RTL_NUMBER_OF (err)))
		return record (L"(a) authenticode", CHECK_STATE_FAIL, L"Authenticode query failed: %ls", err);

	// PS serializes JSON null for missing certs — python's .get() gives None,
	// coerced to "" (Thumbprint) / falsy (NotAfter); mirror that
	if (_wcsicmp (thumbprint, L"null") == 0)
		thumbprint[0] = UNICODE_NULL;

	if (_wcsicmp (not_after, L"null") == 0)
		not_after[0] = UNICODE_NULL;

	// ConvertTo-Json serializes the SignatureStatus enum as a NUMBER
	// (Valid=0) in some PowerShell versions, as the NAME in others
	if (wcscmp (status_tok, L"Valid") != 0 && wcscmp (status_tok, L"0") != 0)
		return record (L"(a) authenticode", CHECK_STATE_FAIL, L"signature Status=%ls (%ls)", status_tok, status_message);

	if (_wcsicmp (thumbprint, thumbprint_expected) != 0)
		return record (L"(a) authenticode", CHECK_STATE_FAIL, L"thumbprint %ls != expected %ls", thumbprint, thumbprint_expected);

	{
		STRB evidence;

		strb_reset (&evidence);
		strb_add (&evidence, L"Valid, thumbprint match");

		if (not_after[0])
		{
			strb_addformat (&evidence, L" | NotAfter %ls", not_after);

			// python: best-effort ISO NotAfter parse; WARN < 30 days
			// (owner renewal decision — WARNING, never FAIL). /Date(...)
			// serializations fail python's fromisoformat silently; skipped.
			if (wcslen (not_after) >= 11 && not_after[4] == L'-' && not_after[7] == L'-' && (not_after[10] == L'T' || not_after[10] == L' '))
			{
				SYSTEMTIME st = {0};
				FILETIME ft_cert = {0};
				FILETIME ft_now = {0};
				ULARGE_INTEGER cert_ul;
				ULARGE_INTEGER now_ul;
				LONGLONG days;

				st.wYear = (WORD)_wtoi (not_after);
				st.wMonth = (WORD)_wtoi (not_after + 5);
				st.wDay = (WORD)_wtoi (not_after + 8);

				if (st.wYear >= 2000 && st.wMonth >= 1 && st.wMonth <= 12 && st.wDay >= 1 && st.wDay <= 31 && SystemTimeToFileTime (&st, &ft_cert))
				{
					GetSystemTimeAsFileTime (&ft_now);

					cert_ul.LowPart = ft_cert.dwLowDateTime;
					cert_ul.HighPart = ft_cert.dwHighDateTime;
					now_ul.LowPart = ft_now.dwLowDateTime;
					now_ul.HighPart = ft_now.dwHighDateTime;

					days = ((LONGLONG)cert_ul.QuadPart - (LONGLONG)now_ul.QuadPart) / (LONGLONG)10000000 / (LONGLONG)86400;

					if (days < 30)
					{
						PR_STRING warn = _r_format_string (L"WARN: Authenticode cert expires in %lld days (owner renewal decision)", days);

						out_write (warn->buffer, warn->length);

						_r_obj_dereference (warn);
					}
				}
			}
		}

		return record (L"(a) authenticode", CHECK_STATE_PASS, L"%ls", evidence.buf);
	}
}

//
// Check (b1): embedded feed key vs in-tree src/update_key.h (CI-safe)
//

static BOOLEAN check_embedded_key (const BYTE *exe_data, SIZE_T exe_size, const BYTE tree_key[64])
{
	ULONG_PTR idx = memfind (exe_data, exe_size, tree_key, 64);

	if (idx == (ULONG_PTR)-1)
		return record (L"(b1) embedded key == in-tree update_key.h", CHECK_STATE_FAIL, L"embedded key NOT present");

	// corrupted historical bytes must be absent (python: checked only when
	// the correct key is present)
	if (memfind (exe_data, exe_size, CORRUPTED_KEY_Y, sizeof (CORRUPTED_KEY_Y)) != (ULONG_PTR)-1)
		return record (L"(b1) embedded key == in-tree update_key.h", CHECK_STATE_FAIL, L"CORRUPTED historical key bytes present (db1ef855 regression)");

	return record (L"(b1) embedded key == in-tree update_key.h", CHECK_STATE_PASS, L"embedded key found at 0x%Ix", idx);
}

//
// Check (b2): in-tree key vs off-repo JSON ground truth (owner-side only)
//

static BOOLEAN check_key_json (LPCWSTR json_path, const BYTE tree_key[64], LPCWSTR pinned_sha)
{
	PR_BYTE blob;
	NTSTATUS status;

	if (!path_exists (json_path, FALSE))
		return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON missing: %ls", json_path);

	// pinned SHA256 of the change-controlled trust anchor (RSK-04)
	{
		PR_STRING hash_string;
		R_STRINGREF sr;
		WCHAR computed[128];

		_r_obj_initializestringref (&sr, json_path);

		if (!NT_SUCCESS (_r_crypt_getfilehash (&hash_string, L"SHA256", &sr, NULL)))
			return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON hash failed");

		copy_bounded (computed, RTL_NUMBER_OF (computed), hash_string->buffer);

		for (PWSTR p = computed; *p; p++)
			*p = (WCHAR)towlower (*p);

		_r_obj_dereference (hash_string);

		if (_wcsicmp (computed, pinned_sha) != 0)
			return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON SHA256 %ls != pinned %ls \u2014 change-controlled trust anchor violated (RSK-04)", computed, pinned_sha);
	}

	status = read_file_bytes (json_path, &blob);

	if (!NT_SUCCESS (status))
		return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON read failed (status 0x%08lx)", status);

	{
		CHAR text[4096];
		WCHAR wide[4096];
		WCHAR x_b64[128];
		WCHAR y_b64[128];
		BYTE x_bytes[64];
		BYTE y_bytes[64];
		ULONG x_len = 0;
		ULONG y_len = 0;
		INT wide_len;
		BYTE json_key[64];

		if (blob->length >= RTL_NUMBER_OF (text))
		{
			_r_obj_dereference (blob);

			return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON parse failed: file too large");
		}

		memcpy (text, blob->buffer, blob->length);
		text[blob->length] = 0;

		_r_obj_dereference (blob);

		wide_len = MultiByteToWideChar (CP_UTF8, 0, text, -1, wide, RTL_NUMBER_OF (wide));

		if (wide_len <= 0 ||
			!json_scan_member (wide, L"x", x_b64, RTL_NUMBER_OF (x_b64)) ||
			!json_scan_member (wide, L"y", y_b64, RTL_NUMBER_OF (y_b64)) ||
			!base64_decode (x_b64, x_bytes, RTL_NUMBER_OF (x_bytes), &x_len) ||
			!base64_decode (y_b64, y_bytes, RTL_NUMBER_OF (y_bytes), &y_len) ||
			(x_len + y_len) != 64)
		{
			return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON parse failed: x/y members missing or malformed");
		}

		memcpy (json_key, x_bytes, x_len);
		memcpy (json_key + x_len, y_bytes, y_len);

		if (memcmp (json_key, tree_key, 64) != 0)
			return record (L"(b2) key vs off-repo JSON", CHECK_STATE_FAIL, L"JSON key bytes != in-tree key");
	}

	return record (L"(b2) key vs off-repo JSON", CHECK_STATE_PASS, L"pinned SHA256 OK + bytes match");
}

//
// Check (b-feed, DEC-09): repo feed pair vs the PRODUCTION verifier
//

static BOOLEAN check_feed (LPCWSTR feed_dir, const BYTE tree_key[64])
{
	WCHAR path_version[4096];
	WCHAR path_sig[4096];
	PR_BYTE version_bytes = NULL;
	PR_BYTE sig_bytes = NULL;
	PR_BYTE sig_tampered = NULL;
	R_BYTEREF data_bytes;
	NTSTATUS status;
	SIZE_T dir_length;
	BOOLEAN result = FALSE;

	dir_length = wcslen (feed_dir);

	_snwprintf_s (path_version, RTL_NUMBER_OF (path_version), _TRUNCATE, L"%ls%lsVERSION", feed_dir, (dir_length && feed_dir[dir_length - 1] == L'\\') ? L"" : L"\\");
	_snwprintf_s (path_sig, RTL_NUMBER_OF (path_sig), _TRUNCATE, L"%ls%lsVERSION.sig", feed_dir, (dir_length && feed_dir[dir_length - 1] == L'\\') ? L"" : L"\\");

	if (!path_exists (path_version, FALSE))
		return record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"feed file missing: %ls", path_version);

	if (!path_exists (path_sig, FALSE))
		return record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"feed file missing: %ls", path_sig);

	status = read_file_bytes (path_version, &version_bytes);

	if (!NT_SUCCESS (status))
		return record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"feed read failed: %ls (status 0x%08lx)", path_version, status);

	status = read_file_bytes (path_sig, &sig_bytes);

	if (!NT_SUCCESS (status))
	{
		record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"feed read failed: %ls (status 0x%08lx)", path_sig, status);
		goto CleanupExit;
	}

	if (sig_bytes->length != 64)
	{
		record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"VERSION.sig is not a 64-byte P1363 signature (%I64u bytes)", (ULONG64)sig_bytes->length);
		goto CleanupExit;
	}

	// the exact src/main.c:1840 call shape with the in-tree key bytes
	_r_update_setpublickey (tree_key, 64);

	data_bytes.length = version_bytes->length;
	data_bytes.buffer = version_bytes->buffer;

	status = _r_update_verifysignature (&data_bytes, sig_bytes);

	if (!NT_SUCCESS (status))
	{
		record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"production verifier rejected repo pair (status 0x%08lx; VERSION %I64uB, VERSION.sig %I64uB)", status, (ULONG64)version_bytes->length, (ULONG64)sig_bytes->length);
		goto CleanupExit;
	}

	// tamper-witness: a flipped signature byte MUST be rejected
	sig_tampered = _r_obj_createbyte_ex (sig_bytes->buffer, sig_bytes->length);
	sig_tampered->buffer[0] ^= 0x01;

	status = _r_update_verifysignature (&data_bytes, sig_tampered);

	if (NT_SUCCESS (status))
	{
		record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_FAIL, L"TAMPER-WITNESS FAILED: flipped-byte signature still verifies \u2014 production verifier broken");
	}
	else
	{
		record (L"(b-feed) feed signature (production verifier)", CHECK_STATE_PASS, L"production verifier OK on repo pair (VERSION %I64uB, VERSION.sig %I64uB); tamper-witness: flipped-byte signature correctly rejected (status 0x%08lx)", (ULONG64)version_bytes->length, (ULONG64)sig_bytes->length, status);

		result = TRUE;
	}

CleanupExit:

	if (version_bytes)
		_r_obj_dereference (version_bytes);

	if (sig_bytes)
		_r_obj_dereference (sig_bytes);

	if (sig_tampered)
		_r_obj_dereference (sig_tampered);

	return result;
}

//
// Check (c): import-table parity
//

static BOOLEAN check_imports (const PE_INFO *pi, const GT_DATA *gt_imports)
{
	WCHAR actual[MAX_IMPORTS][64];
	ULONG actual_count = 0;
	LPCWSTR error = NULL;

	if (!pe_import_dlls (pi, actual, &actual_count, &error))
		return record (L"(c) import parity", CHECK_STATE_FAIL, L"%ls", error ? error : L"import walk failed");

	sort_names (actual, actual_count);

	{
		WCHAR expected[MAX_GT_STRINGS][64];
		ULONG expected_count = gt_imports->dlls_count;
		STRB extra_list;
		STRB missing_list;
		ULONG extra_count = 0;
		ULONG missing_count = 0;
		ULONG a = 0;
		ULONG e = 0;

		for (ULONG i = 0; i < expected_count; i++)
			copy_bounded (expected[i], 64, gt_imports->dlls[i]);

		sort_names (expected, expected_count);

		strb_reset (&extra_list);
		strb_reset (&missing_list);

		// both arrays sorted -> merge-style set diff preserves python's
		// sorted(...) output order
		while (a < actual_count || e < expected_count)
		{
			INT cmp;

			if (a >= actual_count)
				cmp = 1;
			else if (e >= expected_count)
				cmp = -1;
			else
				cmp = wcscmp (actual[a], expected[e]);

			if (cmp < 0)
			{
				if (extra_count++)
					strb_add (&extra_list, L", ");

				strb_addformat (&extra_list, L"'%ls'", actual[a]);
				a += 1;
			}
			else if (cmp > 0)
			{
				if (missing_count++)
					strb_add (&missing_list, L", ");

				strb_addformat (&missing_list, L"'%ls'", expected[e]);
				e += 1;
			}
			else
			{
				a += 1;
				e += 1;
			}
		}

		{
			STRB evidence;

			strb_reset (&evidence);
			strb_addformat (&evidence, L"%lu DLLs", actual_count);

			if (extra_count)
				strb_addformat (&evidence, L" | EXTRA: [%ls] (upstream merge? update imports.json with the cited diff \u2014 RSK-01)", extra_list.buf);

			if (missing_count)
				strb_addformat (&evidence, L" | MISSING: [%ls] (upstream merge? \u2014 RSK-01)", missing_list.buf);

			return record (L"(c) import parity", (extra_count || missing_count) ? CHECK_STATE_FAIL : CHECK_STATE_PASS, L"%ls", evidence.buf);
		}
	}
}

//
// Check (d): version resource ProductVersion vs src/app.h APP_VERSION
//

static BOOLEAN check_version (LPCWSTR exe_path, LPCWSTR app_version)
{
	ULONG ver_size;
	ULONG handle = 0;
	PVOID ver_block = NULL;
	PR_STRING pv = NULL;
	BOOLEAN result;

	ver_size = GetFileVersionInfoSizeExW (FILE_VER_GET_LOCALISED | FILE_VER_GET_NEUTRAL, exe_path, &handle);

	if (ver_size)
	{
		ver_block = _r_mem_allocate (ver_size);

		if (GetFileVersionInfoExW (FILE_VER_GET_LOCALISED, exe_path, 0, ver_size, ver_block))
			pv = _r_res_querystring (ver_block, L"ProductVersion", _r_res_querytranslation (ver_block));
	}

	if (ver_block)
		_r_mem_free (ver_block);

	if (!pv)
		return record (L"(d) version resource", CHECK_STATE_FAIL, L"no RT_VERSION resource with ProductVersion");

	result = record (L"(d) version resource", (wcscmp (pv->buffer, app_version) == 0) ? CHECK_STATE_PASS : CHECK_STATE_FAIL, L"ProductVersion %ls vs APP_VERSION %ls", pv->buffer, app_version);

	_r_obj_dereference (pv);

	return result;
}

//
// Check (e): SWC1 container integrity + blocklist parity
//

static BOOLEAN check_swc1 (LPCWSTR exe_path, const GT_DATA *gt_blocklist)
{
	PVOID hmodule = NULL;
	R_STRINGREF exe_sr;
	R_STORAGE storage;
	PR_BYTE plain = NULL;
	PR_BYTE digest = NULL;
	R_CRYPT_CONTEXT hash_context;
	R_XML_LIBRARY xml_library;
	LPCWSTR fmt_name = NULL;
	BOOLEAN sha_ok = FALSE;
	LONG64 count;
	ULONG64 plain_length = 0;
	ULONG blob_length;
	BYTE flag_byte;
	BYTE stored_digest[32];
	const BYTE *blob;
	BOOLEAN ok;

	_r_obj_initializestringref (&exe_sr, exe_path);


	if (!NT_SUCCESS (_r_sys_loadlibrary (&exe_sr, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE, &hmodule)) || !hmodule)
		return record (L"(e) SWC1 container + blocklist parity", CHECK_STATE_FAIL, L"resource map load failed (fail-closed)");


	if (!NT_SUCCESS (_r_res_loadresource (&storage, hmodule, RT_RCDATA, MAKEINTRESOURCEW (1), 0)))
	{
		_r_sys_freelibrary (hmodule);

		return record (L"(e) SWC1 container + blocklist parity", CHECK_STATE_FAIL, L"RCDATA id=1 (IDR_PROFILE_INTERNAL) not found");
	}

	blob = (const BYTE *)storage.buffer;
	blob_length = storage.length;


	if (blob_length < 36)
	{
		_r_sys_freelibrary (hmodule);

		return record (L"(e) SWC1 container + blocklist parity", CHECK_STATE_FAIL, L"SWC1 container too small (%lu bytes)", blob_length);
	}

	if (blob[0] != 'S' || blob[1] != 'W' || blob[2] != 'C')
	{
		_r_sys_freelibrary (hmodule);

		return record (L"(e) SWC1 container + blocklist parity", CHECK_STATE_FAIL, L"SWC fourcc not present");
	}

	// copy the flag + stored SHA256 out of the module mapping BEFORE it is
	// unmapped (the mapping is only valid while the resource module lives)
	flag_byte = blob[3];
	memcpy (stored_digest, blob + 4, sizeof (stored_digest));

	// decompress LZNT1 then XPRESS — mirrors src/db.c:523 reader order.
	// NOTE: the resource pointer lives inside the module mapping; the
	// module stays loaded until the decompressed copy exists.
	{
		USHORT format[] = {COMPRESSION_FORMAT_LZNT1, COMPRESSION_FORMAT_XPRESS};
		LPCWSTR format_name[] = {L"LZNT1", L"XPRESS"};
		R_BYTEREF body;
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		body.length = (ULONG_PTR)blob_length - 36;
		body.buffer = (LPSTR)(blob + 36);

		for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (format); i++)
		{
			status = _r_sys_decompressbuffer (&plain, format[i], &body);

			if (NT_SUCCESS (status))
			{
				fmt_name = format_name[i];
				break;
			}
		}

		_r_sys_freelibrary (hmodule);

		if (!NT_SUCCESS (status) || !plain)
			return record (L"(e) SWC1 container + blocklist parity", CHECK_STATE_FAIL, L"SWC1 body decompressed by neither LZNT1 nor XPRESS");

	}

	// stored SHA256 over the plaintext (raw digest variant)
	if (NT_SUCCESS (_r_crypt_createhashcontext (&hash_context, L"SHA256")))
	{
		if (NT_SUCCESS (_r_crypt_hashbuffer (&hash_context, plain->buffer, (ULONG)plain->length)))
		{
			if (NT_SUCCESS (_r_crypt_finalhashcontext (&hash_context, NULL, &digest)))
				sha_ok = (digest->length == 32) && RtlEqualMemory (digest->buffer, stored_digest, 32);
		}

		_r_crypt_destroycryptcontext (&hash_context);
	}


	if (digest)
		_r_obj_dereference (digest);

	// XML: parse + count rules_blocklist items (db.c:842 pattern)
	memset (&xml_library, 0, sizeof (xml_library));

	count = -2; // parse-failure marker (fail closed)

	if (NT_SUCCESS (_r_xml_initializelibrary (&xml_library, TRUE)))
	{
		HRESULT xml_status = _r_xml_parsestring (&xml_library, plain->buffer, (ULONG)plain->length);

		if (SUCCEEDED (xml_status))
		{
			count = -1; // python: -1 when rules_blocklist is absent

			if (_r_xml_findchildbytagname (&xml_library, L"rules_blocklist"))
			{
				count = 0;

				while (_r_xml_enumchilditemsbytagname (&xml_library, L"item"))
					count += 1;
			}
		}

		_r_xml_destroylibrary (&xml_library);
	}

	plain_length = (ULONG64)plain->length;

	_r_obj_dereference (plain);

	if (count == -2)
		return record (L"(e) SWC1 container + blocklist parity", CHECK_STATE_FAIL, L"XML parse failed (fail-closed)");

	ok = sha_ok && (count == gt_blocklist->count) && (flag_byte == 0x31);

	return record (L"(e) SWC1 container + blocklist parity", ok ? CHECK_STATE_PASS : CHECK_STATE_FAIL,
		L"flag=0x%02x fmt=%ls plaintext %I64uB sha256 %ls blocklist %I64d/%I64d (RSK-01 if drift)",
		flag_byte,
		fmt_name,
		plain_length,
		sha_ok ? L"OK" : L"MISMATCH",
		count,
		gt_blocklist->count);
}

//
// Check (f): PE security flags parity
//

static BOOLEAN check_peflags (const PE_INFO *pi, const GT_DATA *gt_peflags)
{
	STRB flags_list;

	if (gt_peflags->value < 0 || gt_peflags->value > 0xFFFF)
		return record (L"(f) PE security flags parity", CHECK_STATE_FAIL, L"parity value out of range (fail-closed)");

	strb_reset (&flags_list);

	for (ULONG i = 0; i < gt_peflags->flags_count; i++)
	{
		if (i)
			strb_add (&flags_list, L", ");

		strb_add (&flags_list, gt_peflags->flags[i]);
	}

	return record (L"(f) PE security flags parity", ((ULONG)gt_peflags->value == (ULONG)pi->dllchar) ? CHECK_STATE_PASS : CHECK_STATE_FAIL,
		L"DllCharacteristics 0x%04x vs parity 0x%04x (%ls)",
		pi->dllchar,
		(ULONG)gt_peflags->value,
		flags_list.buf);
}

//
// Ground-truth loading (FR-02: before anything else; fail closed)
//

static BOOLEAN load_ground_truth (LPCWSTR gt_dir, WCHAR *err_path, SIZE_T err_path_cch)
{
	static const struct
	{
		LPCWSTR name;
		ULONG target; // 0=imports 1=blocklist 2=peflags
	} gt_files[] = {
		{L"imports.json", 0},
		{L"blocklist.json", 1},
		{L"pe-flags.json", 2},
	};

	GT_DATA *targets[3] = {&gt_imports_data, &gt_blocklist_data, &gt_peflags_data};

	copy_bounded (err_path, err_path_cch, gt_dir);

	// python: `if not os.path.isdir(gt_dir): raise "ground-truth directory
	// missing: <gt_dir>"` — checked before any file
	if (!path_exists (gt_dir, TRUE))
	{
		record (L"ground-truth-load", CHECK_STATE_FAIL, L"ground-truth directory missing: %ls", gt_dir);
		return FALSE;
	}

	for (ULONG i = 0; i < RTL_NUMBER_OF (gt_files); i++)
	{
		PR_STRING path = _r_format_string (L"%ls\\%ls", gt_dir, gt_files[i].name);
		CHAR text[32768];
		ULONG_PTR length;
		GT_PARSER parser;
		GT_DATA *data;
		BOOLEAN parsed;

		copy_bounded (err_path, err_path_cch, path->buffer);

		if (!read_file_text (path->buffer, text, RTL_NUMBER_OF (text), &length))
		{
			record (L"ground-truth-load", CHECK_STATE_FAIL, L"ground-truth file missing: %ls", path->buffer);
			_r_obj_dereference (path);
			return FALSE;
		}

		data = (GT_DATA *)_r_mem_allocate (sizeof (GT_DATA));
		memset (data, 0, sizeof (GT_DATA));

		parser.p = text;
		parser.end = text + length;
		parser.err[0] = UNICODE_NULL;

		parsed = gt_parse_document (&parser, data);

		if (parsed && !data->has_provenance)
		{
			gt_seterr (&parser, L"provenance header missing");
			parsed = FALSE;
		}

		if (!parsed)
		{
			record (L"ground-truth-load", CHECK_STATE_FAIL, L"%ls: %ls", path->buffer, parser.err[0] ? parser.err : L"JSON parse error");
			_r_mem_free (data);
			_r_obj_dereference (path);
			return FALSE;
		}

		memcpy (targets[gt_files[i].target], data, sizeof (GT_DATA));

		_r_mem_free (data);
		_r_obj_dereference (path);
	}

	// key-json-sha256.txt (pinned hash of the off-repo JSON, RSK-04)
	{
		PR_STRING path = _r_format_string (L"%ls\\%ls", gt_dir, L"key-json-sha256.txt");
		CHAR text[512];
		ULONG_PTR length;

		copy_bounded (err_path, err_path_cch, path->buffer);

		if (!read_file_text (path->buffer, text, RTL_NUMBER_OF (text), &length))
		{
			record (L"ground-truth-load", CHECK_STATE_FAIL, L"ground-truth file missing: %ls", path->buffer);
			_r_obj_dereference (path);
			return FALSE;
		}

		{
			CHAR *p = text;
			ULONG pos = 0;

			while (*p)
			{
				if (*p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
					key_sha_pinned[pos++] = (WCHAR)*p;

				p += 1;
			}

			key_sha_pinned[pos] = UNICODE_NULL;
		}

		_r_obj_dereference (path);

		if (wcslen (key_sha_pinned) != 64)
		{
			record (L"ground-truth-load", CHECK_STATE_FAIL, L"key-json-sha256.txt: expected 64 hex chars");
			return FALSE;
		}
	}

	// DEC-11: provenance fields are parsed and equality-checked against the
	// recorded source identifiers (all parity files must record the same
	// upstream source identity — RSK-04 change-control anchor)
	{
		GT_DATA *files[] = {&gt_imports_data, &gt_blocklist_data, &gt_peflags_data};

		for (ULONG i = 1; i < RTL_NUMBER_OF (files); i++)
		{
			if (!files[i]->prov_source[0] || !files[0]->prov_source[0] || _wcsicmp (files[0]->prov_source, files[i]->prov_source) != 0)
			{
				record (L"ground-truth-load", CHECK_STATE_FAIL, L"provenance source mismatch across ground-truth files (RSK-04)");
				return FALSE;
			}

			if (!files[i]->prov_sha256[0] || !files[0]->prov_sha256[0] || _wcsicmp (files[0]->prov_sha256, files[i]->prov_sha256) != 0)
			{
				record (L"ground-truth-load", CHECK_STATE_FAIL, L"provenance sha256_of_archive mismatch across ground-truth files (RSK-04)");
				return FALSE;
			}
		}
	}

	return TRUE;
}

//
// CLI
//

static BOOLEAN opt_matches (LPCWSTR token, LPCWSTR name, BOOLEAN *has_attached_value)
{
	SIZE_T name_length;

	if (*token != L'-')
		return FALSE;

	token += 1;

	if (*token == L'-')
		token += 1;

	name_length = wcslen (name);

	if (_wcsnicmp (token, name, name_length) != 0)
		return FALSE;

	token += name_length;

	if (!*token)
	{
		*has_attached_value = FALSE;
		return TRUE;
	}

	if (*token == L':' || *token == L'=')
	{
		*has_attached_value = TRUE;
		return TRUE;
	}

	return FALSE;
}

static PR_STRING find_positional_exe (VOID)
{
	INT numargs = 0;
	LPWSTR *arga;
	PR_STRING result = NULL;

	arga = CommandLineToArgvW (_r_sys_getcommandline (), &numargs);

	if (!arga)
		return NULL;

	for (INT i = 1; i < numargs; i++)
	{
		LPCWSTR token = arga[i];

		if (*token == L'-')
		{
			BOOLEAN attached = FALSE;

			// value options consume the NEXT token when the value is separate
			if (opt_matches (token, L"thumbprint", &attached) ||
				opt_matches (token, L"app-h", &attached) ||
				opt_matches (token, L"ground-truth-dir", &attached) ||
				opt_matches (token, L"feed-dir", &attached))
			{
				if (!attached && (i + 1) < numargs && *arga[i + 1] != L'-')
					i += 1;
			}

			continue;
		}

		result = _r_obj_createstring (token);
		break;
	}

	LocalFree (arga);

	return result;
}

//
// --json writer (same object shape as python json.dumps(..., indent=2))
//

static VOID json_escape_into (STRB *sb, LPCWSTR string)
{
	for (; *string; string++)
	{
		switch (*string)
		{
			case L'"':
			{
				strb_add (sb, L"\\\"");
				break;
			}

			case L'\\':
			{
				strb_add (sb, L"\\\\");
				break;
			}

			case L'\n':
			{
				strb_add (sb, L"\\n");
				break;
			}

			case L'\r':
			{
				strb_add (sb, L"\\r");
				break;
			}

			case L'\t':
			{
				strb_add (sb, L"\\t");
				break;
			}

			default:
			{
				if (*string < 0x20)
					strb_addformat (sb, L"\\u%04x", (ULONG)*string);
				else
					strb_addformat (sb, L"%lc", *string);

				break;
			}
		}
	}
}

static VOID write_json_output (LPCWSTR exe_path, BOOLEAN is_ci, BOOLEAN ok)
{
	STRB sb;
	HANDLE hconsole;
	ULONG mode;
	LPCWSTR nl;
	PR_STRING line;
	PCHAR buffer;
	INT buffer_length;
	DWORD written = 0;

	hconsole = NtCurrentPeb ()->ProcessParameters->StandardOutput;

	if (hconsole && hconsole != INVALID_HANDLE_VALUE && GetConsoleMode (hconsole, &mode))
		nl = L"\r\n";
	else
		nl = L"\n";

	strb_reset (&sb);

	strb_addformat (&sb, L"{%ls  \"exe\": \"", nl);
	json_escape_into (&sb, exe_path);
	strb_addformat (&sb, L"\",%ls  \"ci_profile\": %ls,%ls  \"ok\": %ls,%ls  \"checks\": [",
		nl, is_ci ? L"true" : L"false", nl, ok ? L"true" : L"false", nl);

	for (ULONG i = 0; i < check_count; i++)
	{
		CHECK_RECORD *rec = &check_results[i];

		strb_add (&sb, i ? L"," : L"");
		strb_addformat (&sb, L"%ls    {%ls      \"name\": \"", nl, nl);
		json_escape_into (&sb, rec->name);
		strb_addformat (&sb, L"\",%ls      \"status\": \"", nl);
		json_escape_into (&sb, rec->status);
		strb_addformat (&sb, L"\",%ls      \"evidence\": \"", nl);
		json_escape_into (&sb, rec->evidence);
		strb_addformat (&sb, L"\"%ls    }", nl);
	}

	if (check_count)
		strb_addformat (&sb, L"%ls  ", nl);

	strb_addformat (&sb, L"]%ls}%ls", nl, nl);

	line = _r_obj_createstring (sb.buf);

	// line->length is in BYTES (routine string convention)
	if (hconsole && hconsole != INVALID_HANDLE_VALUE && (nl[0] == L'\r'))
	{
		// real console: the routine writer serves this handle
		_r_console_writestring_ex (line->buffer, line->length / sizeof (WCHAR));
	}
	else
	{
		buffer_length = WideCharToMultiByte (CP_UTF8, 0, line->buffer, (INT)(line->length / sizeof (WCHAR)), NULL, 0, NULL, NULL);

		if (buffer_length > 0)
		{
			buffer = (PCHAR)_r_mem_allocate ((SIZE_T)buffer_length);

			if (WideCharToMultiByte (CP_UTF8, 0, line->buffer, (INT)(line->length / sizeof (WCHAR)), buffer, buffer_length, NULL, NULL) > 0)
				WriteFile (hconsole, buffer, (DWORD)buffer_length, &written, NULL);

			_r_mem_free (buffer);
		}
	}

	_r_obj_dereference (line);
}

//
// main
//

INT wmain (INT argc, WCHAR **argv)
{
	BOOLEAN is_ci;
	BOOLEAN is_json;
	BOOLEAN ok_all = TRUE;
	PR_STRING thumbprint_value = NULL;
	PR_STRING apph_value = NULL;
	PR_STRING gt_value = NULL;
	PR_STRING feed_value = NULL;
	PR_STRING exe_arg = NULL;
	PR_STRING exe_path = NULL;
	PR_STRING base_dir = NULL;
	WCHAR thumbprint[128];
	WCHAR tree_key_path[4096];
	WCHAR app_h_path[4096];
	WCHAR gt_dir[4096];
	WCHAR feed_dir[4096];
	WCHAR app_version[32];
	WCHAR err_path[4096];
	BYTE tree_key[64];
	PR_BYTE exe_bytes = NULL;
	PE_INFO pe_info;
	LPCWSTR pe_error = NULL;
	NTSTATUS status;

	(VOID)argc;
	(VOID)argv;

	if (!_r_app_initialize (NULL))
		return ERROR_APP_INIT_FAILURE;


	is_ci = _r_sys_getopt (_r_sys_getcommandline (), L"ci", NULL);
	is_json = _r_sys_getopt (_r_sys_getcommandline (), L"json", NULL);

	copy_bounded (thumbprint, RTL_NUMBER_OF (thumbprint), DEFAULT_THUMBPRINT);
	copy_bounded (app_h_path, RTL_NUMBER_OF (app_h_path), L"");
	copy_bounded (gt_dir, RTL_NUMBER_OF (gt_dir), L"");
	copy_bounded (feed_dir, RTL_NUMBER_OF (feed_dir), L"");

	if (_r_sys_getopt (_r_sys_getcommandline (), L"thumbprint", &thumbprint_value))
	{
		if (thumbprint_value)
			copy_bounded (thumbprint, RTL_NUMBER_OF (thumbprint), thumbprint_value->buffer);
	}

	if (_r_sys_getopt (_r_sys_getcommandline (), L"app-h", &apph_value) && apph_value)
		copy_bounded (app_h_path, RTL_NUMBER_OF (app_h_path), apph_value->buffer);

	if (_r_sys_getopt (_r_sys_getcommandline (), L"ground-truth-dir", &gt_value) && gt_value)
		copy_bounded (gt_dir, RTL_NUMBER_OF (gt_dir), gt_value->buffer);

	if (_r_sys_getopt (_r_sys_getcommandline (), L"feed-dir", &feed_value) && feed_value)
		copy_bounded (feed_dir, RTL_NUMBER_OF (feed_dir), feed_value->buffer);

	if (thumbprint_value)
		_r_obj_dereference (thumbprint_value);

	if (apph_value)
		_r_obj_dereference (apph_value);

	if (gt_value)
		_r_obj_dereference (gt_value);

	if (feed_value)
		_r_obj_dereference (feed_value);

	exe_arg = find_positional_exe ();


	if (!exe_arg)
	{
		PR_STRING usage = _r_obj_createstring (L"usage: preflight.exe <exe> [--ci] [--json] [--thumbprint <hex>] [--app-h <path>] [--ground-truth-dir <dir>] [--feed-dir <dir>]");

		out_write (usage->buffer, usage->length);
		_r_obj_dereference (usage);

		return 2; // argparse exits 2 on a missing positional
	}

	// python: exe = os.path.abspath(args.exe)
	{
		WCHAR full[4096];

		if (!GetFullPathNameW (exe_arg->buffer, RTL_NUMBER_OF (full), full, NULL) || !full[0])
		{
			PR_STRING line = _r_format_string (L"FAIL: exe not found: %ls", exe_arg->buffer);

			out_write (line->buffer, line->length);
			_r_obj_dereference (line);
			_r_obj_dereference (exe_arg);

			return 1;
		}

		exe_path = _r_obj_createstring (full);
	}

	_r_obj_dereference (exe_arg);

	if (!path_exists (exe_path->buffer, FALSE))
	{
		PR_STRING line = _r_format_string (L"FAIL: exe not found: %ls", exe_path->buffer);

		out_write (line->buffer, line->length);
		_r_obj_dereference (line);

		return 1;
	}

	// path bases (python resolves relative to its script dir; the C tool
	// resolves relative to the repo layout around the exe)
	{
		R_STRINGREF image_sr;

		_r_obj_initializestringref (&image_sr, _r_sys_getimagepath ());

		base_dir = _r_path_getbasedirectory (&image_sr);
	}

	if (!base_dir)
	{
		PR_STRING line = _r_obj_createstring (L"FAIL: cannot resolve base directory");

		out_write (line->buffer, line->length);
		_r_obj_dereference (line);

		return 1;
	}

	if (!app_h_path[0])
	{
		PR_STRING resolved = resolve_path (base_dir->buffer, L"..\\..\\src\\app.h", L"src\\app.h", FALSE);

		copy_bounded (app_h_path, RTL_NUMBER_OF (app_h_path), resolved->buffer);
		_r_obj_dereference (resolved);
	}

	if (!gt_dir[0])
	{
		PR_STRING resolved = resolve_path (base_dir->buffer, L"..\\..\\tools\\preflight-ground-truth", L"tools\\preflight-ground-truth", TRUE);

		copy_bounded (gt_dir, RTL_NUMBER_OF (gt_dir), resolved->buffer);
		_r_obj_dereference (resolved);
	}

	if (!feed_dir[0])
	{
		// repo root, resolved via the in-repo VERSION.sig (GetFullPathNameW
		// refuses to collapse a TRAILING dot-dot segment, so anchor on a
		// real child file and take its parent directory)
		PR_STRING resolved = resolve_path (base_dir->buffer, L"..\\..\\VERSION.sig", L"VERSION.sig", FALSE);
		LPCWSTR last = wcsrchr (resolved->buffer, L'\\');

		if (last && last != resolved->buffer)
		{
			SIZE_T dir_len = (SIZE_T)(last - resolved->buffer);

			if (dir_len >= RTL_NUMBER_OF (feed_dir))
				dir_len = RTL_NUMBER_OF (feed_dir) - 1;

			memcpy (feed_dir, resolved->buffer, dir_len * sizeof (WCHAR));
			feed_dir[dir_len] = UNICODE_NULL;
		}
		else
		{
			copy_bounded (feed_dir, RTL_NUMBER_OF (feed_dir), resolved->buffer);
		}

		_r_obj_dereference (resolved);
	}

	{
		PR_STRING resolved = resolve_path (base_dir->buffer, L"..\\..\\src\\update_key.h", L"src\\update_key.h", FALSE);

		copy_bounded (tree_key_path, RTL_NUMBER_OF (tree_key_path), resolved->buffer);
		_r_obj_dereference (resolved);
	}

	_r_obj_dereference (base_dir);


	// FR-02: ground truth must load before anything else — fail closed
	if (!load_ground_truth (gt_dir, err_path, RTL_NUMBER_OF (err_path)))
		return 1;


	record (L"ground-truth-load", CHECK_STATE_PASS, L"%ls", gt_dir);

	// python block: tree_key = parse_update_key_h(...); app_version =
	// parse_app_version(...); read_pe(exe) — one combined fail-closed step
	memset (tree_key, 0, sizeof (tree_key));
	app_version[0] = UNICODE_NULL;

	if (!parse_update_key_h (tree_key_path, tree_key))
	{
		record (L"pe/app-h parse", CHECK_STATE_FAIL, L"UPDATE_PUBLIC_KEY not found in update_key.h");
		return 1;
	}

	if (!parse_app_version (app_h_path, app_version))
	{
		record (L"pe/app-h parse", CHECK_STATE_FAIL, L"APP_VERSION not found in app.h");
		return 1;
	}

	status = read_file_bytes (exe_path->buffer, &exe_bytes);

	if (!NT_SUCCESS (status))
	{
		record (L"pe/app-h parse", CHECK_STATE_FAIL, L"exe read failed (status 0x%08lx)", status);
		return 1;
	}

	if (!pe_parse (exe_bytes->buffer, exe_bytes->length, &pe_info, &pe_error))
	{
		record (L"pe/app-h parse", CHECK_STATE_FAIL, L"%ls", pe_error ? pe_error : L"not a PE image");
		return 1;
	}

	// (a) Authenticode — full profile only
	ok_all &= check_authenticode (exe_path->buffer, thumbprint, is_ci);


	// (b1) embedded feed key vs in-tree update_key.h (CI-safe)
	ok_all &= check_embedded_key (exe_bytes->buffer, exe_bytes->length, tree_key);


	// (b2) in-tree key vs off-repo JSON ground truth (owner-side only)
	if (is_ci)
		ok_all &= record (L"(b2) key vs off-repo JSON", CHECK_STATE_SKIP, L"release profile \u2014 JSON never leaves owner machine");
	else
		ok_all &= check_key_json (KEY_JSON_PATH, tree_key, key_sha_pinned);


	// (b-feed, DEC-09): repo feed pair vs the production verifier
	ok_all &= check_feed (feed_dir, tree_key);


	// (c) import parity
	ok_all &= check_imports (&pe_info, &gt_imports_data);


	// (d) version resource vs src/app.h
	ok_all &= check_version (exe_path->buffer, app_version);


	// (e) SWC1 container + blocklist parity
	ok_all &= check_swc1 (exe_path->buffer, &gt_blocklist_data);


	// (f) PE security flags parity
	ok_all &= check_peflags (&pe_info, &gt_peflags_data);

	if (is_json)
		write_json_output (exe_path->buffer, is_ci, ok_all ? TRUE : FALSE);

	_r_obj_dereference (exe_bytes);
	_r_obj_dereference (exe_path);

	return ok_all ? 0 : 1;
}
