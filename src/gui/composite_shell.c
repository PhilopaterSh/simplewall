// simplewall
// Copyright (c) 2016-2026 Henry++

// composite_shell (G-1, r3-integrated): fork-native owner-drawn GUI.
// Visual authority docs/specs/gui/mockup-r1.html; mechanics authority
// design-gui-draft.md r2 + r3 amendment (G1-M1 theme + DPI awareness +
// buffered paint, G1-M2 virtualized Apps page + debounced shell-global
// search + full-row signature, G1-M3 draw-side RTL mirroring, G1-M4
// locale pipeline, G1-M5 hygiene incl. the DEC-04 lockdown pre-flight
// surface, G1-M6 basic MSAA labels in composite_shell_a11y.c).
// Extends the composite modules through their query APIs only — no
// WFP/engine interaction here. Run with `simplewall.exe -gui` AFTER
// _r_app_initialize (locale/config/mitigations live; the shell loads
// the profile itself in WM_CREATE).

#include "../global.h"

#include <wchar.h>

#include "../composite_lockdown.h" // composite Phase 1 (FR-06/DEC-04)
#include "../composite_packs.h" // composite Phase 2 (FR-08/DATA-02)
#include "../composite_ledger.h" // composite Phase 2 (FR-10/DATA-03)
#include "../composite_resolver.h" // composite Phase 3 (DNS attribution)
#include "../composite_state.h" // composite Phase 1 (T005/T006)
#include "../composite_bypass.h" // composite Phase 3 (T033b)

#include "../wfp.h" // engine-installed probe for the Log page honesty line

#include "composite_shell_res.h" // fork-owned IDS_SHELL_* (DEC-09)
#include "composite_shell.h"

// a11y bridge (G1-M6): implemented in composite_shell_a11y.c
LRESULT _app_shell_a11y_getobject (
	_In_ HWND hwnd,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
);

#define SHELL_CLASSNAME L"quietwall_shell"
#define SHELL_TIMER_REFRESH 1
#define SHELL_TIMER_FILTER 2
#define SHELL_TIMER_COUNTDOWN 3
#define SHELL_TIMER_REFRESH_MS 2000
#define SHELL_TIMER_FILTER_MS 250 // System Informer SearchDelayMs precedent
#define SHELL_TIMER_COUNTDOWN_MS 1000 // r4 G2-M4 urgency cadence

#define SHELL_ID_SEARCH 1

#define SHELL_CLIENT_W 1080
#define SHELL_CLIENT_H 680
#define SHELL_RAIL_W 200
#define SHELL_MARGIN 16
#define SHELL_CARD_H 56
#define SHELL_CARD_GAP 8
#define SHELL_ROW_PITCH (SHELL_CARD_H + SHELL_CARD_GAP)
#define SHELL_RULES_ROW_PITCH 40
#define SHELL_PILL_W 72
#define SHELL_PILL_H 24
#define SHELL_CHECKBOX_SIZE 16
#define SHELL_SEARCH_OFF 44
#define SHELL_SEARCH_H 30
#define SHELL_SEARCH_W 320
#define SHELL_CHIPS_OFF (SHELL_SEARCH_OFF + SHELL_SEARCH_H + 10)
#define SHELL_CHIPS_H 30
#define SHELL_ROWS_OFF (SHELL_CHIPS_OFF + SHELL_CHIPS_H + 12)
#define SHELL_SCROLLBAR_W 10
#define SHELL_FILTER_MAX 64
#define SHELL_NAME_MAX 96
#define SHELL_PATH_MAX 192
#define SHELL_LINE_MAX 160
#define SHELL_TEXT_MAX 1024

// EM_SETCUEBANNER landed with _WIN32_IE 0x0600; guard for old SDKs
#ifndef EM_SETCUEBANNER
#define EM_SETCUEBANNER (WM_USER + 0x1501)
#endif

// buffered paint is dynamic-resolved (NFR-02): documented uxtheme named
// exports, no library linkage, no ordinal hooking (r3 G1-M1)
#ifndef BPBF_COMPATIBLEBUFFERS
#define BPBF_COMPATIBLEBUFFERS 0
#endif

typedef HANDLE HPAINTBUFFER_SHELL;

typedef HPAINTBUFFER_SHELL (WINAPI *SHELL_PFN_BEGINBUFFEREDPAINT) (
	_In_ HDC hdc_target,
	_In_ LPCRECT prc_target,
	_In_ UINT format,
	_In_opt_ void *paint_params,
	_Out_ HDC *hdc_buffer
);

typedef HRESULT (WINAPI *SHELL_PFN_ENDBUFFEREDPAINT) (
	_In_ HPAINTBUFFER_SHELL hbufferedpaint,
	_In_ BOOLEAN update_target
);

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((HANDLE)-4)
#endif

typedef HANDLE (WINAPI *SHELL_PFN_SETDPICONTEXT) (
	_In_ HANDLE value
);

// mockup-r1.html palette (dark) + derived light palette (r3 G1-M1:
// owner-selectable per DEC-11 "dark/light owner-selectable")
typedef struct _SHELL_PALETTE
{
	COLORREF bg;
	COLORREF rail;
	COLORREF card;
	COLORREF line;
	COLORREF accent;
	COLORREF accenttext;
	COLORREF text;
	COLORREF muted;
	COLORREF ok;
	COLORREF okbg;
	COLORREF okline;
	COLORREF danger;
	COLORREF dangerbg;
	COLORREF dangerline;
	COLORREF warn;
	COLORREF warnbg;
	COLORREF warnline;
} SHELL_PALETTE;

static const SHELL_PALETTE shell_palette_dark = {
	RGB (0x0b, 0x12, 0x20), // bg
	RGB (0x11, 0x1a, 0x2e), // rail
	RGB (0x16, 0x20, 0x3a), // card
	RGB (0x22, 0x30, 0x52), // line
	RGB (0x2d, 0xd4, 0xbf), // accent
	RGB (0x06, 0x20, 0x20), // accenttext
	RGB (0xdb, 0xe6, 0xf5), // text
	RGB (0x8a, 0xa0, 0xc0), // muted
	RGB (0x34, 0xd3, 0x99), // ok
	RGB (0x0f, 0x2b, 0x22), // okbg
	RGB (0x1c, 0x5a, 0x45), // okline
	RGB (0xf8, 0x71, 0x71), // danger
	RGB (0x2b, 0x12, 0x12), // dangerbg
	RGB (0x6b, 0x27, 0x27), // dangerline
	RGB (0xfb, 0xbf, 0x24), // warn
	RGB (0x2b, 0x20, 0x05), // warnbg
	RGB (0x6b, 0x54, 0x1c), // warnline
};

static const SHELL_PALETTE shell_palette_light = {
	RGB (0xf4, 0xf6, 0xfa), // bg
	RGB (0xe9, 0xec, 0xf2), // rail
	RGB (0xff, 0xff, 0xff), // card
	RGB (0xd5, 0xda, 0xe4), // line
	RGB (0x14, 0xb8, 0xa6), // accent
	RGB (0xff, 0xff, 0xff), // accenttext
	RGB (0x1a, 0x22, 0x33), // text
	RGB (0x5c, 0x6c, 0x88), // muted
	RGB (0x0f, 0x9d, 0x6f), // ok
	RGB (0xe6, 0xf7, 0xf0), // okbg
	RGB (0xa9, 0xdf, 0xca), // okline
	RGB (0xdc, 0x3d, 0x3d), // danger
	RGB (0xfd, 0xee, 0xee), // dangerbg
	RGB (0xf0, 0xb4, 0xb4), // dangerline
	RGB (0xc0, 0x8a, 0x00), // warn
	RGB (0xff, 0xf6, 0xdc), // warnbg
	RGB (0xe4, 0xd0, 0x8f), // warnline
};

typedef enum _SHELL_PAGE
{
	SHELL_PAGE_APPS = 0,
	SHELL_PAGE_RULES,
	SHELL_PAGE_PACKS,
	SHELL_PAGE_LOCKDOWN,
	SHELL_PAGE_LOG,
	SHELL_PAGE_SETTINGS,
	SHELL_PAGE_MAX
} SHELL_PAGE;

typedef struct _SHELL_APP_SNAPSHOT
{
	WCHAR name[SHELL_NAME_MAX];
	WCHAR path[SHELL_PATH_MAX];
	INT state; // render state: 0 = block, 1 = allow, 2 = prompt (notification set)
} SHELL_APP_SNAPSHOT;

// shell_is_rtl is the direction-flag plumbing required in M1 (r3
// G1-M3): the M4 i18n sweep wires it to the active pack's direction
// metadata; the mockup authority (dir="rtl") makes RTL the M1 truth
static BOOLEAN shell_is_rtl = TRUE;

static const ULONG shell_rail_ids[SHELL_PAGE_MAX] = {
	IDS_SHELL_RAIL_APPS,
	IDS_SHELL_RAIL_RULES,
	IDS_SHELL_RAIL_PACKS,
	IDS_SHELL_RAIL_LOCKDOWN,
	IDS_SHELL_RAIL_LOG,
	IDS_SHELL_RAIL_SETTINGS,
};

// apps snapshot (heap-grown; r3 G1-M2 removed the 200-row cap)
static SHELL_APP_SNAPSHOT *shell_apps = NULL;
static ULONG shell_apps_cap = 0;
static ULONG shell_apps_count = 0;
static ULONG shell_apps_total = 0;
static ULONG shell_apps_allowed = 0;
static ULONG shell_apps_blocked = 0;
static ULONG shell_apps_prompt = 0;
static ULONG64 shell_apps_sig = 0; // full-row hash (goldfish finding 6)

// filtered view index over the snapshot (System Informer pipeline shape)
static ULONG *shell_view = NULL;
static ULONG shell_view_cap = 0;
static ULONG shell_view_count = 0;
static WCHAR shell_filter[SHELL_FILTER_MAX] = {0};

// rules page data (r4 G2-M2/M4): decisions snapshot (names resolved by
// the module query API; remaining computed from the ABSOLUTE expiry) +
// anchor count. The remaining[] display string is recomputed by the 1s
// countdown tick ONLY — it is excluded from every change signature
// (r3 finding 5 rule i)
typedef struct _SHELL_DECISION_ROW
{
	ULONG app_hash;
	WCHAR name[SHELL_NAME_MAX];
	BOOLEAN is_block;
	BOOLEAN is_once;
	LONG64 expires; // unix time; 0 = until restart
	ULONG remaining_cached; // seconds at last tick (color threshold)
	WCHAR remaining[48]; // displayed countdown text
} SHELL_DECISION_ROW;

static SHELL_DECISION_ROW *shell_decisions = NULL;
static ULONG shell_decisions_cap = 0;
static ULONG shell_decisions_count = 0;
static ULONG shell_anchors_count = 0;
static ULONG64 shell_decisions_sig = 0; // EXCLUDES remaining[] text

static INT shell_page = SHELL_PAGE_APPS;
static INT shell_rail_focus = SHELL_PAGE_APPS;
static BOOLEAN shell_input_kbd = FALSE; // last input was keyboard (focus rect)
static RECT shell_rail_rects[SHELL_PAGE_MAX] = {0};
static RECT shell_lockdown_btn = {0};
static RECT shell_check_rects[5] = {0}; // settings rows (4 gates + theme)
static RECT shell_scrollbar_rect = {0};
static RECT shell_scrollbar_thumb = {0};
static BOOLEAN shell_scrollbar_drag = FALSE;
static LONG shell_scrollbar_drag_off = 0;
static LONG shell_scroll = 0; // px

static BOOLEAN shell_is_light = FALSE;
static const SHELL_PALETTE *shell_pal = &shell_palette_dark;
static HWND shell_hwnd_search = NULL;

static HFONT shell_font_title = NULL;
static HFONT shell_font_main = NULL;
static HFONT shell_font_small = NULL;
static HFONT shell_font_pill = NULL;

static SHELL_PFN_BEGINBUFFEREDPAINT shell_pfn_beginbufferedpaint = NULL;
static SHELL_PFN_ENDBUFFEREDPAINT shell_pfn_endbufferedpaint = NULL;

static VOID _app_shell_locale (
	_Out_writes_ (cch) WCHAR *dst,
	_In_ ULONG cch,
	_In_ ULONG id
)
{
	LPWSTR src;

	if (!cch)
		return;

	dst[0] = UNICODE_NULL;

	// copy-immediately contract: _r_locale_getstring returns the buffer
	// of a temporarily-referenced object (routine rapp.c's own TODO
	// admits it) — never store the pointer (r3 G1-M4; upstream
	// precedent main.c:85)
	src = _r_locale_getstring (id);

	if (src && src[0])
	{
		_r_str_copy (dst, cch, src);
	}
	else
	{
		// last-resort fallback: the fork-owned exe stringtable
		LoadStringW (NULL, id, dst, (INT)cch);
	}
}

static VOID _app_shell_strcopy (
	_Out_writes_ (dst_chars) WCHAR *dst,
	_In_ ULONG dst_chars,
	_In_opt_ LPCWSTR src
)
{
	ULONG i;

	if (!dst_chars)
		return;

	if (!src)
	{
		dst[0] = UNICODE_NULL;
		return;
	}

	for (i = 0; i + 1 < dst_chars && src[i] != UNICODE_NULL; i++)
		dst[i] = src[i];

	dst[i] = UNICODE_NULL;
}

// case-insensitive substring (manual, no shlwapi dependency)
static BOOLEAN _app_shell_strfindi (
	_In_ LPCWSTR haystack,
	_In_ LPCWSTR needle
)
{
	WCHAR hay_lower[2 * SHELL_PATH_MAX];
	WCHAR needle_lower[SHELL_FILTER_MAX];
	ULONG i;
	ULONG hay_len;

	if (!needle || !needle[0])
		return TRUE;

	if (!haystack)
		return FALSE;

	hay_len = 0;

	for (i = 0; haystack[i] && hay_len + 1 < RTL_NUMBER_OF (hay_lower); i++)
		hay_lower[hay_len++] = (WCHAR)towlower (haystack[i]);

	hay_lower[hay_len] = UNICODE_NULL;

	for (i = 0; needle[i] && i + 1 < RTL_NUMBER_OF (needle_lower); i++)
		needle_lower[i] = (WCHAR)towlower (needle[i]);

	needle_lower[i] = UNICODE_NULL;

	return wcsstr (hay_lower, needle_lower) != NULL;
}

static VOID _app_shell_drawtext (
	_In_ HDC hdc,
	_In_ LPCWSTR text,
	_In_ PRECT rect,
	_In_ HFONT font,
	_In_ COLORREF color,
	_In_ UINT flags
)
{
	HFONT old_font;
	COLORREF old_color;

	old_font = (HFONT)SelectObject (hdc, font);
	old_color = SetTextColor (hdc, color);
	SetBkMode (hdc, TRANSPARENT);
	DrawTextW (hdc, text, -1, rect, flags | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
	SetTextColor (hdc, old_color);
	SelectObject (hdc, old_font);
}

static VOID _app_shell_fillrect (
	_In_ HDC hdc,
	_In_ PRECT rect,
	_In_ COLORREF fill
)
{
	HBRUSH brush = CreateSolidBrush (fill);
	HBRUSH old_brush = (HBRUSH)SelectObject (hdc, brush);

	FillRect (hdc, rect, brush);

	SelectObject (hdc, old_brush);
	DeleteObject (brush);
}

static VOID _app_shell_fillround (
	_In_ HDC hdc,
	_In_ PRECT rect,
	_In_ COLORREF fill,
	_In_ COLORREF border,
	_In_ LONG radius
)
{
	HBRUSH brush = CreateSolidBrush (fill);
	HPEN pen = CreatePen (PS_SOLID, 1, border);
	HBRUSH old_brush;
	HPEN old_pen;

	old_brush = (HBRUSH)SelectObject (hdc, brush);
	old_pen = (HPEN)SelectObject (hdc, pen);

	RoundRect (hdc, rect->left, rect->top, rect->right, rect->bottom, radius, radius);

	SelectObject (hdc, old_brush);
	SelectObject (hdc, old_pen);

	DeleteObject (brush);
	DeleteObject (pen);
}

static VOID _app_shell_drawpill (
	_In_ HDC hdc,
	_In_ PRECT rect,
	_In_ LPCWSTR text,
	_In_ COLORREF fg,
	_In_ COLORREF bg,
	_In_ COLORREF border
)
{
	_app_shell_fillround (hdc, rect, bg, border, 6);
	_app_shell_drawtext (hdc, text, rect, shell_font_pill, fg, DT_CENTER | DT_VCENTER);
}

static VOID _app_shell_drawchip (
	_In_ HDC hdc,
	_In_ PRECT rect,
	_In_ LPCWSTR text
)
{
	_app_shell_fillround (hdc, rect, shell_pal->card, shell_pal->line, 8);
	_app_shell_drawtext (hdc, text, rect, shell_font_small, shell_pal->text, DT_CENTER | DT_VCENTER);
}

static VOID _app_shell_pagetitle (
	_In_ HDC hdc,
	_In_ PRECT content,
	_In_ ULONG title_id,
	_In_ ULONG subtitle_id // 0 = none
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	RECT rect;

	rect = *content;
	rect.bottom = rect.top + 34;

	_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), title_id);
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_title, shell_pal->text, shell_is_rtl ? DT_RIGHT : DT_LEFT);

	if (subtitle_id)
	{
		rect.top = rect.bottom + 2;
		rect.bottom = rect.top + 22;

		_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), subtitle_id);
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);
	}
}

// window frame: rail rect + content rect, language-conditional (r3
// G1-M3: rail on the inline-start — right under RTL, left under LTR)
static VOID _app_shell_frame (
	_In_ HWND hwnd,
	_Out_ PRECT rail,
	_Out_ PRECT content
)
{
	RECT client;

	if (!GetClientRect (hwnd, &client))
	{
		SetRectEmpty (rail);
		SetRectEmpty (content);
		return;
	}

	if (shell_is_rtl)
	{
		rail->left = client.right - SHELL_RAIL_W;
		rail->right = client.right;
		rail->top = 0;
		rail->bottom = client.bottom;

		content->left = SHELL_MARGIN;
		content->right = client.right - SHELL_RAIL_W - SHELL_MARGIN;
	}
	else
	{
		rail->left = client.left;
		rail->right = client.left + SHELL_RAIL_W;
		rail->top = 0;
		rail->bottom = client.bottom;

		content->left = client.left + SHELL_RAIL_W + SHELL_MARGIN;
		content->right = client.right - SHELL_MARGIN;
	}

	content->top = SHELL_MARGIN;
	content->bottom = client.bottom - SHELL_MARGIN;
}

// rows region of the Apps page: shared by paint, scrollbar and a11y
static VOID _app_shell_appsrowsrect (
	_In_ HWND hwnd,
	_Out_ PRECT rows
)
{
	RECT rail;
	RECT content;

	_app_shell_frame (hwnd, &rail, &content);

	rows->top = content.top + SHELL_ROWS_OFF;
	rows->bottom = content.bottom;

	if (shell_is_rtl)
	{
		rows->left = content.left + SHELL_SCROLLBAR_W + 6;
		rows->right = content.right;
	}
	else
	{
		rows->left = content.left;
		rows->right = content.right - SHELL_SCROLLBAR_W - 6;
	}
}

// rows region for the ACTIVE page (apps cards or rules rows) — the
// scrollbar machinery is shared (r4 G2-M2); rules rows start below the
// page title (no search/chips offsets on that page)
static VOID _app_shell_listrowsrect (
	_In_ HWND hwnd,
	_Out_ PRECT rows
)
{
	RECT rail;
	RECT content;

	if (shell_page != SHELL_PAGE_RULES)
	{
		_app_shell_appsrowsrect (hwnd, rows);
		return;
	}

	_app_shell_frame (hwnd, &rail, &content);

	rows->top = content.top + 60;
	rows->bottom = content.bottom;

	if (shell_is_rtl)
	{
		rows->left = content.left + SHELL_SCROLLBAR_W + 6;
		rows->right = content.right;
	}
	else
	{
		rows->left = content.left;
		rows->right = content.right - SHELL_SCROLLBAR_W - 6;
	}
}

// combined render-row count of the rules page (2 section headers +
// decisions + anchors)
static ULONG _app_shell_rules_totalrows (VOID)
{
	return 2 + shell_decisions_count + shell_anchors_count;
}

static VOID _app_shell_scrollclamp (_In_ HWND hwnd)
{
	LONG scrollmax = _app_shell_scrollmax (hwnd);

	shell_scroll = min (max (0, shell_scroll), scrollmax);
}

static VOID _app_shell_scrollby (
	_In_ HWND hwnd,
	_In_ LONG delta
)
{
	shell_scroll += delta;
	_app_shell_scrollclamp (hwnd);
	InvalidateRect (hwnd, NULL, FALSE);
}

static LONG _app_shell_pagedelta (_In_ HWND hwnd)
{
	RECT rows;

	_app_shell_listrowsrect (hwnd, &rows);

	return max (SHELL_ROW_PITCH, (rows.bottom - rows.top) - SHELL_ROW_PITCH);
}

static LONG _app_shell_scrollmax (_In_ HWND hwnd)
{
	RECT rows;
	LONG total_height;

	_app_shell_listrowsrect (hwnd, &rows);

	if (shell_page == SHELL_PAGE_RULES)
		total_height = (LONG)_app_shell_rules_totalrows () * SHELL_RULES_ROW_PITCH;
	else
		total_height = (LONG)shell_view_count * SHELL_ROW_PITCH;

	if (total_height)
		total_height -= SHELL_CARD_GAP; // no trailing gap

	return max (0, total_height - (rows.bottom - rows.top));
}

// DPI awareness prerequisite (r3 G1-M1, goldfish finding 2): the
// process declared nothing, so WM_DPICHANGED could never arrive. No
// manifest (GenerateManifest=false is the binary posture) — dynamic
// per-OS code path, scoped to the shell before its first window.
static VOID _app_shell_dpiaware (VOID)
{
	SHELL_PFN_SETDPICONTEXT pfn;
	HMODULE huser32;

	huser32 = GetModuleHandleW (L"user32.dll");

	if (!huser32)
		return;

	pfn = (SHELL_PFN_SETDPICONTEXT)GetProcAddress (huser32, "SetProcessDpiAwarenessContext");

	if (pfn)
	{
		pfn (DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	}
	else
	{
		// pre-1703 fallback: the plain documented user32 export
		pfn = (SHELL_PFN_SETDPICONTEXT)GetProcAddress (huser32, "SetProcessDPIAware");

		if (pfn)
			pfn (NULL); // BOOL (VOID) — the context argument is ignored
	}
}

static VOID _app_shell_fonts_destroy (VOID)
{
	if (shell_font_title)
		DeleteObject (shell_font_title);

	if (shell_font_main)
		DeleteObject (shell_font_main);

	if (shell_font_small)
		DeleteObject (shell_font_small);

	if (shell_font_pill)
		DeleteObject (shell_font_pill);

	shell_font_title = NULL;
	shell_font_main = NULL;
	shell_font_small = NULL;
	shell_font_pill = NULL;
}

static VOID _app_shell_fonts_create (_In_ LONG dpi)
{
	_app_shell_fonts_destroy ();

	shell_font_title = CreateFontW (-MulDiv (15, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	shell_font_main = CreateFontW (-MulDiv (12, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	shell_font_small = CreateFontW (-MulDiv (10, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	shell_font_pill = CreateFontW (-MulDiv (10, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
}

static VOID _app_shell_themeapply (_In_ HWND hwnd)
{
	LONG override_value;

	// tri-state: -1 = follow the system, 0 = dark, 1 = light (DEC-11
	// "owner-selectable"; auto-detect is the registry read routine
	// itself trusts — ShouldAppsUseDarkMode is unreliable >=1903)
	override_value = _r_config_getlong (L"IsShellLightTheme", -1, NULL);

	shell_is_light = (override_value == -1) ? !_r_wnd_isdarkmodeenabled () : (override_value != 0);
	shell_pal = shell_is_light ? &shell_palette_light : &shell_palette_dark;

	// dark titlebar (attr 20 with the attr-19 pre-20H1 fallback inside
	// routine; Win11 border/caption/corner handled there too)
	_r_theme_setwindowframe (hwnd, !shell_is_light);

	if (shell_hwnd_search)
		_r_theme_enable (shell_hwnd_search, !shell_is_light);

	InvalidateRect (hwnd, NULL, TRUE);
}

// full apps-table snapshot + FULL-ROW signature (r3 G1-M2, goldfish
// finding 6: aggregate signatures miss renames/toggles/swaps).
// Single-threaded UI: the GUI thread is the only writer of the arrays;
// the shared apps lock protects the table read.
static BOOLEAN _app_shell_snapshot (VOID)
{
	PITEM_APP ptr_app = NULL;
	ULONG_PTR enum_key = 0;
	ULONG count = 0;
	ULONG allowed = 0;
	ULONG blocked = 0;
	ULONG prompt = 0;
	ULONG64 sig = 0xcbf29ce484222325ull; // FNV-1a offset basis
	BOOLEAN changed;

	_r_queuedlock_acquireshared (&lock_apps);

	while (_r_obj_enumhashtablepointer (apps_table, (PVOID_PTR)&ptr_app, NULL, &enum_key))
	{
		SHELL_APP_SNAPSHOT snap;
		LPCWSTR name_src;
		LPCWSTR path_src;
		ULONG i;

		if (count == shell_apps_cap)
		{
			ULONG new_cap = shell_apps_cap ? shell_apps_cap * 2 : 64;
			SHELL_APP_SNAPSHOT *grown = (SHELL_APP_SNAPSHOT *)HeapReAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, shell_apps, new_cap * sizeof (SHELL_APP_SNAPSHOT));

			if (!grown)
				break; // OOM: render what we have (degrades honestly)

			shell_apps = grown;
			shell_apps_cap = new_cap;
		}

		memset (&snap, 0, sizeof (snap));

		name_src = ptr_app->display_name ? ptr_app->display_name->buffer : NULL;
		path_src = ptr_app->real_path ? ptr_app->real_path->buffer : (ptr_app->short_name ? ptr_app->short_name->buffer : NULL);

		_app_shell_strcopy (snap.name, SHELL_NAME_MAX, name_src);
		_app_shell_strcopy (snap.path, SHELL_PATH_MAX, path_src);

		if (ptr_app->notification)
			snap.state = 2;
		else if (ptr_app->is_enabled)
			snap.state = 1;
		else
			snap.state = 0;

		shell_apps[count++] = snap;

		// counts follow the RENDER states (goldfish finding 6: a
		// notification-flagged enabled app is a prompt, not an allow)
		if (snap.state == 2)
			prompt++;
		else if (snap.state == 1)
			allowed++;
		else
			blocked++;

		for (i = 0; snap.name[i]; i++)
		{
			sig ^= (ULONG64)(USHORT)snap.name[i];
			sig *= 0x100000001b3ull;
		}

		sig ^= (ULONG64)(USHORT)UNICODE_NULL;
		sig *= 0x100000001b3ull;

		for (i = 0; snap.path[i]; i++)
		{
			sig ^= (ULONG64)(USHORT)snap.path[i];
			sig *= 0x100000001b3ull;
		}

		sig ^= (ULONG64)(USHORT)UNICODE_NULL;
		sig *= 0x100000001b3ull;

		sig ^= (ULONG64)(ULONG)snap.state;
		sig *= 0x100000001b3ull;
	}

	_r_queuedlock_releaseshared (&lock_apps);

	sig ^= (ULONG64)count;
	sig *= 0x100000001b3ull;

	changed = (count != shell_apps_count) || (sig != shell_apps_sig);

	shell_apps_count = count;
	shell_apps_sig = sig;
	shell_apps_total = count;
	shell_apps_allowed = allowed;
	shell_apps_blocked = blocked;
	shell_apps_prompt = prompt;

	return changed;
}

static VOID _app_shell_applyfilter (VOID)
{
	ULONG i;

	if (shell_view_cap < shell_apps_count)
	{
		ULONG new_cap = shell_apps_count ? shell_apps_count : 1;
		ULONG *grown = (ULONG *)HeapReAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, shell_view, new_cap * sizeof (ULONG));

		if (!grown)
			return;

		shell_view = grown;
		shell_view_cap = new_cap;
	}

	shell_view_count = 0;

	for (i = 0; i < shell_apps_count; i++)
	{
		SHELL_APP_SNAPSHOT *snap = &shell_apps[i];

		if (!shell_filter[0] ||
			_app_shell_strfindi (snap->name, shell_filter) ||
			_app_shell_strfindi (snap->path, shell_filter))
		{
			shell_view[shell_view_count++] = i;
		}
	}
}

// countdown display rule (r4 G2-M4; the research synthesis): adaptive
// precision — >60m "3h 05m" · 10-60m "42m" · 1-10m "m:ss" · <=60s "38s";
// until-restart = static badge
static VOID _app_shell_remainingtext (
	_In_ LONG64 expires,
	_Out_ WCHAR *buffer,
	_In_ ULONG cch,
	_Out_opt_ PULONG out_seconds
)
{
	WCHAR fmt[64];
	LONG64 now;
	ULONG rem;

	buffer[0] = UNICODE_NULL;

	if (out_seconds)
		*out_seconds = 0;

	if (!expires)
	{
		_app_shell_locale (buffer, cch, IDS_SHELL_UNTIL_RESTART);
		return;
	}

	now = _r_unixtime_now ();
	rem = expires > now ? (ULONG)(expires - now) : 0;

	if (out_seconds)
		*out_seconds = rem;

	if (rem >= 3600)
	{
		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_CD_HM);
		_r_str_printf (buffer, cch, fmt, rem / 3600, (rem % 3600) / 60);
	}
	else if (rem >= 600)
	{
		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_CD_M);
		_r_str_printf (buffer, cch, fmt, rem / 60);
	}
	else if (rem >= 60)
	{
		_r_str_printf (buffer, cch, L"%lu:%02lu", rem / 60, rem % 60);
	}
	else
	{
		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_CD_S);
		_r_str_printf (buffer, cch, fmt, rem);
	}
}

// rules page data refresh (2s tick + create): decisions via the module
// query API (lock_state ALONE inside the module; names resolved with
// zero nesting) + the anchor count. Change signature EXCLUDES the
// countdown text (r3 finding 5 rule i)
static VOID _app_shell_rulesrefresh (_Out_opt_ PBOOLEAN out_changed)
{
	SHELL_DECISION_ROW *rows;
	ULONG count;
	ULONG64 sig;
	ULONG i;

	if (out_changed)
		*out_changed = FALSE;

	count = _app_state_querycount ();

	if (count > shell_decisions_cap)
	{
		ULONG new_cap = count ? count * 2 : 8;
		SHELL_DECISION_ROW *grown = (SHELL_DECISION_ROW *)HeapReAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY, shell_decisions, new_cap * sizeof (SHELL_DECISION_ROW));

		if (!grown)
			return; // OOM: keep the previous snapshot

		shell_decisions = grown;
		shell_decisions_cap = new_cap;
	}

	rows = shell_decisions;
	sig = 0xcbf29ce484222325ull;

	for (i = 0; i < count; i++)
	{
		SHELL_DECISION_ROW *row = &rows[i];
		ULONG hash = 0;
		WCHAR name[SHELL_NAME_MAX];
		BOOLEAN is_block;
		BOOLEAN is_once;
		ULONG rem;

		if (!_app_state_query (i, &hash, name, RTL_NUMBER_OF (name), &is_block, &is_once, &rem))
			break;

		row->app_hash = hash;
		row->is_block = is_block;
		row->is_once = is_once;
		row->remaining_cached = rem;

		// keep the ABSOLUTE expiry as the query API derives it: re-query
		// gives remaining only, so derive expires back from now (the
		// absolute value is the module's truth; our tick recomputes from
		// this derived value and self-corrects on the next refresh)
		row->expires = rem ? (_r_unixtime_now () + (LONG64)rem) : 0;

		_r_str_copy (row->name, SHELL_NAME_MAX, name);

		_app_shell_remainingtext (row->expires, row->remaining, RTL_NUMBER_OF (row->remaining), NULL);

		// signature: identity + verdict + expiry bucket — NOT remaining
		// text, NOT the per-second churn
		sig ^= (ULONG64)hash;
		sig *= 0x100000001b3ull;
		sig ^= row->expires ? (ULONG64)(row->expires / 60) : 1; // minute bucket
		sig *= 0x100000001b3ull;
		sig ^= is_block ? 0x2 : 0x1;
		sig *= 0x100000001b3ull;
	}

	shell_decisions_count = count;
	shell_anchors_count = _app_publisher_queryanchorcount ();

	if (out_changed && sig != shell_decisions_sig)
		*out_changed = TRUE;

	shell_decisions_sig = sig;
}

// countdown tick (1s, r4 G2-M4 + r3 finding 5 rules ii/iii): recompute
// ONLY the displayed strings; invalidate the rules rows region ONLY
// when a displayed string actually changed
static VOID _app_shell_countdowntick (_In_ HWND hwnd)
{
	RECT rows;
	BOOLEAN changed = FALSE;

	for (ULONG i = 0; i < shell_decisions_count; i++)
	{
		SHELL_DECISION_ROW *row = &shell_decisions[i];
		WCHAR text[48];
		ULONG rem;

		if (!row->expires)
			continue; // until-restart badge never ticks

		_app_shell_remainingtext (row->expires, text, RTL_NUMBER_OF (text), &rem);

		if (wcscmp (text, row->remaining) != 0)
		{
			_r_str_copy (row->remaining, RTL_NUMBER_OF (row->remaining), text);
			row->remaining_cached = rem;
			changed = TRUE;
		}
	}

	if (changed && shell_page == SHELL_PAGE_RULES)
	{
		_app_shell_listrowsrect (hwnd, &rows);
		InvalidateRect (hwnd, &rows, FALSE);
	}
}

// countdown timer lifecycle (r3 finding 5 rule ii): runs only while a
// countdown row is visible on the rules page
static VOID _app_shell_countdowntimer_update (_In_ HWND hwnd)
{
	BOOLEAN has_countdown = (shell_page == SHELL_PAGE_RULES);

	if (has_countdown)
	{
		for (ULONG i = 0; i < shell_decisions_count && has_countdown; i++)
		{
			if (!shell_decisions[i].expires)
				has_countdown = FALSE;
		}
	}

	if (has_countdown)
		SetTimer (hwnd, SHELL_TIMER_COUNTDOWN, SHELL_TIMER_COUNTDOWN_MS, NULL);
	else
		KillTimer (hwnd, SHELL_TIMER_COUNTDOWN);
}

// position the search edit + show/hide it per active page
static VOID _app_shell_layout (_In_ HWND hwnd)
{
	RECT rail;
	RECT content;
	LONG edit_left;

	_app_shell_frame (hwnd, &rail, &content);

	if (!shell_hwnd_search)
		return;

	if (shell_page != SHELL_PAGE_APPS)
	{
		ShowWindow (shell_hwnd_search, SW_HIDE);
		return;
	}

	ShowWindow (shell_hwnd_search, SW_SHOW);

	edit_left = shell_is_rtl ? (content.right - SHELL_SEARCH_W) : content.left;

	SetWindowPos (
		shell_hwnd_search,
		NULL,
		edit_left,
		content.top + SHELL_SEARCH_OFF,
		SHELL_SEARCH_W,
		SHELL_SEARCH_H,
		SWP_NOZORDER | SWP_NOACTIVATE
	);
}

static VOID _app_shell_drawapps (
	_In_ HWND hwnd,
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR fmt[SHELL_LINE_MAX];
	RECT rect;
	RECT rows;
	RECT card;
	RECT client;
	LONG y;
	LONG rows_height;
	ULONG first_visible;
	ULONG drawn = 0;

	_app_shell_pagetitle (hdc, content, IDS_SHELL_RAIL_APPS, 0);

	if (!GetClientRect (hwnd, &client))
		return;

	// summary chips (inline-start to inline-end: total, allowed,
	// blocked, prompt)
	y = content->top + SHELL_CHIPS_OFF;

	for (INT i = 0; i < 4; i++)
	{
		ULONG id;
		ULONG value;

		switch (i)
		{
			case 0:
			{
				id = IDS_SHELL_CHIP_TOTAL;
				value = shell_apps_total;
				break;
			}

			case 1:
			{
				id = IDS_SHELL_CHIP_ALLOWED;
				value = shell_apps_allowed;
				break;
			}

			case 2:
			{
				id = IDS_SHELL_CHIP_BLOCKED;
				value = shell_apps_blocked;
				break;
			}

			default:
			{
				id = IDS_SHELL_CHIP_PROMPT;
				value = shell_apps_prompt;
				break;
			}
		}

		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), id);
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, value);

		rect.top = y;
		rect.bottom = y + SHELL_CHIPS_H;

		if (shell_is_rtl)
		{
			rect.right = content->right - i * 160;
			rect.left = rect.right - 150;
		}
		else
		{
			rect.left = content->left + i * 160;
			rect.right = rect.left + 150;
		}

		_app_shell_drawchip (hdc, &rect, buffer);
	}

	_app_shell_appsrowsrect (hwnd, &rows);
	rows_height = rows.bottom - rows.top;

	if (shell_view_count == 0)
	{
		rect.left = rows.left;
		rect.right = rows.right;
		rect.top = rows.top;
		rect.bottom = rows.top + 60;

		_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

		_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), shell_filter[0] ? IDS_SHELL_SEARCH_NOHIT : IDS_SHELL_EMPTY_APPS);
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, shell_pal->muted, DT_CENTER | DT_VCENTER);
		return;
	}

	first_visible = (ULONG)(shell_scroll / SHELL_ROW_PITCH);
	y = rows.top - (shell_scroll % SHELL_ROW_PITCH);

	for (ULONG i = first_visible; i < shell_view_count; i++)
	{
		SHELL_APP_SNAPSHOT *snap = &shell_apps[shell_view[i]];
		WCHAR pill_text[SHELL_LINE_MAX];
		COLORREF pill_fg;
		COLORREF pill_bg;
		COLORREF pill_line;
		ULONG pill_id;

		card.left = rows.left;
		card.right = rows.right;
		card.top = y;
		card.bottom = y + SHELL_CARD_H;

		if (card.bottom > rows.bottom)
			break; // virtualized: render only the visible window

		_app_shell_fillround (hdc, &card, shell_pal->card, shell_pal->line, 10);

		// name + path (inline-end of the pill)
		rect.left = card.left + SHELL_MARGIN + SHELL_PILL_W;
		rect.right = card.right - SHELL_MARGIN;
		rect.top = card.top + 8;
		rect.bottom = rect.top + 22;

		_app_shell_drawtext (hdc, snap->name, &rect, shell_font_main, shell_pal->text, shell_is_rtl ? DT_RIGHT : DT_LEFT);

		rect.top = rect.bottom + 2;
		rect.bottom = rect.top + 18;
		_app_shell_drawtext (hdc, snap->path, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);

		// state pill (inline-start side under RTL, mirrored otherwise)
		if (shell_is_rtl)
		{
			rect.left = card.left + SHELL_MARGIN;
			rect.right = rect.left + SHELL_PILL_W;
		}
		else
		{
			rect.right = card.right - SHELL_MARGIN;
			rect.left = rect.right - SHELL_PILL_W;
		}

		rect.top = card.top + (SHELL_CARD_H - SHELL_PILL_H) / 2;
		rect.bottom = rect.top + SHELL_PILL_H;

		if (snap->state == 2)
		{
			pill_id = IDS_SHELL_PILL_PROMPT;
			pill_fg = shell_pal->warn;
			pill_bg = shell_pal->warnbg;
			pill_line = shell_pal->warnline;
		}
		else if (snap->state == 1)
		{
			pill_id = IDS_SHELL_PILL_ALLOW;
			pill_fg = shell_pal->ok;
			pill_bg = shell_pal->okbg;
			pill_line = shell_pal->okline;
		}
		else
		{
			pill_id = IDS_SHELL_PILL_BLOCK;
			pill_fg = shell_pal->danger;
			pill_bg = shell_pal->dangerbg;
			pill_line = shell_pal->dangerline;
		}

		_app_shell_locale (pill_text, RTL_NUMBER_OF (pill_text), pill_id);
		_app_shell_drawpill (hdc, &rect, pill_text, pill_fg, pill_bg, pill_line);

		y = card.bottom + SHELL_CARD_GAP;
		drawn++;
	}

	// honesty line (r3 verification: the virtualization is visible)
	if (shell_filter[0] || (LONG)((ULONG64)shell_view_count * SHELL_ROW_PITCH) > rows_height)
	{
		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_RENDERED);
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, (ULONG)(first_visible + drawn), shell_view_count);

		rect.left = content->left;
		rect.right = content->right;
		rect.top = client.bottom - SHELL_MARGIN - 18;
		rect.bottom = rect.top + 18;

		_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);
	}
}

static VOID _app_shell_drawrules (
	_In_ HWND hwnd,
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR fmt[SHELL_LINE_MAX];
	RECT rect;
	RECT rows;
	RECT card;
	LONG y;
	ULONG first_visible;
	ULONG total_rows;
	ULONG row_index;

	_app_shell_pagetitle (hdc, content, IDS_SHELL_RAIL_RULES, IDS_SHELL_RULES_SUB2);

	_app_shell_listrowsrect (hwnd, &rows);
	total_rows = _app_shell_rules_totalrows ();

	if (!total_rows)
		return;

	first_visible = (ULONG)(shell_scroll / SHELL_RULES_ROW_PITCH);
	y = rows.top - (shell_scroll % SHELL_RULES_ROW_PITCH);

	for (row_index = first_visible; row_index < total_rows; row_index++)
	{
		card.left = rows.left;
		card.right = rows.right;
		card.top = y;
		card.bottom = y + SHELL_RULES_ROW_PITCH;

		if (card.bottom > rows.bottom)
			break; // virtualized: render only the visible window

		rect = card;

		if (row_index == 0)
		{
			// section header: live session decisions (n) — the upstream
			// count-in-header pattern
			_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_SEC_SESSION);
			_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, shell_decisions_count);
			_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);
		}
		else if (row_index <= shell_decisions_count)
		{
			// session-decision row: verdict PILL (color + text always
			// paired, WCAG) at the inline-end, countdown chip at the
			// inline-start, name between
			SHELL_DECISION_ROW *row = &shell_decisions[row_index - 1];
			ULONG state_id = row->is_block ? IDS_SHELL_VERDICT_BLOCK : IDS_SHELL_VERDICT_ALLOW;
			COLORREF pill_fg = row->is_block ? shell_pal->danger : shell_pal->ok;
			COLORREF pill_bg = row->is_block ? shell_pal->dangerbg : shell_pal->okbg;
			COLORREF pill_line = row->is_block ? shell_pal->dangerline : shell_pal->okline;
			RECT pill;
			RECT chip;

			rect.top += 3;
			rect.bottom -= 3;

			_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 8);

			pill.top = rect.top + (rect.bottom - rect.top - SHELL_PILL_H) / 2;
			pill.bottom = pill.top + SHELL_PILL_H;

			if (shell_is_rtl)
			{
				pill.right = rect.right - SHELL_MARGIN;
				pill.left = pill.right - SHELL_PILL_W;
			}
			else
			{
				pill.left = rect.left + SHELL_MARGIN;
				pill.right = pill.left + SHELL_PILL_W;
			}

			_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), state_id);
			_app_shell_drawpill (hdc, &pill, buffer, pill_fg, pill_bg, pill_line);

			// countdown chip (inline-start); red under 10s (the
			// Authenticator urgency precedent)
			chip = pill;
			if (shell_is_rtl)
			{
				chip.left = rect.left + SHELL_MARGIN;
				chip.right = chip.left + 96;
			}
			else
			{
				chip.right = rect.right - SHELL_MARGIN;
				chip.left = chip.right - 96;
			}

			_app_shell_drawpill (hdc, &chip, row->remaining, row->expires && row->remaining_cached < 10 ? shell_pal->danger : shell_pal->muted, shell_pal->card, shell_pal->line);

			// name (between chip and pill)
			rect.left = shell_is_rtl ? (chip.right + 8) : (pill.right + 8);
			rect.right = shell_is_rtl ? (pill.left - 8) : (chip.left - 8);

			_app_shell_drawtext (hdc, row->name, &rect, shell_font_main, shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);
		}
		else if (row_index == shell_decisions_count + 1)
		{
			// section header: publisher anchors (n)
			_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_SEC_ANCHORS);
			_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, shell_anchors_count);
			_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);
		}
		else
		{
			// publisher-anchor row: "Verified publisher: X" (the UAC
			// vocabulary) + filters + 4-state pill (Valid / Invalid-red /
			// Not-checked-gray; staleness = contract-deferred, r3 f7)
			ULONG anchor_index = row_index - shell_decisions_count - 2;
			WCHAR aname[SHELL_LINE_MAX];
			WCHAR pub_line[SHELL_LINE_MAX];
			ULONG acount = 0;
			BOOLEAN aval = FALSE;
			ULONG pill_id;
			COLORREF pill_fg;
			COLORREF pill_bg;
			COLORREF pill_line;
			RECT pill;

			rect.top += 3;
			rect.bottom -= 3;

			_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 8);

			pill = rect;
			pill.top = rect.top + (rect.bottom - rect.top - SHELL_PILL_H) / 2;
			pill.bottom = pill.top + SHELL_PILL_H;

			if (shell_is_rtl)
			{
				pill.right = rect.right - SHELL_MARGIN;
				pill.left = pill.right - SHELL_PILL_W;
			}
			else
			{
				pill.left = rect.left + SHELL_MARGIN;
				pill.right = pill.left + SHELL_PILL_W;
			}

			if (_app_publisher_queryanchor (anchor_index, aname, RTL_NUMBER_OF (aname), &acount, &aval))
			{
				if (aname[0])
				{
					_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_ANCHOR_PUB);
					_r_str_printf (pub_line, RTL_NUMBER_OF (pub_line), fmt, aname);
				}
				else
				{
					_app_shell_locale (pub_line, RTL_NUMBER_OF (pub_line), IDS_SHELL_ANCHOR_PUB_UNKNOWN);
				}

				if (aval)
				{
					pill_id = IDS_SHELL_ANCHOR_VALID;
					pill_fg = shell_pal->ok;
					pill_bg = shell_pal->okbg;
					pill_line = shell_pal->okline;
				}
				else if (acount)
				{
					pill_id = IDS_SHELL_ANCHOR_INVALID;
					pill_fg = shell_pal->danger;
					pill_bg = shell_pal->dangerbg;
					pill_line = shell_pal->dangerline;
				}
				else
				{
					pill_id = IDS_SHELL_ANCHOR_UNKNOWN;
					pill_fg = shell_pal->muted;
					pill_bg = shell_pal->card;
					pill_line = shell_pal->line;
				}

				rect.left = shell_is_rtl ? rect.left : (pill.right + 8);
				rect.right = shell_is_rtl ? (pill.left - 8) : rect.right;

				_app_shell_drawtext (hdc, pub_line, &rect, shell_font_main, shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

				// filters count line (small, under the publisher line when
				// the row allows; drawn as trailing ellipsized text)
				_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_ANCHOR_FILTERS);
				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, acount);

				{
					RECT sub = rect;

					sub.top = rect.bottom - 16;
					sub.bottom = rect.bottom - 2;
					_app_shell_drawtext (hdc, buffer, &sub, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);
				}

				_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), pill_id);
				_app_shell_drawpill (hdc, &pill, buffer, pill_fg, pill_bg, pill_line);
			}
		}

		y += SHELL_RULES_ROW_PITCH;
	}
}

static VOID _app_shell_drawpacks (
	_In_ HWND hwnd,
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR fmt[SHELL_LINE_MAX];
	WCHAR pack_id[SHELL_NAME_MAX];
	WCHAR pack_version[32];
	WCHAR pill_text[SHELL_LINE_MAX];
	RECT rect;
	RECT pill;
	RECT client;
	ULONG count;
	ULONG drawn = 0;

	_app_shell_pagetitle (hdc, content, IDS_SHELL_RAIL_PACKS, IDS_SHELL_PACKS_SUB2);

	if (!GetClientRect (hwnd, &client))
		return;

	// the packstate sidecar IS the enabled set (r4 G2-M3): every row
	// passed hash-verify by construction; the pill wording says
	// "checksum ok" — tamper-EVIDENT store, ECDSA fired at import only
	// (r3 finding 8). Toggle + epoch/watermark + import wizard =
	// contract-deferred (r3 finding 9, page subtitle).
	count = _app_packs_querycount ();

	for (ULONG i = 0; i < count; i++)
	{
		BOOLEAN enabled = FALSE;

		if (!_app_packs_query (i, pack_id, RTL_NUMBER_OF (pack_id), pack_version, RTL_NUMBER_OF (pack_version), &enabled))
			break;

		rect.left = content->left;
		rect.right = content->right;
		rect.top = content->top + 60 + (LONG)i * (SHELL_CARD_H + SHELL_CARD_GAP);
		rect.bottom = rect.top + SHELL_CARD_H;

		if (rect.bottom > client.bottom - SHELL_MARGIN)
			break; // clip at the page bottom (count honesty line below)

		_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

		if (shell_is_rtl)
		{
			pill.left = rect.left + SHELL_MARGIN;
			pill.right = pill.left + SHELL_PILL_W + 24;
		}
		else
		{
			pill.right = rect.right - SHELL_MARGIN;
			pill.left = pill.right - SHELL_PILL_W - 24;
		}

		pill.top = rect.top + (SHELL_CARD_H - SHELL_PILL_H) / 2;
		pill.bottom = pill.top + SHELL_PILL_H;

		rect.left = shell_is_rtl ? (pill.right + SHELL_MARGIN) : rect.left;
		rect.right = shell_is_rtl ? rect.right : (pill.left - SHELL_MARGIN);
		rect.top += 8;
		rect.bottom = rect.top + 22;

		// pack name "(id)" — the Portmaster list-node pattern
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%s (%s)", pack_id, pack_version);
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, shell_pal->text, shell_is_rtl ? DT_RIGHT : DT_LEFT);

		rect.top = rect.bottom + 2;
		rect.bottom = rect.top + 18;

		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_PACKS_FILTERS);
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, _app_packs_queryfiltercount (i));
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);

		_app_shell_locale (pill_text, RTL_NUMBER_OF (pill_text), IDS_SHELL_PACKS_STORE);
		_app_shell_drawpill (hdc, &pill, pill_text, shell_pal->ok, shell_pal->okbg, shell_pal->okline);

		drawn++;
	}

	// count honesty line when the page clipped rows
	if (drawn < count)
	{
		_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_RENDERED);
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, drawn, count);

		rect.left = content->left + SHELL_MARGIN;
		rect.right = content->right - SHELL_MARGIN;
		rect.top = client.bottom - SHELL_MARGIN - 18;
		rect.bottom = rect.top + 18;
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);
	}
}

static VOID _app_shell_drawlockdown (
	_In_ HWND hwnd,
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	static const ULONG contract_ids[] = {
		IDS_SHELL_LDN_CONTRACT1,
		IDS_SHELL_LDN_CONTRACT2,
		IDS_SHELL_LDN_CONTRACT3,
		IDS_SHELL_LDN_CONTRACT4,
		IDS_SHELL_LDN_CONTRACT5,
	};
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR fmt[SHELL_LINE_MAX];
	WCHAR owned_text[SHELL_LINE_MAX];
	RECT rect;
	BOOLEAN is_active;

	is_active = _app_lockdown_isactive ();

	_app_shell_pagetitle (hdc, content, IDS_SHELL_RAIL_LOCKDOWN, IDS_SHELL_SUB_LOCKDOWN);

	// state line
	rect.left = content->left;
	rect.right = content->right;
	rect.top = content->top + 60;
	rect.bottom = rect.top + 44;
	_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

	_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), is_active ? IDS_SHELL_LDN_ACTIVE : IDS_SHELL_LDN_INACTIVE);

	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, is_active ? shell_pal->ok : shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

	// action button (inline-end side)
	if (shell_is_rtl)
	{
		shell_lockdown_btn.left = content->right - 220;
		shell_lockdown_btn.right = content->right;
	}
	else
	{
		shell_lockdown_btn.left = content->left;
		shell_lockdown_btn.right = content->left + 220;
	}

	shell_lockdown_btn.top = rect.bottom + SHELL_MARGIN;
	shell_lockdown_btn.bottom = shell_lockdown_btn.top + 40;

	if (is_active)
		_app_shell_fillround (hdc, &shell_lockdown_btn, shell_pal->dangerbg, shell_pal->dangerline, 8);
	else
		_app_shell_fillround (hdc, &shell_lockdown_btn, shell_pal->accent, shell_pal->accent, 8);

	_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), is_active ? IDS_SHELL_LDN_DISABLE : IDS_SHELL_LDN_ENABLE);
	_app_shell_drawtext (hdc, buffer, &shell_lockdown_btn, shell_font_main, is_active ? shell_pal->danger : shell_pal->accenttext, DT_CENTER | DT_VCENTER);

	// resolver ownership (read-only)
	rect.left = shell_is_rtl ? content->left : (shell_lockdown_btn.right + SHELL_MARGIN);
	rect.right = shell_is_rtl ? (shell_lockdown_btn.left - SHELL_MARGIN) : content->right;

	_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_LDN_RESOLVER);
	_app_shell_locale (owned_text, RTL_NUMBER_OF (owned_text), _app_resolver_isowned () ? IDS_SHELL_LDN_RESOLVER_OWNED : IDS_SHELL_LDN_RESOLVER_FREE);
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, owned_text);

	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, shell_pal->muted, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

	// safety contract (design r2)
	rect.left = content->left;
	rect.right = content->right;
	rect.top = shell_lockdown_btn.bottom + 16;
	rect.bottom = rect.top + 26;

	_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), IDS_SHELL_LDN_CONTRACT);
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, shell_pal->text, shell_is_rtl ? DT_RIGHT : DT_LEFT);

	for (ULONG i = 0; i < RTL_NUMBER_OF (contract_ids); i++)
	{
		rect.top = rect.bottom + 4;
		rect.bottom = rect.top + 22;

		_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), contract_ids[i]);
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);
	}
}

static VOID _app_shell_drawlog (
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR fmt[SHELL_LINE_MAX];
	WCHAR line[SHELL_LINE_MAX];
	RECT rect;
	ULONG held;
	ULONG foreign_count;
	BOOLEAN is_policy;
	BOOLEAN is_engine;

	held = _app_state_getheldtotal ();
	foreign_count = _app_ledger_querycount ();
	is_engine = _wfp_isfiltersinstalled ();

	_app_shell_pagetitle (hdc, content, IDS_SHELL_RAIL_LOG, 0);

	rect.left = content->left;
	rect.right = content->right;
	rect.top = content->top + 44;
	rect.bottom = rect.top + 44;
	_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

	_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_LOG_HELD);
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, held);

	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, held ? shell_pal->warn : shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

	rect.left = content->left;
	rect.right = content->right;
	rect.top = rect.bottom + SHELL_CARD_GAP;
	rect.bottom = rect.top + 44;
	_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

	_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_LOG_FOREIGN);
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, foreign_count);

	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, foreign_count ? shell_pal->warn : shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

	// honesty line: the live feed needs the engine (main path)
	rect.left = content->left + SHELL_MARGIN;
	rect.right = content->right - SHELL_MARGIN;
	rect.top = rect.bottom + SHELL_MARGIN;
	rect.bottom = rect.top + 22;

	_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), IDS_SHELL_LOG_ENGINE);
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, is_engine ? shell_pal->muted : shell_pal->warn, shell_is_rtl ? DT_RIGHT : DT_LEFT);

	// foreign ledger records (up to 10)
	for (ULONG i = 0; i < foreign_count && i < 10; i++)
	{
		if (!_app_ledger_queryforeign (i, buffer, SHELL_LINE_MAX, &is_policy))
			break;

		_r_str_printf (line, RTL_NUMBER_OF (line), L"%lu. %s%s", i + 1, buffer, is_policy ? L" (p)" : L"");

		rect.top = rect.bottom + 6;
		rect.bottom = rect.top + 20;
		_app_shell_drawtext (hdc, line, &rect, shell_font_small, shell_pal->text, shell_is_rtl ? DT_RIGHT : DT_LEFT);
	}
}

static VOID _app_shell_drawsettings (
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	struct
	{
		LPCWSTR key;
		ULONG label_id;
		BOOLEAN default_value;
	} gates[] = {
		{COMPOSITE_CONFIG_TIERS, IDS_SHELL_GATES_TIERS, TRUE},
		{COMPOSITE_CONFIG_SINGLEFLIGHT, IDS_SHELL_GATES_SINGLEFLIGHT, TRUE},
		{L"IsCompositeDnsAttributionEnabled", IDS_SHELL_GATES_DNS, FALSE},
		{L"IsCompositeLedgerEnabled", IDS_SHELL_GATES_LEDGER, FALSE},
	};
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR fmt[SHELL_LINE_MAX];
	RECT rect;
	RECT box;
	BOOLEAN value;
	BOOLEAN theme_value;

	_app_shell_pagetitle (hdc, content, IDS_SHELL_RAIL_SETTINGS, IDS_SHELL_SUB_SETTINGS);

	for (ULONG i = 0; i < RTL_NUMBER_OF (gates); i++)
	{
		value = _r_config_getboolean (gates[i].key, gates[i].default_value, NULL);

		rect.left = content->left;
		rect.right = content->right;
		rect.top = content->top + 60 + (LONG)i * 44;
		rect.bottom = rect.top + 36;
		shell_check_rects[i] = rect;

		_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

		// checkbox (owner-drawn; accent-filled when checked)
		if (shell_is_rtl)
		{
			box.left = rect.right - SHELL_MARGIN - SHELL_CHECKBOX_SIZE;
		}
		else
		{
			box.left = rect.left + SHELL_MARGIN;
		}

		box.right = box.left + SHELL_CHECKBOX_SIZE;
		box.top = rect.top + (36 - SHELL_CHECKBOX_SIZE) / 2;
		box.bottom = box.top + SHELL_CHECKBOX_SIZE;

		if (value)
			_app_shell_fillround (hdc, &box, shell_pal->accent, shell_pal->accent, 4);
		else
			_app_shell_fillround (hdc, &box, shell_pal->bg, shell_pal->line, 4);

		if (value)
			_app_shell_drawtext (hdc, L"\x2713", &box, shell_font_small, shell_pal->accenttext, DT_CENTER | DT_VCENTER);

		rect.left = shell_is_rtl ? (rect.left + SHELL_MARGIN) : (box.right + 10);
		rect.right = shell_is_rtl ? (box.left - 10) : (rect.right - SHELL_MARGIN);

		_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), gates[i].label_id);
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);
	}

	// owner-selectable theme (DEC-11 §2; r3 G1-M1)
	theme_value = _r_config_getlong (L"IsShellLightTheme", -1, NULL) == 1;

	rect.left = content->left;
	rect.right = content->right;
	rect.top = content->top + 60 + 4 * 44;
	rect.bottom = rect.top + 36;
	shell_check_rects[4] = rect;

	_app_shell_fillround (hdc, &rect, shell_pal->card, shell_pal->line, 10);

	if (shell_is_rtl)
	{
		box.left = rect.right - SHELL_MARGIN - SHELL_CHECKBOX_SIZE;
	}
	else
	{
		box.left = rect.left + SHELL_MARGIN;
	}

	box.right = box.left + SHELL_CHECKBOX_SIZE;
	box.top = rect.top + (36 - SHELL_CHECKBOX_SIZE) / 2;
	box.bottom = box.top + SHELL_CHECKBOX_SIZE;

	if (theme_value)
		_app_shell_fillround (hdc, &box, shell_pal->accent, shell_pal->accent, 4);
	else
		_app_shell_fillround (hdc, &box, shell_pal->bg, shell_pal->line, 4);

	if (theme_value)
		_app_shell_drawtext (hdc, L"\x2713", &box, shell_font_small, shell_pal->accenttext, DT_CENTER | DT_VCENTER);

	rect.left = shell_is_rtl ? (rect.left + SHELL_MARGIN) : (box.right + 10);
	rect.right = shell_is_rtl ? (box.left - 10) : (rect.right - SHELL_MARGIN);

	_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), IDS_SHELL_THEME_LIGHT);
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, shell_pal->text, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

	// footprint chip (r2 §2 budget; M1 asserts the hidden-window state —
	// the tray surface itself follows design r2 §8 in M3)
	_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_FOOTPRINT);
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), fmt, (ULONG)16);

	rect.left = content->left + SHELL_MARGIN;
	rect.right = content->right - SHELL_MARGIN;
	rect.top = shell_check_rects[4].bottom + SHELL_MARGIN;
	rect.bottom = rect.top + 22;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, shell_pal->muted, shell_is_rtl ? DT_RIGHT : DT_LEFT);
}

static VOID _app_shell_drawrail (
	_In_ HWND hwnd,
	_In_ HDC hdc
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	RECT rail;
	RECT rect;
	RECT bar;

	_app_shell_frame (hwnd, &rail, &bar); // bar reused as client sink here

	_app_shell_fillrect (hdc, &rail, shell_pal->rail);

	// separator (inline-end edge of the rail)
	{
		RECT sep;

		sep.left = shell_is_rtl ? (rail.left - 1) : rail.right;
		sep.right = sep.left + 1;
		sep.top = 0;
		sep.bottom = rail.bottom;
		_app_shell_fillrect (hdc, &sep, shell_pal->line);
	}

	for (INT i = 0; i < SHELL_PAGE_MAX; i++)
	{
		RECT item;

		item.left = rail.left + 12;
		item.right = rail.right - 12;
		item.top = 20 + i * 44;
		item.bottom = item.top + 36;
		shell_rail_rects[i] = item;

		if (i == shell_page)
		{
			_app_shell_fillround (hdc, &item, shell_pal->card, shell_pal->line, 8);

			// accent bar on the inline-end edge (RTL: right)
			bar.left = shell_is_rtl ? (item.right - 3) : item.left;
			bar.right = bar.left + 3;
			bar.top = item.top + 6;
			bar.bottom = item.bottom - 6;
			_app_shell_fillrect (hdc, &bar, shell_pal->accent);
		}

		rect = item;
		rect.left += 10;
		rect.right -= 10;

		_app_shell_locale (buffer, RTL_NUMBER_OF (buffer), shell_rail_ids[i]);
		_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, i == shell_page ? shell_pal->text : shell_pal->muted, (shell_is_rtl ? DT_RIGHT : DT_LEFT) | DT_VCENTER);

		// keyboard focus indicator (r3 G1-M5/G1-M6)
		if (shell_input_kbd && i == shell_rail_focus)
			DrawFocusRect (hdc, &item);
	}
}

static VOID _app_shell_paintclient (
	_In_ HWND hwnd,
	_In_ HDC hdc
)
{
	RECT rail;
	RECT content;
	RECT body;
	RECT client;

	_app_shell_frame (hwnd, &rail, &content);

	// content background covers the whole non-rail client (margins too)
	if (GetClientRect (hwnd, &client))
	{
		body.left = shell_is_rtl ? client.left : rail.right;
		body.right = shell_is_rtl ? rail.left : client.right;
		body.top = 0;
		body.bottom = client.bottom;
		_app_shell_fillrect (hdc, &body, shell_pal->bg);
	}

	_app_shell_drawrail (hwnd, hdc);

	switch (shell_page)
	{
		case SHELL_PAGE_APPS:
		{
			_app_shell_drawapps (hwnd, hdc, &content);
			break;
		}

		case SHELL_PAGE_RULES:
		{
			_app_shell_drawrules (hwnd, hdc, &content);
			break;
		}

		case SHELL_PAGE_PACKS:
		{
			_app_shell_drawpacks (hwnd, hdc, &content);
			break;
		}

		case SHELL_PAGE_LOCKDOWN:
		{
			_app_shell_drawlockdown (hwnd, hdc, &content);
			break;
		}

		case SHELL_PAGE_LOG:
		{
			_app_shell_drawlog (hdc, &content);
			break;
		}

		case SHELL_PAGE_SETTINGS:
		{
			_app_shell_drawsettings (hdc, &content);
			break;
		}
	}
}

// custom-drawn scrollbar (r3 G1-M2): native WS_VSCROLL rejected for the
// light-scrollbar dark-mode pitfall (the Explorer::ScrollBar re-theme is
// an undocumented self-theme — same rejection family as the IAT hook)
static VOID _app_shell_drawscrollbar (
	_In_ HWND hwnd,
	_In_ HDC hdc
)
{
	RECT rail;
	RECT content;
	RECT rows;
	LONG rows_height;
	LONG total_height;
	LONG scrollmax;
	LONG thumb_h;
	LONG track_h;

	if (shell_page != SHELL_PAGE_APPS && shell_page != SHELL_PAGE_RULES)
		return;

	if ((shell_page == SHELL_PAGE_APPS && shell_view_count == 0) || (shell_page == SHELL_PAGE_RULES && shell_decisions_count == 0 && shell_anchors_count == 0))
		return;

	_app_shell_frame (hwnd, &rail, &content);
	_app_shell_listrowsrect (hwnd, &rows);

	rows_height = rows.bottom - rows.top;
	total_height = (shell_page == SHELL_PAGE_RULES)
		? (LONG)_app_shell_rules_totalrows () * SHELL_RULES_ROW_PITCH
		: (LONG)shell_view_count * SHELL_ROW_PITCH;
	scrollmax = _app_shell_scrollmax (hwnd);

	// strip (inline-start under RTL)
	shell_scrollbar_rect.top = rows.top;
	shell_scrollbar_rect.bottom = rows.bottom;

	if (shell_is_rtl)
	{
		shell_scrollbar_rect.left = content.left;
		shell_scrollbar_rect.right = content.left + SHELL_SCROLLBAR_W;
	}
	else
	{
		shell_scrollbar_rect.right = content.right;
		shell_scrollbar_rect.left = shell_scrollbar_rect.right - SHELL_SCROLLBAR_W;
	}

	_app_shell_fillround (hdc, &shell_scrollbar_rect, shell_pal->rail, shell_pal->line, 4);

	if (scrollmax <= 0)
		return;

	track_h = rows_height - 8;
	thumb_h = max (24, MulDiv (rows_height, rows_height, total_height));
	thumb_h = min (thumb_h, track_h);

	shell_scrollbar_thumb.left = shell_scrollbar_rect.left + 1;
	shell_scrollbar_thumb.right = shell_scrollbar_rect.right - 1;
	shell_scrollbar_thumb.top = rows.top + 4 + (LONG)((LONG64)shell_scroll * (track_h - thumb_h) / scrollmax);
	shell_scrollbar_thumb.bottom = shell_scrollbar_thumb.top + thumb_h;

	_app_shell_fillround (hdc, &shell_scrollbar_thumb, shell_pal->line, shell_pal->line, 3);
}

static VOID _app_shell_paint (
	_In_ HWND hwnd,
	_In_ HDC hdc
)
{
	_app_shell_paintclient (hwnd, hdc);
	_app_shell_drawscrollbar (hwnd, hdc);
}

static VOID _app_shell_selectpage (
	_In_ HWND hwnd,
	_In_ INT page
)
{
	if (page < 0 || page >= SHELL_PAGE_MAX)
		return;

	if (shell_page != page)
	{
		shell_page = page;
		shell_rail_focus = page;
		shell_scroll = 0;
		_app_shell_layout (hwnd);
		_app_shell_countdowntimer_update (hwnd); // r3 finding 5 rule ii: kill on page-leave
		InvalidateRect (hwnd, NULL, TRUE);
	}
}

// DEC-04 verify-then-commit on the UI surface (r3 G1-M5, goldfish
// finding 3): the pre-flight outcome is computed and SHOWN in the
// confirm dialog BEFORE the commit call; is_confirmed=TRUE is passed
// only after the owner has seen and accepted the specific outcome.
static VOID _app_shell_applylockdown (
	_In_ HWND hwnd,
	_In_ BOOLEAN is_enable
)
{
	WCHAR pf_line[256];
	WCHAR pf_fmt[256];
	WCHAR l1[SHELL_LINE_MAX];
	WCHAR l2[SHELL_LINE_MAX];
	WCHAR q[SHELL_LINE_MAX];
	WCHAR title[SHELL_LINE_MAX];
	WCHAR err[SHELL_LINE_MAX];
	WCHAR text[SHELL_TEXT_MAX];
	NTSTATUS pfstatus;
	NTSTATUS status;

	pfstatus = (NTSTATUS)0;

	if (is_enable)
	{
		pfstatus = _app_lockdown_preflight ();

		_app_shell_locale (pf_fmt, RTL_NUMBER_OF (pf_fmt), NT_SUCCESS (pfstatus) ? IDS_SHELL_LDN_PF_OK : IDS_SHELL_LDN_PF_FAIL);
		_r_str_printf (pf_line, RTL_NUMBER_OF (pf_line), pf_fmt, (ULONG)pfstatus);

		_app_shell_locale (l1, RTL_NUMBER_OF (l1), IDS_SHELL_LDN_CONFIRM_EN1);
		_app_shell_locale (l2, RTL_NUMBER_OF (l2), IDS_SHELL_LDN_CONFIRM_EN2);
		_r_str_printf (text, RTL_NUMBER_OF (text), L"%s\r\n%s\r\n%s\r\n\r\n%s", l1, l2, pf_line, L"");
	}
	else
	{
		_app_shell_locale (l1, RTL_NUMBER_OF (l1), IDS_SHELL_LDN_CONFIRM_DIS1);
		_r_str_printf (text, RTL_NUMBER_OF (text), L"%s", l1);
	}

	_app_shell_locale (q, RTL_NUMBER_OF (q), IDS_SHELL_LDN_CONFIRM_Q);
	_r_str_printf (text, RTL_NUMBER_OF (text), L"%s\r\n\r\n%s", text, q);

	_app_shell_locale (title, RTL_NUMBER_OF (title), IDS_SHELL_LDN_TITLE);

	// safe default = No (most secure response, MS UX-Guide)
	if (MessageBoxW (hwnd, text, title, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_RTLREADING | MB_SETFOREGROUND) != IDYES)
		return;

	status = is_enable ? _app_lockdown_enable (TRUE) : _app_lockdown_disable ();

	if (!NT_SUCCESS (status))
	{
		_app_shell_locale (err, RTL_NUMBER_OF (err), IDS_SHELL_LDN_ERROR);
		_app_shell_locale (title, RTL_NUMBER_OF (title), IDS_SHELL_RAIL_LOCKDOWN);
		MessageBoxW (hwnd, err, title, MB_OK | MB_ICONERROR | MB_RTLREADING);
	}

	InvalidateRect (hwnd, NULL, TRUE);
}

static VOID _app_shell_onclick (
	_In_ HWND hwnd,
	_In_ LONG x,
	_In_ LONG y
)
{
	POINT pt = {x, y};

	shell_input_kbd = FALSE;

	for (INT i = 0; i < SHELL_PAGE_MAX; i++)
	{
		if (PtInRect (&shell_rail_rects[i], pt))
		{
			_app_shell_selectpage (hwnd, i);
			return;
		}
	}

	if ((shell_page == SHELL_PAGE_APPS && shell_view_count) || (shell_page == SHELL_PAGE_RULES && _app_shell_rules_totalrows ()))
	{
		RECT rows;
		LONG total_height = (shell_page == SHELL_PAGE_RULES)
			? (LONG)_app_shell_rules_totalrows () * SHELL_RULES_ROW_PITCH
			: (LONG)shell_view_count * SHELL_ROW_PITCH;

		_app_shell_listrowsrect (hwnd, &rows);

		// scrollbar: thumb grab or track jump
		if (PtInRect (&shell_scrollbar_rect, pt))
		{
			LONG scrollmax = _app_shell_scrollmax (hwnd);
			LONG rows_height = rows.bottom - rows.top;
			LONG track_h = rows_height - 8;
			LONG thumb_h = max (24, MulDiv (rows_height, rows_height, total_height));

			if (scrollmax > 0)
			{
				thumb_h = min (thumb_h, track_h);

				if (PtInRect (&shell_scrollbar_thumb, pt))
				{
					shell_scrollbar_drag = TRUE;
					shell_scrollbar_drag_off = pt.y - shell_scrollbar_thumb.top;
					SetCapture (hwnd);
				}
				else
				{
					LONG rel = pt.y - (rows.top + 4);

					shell_scroll = (LONG)((LONG64)max (0, rel - thumb_h / 2) * scrollmax / (track_h - thumb_h));
					_app_shell_scrollclamp (hwnd);
					InvalidateRect (hwnd, NULL, FALSE);
				}
			}

			return;
		}
	}

	if (shell_page == SHELL_PAGE_LOCKDOWN && PtInRect (&shell_lockdown_btn, pt))
	{
		_app_shell_applylockdown (hwnd, !_app_lockdown_isactive ());
		return;
	}

	if (shell_page == SHELL_PAGE_SETTINGS)
	{
		static const LPCWSTR keys[] = {
			COMPOSITE_CONFIG_TIERS,
			COMPOSITE_CONFIG_SINGLEFLIGHT,
			L"IsCompositeDnsAttributionEnabled",
			L"IsCompositeLedgerEnabled",
		};
		static const BOOLEAN defaults[] = {TRUE, TRUE, FALSE, FALSE};

		for (ULONG j = 0; j < RTL_NUMBER_OF (keys); j++)
		{
			if (PtInRect (&shell_check_rects[j], pt))
			{
				_r_config_setboolean (keys[j], !_r_config_getboolean (keys[j], defaults[j], NULL), NULL);
				InvalidateRect (hwnd, NULL, TRUE);
				return;
			}
		}

		// theme row (DEC-11 owner-selectable; r3 G1-M1)
		if (PtInRect (&shell_check_rects[4], pt))
		{
			LONG current = _r_config_getlong (L"IsShellLightTheme", -1, NULL);
			LONG next = (current == 1) ? 0 : 1;

			_r_config_setlong (L"IsShellLightTheme", next, NULL);
			_app_shell_themeapply (hwnd);
			return;
		}
	}
}

static VOID _app_shell_onkeydown (
	_In_ HWND hwnd,
	_In_ ULONG key
)
{
	shell_input_kbd = TRUE;

	switch (key)
	{
		case VK_DOWN:
		{
			shell_rail_focus = (shell_rail_focus + 1) % SHELL_PAGE_MAX;
			InvalidateRect (hwnd, NULL, FALSE);
			break;
		}

		case VK_UP:
		{
			shell_rail_focus = (shell_rail_focus + SHELL_PAGE_MAX - 1) % SHELL_PAGE_MAX;
			InvalidateRect (hwnd, NULL, FALSE);
			break;
		}

		case VK_RETURN:
		{
			_app_shell_selectpage (hwnd, shell_rail_focus);
			break;
		}

		case VK_NEXT:
		{
			if (shell_page == SHELL_PAGE_APPS || shell_page == SHELL_PAGE_RULES)
				_app_shell_scrollby (hwnd, _app_shell_pagedelta (hwnd));

			break;
		}

		case VK_PRIOR:
		{
			if (shell_page == SHELL_PAGE_APPS || shell_page == SHELL_PAGE_RULES)
				_app_shell_scrollby (hwnd, -_app_shell_pagedelta (hwnd));

			break;
		}

		case VK_HOME:
		{
			if (shell_page == SHELL_PAGE_APPS || shell_page == SHELL_PAGE_RULES)
			{
				shell_scroll = 0;
				InvalidateRect (hwnd, NULL, FALSE);
			}

			break;
		}

		case VK_END:
		{
			if (shell_page == SHELL_PAGE_APPS || shell_page == SHELL_PAGE_RULES)
			{
				shell_scroll = _app_shell_scrollmax (hwnd);
				InvalidateRect (hwnd, NULL, FALSE);
			}

			break;
		}
	}
}

// ---- a11y bridge helpers (G1-M6; consumed by composite_shell_a11y.c)

// child ids: 1..6 rail entries, 7..6+shell_view_count rendered cards
BOOLEAN _app_shell_a11ychild (
	_In_ ULONG child_id,
	_Out_ WCHAR *name,
	_In_ ULONG cch,
	_Out_ RECT *rect,
	_Out_ LONG *role,
	_Out_ LONG *state
)
{
	HWND hwnd;
	RECT rows;
	ULONG card_index;
	ULONG snap_index;
	SHELL_APP_SNAPSHOT *snap;

	if (!child_id)
		return FALSE;

	hwnd = _r_app_gethwnd ();

	if (!hwnd)
		return FALSE;

	if (child_id <= (ULONG)SHELL_PAGE_MAX)
	{
		ULONG rail_index = child_id - 1;

		if (!shell_rail_rects[rail_index].right && !shell_rail_rects[rail_index].left)
			return FALSE;

		_app_shell_locale (name, cch, shell_rail_ids[rail_index]);

		*rect = shell_rail_rects[rail_index];
		*role = 0x25; // ROLE_SYSTEM_PAGETAB
		*state = 0x100000 | 0x200000; // FOCUSABLE | SELECTABLE

		if ((ULONG)shell_page == rail_index)
			*state |= 0x2 | 0x4; // SELECTED | FOCUSED

		return TRUE;
	}

	// card
	// rules page: children are the section headers + decision rows +
	// anchor rows (r4 G2-M6: every row type exposes a humanized name)
	if (shell_page == SHELL_PAGE_RULES)
	{
		WCHAR fmt[SHELL_LINE_MAX];
		WCHAR part[SHELL_LINE_MAX];
		ULONG row_index = child_id - (ULONG)SHELL_PAGE_MAX - 1;
		ULONG total = _app_shell_rules_totalrows ();

		if (row_index >= total)
			return FALSE;

		_app_shell_listrowsrect (hwnd, &rows);

		rect->left = rows.left;
		rect->right = rows.right;
		rect->top = rows.top + (LONG)(row_index * SHELL_RULES_ROW_PITCH) - shell_scroll;
		rect->bottom = rect->top + SHELL_RULES_ROW_PITCH;
		*state = 0; // headers are not focusable

		if (row_index == 0)
		{
			_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_SEC_SESSION);
			_r_str_printf (name, cch, fmt, shell_decisions_count);
			*role = 0x2C; // ROLE_SYSTEM_STATICTEXT
			return TRUE;
		}

		if (row_index <= shell_decisions_count)
		{
			SHELL_DECISION_ROW *row = &shell_decisions[row_index - 1];

			_app_shell_locale (part, RTL_NUMBER_OF (part), row->is_block ? IDS_SHELL_VERDICT_BLOCK : IDS_SHELL_VERDICT_ALLOW);
			_r_str_printf (name, cch, L"%s — %s — %s", part, row->name, row->remaining);
			*role = 0x22; // ROLE_SYSTEM_LISTITEM
			*state = 0x100000 | 0x200000; // FOCUSABLE | SELECTABLE
			return TRUE;
		}

		if (row_index == shell_decisions_count + 1)
		{
			_app_shell_locale (fmt, RTL_NUMBER_OF (fmt), IDS_SHELL_SEC_ANCHORS);
			_r_str_printf (name, cch, fmt, shell_anchors_count);
			*role = 0x2C; // ROLE_SYSTEM_STATICTEXT
			return TRUE;
		}

		{
			ULONG anchor_index = row_index - shell_decisions_count - 2;
			WCHAR aname[SHELL_LINE_MAX];
			ULONG acount = 0;
			BOOLEAN aval = FALSE;

			if (!_app_publisher_queryanchor (anchor_index, aname, RTL_NUMBER_OF (aname), &acount, &aval))
				return FALSE;

			_app_shell_locale (part, RTL_NUMBER_OF (part), aval ? IDS_SHELL_ANCHOR_VALID : (acount ? IDS_SHELL_ANCHOR_INVALID : IDS_SHELL_ANCHOR_UNKNOWN));

			if (aname[0])
				_r_str_printf (name, cch, L"%s — %s (%lu)", part, aname, acount);
			else
				_r_str_printf (name, cch, L"%s — %s (%lu)", part, L"?", acount);

			*role = 0x22; // ROLE_SYSTEM_LISTITEM
			*state = 0x100000 | 0x200000; // FOCUSABLE | SELECTABLE
			return TRUE;
		}
	}

	card_index = child_id - (ULONG)SHELL_PAGE_MAX - 1;

	if (card_index >= shell_view_count)
		return FALSE;

	snap_index = shell_view[card_index];

	if (snap_index >= shell_apps_count)
		return FALSE;

	snap = &shell_apps[snap_index];

	// card name = "app — state" (locale pills; separate buffers, no
	// aliasing between source and destination)
	{
		WCHAR state_word[SHELL_LINE_MAX];
		ULONG state_id = snap->state == 2 ? IDS_SHELL_PILL_PROMPT : (snap->state == 1 ? IDS_SHELL_PILL_ALLOW : IDS_SHELL_PILL_BLOCK);

		_app_shell_locale (state_word, RTL_NUMBER_OF (state_word), state_id);
		_r_str_printf (name, cch, L"%s — %s", snap->name, state_word);
	}

	_app_shell_appsrowsrect (hwnd, &rows);

	rect->left = rows.left;
	rect->right = rows.right;
	rect->top = rows.top + (LONG)(card_index * SHELL_ROW_PITCH) - shell_scroll;
	rect->bottom = rect->top + SHELL_CARD_H;

	*role = 0x22; // ROLE_SYSTEM_LISTITEM
	*state = 0x100000 | 0x200000; // FOCUSABLE | SELECTABLE

	if (rect->top < rows.top || rect->bottom > rows.bottom)
		*state |= 0x10000; // OFFSCREEN

	return TRUE;
}

VOID _app_shell_a11yselectpage (
	_In_ HWND hwnd,
	_In_ ULONG rail_index
)
{
	_app_shell_selectpage (hwnd, (INT)rail_index);
}

ULONG _app_shell_a11ychildcount (VOID)
{
	if (shell_page == SHELL_PAGE_RULES)
		return (ULONG)SHELL_PAGE_MAX + _app_shell_rules_totalrows ();

	return (ULONG)SHELL_PAGE_MAX + shell_view_count;
}

ULONG _app_shell_a11yfocuspage (VOID)
{
	return (ULONG)shell_page;
}

static LRESULT CALLBACK _app_shell_wndproc (
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
)
{
	switch (msg)
	{
		case WM_CREATE:
		{
			HDC hdc;
			WCHAR cue[SHELL_LINE_MAX];
			WCHAR title[SHELL_LINE_MAX];

			// populate apps_table from the profile (the shell replaces the
			// main window, so the upstream WM_INITDIALOG load never runs)
			// fix (2026-11-18, 4-dump crash): profile_info paths were empty
			// stringrefs without the profile load (AV 0xC0000005 at
			// _r_fs_dospathnametontpathname+0x233, dumps
			// simplewall-1794961299..422); the post-init -gui dispatch (r3
			// G1-M4) guarantees locale/config are initialized BEFORE we get
			// here, so localized strings resolve on fresh profiles too
			_app_profile_initialize ();
			_app_profile_load (NULL, NULL);

			hdc = GetDC (hwnd);

			_app_shell_fonts_create (hdc ? GetDeviceCaps (hdc, LOGPIXELSY) : 96);

			if (hdc)
				ReleaseDC (hwnd, hdc);

			_r_app_sethwnd (hwnd);

			// window title through the locale pipeline (G1-M4)
			_app_shell_locale (title, RTL_NUMBER_OF (title), IDS_SHELL_WINDOWTITLE);
			SetWindowTextW (hwnd, title);

			// global search box (DEC-11 §1; shell-global from M1 — the
			// filter binds to the Apps page while it is the only content
			// page; per-page semantics extend with G-2/G-3)
			shell_hwnd_search = CreateWindowExW (
				0,
				L"EDIT",
				NULL,
				WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
				0,
				0,
				0,
				0,
				hwnd,
				(HMENU)(INT_PTR)SHELL_ID_SEARCH,
				NULL,
				NULL
			);

			if (shell_hwnd_search)
			{
				_app_shell_locale (cue, RTL_NUMBER_OF (cue), IDS_SHELL_SEARCH_CUE);
				SendMessageW (shell_hwnd_search, WM_SETFONT, (WPARAM)shell_font_main, TRUE);
				SendMessageW (shell_hwnd_search, EM_SETCUEBANNER, TRUE, (LPARAM)cue);
			}

			_app_shell_themeapply (hwnd);
			_app_shell_layout (hwnd);

			_app_shell_snapshot ();
			_app_shell_applyfilter ();

			_app_shell_rulesrefresh (NULL); // r4 G2-M2: decisions + anchors initial snapshot
			_app_shell_countdowntimer_update (hwnd);

			SetTimer (hwnd, SHELL_TIMER_REFRESH, SHELL_TIMER_REFRESH_MS, NULL);

			return 0;
		}

		case WM_SETTINGCHANGE:
		case WM_THEMECHANGED:
		{
			// system theme changed: re-evaluate only when the owner has no
			// explicit choice (r3 G1-M1 auto-detect)
			if (_r_config_getlong (L"IsShellLightTheme", -1, NULL) == -1)
				_app_shell_themeapply (hwnd);

			return 0;
		}

		case WM_DPICHANGED:
		{
			// per-monitor DPI (DEC-11 §2; the r3 G1-M1 awareness
			// prerequisite makes this message actually arrive): recreate
			// the fonts at the new dpi + adopt the suggested rect
			LPRECT suggested = (LPRECT)lparam;
			LONG dpi = HIWORD (wparam);

			_app_shell_fonts_create (dpi);

			if (suggested)
				SetWindowPos (hwnd, NULL, suggested->left, suggested->top, suggested->right - suggested->left, suggested->bottom - suggested->top, SWP_NOZORDER | SWP_NOACTIVATE);

			_app_shell_layout (hwnd);
			InvalidateRect (hwnd, NULL, TRUE);
			return 0;
		}

		case WM_SIZE:
		{
			_app_shell_layout (hwnd);
			_app_shell_scrollclamp (hwnd);
			InvalidateRect (hwnd, NULL, FALSE);
			return 0;
		}

		case WM_COMMAND:
		{
			// search-as-you-type → debounced filter rebuild (System
			// Informer SearchDelayMs precedent; r3 verification: typing
			// 10 chars issues ONE rebuild)
			if (LOWORD (wparam) == SHELL_ID_SEARCH && HIWORD (wparam) == EN_CHANGE)
			{
				SetTimer (hwnd, SHELL_TIMER_FILTER, SHELL_TIMER_FILTER_MS, NULL);
				return 0;
			}

			break;
		}

			case WM_TIMER:
			{
				if (wparam == SHELL_TIMER_REFRESH)
				{
					BOOLEAN rules_changed = FALSE;

					// cheap refresh: re-snapshot; invalidate ONLY on change
					// (r3 G1-M2 idle discipline — no repaints while the
					// profile is untouched)
					if (_app_shell_snapshot ())
					{
						_app_shell_applyfilter ();
						_app_shell_scrollclamp (hwnd);
						InvalidateRect (hwnd, NULL, FALSE);
					}

					// rules page data (r4 G2-M2): decisions + anchors via
					// the module query APIs; the countdown text is NOT
					// part of the change signature (r3 finding 5 rule i)
					_app_shell_rulesrefresh (&rules_changed);

					if (rules_changed)
					{
						_app_shell_scrollclamp (hwnd);
						InvalidateRect (hwnd, NULL, FALSE);
					}

					_app_shell_countdowntimer_update (hwnd);

					return 0;
				}

				if (wparam == SHELL_TIMER_COUNTDOWN)
				{
					// 1s tick (r4 G2-M4): recompute displayed strings only;
					// invalidate the rules rows region only when a string
					// changed
					_app_shell_countdowntick (hwnd);
					return 0;
				}

				if (wparam == SHELL_TIMER_FILTER)
				{
					WCHAR filter[SHELL_FILTER_MAX];

					KillTimer (hwnd, SHELL_TIMER_FILTER);

					if (shell_hwnd_search)
					{
						GetWindowTextW (shell_hwnd_search, filter, RTL_NUMBER_OF (filter));
						_r_str_copy (shell_filter, RTL_NUMBER_OF (shell_filter), filter);
					}
					else
					{
						shell_filter[0] = UNICODE_NULL;
					}

					_app_shell_applyfilter ();
					shell_scroll = 0;
					InvalidateRect (hwnd, NULL, FALSE);
					return 0;
				}

				break;
			}

			case WM_MOUSEWHEEL:
			{
				if (shell_page == SHELL_PAGE_APPS || shell_page == SHELL_PAGE_RULES)
				{
					LONG delta = (LONG)(SHORT)HIWORD (wparam);
					LONG pitch = (shell_page == SHELL_PAGE_RULES) ? SHELL_RULES_ROW_PITCH : SHELL_ROW_PITCH;

					_app_shell_scrollby (hwnd, -(delta / WHEEL_DELTA) * pitch);
				}

				return 0;
			}

		case WM_KEYDOWN:
		{
			_app_shell_onkeydown (hwnd, (ULONG)wparam);
			return 0;
		}

			case WM_MOUSEMOVE:
			{
				if (shell_scrollbar_drag && GetCapture () == hwnd)
				{
					RECT rows;
					POINT pt = {(LONG)(SHORT)LOWORD (lparam), (LONG)(SHORT)HIWORD (lparam)};
					LONG scrollmax = _app_shell_scrollmax (hwnd);
					LONG track_h;
					LONG thumb_h;

					if (scrollmax > 0)
					{
						_app_shell_listrowsrect (hwnd, &rows);

					track_h = (rows.bottom - rows.top) - 8;
					thumb_h = shell_scrollbar_thumb.bottom - shell_scrollbar_thumb.top;

					shell_scroll = (LONG)((LONG64)(pt.y - rows.top - 4 - shell_scrollbar_drag_off) * scrollmax / max (1, track_h - thumb_h));
					_app_shell_scrollclamp (hwnd);
					InvalidateRect (hwnd, NULL, FALSE);
				}

				return 0;
			}

			break;
		}

		case WM_LBUTTONUP:
		{
			if (shell_scrollbar_drag)
			{
				shell_scrollbar_drag = FALSE;
				ReleaseCapture ();
				return 0;
			}

			break;
		}

		case WM_LBUTTONDOWN:
		{
			SetFocus (hwnd);
			_app_shell_onclick (hwnd, (LONG)(SHORT)LOWORD (lparam), (LONG)(SHORT)HIWORD (lparam));
			return 0;
		}

		case WM_GETOBJECT:
		{
			// basic MSAA labels (r3 G1-M6: the approved M1 accessibility
			// line; the full audit stays a later milestone per design r2)
			if ((LONG)lparam == OBJID_CLIENT)
				return _app_shell_a11y_getobject (hwnd, wparam, lparam);

			break;
		}

		case WM_ERASEBKGND:
		{
			return 1;
		}

		case WM_PAINT:
		{
			PAINTSTRUCT ps;
			HDC hdc_target;
			HPAINTBUFFER_SHELL pb;

			if (!BeginPaint (hwnd, &ps))
				return 0;

			hdc_target = ps.hdc;
			pb = 0;

			// double-buffer through the documented uxtheme API (r3 G1-M1:
			// kills the direct-paint progressive-composition tear)
			if (shell_pfn_beginbufferedpaint && shell_pfn_endbufferedpaint)
				pb = shell_pfn_beginbufferedpaint (ps.hdc, &ps.rcPaint, BPBF_COMPATIBLEBUFFERS, NULL, &hdc_target);

			_app_shell_paint (hwnd, hdc_target);

			if (pb && shell_pfn_endbufferedpaint)
				shell_pfn_endbufferedpaint (pb, TRUE);

			EndPaint (hwnd, &ps);
			return 0;
		}

		case WM_DESTROY:
		{
			KillTimer (hwnd, SHELL_TIMER_REFRESH);
			KillTimer (hwnd, SHELL_TIMER_FILTER);
			KillTimer (hwnd, SHELL_TIMER_COUNTDOWN);

			shell_hwnd_search = NULL;
			_r_app_sethwnd (NULL);

			_app_shell_fonts_destroy ();

			if (shell_apps)
			{
				HeapFree (GetProcessHeap (), 0, shell_apps);
				shell_apps = NULL;
				shell_apps_cap = 0;
				shell_apps_count = 0;
			}

			if (shell_view)
			{
				HeapFree (GetProcessHeap (), 0, shell_view);
				shell_view = NULL;
				shell_view_cap = 0;
				shell_view_count = 0;
			}

			if (shell_decisions)
			{
				HeapFree (GetProcessHeap (), 0, shell_decisions);
				shell_decisions = NULL;
				shell_decisions_cap = 0;
				shell_decisions_count = 0;
			}

			PostQuitMessage (0);
			return 0;
		}
	}

	return DefWindowProcW (hwnd, msg, wparam, lparam);
}

INT APIENTRY _app_shell_run (
	_In_ HINSTANCE hinst
)
{
	WNDCLASSEXW wc = {0};
	MSG msg = {0}; // r3 G1-M5 (goldfish finding 9): zero-init, no hack
	HMODULE huxtheme;
	HWND hwnd;
	RECT rect = {0, 0, SHELL_CLIENT_W, SHELL_CLIENT_H};

	// COM for the MSAA bridge (r3 G1-M6); harmless when already up
	CoInitializeEx (NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	// DPI awareness BEFORE any window exists (r3 G1-M1, goldfish
	// finding 2 — without it WM_DPICHANGED is never delivered)
	_app_shell_dpiaware ();

	// buffered paint procs: documented named exports of uxtheme
	// (NFR-02 dynamic-resolve; no library linkage, no ordinal hooking)
	huxtheme = GetModuleHandleW (L"uxtheme.dll");

	if (!huxtheme)
		huxtheme = LoadLibraryW (L"uxtheme.dll");

	if (huxtheme)
	{
		shell_pfn_beginbufferedpaint = (SHELL_PFN_BEGINBUFFEREDPAINT)GetProcAddress (huxtheme, "BeginBufferedPaint");
		shell_pfn_endbufferedpaint = (SHELL_PFN_ENDBUFFEREDPAINT)GetProcAddress (huxtheme, "EndBufferedPaint");
	}

	wc.cbSize = sizeof (wc);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = &_app_shell_wndproc;
	wc.hInstance = hinst;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.lpszClassName = SHELL_CLASSNAME;

	if (!RegisterClassExW (&wc))
		return ERROR_APP_INIT_FAILURE;

	// NOTE: AdjustWindowRect uses the primary-monitor dpi; the initial
	// size may differ by a few px at high dpi until WM_DPICHANGED —
	// acceptable for M1 (documented in the r3 verification additions)
	AdjustWindowRect (&rect, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, FALSE);

	// resize enabled (r3 G1-M2): virtual scrolling makes resize safe
	// (the r1 clip-at-bottom could not resize at all)
	hwnd = CreateWindowExW (
		0,
		SHELL_CLASSNAME,
		SHELL_CLASSNAME, // replaced by the localized title at WM_CREATE
		WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
		CW_USEDEFAULT,
		CW_USEDEFAULT,
		rect.right - rect.left,
		rect.bottom - rect.top,
		NULL,
		NULL,
		hinst,
		NULL
	);

	if (!hwnd)
		return ERROR_APP_INIT_FAILURE;

	ShowWindow (hwnd, SW_SHOW);
	UpdateWindow (hwnd);

	while (GetMessageW (&msg, NULL, 0, 0) > 0)
	{
		TranslateMessage (&msg);
		DispatchMessageW (&msg);
	}

	return (INT)msg.wParam;
}
