// simplewall
// Copyright (c) 2016-2026 Henry++

// composite_shell (G-1/G-2): fork-native owner-drawn GUI, visual
// authority docs/specs/gui/mockup-r1.html (dark palette, RTL rail,
// state pills). Extends the composite modules through their query APIs
// only — no WFP/engine interaction here. Compile this file with /utf-8
// (vcxproj per-file setting); Arabic UI strings are UTF-8 literals.

#include "../global.h"

#include "../composite_lockdown.h" // composite Phase 1 (FR-06/DEC-04)
#include "../composite_packs.h" // composite Phase 2 (FR-08/DATA-02)
#include "../composite_ledger.h" // composite Phase 2 (FR-10/DATA-03)
#include "../composite_resolver.h" // composite Phase 3 (DNS attribution)
#include "../composite_state.h" // composite Phase 1 (T005/T006)
#include "../composite_bypass.h" // composite Phase 3 (T033b)

#include "../wfp.h" // engine-installed probe for the Log page honesty line

#include "composite_shell.h"

#define SHELL_CLASSNAME L"quietwall_shell"
#define SHELL_WINDOWNAME L"simplewall — القشرة المركّبة"
#define SHELL_TIMER_ID 1
#define SHELL_TIMER_MS 2000

#define SHELL_CLIENT_W 1080
#define SHELL_CLIENT_H 680
#define SHELL_RAIL_W 200
#define SHELL_MARGIN 16
#define SHELL_CARD_H 56
#define SHELL_CARD_GAP 8
#define SHELL_PILL_W 72
#define SHELL_PILL_H 24
#define SHELL_CHECKBOX_SIZE 16

#define SHELL_APPS_MAX 200
#define SHELL_NAME_MAX 96
#define SHELL_PATH_MAX 192
#define SHELL_LINE_MAX 160

// mockup-r1.html palette
#define SHELL_COLOR_BG RGB (0x0b, 0x12, 0x20)
#define SHELL_COLOR_RAIL RGB (0x11, 0x1a, 0x2e)
#define SHELL_COLOR_CARD RGB (0x16, 0x20, 0x3a)
#define SHELL_COLOR_LINE RGB (0x22, 0x30, 0x52)
#define SHELL_COLOR_ACCENT RGB (0x2d, 0xd4, 0xbf)
#define SHELL_COLOR_ACCENTTEXT RGB (0x06, 0x20, 0x20)
#define SHELL_COLOR_TEXT RGB (0xdb, 0xe6, 0xf5)
#define SHELL_COLOR_MUTED RGB (0x8a, 0xa0, 0xc0)
#define SHELL_COLOR_OK RGB (0x34, 0xd3, 0x99)
#define SHELL_COLOR_OKBG RGB (0x0f, 0x2b, 0x22)
#define SHELL_COLOR_OKLINE RGB (0x1c, 0x5a, 0x45)
#define SHELL_COLOR_DANGER RGB (0xf8, 0x71, 0x71)
#define SHELL_COLOR_DANGERBG RGB (0x2b, 0x12, 0x12)
#define SHELL_COLOR_DANGERLINE RGB (0x6b, 0x27, 0x27)
#define SHELL_COLOR_WARN RGB (0xfb, 0xbf, 0x24)
#define SHELL_COLOR_WARNBG RGB (0x2b, 0x20, 0x05)
#define SHELL_COLOR_WARNLINE RGB (0x6b, 0x54, 0x1c)

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
	INT state; // 0 = block, 1 = allow, 2 = prompt (notification set)
} SHELL_APP_SNAPSHOT;

static const LPCWSTR shell_rail_names[SHELL_PAGE_MAX] = {
	L"التطبيقات",
	L"القواعد",
	L"الحزم",
	L"Lockdown",
	L"السجل",
	L"الإعدادات",
};

static SHELL_APP_SNAPSHOT shell_apps[SHELL_APPS_MAX] = {0};
static ULONG shell_apps_count = 0; // rendered (capped) count
static ULONG shell_apps_total = 0;
static ULONG shell_apps_allowed = 0;
static ULONG shell_apps_blocked = 0;

static INT shell_page = SHELL_PAGE_APPS;
static RECT shell_rail_rects[SHELL_PAGE_MAX] = {0};
static RECT shell_lockdown_btn = {0};
static RECT shell_check_rects[4] = {0}; // settings rows (hit-test)

static HFONT shell_font_title = NULL;
static HFONT shell_font_main = NULL;
static HFONT shell_font_small = NULL;
static HFONT shell_font_pill = NULL;

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

static VOID _app_shell_snapshot_apps (VOID)
{
	PITEM_APP ptr_app = NULL;
	ULONG_PTR enum_key = 0;
	ULONG total = 0;
	ULONG allowed = 0;
	ULONG blocked = 0;
	ULONG rendered = 0;

	_r_queuedlock_acquireshared (&lock_apps);

	while (_r_obj_enumhashtablepointer (apps_table, (PVOID_PTR)&ptr_app, NULL, &enum_key))
	{
		total++;

		if (ptr_app->is_enabled)
			allowed++;
		else
			blocked++;

		if (rendered < SHELL_APPS_MAX)
		{
			SHELL_APP_SNAPSHOT *snap = &shell_apps[rendered];

			_app_shell_strcopy (snap->name, SHELL_NAME_MAX, ptr_app->display_name ? ptr_app->display_name->buffer : NULL);
			_app_shell_strcopy (snap->path, SHELL_PATH_MAX, ptr_app->real_path ? ptr_app->real_path->buffer : (ptr_app->short_name ? ptr_app->short_name->buffer : NULL));

			if (ptr_app->notification)
				snap->state = 2;
			else if (ptr_app->is_enabled)
				snap->state = 1;
			else
				snap->state = 0;

			rendered++;
		}
	}

	_r_queuedlock_releaseshared (&lock_apps);

	shell_apps_count = rendered;
	shell_apps_total = total;
	shell_apps_allowed = allowed;
	shell_apps_blocked = blocked;
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
	_app_shell_fillround (hdc, rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 8);
	_app_shell_drawtext (hdc, text, rect, shell_font_small, SHELL_COLOR_TEXT, DT_CENTER | DT_VCENTER);
}

static VOID _app_shell_pagetitle (
	_In_ HDC hdc,
	_In_ PRECT content,
	_In_ LPCWSTR title,
	_In_ LPCWSTR subtitle
)
{
	RECT rect;

	rect = *content;
	rect.bottom = rect.top + 34;
	_app_shell_drawtext (hdc, title, &rect, shell_font_title, SHELL_COLOR_TEXT, DT_RIGHT);

	if (subtitle)
	{
		rect.top = rect.bottom + 2;
		rect.bottom = rect.top + 22;
		_app_shell_drawtext (hdc, subtitle, &rect, shell_font_small, SHELL_COLOR_MUTED, DT_RIGHT);
	}
}

static VOID _app_shell_drawapps (
	_In_ HDC hdc,
	_In_ PRECT content,
	_In_ PRECT client
)
{
	WCHAR buffer[128];
	RECT rect;
	RECT card;
	LONG y;

	_app_shell_pagetitle (hdc, content, L"التطبيقات", NULL);

	// summary chips (right-to-left order: total, allowed, blocked)
	y = content->top + 44;

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"الإجمالي: %lu", shell_apps_total);
	rect.left = content->right - 3 * 160 - 2 * 10;
	rect.right = content->right;
	rect.top = y;
	rect.bottom = y + 30;
	_app_shell_drawchip (hdc, &rect, buffer);

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"مسموح: %lu", shell_apps_allowed);
	rect.left = content->right - 2 * 160 - 10;
	rect.right = rect.left + 160;
	_app_shell_drawchip (hdc, &rect, buffer);

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"محجوب: %lu", shell_apps_blocked);
	rect.left = content->right - 160;
	rect.right = rect.left + 160;
	_app_shell_drawchip (hdc, &rect, buffer);

	y += 30 + SHELL_MARGIN;

	if (shell_apps_count == 0)
	{
		rect.left = content->left;
		rect.right = content->right;
		rect.top = y;
		rect.bottom = y + 60;
		_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);
		_app_shell_drawtext (hdc, L"لا توجد تطبيقات في الملف الشخصي بعد", &rect, shell_font_main, SHELL_COLOR_MUTED, DT_CENTER | DT_VCENTER);
		return;
	}

	for (ULONG i = 0; i < shell_apps_count; i++)
	{
		SHELL_APP_SNAPSHOT *snap = &shell_apps[i];

		card.left = content->left;
		card.right = content->right;
		card.top = y;
		card.bottom = y + SHELL_CARD_H;

		if (card.bottom > client->bottom - SHELL_MARGIN)
			break; // G-1: clip at the bottom edge, no scrollbars yet

		_app_shell_fillround (hdc, &card, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

		// name + path (right side, RTL)
		rect.left = card.left + SHELL_MARGIN + SHELL_PILL_W;
		rect.right = card.right - SHELL_MARGIN;
		rect.top = card.top + 8;
		rect.bottom = rect.top + 22;
		_app_shell_drawtext (hdc, snap->name, &rect, shell_font_main, SHELL_COLOR_TEXT, DT_RIGHT);

		rect.top = rect.bottom + 2;
		rect.bottom = rect.top + 18;
		_app_shell_drawtext (hdc, snap->path, &rect, shell_font_small, SHELL_COLOR_MUTED, DT_RIGHT);

		// state pill (left side)
		rect.left = card.left + SHELL_MARGIN;
		rect.right = rect.left + SHELL_PILL_W;
		rect.top = card.top + (SHELL_CARD_H - SHELL_PILL_H) / 2;
		rect.bottom = rect.top + SHELL_PILL_H;

		if (snap->state == 2)
			_app_shell_drawpill (hdc, &rect, L"تنبيه", SHELL_COLOR_WARN, SHELL_COLOR_WARNBG, SHELL_COLOR_WARNLINE);
		else if (snap->state == 1)
			_app_shell_drawpill (hdc, &rect, L"سماح", SHELL_COLOR_OK, SHELL_COLOR_OKBG, SHELL_COLOR_OKLINE);
		else
			_app_shell_drawpill (hdc, &rect, L"حجب", SHELL_COLOR_DANGER, SHELL_COLOR_DANGERBG, SHELL_COLOR_DANGERLINE);

		y = card.bottom + SHELL_CARD_GAP;
	}
}

static VOID _app_shell_drawrules (
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	WCHAR buffer[128];
	RECT rect;
	ULONG decisions;

	decisions = _app_state_querycount ();

	_app_shell_pagetitle (hdc, content, L"القواعد", L"معلم G-2 — العرض الكامل للقواعد قادم في المرحلة التالية");

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"قرارات الجلسة الحية: %lu", decisions);

	rect.left = content->left;
	rect.right = content->right;
	rect.top = content->top + 60;
	rect.bottom = rect.top + 48;

	_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, SHELL_COLOR_TEXT, DT_RIGHT | DT_VCENTER);
}

static VOID _app_shell_drawpacks (
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	struct
	{
		LPCWSTR id;
		LPCWSTR title;
	} packs[] = {
		{L"telemetry-refresh", L"حزمة تحديث القياسات (telemetry-refresh)"},
		{L"vendor-blockers", L"حزمة حجب المورّدين (vendor-blockers)"},
		{L"ai-agents", L"حزمة وكلاء الذكاء الاصطناعي (ai-agents)"},
	};
	RECT rect;
	RECT pill;

	_app_shell_pagetitle (hdc, content, L"الحزم", L"الحزم الموقّعة (FR-08) — الاستيراد والتحكم في معلم G-2");

	for (ULONG i = 0; i < RTL_NUMBER_OF (packs); i++)
	{
		rect.left = content->left;
		rect.right = content->right;
		rect.top = content->top + 60 + (LONG)i * (SHELL_CARD_H + SHELL_CARD_GAP);
		rect.bottom = rect.top + SHELL_CARD_H;

		_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

		pill.left = content->left + SHELL_MARGIN;
		pill.right = pill.left + SHELL_PILL_W;
		pill.top = rect.top + (SHELL_CARD_H - SHELL_PILL_H) / 2;
		pill.bottom = pill.top + SHELL_PILL_H;

		rect.left = pill.right + SHELL_MARGIN;
		rect.right -= SHELL_MARGIN;
		rect.top += 8;
		rect.bottom = rect.top + 22;
		_app_shell_drawtext (hdc, packs[i].title, &rect, shell_font_main, SHELL_COLOR_TEXT, DT_RIGHT);

		rect.top = rect.bottom + 2;
		rect.bottom = rect.top + 18;
		_app_shell_drawtext (hdc, packs[i].id, &rect, shell_font_small, SHELL_COLOR_MUTED, DT_RIGHT);

		if (_app_packs_isenabled (packs[i].id))
			_app_shell_drawpill (hdc, &pill, L"مفعّلة", SHELL_COLOR_OK, SHELL_COLOR_OKBG, SHELL_COLOR_OKLINE);
		else
			_app_shell_drawpill (hdc, &pill, L"غير مفعّلة", SHELL_COLOR_MUTED, SHELL_COLOR_CARD, SHELL_COLOR_LINE);
	}
}

static VOID _app_shell_drawlockdown (
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	static const LPCWSTR contract_lines[] = {
		L"لقطة (snapshot) لحالة الجدار قبل أي تغيير",
		L"تحقق قبل التنفيذ (verify-then-commit) — DEC-04",
		L"تراجع كامل تلقائي عند فشل أي خطوة (revert)",
		L"watchdog يراقب العزل طوال فترة تفعيله",
		L"RSK-04: تعارض المنفذ 53 يُبلَّغ عنه ولا يُتجاوز بصمت",
	};
	WCHAR buffer[128];
	RECT rect;
	BOOLEAN is_active;

	is_active = _app_lockdown_isactive ();

	_app_shell_pagetitle (hdc, content, L"Lockdown", L"عزل دفاعي على طبقة WFAS (FR-06) — إجراء حرج للجهاز");

	// state line
	rect.left = content->left;
	rect.right = content->right;
	rect.top = content->top + 60;
	rect.bottom = rect.top + 44;
	_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"حالة العزل: %s", is_active ? L"مفعّل" : L"غير مفعّل");

	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, is_active ? SHELL_COLOR_OK : SHELL_COLOR_TEXT, DT_RIGHT | DT_VCENTER);

	// action button (rail-style rect)
	shell_lockdown_btn.left = content->right - 220;
	shell_lockdown_btn.right = content->right;
	shell_lockdown_btn.top = rect.bottom + SHELL_MARGIN;
	shell_lockdown_btn.bottom = shell_lockdown_btn.top + 40;

	if (is_active)
		_app_shell_fillround (hdc, &shell_lockdown_btn, SHELL_COLOR_DANGERBG, SHELL_COLOR_DANGERLINE, 8);
	else
		_app_shell_fillround (hdc, &shell_lockdown_btn, SHELL_COLOR_ACCENT, SHELL_COLOR_ACCENT, 8);

	_app_shell_drawtext (hdc, is_active ? L"إيقاف Lockdown" : L"تفعيل Lockdown", &shell_lockdown_btn, shell_font_main, is_active ? SHELL_COLOR_DANGER : SHELL_COLOR_ACCENTTEXT, DT_CENTER | DT_VCENTER);

	// resolver ownership (read-only)
	rect.left = content->left;
	rect.right = shell_lockdown_btn.left - SHELL_MARGIN;
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"المحلّل (resolver): %s", _app_resolver_isowned () ? L"مملوك للمنصة" : L"غير مملوك");
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, SHELL_COLOR_MUTED, DT_RIGHT | DT_VCENTER);

	// safety contract (design r2)
	rect.left = content->left;
	rect.right = content->right;
	rect.top = shell_lockdown_btn.bottom + 16;
	rect.bottom = rect.top + 26;
	_app_shell_drawtext (hdc, L"عقد الأمان (design r2):", &rect, shell_font_main, SHELL_COLOR_TEXT, DT_RIGHT);

	for (ULONG i = 0; i < RTL_NUMBER_OF (contract_lines); i++)
	{
		rect.top = rect.bottom + 4;
		rect.bottom = rect.top + 22;
		_app_shell_drawtext (hdc, contract_lines[i], &rect, shell_font_small, SHELL_COLOR_MUTED, DT_RIGHT);
	}
}

static VOID _app_shell_drawlog (
	_In_ HDC hdc,
	_In_ PRECT content
)
{
	WCHAR buffer[SHELL_LINE_MAX];
	WCHAR line[SHELL_LINE_MAX];
	RECT rect;
	ULONG held;
	ULONG foreign_count;
	BOOLEAN is_policy;
	BOOLEAN is_engine;

	held = _app_state_getheldtotal ();
	foreign_count = _app_ledger_querycount ();
	is_engine = _wfp_isfiltersinstalled ();

	_app_shell_pagetitle (hdc, content, L"السجل", NULL);

	rect.left = content->left;
	rect.right = content->right;
	rect.top = content->top + 44;
	rect.bottom = rect.top + 44;
	_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"اتصالات محتجزة بانتظار قرار: %lu", held);
	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, held ? SHELL_COLOR_WARN : SHELL_COLOR_TEXT, DT_RIGHT | DT_VCENTER);

	rect.left = content->left;
	rect.right = content->right;
	rect.top = rect.bottom + SHELL_CARD_GAP;
	rect.bottom = rect.top + 44;
	_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"تغييرات أجنبية في دفتر التدقيق: %lu", foreign_count);
	rect.left += SHELL_MARGIN;
	rect.right -= SHELL_MARGIN;
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_main, foreign_count ? SHELL_COLOR_WARN : SHELL_COLOR_TEXT, DT_RIGHT | DT_VCENTER);

	// honesty line: the live feed needs the engine (main path)
	rect.left = content->left + SHELL_MARGIN;
	rect.right = content->right - SHELL_MARGIN;
	rect.top = rect.bottom + SHELL_MARGIN;
	rect.bottom = rect.top + 22;
	_app_shell_drawtext (hdc, L"السجل الحي يتطلب تشغيل المحرك (المسار الرئيسي)", &rect, shell_font_small, is_engine ? SHELL_COLOR_MUTED : SHELL_COLOR_WARN, DT_RIGHT);

	// foreign ledger records (up to 10)
	for (ULONG i = 0; i < foreign_count && i < 10; i++)
	{
		if (!_app_ledger_queryforeign (i, buffer, SHELL_LINE_MAX, &is_policy))
			break;

		_r_str_printf (line, RTL_NUMBER_OF (line), L"%lu. %s%s", i + 1, buffer, is_policy ? L" (سياسة)" : L"");

		rect.top = rect.bottom + 6;
		rect.bottom = rect.top + 20;
		_app_shell_drawtext (hdc, line, &rect, shell_font_small, SHELL_COLOR_TEXT, DT_RIGHT);
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
		LPCWSTR label;
		BOOLEAN default_value;
	} gates[] = {
		{COMPOSITE_CONFIG_TIERS, L"الطبقات التلقائية (IsCompositeTiersEnabled)", TRUE},
		{COMPOSITE_CONFIG_SINGLEFLIGHT, L"الرحلة الواحدة (IsCompositeSingleFlightEnabled)", TRUE},
		{L"IsCompositeDnsAttributionEnabled", L"إسناد DNS (IsCompositeDnsAttributionEnabled)", FALSE},
		{L"IsCompositeLedgerEnabled", L"دفتر التدقيق (IsCompositeLedgerEnabled)", FALSE},
	};
	WCHAR buffer[128];
	RECT rect;
	RECT box;
	BOOLEAN value;

	_app_shell_pagetitle (hdc, content, L"الإعدادات", L"بوابات الميزات المركّبة — تُكتب مباشرة في الإعدادات");

	for (ULONG i = 0; i < RTL_NUMBER_OF (gates); i++)
	{
		value = _r_config_getboolean (gates[i].key, gates[i].default_value, NULL);

		rect.left = content->left;
		rect.right = content->right;
		rect.top = content->top + 60 + (LONG)i * 44;
		rect.bottom = rect.top + 36;
		shell_check_rects[i] = rect;

		_app_shell_fillround (hdc, &rect, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 10);

		// checkbox (owner-drawn; accent-filled when checked)
		box.left = rect.right - SHELL_MARGIN - SHELL_CHECKBOX_SIZE;
		box.right = box.left + SHELL_CHECKBOX_SIZE;
		box.top = rect.top + (36 - SHELL_CHECKBOX_SIZE) / 2;
		box.bottom = box.top + SHELL_CHECKBOX_SIZE;

		if (value)
			_app_shell_fillround (hdc, &box, SHELL_COLOR_ACCENT, SHELL_COLOR_ACCENT, 4);
		else
			_app_shell_fillround (hdc, &box, SHELL_COLOR_BG, SHELL_COLOR_LINE, 4);

		if (value)
			_app_shell_drawtext (hdc, L"✓", &box, shell_font_small, SHELL_COLOR_ACCENTTEXT, DT_CENTER | DT_VCENTER);

		rect.right = box.left - 10;
		rect.left += SHELL_MARGIN;
		_app_shell_drawtext (hdc, gates[i].label, &rect, shell_font_main, SHELL_COLOR_TEXT, DT_RIGHT | DT_VCENTER);
	}

	rect.left = content->left + SHELL_MARGIN;
	rect.right = content->right - SHELL_MARGIN;
	rect.top = shell_check_rects[3].bottom + SHELL_MARGIN;
	rect.bottom = rect.top + 22;
	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"الاستهلاك في وضع الخمول: ~16 MB");
	_app_shell_drawtext (hdc, buffer, &rect, shell_font_small, SHELL_COLOR_MUTED, DT_RIGHT);
}

static VOID _app_shell_drawrail (
	_In_ HDC hdc,
	_In_ PRECT client
)
{
	RECT rail;
	RECT rect;

	rail.left = client->right - SHELL_RAIL_W;
	rail.right = client->right;
	rail.top = 0;
	rail.bottom = client->bottom;

	_app_shell_fillrect (hdc, &rail, SHELL_COLOR_RAIL);

	// separator
	{
		RECT sep = {rail.left - 1, 0, rail.left, client->bottom};
		_app_shell_fillrect (hdc, &sep, SHELL_COLOR_LINE);
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
			_app_shell_fillround (hdc, &item, SHELL_COLOR_CARD, SHELL_COLOR_LINE, 8);

			// accent bar on the right edge (RTL)
			{
				RECT bar = {item.right - 3, item.top + 6, item.right, item.bottom - 6};
				_app_shell_fillrect (hdc, &bar, SHELL_COLOR_ACCENT);
			}
		}

		rect = item;
		rect.left += 10;
		rect.right -= 10;
		_app_shell_drawtext (hdc, shell_rail_names[i], &rect, shell_font_main, i == shell_page ? SHELL_COLOR_TEXT : SHELL_COLOR_MUTED, DT_RIGHT | DT_VCENTER);
	}
}

static VOID _app_shell_paint (
	_In_ HWND hwnd,
	_In_ HDC hdc
)
{
	RECT client;
	RECT content;

	if (!GetClientRect (hwnd, &client))
		return;

	_app_shell_fillrect (hdc, &client, SHELL_COLOR_BG);

	_app_shell_drawrail (hdc, &client);

	content.left = SHELL_MARGIN;
	content.right = client.right - SHELL_RAIL_W - SHELL_MARGIN;
	content.top = SHELL_MARGIN;
	content.bottom = client.bottom - SHELL_MARGIN;

	switch (shell_page)
	{
		case SHELL_PAGE_APPS:
		{
			_app_shell_drawapps (hdc, &content, &client);
			break;
		}

		case SHELL_PAGE_RULES:
		{
			_app_shell_drawrules (hdc, &content);
			break;
		}

		case SHELL_PAGE_PACKS:
		{
			_app_shell_drawpacks (hdc, &content);
			break;
		}

		case SHELL_PAGE_LOCKDOWN:
		{
			_app_shell_drawlockdown (hdc, &content);
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

static VOID _app_shell_applylockdown (
	_In_ HWND hwnd,
	_In_ BOOLEAN is_enable
)
{
	LPCWSTR text;
	NTSTATUS status;

	if (is_enable)
	{
		text = L"سيتم تفعيل العزل الكامل (Lockdown).\r\nهذا إجراء حرج للجهاز: يتم تغيير حالة الجدار على مستوى النظام وتحويل المُحلِّل (DNS).\r\n\r\nهل تريد المتابعة؟";
	}
	else
	{
		text = L"سيتم إيقاف العزل الكامل (Lockdown) وتراجع كامل عن تغييراته.\r\n\r\nهل تريد المتابعة؟";
	}

	if (MessageBoxW (hwnd, text, L"تأكيد Lockdown", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_RTLREADING | MB_SETFOREGROUND) != IDYES)
		return;

	status = is_enable ? _app_lockdown_enable (TRUE) : _app_lockdown_disable ();

	if (!NT_SUCCESS (status))
		MessageBoxW (hwnd, L"فشل تنفيذ العملية — راجع السجل لتفاصيل الخطأ.", L"Lockdown", MB_OK | MB_ICONERROR | MB_RTLREADING);

	InvalidateRect (hwnd, NULL, TRUE);
}

static VOID _app_shell_onclick (
	_In_ HWND hwnd,
	_In_ LONG x,
	_In_ LONG y
)
{
	POINT pt = {x, y};

	for (INT i = 0; i < SHELL_PAGE_MAX; i++)
	{
		if (PtInRect (&shell_rail_rects[i], pt))
		{
			if (shell_page != i)
			{
				shell_page = i;
				InvalidateRect (hwnd, NULL, TRUE);
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

		for (ULONG i = 0; i < RTL_NUMBER_OF (keys); i++)
		{
			if (PtInRect (&shell_check_rects[i], pt))
			{
				_r_config_setboolean (keys[i], !_r_config_getboolean (keys[i], defaults[i], NULL), NULL);
				InvalidateRect (hwnd, NULL, TRUE);
				return;
			}
		}
	}
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

			// populate apps_table from the profile (the shell replaces the
			// main window, so the upstream WM_INITDIALOG load never runs)
			// fix (2026-11-18, 4-dump crash): the -gui path skips the upstream
			// _app_profile_initialize call - profile_info paths were empty
			// stringrefs (NULL buffer) and the path converter dereferenced
			// NULL inside _r_str_isnullterminated (AV 0xC0000005 at
			// _r_fs_dospathnametontpathname+0x233, dumps simplewall-1794961299..422)
			_app_profile_initialize ();
			_app_profile_load (NULL, NULL);

			hdc = GetDC (hwnd);

			if (hdc)
			{
				LONG dpi = GetDeviceCaps (hdc, LOGPIXELSY);

				shell_font_title = CreateFontW (-MulDiv (15, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
				shell_font_main = CreateFontW (-MulDiv (12, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
				shell_font_small = CreateFontW (-MulDiv (10, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
				shell_font_pill = CreateFontW (-MulDiv (10, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

				ReleaseDC (hwnd, hdc);
			}

			_r_app_sethwnd (hwnd);

			_app_shell_snapshot_apps ();
			SetTimer (hwnd, SHELL_TIMER_ID, SHELL_TIMER_MS, NULL);

			return 0;
		}

		case WM_TIMER:
		{
			if (wparam != SHELL_TIMER_ID)
				break;

			// cheap refresh: re-snapshot the counts/states, repaint
			_app_shell_snapshot_apps ();
			InvalidateRect (hwnd, NULL, TRUE);
			return 0;
		}

		case WM_LBUTTONDOWN:
		{
			_app_shell_onclick (hwnd, (LONG)(SHORT)LOWORD (lparam), (LONG)(SHORT)HIWORD (lparam));
			return 0;
		}

		case WM_ERASEBKGND:
		{
			return 1;
		}

		case WM_PAINT:
		{
			PAINTSTRUCT ps;

			if (BeginPaint (hwnd, &ps))
			{
				_app_shell_paint (hwnd, ps.hdc);
				EndPaint (hwnd, &ps);
			}

			return 0;
		}

		case WM_DESTROY:
		{
			KillTimer (hwnd, SHELL_TIMER_ID);

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

			PostQuitMessage (0);
			return 0;
		}
	}

	return DefWindowProcW (hwnd, msg, wparam, lparam);
}

// TEMP debug (G-1): record faulting address to shell_crash.txt next to the
// exe; remove after the crash is diagnosed
static LONG WINAPI _app_shell_seh_filter (
	_In_ PEXCEPTION_POINTERS ptrs
)
{
	WCHAR path[MAX_PATH];
	HANDLE file;
	DWORD written = 0;
	DWORD size;
	CHAR line[160];

	if (GetModuleFileNameW (NULL, path, RTL_NUMBER_OF (path)))
	{
		PWSTR slash = wcsrchr (path, L'\\');

		if (slash)
			*slash = UNICODE_NULL;

		wcscat_s (path, RTL_NUMBER_OF (path), L"\\shell_crash.txt");

		file = CreateFileW (path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);

		if (file != INVALID_HANDLE_VALUE)
		{
			size = (DWORD)_snprintf_s (line, RTL_NUMBER_OF (line), _TRUNCATE, "code=0x%08lx addr=%p rip=%p rbp=%p\n", (ULONG)ptrs->ExceptionRecord->ExceptionCode, (PVOID)ptrs->ExceptionRecord->ExceptionAddress, (PVOID)(ULONG_PTR)ptrs->ContextRecord->Rip, (PVOID)(ULONG_PTR)ptrs->ContextRecord->Rbp);
			WriteFile (file, line, size, &written, NULL);
			CloseHandle (file);
		}
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

INT APIENTRY _app_shell_run (
	_In_ HINSTANCE hinst
)
{
	WNDCLASSEXW wc = {0};
	MSG msg;
	HWND hwnd;
	RECT rect = {0, 0, SHELL_CLIENT_W, SHELL_CLIENT_H};

	msg.message = WM_QUIT; // silence /W4 "possibly uninitialized" on early-exit paths

	SetUnhandledExceptionFilter (&_app_shell_seh_filter);

	wc.cbSize = sizeof (wc);
	wc.style = CS_HREDRAW | CS_VREDRAW;
	wc.lpfnWndProc = &_app_shell_wndproc;
	wc.hInstance = hinst;
	wc.hCursor = LoadCursor (NULL, IDC_ARROW);
	wc.lpszClassName = SHELL_CLASSNAME;

	if (!RegisterClassExW (&wc))
		return ERROR_APP_INIT_FAILURE;

	AdjustWindowRect (&rect, WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX), FALSE);

	hwnd = CreateWindowExW (
		0,
		SHELL_CLASSNAME,
		SHELL_WINDOWNAME,
		WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
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
