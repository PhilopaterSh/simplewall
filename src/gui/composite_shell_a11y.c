// simplewall
// Copyright (c) 2016-2026 Henry++

// composite_shell_a11y (G1-M6, r3 amendment): basic MSAA accessibility
// for the owner-drawn shell — the approved M1 design line ("basic
// screen-reader labels in M1, full audit later"). Exposes the shell
// window with named children: rail entries (ROLE_SYSTEM_PAGETAB) and
// rendered app cards (ROLE_SYSTEM_LISTITEM). Pure-C COM vtable; system
// libraries only (oleacc/ole32 — NFR-02 compliant). The shell-side
// child-info provider lives in composite_shell.c.

#include "../global.h"

#include <ole2.h>
#include <oleacc.h>

#pragma comment(lib, "oleacc.lib")

// exported by composite_shell.c (shell-state owner)
ULONG _app_shell_a11ychildcount (VOID);

BOOLEAN _app_shell_a11ychild (
	_In_ ULONG child_id,
	_Out_ WCHAR *name,
	_In_ ULONG cch,
	_Out_ RECT *rect,
	_Out_ LONG *role,
	_Out_ LONG *state
);

VOID _app_shell_a11yselectpage (
	_In_ HWND hwnd,
	_In_ ULONG rail_index
);

ULONG _app_shell_a11yfocuspage (VOID);

#define SHELL_ACC_NAME_MAX 512

typedef struct _SHELL_ACCOBJ
{
	IAccessible acc; // lpVtbl only (C COM)
	LONG refs;
	HWND hwnd;
} SHELL_ACCOBJ;

// static-lifetime object; the vtbl pointer is wired lazily in
// _app_shell_a11y_getobject (after the vtbl definition below)
static SHELL_ACCOBJ shell_accobj = {NULL, 1, NULL};

// helper: the shell window (set on WM_GETOBJECT)
static HWND shellacc_hwnd (VOID)
{
	return shell_accobj.hwnd;
}

static ULONG STDMETHODCALLTYPE shell_acc_addref (_In_ IAccessible *this_ptr)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;

	obj->refs++;
	return (ULONG)obj->refs;
}

static ULONG STDMETHODCALLTYPE shell_acc_release (_In_ IAccessible *this_ptr)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;

	// static-lifetime object: refs never reach zero (the window owns us)
	if (obj->refs)
		obj->refs--;

	return (ULONG)obj->refs;
}

static HRESULT STDMETHODCALLTYPE shell_acc_queryinterface (
	_In_ IAccessible *this_ptr,
	_In_ REFIID riid,
	_Outptr_ void **ppv
)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;

	if (!ppv)
		return E_POINTER;

	*ppv = NULL;

	if (IsEqualIID (riid, &IID_IUnknown) || IsEqualIID (riid, &IID_IDispatch) || IsEqualIID (riid, &IID_IAccessible))
	{
		*ppv = (void *)&obj->acc;
		shell_acc_addref (this_ptr);
		return S_OK;
	}

	return E_NOINTERFACE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_gettypeinfocount (_In_ IAccessible *this_ptr, _Out_ UINT *pcount)
{
	if (pcount)
		*pcount = 0;

	return S_OK;
}

static HRESULT STDMETHODCALLTYPE shell_acc_gettypeinfo (_In_ IAccessible *this_ptr, _In_ UINT itinfo, _In_ LCID lcid, _Outptr_opt_result_maybenull_ ITypeInfo **pptinfo)
{
	if (pptinfo)
		*pptinfo = NULL;

	return DISP_E_BADINDEX;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getidsofnames (
	_In_ IAccessible *this_ptr,
	_In_ REFIID riid,
	_In_reads_ (cnames) LPOLESTR *rgsznames,
	_In_ UINT cnames,
	_In_ LCID lcid,
	_Out_writes_ (cnames) DISPID *rgdispid
)
{
	if (cnames && rgdispid)
		rgdispid[0] = DISPID_UNKNOWN;

	return DISP_E_UNKNOWNNAME;
}

// basic IDispatch: screen readers consult the raw IAccessible vtable,
// but legacy MSAA clients may come through Invoke for the ACC_* props
static HRESULT STDMETHODCALLTYPE shell_acc_invoke (
	_In_ IAccessible *this_ptr,
	_In_ DISPID dispid,
	_In_ REFIID riid,
	_In_ LCID lcid,
	_In_ WORD flags,
	_In_ DISPPARAMS *params,
	_Out_opt_ VARIANT *result,
	_Out_opt_ EXCEPINFO *excepinfo,
	_Out_opt_ UINT *argerr
)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;
	VARIANT child;
	HRESULT hr = S_OK;

	if (result)
		VariantInit (result);

	if ((flags & DISPATCH_PROPERTYGET) == 0 || !result)
		return DISP_E_MEMBERNOTFOUND;

	// child argument (last rgvarg when present)
	VariantInit (&child);

	if (params && params->cArgs)
	{
		VARIANT *var = &params->rgvarg[params->cArgs - 1];

		if (var->vt == VT_I4 || var->vt == VT_I2 || var->vt == VT_EMPTY)
			child = *var;
	}

	if (child.vt != VT_I4)
	{
		child.vt = VT_I4;
		child.lVal = 0; // CHILDID_SELF
	}

	switch (dispid)
	{
		case DISPID_ACC_NAME:
		{
			WCHAR name[SHELL_ACC_NAME_MAX];
			BSTR bstr = NULL;

			if (child.lVal == 0)
			{
				GetWindowTextW (obj->hwnd, name, RTL_NUMBER_OF (name));
			}
			else
			{
				LONG role;
				LONG state;
				RECT rect;

				if (!_app_shell_a11ychild ((ULONG)child.lVal, name, RTL_NUMBER_OF (name), &rect, &role, &state))
					return DISP_E_MEMBERNOTFOUND;
			}

			bstr = SysAllocString (name);

			if (!bstr)
				return E_OUTOFMEMORY;

			result->vt = VT_BSTR;
			result->bstrVal = bstr;
			break;
		}

		case DISPID_ACC_ROLE:
		case DISPID_ACC_STATE:
		case DISPID_ACC_CHILDCOUNT:
		case DISPID_ACC_FOCUS:
		{
			if (dispid == DISPID_ACC_CHILDCOUNT)
			{
				result->vt = VT_I4;
				result->lVal = (LONG)_app_shell_a11ychildcount ();
				break;
			}

			if (dispid == DISPID_ACC_FOCUS)
			{
				result->vt = VT_I4;
				result->lVal = (LONG)(_app_shell_a11yfocuspage () + 1); // rail child id
				break;
			}

			// ROLE / STATE
			{
				ULONG role;
				ULONG state;

				if (child.lVal == 0)
				{
					role = 0x20; // ROLE_SYSTEM_WINDOW
					state = 0x100000; // FOCUSABLE
				}
				else
				{
					WCHAR name[SHELL_ACC_NAME_MAX];
					RECT rect;
					LONG r;
					LONG s;

					if (!_app_shell_a11ychild ((ULONG)child.lVal, name, RTL_NUMBER_OF (name), &rect, &r, &s))
						return DISP_E_MEMBERNOTFOUND;

					role = (ULONG)r;
					state = (ULONG)s;
				}

				result->vt = VT_I4;
				result->lVal = (LONG)(dispid == DISPID_ACC_ROLE ? role : state);
			}

			break;
		}

		default:
		{
			hr = DISP_E_MEMBERNOTFOUND;
			break;
		}
	}

	return hr;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccparent (_In_ IAccessible *this_ptr, _Outptr_result_maybenull_ IDispatch **ppdispParent)
{
	if (ppdispParent)
		*ppdispParent = NULL;

	return S_FALSE; // root window
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccchildcount (_In_ IAccessible *this_ptr, _Out_ long *pcountchildren)
{
	if (pcountchildren)
		*pcountchildren = (long)_app_shell_a11ychildcount ();

	return S_OK;
}

// children-by-id pattern: ids are returned as VT_I4 variants
static HRESULT STDMETHODCALLTYPE shell_acc_getaccchild (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ IDispatch **ppdispChild)
{
	if (ppdispChild)
		*ppdispChild = NULL;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccname (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ BSTR *pszName)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;
	WCHAR name[SHELL_ACC_NAME_MAX];
	LONG child_id;

	if (!pszName)
		return E_POINTER;

	*pszName = NULL;

	child_id = (varChild.vt == VT_I4) ? varChild.lVal : 0;

	if (child_id == 0)
	{
		GetWindowTextW (obj->hwnd, name, RTL_NUMBER_OF (name));
	}
	else
	{
		LONG role;
		LONG state;
		RECT rect;

		if (!_app_shell_a11ychild ((ULONG)child_id, name, RTL_NUMBER_OF (name), &rect, &role, &state))
			return S_FALSE;
	}

	*pszName = SysAllocString (name);

	return *pszName ? S_OK : E_OUTOFMEMORY;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccvalue (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ BSTR *pszValue)
{
	if (pszValue)
		*pszValue = NULL;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccdescription (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ BSTR *pszDescription)
{
	if (pszDescription)
		*pszDescription = NULL;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccrole (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Out_ VARIANT *pvarRole)
{
	LONG role;
	LONG state;
	WCHAR name[SHELL_ACC_NAME_MAX];
	RECT rect;
	LONG child_id = (varChild.vt == VT_I4) ? varChild.lVal : 0;

	if (!pvarRole)
		return E_POINTER;

	VariantInit (pvarRole);

	if (child_id == 0)
	{
		role = 0x20; // ROLE_SYSTEM_WINDOW
	}
	else
	{
		if (!_app_shell_a11ychild ((ULONG)child_id, name, RTL_NUMBER_OF (name), &rect, &role, &state))
			return S_FALSE;
	}

	pvarRole->vt = VT_I4;
	pvarRole->lVal = role;

	return S_OK;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccstate (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Out_ VARIANT *pvarState)
{
	LONG role;
	LONG state;
	WCHAR name[SHELL_ACC_NAME_MAX];
	RECT rect;
	LONG child_id = (varChild.vt == VT_I4) ? varChild.lVal : 0;

	if (!pvarState)
		return E_POINTER;

	VariantInit (pvarState);

	if (child_id == 0)
	{
		state = 0x100000; // FOCUSABLE

		if (GetForegroundWindow () == shellacc_hwnd ())
			state |= 0x4; // FOCUSED
	}
	else
	{
		if (!_app_shell_a11ychild ((ULONG)child_id, name, RTL_NUMBER_OF (name), &rect, &role, &state))
			return S_FALSE;
	}

	pvarState->vt = VT_I4;
	pvarState->lVal = state;

	return S_OK;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getacchelp (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ BSTR *pszHelp)
{
	if (pszHelp)
		*pszHelp = NULL;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getacchelptopic (_In_ IAccessible *this_ptr, _Outptr_opt_result_maybenull_ BSTR *pszHelpFile, _In_ VARIANT varChild, _Out_opt_ long *pidTopic)
{
	if (pszHelpFile)
		*pszHelpFile = NULL;

	if (pidTopic)
		*pidTopic = 0;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getacckeyboardshortcut (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ BSTR *pszKeyboardShortcut)
{
	if (pszKeyboardShortcut)
		*pszKeyboardShortcut = NULL;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccfocus (_In_ IAccessible *this_ptr, _Out_ VARIANT *pvarFocus)
{
	if (!pvarFocus)
		return E_POINTER;

	VariantInit (pvarFocus);

	// keyboard focus lives on the rail (arrow keys + Enter)
	pvarFocus->vt = VT_I4;
	pvarFocus->lVal = (LONG)(_app_shell_a11yfocuspage () + 1);

	return S_OK;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccselection (_In_ IAccessible *this_ptr, _Out_ VARIANT *pvarSelection)
{
	if (!pvarSelection)
		return E_POINTER;

	VariantInit (pvarSelection);

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_getaccdefaultaction (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _Outptr_result_maybenull_ BSTR *pszAction)
{
	if (pszAction)
		*pszAction = NULL;

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_accselect (_In_ IAccessible *this_ptr, _In_ long flagsSelect, _In_ VARIANT varChild)
{
	return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE shell_acc_acclocation (
	_In_ IAccessible *this_ptr,
	_Out_ long *pxleft,
	_Out_ long *pytop,
	_Out_ long *pcxwidth,
	_Out_ long *pcyheight,
	_In_ VARIANT varChild
)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;
	RECT rect;
	LONG child_id = (varChild.vt == VT_I4) ? varChild.lVal : 0;

	if (!pxleft || !pytop || !pcxwidth || !pcyheight)
		return E_POINTER;

	if (child_id == 0)
	{
		if (!GetWindowRect (obj->hwnd, &rect))
			return E_FAIL;
	}
	else
	{
		LONG role;
		LONG state;
		WCHAR name[SHELL_ACC_NAME_MAX];

		if (!_app_shell_a11ychild ((ULONG)child_id, name, RTL_NUMBER_OF (name), &rect, &role, &state))
			return S_FALSE;

		// client → screen (the window is not layout-mirrored: GDI
		// MapWindowPoints converts both points in one call)
		MapWindowPoints (obj->hwnd, NULL, (LPPOINT)&rect, 2);
	}

	*pxleft = rect.left;
	*pytop = rect.top;
	*pcxwidth = rect.right - rect.left;
	*pcyheight = rect.bottom - rect.top;

	return S_OK;
}

static HRESULT STDMETHODCALLTYPE shell_acc_accnavigate (_In_ IAccessible *this_ptr, _In_ long navdir, _In_ VARIANT varStart, _Out_opt_ VARIANT *pvarEndUpAt)
{
	return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE shell_acc_acchittest (_In_ IAccessible *this_ptr, _In_ long xleft, _In_ long ytop, _Out_ VARIANT *pvarChild)
{
	SHELL_ACCOBJ *obj = (SHELL_ACCOBJ *)this_ptr;
	POINT pt;
	ULONG count;

	if (!pvarChild)
		return E_POINTER;

	VariantInit (pvarChild);

	pvarChild->vt = VT_I4;
	pvarChild->lVal = 0; // CHILDID_SELF

	if (!obj->hwnd)
		return S_OK;

	pt.x = xleft;
	pt.y = ytop;
	ScreenToClient (obj->hwnd, &pt);

	count = _app_shell_a11ychildcount ();

	for (ULONG id = 1; id <= count; id++)
	{
		WCHAR name[SHELL_ACC_NAME_MAX];
		RECT rect;
		LONG role;
		LONG state;

		if (!_app_shell_a11ychild (id, name, RTL_NUMBER_OF (name), &rect, &role, &state))
			continue;

		if (PtInRect (&rect, pt))
		{
			pvarChild->lVal = (LONG)id;
			break;
		}
	}

	return S_OK;
}

static HRESULT STDMETHODCALLTYPE shell_acc_accdodefaultaction (_In_ IAccessible *this_ptr, _In_ VARIANT varChild)
{
	LONG child_id = (varChild.vt == VT_I4) ? varChild.lVal : 0;

	// rail entries activate their page; cards have no default action
	if (child_id >= 1 && child_id <= 6)
	{
		HWND hwnd = shellacc_hwnd ();

		if (hwnd)
			_app_shell_a11yselectpage (hwnd, (ULONG)child_id - 1);

		return S_OK;
	}

	return S_FALSE;
}

static HRESULT STDMETHODCALLTYPE shell_acc_putaccname (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _In_ BSTR szName)
{
	return E_NOTIMPL;
}

static HRESULT STDMETHODCALLTYPE shell_acc_putaccvalue (_In_ IAccessible *this_ptr, _In_ VARIANT varChild, _In_ BSTR szValue)
{
	return E_NOTIMPL;
}

static IAccessibleVtbl shell_accvtbl = {
	shell_acc_queryinterface,
	shell_acc_addref,
	shell_acc_release,
	shell_acc_gettypeinfocount,
	shell_acc_gettypeinfo,
	shell_acc_getidsofnames,
	shell_acc_invoke,
	shell_acc_getaccparent,
	shell_acc_getaccchildcount,
	shell_acc_getaccchild,
	shell_acc_getaccname,
	shell_acc_getaccvalue,
	shell_acc_getaccdescription,
	shell_acc_getaccrole,
	shell_acc_getaccstate,
	shell_acc_getacchelp,
	shell_acc_getacchelptopic,
	shell_acc_getacckeyboardshortcut,
	shell_acc_getaccfocus,
	shell_acc_getaccselection,
	shell_acc_getaccdefaultaction,
	shell_acc_accselect,
	shell_acc_acclocation,
	shell_acc_accnavigate,
	shell_acc_acchittest,
	shell_acc_accdodefaultaction,
	shell_acc_putaccname,
	shell_acc_putaccvalue,
};

LRESULT _app_shell_a11y_getobject (
	_In_ HWND hwnd,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
)
{
	// single-threaded (UI thread): wire the vtbl on first use
	if (!shell_accobj.acc.lpVtbl)
		shell_accobj.acc.lpVtbl = &shell_accvtbl;

	shell_accobj.hwnd = hwnd;

	return LresultFromObject (&IID_IAccessible, wparam, (IUnknown *)&shell_accobj.acc);
}
