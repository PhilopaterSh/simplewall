#include "global.h"
#include "composite_eventlog.h"

#include <winevt.h>

// dynamic wevtapi resolve — T002 binds EvtSubscribe/EvtClose here
static HANDLE wevtapi_module = NULL;

static NTSTATUS _app_eventlog_resolvewevtapi (VOID)
{
	if (wevtapi_module)
		return STATUS_SUCCESS;

	return _r_sys_loadlibrary2 (&wevtapi_module, L"wevtapi.dll", 0);
}

NTSTATUS _app_eventlog_start (_In_ HWND hwnd)
{
	NTSTATUS status;

	status = _app_eventlog_resolvewevtapi ();

	if (!NT_SUCCESS (status))
		return status;

	return STATUS_NOT_IMPLEMENTED; // T002
}

VOID _app_eventlog_stop (VOID)
{
}

BOOLEAN _app_eventlog_ishealthy (VOID)
{
	return FALSE; // T002: subscription health drives the prompt-degradation state
}
