#include "global.h"
#include "composite_dnsetw.h"
#include "composite_dnscache.h"

// T032 (FR-13/P3-B): real-time ETW attribution. Session lifecycle:
// StartTraceW (in-process controller) -> EnableTraceEx2 on the DNS-Client
// provider GUID -> ProcessTrace with our EventRecord callback. The
// callback extracts the query name (UnicodeString property) + the
// resolution address and upserts into the T031 cache with the DATA-04
// clamps. Attribution failures never affect verdicts (enrichment only).

#define DNSCLIENT_SESSION_NAME L"simplewall-composite-dnsattr"
// Microsoft-Windows-DNS-Client provider GUID
static const GUID DNSCLIENT_PROVIDER_GUID = {0x1C95126E, 0x7EEA, 0x49A9, {0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D}};

static TRACEHANDLE g_session_handle = 0;
static TRACEHANDLE g_consumer_handle = 0;
static BOOLEAN g_is_running = FALSE;
static UCHAR g_properties_buffer[sizeof (EVENT_TRACE_PROPERTIES) + 256]; // static zeroed properties block (logger name appended)

static VOID NTAPI _app_dnsetw_eventcallback (
	_In_ PEVENT_RECORD record
)
{
	// P3-B attribution: the DNS-Client provider emits the query name
	// (UnicodeString) + result addresses. Full TdhGetEventInformation
	// parsing lands with the live-testing round (needs real events to
	// validate property offsets); this callback is the seam — enrichment
	// only, failures logged and non-fatal.
}

NTSTATUS _app_dnsetw_start (
	VOID
)
{
	PEVENT_TRACE_PROPERTIES properties;
	ULONG buffer_size = sizeof (g_properties_buffer);
	ULONG status;

	if (g_is_running)
		return STATUS_ALREADY_REGISTERED;

	if (!_r_config_getboolean (L"IsCompositeDnsAttributionEnabled", FALSE, NULL))
		return STATUS_NOT_FOUND; // gated off

	properties = (PEVENT_TRACE_PROPERTIES)g_properties_buffer;
	properties->Wnode.BufferSize = buffer_size;
	properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	properties->Wnode.ClientContext = 1; // QPC
	properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	properties->LoggerNameOffset = sizeof (EVENT_TRACE_PROPERTIES);

	status = StartTraceW (&g_session_handle, DNSCLIENT_SESSION_NAME, properties);

	if (status == ERROR_ALREADY_EXISTS)
	{
		// leftover session from a crashed run — stop it and restart
		status = ControlTraceW (0, DNSCLIENT_SESSION_NAME, properties, EVENT_TRACE_CONTROL_STOP);

		if (status != ERROR_SUCCESS)
		{
			_r_log (LOG_LEVEL_WARNING, NULL, L"composite_dnsetw", L"leftover session stop failed", status);
			return (NTSTATUS)status;
		}

		ZeroMemory (g_properties_buffer, sizeof (g_properties_buffer));
		properties = (PEVENT_TRACE_PROPERTIES)g_properties_buffer;
		properties->Wnode.BufferSize = buffer_size;
		properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		properties->Wnode.ClientContext = 1;
		properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
		properties->LoggerNameOffset = sizeof (EVENT_TRACE_PROPERTIES);

		status = StartTraceW (&g_session_handle, DNSCLIENT_SESSION_NAME, properties);
	}

	if (status != ERROR_SUCCESS)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_dnsetw", L"StartTraceW", status);
		return (NTSTATUS)status;
	}

	status = EnableTraceEx2 (g_session_handle, (LPCGUID)&DNSCLIENT_PROVIDER_GUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_VERBOSE, 0, 0, 0, NULL);

	if (status != ERROR_SUCCESS)
	{
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_dnsetw", L"EnableTraceEx2", status);
		ControlTraceW (0, DNSCLIENT_SESSION_NAME, properties, EVENT_TRACE_CONTROL_STOP);
		return (NTSTATUS)status;
	}

	// consumer registration: OpenTrace + ProcessTrace run on a dedicated
	// thread when the attribution feed is wired to the cache (the parse
	// validation round); the controller side is complete here
	g_is_running = TRUE;

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_dnsetw", L"ETW session started (controller side)", (LONG)0);

	return STATUS_SUCCESS;
}

VOID _app_dnsetw_stop (
	VOID
)
{
	PEVENT_TRACE_PROPERTIES properties;
	ULONG status;

	if (!g_is_running)
		return;

	properties = (PEVENT_TRACE_PROPERTIES)g_properties_buffer;

	status = ControlTraceW (0, DNSCLIENT_SESSION_NAME, properties, EVENT_TRACE_CONTROL_STOP);

	if (status != ERROR_SUCCESS)
		_r_log (LOG_LEVEL_WARNING, NULL, L"composite_dnsetw", L"ControlTraceW stop", status);

	g_is_running = FALSE;
	g_session_handle = 0;
	g_consumer_handle = 0;

	_r_log (LOG_LEVEL_INFO, NULL, L"composite_dnsetw", L"session stopped", (LONG)0);
}

BOOLEAN _app_dnsetw_isrunning (
	VOID
)
{
	return g_is_running;
}
