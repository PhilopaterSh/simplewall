// composite_dnsetw: T032 (FR-13) ETW DNS-Client attribution session.
// Real-time in-process ETW controller (SEC-05: no new processes) over
// Microsoft-Windows-DnsClient, feeding observed resolutions into the
// DNS cache (T031). Config gate: IsCompositeDnsAttributionEnabled
// (default OFF — Phase 3 ships everything gated). Event parsing uses
// TdhGetEventInformation (tdh.dll, in-box, NFR-02). Errors degrade to
// logged no-ops — attribution is an enrichment layer, never a verdict
// dependency (the WFP pipeline works without it).
#pragma once

#include <windows.h>

// start the ETW session (idempotent; requires elevation as the app
// already has); returns non-zero NTSTATUS/HRESULT-style codes
NTSTATUS _app_dnsetw_start (
	VOID
);

// stop the session and flush pending attributions
VOID _app_dnsetw_stop (
	VOID
);

BOOLEAN _app_dnsetw_isrunning (
	VOID
);
