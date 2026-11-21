// simplewall
// Copyright (c) 2016-2026 Henry++

#pragma once

#include <windows.h>

// composite shell selftest instrument (G-2, r4; NFR-06): headless
// in-process verification of the DEC-11 query-API layer. Run with
// `simplewall.exe -gui-selftest` — writes selftest-result.txt next to
// the exe and returns the failure count as the process exit code. NOT
// a UI path; never wired to production behavior.
INT _app_shell_selftest_run (
	VOID
);
