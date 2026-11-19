// simplewall
// Copyright (c) 2016-2026 Henry++

#pragma once

#include <windows.h>

// composite shell (G-1/G-2): fork-native owner-drawn GUI. Run with
// `simplewall.exe -gui` after _r_app_initialize; the shell REPLACES the
// main window for this session (engine/filters are not started — the
// shell is read-mostly, Lockdown actions go through the module APIs
// with their own elevation semantics). Returns the message-loop exit
// code.
INT APIENTRY _app_shell_run (
	_In_ HINSTANCE hinst
);
