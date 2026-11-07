// composite_publisher: Authenticode publisher rules (FR-03, DEC-05).
// Signer-hash anchors + materialized path filters, re-validated under
// WinVerifyTrust at three points (prompt time, the FileMonitor 10-minute
// re-hash loop, rule-apply); lazy at-connection validation cached per
// path+mtime; self-signed binaries never qualify. Implemented in T004.

#pragma once

#include <windows.h>

BOOLEAN _app_publisher_ismaterialized (_In_ LPCWSTR path);
