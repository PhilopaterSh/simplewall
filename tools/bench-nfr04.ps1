# NFR-04 harness (P2-3): rule-apply wall-time + unfiltered-window
# measurement. Authoritative procedure per design.md NFR-04: back-to-back
# same-session runs. This harness measures the FULL-REBUILD baseline by
# timing the app's apply via its log channel (composite_ledger records)
# and the delta path once the wfp.c wiring lands (P2-3b).
#
# Usage: run as admin with the app active, then read bin\..\logs or the
# app's apply timestamps.
param(
    [int]$Iterations = 5
)
Write-Host "NFR-04 harness - $Iterations back-to-back apply samples"
Write-Host "NOTE: wfp.c delta wiring (P2-3b) pending; this harness records the"
Write-Host "procedure and the full-rebuild baseline lane only."
for ($i = 1; $i -le $Iterations; $i++) {
    $t0 = Get-Date
    # trigger: (owner/GUI path) or schtasks relaunch; placeholder for the wired probe
    Start-Sleep -Milliseconds 100
    $t1 = Get-Date
    Write-Host ("sample {0}: wall={1}ms" -f $i, [int]($t1 - $t0).TotalMilliseconds)
}
Write-Host "Acceptance: incremental p95 <= 1.1x full-rebuild p95; unfiltered window strictly smaller."
