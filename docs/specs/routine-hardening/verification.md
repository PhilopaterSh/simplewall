# Verification: Round 2 — Routine Hardening & Secure Updater

Task T013 (RSK-02/RSK-04 runbooks + manual procedures).

## Signing bootstrap (T011) — RSK-04 gate

```powershell
# one-time (done 2026-11-06, key-epoch 1):
.\tools\update-signer.ps1 -NewKey -KeyPath D:\keys\simplewall-signing.json
.\tools\update-signer.ps1 -SelfTest -KeyPath D:\keys\simplewall-signing.json   # must PASS
.\tools\update-signer.ps1 -ExportPubHex -KeyPath ...   # paste into src\update_key.h

# per release:
.\tools\update-signer.ps1 -Sign -KeyPath ... -File bin\VERSION         # -> VERSION.sig
```

- SelfTest (round-trip + tamper-rejection) is the RSK-04 gate; it passed
  at generation time on 2026-11-06.
- **Interop caveat**: the CNG verifier expects a raw 64-byte r||s
  signature over the precomputed SHA-256 digest; the PS signer emits
  IEEE P1363 (identical layout). First real build must confirm the
  C-side round-trip with a sign→verify test before enabling updates
  (RSK-04).

## Key rotation (RSK-02 runbook)

1. Generate a new key (`-NewKey`) — the new key-epoch increments.
2. Ship ONE release signed by the OLD key that embeds the NEW public key.
3. From the following release, sign with the new key only. If the old
   key is lost, ship the new public key via a signed installer the user
   runs manually (documented loss path).

## Manual verification procedures

- **FR-01/MITM**: point `_r_app_getupdate_url` (vendored rapp.h) at a
  local HTTPS server with a self-signed certificate → the update check
  must abort with the fail-closed log line and never retry with ignored
  flags.
- **FR-03/tamper**: flip a byte in the downloaded artifact → sha256
  mismatch drops the cache file and logs (fail-closed).
- **FR-03/rollback**: serve a manifest with a lower version → rejected
  by the existing `_r_str_versioncompare` monotonicity check.
- **FR-03/forged manifest**: serve a manifest with a random 64-byte
  `.sig` → rejected before parsing (no version parsing side effects).
- **FR-04/TOCTOU**: with Procmon, confirm the cache file is opened once
  (exclusive), renamed via the held handle, and never re-opened by path
  between download and landing on Win10+.
- **FR-07/junction**: plant a junction as the cache path → the updater
  must reject (reparse-point check) and log.
- **FR-05**: registry value growth between probe and read no longer
  overflows (code-reviewed + cppcheck clean; the capacity contract makes
  the overflow structurally impossible).
- **FR-10**: build passes `C_ASSERT`-style function-pointer guards —
  any ABI drift fails compilation.
- **NFR-01**: healthy flow against the fork feed completes the existing
  update UX.

## Build gate (T016 — owner machine, now simpler)

The library is vendored in-tree: **no sibling `..\routine` clone is
needed anymore**. Build = open `simplewall.sln` (VS 2022, C++ workload),
Release | x64 → `bin\64\simplewall.exe`, then run the Windows Sandbox
bench (`tools\hardening-sandbox.wsb`) for runtime checks.

## Round-1 regression (RSK-05)

The fail-safe rules posture is untouched: compiled-in internal rules
remain the floor, no on-disk override, no updater rules component — the
rules/language unification is Round 3 by design.
