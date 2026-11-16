# Design: Round 2 — Routine Hardening & Secure Updater

> Revision `2026-11-07-r4` — compliance amendment (2026-11-07): commit
> 26a69775 (PR #3, "THE DEAD FEED") fixed 5 stacked bugs that made the
> signed update feed **unverifiable on every machine** — every update
> attempt was fail-closed forever. Discovered during the owner's
> site-parity request; shipped BEFORE running the chain (gate bypass,
> caught by the owner's compliance question) — this amendment + a
> fresh-context goldfish review of the 26a69775 diff is the mandatory
> retrospective reconciliation. The five fixes, mapped to decisions:
>
> 1. **Byte-exact transport (extends DEC-05, "exact feed bytes"):**
>    `R_DOWNLOAD_INFO` gains `is_bytes` mode (rtypes.h) — the old path
>    converted every download through `RtlMultiByteToUnicodeN` (ACP), so
>    the manifest was hashed as UTF-16LE while update-signer.ps1 signs
>    raw file bytes; the 64-byte raw r||s signature expanded to 128
>    bytes of WCHARs (plus lossy ACP undefined bytes) and tripped the
>    64-byte length check. Manifest AND detached .sig now download
>    bit-exact; the verified bytes are converted to a parseable string
>    only AFTER signature success (ASCII feed = 1:1).
> 2. **Endianness contract (extends DEC-05 blob spec) — CORRECTED by
>    the follow-up review below:** CNG ECDSA blobs and signatures are
>    BIG-endian (not little-endian as first assumed); update_key.h
>    X||Y big-endian and the .NET P1363 r||s signature both copy
>    VERBATIM — proven by tools/cng-signature-bench.py (see follow-up).
> 3. **Key integrity from ground truth (extends DEC-05 key spec):** the
>    committed public key was transcription-corrupted from its very
>    first commit (db1ef855 — y-half missing one nibble + one inserted
>    byte → off-curve point, import fails). Header rewritten from
>    D:\CV\Github\.keys\simplewall-signing.json; **new runbook rule:
>    key material in-tree is NEVER trusted — it is always re-derived
>    from the off-repo JSON at keygen/sign/verify-bootstrap time.**
> 4. **EOL pinning for the feed (extends DEC-03 feed origin):**
>    VERSION.sig was signed over CRLF worktree bytes while
>    raw.githubusercontent.com serves LF — re-signed over exact LF
>    bytes; .gitattributes pins `VERSION eol=lf` + `*.sig binary`.
> 5. **Verification evidence (extends T015 pattern):** independent
>    pure-math ECDSA P-256 verification (positive PASS; tampered feed
>    REJECTED; tampered sig REJECTED) + .NET VerifyData cross-check.
>    Verified in-binary: corrected BE key bytes embedded, corrupted
>    bytes absent (exe SHA256 2eba6894…e2c76c, Authenticode Valid).
>
> Known deferred item (owner decision pending): feed CONTENT still
> points at upstream artifacts — repoint to fork releases + re-sign at
> first release.
>
> Prior r3 content unchanged (r3 = retrospective amendment for the
> crash class: DEC-04 covers every caller in the vendored tree;
> T014 patch set F9-F13, T015 dual fresh-context goldfish audits).
> Owner policy input: the updater keeps working, fail-closed and signed.
>
> **r4 follow-up — fresh-context goldfish review of 26a69775 (VERDICT:
> BLOCK, findings integrated the same day):** the review's BLOCKING
> claim ("CNG wants little-endian signature halves") was REFUTED
> empirically — a CNG bench (tools/cng-signature-bench.py, RSK-04 gate)
> proves CNG ECDSA wants BIG-endian for both the ECCPUBLICBLOB (verbatim
> import = STATUS_SUCCESS; LE halves = 0xC000000D) and the P1363 r||s
> signature (verbatim verify = STATUS_SUCCESS; LE halves = 0xC000A000;
> tampered = rejected). Consequence: the r4 "endianness fix" was itself
> a regression (it broke BCryptImportKeyPair) and is REVERTED — the key
> copies verbatim, matching the header and the signature convention.
> The review's MAJOR findings are real and fixed: (a) zero-byte 200
> response dereferenced a never-allocated buffer in the bytes-mode
> shrink-to-fit — now fails closed (empty/truncated/Content-Length-unmet
> responses return STATUS_UNSUCCESSFUL); (b) the stringbuilder leaked
> ~32KB per bytes-mode download — now initialized only for string mode;
> (c) Content-Length-derived preallocation is clamped to 1MB (server-
> controlled value). MINOR findings pinned: union-slot cleanup invariant
> documented in _r_inet_destroydownload; truncated-download vs
> signature-fail diagnosis improved; pre-existing _r_update_navigate
> icon-param misuse (rapp.c, inherited from upstream import) logged as
> a follow-up. Rebuilt + re-signed: exe SHA256 03c4c0d4631dae927597871d
> 3a9ce8c08b45cce101bff1f2b835238656b04ec0 (Authenticode Valid). The
> CNG bench is now the standing RSK-04 gate (exit 0 required).

## Problem and intended outcomes

The fork builds against a shared utility library whose update/transport
chain is MITM-exploitable end-to-end today: TLS CA validation is silently
disabled on retry (routine.c:14209), the updater trusts a server-sent
`name=ver|url;` line for both version and download URL with no
signature/hash/host-pinning and executes the downloaded installer elevated
(rapp.c:2289, 2826), and the download→move step is a TOCTOU race in a
user-writable cache dir (rapp.c:2098). Additionally the public library
master is a different ABI from what this fork calls (setprocessprivilege /
createfile argument shapes), so builds cannot float on master.

Intended observable outcomes:

1. The update chain is **fail-closed at every step**: transport (HTTPS,
   no CA-ignore), integrity (signature by an embedded public key + sha256
   + monotonic version), and landing (atomic, exclusive, reparse-proof).
2. The updater **keeps working** in the fork — pointed at the fork's own
   signed feed instead of upstream's unsigned one (FR/NFR-01).
3. The library is **vendored and pinned** inside this repo (S2C2F
   pin+verify), patched for the audited findings, with compile-time arity
   guards on every consumer API.

## In scope and out of scope

- **In scope:** a vendored copy of `routine` (src) inside this repo under
  `vendor/routine/` (include path updated in `simplewall.vcxproj`);
  patches F1–F6 (+ the four LOW hygiene fixes) from the audit; a
  signature scheme over the update manifest using Windows CNG (BCrypt,
  ECDSA P-256, detached `manifest.sig`); bootstrap tooling to generate
  keys and sign manifests; `C_ASSERT` arity/type guards for the
  fork-dependency API list.
- **Out of scope:** auditing/patching upstream's own released binaries;
  switching update UI/UX; porting routine's non-consumed modules;
  TUF/WinSparkle/Omaha adoption (see DEC-02 alternatives); RSK-04
  (main-window message surface) — separate round; **rules/language
  update unification — deferred to Round 3** (Round-1's fail-safe
  posture: compiled-in rules are the floor, no on-disk override, stays
  exactly as shipped in Round 1; see RSK-05).

## User journeys and behavior

1. **Update check (fork feed):** the app fetches a signed manifest from
   the fork's release host over HTTPS. A TLS secure failure aborts (no
   retry-with-ignore). The manifest (`manifest.json`: version, url,
   sha256, key-epoch) is fetched from the pinned/validated manifest
   origin; its detached `manifest.sig` (ECDSA P-256, raw 64-byte r||s
   over the exact manifest bytes) is verified against the embedded public
   key, plus version monotonicity against the installed one. A valid
   manifest triggers download; an invalid one is logged and dropped
   (FR-01..03, SEC-01).
2. **Artifact landing:** artifacts are fetched from wherever the release
   host serves them (GitHub redirects included) but are **untrusted until
   the manifest sha256 passes** — integrity, not origin, is the artifact
   trust anchor. The download lands in a cache file held with an
   exclusive handle through the download+hash window, atomically renamed
   via `FileRenameInformation` on the open handle; only after integrity
   passes may it be re-opened by path (installer exec); the cache
   directory carries a restrictive DACL and opens use
   `FILE_OPEN_REPARSE_POINT` + final-path verification (FR-04, FR-07,
   SEC-02).
3. **Every verification failure is logged fail-visibly** (OPS-01) and
   never degrades into "use it anyway".

## Constraints and quality attributes

- The updater keeps working end-to-end in the fork against the fork feed
  (NFR-01) — no feature removal.
- No new third-party crypto dependency: signatures use Windows CNG
  (`BCrypt*`, ECDSA P-256) already available to MSVC builds (NFR-02).
- MSVC build stays green; vendored routine aligns to the fork's expected
  ABI (DEC-04) so the master-staleness mismatch is resolved by pinning,
  not by shimming (NFR-03).
- The signing private key never lives in this repo; loss/rotation
  procedure documented (DATA-01, RSK-02).

## Proposed decisions (pending approval)

- DEC-01: vendor `routine` inside the fork repo (`vendor/routine/`),
  pinned by commit snapshot in-tree — single audit unit; include path
  updated; no float-on-master submodule (S2C2F pin+verify).
- DEC-02: signatures via Windows CNG ECDSA P-256 (BCrypt) — no new crypto
  code to audit. Alternative rejected for now: vendored Ed25519
  (orlp/ed25519-class) — smaller tables but new crypto to maintain; may
  be revisited if CNG proves awkward for detached signatures.
- DEC-03: the fork's update feed = `PhilopaterSh/simplewall` GitHub
  releases carrying `manifest.json` + detached `manifest.sig`; upstream
  henrypp feed is no longer consulted by the fork (fork is its own
  source of truth). The manifest origin is pinned/validated; artifact
  URLs are untrusted until sha256 passes (GitHub redirects to
  objects.githubusercontent.com are therefore acceptable by design).
- DEC-04: vendored routine is aligned to the fork's expected ABI — the
  guarded contract is exactly these two call shapes: 5-arg
  `_r_sys_setprocessprivilege(hwnd, handle, privs, count, enable)` and
  `_r_fs_createfile(&handle, &path, ...)` out-handle-first — with
  `C_ASSERT` guards against regressions (goldfish-verified consumer call
  sites: src/notifications.c:464, src/main.c:1837, src/db.c:912,
  src/log.c:100).
- DEC-05: canonical detached signature form — `manifest.sig` is a raw
  64-byte ECDSA P-256 signature (r||s) over the exact bytes of
  `manifest.json`; the public key is embedded as a
  `BCRYPT_ECDSA_PUBLIC_P256_MAGIC` blob (little-endian X/Y) and verify
  takes the precomputed SHA-256 digest of the manifest bytes (no DER, no
  prehash flag). RSK-04's test vectors pin this normalization.

## Risks and open questions

- RSK-01: the fork stops auto-tracking upstream releases (intentional
  under DEC-03; upstream must be merged manually by the owner).
- RSK-02: loss of the signing private key blocks further updates until
  the embedded public key is rotated (a new app release); rotation
  procedure: key-epoch field in the manifest + documented regeneration
  runbook (DATA-01).
- RSK-03: vendoring means upstream routine fixes must be merged manually
  into `vendor/routine/` — mitigation: the audit report doubles as the
  patch baseline; upstream diffs reviewed per release.
- RSK-04: CNG detached-signature plumbing (BCryptImportKeyPair blob
  format, raw r||s vs DER normalization, digest-only verify) must be
  exercised with test vectors before the updater is enabled — bootstrap
  script ships with self-test.
- RSK-05: Round-1's promised signed internal-rule packages are DEFERRED
  to Round 3 (goldfish blocking finding: a signed package landing in a
  user-writable location would reopen Round-1's SEC-02 hole unless
  load-time re-verification, additive-only semantics, and explicit
  supersession are designed in). Round-1's fail-safe posture remains
  the shipped behavior; DEC-03 Round-1's "Round 2" promise is hereby
  consciously superseded by this deferral.

## Traceability Key

| Key | Meaning |
| --- | --- |
| FR-01 | transport never ignores TLS secure failures; CA/CN/date errors abort the update |
| FR-02 | manifest fetched only over HTTPS from the pinned/validated manifest origin; artifact URLs untrusted until the manifest sha256 passes (GitHub redirects acceptable by design) |
| FR-03 | every artifact verified before use: detached ECDSA manifest.sig (raw r||s over exact manifest bytes) against the embedded public key + sha256 of the artifact + monotonic version |
| FR-04 | cache file held with an exclusive handle through the download+hash+rename window (FileRenameInformation on the open handle); re-open by path allowed only after integrity passes |
| FR-05 | variable-size registry queries use a bounded retry loop on ResultLength |
| FR-06 | config object body is referenced while holding the lock protecting it |
| FR-07 | update-path file opens use FILE_OPEN_REPARSE_POINT plus final-path verification; cache dir has a restrictive DACL |
| FR-08 | LOW-hygiene set: REG_SZ zero-length guard, swapreference order, quoted installer args, INI values bounded with a documented truncation limit |
| FR-09 | routine vendored and pinned in-tree; include path updated; no float-on-master |
| FR-10 | C_ASSERT arity/type guards exist for the consumer-dependency API list |
| SEC-01 | update chain fail-closed at transport, integrity, and version steps |
| SEC-02 | no attacker-writable path participates in the update chain (cache dir DACL) |
| NFR-01 | updater fully functional in the fork against the fork's signed feed |
| NFR-02 | no new third-party crypto dependency (CNG BCrypt ECDSA P-256) |
| NFR-03 | MSVC build green with vendored routine aligned to the fork ABI |
| DATA-01 | key generation/rotation runbook documented; private key never in repo |
| OPS-01 | every verification failure logged fail-visibly |
| DEC-01 | vendored in-tree routine (vendor/routine), pinned snapshot |
| DEC-02 | CNG ECDSA P-256 signatures (alternative: vendored Ed25519, rejected for now) |
| DEC-03 | fork feed = PhilopaterSh releases + signed manifest; upstream feed dropped |
| DEC-04 | vendored routine adopts the fork ABI (resolves master mismatch) |
| DEC-05 | canonical detached signature: manifest.sig = raw 64-byte ECDSA P-256 (r||s) over exact manifest.json bytes; embedded BCRYPT_ECDSA_PUBLIC_P256_MAGIC key; verify on precomputed SHA-256 digest |
| RSK-01 | upstream auto-tracking stops (manual merges) |
| RSK-02 | signing key loss blocks updates until rotation (documented runbook) |
| RSK-03 | upstream routine fixes merged manually into the vendor copy |
| RSK-04 | CNG import/verify normalization (blob format, raw r||s vs DER, digest-only) proven by test vectors before updater enable |
| RSK-05 | rules/language unification deferred to Round 3; Round-1 fail-safe rules posture stays shipped behavior (supersedes Round-1 DEC-03's Round-2 promise) |
