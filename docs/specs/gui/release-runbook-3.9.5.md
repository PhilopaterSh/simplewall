# Release runbook — simplewall 3.9.5-hardened.1 (the Findings-5/10 release)

> EXECUTED 2026-11-21 (steps 2-9 done, step 1 = the owner merge click;
> the tag v3.9.5-hardened.1 was created by the release, release id
> 453415486; the feed on master = commits c4345621db + b44c068ddd; the
> post-CDN independent P-256 verify = PASS; the release-gate chain =
> verifier run 44863951090 ALL GREEN incl. hash+Authenticode on the
> released asset). The verification evidence: verifier-lane run
> 44860140693 (green) + every fix cited in testing-record.md
> Findings 5/8/10 and ledger row 47.

## Why this release is mandatory

The released v3.9.4-hardened.1 carries THREE latent heap-corruption
sites (the borrowed-finalstringbuilder dereferences in the ledger /
resolver / lockdown sidecar writes) — every write of those sidecars
poisons the heap (Founding 5 root 1). This release also carries the
Finding-8 freeze fix (packs_getpath UAF), the packstate round-trip
repairs (Finding 10: byte/char, HeapReAlloc-NULL, filter-line format,
mtime+SIZE key), and the honest-exit instrument.

## Version target

- Tag / release name: `v3.9.5-hardened.1` / "simplewall 3.9.5 — hardened
  composite fork (verification-green release)"
- The app's internal version: bump the rc version resource to 3.9.5.0.

## Steps

1. [OWNER] Merge PR #24 (green on the verifier lane at 8150f18e; the
   docs commit 6b39dac2 rides along).
2. [AGENT] Bump the version resource to 3.9.5.0 + commit on the branch
   the merge produced (or directly on master post-merge).
3. [AGENT] Build Release x64 (v143) + verify 0 err/0 warn.
4. [AGENT] Preflight gate (CI profile) — already wired into the
   verifier lane (run 13+); on the release exe the FULL profile runs
   at the signing step (Authenticode + parity + feed).
5. [OWNER] Grant the PFX access (or sign in-session): the v2 cert
   (FEC37DA0…344D) signs the exe — signtool from bash needs
   `MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*"` with SINGLE slashes.
6. [AGENT] Full preflight gate 9/9 PASS on the SIGNED exe (the
   release-authoritative checks: thumbprint match, version 3.9.5,
   parity, feed verify).
7. [DONE 2026-11-21] GitHub release `v3.9.5-hardened.1` (id 453415486) with the three assets:
   simplewall-3.9.5-hardened.1-x64.exe, simplewall.lng,
   SHA256SUMS.txt (same structure as the 450725439 release).
8. [OWNER] The feed private key (ECDSA P-256, off-repo) signs the new
   VERSION — OR: [AGENT] with the key granted in-session.
9. [AGENT] Update master's VERSION (3.9.5) + VERSION.sig; verify
   post-CDN (raw vs master vs the release hash — the row-40 lesson:
   expect ~5 min CDN delay, verify consistent-stale = fail-safe).
10. [AGENT] Tag v3.9.5-hardened.1 + push; update RESUME.md.

## Release notes (draft — ship as-is)

**EN**: simplewall 3.9.5 — hardened composite fork. Verification-green
release: the composite shell (RTL rail, adaptive countdowns, publisher
anchors, held-notification loop) is screenshot-proven and the in-binary
selftest passes with 0 failures. SIX root-cause fixes: the startup
freeze (a borrowed-pointer UAF), five latent heap-corruption sites in
the sidecar writers (ledger/resolver/lockdown states could corrupt the
heap on every write), the packstate round-trip (byte-length, filter
format, mtime+SIZE invalidation), snapshot heap growth, and the held
counter updates. The verifier lane (an Actions-independent CI judge)
proves every step green.

**AR**: إصدار التحقق الأخضر: القشرة المركّبة مثبتة بالصور والاختبار
الداخلي يمرّ بصفر إخفاقات. ستة إصلاحات جذرية: تجميد بدء التشغيل (UAF)،
خمسة مواقع فساد كامنة في كتّاب ملفات الحالة (كانت تُفسد الذاكرة مع كل
كتابة)، إصلاح round-trip لحالة الحزم، نمو اللقطات، وعدّاد التنبيهات
المعلّقة. سكة تحقق مستقلة عن Actions تُثبت كل خطوة خضراء.
