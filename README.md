<h1 align="center">simplewall — hardened composite fork</h1>

<p align="center">
	<a href="https://github.com/PhilopaterSh/simplewall"><img src="https://img.shields.io/github/license/PhilopaterSh/simplewall?style=flat-square" /></a>
	<a href="https://github.com/PhilopaterSh/simplewall/actions/workflows/smoke-test.yml"><img src="https://img.shields.io/badge/CI-smoke--test-blue?style=flat-square" /></a>
	<a href="https://github.com/PhilopaterSh/simplewall/issues"><img src="https://img.shields.io/github/issues-raw/PhilopaterSh/simplewall.svg?style=flat-square&label=issues" /></a>
	<a href="https://github.com/henrypp/simplewall"><img src="https://img.shields.io/badge/upstream-henrypp%2Fsimplewall-blue?style=flat-square" /></a>
</p>

<p align="center">
	<i>The lightweight WFP firewall you know — hardened, audited, and evolving into a composite security tool.</i>
</p>

---

> ### Attribution (GPL-3.0)
> This is a fork of **[simplewall](https://github.com/henrypp/simplewall)** by **Henry++** — © 2016-2026 Henry++.
> All credit for the original application belongs to upstream. This repository carries the upstream GPL-3.0 license
> and publishes every change openly. Upstream website: [henrypp.org](https://www.henrypp.org/product/simplewall).

## What is this fork?

A hardened and audited evolution of simplewall: the same tiny, user-space, no-driver WFP firewall — with its
trust boundaries fixed, its updater rebuilt around signed releases, and a composite feature roadmap designed
through a formal design-gate process (see [Engineering discipline](#engineering-discipline)).

**Current status:** based on the upstream 3.9.x line, with 3 hardening/audit rounds completed, every fix
verified by fresh-context code reviews, and the first interactive build validated on Windows 11 x64.

### Verified build

| | |
| --- | --- |
| Binary | `bin/64/simplewall.exe` (~1.0 MB) |
| SHA256 | per-commit — authoritative hashes ship in each **release manifest** (the tree moves fast; trust the signed manifest, not this file) |
| Built with | MSVC 14.44 (v143), Windows SDK 10.0.26100 |
| CI | smoke-test workflow on every push (build + launch + 20s lifetime check) |
| Audited | 2026-11-07 — independent fresh-context reviews (vendor + src + design-gate seam) + cppcheck (0 findings) |

## Differences from upstream

| Area | Upstream | This fork |
| --- | --- | --- |
| Enforcement failure | Silent log entries | **Visible degraded-enforcement state** on tray/status + tri-state transaction (applying-never-sticks) |
| Internal rules | On-disk override possible | **Compiled-in resource only** — attacker-writable override removed, foreign files logged as ignored |
| Log viewer | Elevated launch (LPE class) | **De-elevated via shell token** — refuse + log on failure |
| Privileges | Multiple SE_* held for lifetime | **SE_INC_BASE_PRIORITY only**; SE_DEBUG on-demand around the kill path |
| Windows Update fix | Rewrites `System32\wusvc.exe` | **Original ImagePath preserved and restorable** with a guard |
| Notification window | Ungated action messages | **All action branches gated** (enabled/visible check) |
| Log file | Default ACL | **Explicit user+admins DACL** + migration for existing files |
| Updates | Vendor transport (CA-ignore retry, unsigned URLs) | **Fail-closed TLS + ECDSA P-256 signed manifest + artifact SHA256** — unsigned content never executes |
| Vendored library | n/a (submodule) | **In-tree, ABI-aligned** (every internal caller verified against the fork contract — see audit) |

## Roadmap — the composite

Designed and approved through the gate process (`docs/specs/composite/`), implemented in phases:

- **Phase 1 — trust-aware prompting & packs** *(next)*
  Security-audit-event prompt pipeline (5157) with automatic fallback and a visible prompt-degradation state •
  pre-prompt auto-tiers • **publisher (Authenticode) rules** that survive app updates • decision durations
  (once / until restart / always) • **single-flight prompting** • guarded **Lockdown mode** with recorded-snapshot
  rollback • **signed rule packs** (Ed25519-class verification, anti-rollback) from a separate packs repository.
- **Phase 2 — accountability & scale**
  Audit ledger (detect/quarantine foreign firewall-rule changes, GPO-aware) • sorted-array blocklist engine
  (2M entries/zone) • incremental filter apply.
- **Phase 3 — domain layer (no driver)**
  Per-app domain-level filtering via local resolver ownership + ETW DNS attribution • DoH/DoT • DNS-leak prevention.

## Features (inherited from upstream)

- Simple interface; rules editor (IP/ranges/CIDR/ports, global and per-app rules)
- Built-in telemetry blocklist (WindowsSpyBlocker-based; 1,496 entries)
- Dropped/allowed packet logging with notifications (win7+/win8+)
- WSL, Windows Store (UWP) and per-service (svchost) filtering
- IPv6, localization, portable mode (`simplewall.ini` beside the exe), free and open source

## System requirements

- Windows 7 SP1 … 11, 64-bit (x64 builds verified; ARM64 project configuration available)
- SSE2-capable CPU; no external dependencies

## Performance & footprint (measured, honest)

Published as measured, not aspirational (2026-11-10, x64 Release, Win11 26H2, idle with main window loaded):

- Idle working set: **~48 MB** steady across repeated samples (no growth in short-run observation).
- Zero idle CPU when no connection events fire (event-driven; no polling loops).
- Long-run soak (#2135-class memory growth) is an open watch item — see `docs/BACKLOG.md`.

Comparison anchors: Portmaster reports 600 MB+ baseline with documented leak issues (safing/portmaster#1870);
the composite goal is the lowest footprint in the class, and the number above is updated with every release.

## Build from source

```bat
git clone https://github.com/PhilopaterSh/simplewall.git
cd simplewall
msbuild simplewall.sln -p:Configuration=Release -p:Platform=x64 -p:PlatformToolset=v143 -restore
```

The support library is vendored in-tree (`vendor/routine/`) — no submodule step needed.
Requires VS 2022 Build Tools with the C++ workload.

## Command line

```
-install          enable filtering
-install -temp    enable filtering until next reboot
-install -silent  enable filtering without prompt
-uninstall        remove all installed filters
```

## Uninstall — safe by design

This fork asks **keep-or-release** during uninstall while filters are active (default: full revert),
and intentionally disabling the firewall clears the degraded-state flag — you are never left with
silent filters or a misleading status. (Upstream guidance: filters persist until "Disable filters"
is pressed — this fork automates the decision.)

## Rule syntax

Same engine, same syntax as upstream: IPs (`192.168.0.1`), IP:port (`192.168.0.1:443`),
ranges (`192.168.0.1-192.168.0.255`), CIDR (`192.168.0.0/16`, `fe80::/10`), ports and port ranges
(`443`, `49152-65534`), semicolon-separated. See upstream documentation for the full CIDR tables.

## FAQ

**Is it safe to run alongside Windows Firewall?**
Yes — this tool configures WFP directly and works independently; both firewalls can coexist.

**Are filters active when the app is closed?**
Yes — installed filters persist in the system regardless of the process.

**How are releases verified?**
Release artifacts ship with a SHA256 hash and a signature over the update manifest
(ECDSA P-256); the app itself refuses to apply any update that fails verification (fail-closed).

**Is the blocklist configurable?**
Yes — `Settings -> Blocklist` per-category enable/disable; signed pack support (Phase 1) adds
community-maintained, tamper-evident lists on top.

## Engineering discipline

Every feature and fix in this fork passes through a machine-checked design-gate workflow
([goldfish-gate](https://github.com/PhilopaterSh/goldfish-gate)): an approved design, a fresh-context
review, human approval, and traceability keys that must survive into spec, plan and tasks
(`docs/specs/`). The 2026-11-07 audit ran two independent fresh-context reviews over the full delta
(vendor: *patch-set-sound*; src: all fixes verified) plus cppcheck (0 findings).

## Credits

- **Henry++** — original simplewall ([upstream](https://github.com/henrypp/simplewall))
- **WindowsSpyBlocker** — telemetry blocklist data
- **goldfish-gate** — design-gate workflow (same author, this fork)

## License

GPL-3.0 — see [LICENSE](LICENSE).
© 2016-2026 Henry++ (upstream). Fork changes © 2026 PhilopaterSh.
