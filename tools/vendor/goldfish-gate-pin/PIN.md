# goldfish-gate vendor pin

- Pinned version: 0.2.0 (source commit 5e31480, upstream repo
  github.com/PhilopaterSh/goldfish-gate — PRIVATE, hence this vendor pin;
  S2C2F pin+verify posture, same as vendor/routine).
- Why 0.2.0 and not HEAD (0.3.2): every chain in docs/specs was
  gate-validated with 0.2.0; the local CLI is also 0.2.0. Upgrading the
  pin is an OWNER action: bump here, re-run goldfish check on all four
  chains locally, note the upgrade in the retrospective ledger.
- CI installs from this directory (smoke-test.yml Chain gates step) —
  no network dependency on the private upstream repo.
