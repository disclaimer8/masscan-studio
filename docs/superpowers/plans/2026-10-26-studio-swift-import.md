# Historical plan — CANCELLED: Swift-history import

Superseded by the user on 2026-10-26. Swift is permanently retired. Do not restore
this importer. See 2026-10-26-studio-native-profiles.md.

Authorized continuation after PR #16. Work in `masscan-studio-app`, branch
`feat/studio-swift-import`, baseline `6ea6efd`. Claude owns rmasscan; no engine,
adapter, lab, root install or raw-gate changes are part of this slice.

Spec: `docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`, §7.
Swift schema source: archived commit `b02dd29`, ScanSession/ScanProfile,
ScanConfiguration, PortResult, HostInspection. The Swift sources no longer live
in main. Import is an explicit macOS action, never a startup migration of sources.

## Contracts

- Select the old data directory after closing Swift. Read stable snapshots of
  both sessions.json and profiles.json; missing/changed/symlinked/nonregular,
  oversized, malformed or invalid files fail without importing either file.
- Validate full inputs before a single transaction. Bounds: sessions 32 MiB,
  profiles 4 MiB, 10,000 sessions/profiles, 100,000 total result rows. Report errors.
- Swift dates are seconds since 2001-01-01; retain fractional seconds. Preserve
  exact u64 seed/resumeIndex and original record JSON, including unknown fields;
  report unknown fields. Only IPv4/TCP records supported in this slice; reject
  other protocols explicitly instead of relabelling them.
- Idempotency key: Swift origin + record kind + canonical UUID, independent of
  source directory. Canonical record fingerprints ignore object-key order and
  whitespace. Same record skips; changed record conflicts without overwriting.
- Imported results are real archived observations, never simulation fixtures.
  Active statuses recover to Interrupted; pending DNS to not-checked. A legacy
  Paused status/index is retained but cannot resume in rmasscan. Start and Resume
  reject the import backend independently of UI controls. No scan starts on import.
- Preserve name/date/log/percent/config/results/inspection/evidence. Deduplicate
  identical endpoint keys with a visible count; retain originals in archive JSON.
- Imported profiles are selectable to fill the new-scan form; loading is not
  running. Old interface/checkpoint are shown as legacy metadata, not used as
  a current raw binding. Explicit user start still goes through current gates.
- Additive schema v3 migration uses a consistent SQLite backup first, then one
  transaction. Originals are read-only; test against disposable destination DBs.

### Task 1: Snapshot and decoder

Write RED tests for dates, exact u64, statuses, optional fields, inspection,
malformed files, full-file validation and stable source bounds. Implement Rust
parser in studio-store::legacy; no subprocesses, no network, no Python.

### Task 2: Transactional archive/history/profile storage

RED tests for v2 migration/backup, source preservation, idempotency after source
copy, conflicts, duplicate endpoints, transaction rollback and resume refusal.
Implement migration, atomic import report and saved metadata/profile access.

### Task 3: Controller and macOS UI

Manual Import Swift… flow with close-Swift notice, directory chooser, background
work and durable report. Disable import during scans; controller enforces it.
Show imported labels/details; profile selection fills settings without starting.
Unit/integration tests for rejection during scan, no runner/network on import,
and imported history selection/Resume refusal. Linux/Windows have no import UI.

### Task 4: Verification and review

Run Studio suite/clippy/fmt, build a signed Mac package, exercise import with a
synthetic source and repeat it to verify skip reporting. Read real Swift files
only into a disposable test destination, if present; verify before/after hashes.
Run native Windows/Linux or three-OS CI for shared crate/API changes. Fresh review
of snapshot races, exact integers, migration/rollback, source integrity and
incompatible-resume gate. Fix important findings, record evidence and commit.
