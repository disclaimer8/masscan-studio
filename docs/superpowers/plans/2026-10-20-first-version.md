# Masscan Studio Implementation Plan

**Goal:** Install a working local macOS GUI for masscan.
**Architecture:** Shared validated scan model, native SwiftUI app, narrow privileged
process runner with authenticated loopback event stream.
**Tech Stack:** Swift 6 compiler in Swift 5 mode, SwiftUI/AppKit, Foundation, Network.
**Spec:** ../specs/2026-10-20-masscan-studio-design.md

## Constraints
- macOS 14+, no downloaded dependencies, installed masscan 1.3.2 compatibility.
- No passwords in app storage, no root UI, no arbitrary shell command field.
- Explicit targets; validation sends no packets; one running job.

## Review focus
- Untrusted range/interface text must never become command options.
- Partial and combined stdout/stderr chunks must retain complete records.
- Cancellation, app exit, and lost transport must stop the child.
- Pause must preserve seed and resume position, including after relaunch.
- Interrupted history and failed export must not appear successful.

## Tasks
- [x] Core: ScanConfiguration validation/argument construction; result and
  progress parser; framing; CSV serializer. Tests in Tests/ScanCoreTests.
  Run `swift test` before and after implementation.
- [x] Runner: fixed executable resolution, temporary work directory, socket
  handshake, stdout/stderr events, SIGINT and timeout shutdown, checkpoint.
  Test using actual installed masscan with `--echo`, no elevated scan.
- [x] App: observable session store, profiles, history, config sheet,
  sortable/filterable table, summary, diagnostics and export.
  Exercise real validation and empty/error states through the native UI.
- [x] Package: build release executables into dist/Masscan Studio.app,
  ad-hoc sign, run all tests, inspect UI, install in ~/Applications.
