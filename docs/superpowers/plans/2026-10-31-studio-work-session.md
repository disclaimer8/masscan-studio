# Studio Working Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task.

**Goal:** One macOS password prompt supports repeated isolated Studio helper and fixture runs during the work period.
**Architecture:** Audited, hash-pinned root task host; typed operations and lease-owned helpers; current Controller transport unchanged.
**Tech Stack:** Existing Rust/std/serde/libc/platform audit code, no new dependencies.
**Spec:** docs/superpowers/specs/2026-10-31-studio-work-session-design.md

## Global Constraints

One explicit start, persistent until stop; no generic shell or environment bypass; fixed reviewed tool/helper/caller hashes; no change to physical-network gates; preserve pending native evidence. Root runtime directory and server identity checked on every connection. Limit8 clients and16KiB frames.

## Review Focus

- Same uid but wrong executable, foreign uid, forged owner or stale pid must fail before helper spawn.
- Malformed/oversized JSON and arbitrary fixture arguments must fail before side effects.
- Disconnect or cancellation ends only its helper, not the work session or another job.
- A valid installed host cannot authorize a different helper hash or caller build.
- Stop must refuse active jobs and clean its own fixture/runtime only.

### Task1: Shared typed protocol and client integration
Files: new studio/crates/studio-platform/src/work_session.rs; macos.rs, lib.rs.
- [x] Add bounded request/response framing, fixed operation enums and validation tests (bad uid/hash/owner/nonce/length/unknown fields).
- [x] Authenticate root metadata/audit peer; request pinned helper and return lease. Missing session falls back; present broken session refuses.
- [x] Adapt macOS Authorized launcher ownership to subprocess or host lease, preserving direct runner peer verification, cancellation and Drop cleanup.

### Task2: Task host and CLI
Files: new studio/xtask/src/work_session.rs; main.rs.
- [x] Implement start/status/stop/fixture/export/serve commands; reuse reviewed installer and one immutable osascript snapshot.
- [x] Root host authenticates approved uid/caller, owns bounded helpers/jobs and root output records, serializes fixture operations.
- [x] Exercise rejected operations, child lease cleanup, stop-active refusal and repeated sequential client lifetimes without root/native packets in tests.

### Task3: Review and real one-prompt acceptance
- [x] Run affected tests, workspace tests, clippy/fmt; independent privilege-boundary review and fixes.
- [x] Record source/artifact hashes, install/start with one macOS prompt; verify two independent helper sessions without further prompts and retained host status.
- [x] Keep host available as requested; document status/stop commands and native limits. Guard test correction is separate from host functionality.
