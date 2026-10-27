# Studio runner setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Install the runner matching the running Studio build through an explicit UI action on macOS, Linux and Windows.

**Architecture:** A platform setup object hashes and validates the bundled runner, checks the existing immutable installation and invokes the existing install script through the OS elevation mechanism. The app controller serializes setup with authorization/scanning; Slint presents a separate setup panel. Installation never opens an adapter or authorizes a scanning session.

**Tech Stack:** Rust, Slint, existing OS shell/PowerShell integration; no new dependencies.

**Spec:** This document's bounded design below extends `studio/AUTHORIZATION.md`'s hash-addressed personal installation contract. Existing raw gates and engine behavior remain unchanged.

## Global Constraints

- Claude owns rmasscan discovery/engine changes; this branch changes Studio only.
- Explicit Install click before elevation; no startup elevation, permanent service, driver installation or network traffic.
- Retain SHA-256 addressing, protected destination ownership, atomic installation and no overwrite. Verify after installation; failures never imply ready/authorized.
- macOS validates signature/system dependencies; Linux validates ELF system dependencies. Windows uses administrator-owned PowerShell 7 in Program Files, pinned during UAC and execution; no PATH lookup.
- Cancel stops waiting, not an asserted rollback of an elevated copy already underway. Explain that an outstanding OS dialog must be dismissed and installation may finish. Bound waiting to 180 seconds; close must remain responsive.
- Disable setup while scanning/authorized. Simulation remains usable without installation. Missing or invalid installation has actionable diagnostics.

## Review Focus

- Source changed between check and Install: hash recheck and post-copy verification refuse substitution.
- Broken destination, symlink/reparse or writable ancestor: never silently overwrite or mark ready.
- Cancel/close during OS prompt: worker returns promptly; late completion cannot authorize or scan.
- Queued actions during setup: no accidental scan/session starts after a long prompt.
- Windows paths with spaces, quotes and Unicode: direct executable invocation with CRT arguments, no mutable elevated script file.

### Task 1: Platform setup

**Files:** `studio/crates/studio-platform/src/setup.rs`, `lib.rs`, Windows `install.rs`, `uac.rs`; setup tests.

**Interfaces:** Produces `setup::Prepared::new(&Path, &AtomicBool) -> Result<Self,String>`, `installed() -> Result<bool,String>`, `install(&AtomicBool) -> Result<(),String>`; exposes read-only hash/path for diagnostics. Consumes existing script builders and trusted installation checks.

- [ ] Write tests for missing/invalid source, cancellation before work, source replacement before install, bounded command timeout/output and nonzero exit; Windows argument roundtrip with hostile paths.
- [ ] Run `cargo test -p studio-platform setup` in `studio`; expect RED for absent behavior.
- [ ] Implement setup using existing protected installers. Retain launcher/handle lifetime on Windows; reuse narrow native UAC call, not a public arbitrary elevation API.
- [ ] Run platform tests; expect GREEN. Commit platform implementation.

### Task 2: Controller and UI

**Files:** `studio/crates/studio-app/src/setup.rs`, `lib.rs`, `studio/crates/studio-ui/src/main.rs`, `ui/main.slint`.

**Interfaces:** Consumes Task 1. Produces explicit CheckSetup/InstallRunner actions and Setup update (busy, ready, installable, detail). A controller-side pending flag rejects competing commands while setup is in progress; cancellation is out of band.

- [ ] Write regression tests for check/install separation, missing runner without elevation, setup refusal while active/authorized and command queue gating. Expect RED before implementation.
- [ ] Add controller handler and Slint setup panel with Check, Install, Cancel waiting and Close. A completed installation requires a separate Authorize action.
- [ ] Run app tests and compile UI; expect GREEN. Commit UI/controller implementation.

### Task 3: Acceptance and documentation

**Files:** `studio/README.md`, `studio/AUTHORIZATION.md`, experiment record if live installation is performed.

- [ ] Run workspace tests, formatting and packaging; inspect UI and exact installed hash on Mac. OS prompt remains user-controlled. No live scan required.
- [ ] Document prerequisites, cancellation semantics and measured versus CI-only coverage. Update stale restart/guard acceptance pointers, preserving historical evidence.
- [ ] One fresh whole-branch review, one fix pass for material findings with regression tests; exact-head cross-platform CI before merge.

Windows UAC success and Linux polkit success require interactive hosts; CI compilation/offline tests do not substitute for those manual OS prompts. Record unavailable checks explicitly.
