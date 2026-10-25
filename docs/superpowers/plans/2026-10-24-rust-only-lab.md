# Rust-only laboratory tooling

User decision: all active rmasscan tooling and tests use Rust; remove Python runtime dependencies.
Authorization: implement the migration, preserving existing scanner behaviour and test evidence.

## Architecture

Add workspace crate `rmasscan-lab`, library and binary. Subcommands replace the existing Python entry points:
`verify-wire`, `windows-verify`, `vm-lab`, `peer`, `capture`, `wire-suite`, `windows-suite`, `oracle-fixtures`.
Platform command invocation uses argument arrays. External system tools (ssh, ip, tcpdump, compiler for the
independent C oracle) remain tools, never interpreters for application logic. PowerShell remains only the
existing Windows system integration until its migration is explicitly scoped; no Python may be launched.
Historical evidence scripts remain immutable records, not current entry points. The original Swift project
and its historical helper tests are outside this rmasscan migration.

## Constraints and review focus

- Preserve FAIL / INVALID / NOT RUN / PASS, exact bytes, unknown counters and all current acceptance checks.
- Verify capture interfaces/filters, checkpoint contents and requested scan identity, not only file presence.
- A failed guest check must never reuse a previous successful report. Bind reports to individual runs.
- Restrict and contain scratch paths; quote external shell boundaries, no arbitrary deletion paths.
- Namespace ownership failures must roll back only objects created by that operation.
- No live scans, network reconfiguration, merge or push as part of offline implementation validation.
- `rmasscan-net` remains the unsafe OS boundary. New lab orchestration is safe Rust.

## Tasks and ownership

1. Verifier: `rmasscan-lab/src/{verify,pcap}.rs` plus verifier tests. Replace verify-wire and windows_wire_verify.
   Start with failing packet/evidence regression tests; replay preserved evidence and deliberate mutations.
2. Lab and peer: `rmasscan-lab/src/{vm_lab,peer}.rs` and tests, optional confined net OS helper.
   Port isolation, ownership, status, TCP listeners, injection, flooding and QMP controls. Mock commands in tests.
3. Suites: `rmasscan-lab/src/{wire_suite,windows_suite,oracle}.rs` and tests.
   Port Linux/Windows orchestration and independent oracle fixture collection; fix freshness/path defects.
4. Integration: Cargo manifests, dispatcher, capture module, existing shell entry points, Rust test callers,
   CI and current docs. Remove superseded active Python files only after equivalent Rust tools pass.
5. Validation: workspace tests, Clippy, archived evidence replay, native Windows build/tests, independent review.

Shared CLI boundary: each module exposes `pub fn run(args: &[String]) -> Result<i32, String>`.
The coordinator owns Cargo files, `lib.rs`, `main.rs` and shared integration. Modules own their internal tests.
No worker commits or changes another worker's files. Reuse the existing workspace at stage2b-win.

## Completion

Active rmasscan commands, tests and CI run without Python installed. Saved evidence hashes do not change.
Passing offline tests does not imply rerun live Windows/Linux acceptance; record the distinction.

Implementation and native offline validation completed on 2026-10-24. See
[verification report](../../experiments/2026-10-24-rust-only-lab.md) for exact
source snapshot, test counts, review fixes and remaining live-acceptance boundary.
