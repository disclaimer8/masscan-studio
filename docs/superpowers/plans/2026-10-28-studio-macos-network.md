# Studio macOS Network Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Scan home-network devices and owned remote IPv4 servers through a real macOS Wi-Fi/Ethernet interface from Studio.

**Architecture:** Reuse the existing OS discovery seams, add immutable per-target Ethernet destinations, and prepare a bounded physical-network plan in the authenticated helper. Persist that plan with checkpoint provenance, then expose it through the existing Studio lifecycle.

**Tech Stack:** Rust 1.99.1, current main Cargo locks, Slint 1.18.1, SQLite, macOS BPF. No new third-party dependency is planned.

**Spec:** `docs/superpowers/specs/2026-10-28-studio-macos-network-design.md`

## Global Constraints

- First release accepts IPv4 addresses, ranges and CIDRs, and TCP ports; no hostname resolution, IPv6/UDP or tunnel/loopback scanning.
- At most 1,024 effective target addresses and 1,048,576 probes; all TCP ports
  1–65,535 are available, with at most 1,000 SYN packets/s; initial rate 100 packets/s.
- Opening settings, checking a route, installing or authorizing the helper never sends ARP or TCP packets.
- ARP: at most three requests per next hop, at least one second apart, at most 100 ARP frames/s, 35-second total deadline, 50 ms adapter I/O limit.
- Existing single-MAC identity bytes/checkpoints, feth behaviour and Simulation remain compatible.
- Unit tests use injected fake adapters, routes, interfaces and clocks; they never open BPF.
- The separate `masscan-studio-autodetect` worktree is read-only for this work.
- Keep physical raw scanning gated in merged/distributed builds until documented acceptance. An unmerged, explicitly identified acceptance candidate enables the production gate. Never infer live targets from a route lookup.
- Retain MAX_FRAME=131072; compact network report/checkpoint blobs are at most 24576 bytes, with worst-case outer JSON size validated before ARP.
- Route/interface observations are cancellable with absolute deadlines: ten seconds for full preflight, three seconds for guard, one second per Darwin lookup; retry/poll slices are at most 50 ms.

## Review Focus

- A /24 contains addresses that do not answer ARP: report them as not scanned and keep TCP counts honest (tasks 2–4).
- Target endpoints can share a route while an interior address follows a VPN: inspect every bounded effective target (task 2).
- Stop arrives while ARP or database acknowledgement is pending: no delayed scan can start (tasks 3–4).
- A resume uses a different MAC map or a formerly missing host appears: do not change the frozen scan implicitly (tasks 1, 3–4).
- Old installed helpers and old stored jobs remain present: version refusal and legacy read compatibility need explicit tests (tasks 3, 5).

---

### Task 1: Discovery reuse and immutable destination maps

**Files:**
- Import selected networking modules and tests under `rmasscan/crates/rmasscan-net/` from `feat/rmasscan-autodetect` at `e2a3352`; exclude CLI/lab changes.
- Modify `rmasscan/crates/rmasscan-core/src/probe.rs`.
- Modify `rmasscan/crates/rmasscan-engine/src/identity.rs`.
- Test in the existing core probe and engine identity/checkpoint test suites.

**Interfaces:**
- Consume existing `AdapterBinding`, `EffectiveConfig`, `RouteTable`, `Interfaces` and `AdapterPair`.
- Produce `ReadyPlan::with_destinations(effective: EffectiveConfig, binding: AdapterBinding, destinations: BTreeMap<u32, [u8; 6]>) -> Result<ReadyPlan, PlanError>` and `ReadyPlan::destinations() -> Option<&BTreeMap<u32, [u8; 6]>>`.
- Existing `ReadyPlan::new` and single-MAC identity output are unchanged.

- [x] Import the selected modules, recording donor commit and preserving main's dependency versions; compile and run `cargo test --locked -p rmasscan-net`.
- [x] Add failing tests for two on-link targets with different destination MACs, shared gateway MACs, missing/extra destination keys, invalid MACs, wrong link type and unchanged IP/TCP bytes.
- [x] Add failing identity/resume tests: map order is canonical, MAC changes alter digest, old single-MAC golden bytes are unchanged, changed map cannot resume.
- [x] Run the focused core/engine tests and record the expected failures.
- [x] Implement the constructor, frame destination selection and domain-separated map identity.
- [x] Run `cargo test --locked -p rmasscan-core -p rmasscan-engine -p rmasscan-net`, formatting and Clippy; commit the foundation.

### Task 2: Bounded route planning and cancellable neighbour discovery

**Files:**
- Create `rmasscan/crates/rmasscan-net/src/network_plan.rs` and `network_plan_tests.rs`.
- Create `rmasscan/crates/rmasscan-net/src/neighbours.rs` and `neighbours_tests.rs`.
- Extend prefix observations in `discover.rs` and OS interface modules/tests.
- Expose APIs through `rmasscan/crates/rmasscan-net/src/lib.rs`.

**Interfaces:**
- `PhysicalRoutePlan`: interface name/index, source IPv4/MAC, per-target next-hop IPv4, excluded endpoint reasons; equality compares the complete observation.
- `PhysicalTargets` retains normalized targets plus explicit singleton provenance and user exclusions. `plan_physical(targets: &PhysicalTargets, routes: &dyn RouteTable, interfaces: &dyn Interfaces, deadline: Instant, cancelled: &dyn Fn() -> bool) -> Result<PhysicalRoutePlan, NetError>` consumes bounded targets and never opens an adapter. Cancellable OS lookup methods use the same absolute deadline; legacy calls use bounded defaults.
- `resolve_neighbours(io: &mut AdapterPair, plan: &PhysicalRoutePlan, clock: &dyn Clock, cancelled: &dyn Fn() -> bool) -> Result<NeighbourReport, NetError>` returns a complete destination map plus unresolved on-link targets; unresolved gateway is an error.
- Constructor and input validation enforce the spec budgets independently of UI validation.

- [x] Add failing pure route tests for all targets including interior VPN route, mixed interfaces, multiple gateways on one interface, local/invalid addresses, subnet endpoints and /31-/32 semantics.
- [x] Add fake-I/O tests for three fair ARP passes, one-second final response opportunity, duplicate/out-of-scope replies, missing local peers, gateway failure, backpressure, uncertainty, cancellation and deadline. Deadline before a full response opportunity fails the preparation.
- [x] Add route-observation tests for endless foreign messages/EINTR and cancellation during a blocked lookup; original absolute deadlines must hold.
- [x] Test that a home /24 excludes the scanner address, an explicit self-address is refused unless user-excluded, overlap preserves singleton provenance, and remote addresses are not classified from local subnet masks.
- [x] Demonstrate failures with `cargo test --locked -p rmasscan-net network_plan` and `cargo test --locked -p rmasscan-net neighbours`.
- [x] Implement portable planning and neighbour resolution, extending only the necessary OS observation fields.
- [x] Run the focused tests plus the net crate suite; commit.

### Task 3: Job-specific network reports and checkpoint envelopes

**Files:**
- Modify `studio/crates/studio-protocol/src/lib.rs`.
- Create `studio/crates/studio-protocol/src/network.rs` and corresponding integration tests.
- Modify `studio/crates/studio-store/src/lib.rs` and add a schema migration/report persistence test.

**Interfaces:**
- `Backend::MacNetwork`, enabled only for macOS after acceptance.
- A versioned `NetworkReport` with original-job digest, bounded route plan, resolved destination map and unresolved targets; `encode() -> Result<Vec<u8>, String>` / `decode(&[u8]) -> Result<Self, String>` enforce a compact sorted binary format and the 24576-byte blob limit.
- A versioned `NetworkCheckpoint` containing `NetworkReport` and the existing engine checkpoint bytes.
- `Job::validate()` validates settings without a real binding; `Job::prepare_network(&NetworkReport)` reconstructs the exact runtime plan.
- `validate_checkpoint` and `checkpoint_origin` retain their external signatures and support legacy checkpoints as well as the new envelope.
- Add job-specific read-only preflight and preparation-report/acknowledgement protocol messages; bump IPC version.

- [x] Add failing tests for target/port/rate bounds, unsupported OS gate, legacy job JSON, mismatched job/report, report overflow and checkpoint substitution/corruption. Include all 65535 ports on one host, exact 1048576-probe admission, and limit checks before unresolved hosts are removed.
- [x] Test maximum-size report/checkpoint bytes inside the actual JSON Envelope, including worst-case byte values and skipped-address records; admission must reject unpausable jobs before any adapter access.
- [x] Add persistence tests proving report commit precedes acknowledgement and that original requested targets and unresolved targets survive reopening History.
- [x] Run the focused protocol/store tests to record failures.
- [x] Implement validation, bounded serialization, runtime-plan reconstruction, schema migration and durable report storage.
- [x] Run `cargo test --locked -p studio-protocol -p studio-store`; commit.

### Task 4: Helper preparation, lifecycle and network guard

Execute this task as two sequential, independently reviewed changes: **4a** owns
the runner preparation/lifecycle/guard and its fake tests; **4b** owns application
authorization/readiness, durable report acknowledgement and coverage updates.
The 4a report supplies the runtime contract consumed by 4b. A focused helper
module may hold the new state machine rather than growing the existing entrypoint.

**Files:**
- Create `studio/crates/studio-runner/src/network.rs` and targeted fake tests.
- Modify `studio/crates/studio-runner/src/main.rs`, `guard.rs` and relevant runner integration tests.
- Modify `studio/crates/studio-app/src/lib.rs` for report acknowledgement and job-specific readiness.

**Interfaces:**
- A preparation worker owned by one attempt accepts Job/optional checkpoint and a cancellation flag, then returns the frozen report and runtime plan; no packets are sent after cancellation acknowledgement.
- IPC remains responsive while preparation runs. The engine starts only after the app acknowledges the persisted report and the final network snapshot still matches.
- Route inspection uses the existing guard's one-second polling, three-second freshness and five-second suspension rules.
- `Authorize` establishes a helper session; the selected job determines feth versus physical preflight.

- [x] Add fake lifecycle tests for successful LAN/routed scans and truthful unresolved-target reporting.
- [x] Add tests for Stop/Close while resolving ARP or waiting for report ACK, stale completion, worker panic, changed route before first SYN, and no usable targets.
- [x] Add restart-resume tests requiring the exact frozen job/map and a fresh attempt; formerly unresolved hosts cannot join Resume.
- [x] Add guard tests for source/interface change, interior route change, stale observation and suspension.
- [x] Run targeted tests to show failures; implement the worker/state transitions and authenticated report handling.
- [x] Run the runner/app suites and existing Simulation/feth lifecycle regressions; commit.

### Task 5: Studio controls, summaries and history

**Files:**
- Modify `studio/crates/studio-ui/ui/main.slint`, `src/main.rs`, and UI contract tests.
- Extend `studio/crates/studio-inspection` export DTOs/serializers and tests for physical-scan coverage.
- Update `studio/README.md`, `studio/AUTHORIZATION.md` and `studio/VERIFICATION.md`.

**Interfaces:**
- Add `Mac network · Wi-Fi / Ethernet` without changing existing feth/Simulation saved backend meanings.
- Show requested target/probe counts, interface/source and route result, Preparing network, and separately counted not-scanned neighbours.
- Preserve profile save/load, History, inspection and export; report preparation and partial coverage persistently.
- Physical exports retain scan-wide coverage in the same atomic file, including zero-result scans: JSON coverage metadata and explicit CSV non-result record kinds. Preserve legacy exports and filtered result rows; never invent closed-port rows for unscanned addresses.
- Keep Stop available during preparation and make the backend-specific helper/route readiness clear.

- [x] Add failing headless tests for backend/profile round-trip, counts, unsupported-OS display, preparation cancellation and partial-coverage History.
- [x] Implement the controls and report presentation using existing UI conventions.
- [x] Run targeted UI tests and `cargo xtask test`; update documentation with exact limits and measured status, then commit.

### Task 6: Review, cross-platform CI and real-network acceptance

Execution split: **6a** prepares the bounded Rust fixture, packet witnesses and Controller driver with native launch refused. **6b** reviews the complete branch, adds a separate unmerged fixture-constrained candidate, then performs privileged lab and owned-target acceptance. Candidate fixture constraints must reject a different source/interface/route before packet adapter open and reject a different persisted report before ACK; external preflight alone cannot close that race. Removing fixture-only constraints for owned-target acceptance is a separate reviewed change. The distributed physical gate stays closed until acceptance evidence is complete.

**Files:**
- Add `docs/experiments/2026-10-28-studio-macos-network.md` and bounded evidence artifacts.
- Add/extend native lab acceptance fixtures needed for both direct and routed destinations.
- Update the physical gate only in the acceptance commit.

- [ ] Review the complete diff, including source selection, physical binding verification, checkpoint provenance, cancellation and truthful counters.
- [ ] Run both workspace tests, Clippy, formatting, cargo-deny and language guard; require green three-OS CI on the exact candidate commit.
- [ ] Create a reviewed, unmerged candidate commit enabling the physical profile, and prepare and verify a sealed multi-peer/routed lab fixture; request only the concrete native setup/grant that cannot be performed without user action.
- [ ] Execute packet-evidenced direct/routed, missing-neighbour, Stop, Pause/Resume, restart and drift cases with the candidate build.
- [ ] Obtain explicit owned home/server acceptance targets; verify expected port outcomes on real Wi-Fi/Ethernet without broadening target scope.
- [ ] Record platform/fixture limits, retain or merge the candidate gate only after its criteria pass, rerun affected tests and CI, and create reviewable PRs. Merge/install only within the user's authorization at that point.
