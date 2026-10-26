# Studio: active-attempt network guard

Implements the sleep/network interruption requirement in the cross-platform
design §7 and the 2026-10-25 next-stage plan. Scope: Studio only; no rmasscan,
lab configuration, network scans, or raw-release gate changes.

## Contract

- The current explicit macOS feth profile repeats its existing read-only
  isolation validation during a running attempt, against its initial manifest.
  A valid but replaced manifest is also a change, not permission to continue.
- One worker per raw attempt; checks start immediately and repeat after a
  one-second interval. A complete observation has a three-second budget.
  A last successful observation older than three seconds is unsafe. These are
  conservative Studio policy values, not measured network guarantees.
- A runner/observer scheduling gap over five seconds, or a backwards wall clock,
  interrupts. This catches long suspension on platforms where Instant excludes
  sleep; it is not an OS pre-sleep hook or proof of detecting every short sleep.
- Inspection is cancellable and never runs on the IPC/event loop. Stop reaches
  the existing engine cancellation handle. A sticky interruption takes priority
  over a simultaneous Completed/Paused; drain results, emit Interrupted, and do
  not publish a checkpoint. No automatic restart. Normal pause still requires
  durable checkpoint ACK. Monitoring ends when the engine ends, not after ACK.
- Simulation exercises lifecycle protection without inspecting or changing the
  host network. Tests inject observations only through internal Rust APIs,
  never argv/environment switches in the privileged runner.
- Raw remains false. Polling can miss a transient change between observations,
  is not an atomic route snapshot, and cannot promise zero packets after a
  change. Physical NICs and Linux/Windows raw observers are separate work.

## Task 1: monitor, runner integration, evidence

1. Add failing offline tests for drift, stale/hung observations, clock gaps,
   worker failure/cancellation, successful checks, and terminal/pause races.
2. Implement a bounded cancellable observer in studio-runner and wire the real
   feth collector. Preserve the manifest validated before opening the adapter.
3. Exercise the actual fake engine and runner event path; assert result retention,
   Interrupted precedence, no checkpoint, and clean next attempt.
4. Update README/AUTHORIZATION/VERIFICATION with scope and exact evidence.
5. Run focused tests then cargo xtask test; fresh whole-branch review; fix important
   findings with regressions; push PR and merge only its exact green CI head.

## Review focus

Inspect completion/pause races, stale-success masking of a failed observation,
worker teardown and cancellation, timing across sleep, raw-gate preservation,
and any route/identity claim stronger than the actual collector validates.
