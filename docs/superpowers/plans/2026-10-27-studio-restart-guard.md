# Studio restart and network interruption acceptance

> Use superpowers:executing-plans inline, with one final fresh review.

**Goal:** prove raw Resume across two Studio processes, and an Interrupted result
after a controlled change inside the sealed Mac feth network.

**Architecture:** extend the existing smoke driver with explicit pause-exit,
resume-saved and guard modes. Keep the controller, runner and engine production
paths unchanged unless a regression demonstrates a defect. Reuse the existing
feth orchestration and independent tcpdump witnesses; preserve evidence from both
processes instead of replacing the earlier chronicle.

**Tech Stack:** Rust, Slint, external Homebrew SQLite, existing rmasscan-lab.
**Spec:** 2026-10-26-studio-network-guard.md and the accepted Mac feth plan/report;
the user's 2026-10-27 instruction authorizes these follow-ups.

## Global constraints

- Mac feth only, target 198.18.0.2; no physical NIC, VPN, firewall or default-route changes.
- No rmasscan engine/adapter changes; Claude owns those components.
- No privileged test switches in runner. Observe the actual production guard.
- Keep runner hash unchanged where possible; system dialogs remain user-owned.
- Mac builds/tests use SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib.
- Live PASS requires complete peer/uplink captures, zero lab uplink packets,
  hash provenance and an independently checked durable history. Offline success
  cannot close a live acceptance item. Restore any lab-only change before exit.

## Task 1: independently runnable UI stages

Files: studio/crates/studio-ui/src/{main,smoke_feth}.rs; stage tests beside driver.
Interfaces: explicit pause/resume/guard stage selection; the existing Step and
Action path; one chronicle per process, guard-ready marker only after Scanning.

1. RED: pause stage exits only after durable Paused history and Lock; it never
   emits Resume. Resume stage rejects missing/ambiguous/mismatched checkpoints,
   selects the exact saved scan, authorizes anew and emits Resume, never Start.
   Guard stage accepts only guard-origin Interrupted with no checkpoint, rejects
   Completed/Stopped/Failed, and times out safely.
2. Implement minimal stage extensions and CLI validation; preserve standard smoke.
3. Focused driver tests then cargo xtask test. Commit the tested slice.

## Task 2: repeatable windows and evidence

Files: studio/xtask/src/feth_acceptance.rs; a focused stage verifier in laboratory
tooling if existing verifier cannot judge paired windows; acceptance procedure.
Consumes Task 1's modes; produces separate immutable chronicles/history snapshots
and process IDs with an explicit shared-history binding for restart.

1. RED: reject incompatible modes and unsafe/missing shared history before launch;
   preserve isolation interlock and cleanup across each process/window.
2. Reuse existing orchestration. Record before/after hashes, checkpoint identity,
   new process/attempt identity, packet sequence across pause/resume and terminal
   guard status. Missing evidence, witness loss or a mismatched job cannot PASS.
3. Controlled guard case changes only the lab's source ARP entry, with explicit
   user-owned privileged operation and restoration; no simulated guard result.
4. Focused regressions and full relevant suites. Commit and obtain fresh review.

## Task 3: live acceptance and delivery

1. Build concrete signed app/tools and verify runner hash against installed copy.
2. Inspect stand read-only; prepare exact setup/restore commands if absent.
3. Run pause-exit/new-process-resume and guard windows with independent witnesses;
   close only the checks actually observed. User handles required system prompts.
4. Record evidence and limitations, run exact-head three-OS CI; merge green work.

## Review focus

- Startup history can arrive before authorization; reject stale or wrong selection.
- Pause must be durable and acknowledged before process one exits.
- Resume must preserve scan/job and use a fresh attempt, including existing rows.
- Guard must not mistake an ordinary adapter error or Stop for its own interruption.
- Witness/cleanup failures and delayed user action must fail closed without touching
  the normal network or silently discarding earlier evidence.
