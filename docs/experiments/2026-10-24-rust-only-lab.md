# rmasscan: Rust-only lab migration verification

Date: 2026-10-24. Working tree: `feat/rmasscan-stage2b-windows`, based on
`f71330c2f5aff51b2e7d39913486f8f5f4a6fccc`. Changes are uncommitted.

## Delivered

All ten active Python programs/tests under `rmasscan/scripts` were replaced by
the workspace crate `rmasscan-lab`. Packet comparison, evidence verification,
VM ownership/isolation, peer tools, capture, suite orchestration and C-oracle
metadata now run in Rust. Active shell and PowerShell entry points invoke Rust
and OS utilities; they do not invoke Python. The CI workflow runs the Rust
checks. A regression test rejects Python files and Python calls in active lab scripts.

The lab crate forbids unsafe code; OS-specific operations stay in `rmasscan-net`.
The independent pinned C oracle remains independent. Historical experiment
artifacts and the original Swift application's helper test are outside this
migration and have not been rewritten.

Also fixed during the port/review:

- Failed guest verification cannot be replaced by a stale successful report;
  unique invocation nonces and artifact hashes bind the evidence.
- Capture interface/filter, checkpoint content, scan identity and unsigned
  counters are validated; malformed counters cannot overflow into PASS.
- Namespace creation rollback handles ownership-marker failure.
- Windows random tokens use the OS random generator; firewall-query failures
  fail closed. Root-created manifests preserve the invoking user's ownership.
- Command timeouts bound subprocess output collection. Remote process cleanup
  checks PID and start time. Linux suite cleanup owns a dedicated process group.
- Oracle staging includes both shell files required on a fresh remote host.

## Fresh native checks

The final source archive was verified before extracting on each remote host:
`874ea8daa5a6f34ea6d80c737e3dfb281389fc6bdc2abd4461701636c84f36c0` (SHA-256).
It contains `rmasscan/` without build/cache directories and the rmasscan CI
workflow. This identifies a working-tree snapshot, not a Git commit.

| Native host | Workspace passed | Failed | Ignored | Clippy `-D warnings` |
|---|---:|---:|---:|---|
| macOS arm64 | 494 | 0 | 8 | PASS |
| Linux x86_64 (`minipc`) | 541 | 0 | 14 | PASS |
| Windows x64 (`winvm`) | 496 | 0 | 25 | PASS |

Commands: `cargo test --locked --workspace` (remote hosts also use
`--no-fail-fast`); `cargo clippy --locked --workspace --all-targets -- -D warnings`.
Platform-specific tests explain the different counts. Ignored raw/network tests
were not enabled. The Linux offline process-group regression passed after
killing its driver while a descendant ignored TERM; it sends no packets.

Additional checks:

- `cargo fmt --all --check`: PASS.
- `rmasscan-lab verify-wire --self-test`: PASS on all three native hosts.
- macOS release-mode verifier tests: 43 passed, 0 failed, 52 filtered out.
- PowerShell parser: all active `.ps1` files parsed, zero errors.
- Bash syntax and `git diff --check`: PASS.
- Saved Windows functional evidence: 29 required checks PASS.
- Saved Windows failure evidence: 19 required checks PASS.

The saved functional directory also includes an abandoned invalid attempt;
the new verifier still marks that attempt INVALID and does not count it as a
successful required run. Replaying saved packets does not prove fresh raw I/O.

## Evidence and limits

Full logs: [rust-only-lab-raw](2026-10-24-rust-only-lab-raw/).
Windows `final-checks.json` records exit codes and source archive hash; Linux
`final-checks.txt` records exit codes. Mac logs include the full workspace and
release verifier output. All three native runs used Rust 1.99.1.

No new live scans, network reconfiguration, package publication, merge or push
were performed. Fresh end-to-end raw acceptance of the replacement harness is
still required in the isolated lab before treating the migration as live-wire
acceptance. User-facing Slint functionality and scanner algorithms were not
changed by this migration.

Usage: [Rust laboratory tools](../../rmasscan/docs/rust-lab.md).
