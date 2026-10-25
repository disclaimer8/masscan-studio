# Studio integration evidence

Baseline scanner: `baa5cc789a6a7e96337835ad613d77f573a1f06a`.
Date: 2026-10-25. Studio is a separate workspace/branch; scanner source unchanged.

## Local Apple Silicon (development slice)

- `cargo xtask test`: 16 tests passed; workspace Clippy `-D warnings` and fmt pass.
- Protocol: bounded/truncated framing, wrong IDs/sequences/version, canonical u64.
- History: instance lock, duplicate result replay, stale attempt, invalid checkpoint,
  interrupted recovery, saved pause and Resume after reopening the application.
- Runner: real engine + FakeAdapter, framed child-process IPC, Pause/ACK/Resume/Stop
  on one runner session; clean exit after stdin closes.
- Controller regression: a missing runner initially made subsequent Start impossible.
  New test reproduced this failure, then passed after connection recovery was added.
- GUI `--smoke`: completed eight simulated endpoints, visible saved result rows.
- GUI `--smoke-pause`: Start → Scanning → Saving → Paused → Resume → Stopped.
- Packaged `.app`: `codesign --verify --deep --strict` passed; the packaged UI and
  sibling runner repeated `--smoke-pause` successfully using software rendering.
- Independent review found a lost Stop click when Started was already queued.
  `--smoke-stop-race` reproduced Completed instead of Stopped, then passed after
  Stop became a direct callback. Draft backend no longer controls the scan badge.
- A failed Resume preflight now retains the previous checkpoint. A regression
  test reproduced deletion before the fix; retry and app restart both pass.
- Injected SQLite checkpoint-write failure rolls back, returns failure before ACK,
  leaves no resumable checkpoint and recovers as Interrupted.
- Volume regression: the initial 10,000-result run overflowed the display queue.
  Runner now batches up to 1,000 results/50 ms and coalesces progress. A 100,000
  result simulation at 10,000 packets/s completed in 13.29 s with the application
  polling at 20 Hz; all 100,000 rows were delivered and present after reopening
  SQLite. This measures lifecycle/storage delivery, not displayed-frame latency.

These are simulation and lifecycle results, **not raw network acceptance**.
The fixed feth profile is **disabled**: independent review found the preliminary
manifest check lacks complete live route/ARP/forwarding isolation. A test verifies
explicit refusal before adapter opening. There was no privilege elevation,
adapter creation or raw scan.

## Linux (minipc, Ubuntu 26.04.1 x86_64)

Revisions `75b5abc` and `20853d0`: all 16 tests, Clippy and fmt passed after installing the missing
rustfmt component. SQLite 3.46.1 is linked dynamically. Packaged build succeeded;
software UI in Xvfb passed both pause/resume and Stop-race smoke. This is a virtual
display test, not manual Wayland/clipboard/accessibility acceptance.

## Windows VM

The external SQLite 3.50.4 DLL/import library built and the Rust workspace compiled.
Two 5-second test waits failed during the first parallel run with the volume test;
both passed individually and together on repetition. The test wait was shorter
than the product's 10-second handshake. The volume case now has its own test binary
and startup tests allow 20 seconds; the product handshake is still 10 seconds.
Final revision `20853d0`: all 16 tests, Clippy and fmt passed. The package at
`C:\Users\lab\studio-integration-20261025\studio\dist\build-1792965817853`
passed both software-rendered pause/resume and Stop-race UI smoke scenarios.
This was an automated SSH-session smoke, not manual RDP usability acceptance.

## Reproducible artifacts

| Platform | Build revision | Package | Evidence |
| --- | --- | --- | --- |
| macOS arm64 | `75b5abc` | `studio/dist/build-1792965368596/Masscan Studio.app` | `studio/verification/macos/` |
| Linux x86_64 | `75b5abc` | minipc: `~/studio-integration-20261025/studio/dist/build-1792965491343` | `studio/verification/linux/` |
| Windows x86_64 | `20853d0` | Windows VM: path above | `studio/verification/windows/` |

`20853d0` changes only the test layout/waits and documentation relative to
`75b5abc`; application/runner source and Cargo lock are unchanged. Package
manifests record `dirty: false` and exact binary hashes. The shared Cargo lock
SHA-256 is `5a399e68eae927418f876059ea1ca17247f1e4b3cc97797c703683828d290f33`.
The Studio CI workflow is added but has not run on GitHub (branch not pushed).

Fault injection beyond the listed cases, authenticated privileged bootstrap and
external-capture proof remain pending. Existing scanner Stage 2C results are not
counted as Studio acceptance.

Build manifests and per-machine logs/screenshots belong in `studio/verification/`
(ignored) or an explicitly archived evidence package. Each packaged build writes
its own manifest; a dirty source tree is reported as dirty, never as a clean release.
