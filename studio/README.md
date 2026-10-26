# Masscan Studio (Rust + Slint)

This workspace connects the selected Slint interface to the current `rmasscan`
engine through a separate Rust runner. Engine/core/net remain in `../rmasscan`;
there is no vendored second engine. The original Swift application is untouched.

## Build and run

Use Rust 1.99.1 and a system SQLite development library. SQLite is dynamically
linked; `bundled` and `buildtime_bindgen` are not enabled. On Windows, run
`. ./scripts/windows-sqlite.ps1` in PowerShell first. It downloads the pinned
official SQLite DLL, checks its SHA-256, and creates an MSVC import library.

```sh
cd studio
cargo xtask test
cargo xtask build
```

The last command prints the unique directory under `dist/`. On macOS it contains
`Masscan Studio.app`, signed ad hoc after all executable changes. This is a local
development signature, not Developer ID/notarization. Windows packages contain
`studio-ui.exe`, `studio-runner.exe`, and `sqlite3.dll`; keep them together.
`manifest.json` records the source revision, dirty state, Cargo lock hash and
binary hashes. No Npcap or Nmap is bundled.

History lives separately from Swift: `~/Library/Application Support/Masscan Studio
Rust` on macOS, `%LOCALAPPDATA%/Masscan Studio` on Windows, and
`$XDG_DATA_HOME/masscan-studio` (or `~/.local/share/masscan-studio`) on Linux.
`STUDIO_DATA_DIR` overrides this for tests. Only one instance can own a directory.

## What works in this slice

- System theme by default, with a light/dark override; seven-column table,
  filtering, sorting, selection, context actions and saved scan selection.
- Engine lifecycle: Start, Pause, durable checkpoint, Resume (including after
  restarting Studio), Stop, and reusing/closing a runner session.
- Bounded framed IPC with version/session/scan/attempt IDs and strict sequence
  checks. `u64` fields cross the UI boundary as decimal strings.
- Result delivery in batches of up to 1,000 rows or 50 ms. Intermediate progress
  updates coalesce; results do not. Queue exhaustion interrupts the attempt.
- SQLite WAL/FULL transactions. Result batches commit before display; checkpoints
  commit before acknowledgement. A crash converts unfinished scans to Interrupted.
- A failed launch/connection closes the runner session and allows a fresh attempt.

Choose **Simulation · no network packets** to exercise this flow on any OS. This
uses the real engine with its fake packet adapter, not a prerecorded UI animation.
It does not prove raw packet I/O or network correctness.

The reserved **Mac feth** profile is disabled at a compile-time release gate.
Start/Resume refuse this profile before opening any packet adapter. The new
read-only preflight checks route/VPN overlap, bridge membership, addresses/MACs,
permanent ARP and forwarding. A live isolated scan with independent capture is
still required before opening the release gate. Studio does not create a stand.

## macOS session authorization

The **Authorize** button opens the system administrator dialog, connects to the
installed runner and runs the read-only preflight. It sends no packets. Cancel
or Stop cancels the wait; **Lock** closes the session. The password never enters
Studio. Switching to Simulation closes the elevated session and uses an
unprivileged runner.

Prepare a copy of the runner from the exact app bundle you will run:

```sh
cargo xtask prepare-runner '/absolute/path/Masscan Studio.app/Contents/MacOS/studio-runner'
```

Review the printed directory's `manifest.json` and `install.sh`, then install it:

```sh
cargo xtask install-runner '/absolute/path/studio/dist/runner-TIMESTAMP'
cargo xtask probe-authorization '/absolute/path/Masscan Studio.app/Contents/MacOS/studio-runner'
```

Installation copies one immutable version under
`/Library/PrivilegedHelperTools/MasscanStudio/<sha256>/studio-runner`. It registers
no service. Each build has a separate directory; existing versions are never
overwritten. The UI verifies root ownership, permissions, absence of extended
ACLs/symlinks, and the exact bundled binary hash before launching it. Build-tree
binaries are never executed as root. See [AUTHORIZATION.md](AUTHORIZATION.md)
for the threat model, cancellation rules and remaining acceptance work.

## Deliberate current limits

Simulation uses inherited anonymous pipes as the current user. Unix sockets have
peer identity tests on macOS/Linux; system elevation is implemented on macOS
only. Do not launch the UI with sudo. Windows named-pipe/UAC and Linux pkexec
bootstrap, physical NIC selection, Windows/Linux raw profiles, DNS/Nmap inspection,
export and Swift-history import remain open. Context actions state when inspection
is unavailable.

No auto-scan, auto-update, telemetry, firewall changes or driver installation.
Raw acceptance requires the isolated lab and independent packet evidence; opening
a window or passing simulation never counts as raw acceptance.

## Repeatable UI smoke

Run the packaged UI with `--smoke`, `--smoke-pause`, or `--smoke-stop-race` and a fresh `STUDIO_DATA_DIR`.
All explicitly select Simulation. `--smoke-pause` exercises Start → Pause →
committed checkpoint → Resume → Stop. Set `SLINT_BACKEND=winit-software` for a VM
and `STUDIO_SCREENSHOT` to save a PNG. Linux needs a display server (Xvfb works for
this smoke); Windows needs an interactive desktop for UI evidence.
`--smoke-stop-race` submits Stop while a Started event is pending in the UI queue.

These checks do not measure displayed-frame latency or replace manual keyboard,
screen reader, clipboard and context-menu acceptance.
