# Masscan Studio (Rust + Slint)

This workspace connects the selected Slint interface to the current `rmasscan`
engine through a separate Rust runner. Engine/core/net remain in `../rmasscan`;
there is no vendored second engine. Studio is a Rust/Slint application.

## Build and run

Use Rust 1.99.1 and a system SQLite development library. SQLite is dynamically
linked; `bundled` and `buildtime_bindgen` are not enabled. On Windows, run
`. ./scripts/windows-sqlite.ps1` in PowerShell first. It downloads the pinned
official SQLite DLL, checks its SHA-256, and creates an MSVC import library.
On macOS, use Homebrew SQLite (the macOS 14 system library lacks APIs required
by rusqlite): `brew install sqlite`, then export
`SQLITE3_LIB_DIR="$(brew --prefix sqlite)/lib"` before the commands below.
The packager copies that library into the app and fixes its load path before signing.

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

History lives in `~/Library/Application Support/Masscan Studio
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
  The runner outbox counts actual serialized bytes against 4 MiB, including the
  frame being written; tiny frames also have a 1,024-frame overhead bound.
- SQLite WAL/FULL transactions, grouped at 250 ms or 1,000 results (bounded to
  16 frames). Lifecycle/checkpoint events flush immediately. Result batches commit before display; checkpoints
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
bootstrap, physical NIC selection and Windows/Linux raw profiles remain open.
Raw scanning remains gated independently of host actions and saved profiles.

## Host actions and export

For saved real observations, use **Actions…** or the row context menu to refresh
a hostname or inspect the host with your separately installed Nmap. **Names**
resolves selected visible hosts (or all visible hosts when nothing is selected),
up to 512 per scan selection. The details pane shows progress, errors and evidence;
**Cancel checks** cancels all current host checks. Changing history or closing
Studio also cancels them. Simulation cannot trigger DNS or Nmap requests.

DNS uses four workers, a three-second process deadline and a five-minute cache;
explicit refresh bypasses that cache. On macOS the separate `studio-inspect`
worker uses system DNS-SD, including mDNS; Windows/Linux use the system resolver
inside the cancellable worker. Only an authoritative missing name/record is
displayed as "No hostname" and negatively cached. Resolver failures, malformed
answers and deadlines are errors and do not enter that cache.
Nmap runs without elevation, checks only discovered
open TCP ports (at most 64, excluding printer port 9100) and has a 55-second
deadline. Install Nmap separately, or set `STUDIO_NMAP_PATH` before launching.
Service/device hints retain their method, confidence and time; they do not certify
hardware identity. All inspection data belongs to its original saved scan.

**Export…** writes the visible filtered rows in their current sort order, using a
snapshot taken before the native save dialog. CSV neutralizes spreadsheet formulas;
JSON includes inspection details only for exported ports. Export runs in the
background. Existing exports are replaced only after the full new file is written.
Old history rows without discovery times remain unknown. Pending host checks are
marked cancelled after an interrupted application run.

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

## Saved scan profiles

In **New scan**, enter settings and a profile name, then choose **Save new**.
Select a saved profile and **Load** to fill the form; **Update loaded** saves your
edits. **Delete…** asks for confirmation and deletes only the profile, never scans.
These controls are available on all platforms.

Saving/loading never start a scan or request administrator access. Review and
check settings before explicitly starting. A profile stores backend, targets,
exclusions, TCP ports, rate and exact seed; it contains no checkpoint. Invalid
input, duplicate names and stale IDs leave existing profiles unchanged.
Up to 100 profiles are supported. Names are trimmed, limited to 128 characters
and 512 bytes, and compared after Unicode lowercasing.

Schema v4 adds native profiles after a consistent SQLite backup named
`before-v4-*.sqlite3`. Existing history stays readable. The retired Swift importer,
its APIs and its UI have been removed.

## Manage saved scans

**History…** opens saved scans with status, UTC creation time and a short ID.
Choose a scan to view its results, rename it, repeat its settings, or delete it.
Names may repeat; each scan retains its own identity and checkpoint. Older scans
without creation times show **Unknown date**; Studio does not invent dates.

**Repeat settings…** opens New scan with the original configuration and exact
seed. It does not run anything or resume a checkpoint. Check the settings and
explicitly start a new scan when ready. The original scan stays unchanged.

**Delete scan…** asks for confirmation and atomically removes that scan's results,
host inspection data and checkpoint; saved profiles and other scans are retained.
Deleting the last scan clears the view. History changes are disabled during a
scan. Inspection of a deleted scan is cancelled and late replies are ignored.
