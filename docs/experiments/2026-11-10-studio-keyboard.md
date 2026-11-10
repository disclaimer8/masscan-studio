# Studio macOS keyboard follow-up

Date: 2026-11-10. Branch: `integration/studio-current-engine`.
Code: `5c095a1f`; lockfile and clean package source:
`57ac3f321b342c579c6b83dc3eb7b5d2b23bd805`.
No push, integration with the separate protocol branch, helper installation or
physical-network scan was performed.

## Confirmed cause

On the earlier `25c1dcb` package, automated Cmd+A appended a character to the
search or settings field instead of selecting all. The failure occurred with
both Latin `a` and Cyrillic `ф`; it was not solely a layout mismatch.

A disposable, scanner-free application using the exact cached Slint 1.18.1 and
winit 0.30.13 logged the native event stream. Cmd+A produced:

- `ModifiersChanged` with `SUPER`, without a separate named Super key press.
- KeyA with logical character `ф`, but native `text_with_all_modifiers` of `a`.
- `ModifiersChanged` back to an empty state before ordinary text entry.

The pinned Slint winit adapter converts named modifier key events, while leaving
aggregate modifier changes unused. Its text shortcuts consequently see neither
the Command modifier nor the native Command character in this event sequence.
The probe and native Studio both reproduced the failure before the change.
This establishes an interoperability failure for the observed input stream;
it does not establish that every physical keyboard produces the same stream.

## Change

A macOS-only window-event adapter now follows aggregate modifier flags and maps
Command/Control to Slint's existing Control/Meta convention. It suppresses the
duplicate individual modifier events, and clears held modifiers on focus loss.
For Command letter shortcuts it uses the native macOS character when that differs
from the ordinary layout character. It does not use a physical QWERTY mapping.
Option, Control, ordinary Unicode, IME and dead-key translation remain delegated
to the backend. Repeat/release events retain their event kind.

The extension feature is enabled only for the macOS target. The scanner, IPC,
controller, saved results and other platform input paths are unchanged.

## Verification

The red regression log records failed select-all and Command-character
assertions before the implementation. Four regression tests now cover those
cases, Shift selection in a real Slint TextInput, ordinary typing after release,
and focus-loss cleanup. The full `cargo xtask test` completed with **483 passed,
0 failed, 2 ignored**, Clippy with warnings denied and formatting PASS. The two
ignored external-service tests remain unchanged.

The native checks used a clean debug package from `57ac3f32`, software rendering
and a copied Simulation history containing 128 saved rows. Through native UI
automation, without AX value replacement for the shortcut assertions:

| Operation | Observed result |
| --- | --- |
| Search: Cmd+A, type `80` over `443` | Exact value `80`; 64 of 128 rows |
| Select the last two digits of `123456` with Shift+Left twice, type `80` | Exact value `123480` |
| First filtered row, Shift+Down twice | 3 selected |
| Table Cmd+A with the port-443 filter | 64 selected |
| Escape, select one row, Cmd+C, Cmd+F, Cmd+A, Cmd+V | Exact selected IP in search; 2 saved ports for that IP; `Copied 1 IP address` |
| Settings Ports and Seed: Cmd+A followed by replacement | Exact values `80,443` and `73` |
| Ports: Tab, then Shift+Tab | Focus moved to Rate and back to Ports |
| Cancel native export, return to search, Cmd+A and type `443` | `Export cancelled`, then exact value `443` and 64 of 128 rows |

The exact packaged binaries also passed Complete, Pause/Resume/Stop and
stop-race Simulation smokes, each in a separate data directory, exit code 0.
The pause screenshot preserves 2 cumulative saved rows and latest-run 1/1
counters. No new network scan was started in the interactive checks.

Package verification checked all 7 inventoried files and deep/strict ad-hoc
signatures. The UTF-8/UTF-16 home-path audit checked 8 files including the
manifest and found zero matches. Direct `rmasscan-lab privacy-scan` with known
private tokens returned zero hits on the retained evidence and package, and on
the staged code/lockfile snapshots before committing. This is a debug,
ad-hoc-signed package, not a notarized release.

## Remaining limits

Automated Cmd+A/text entry remains unreliable in the AppKit-owned Save name
field, both before and after this adapter. Cancel works and Studio input recovers
after returning. The adapter handles Slint windows, not AppKit text fields; the
remaining system-field behavior is not attributed to a confirmed cause here.
The earlier report's working Save shortcut was Cmd+Shift+G, not Cmd+A.

Physical-keyboard checks, other input layouts, native minimum-width resizing,
fresh distribution CI and physical-network acceptance are still open. Manual
Windows GUI acceptance remains excluded by the user's instruction. Protocol
integration remains deferred.

## Evidence

Neutral directory: `/private/var/tmp/studio-keyboard-20261110/`.
It contains the disposable probe source and event log, red/green regression logs,
full Studio test log, package manifest and verification logs, privacy results,
three packaged smoke logs/screenshots and `smokes.json`. The package is
`package/Masscan Studio.app`. Native interactive observations are recorded in the
session tool transcript; the smoke screenshots are separate evidence.
