# Studio native UI and draft queue follow-up

Date: 2026-11-10. Branch: `integration/studio-current-engine`.
UI counter labels: `7565b4d91c84206dfe64943641a47ad05ed68157`.
Controller fix: `25c1dcb14c86dc7ba75b80552dd4dc30f623dd5f`.
No merge, push, scanner changes or physical packet transmission in this follow-up.

## Draft-edit failure and fix

Typing a long settings value in the native window produced
`Application command queue is busy or closed`. Every edit was putting a complete
SetDraft action into an eight-slot queue. A deterministic controller regression
reproduced this failure before production changes.

The bounded command channel now coalesces consecutive unconsumed draft edits.
Start, Stop, route checks and other explicit actions seal the preceding draft;
later edits get a new queue entry. Taking a draft marks it consumed under the
same lock used for edits, preventing a racing edit from modifying an already read
job. The sender keeps a weak reference, so a pending draft cannot conceal a dead
receiver. Setup gates and immediate Stop/Lock cancellation remain in Controller.

The regression sends 2,000 edits around Start/Stop and checks the last draft on
each side, exact action order and cancellation epochs. Additional tests cover
route-check boundaries, edits after consumption, capacity and receiver death.
Existing cancellation, persistence, stale readiness and setup tests also pass.

`cargo xtask test` on the exact production sources later committed as `25c1dcb`:
**479 passed, 0 failed, 2 ignored**, workspace Clippy with warnings denied and
formatting PASS. The ignored tests require external resolver/Nmap services.
Staged files passed direct `rmasscan-lab privacy-scan` with known private tokens
before committing. Hosted CI has not been run for this local commit.

## Native macOS checks

Both clean source snapshots were packaged in neutral directories with Homebrew
Rust 1.99.1, SQLite and debug symbols disabled. Manifest source hashes remain
exact; these are debug-profile, ad-hoc-signed packages, not notarized releases.
Complete package inventories and deep/strict signatures passed.

The GUI used a separate history directory and Simulation with its fake packet
adapter. Initial settings: 64 synthetic IPv4 addresses, ports 80/443, rate 100,
seed 73, giving 128 results. No adapter authorization or network packets were used.

- On `7565b4d`, native Save dialogs exported all 128 rows to JSON and 64 filtered
  port-443 rows to CSV. Cancel returned `Export cancelled`; export could be opened
  again. Repeat settings restored the original fields without starting a scan.
- On `25c1dcb`, reopening the same history restored all 128 rows. Rapid typing of
  64 repeated port-80 tokens followed by port 443 no longer produced the queue
  error. Check settings showed 128 endpoints; Start completed with 128 saved
  rows and sent/received 128/128. SQLite retained the exact final ports text.
- On `25c1dcb`, the native zoom/restore action retained visible controls and rows.
  Native Save exported another 64-row filtered JSON successfully.
- Independent JSON/CSV parsing and read-only SQLite comparison confirmed exact
  endpoint sets and Simulation sources. Both scans have 128 unique results;
  filtering did not remove rows from history.
- The packaged `25c1dcb` Complete, Pause/Resume/Stop and stop-race Simulation
  smokes all exited successfully in three additional isolated histories.
- The final package home-path audit found no UTF-8/UTF-16 home paths; direct
  known-private-token scanning also found zero hits.

## Limits and remaining UI checks

Full keyboard acceptance remains open. During native automation with the current
input layout, Cmd+A in a settings field inserted a Cyrillic character instead of
selecting all; the native Save panel's shortcut worked. This is an observation,
not a confirmed attribution to Studio, Slint or the input tool. AX value-setting
was used to complete the form checks. Home/End moved the table viewport, but
complete modifier/focus behavior was not accepted. Native minimum-width resizing
was not established by the attempted edge drags; ordinary and zoomed layouts were
visually inspected. Do not label this as complete keyboard/mouse acceptance.

No new helper installation, Windows GUI/UAC, Linux desktop/polkit, physical
network, publisher signing or distribution acceptance is claimed. Claude's
protocol integration and the Open/ICMP Closed policy remain deferred.

## Evidence

Neutral local directory: `/private/var/tmp/studio-native-ui-20261110/`.
It contains the two package manifests, inventory/signature/privacy checks,
red/green controller logs, full Studio test log, native UI logs, JSON/CSV exports,
SQLite snapshot and `export-history-validation.json` with content hashes.
The final code package is `package-fixed/Masscan Studio.app` from `25c1dcb`.
Native window observations are in the session tool transcript; generated
Simulation smoke screenshots are separate from those observations.
