# GUI working-session and native acceptance — 2026-11-02

The operator requested continued development without repeated administrator
dialogs. Root work host PID 49278 from October 31 was still ready on November 2.
The hotel Wi-Fi is outside the scan scope: the operator authorized choosing a safe
target, and this run uses only the existing isolated fixed feth fixture on this Mac.

## Packaged GUI authorization

The original bundled GUI was not an approved caller. A packet-free GUI run first
reported a missing matching helper, then (after staging that helper) correctly
reported `Caller build is not authorized for this working session`. Neither failure
started a scan. Both results are retained locally.

Simply staging the bundled executable failed: its signature referred to the bundle
Info.plist/resources and was invalid after copying it into the host's immutable
executable directory. A standalone re-signed GUI worked, but was not treated as a
packaged-app result. Embedding Info.plist alone still failed resource validation.

The macOS package now has a small unprivileged `studio-launcher` entry point. It
executes sibling `studio-ui`, forwarding literal OS arguments, without a shell.
The GUI is signed as a nested executable before the launcher/bundle are signed.
Both the complete bundle and a standalone copy of the exact GUI bytes verify.
The launcher regression checks literal arguments with spaces/metacharacters and
the child's exit status (RED before implementation, GREEN afterward).

Enrollment uses the already authorized maintenance Stage operation: select the
reviewed GUI and helper, then restore the fixture tool with the same helper before
launching. Previously approved caller hashes remain admitted. This changes no host
protocol, does not restart the host and does not request another OS authorization.
It uses the existing broad reviewed-code maintenance capability, not a separate
least-privilege GUI permission. Host idle status and restored selection are checked.

Package `studio/dist/build-1793583511328/Masscan Studio.app`, through its launcher,
passed `--smoke-work-session`: two real authenticated helper authorizations/releases,
followed by simulation Complete (8 rows), Stop (2 retained rows), and another Start
with the same form settings (16 rows, Completed). SQLite integrity and all three
durable statuses were checked separately. All scan jobs were Simulation; snapshots
show the actual application rendering. Host PID 49278 remained ready, active 0.
GUI SHA256 `2ad0f84d1095942922b7b40f55c21f6d2b54e219b355f2d471a62b0c3e892710`;
helper SHA256 `f63fedf885e7b0ac4ad7ecbddeb18205ee91889c79e500e4333f60914235ca2f`.
This development artifact was built from an uncommitted worktree; it is evidence
for that package, not a clean release candidate.

## Native GUI candidate

`--smoke-network-case=complete|stop-running` uses the real GUI form and button
callbacks against the fixed sealed topology. It requires a fresh independently
supervised ticket, current root seal, matching helper/tool selection, and a fresh
isolated history. Targets, ports, rate and exclusions are fixed. Production helper
admission and all existing packet-verifier rules remain unchanged.

The driver checks button availability, validates coverage, compares the displayed
terminal status/row count with durable SQLite, retains a terminal screenshot and
waits through a quiet period. It drops the GUI/timer callbacks, requires exclusive
ownership of the Controller, joins it, then publishes the existing Attempt record.
The same independent root supervisor verifies packet order, replies, lifecycle,
quiet periods, child cleanup and uplink isolation. GUI success alone is not PASS.
Clock/evidence structures were moved without semantic changes into studio-protocol
for reuse by the GUI and verifier. A regression rejects empty/incomplete rendering
even when a Controller could otherwise claim completion.

Native packet execution on this new GUI candidate is pending CI admission and the
live run. This report does not claim general physical-network release readiness,
manual mouse/keyboard acceptance, hotel-device scanning, or Windows/Linux native UI
acceptance. The branch remains fixture-only and must not be distributed or merged.

## Verification and retained failures

Local full Studio tests, Clippy with warnings denied, and formatting passed after
review. The work-session EOF test originally assumed an immediate nonblocking EOF;
it now polls with a one-second bound, like the production watcher. No production
lease code changed. The timeout is configured before closing the peer because
macOS can reject setting it on an already disconnected socket.

One full local run also hit the existing
`running_owned_child_is_cancelled_and_reaped_with_same_absolute_budget` test at
1.01 seconds versus its strict one-second assertion while another build was running.
That test/runtime were not changed; the subsequent full isolated run passed.

Local evidence: `.superpowers/sdd/2026-11-02-studio-gui-session/`, including
`green-bundle/verified.json`, screenshots, initial failures, package/signature
probes and `reviewed-tests.log`. Earlier native fixture evidence remains in the
[October 31 capture report](2026-10-31-studio-macos-network-capture.md).
