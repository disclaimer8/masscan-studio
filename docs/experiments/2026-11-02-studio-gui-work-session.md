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

The clean optimized package `studio/dist/build-1793584709600/Masscan Studio.app`
at `4a2883e` also passed the two-authorizations/Complete/Stop/Start GUI scenario
(8, 2 and 16 retained rows). GUI hash
`1b66166d8583fc3753bda528232fe4bd135ba65db712e03ea9598ba63cfafaff`;
helper `5a36e5206db04e9a4314b9890f9ddecfedff87e107ee7798e9f43623eab70238`.
Studio CI `41375100205` and engine CI `41375100245` passed on all three OSes.
The prior Studio CI failed only a test's hardcoded Unix absolute path on Windows;
`4a2883e` uses an absolute path from the current platform. Runtime behavior was
unchanged by that correction.

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

The November 3 native runs below passed on the corrected optimized candidate.
This report does not claim general physical-network release readiness,
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

## November 3: first native GUI attempt and privilege-boundary correction

The retained host was still ready with active 0. The optimized GUI's first
supervised attempt `d0667dcac65042d6300b15b607f0d906` failed before Controller
creation: the acceptance driver tried to read the root-only fixture journal from
the ordinary GUI process. The file namespace remains root-owned mode 0700; its
permissions were not changed. Driver and supervisor exited 1, export and owned
fixture cleanup exited 0, and the original host PID 49278 remained ready/idle.
The failed archive is retained with SHA256
`d05da234451ef255404698f5728dcd70cdd83e763c15878386ad029bcc2e0320`.

The correction aligns the GUI with the existing unprivileged CLI driver: validate
the exported ticket syntax, helper bytes, trusted host selection and deadline;
leave privileged seal reading/pinning and pre-I/O checks in the root helper.
The independent root supervisor still requires its exact issued ticket when
accepting evidence. Syntax checks alone do not authenticate the ticket.
No helper, engine, fixture ownership or packet-verifier policy was weakened.

## November 3: optimized native GUI acceptance

Clean source `4fbe47291d44d9e6d1773b530e8ae5407569dc3a`, release-profile package
`studio/dist/build-1793704084608/Masscan Studio.app` (`dirty: false`):

| Executable | SHA256 |
| --- | --- |
| launcher | `c8856f29196ca7f79a847d71df5ec3e0571b568792d576a43a6977a99fcf3606` |
| GUI | `45bc45013eb0fa99bd6cd71e811d87bd14db61907d5a54368527dca37a5daf9c` |
| helper | `5a36e5206db04e9a4314b9890f9ddecfedff87e107ee7798e9f43623eab70238` |
| fixture tool | `89cf345602bb9c7f9de6711e35bf031a5a87f35db5d0899506e7df8f43c55018` |

Studio CI `41624845151` passed on macOS, Windows and Linux at this exact source.
Native admission reused successful engine CI `41375100245` at `4a2883e`: both
commits have identical rmasscan tree `168dd7b2a0ec2d33c6a03a601c3d636eb45a71f5`
and engine workflow blob `3d9e50a4213c23935b78aed73a72c6eef16ef8ce`.
The admission script verifies both identities. The GUI-only boundary correction
passed 39 GUI unit tests, the launcher integration test, Clippy and formatting.
The preceding full isolated Studio run passed 336 tests with two ignored.

| Separate GUI launch | Peer SYNs / replies | Saved rows (open / closed) | Outcome |
| --- | --- | --- | --- |
| Complete first | 96 / 96 | 96 (48 / 48) | Completed, PASS |
| Stop while running | 5 / 5 | 5 (1 / 4) | Stopped, PASS |
| Complete again | 96 / 96 | 96 (48 / 48) | Completed, PASS |

Stop callback to observed terminal state was 49.29275 ms in this single run.
Each case used a fresh fixture generation and history. The root supervisor
verified protected original captures before exit 0; export and independent
offline verification also exited 0. All nine capture/responder children exited 0
without forced termination. Manifests report no failure and clean children.
Independent SQLite checks passed integrity, exact result tuples, terminal status
and report/attempt agreement. Rendered terminal snapshots show 96, 5 and 96 rows.

Every uplink pcap is a 24-byte header with zero matching fixture frames. General
uplink receive counters were 10084, 915 and 3747; this is not a claim of zero
background Wi-Fi traffic. Owned fixture cleanup succeeded after each case;
`feth4203` and `feth4204` were absent afterward. The same administrative host
PID 49278 remained ready with active 0, without another OS authorization.

Local evidence is under
`.superpowers/sdd/2026-11-02-studio-gui-session/native-retry1/`:
`summary.json`, `verified-stores.json`, per-case protected-original verifier logs,
exported evidence, offline logs, screenshots and SQLite histories. Raw captures
remain local. Export archive SHA256 values:

| Case / nonce | Archive SHA256 |
| --- | --- |
| Complete / `a8a4a8f25607dc822478267187fa1fdc` | `a5eb535d7f2a4730d8d0dd3e39d7e1d9d591181d474ef00349104fa931f83df3` |
| Stop / `8e00cdb45d303938c4ef16062aa85465` | `318810cb50498695c19d213e8bfca5b8088699d5f5eb16de5adc117bb1abf4a1` |
| Complete / `b085ba6c19960b7abf8adbf328a72cad` | `3ff34ee68a53eedf4b51d1dc5221d9527ed390ea38d14e8fa25368e2a62a639f` |

The exact final package also passed the packet-free two-authorizations and
simulation Complete/Stop/Start scenario (8, 2, 16 rows). Native runs above are
separate launches: same-window native Stop/Start and native Pause/Resume on this
package remain untested. Callback automation with rendered snapshots does not
establish manual keyboard/mouse acceptance or physical Wi-Fi delivery. The app
was subsequently launched with a private SQLite backup of the last 96-row scan;
the original evidence database was preserved.
