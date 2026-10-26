# Studio integration evidence

Baseline scanner: `baa5cc789a6a7e96337835ad613d77f573a1f06a`.
Studio is a separate workspace/branch; scanner source unchanged.

## 2026-10-26 — PR #30 viewport and idle-summary follow-up

Base: `4413e113165e9eb6dbed04ae5d9448d89318e0da`. Both deferred minor findings
are addressed. Paging and bottom-edge scrolling use ListView.visible-height.
Local `cargo xtask test`: 98 passed, 0 failed, 2 privileged tests ignored;
formatting and Clippy passed. Hosted CI gates merging.
Summary invalidation shares the existing model-change notification, so unchanged
timer ticks return before borrowing the result table. Changes in selection,
filter/order, results, enrichment and history clear still refresh it.

The boundary regression reproduced a focused-row bottom of 531px outside a
527px viewport before the fix. It now checks every pixel of a 35px height range
at both 820px and 1160px window widths. A separate idle regression holds a mutable
model borrow across 20 summary calls, proving that clean ticks do not access the
model at all. An integration test checks sorting, hostname-driven filter changes,
batched results, clear/replacement and selection changes for stale summaries.
These are headless Slint tests, not native UI or network acceptance.

## 2026-10-26 — table keyboard and empty-state behavior

Base: `12c4daa56671634261965e75cb89f971dbad1d23` (PR #28).
Scope: table model and Slint UI. Engine, runner, raw gate and labs are unchanged.
The concurrent live feth acceptance in another worktree was left untouched.
Local `cargo xtask test`: 95 passed, 0 failed, 2 privileged tests ignored;
formatting and Clippy passed. Hosted CI remains the merge gate.

Three model tests cover unique selected IPs in sorted order, filtering without
hidden/focused-row fallback, and resetting the Shift-range anchor after Escape.
Five headless tests instantiate the real generated MainWindow and the extracted
production callback wiring. They dispatch keyboard events and check multiline
clipboard contents, empty-copy preservation, filter exclusions, text-input and
context-menu shortcut isolation, viewport-dependent paging with Shift/Home/End,
and first-use/waiting/history/filter empty states.

The original single-IP copy, fixed ten-row paging and misleading first-use state
all failed these tests before the fixes. Slint's pinned 1.18.1 testing backend is
a dev-dependency only. Tests use its private clipboard and no native window;
they are not proof of native Command mapping, Wayland clipboard, IME or a11y.

## 2026-10-26 — active-attempt environment guard

Base: `644f6cd16d543c56284050947f8fd8169c19074e` (PR #26).
Scope: Studio runner only; no engine/lab edits or real packet transmission.
Local `cargo xtask test`: 87 passed, 0 failed, 2 privileged tests ignored;
formatting and Clippy passed. Hosted cross-platform checks gate the PR merge.

Offline regression coverage:

- Failed or stale observations stop the real engine with a fake adapter; errors
  remain sticky and a late success cannot refresh an already stale interval.
- Simulated wall-clock and monotonic gaps, including an unchanged monotonic clock
  across a long wall-clock gap, interrupt. This is clock injection, not live sleep.
- Worker panic and in-flight failure during terminal teardown remain errors;
  a healthy observer cancels and joins promptly without stopping a healthy engine.
- The actual runner loop over in-memory framed IPC delivers received results,
  records Interrupted/no checkpoint in SQLite, survives database reopen, and
  accepts an explicit fresh attempt on the same session.
- Already queued Completed/Paused outcomes cannot override an observer failure;
  the terminal publisher preserves rows and suppresses checkpoint/ACK state.

No privileged observer test or network manipulation was performed. The raw gate
is unchanged (false). Live feth drift/sleep evidence, physical NICs and platform
observers beyond macOS remain NOT RUN here; engine Stage 2C is not evidence for
these Studio contracts. The five/three/one-second values are policy, not measured
wire timing.

## PR #16 integration checks

Current main's lab fixes (`b6986c7`) were merged into the Studio branch without
conflicts or changes to rmasscan relative to main. The first hosted Windows run
exposed an event-queue overflow in the unchanged 100k-result acceptance test.
The history path was performing a separate autocommit read for every result's
discovery time. It now uses a prepared UPSERT with RETURNING inside the original
write transaction and returns observations only after successful commit. No queue
capacity, scan rate, timeout or row-count assertion was relaxed.

New durability tests cover returned first-discovery dates, duplicate event replay
and full rollback when committing a result batch fails. macOS after this fix:
49 offline tests, Clippy and formatting passed. Hosted revalidation gates merging.
Studio CI runs on PRs and main pushes; superseded PR runs are cancelled.

## 2026-10-26 — DNS error classification corrected

The deferred DNS review finding is closed. macOS DNS-SD now requests intermediate
negative responses and distinguishes NoSuchName/NoSuchRecord from daemon errors,
invalid PTR data, disconnected sockets and the query deadline. Windows/Linux
classify the system resolver's NoName/NoData as absence; all other errors exit the
unprivileged worker unsuccessfully. The parent reports Failed and does not cache
the error as a missing hostname.

New tests cover DNS-SD failure/absence/valid and invalid PTR/deadline, system
resolver error kinds (Windows/Linux), and controller cache behavior. macOS:
47 offline tests passed, Clippy/fmt passed, explicit loopback resolver test passed.
Linux native DNS/controller tests and the loopback resolver check also passed.
Windows native tests passed; its live loopback query returned the configured
computer name `W-`, which is invalid under the hostname validator and is now
correctly reported as an error (not a negative cached response). A packaged Mac
query reported a transient deadline, and the next query resolved `localhost`;
the failed request was not reported as absence.
The previously recorded packages below predate this correction; their hashes and
evidence remain historical rather than being silently replaced.

## 2026-10-26 — host actions and filtered export

Implementation `7770743`, reviewed fixes `7e17e3b`. Test-only follow-ups
`af9ec60` and `34e173a` exclude compilation/cold fixture startup from cancellation
timing. No scanner source or privileged IPC API changed. Raw remains disabled.

| Host | Offline tests | Clippy / fmt | Packaged UI |
| --- | --- | --- | --- |
| macOS arm64 | 44 passed, 2 explicit live tests skipped | passed | Pause/Resume/Stop and Stop-race passed |
| Linux minipc x86_64 | 38 passed, 2 explicit live tests skipped | passed | Xvfb/software Pause/Resume/Stop passed |
| Windows VM x86_64 | 33 passed, 2 explicit live tests skipped | passed | software Pause/Resume/Stop passed |

The two explicit live tests additionally passed on Mac: system resolver returned
`localhost`; unprivileged Nmap 7.992 inspected a Rust HTTP fixture bound only to
`127.0.0.1` on a dynamically assigned port. Nmap recognized its deliberately known
nginx response, including method/confidence/CPE. This is inspection acceptance,
not evidence of raw scanning or physical NIC performance.

Fresh review found and reproduced three important defects: queue-full lost the
old pending request, inherited child pipes escaped the deadline, and a failed
metadata write discarded subsequent completions. Each has a RED-to-GREEN
regression. Children now belong to a Unix process group / Windows Job Object;
queue rejection preserves the previous request; failed writes keep previously
saved evidence and report an error while other host replies continue.

The Windows timing investigation measured 1.594 seconds in the first creation of
a fresh fixture EXE, then process exit/tree termination/pipe draining by 1.620
seconds. The test warms the generated executable before timing cancellation;
the 1-second/2-second assertions remain unchanged. This does not establish a
hard bound on operating-system cold process creation.

Native Mac UI acceptance used a separate simulation history: filtering port
8003 showed one of eight results, and native Save dialogs produced CSV and JSON
containing exactly that one row. CSV permissions were 0600. Simulation inspection
actions were disabled; controller tests independently reject network requests.
Late replies, explicit refresh/cache, cancellation, v1 SQLite migration, pending
recovery, observation dates, XML limits and filtered-export privacy are tested.

Clean Mac package: `studio/dist/build-1793002438127/Masscan Studio.app` at `7e17e3b`.
Linux package: `~/studio-integration-20261025/studio/dist/build-1793002645883` on
minipc, same implementation revision. Windows package at test revision `34e173a`:
`C:\Users\lab\studio-integration-20261025\studio\dist\build-1793004670738`.
Only process-test setup changed after `7e17e3b`; production sources are identical.
Windows and Linux GUI smoke ran in test sessions, not a manual RDP/Wayland
usability review; native Save dialogs were exercised only on Mac.
Manifests include all three executables
(`studio-ui`, `studio-runner`, unprivileged `studio-inspect`) and SHA-256 hashes.
The new packaged runner hash is `6a8e43…`; the installed root helper is still
`3b1acf…`. This block did not require installing another privileged helper.
Authorize in this new package therefore requires its own matching installation;
the previous elevated-session acceptance below is unchanged.

The minor resolver-error classification finding from this review was subsequently
fixed; see the DNS correction section above.

Evidence directory: `studio/verification/host-actions-20261026/` (ignored local
artifact archive; includes tests, review regressions, package manifests, UI check
notes and actual CSV/JSON exports). No remote push or merge performed.
Archive: `studio/verification/studio-host-actions-20261026.tar.gz`, SHA-256
`bf2a5a885355b074f6d8eba3199025c77cfd3a71aec6b11d6e1b2252a661aaac`.
All 26 enclosed files passed their SHA256SUMS verification.

## 2026-10-26 — confirmed elevated session

The user approved the new system authorization request. Client fix `068a94d`
successfully authenticated the installed `1b397f…` runner as UID 0 (PID 18317),
checked the exact installed executable/hash and exchanged protocol-v2 Hello.
CheckNetwork returned `ready=false` because the stand manifest is absent.
CloseSession completed, the audited process was gone and the socket endpoint was
removed. An independent `ps -p 18317` also found no process afterward.

This proves the system-launch/authenticated-channel/cleanup path against the
installed helper. It does **not** prove acceptance of a configured feth network,
raw scanning, packet isolation or physical NIC support. No packets were sent;
the compile-time raw gate remains closed. Evidence is saved under
`studio/verification/auth-confirmed-20261026/`.
Archive: `studio/verification/studio-auth-confirmed-20261026.tar.gz`, SHA-256
`4990ad2bbb375eced40d4bafd6a85a20dce5c989c3387a599a569be006daf1bc`;
individual file hashes were checked against the enclosed SHA256SUMS.

The user then approved installation of helper `3b1acf…` from the updated Mac
package. Installation, root ownership, permission/ACL checks and exact SHA-256
validation passed. The package and installed helper now match. The elevated
session proof above used the previously installed `1b397f…` helper with the fixed
client; the new helper was not separately subjected to another elevated session
probe. Its packaged unprivileged lifecycle smoke is recorded below.

## 2026-10-26 — root installation and audit-token correction

The user confirmed the administrator dialog. The `1b397f…` runner below is now
installed; installer ownership/ACL/hash validation succeeded. The first live
probe then failed closed with `PROC_PIDTBSDINFO: EPERM` while the unprivileged UI
inspected the root peer. No Hello/engine start or packets followed; the runner
exited. A standalone read-only diagnostic reproduced the same denied lookup
against PID 1 while PID-path lookup remained available.

Fix `068a94d` uses the kernel socket audit token and `proc_pidpath_audittoken` for
the root-peer lookup, retaining root UID, exact path, immutable installation and
hash checks. A wrong PID-generation regression is rejected by the kernel. A
fresh review verified FFI layout/signatures against the SDK and Apple source.
All 29 macOS workspace tests, Clippy and formatting pass. Linux/Windows results
below remain at `fa0e625`; this macOS-specific fix was not rerun there.

The first retry with the fixed client expired at the 180-second OS-authorization
deadline without confirmation. No runner or launcher remained after that timeout.
The later approved retry passed Hello and cleanup as recorded above. The isolated
stand manifest is absent, so live stand acceptance is still pending.

Updated clean Mac package: `studio/dist/build-1792998323580/Masscan Studio.app`.
Its packaged Start/Pause/Resume/Stop simulation smoke passed.
Its newly built helper was prepared and subsequently **installed and verified** from
`studio/dist/runner-1792998393567`; SHA-256
`3b1acf74399c2a4e49e43f885e465b82993a8de983f28ef4bf897f1da5f520aa`.
Evidence: `studio/verification/auth-root-20261026/`.
Archive `studio/verification/studio-root-evidence-20261026.tar.gz`, SHA-256:
`6976870c9d15a82dae8537b7caef1ebb70caa1d892dd6a0ebd0182164ee7c1d8`.
Raw scanning remains disabled. Installing the original helper did not open that
gate and does not establish Studio's raw-scanning acceptance.

## 2026-10-26 — session authorization and complete preflight implementation

Implementation revision: `fa0e6254b94757cd0eb444d6c689efa698be16fa`.

| Host | Tests | Clippy / fmt | Package / simulated UI |
| --- | --- | --- | --- |
| macOS arm64 | 27 passed | passed | both lifecycle smoke cases passed |
| minipc Linux x86_64 | 23 passed | passed | both Xvfb/software smoke cases passed |
| Windows VM x86_64 | 18 passed | passed | both software smoke cases passed |

Different test totals reflect OS-specific test compilation, not ignored failures.
All packages have `dirty: false` and the same source revision. Sources under
`rmasscan/` are unchanged from the scanner baseline. The full 100k result/storage
regression passes on all three hosts; this still does not measure displayed frames.

Added evidence:

- Unix peer credentials, stale birth/wrong account refusal, private socket modes,
  endpoint substitution refusal and removal; actual child runner Hello,
  CheckNetwork, simulation Start and clean exit on disconnect on macOS/Linux.
- macOS extended ACL negative fixture and preflight subprocess cancellation/reap;
  no administrator rights are required for these tests.
- Sealed-network parsing plus 14 isolation mutations and malformed/overlapping
  routes. The checker now includes routes, ARP and forwarding; its live isolated
  stand acceptance remains distinct from these fixture tests.
- Missing/unsupported authorization returns to a usable controller and successful
  Simulation. Raw Start refuses before adapter open without an elevation prompt.
- A custom `CARGO_TARGET_DIR=/private/tmp/studio-auth-target-20261026` preparation
  selected Cargo's reported artifact; the old hardcoded target path is gone.
- Fresh review found ACL trust, `/var/run` permissions, stale target selection and
  delayed preflight disconnect issues. All four were fixed and re-reviewed with
  no remaining blocker for the no-packet authorization probe.

macOS package: `studio/dist/build-1792987790581/Masscan Studio.app`.
Linux package: `~/studio-integration-20261025/studio/dist/build-1792987907745` on minipc.
Windows package: `C:\Users\lab\studio-integration-20261025\studio\dist\build-1792987971651`.
Logs, manifests and inspected UI screenshots: `studio/verification/auth-20261026/`.
Evidence archive: `studio/verification/studio-auth-evidence-20261026.tar.gz`, SHA-256
`96876d7cd104e74b0b5a37f85ea658c70d172f1cacca8a20d52341bdd35c0788`.
Individual evidence hashes were verified from the enclosed SHA256SUMS.

Prepared macOS install directory: `studio/dist/runner-1792987801550`.
Runner SHA-256: `1b397fccdcd01a9fbd58d5caebd0af574533dbbecae55855a306eb1f16548838`.
Installation script SHA-256: `74f4e35effcf52fe310db7edd36fef8a3a5df1a6365b7306b7df878f84119a1b`.
System installation was confirmed by the user and passed hash/ownership
verification. The subsequent probe exposed the access failure described above.
Elevated Hello and cleanup were subsequently verified with the fixed client;
acceptance of a configured isolated stand remains **NOT YET VERIFIED**.
`RAW_SCANNING_ENABLED=false`;
no raw packets, route changes, lab creation or scanner acceptance run occurred.

Cargo lock SHA-256 on macOS/Linux:
`f771d8aa7286c252cfdeb7682cfb352c4e00384f45a828abfbacc5091e3cef46`.
Windows CRLF file SHA-256:
`218ad016338a306289d5c9a62b7cbb706c24ec804fd43ab3d2b23635e4675224`.
The LF-to-CRLF transformation was checked and reproduces the Windows hash.
No branch push or GitHub CI run was performed.

## Historical evidence — 2026-10-25

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
Revision `7177536` repeated the full verification successfully while capturing
native subprocess output explicitly in `verification/windows-native.log`;
its package is `dist/build-1792966064097` on the same VM. Application source is
unchanged from the package above.

## Reproducible artifacts

| Platform | Build revision | Package | Evidence |
| --- | --- | --- | --- |
| macOS arm64 | `75b5abc` | `studio/dist/build-1792965368596/Masscan Studio.app` | `studio/verification/macos/` |
| Linux x86_64 | `75b5abc` | minipc: `~/studio-integration-20261025/studio/dist/build-1792965491343` | `studio/verification/linux/` |
| Windows x86_64 | `20853d0` | Windows VM: path above | `studio/verification/windows/` |

`20853d0` changes only the test layout/waits and documentation relative to
`75b5abc`; application/runner source and Cargo lock are unchanged. Package
manifests record `dirty: false` and exact binary hashes. Cargo lock SHA-256 is
`5a399e68eae927418f876059ea1ca17247f1e4b3cc97797c703683828d290f33` on macOS/Linux.
Windows Git checks it out with CRLF, producing
`cf37b8944f39934e362057974ad53d64ce002083f5ef385a02e762566172c48d`;
converting the LF file to CRLF reproduces that exact hash. Dependency content is
identical; manifests deliberately hash actual file bytes.
The Studio CI workflow is added but has not run on GitHub (branch not pushed).

Fault injection beyond the listed cases, authenticated privileged bootstrap and
external-capture proof remain pending. Existing scanner Stage 2C results are not
counted as Studio acceptance.

Build manifests and per-machine logs/screenshots belong in `studio/verification/`
(ignored) or an explicitly archived evidence package. Each packaged build writes
its own manifest; a dirty source tree is reported as dirty, never as a clean release.

### PR #16 CI follow-up: grouped commits and macOS SQLite

The second hosted Windows volume run still exhausted the event queue after the
per-row read fix; the same revision passed on the home Windows VM. The controller
now groups ordered frames into one WAL/FULL transaction at 250 ms or 1,000 results,
with a 16-frame bound. Lifecycle and checkpoint frames force an immediate flush.
The controller keeps handling commands while collecting the batch; rows and ACKs
are exposed only after commit. A sequence gap rolls back the whole batch. Runner
queue limits, scan rate and the 100,000-row test deadline are unchanged.

macOS 14 CI exposed a separate link failure: its system SQLite lacks
`sqlite3_set_clientdata`. CI now explicitly links Homebrew SQLite; the existing
packager includes the dylib in the signed bundle. This is a build dependency,
not a change to the history format or engine.

Local full workspace tests after these corrections: 52 passed, 2 explicit live
tests ignored; clippy with warnings denied and formatting passed. Log:
`/tmp/studio-group-tests.log`. Hosted CI must pass on the updated PR head before
merge; a passing local run alone is not merge acceptance.

### Windows WAL checkpoint diagnosis

The 250 ms/1,000-row transaction grouping alone did not close hosted Windows
acceptance. Instrumented run 40300793387 localized the backlog: 53,380 committed
rows spent 15,368 ms in storage, while the reader eventually waited for the
controller and blocked the runner's bounded writer queue. No rows were reported
as Completed after that interruption.

A native Windows split measurement showed row insertion taking 2–9 ms per batch,
while automatic WAL-to-database checkpoints during commit took 50–135 ms and grew
with the result index. Changing only `wal_autocheckpoint` from its default 1,000
pages to 4,096 reduced cumulative storage time for the same 100,000-row, 10k/s test
from 6,103 ms to 2,879 ms. Both native runs preserved every row and completed.
Local comparison logs: `/tmp/studio-wal-1000.log`, `/tmp/studio-wal-4096.log`.

`FULL` still synchronizes each WAL commit before display or checkpoint ACK. The
new setting triggers consolidation at roughly 16 MiB with 4 KiB pages; it is not
a hard WAL-size limit, because readers may pin WAL frames. It trades a larger WAL
and possible individual checkpoint/recovery latency for less repeated index-page
writing. Queue bounds, scan rate and test deadline were not changed. Latest-head
hosted Windows acceptance remains required. `STUDIO_TRACE_TIMINGS=1` enables
local aggregate IPC/commit diagnostics; it logs counts and timings, not targets.

### Serialized output-budget correction

Hosted Windows run 40301986347 still interrupted: individual FULL commits and
WAL checkpoints took up to 1,970 ms. The runner's previous limit of 32 frames
represented 4 MiB only at the maximum legal frame length. Real 500-row frames
are much smaller, so it rejected a bounded backlog well before the agreed
4 MiB serialized-data budget was used.

The outbox now reserves the exact encoded frame length, including its length
header, against 4 MiB. The writer's in-flight frame remains reserved until it is
written/dropped. Send stays nonblocking; actual exhaustion still interrupts the
scan. A separate 1,024-frame bound limits overhead for tiny control messages.
The controller's queues, FULL commits, scan rate and volume-test deadline are
unchanged. This is a serialized-byte budget, not a claim that all process memory
fits in 4 MiB; allocation/channel overhead and one encoding buffer are separate.
Tests cover byte saturation, in-flight accounting, writer/disconnect failure,
frame-count saturation and protocol round-trip.

The outbox review also found that checkpoint ACK time previously included time
spent waiting in the output queue. A delivery receipt now starts the unchanged
10-second ACK deadline only after the checkpoint frame has been written/flushed.
While queued, ten seconds without writer progress is a separate transport-stall
failure. Tests distinguish progressing backlog, stalled transport, failed writes
and delivered-but-unacknowledged checkpoints. Full macOS suite: 58 passed,
2 explicit live tests ignored; Clippy/formatting passed
(`/tmp/studio-byte-budget-tests.log`).

## 2026-10-26 — manual Swift history and profile import

Implementation `da3c0cf`, PR #19, baseline main `6ea6efd`. Studio-only changes;
no rmasscan changes, root helper installation or raw gate changes.

Local Mac arm64: `cargo xtask test` passed 77 tests, 0 failed, 3 explicitly
ignored (two live inspection tests and the real-source import test); Clippy with
`-D warnings` and formatting passed. Separately, the ignored real-source import
check read both existing Swift files into a disposable destination: 2 sessions,
1 profile, 971 source results. Reimport skipped existing records. Before/after
source bytes matched exactly; no real source records are included in fixtures.

Store tests cover Swift epoch/fractions, u64 maxima and arbitrary-precision unknown
numbers, strict full-file validation, status recovery, historical PTR names,
unknown fields, per-endpoint dedup with full original archive, moved-source and
UUID-case idempotency, conflicts, transaction rollback, active-scan rejection,
v2 backup including live WAL data, source symlinks and durable import reports.
Controller tests cover no runner launch for import/legacy Resume, active-scan
rejection before reading sources, platform gate and reopen+immediate import.

Manual packaged Mac UI acceptance used a synthetic documentation-range source
and a separate data directory: one session and one profile imported, repeat
reported 0 imported/2 unchanged, table displayed historical hostname/device/time,
legacy Paused had no Resume button, profile loading filled targets/ports/rate/seed
without starting a scan. Native folder picker worked. Fresh independent review
found Ready busy-state, legacy PTR grammar and stale startup report delivery;
all three received failing-before/fixed-after regressions and were re-reviewed
with no important findings remaining. The last report now has a distinct startup
event and cannot complete a pending import.

Clean Mac package at implementation commit:
`studio/dist/build-1793012322083/Masscan Studio.app`. Ad-hoc signature and nested
SQLite dylib verification passed; manifest records all hashes and source state.
Local evidence logs: `studio/verification/swift-import-20261026/` (gitignored).
Hosted three-OS checks are linked on PR #19; their completion is recorded by CI,
not inferred from this local test result. The previously installed root runner
is unchanged and is not needed to import, inspect saved data or run simulation.

## 2026-10-26 — Swift import cancelled; native Studio profiles

User correction supersedes the import stage above: Swift is permanently retired.
The importer/parser, import controller actions, file chooser/report and imported
profile flow are removed. The spec's decisions 5/7, data section and transition
requirements now describe one Rust/Slint product. Existing schema-v3 observations
and inert metadata are preserved; the old serialized backend tag is accepted
only to read existing archives and cannot start or resume an engine.

Native profiles support Save new / Load / Update loaded / confirmed Delete on
all OSs. Store validates configuration, exact seed, bounded names, duplicate names,
existing IDs and a 100-profile limit. Schema v4 adds profiles after a consistent
backup. Tests verify update/delete never remove scans and preserve v3 results,
archive metadata and backup contents even with a live WAL connection.

Mac arm64: `cargo xtask test` passed 64 tests, 0 failed, 2 live inspection tests
ignored; clippy -D warnings and fmt passed. Controller tests use a nonexistent
runner and verify profile operations create no scans or authorization events.
Manual packaged UI acceptance in a disposable data directory: create, update,
load (restores saved ports), reopen/persistence, deletion confirmation/cancel,
and absence of import controls. Actual deletion is covered by automated tests.
The settings form now scrolls; exact minimum-window-size behavior was not
confirmed manually. Fresh review found no remaining issues after layout and
error-message adjustments. rmasscan source and raw gate are unchanged; no live
lab or root operations were performed. Local logs are under
`studio/verification/native-profiles-20261026/` (ignored).

## 2026-10-26 — saved scan management

Studio adds History with rename, repeat settings and confirmed deletion. New
scans record UTC creation time; old unknown dates stay unknown. Repeat copies
only the exact configuration/seed into an unchecked draft, not a checkpoint.
The original scan is preserved and no scan or authorization starts implicitly.

Local Mac arm64: `cargo xtask test` passed 72 tests, 0 failed, 2 explicit live
inspection tests ignored; formatting and Clippy `-D warnings` passed. Evidence:
`/tmp/studio-history-final.log`. Store tests cover active/stale/invalid refusal,
transaction rollback after child deletion, other scans/profiles retained,
checkpoint identity on rename, old FK metadata cleanup and reopen persistence.
Controller tests cover selected/last-scan deletion, clearing host state, no
runner invocation for saved history, and active-scan refusal using simulation.
A host test verifies cancellation and ignores completion after deletion and
after selecting another scan. UI unit coverage checks exact repeat settings and
the archived backend refusal.

Packaged Mac `--smoke` completed a simulation in an isolated data directory.
Manual UI checks covered empty-name error recovery, rename, deletion confirmation
and Cancel, and Repeat opening settings with the exact original seed/ports/backend.
Actual deletion was exercised in automated store/controller tests, not manually
against user data. The history form scrolls to keep controls reachable. Manual
screen-reader/IME and Windows/Linux desktop interaction are not claimed by these
checks; hosted CI provides separate offline and Linux software-UI coverage.
rmasscan, raw gate, root installation and live labs are unchanged.

## 2026-10-26 — Windows named-pipe session transport

Windows simulation now exercises Studio controller → authenticated local named
pipe → runner. No UAC, installation or raw adapter is introduced. macOS/Linux
retain their existing transport. The platform uses protected owner-only DACLs,
local first-instance pipes, retained peer process handles, creation times,
SID/logon identity and identification-only SQOS. Frame and queue limits stay intact.

Test-first Windows run 40321001151 failed on the missing Windows module. At
09ccf8a, Windows run 40322310909 passed 67 tests, with two live inspection tests
and one explicitly invoked child-process fixture ignored in the ordinary run.
This includes real Win32 DACL inspection, duplicate-instance refusal, wrong/stale
peer identity, timeouts/cancellation, duplex roundtrip, blocked-read shutdown,
runner handshake/disconnect and the full simulation lifecycle/100k-row suite.
Mac `cargo xtask test` passed 72 tests, two live checks ignored; fmt/Clippy passed.

A fresh review identified an API-contract ambiguity around immediate overlapped
completion without an event signal. A controlled native OVERLAPPED-state test
failed with TimedOut in Windows run 40322875715, then the implementation was
changed to query completion before waiting. The fixture models this state; it
does not claim that a real ReadFile/WriteFile reproduced it on the CI host.
Further tests cover shutdown during a blocked write and peer death during a read.
The follow-up review found no new issues. Latest-head CI must pass these added
checks before merge; earlier green evidence is not a substitute.

Final Windows run 40323404385 passed all three OS jobs and language guards before
PR23 merged as 8e76a3a. Windows: 70 passed, three ignored (two live inspection
checks and one separately invoked child fixture).

No cross-account/UAC, Windows interactive desktop, physical NIC or network-packet
claim follows from these tests. The home lab and rmasscan source were not used.

## 2026-10-26 — Linux session authorization

Linux controller/UI now use a session-only pkexec runner installed under its
SHA-256. Parent/peer identities, trusted installation and the independent raw
gate remain mandatory. Initial Linux support is x86-64/glibc. No product polkit
policy, service or privileged daemon is installed.

At 4f514b1, Ubuntu job 121584669177 in run 40326496452 passed 71 tests (four
ignored: two live inspection checks and two separately invoked fixtures),
Clippy/format, packaging and both software UI lifecycle checks. The actual
polkit probe installed a root-owned runner, authenticated the exact elevated
child, completed Hello/CheckNetwork/CloseSession, verified that preflight remained
unavailable, and checked runner exit/socket removal. A second actual elevated
session terminated within two seconds after its UI-owner fixture was SIGKILLed.
The temporary exact-binary XML policy was removed and is excluded from artifacts.
No packet adapter was opened.

Local Mac `cargo xtask test`: 74 passed, two live inspection checks ignored;
Clippy and formatting passed. Portable installer/ELF tests were observed failing
on the missing APIs before implementation and passing afterwards. Linux tests
cover foreign peer, exact child with wrong UID, cancellation, timeout, child exit,
wrong parent and parent death. Fresh whole-branch review found no confirmed
defects. Publication additionally uses no-clobber rename for simultaneous installs;
the exact final HEAD still requires three-OS green CI before merge.

Evidence: `/tmp/studio-linux-authorization-ci.log` (GitHub job above),
`/tmp/studio-linux-mac-tests.log`. Desktop password prompting/cancellation is not
established by the CI allow policy and remains a Linux release gate. System loader
configuration/runtime and administrators are trusted. Other Linux architectures,
raw network scanning and Claude's engine/lab acceptance are outside this change.

## 2026-10-26 — Windows trusted installation prerequisite

This implements Task 1 of the Windows authorization plan, not session UAC.
The prepare command emits an exact-runner hash manifest and one-time installer;
native Rust checks/pins the installed file and its ancestry. Windows Authorize
and raw scanning remain disabled. No home VM, live lab or rmasscan changes.

Fresh review found three defects in the initial branch. At e7a3b32, Windows job
121602826577/run 40331795184 reproduced all three: a smart quote caused the
PowerShell value test to print INJECTED; a deterministic pre-hardening observation
found inherited unprivileged write access in the staging directory; a metadata-only
directory handle allowed a second open requesting DELETE. These are regressions
observed on Windows, not inferred from passing string assertions.

Fixes use ASCII numeric UTF-16 data expressions, atomic protected DirectorySecurity
creation (PowerShell 7+), and FILE_LIST_DIRECTORY access for sharing protection.
SID bounds inside allow ACEs are checked explicitly. Object-ACE fixtures include
GUIDs because Windows normalizes GUID-less OA/OD into ordinary ACEs.

At e979a08, run 40333613604 passed all three OS jobs and language guards. Windows
job 121609447136 passed 77 tests (three ignored: two live inspection checks and
one separately invoked pipe fixture), lint, packaging and actual protected
Program Files installation. Native checks verified executable write/rename
pinning, no-overwrite, modified-content rejection and version-directory reparse
rejection. All three review regressions passed. Local Mac: 75 passed, two live
checks ignored, fmt/Clippy passed. Evidence logs:
`/tmp/studio-windows-install-red.log`, `/tmp/studio-windows-install-green.log`,
`/tmp/studio-windows-install-fixed-mac.log`. Exact final-head CI gates merge.

CI's Windows account is already administrative. These tests do not establish
UAC consent, alternate credentials, cancellation or elevated runner lifetime.
Those remain the next task. Unsupported effective ACE forms fail closed; only
the volume root permits unprivileged creation of new directories while refusing
modification/deletion of protected existing children. The personal-build threat
model continues to trust administrators and exclude malicious same-account code.

## 2026-10-26 — Windows UAC desktop and lifetime acceptance

Scope: ordinary same-account Windows 11 desktop → exact installed runner →
authenticated IPC. No packets, Npcap, network/lab configuration or rmasscan changes.
The user explicitly authorized the home VM for this acceptance.

Native offline CI at c84dc55 (run 40348308524, Windows job 121661128395)
passed tests, lint, packaging, protected installation and standalone preparation
outside a checkout. The actual consent step failed with Windows error 1223 in
that service session. This is recorded as FAIL/unavailable interactive consent,
not reclassified as PASS. Automatic CI retains the other checks and packages the
native consent fixture; desktop evidence below supplies the interactive check.

Downloaded artifact source: `fded3984120566856216e0603234847f54009708` (GitHub PR
merge tree for c84dc55). Windows 11 Pro build 26300, lab desktop session 1,
EnableLUA=1 and ConsentPromptBehaviorAdmin=5, unchanged. All executable hashes
were checked against package manifests before installation. Exact runner:
`6831512c2ed0a3f29b23e331b72c4776e7909530624b98ce0b96594c92ba9a6f`.
Native test executable:
`649fa53e69d4a33e1c82e89d4bf9a3eb724fe2c4110ef07f4fae10a6f52bb966`.
Transport archive SHA-256:
`6150258577d84c7f0b8366217642b0a84a0961af22b4387d5022a3e3e1829f40`.

| Case | Observed result |
| --- | --- |
| Real UAC consent | PASS; ordinary owner kind=3, elevated=false; runner kind=2, elevated=true |
| Split-token logon | Owner AuthenticationId `[282251,0]`, runner `[281949,0]`; same SID and exact retained launch handle accepted |
| Hello / repeated CheckNetwork | PASS; both checks unavailable, raw remains false |
| CloseSession | PASS twice; retained runner exited within 2 seconds |
| Deny, then retry | PASS; denial returned 1223/exit 1, next consent completed normally |
| IPC disconnect | PASS; retained runner exited within 2 seconds |
| Explicit job drop | PASS; retained runner exited within 2 seconds |
| Cancel / late approval / retry | PASS native integrated test; 1 passed, 0 failed; late runner exited within 2 seconds |
| Abrupt established-owner death | PASS; supervisor verified held process handles, creation times and paths; runner exit observed 6 ms after terminating owner |
| Alternate-account UAC | NOT RUN; no second account created; unsupported and rejected by same-SID contract |

The integrated cancellation fixture releases a controlled launcher barrier only
after cancellation destroyed the pipe/job, then invokes real ShellExecute and
requires the approved late runner to exit. This proves that sequence, not elapsed
wall time from a physical UI cancel click on the secure desktop. The 15.74-second
test duration includes the operator's consent delay.

Evidence archive: `studio/verification/windows-uac-20261026/native-evidence.zip`,
SHA-256 `fef2e4bcd93d6b991a27f43712f8f770744158b9806bb7f27dcad1c1c37368b7`.
It contains per-case stdout/exit files, runner/owner identities, package provenance
and a per-file SHA-256 manifest. `uac-prompt.jpg` records the actual system prompt.
Evidence files remain local ignored artifacts; this report records their hashes.
No surviving studio-runner was reported after the suite.

Fresh whole-branch review at 69d0cb5 found two Important issues: missing runner
environment allowlist and missing integrated late-launch regression. Both were
fixed at 6115a62. The environment test failed first at d2e562d (inherited marker)
and passed natively after the fix. It also checks that a benign working-directory
DLL cannot replace the subsequently loaded System32 module. Static image imports
remain within the documented installed-image/OS-runtime trust boundary.

Local Mac final suite after Windows UI enablement: 76 passed, 0 failed, 2 live
inspection tests ignored; Clippy and formatting passed. Exact-head CI and the
packaged Windows Authorize/Lock UI check are recorded separately below.

An additional desktop probe was terminated by its retained, birth/path-verified
owner handle while the real UAC prompt remained visible. Windows left that prompt
open. Selecting Yes afterwards did not establish a session; the subsequent
process inventory found no runner. This observation has no retained late-child
handle and is not a separate two-second exit measurement; the integrated native
fixture above supplies that stronger exit proof.

### Packaged Windows interface

The package built from PR merge tree `be07686043bb980f2f93cb80032bd79d69f00470`
(head 9497e73) was independently staged and hash-verified on the same VM. Its UI
SHA-256 is `6a833352c0517c963e1f4708c457692fff04f2e7718d60ac2026b2b4469f59c2`;
runner SHA-256 is `e6690e5ae5279d2c137b92c36589e42f8ac6ed6e4a69834f58eb89a5250b624b`.
The matching version was installed and verified with the packaged tools outside
any source checkout. `studio-ui.exe` ran in the ordinary desktop with a fresh
STUDIO_DATA_DIR and winit-software backend.

Authorize opened real UAC. After consent, the interface showed Lock, retained the
installed runner and reported that Mac feth preflight is unavailable on Windows.
Lock restored Authorize and displayed “Runner session closed”; the subsequent
process inventory contained only the UI. No scan was started. Screenshots are
`studio/verification/windows-uac-20261026/ui-authorized.jpg` and `ui-locked.jpg`.

Denying UAC from that packaged UI returned to Ready with Authorize available and
an explicit cancellation notice (`ui-denied.jpg`). The notice incorrectly appended
an installation hint despite the installed runner already being valid. The final
text-only fix attaches that hint solely to installed-image validation failure;
cancelled/failed UAC preserves its own diagnostic. Authentication and lifecycle
logic are unchanged. No scan or background inspection was started by these checks.
