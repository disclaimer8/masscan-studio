# Studio integration evidence

Baseline scanner: `baa5cc789a6a7e96337835ad613d77f573a1f06a`.
Studio is a separate workspace/branch; scanner source unchanged.

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

Deferred minor from review: resolver operational failures can currently appear
as "No hostname" and be cached for 300 seconds; manual refresh bypasses this
cache. Distinguishing missing PTR from resolver failure remains open.

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
