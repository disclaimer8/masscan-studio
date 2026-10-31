# Working-session native bootstrap — 2026-10-31

User requested one authorization for the working period. Implemented in e7c451e,
startup/path correction aa1ecbafb86a2f10d8124f307da2d8f5df4f55a1. Root host is
intentionally LEFT ACTIVE at user request; do not automatically stop it on task
completion. Installed binaries remain in place.

- Host PID97855, uid0, client account501.
- Tool SHA256: `8b62dedb4400b255ee6ec0e2a7f4cda93805d7136f260e4b01d5f9fe2c31a157`.
- Helper SHA256: `e64c1b9181b6d579d13519b9136d601706b289fb2669e2627d34db86d3b1d574`.
- Protected tool: `/Library/PrivilegedHelperTools/MasscanStudio/8b62dedb4400b255ee6ec0e2a7f4cda93805d7136f260e4b01d5f9fe2c31a157/studio-runner`.
- Runtime: `/Library/PrivilegedHelperTools/MasscanStudio/work-501`.
- Root directory0711, metadata0644, socket0666; socket operations require kernel
  peer identity and the approved caller hash. Private job files are0700/0600.

After the single successful startup authorization, the ordinary start CLI exited0.
A new CLI still observed the same root host. Two independent `work-session probe`
processes authenticated helpers PID98247 and98400, protocol3, both helpers exited
and their direct IPC endpoints were removed. HostPID97855 stayed ready with zero
active operations after each. Probes perform no scans or packet adapter opening;
legacy feth preflight correctly reported its missing manifest. A separate Python
socket client was rejected with `Caller build is not authorized for this working
session`. No additional macOS authorization occurred during either probe.

Full local Studio suite323 passed/0 failed/2 ignored before the scoped startup
fix;9 affected tests, Clippy, formatting and independent scoped review passed
for the startup/path changes. Exact-source aa1ecba Studio CI41195011191 passed all3OS, including packages.
The separate engine CI remains pending; no new engine code was changed. No new fixture/network test was run through
this host yet. Prior native Stop/Resume evidence and guard failure remain as
recorded in the network capture report.

The first tool8900b1... installed successfully but its detached startup never
became ready and suppressed its error output. That failed attempt is retained.
Separately found `/private/var/run` root:daemon0775 is incompatible with the
host's strict ancestor checks. The corrected version uses the protected install
namespace, a retained foreground authorization launcher, and bounded error output.
Do not present the original failure's exact initiating error as observed.

Use the stable installed tool above with `work-session status`, `probe RUNNER`,
`fixture ...`, or `export NONCE`. `work-session stop` is explicit, refuses active
jobs, and is NOT requested now. This version pins one tool/caller/helper build;
rebuilding checkout binaries does not silently authorize them. The stable
installed CLI continues managing the existing session. No launchd/sudoers entry,
password storage or generic shell channel was created.

Local logs: work-session-native-start.log (failed),
work-session-native-start-fixed.log, work-session-native-probe1.log,
work-session-native-probe2.log, work-session-native-ready.json. Root host and its
osascript launcher are intentional live resources, not leaked test children.
