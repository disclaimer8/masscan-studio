# macOS sealed network trial — 2026-10-30

Follow-up: the [October31 replacement-capture trial](2026-10-31-studio-macos-network-capture.md)
passed empty-capture shutdown and the complete fixed-fixture case; the remaining
lifecycle acceptance is incomplete. The failed trial below is retained unchanged.

**Result: native acceptance FAIL.** The actual Studio Controller/helper completed
the fixed scan with the expected results, but neither independent tcpdump process
terminated gracefully. Missing capture shutdown statistics and forced termination
remain failures; they are not waived because the application completed.

## Candidate and checks

- Source: `12131014cb8441f89896cbf127ae00c97e3cd668`, unmerged PR43.
- Host: macOS27.2, build26B123, ARM64; system tcpdump4.99.1 Apple161,
  libpcap1.10.1 (Apple library image148).
- Exact-source CI: macOS, Windows, Linux and language guards successful.
- Fresh local Studio workspace: 300 passed, 0 failed, 2 ignored, Apple SDK SQLite.
- Fresh engine workspace: 1416 passed, 0 failed, 23 ignored.
- Package: `studio/dist/build-1793296457448/Masscan Studio.app`.
  Strict/deep signature verification passed; packaged executables and the tool
  link only Apple system libraries/frameworks. Tool load commands were checked.
- Packaged/installed helper SHA256:
  `447942ee0162569fabc4733c0509c97f06fd948f3b2bd0687e4552a7ebcc7881`.
- Installed acceptance tool SHA256:
  `65ff197293b2262860b9d8c34a49edefbccac5001e16be6b33ab26f7d01c1c57`.

The ordinary reviewed installer placed both exact binaries in separate
hash-addressed root-owned directories, mode0755. The tool retains that installer's
`studio-runner` filename but is the xtask executable; it is invoked exclusively
with `network-acceptance`. No service was registered. The stable application and
its history were not replaced.

## Native observations

The operator granted macOS administrator access. The fixed feth4203/feth4204
stand was sealed and status validated. The normal helper authorization flow ran
from an ordinary-user Controller with isolated history.

An initial trial exhausted its ticket/authorization window. Its failed evidence
was retained as `run-1f2f69fbc7cba5bfe3ba63bfc726aa9d`. For the retry, stdout
tickets were written to a separate root-owned, publicly readable directory so
the ordinary-user driver could consume a ticket immediately; original captures,
seal and manifests remained in the private root-owned evidence directory.

Retry `run-13705a8b4f2a1295ce0f44dd14d1bf01` observed:

| Check | Measured result |
| --- | --- |
| Controller and reopened Store | Completed; 96 retained rows |
| Port outcomes | 48 open, 48 closed; driver's exact fixed-fixture validation passed |
| Direct/routed destinations | Fixed A/B peers and routed destination participated |
| Missing neighbour | Frozen report passed the exact fixture predicate, including the unresolved neighbour |
| Scanner SYNs in peer pcap | 96, independently counted using system tcpdump offline |
| Uplink pcap | 24-byte classic pcap header, no packet records |
| Raw peer shutdown | Exit0, trusted stop marker, 99 responses, measured kernel drops0 |
| Peer tcpdump shutdown | SIGINT then 5-second deadline; forced termination, no final statistics |
| Uplink tcpdump shutdown | Same failure |
| Strict offline lifecycle verifier | Refuses: `failed/incomplete supervisor manifest` |

These observations establish native packet exchange and application persistence
on this synthetic stand. They do **not** establish clean capture completion,
complete lifecycle acceptance, physical Wi-Fi scanning, or wired Ethernet support.
Do not synthesize capture counters or alter the retained failed manifest.

## Shutdown investigation

Passive loopback captures filtered exclusively to the synthetic fixture range
reproduced the problem without sending probes. SIGINT and SIGTERM commands
returned success, but the capture stayed alive and ultimately required SIGKILL
(exit137). The blocked-signal mask was0. A process sample after SIGINT showed:

```text
main -> pcap_loop -> pcap_read_bpf -> read
```

The administrative launch inherited ignored INT/TERM dispositions. However, a
small standalone diagnostic reset both to SIG_DFL before exec and the capture
still failed to stop. Therefore inherited dispositions alone are not a proven
cause. The existing harmless shell-child test also fails when its parent ignores
SIGINT, but that separate characterization is not a demonstrated tcpdump fix.
Changing SIGINT to SIGTERM or extending the deadline is unsupported by these
measurements. An impossible capture filter was also tried and refused at startup;
that attempt supplies no shutdown evidence.

The [libpcap documentation](https://www.tcpdump.org/manpages/pcap_breakloop.3pcap.html)
describes platform-dependent wakeup limits. This is relevant context, not proof
of the exact cause in the installed Apple build. The failure is presently bounded
to the measured system tcpdump and administrative launch path; no broader macOS
or Studio product defect is claimed.

## Evidence and remaining work

Private root originals remain under
`/private/var/run/studio-network-fixture-v1/run-<nonce>` for both nonces above.
An exported archive remains at
`/private/var/run/studio-network-tickets-20261030-1656/evidence.tar`:

```text
archive SHA256 40fa20c9f7fe22659348f38b159d1eb05d195a13c9500a2673bee4814d74bd75
peer pcap      aa86e484b6f25f0da52e763a21ba6c347db46e11e00bcec68aec4a5a7efe8522
uplink pcap    84d574a2ce7d10abbbd59cd7c94ccb9e96ac3f5cada39fc68d15f396801ebb6a
```

Local working evidence, isolated histories, test logs and diagnostic source are
under `.superpowers/sdd/2026-10-28-studio-macos-network/`, including
`native-20261030/`. These are local artifacts, not included in this PR.

Ownership-checked teardown succeeded. A fresh interface inventory showed no
fixture pair, the default route remained on en0, and no acceptance runner,
tcpdump or authorization process remained. Immutable installed binaries and
evidence were retained.

Before another scan, establish a bounded independent capture mechanism that
stops cleanly even with zero matching packets and produces trustworthy final
statistics. Reproduce that property on the actual host first. Any replacement
capture implementation requires its own review and validation; forced shutdown
must not be reclassified as success. Then rerun complete, preparation/running
Stop, Pause/restart/Resume and guard drift. Owned-target and visible UI acceptance
remain pending. The distributed physical gate remains closed.

## Capture replacement follow-up (native rerun pending)

Candidate `923334e44769e8026498a939c4ab6531e5f39363` replaces the supervisor's
tcpdump children with separate system-libpcap processes. Reads are nonblocking;
an owned anonymous pipe requests a bounded final drain and clean close. The
capture does not use the scanner's packet adapter or decoder. Root-owned evidence,
sealed topology, exact executable hashes, zero-loss counters, quiet windows and
strict lifecycle verification remain required. Manifest schema2 rejects older
capture provenance rather than reclassifying the failed trial above.

A passive root diagnostic using the installed system libpcap completed100 empty
nonblocking reads, measured a maximum read time of32 microseconds, reported zero
receive/drop/interface-drop counters and exited0. This establishes feasibility;
it is not native acceptance of the integrated replacement.

The replacement passed independent scoped review, full-workspace formatting and
Clippy. Its final complete local Studio run passed312 tests with2 ignored using
Apple SDK SQLite. Exact packet-count and byte-count boundaries also rejected
intentional off-by-one mutations, which were immediately restored. One preceding
full run failed the existing platform cancellation test's one-second timing
assertion. Temporary stage tracing and120 subsequent diagnostic suite runs did
not reproduce it; the original failure log is retained. Its cause is unresolved,
and no timing threshold or production cancellation code was changed.

Signed package `studio/dist/build-1793382752065/Masscan Studio.app` passed signature
verification and all three simulation checks: `--smoke`, `--smoke-pause` and
`--smoke-stop-race`. Packaged helper SHA256:

```text
e64c1b9181b6d579d13519b9136d601706b289fb2669e2627d34db86d3b1d574
```

Acceptance tool SHA256:

```text
21a15706878b968931695ddd6f33b66a9f8ff8b445402e729ab55dc7ce9ecd27
```

Both load only system libraries/frameworks. Prepared immutable installers and
six isolated lifecycle cases remain unexecuted. The actual integrated empty
capture must stop with measured counters before any scanner rerun.

CI initially queued during a [GitHub Actions incident](https://www.githubstatus.com/incidents/pwxsjgnvrk6b).
The macOS job then reported a scheduled `macos-14` runner brownout before executing
any steps. Both workflow matrices now use `macos-15`, following the
[official retirement notice](https://github.com/actions/runner-images/issues/13518).
This changes the CI host, not the application's native acceptance result. The
new head still requires successful macOS, Linux and Windows checks before the
prepared root installation and lifecycle trials.
