# Studio macOS release: package admission and native lifecycle

Date: 2026-11-10. Branch: `integration/studio-current-engine`.
Accepted package source: `de7ee4ad382f55012e2d72ca27bc2e59a13e1e8f`.
Clean release/aarch64, IPC v5, ad-hoc signed, not notarized.
No merge or push; Claude's separate protocol branch was not changed.

## Packaging defect found during acceptance

The first clean release from `73c33b15` passed its inventory, signatures,
privacy checks and Simulation smokes, but the retained work-session host refused
to stage it. The GUI loaded SQLite from
`@executable_path/../Frameworks/libsqlite3.0.dylib`. The runner itself had only
system dependencies. The host stages both the GUI client and runner with the
same strict dependency validation; a dylib inside the app cannot follow a
copied executable into the protected helper directory. The diagnostic's wording
referred to a privileged runner, although the rejected executable was the GUI.

Reproduced without installation via `prepare-runner` on the GUI: exit 1.
An otherwise identical build with `SQLITE3_STATIC=1` had no external SQLite
load command and passed that same check. This preserves the selected Homebrew
SQLite implementation and the existing helper admission policy, including the
rejection of non-system dynamic libraries.

The macOS package command now forces static SQLite for its build. Packaging
and `verify-package` both validate the signed GUI/runner pair against the
existing policy. The macOS CI setup supplies static SQLite too. The updated
verifier rejects the original dynamic package and accepts the static package.
The workflow change has been checked locally; no new GitHub Actions run was
triggered because this branch remains local and integration is deferred.

## Exact package verification

- Full `cargo xtask test` with static SQLite: **484 passed, 0 failed, 2 ignored**;
  Clippy with warnings denied and formatting passed. Ignored external-service
  tests are not passes.
- The exact clean `de7ee4ad` release passed Complete, Pause/Resume/Stop and
  stop-race Simulation smokes in separate histories. The native stop-race
  snapshot again uses the minimum 820x540 logical content area.
- All 6 inventoried files, deep/strict signatures and GUI/runner admission passed.
  The UTF-8/UTF-16 complete-home-path scan checked 7 files including the manifest,
  with zero matches. Direct private-token scans of the package/evidence also
  returned zero hits.
- The ZIP contains neutral relative paths, permission bits and no UID/GID extra
  fields. A fresh extraction passed inventory, signature and admission checks.

## Native network scope and results

Existing SSH identities authenticated the previously used owned peers:
`192.168.1.148` on eno1 and `192.168.1.191` on enp2s0. Both listened on TCP/22;
TCP/65000 had no listener. The Mac route check selected en0, source
`192.168.1.128`, and direct delivery. The ordinary-user Studio window drove all
Start, Pause, Resume, Stop and export actions through CUA.

Independent tcpdump ran on each relevant peer, restricted to TCP involving the
Mac address and port 40000. Every capture started before Start and was stopped
through its verified controller PID. No broad uplink capture or route/interface
mutation was performed. A separate parser correlates SYN sequence numbers with
reply acknowledgements; all captures report zero kernel drops.

| Case | Job | Observed UI and history | Independent wire result |
| --- | --- | --- | --- |
| Complete | Two peers; ports 22,65000; rate 10; seed 61 | Completed; 4 rows; sent/received 4/4 | 4 SYN, 4 matched replies; 22 Open and 65000 Closed on each peer |
| Pause, close, reopen, Resume | One peer; 22,65000-65015; rate 1; seed 62 | Paused at index 7 with 7 rows, 278-byte checkpoint and 116-byte report; reopened as Paused; Resume before authorization did not leave Paused or send probes; authorize and Resume completed 17 rows, last-attempt counters 10/10 | Exactly 17 SYN and matched replies across both attempts, no repeated endpoint |
| Stop | One peer; 22,65000-65031; rate 1; seed 63 | Stopped; 6 saved rows, counters 6/6; remaining plan not sent | 6 SYN and matched closed replies |
| New Start in the same process after Stop | One peer; 22,65000; rate 10; seed 64 | Completed; 2 rows, counters 2/2 | 2 SYN and matched replies; 22 Open, 65000 Closed |

Four JSON exports were saved through the system Save panel. Their row counts,
IP/port/open values, discovery timestamps, scan IDs and original settings match
SQLite; the eligible plan counts are 4, 17, 33 and 2 respectively. The stopped
scan's 33 eligible probes describe its prepared plan, not 33 transmitted probes.
All 29 saved rows match independently correlated probe/reply pairs. TCP/65000
appears twice in the combined Stop/new-Start capture because those are two
intentional jobs with different seeds; neither job repeats an endpoint.

The Save panel's automated character input remained unreliable. Paths and
filenames were set through its exposed accessibility fields and then saved
with the normal Save button. This is export acceptance, not a new claim that
automated native-field keyboard input has been fixed.

## Authorization and remaining limits

The previously authorized development work-session host was reused. Only the
exact signed candidate GUI/helper hashes were staged. No host replacement or
fresh system authorization prompt was needed. After the native cases, Studio
was locked, the original client/runner configuration restored, and status
confirmed the same host PID with zero active clients. Capture controllers exited.
This is not clean-install, authorization-denial, update or publisher-signing
acceptance. The updated package verifier makes the discovered dependency
failure fail early; it does not certify a clean OS installation.

This pass covers direct peers on macOS. Routed targets, partial neighbour
coverage, network loss, route/interface changes and sleep/wake still require
native evidence. Linux desktop polkit and Windows GUI/UAC/packet acceptance are
not established; Windows manual acceptance remains excluded by the user.
The eventual merged/distribution head needs fresh CI and matching acceptance.

## Evidence

Neutral directory: `/private/var/tmp/studio-native-release-20261110/`.
Final bundle: `package-final/Masscan Studio.app`.
Archive: `masscan-studio-macos-aarch64-de7ee4ad.zip`; digest: `SHA256SUMS`.
`package/` is the rejected earlier dynamic-SQLite candidate, not the final one.

Retained files include the admission red/green logs, `package-regression.json`,
static full-suite log, final package checks and smokes, four packet captures with
capture exit/drop logs, `verify-captures.py`, `capture-summary.json`, four native
JSON exports, `paused-metadata.json`, `native-verification.json`, an SQLite backup,
restored-session status, archive round-trip verification and privacy logs.
Native UI observations are also retained in the CUA task transcript.
