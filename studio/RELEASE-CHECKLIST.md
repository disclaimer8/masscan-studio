# Path to a usable release

This branch is an unmerged, fixture-only macOS acceptance candidate. Passing its
tests does not make it a general network scanner or a distributable release.
The next work is ordered by user-visible outcome, not by test count.

## 1. Finish the real GUI path on an isolated local network

- [x] Launch the ordinary `.app` through macOS and preserve argument forwarding.
- [x] Reuse the existing development work session without another password.
- [x] Exercise GUI authorization, simulation completion, Stop and another Start;
  compare displayed results with durable history.
- [ ] Run the packaged GUI against the sealed multi-peer/routed fixture for
  Complete, Stop and another Complete; require independent root packet evidence.
- [ ] Check saved History, repeat settings and exports using those real results.

## 2. Admit a concrete owned physical target

- [ ] Make a separately reviewed change replacing the fixed-fixture policy with
  a bounded owned-target acceptance policy. Keep the distributed gate closed.
- [ ] Verify source/interface selection, direct/routed TCP delivery, neighbour
  preparation, partial coverage, Stop, Pause/Resume and restart on an actual
  physical interface to a specifically authorized target.
- [ ] Exercise network loss, route/interface change, sleep/wake and stale guard
  observations; preserve truthful Interrupted status and partial results.

The current hotel network is not an authorized target inventory. The chosen safe
test is the isolated pair on this Mac; it does not establish physical Wi-Fi
delivery to another owned device. Do not select hotel clients or the gateway as
scan targets merely because they appear in routes or neighbour tables.

## 3. Make the accepted build installable and understandable

- [ ] Verify the optimized release build with its exact packaged helper.
- [ ] Check first install, denied authorization, retry, update and reopening saved
  history in the native GUI. Keep development host maintenance separate from the
  ordinary application's helper session.
- [ ] Perform manual keyboard/mouse, focus, resizing, scrolling and error-message
  acceptance. Callback automation and rendered snapshots cover only part of this.
- [ ] Reconcile README/verification documents with the final enabled profiles and
  clearly explain unsupported targets/protocols.
- [ ] Obtain release signing/notarization and an explicit publish/merge decision
  for a distributable build. Ad-hoc local signing is not that result.

## 4. Keep other platforms explicit

Windows and Linux have CI packages and earlier native helper-installation evidence.
That is not acceptance of their full network-scanning GUI. If included in the
release scope, each needs its own bounded owned-target lifecycle and installation
acceptance. Otherwise the first release must state its macOS-only scan support.

Latest work and exact artifacts:
[GUI/session report](../docs/experiments/2026-11-02-studio-gui-work-session.md),
[prior fixture capture evidence](../docs/experiments/2026-10-31-studio-macos-network-capture.md).
