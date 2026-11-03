# Path to a usable release

This branch is an unmerged, fixture-only macOS acceptance candidate. Passing its
tests does not make it a general network scanner or a distributable release.
The next work is ordered by user-visible outcome, not by test count.

## 1. Finish the real GUI path on an isolated local network

- [x] Launch the ordinary `.app` through macOS and preserve argument forwarding.
- [x] Reuse the existing development work session without another password.
- [x] Exercise GUI authorization, simulation completion, Stop and another Start;
  compare displayed results with durable history.
- [x] Run the optimized packaged GUI against the sealed multi-peer/routed fixture
  for Complete, Stop and another Complete in separate launches; independent root
  packet evidence passed (96, 5, 96 saved results on November 3).
- [x] Verify native Pause and Resume after restarting the packaged GUI: 5 then 91
  independently captured probes, 96 cumulative rows and consumed checkpoint.
- [ ] Verify same-window native Stop/Start and Pause/Resume on this package.
- [x] Check saved History, exact repeat settings, filtered/sorted projections and
  JSON/CSV writers using private copies of those real results (24 files verified).
- [ ] Exercise the native save-file dialog and asynchronous Export action.

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

- [x] Verify the optimized release build with its exact packaged helper on the
  isolated local fixture. Physical-interface acceptance remains separate above.
- [x] Reopen saved native results through the packaged GUI without changing history.
- [ ] Check first install, denied authorization, retry and update in the native GUI. Keep development host maintenance separate from the
  ordinary application's helper session.
- [ ] Perform manual keyboard/mouse, focus, resizing, scrolling and error-message
  acceptance. Callback automation and rendered snapshots cover only part of this.
- [x] Align the current profile labels and README with fixture-only execution.
- [ ] Reconcile documentation again if the supported target policy changes.
- [ ] Obtain release signing/notarization and an explicit publish/merge decision
  for a distributable build. Ad-hoc local signing is not that result.

## 4. Keep other platforms explicit

Windows and Linux have CI packages and earlier native helper-installation evidence.
That is not acceptance of their full network-scanning GUI. If included in the
release scope, each needs its own bounded owned-target lifecycle and installation
acceptance. Otherwise the first release must state its macOS-only scan support.

Latest work and exact artifacts:
[history and Resume report](../docs/experiments/2026-11-03-studio-history-and-resume.md),
[GUI/session report](../docs/experiments/2026-11-02-studio-gui-work-session.md),
[prior fixture capture evidence](../docs/experiments/2026-10-31-studio-macos-network-capture.md).
