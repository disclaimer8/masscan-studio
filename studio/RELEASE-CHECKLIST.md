# Path to a usable release

Updated 2026-11-10. This development branch has ordinary IPv4/TCP profiles for
macOS, Linux and Windows, with IPC v5 and matching packaged helpers. It is not
fixture-only. The separate macOS fixture profiles keep their admission checks.
Protocol work in Claude's other branch is not integrated here.

Builds, CI, Simulation and physical-network acceptance are separate evidence.
Historical native results belong to the package identified in their dated report;
rebuilding after the history rewrite does not transfer that acceptance.

## 1. GUI, history and export

- [x] Label cumulative saved results separately from latest-run sent/received.
- [x] Prevent rapid draft edits from filling the command queue; retain explicit
  action order, cancellation epochs, bounded capacity and receiver-death errors.
- [x] Exercise native macOS JSON/CSV save dialogs, filtering and Cancel in
  Simulation; compare exports with SQLite. Reopen history and repeat exact
  settings without starting automatically.
- [x] Exercise ordinary and zoomed native window layouts; preserve visible
  counters, controls and result rows.
- [x] Diagnose the macOS modifier/Command-character failure and verify native
  automated Cmd+A/C/F/V, Shift selection and Tab/Shift+Tab in Studio fields and
  the results table, including return from a cancelled export dialog.
- [x] Supply native Save editing actions, verify Save/Cancel and post-dialog
  input, and obtain a physical-keyboard Cmd+A confirmation on the menu candidate.
  Automated Cmd+A in the system Save field remains unreliable; the report keeps
  that observation separate from the successful physical test.
- [x] Check Studio shortcuts with ABC, Russian and Ukrainian input sources.
- [x] Fix narrow-header clipping; verify geometry across 820–1160 logical pixels
  and run the final package's native stop-race smoke at 820x540. Mouse-edge
  resizing itself was not successfully automated.
- [ ] Repeat physical-network lifecycle and export acceptance on the exact
  eventual distribution candidate, including same-window Stop/Start and
  Pause/Resume. Historical fixture and direct-network checks remain historical.

Latest UI evidence: [draft queue and native export](../docs/experiments/2026-11-10-studio-native-ui.md).
Keyboard follow-up: [macOS event diagnosis and verification](../docs/experiments/2026-11-10-studio-keyboard.md).
Latest UI completion: [native Save, input layouts and minimum width](../docs/experiments/2026-11-10-studio-ui-finish.md).

## 2. Physical-network acceptance

- [x] Implement bounded native profiles, read-only route checks, authorized
  preparation, persisted coverage and destination MACs, and frozen Resume identity.
- [x] Preserve separate fixture admission; unsupported profiles never fall back
  to an ordinary network profile.
- [ ] Verify the final package's source/interface selection, direct/routed delivery,
  partial neighbour coverage, Stop, Pause/Resume and restart on owned devices.
- [ ] Exercise network loss, route/interface changes, sleep/wake and stale
  observations; compare Interrupted status and partial history with packet capture.

Use explicitly authorized owned targets. Routes and neighbour tables are not a
source of authorization. Record which exact interface, targets and build were
accepted; do not generalize an isolated fixture or direct peer to routed networks.

## 3. Installation and distribution

- [x] Inventory complete packages and verify hashes; check macOS deep/strict
  ad-hoc signatures after all executable and SQLite load-path changes.
- [x] Build in neutral paths and scan uncompressed packages for complete home
  paths plus known private tokens before creating distribution archives.
- [x] Automate Ubuntu 24.04 baseline packaging, direct GLIBC checks, X11/software
  Simulation and archive round-trip verification.
- [x] Reconcile current profile documentation with the implemented native gates.
- [ ] Accept first install, denied authorization, retry and update on the final
  native package. Retained development authorization is not a clean-install test.
- [ ] Obtain Developer ID/notarization and Windows publisher signing where
  required; ad-hoc/unsigned packages are local development artifacts.
- [ ] Verify CI and review for the eventual merge head, then obtain the user's
  release/merge decision. Integration with Claude remains deferred.

See [packaging requirements](PACKAGING.md) for privacy and provenance gates.
The unchanged official Windows SQLite DLL has one reviewed upstream PDB path;
report it explicitly instead of claiming the whole Windows package has none.

## 4. Platform scope

Linux and Windows native profiles are implemented, but CI and Simulation do not
establish desktop polkit/UAC or physical packet acceptance. Linux needs ordinary
user/desktop authorization and independent packet evidence. Windows manual
GUI/UAC/raw acceptance is excluded from the current work by user instruction;
it remains open for distribution readiness, not implicitly passed.

Historical evidence:
[platform release follow-up](../docs/experiments/2026-11-10-studio-release-followup.md),
[MacPhysical integration](../docs/experiments/2026-11-10-studio-integration.md),
[fixture history and Resume](../docs/experiments/2026-11-03-studio-history-and-resume.md).
