# Path to a usable release

Updated 2026-11-11. This development branch has ordinary IPv4/TCP profiles for
macOS, Linux and Windows, with IPC v5 and matching packaged helpers. It is not
fixture-only. The separate macOS fixture profiles keep their admission checks.
The engine includes the IPv4 CLI protocol work merged in PR #55. Studio's
profiles remain TCP-only; UDP, ICMP, SCTP and ARP scanning are not exposed in its UI.

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
- [x] Exercise the clean macOS `de7ee4ad` release on two direct owned peers,
  including JSON/SQLite/packet comparison, Pause/reopen/Resume and same-window
  Stop/Start. Repeat matching acceptance after any later runtime integration.

Latest UI evidence: [draft queue and native export](../docs/experiments/2026-11-10-studio-native-ui.md).
Keyboard follow-up: [macOS event diagnosis and verification](../docs/experiments/2026-11-10-studio-keyboard.md).
Latest UI completion: [native Save, input layouts and minimum width](../docs/experiments/2026-11-10-studio-ui-finish.md).
Latest native release: [static SQLite and physical lifecycle](../docs/experiments/2026-11-10-studio-native-release.md).
Fault follow-up: [sealed network interruption, recovery and coverage](../docs/experiments/2026-11-11-studio-fault-acceptance.md).

## 2. Physical-network acceptance

- [x] Implement bounded native profiles, read-only route checks, authorized
  preparation, persisted coverage and destination MACs, and frozen Resume identity.
- [x] Preserve separate fixture admission; unsupported profiles never fall back
  to an ordinary network profile.
- [x] Verify source/interface selection and direct delivery, Stop,
  Pause/reopen/Resume and restart on the clean macOS `de7ee4ad` release, with
  29 independently correlated probe/reply pairs.
- [x] Verify the exact `de7ee4ad` packaged runner on the isolated MacNetwork
  stand: 96 direct/routed probes, partial neighbour coverage, and interface-down
  interruption after 5 probes. Reopen/export Interrupted history in the release
  GUI and confirm Repeat settings creates only a draft.
- [ ] Verify routed delivery and partial neighbour coverage on ordinary physical
  profiles; the sealed MacNetwork stand does not establish that acceptance.
- [ ] Exercise network loss, route/interface changes, sleep/wake and stale
  observations; compare Interrupted status and partial history with packet capture.

Use explicitly authorized owned targets. Routes and neighbour tables are not a
source of authorization. Record which exact interface, targets and build were
accepted; do not generalize an isolated fixture or direct peer to routed networks.

## 3. Installation and distribution

- [x] Inventory complete packages and verify hashes; check macOS deep/strict
  ad-hoc signatures after all executable and SQLite load-path changes.
- [x] Link macOS package SQLite statically; reject GUI/helper pairs that cannot
  pass the retained-session dependency policy, even when signatures are valid.
- [x] Build in neutral paths and scan uncompressed packages for complete home
  paths plus known private tokens before creating distribution archives.
- [x] Automate Ubuntu 24.04 baseline packaging, direct GLIBC checks, X11/software
  Simulation and archive round-trip verification.
- [x] Reconcile current profile documentation with the implemented native gates.
- [ ] Accept first install, denied authorization, retry and update on the final
  native package. Retained development authorization is not a clean-install test.
- [ ] Obtain Developer ID/notarization and Windows publisher signing where
  required; ad-hoc/unsigned packages are local development artifacts.
- [ ] Complete the remaining native/distribution acceptance before publishing a
  release. Repository integration is authorized separately and does not establish
  installation, publisher-signing or untested physical-network acceptance.

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
