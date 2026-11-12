# Studio keyboard and minimum-width completion

Date: 2026-11-10. Branch: `integration/studio-current-engine`.
Clean package source: `7da5c184b16c8458136d2d5f8d543bcc4b4e3733`.
This continues the [keyboard investigation](2026-11-10-studio-keyboard.md).
It changes Studio UI and its acceptance checks. Protocol integration remains deferred.

## Changes and causes

At 820 logical pixels the previous header clipped the Theme button and scan
status. A software-rendered image and a failing geometry assertion independently
reproduced it: the Theme button began at x=728 and was 109 pixels wide.
Below 1100 pixels the actions now occupy a second header row, while branding,
mode and scan status stay on the first. At wider sizes the header stays compact.
The regression checks widths 820, 950, 1099, 1100 and 1160, including the longer
Cancel authorization button, separation from the mode and status, and bounds.
UI introspection is enabled in debug builds; release packages omit that metadata.

The pinned Slint macOS backend supplies an application menu without Edit.
Export now temporarily installs a standard AppKit Edit menu with Undo/Redo,
Cut/Copy/Paste and Select All. Nil-target actions use the native responder chain.
The menu is removed when Save succeeds or is cancelled, and an existing Edit
menu supplied by the backend is neither duplicated nor removed. No native key
logger or diagnostic event observer is shipped.

## Native keyboard evidence

Before and after adding the menu, automated Command+A in the system Save name
field appended subsequent text rather than selecting the filename, in both ABC
and Russian layouts. Edit > Select All by mouse did select it correctly.
A disposable observer saw automated key events in Studio but none in the Save
field. This identifies a difference at the system-panel input boundary, but does
not prove its precise cause.

The user then checked the open test Save panel with a physical keyboard and
confirmed that Command+A followed by 123 replaced the entire filename. That
confirmation belongs to the intermediate menu candidate, whose native menu
implementation is unchanged in the final package. It is not presented as a
physical-keyboard rerun of the final package. Automated Save-field Command+A
remains an automation limitation under investigation, not a passing test.

Studio search shortcuts were exercised in ABC, Russian and Ukrainian layouts.
In both Cyrillic layouts an ordinary A produced ф, while Command+A selected the
search text for exact replacement. Ukrainian also passed Shift+Down selection
and Command+C/F/A/V from the table. These observations used the disposable
candidate; the keyboard adapter is unchanged from `57ac3f32`. The input source
was restored to Russian. No claim is made for untested layouts or IMEs.

## Final package acceptance

- Full `cargo xtask test`: **484 passed, 0 failed, 2 ignored**; Clippy with
  warnings denied and formatting passed. The two external-service tests remain
  intentionally ignored.
- Packaged Complete, Pause/Resume/Stop and stop-race Simulation smokes exited 0
  in separate data directories. The stop-race smoke now sets the real native
  content area to 820x540; its 1640x1080 Retina snapshot shows every header
  action, status, saved rows and footer counters. The table retains horizontal
  scrolling. Native mouse-edge resizing was not successfully automated.
- Exact-source software renders cover Results, Settings, Scanner setup and
  History at 820x540, plus authorization and wide-header states. Settings uses
  vertical scrolling; these renders are not native interaction evidence.
- Native final-package Save: Undo reverted an appended character; Edit >
  Select All allowed a new filename; JSON saved 8 rows. Filtering for port
  8000 and saving CSV produced one row. Both exports match the isolated SQLite
  history, including IP, port, state and discovery timestamp.
- Save and Cancel removed the temporary Edit menu. Back in Studio, clicking
  search, Command+A and replacement produced exactly 8000 and one visible row;
  clearing it restored all eight. Shift+Down selected two rows; table
  Command+C/F/A/V pasted the single deduplicated IP into search.
- The manifest records a clean tree at the source above. All 7 inventoried files
  and deep/strict ad-hoc signatures verified. The separate UTF-8/UTF-16LE/UTF-16BE
  complete-home-path scan checked 8 files and found no matches. Direct
  `rmasscan-lab privacy-scan` with known private tokens found zero hits in the
  retained evidence/package and the staged source snapshot before committing.

This is a macOS debug, ad-hoc-signed development package. Fresh distribution CI,
notarization, clean installation and physical-network acceptance of the eventual
release remain separate work. Windows manual GUI/UAC acceptance stays excluded
by the user's instruction. No pull, push, merge, helper installation or physical
network scan was performed in this follow-up.

## Evidence

Neutral directory: `/private/var/tmp/studio-ui-finish-20261110/`.
Package: `package/Masscan Studio.app`; provenance: `package/manifest.json`.
The directory contains regression red/green logs, the full test log, source-only
render and disposable dialog probes, before/after renders, packaged smoke logs
and screenshots, `smokes.json`, exported JSON/CSV, `exports-verified.json`,
package verification and privacy logs, and `interactive-observations.json`.
Native interactions and the physical-keyboard confirmation are also retained in
the task transcript. Diagnostic candidates are distinct from `package/`.
