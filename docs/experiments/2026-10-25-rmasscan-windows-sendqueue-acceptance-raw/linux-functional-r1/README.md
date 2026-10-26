# linux-functional-r1 (engine regression on minipc)

Provenance: commit `628fcad7118943642dc797a0432b62851fbe6c1d` from `git archive` on minipc (`~/rmasscan-live`), `rmasscan-lab` sha256 `490c91ea4dd0481fd11d6791178d3795f3a887a07053ce5c26fe361ad82740c8`, `wire_scan` sha256 `718681d3b5d6651592b391b662dabfc4f4e4394f8031269e28a4e070c17c5ca2` (`RMASSCAN_SOURCE_COMMIT` set), oracle masscan `8afc8ec8...` (8e6b3b0), `scripts/wire-lab.sh --suite rust` with fixtures `tests/golden/wire`, `sudo -n` on minipc, sealed netns/veth lab (no uplink). Command line in `linux.log`/`commands.txt`.

## Result

`results.json` totals: **145 PASS, 0 FAIL, 0 NOT RUN** (the brief expected 141; the suite now counts 4 more checks than the 2026-10-24 acceptance, none failed). `identity.tx_mode` is `"single"` in every run summary (28 scan summaries, `tx_batches` 0, `tx_over_budget` 0), as expected for `max_batch 1`. Cleanup line: `namespaces_left=0`, `stray_processes=0`. There is no Windows eno1/stand involvement; this run touched only minipc namespaces.
Hash list taken on minipc before the copy: `linux-out.sha256` (259 files), verified after the copy. `MANIFEST.sha256` is the Mac-side list.
Note: minipc ran unrelated background work (headless Chromium) at the time; not touched.

## NOT RUN / restarts

First start failed in 0 s with `Build rmasscan-lab or set RMASSCAN_LAB_BIN` (my build command had not built `rmasscan-lab`); no lab was created, nothing run. Two restarts, then the run above.
