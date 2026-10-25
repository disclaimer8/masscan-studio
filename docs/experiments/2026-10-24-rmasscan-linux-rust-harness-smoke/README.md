# Linux smoke of the Rust lab harness on minipc (live L1)

Code commit `9ecbe32f82aac77d15575c855dfaa4c10c101ab4` (branch feat/rmasscan-stage2b-windows), shipped with
`git archive --format=tar 9ecbe32 rmasscan scripts docs/experiments .github` to a fresh `~/rl-live` on minipc
(Ubuntu 26.04.1, kernel 7.0.0-38, tcpdump 4.99.6, rustc 1.99.1). This is a harness smoke (review findings LR M13 / LR2 / N2 / N4),
not a new acceptance of the scanner. All raw I/O ran inside the sealed namespaces `scripts/wire-lab.sh` builds
(seal assertions and `capture isolation` passed in every run; no failure). `$HOME` replaces `$HOME` in text files.

## Binaries (sha256)
- rmasscan-lab `fde090dee228b2113ec2f5edc4df51905fb0739252b66ef196a6610b62db4dfd` (built with RMASSCAN_LAB_BUILD_COMMIT=9ecbe32f...)
- wire_scan (`-p rmasscan-net --example wire_scan`) `ef92f6dc663927bcdfebc590ebfc4d8f009c176450395baf96cf05e86d3e423f`
- oracle `~/rmasscan-oracle/masscan/bin/masscan` `8afc8ec81f2e051389116908b01a4482b42e020bc48254585b7dcca4b25e2a3e` (pinned 8e6b3b0, original)
- `deploy-manifest.json` made by `rmasscan-lab deploy-manifest`; exported as RMASSCAN_DEPLOY_MANIFEST for every run.

## Runs and verdicts (common: `RMASSCAN_LAB_BIN`, `RMASSCAN_DEPLOY_MANIFEST` set; oracle as above)
| Dir | Command (from ~/rl-live) | Result |
|---|---|---|
| `rust/` | `rmasscan/scripts/wire-lab.sh --oracle ORACLE --out ev/rust --suite rust --rust-bin .../examples/wire_scan --fixtures rmasscan/tests/golden/wire` | rc 0, 3m22s, every check PASS (6 cases x 2 runs, pause/resume N=0,1,8,15, rejected resumes, stop_*, overflow, removed link), no INVALID |
| `perf/` | same with `--suite perf --reps 1` (default rates 100,1000,10000,100000) | rc 0, 3m30s, 8 cells all VALID, kernel drops 0 in every cell (C and Rust, run and stop captures), 100k NOT invalid; rust/C pps ratio 1.011, 1.004, 1.004, 1.005 |
| `oracle/` | default suite, unpatched script, `--out ev/oracle` (scratch) | FAIL rc 1 after the first run: script bug (see below). Nothing left over |
| `oracle-patched/` | same, scratch copy of `scripts/` with one line added (`oracle-patched` + `scratch-patch.diff`) | rc 0, about 3m50s, 6 cases x 2 runs, all captures valid, `manifest: all_valid=true`, no leftovers |
| `oracle-int`, `oracle-int2` | first SIGINT attempts | INVALID method: a backgrounded non-interactive job inherits SIGINT=ignored; the signal had no effect (int2 was then stopped with SIGTERM, rc 143, clean). Kept for honesty |
| `oracle-int3` (patched script, SIGINT at 12 s), `oracle-int4` (unpatched script, SIGINT at 5 s) | `timeout -s INT N wire-lab.sh --oracle ... --out ...` | both rc 130, log `cleanup: rc=130 ... stray_processes=0 namespaces_left=0`, .work removed, no tcpdump, no netns, link list == baseline |

Acceptance (`acceptance-linux_wire.txt`): `cargo test --locked --release -p rmasscan-net --test linux_wire -- --include-ignored` with
RMASSCAN_WIRE_RESULTS=rust, RMASSCAN_WIRE_PERF_RESULTS=perf: 11 passed, 1 failed. The five rust-result lab tests PASS.
The failure is `lab_perf_matrix_is_complete_and_invalid_cells_are_never_normalised`: it asserts 20 C and 20 Rust cells (5 reps) and
five values per rate, so a `--reps 1` run (4 + 4 cells) fails it at the cell count (`left: 4 right: 20`) before any drop check. That is the
test's 5-rep expectation, not a measured defect; the 5-rep run is still to be done. The stderr lines in the log from the three offline
"rejects ..." tests are their expected panics.

## Odd findings
1. `scripts/wire-lab.sh` `stop_bg()` ends with a `for` whose last `[ ... ] && PIDS[$i]=""` is false for the last element, so the function
   returns 1 and `set -e` aborts the oracle suite after the first run (rc 1, log only the cleanup line, no `oracle-stderr.txt`, no
   `manifest.json`). It is in the oracle path only (the rust/perf suites call it after the suite). Cleanup was still honest and complete.
   The scratch fix is `return 0` before the closing brace (`scratch-patch.diff`); the repository was not changed.
2. Kernel drops at 100k pps with `-U --immediate-mode`: 0 (LR N4 concern did not materialise on this host, 1 rep).
3. The oracle `--version` line reads "unavailable" in results.json; the binary hash and pinned revision checks pass.

## Leftover checks
Before the first run and after each of: rust, perf, oracle, oracle-patched, int, int2 (after SIGTERM), int3, int4:
`ip netns list` empty, `pgrep tcpdump` empty, no wl-/rmasscan-lab/wire_scan process, `ip -br link` names == baseline
(lo enp2s0 wlp1s0 wg0; `baseline.txt`, `baseline-links.txt`). A transient check during int2 showed the live run's own objects
(they were removed by the SIGTERM cleanup). `~/rl-live` was deleted at the end; nothing is running.

## Follow-up on commit 8fa086d (unmodified committed wire-lab.sh)
8fa086d16eb4cfebbc624093b5ed107ea959fbaa adds the `return 0` at the end of `stop_bg()`; nothing else changed. Fresh tree
(`git archive 8fa086d ...` to `~/rl-live2`), rmasscan-lab rebuilt with RMASSCAN_LAB_BUILD_COMMIT=8fa086d... (sha256
`38c16794002313cf5af24051ef7cf0736f22c19873d7c4f7eeab493f7c980940`), new manifest `deploy-manifest-8fa086d.json`.
| Dir | Result |
|---|---|
| `oracle-8fa086d/` | default oracle suite, scratch out dir, unmodified script: rc 0, about 3m50s, 12 runs valid, `manifest: all_valid=true`, cleanup `stray_processes=0 namespaces_left=0` |
| `oracle-8fa086d-int/` | `timeout -s INT 12` on the same script: rc 130, honest log, no .work, no leftovers |
Leftover checks after both: no netns, no tcpdump, link list == baseline; `~/rl-live2` removed. (The checker prints a harmless `baseline.txt` read error; the comparison used `baseline-links.txt`. The first attempt of this follow-up was lost when I removed the tree before copying; it was repeated in full with the same outcome.)
The earlier `oracle-patched/` run used a scratch copy with the same one-line patch that 8fa086d now carries; `oracle/` (FAIL) is the 9ecbe32 behaviour.
