# Smoke of the perf plan, one cell (rmasscan-lab 847e218)

One live cell `perf.100.r1` of `windows-suite --suite smoke-perf-847e218 --plan perf --only perf.100.r1`.
Cell verdict PASS (median wire 100.3 pps); overall NOT RUN by design (19 cells not executed): `{"FAIL":0,"INVALID":0,"NOT RUN":19,"PASS":2}`.
- Code commit: `847e218bbd69c6151d781078df7bf03b00716cf7` (branch feat/rmasscan-stage2b-windows).
- Orchestrator/verifier: `rmasscan-lab` built on the Mac from a clean clone of that commit (`RMASSCAN_LAB_BUILD_COMMIT`, private `CARGO_TARGET_DIR`), sha256 `cfb589a6d79f8832e041e3019bec772ba9d8d3294b99c03ab31633472655f0de` (rebuilt twice, byte-identical), `git_dirty=false`. The manifest and preflight records carry this sha and `build_commit` = the commit.
- home-pc binary (`$HOME/winvm/lab/bin/rmasscan-lab`, built from `git archive` of the commit, rustc 1.99.1): sha256 `4dfd4e6f4da621eee67ea8d60b821f410e7bcd5d3df0ef3d91577281dd4178e9`, size 3201824; deploy manifest sha256 `7b599b1002641bfaf3591cb7509a031be2359ff9757017cfd08833a0e1b361ae` (copy in `deploy/deploy-manifest.json`).
- Guest `wire_scan.exe` (built on the guest, release, `+crt-static`, `RMASSCAN_SOURCE_COMMIT` = full sha): sha256 `cb44c91eb4714e5a663cb486ce1b64736436a6c5fda4c43568812d7b7fc32802`; the same sha is in every run.json.
- Stand: sealed n2 (bridge wvb-n2, netns wvp-n2); the plan sends only to 198.18.0.2. capture_schema 3; every run passed the raw-run gate (guest Verify with nonce, record-guest, full status raw_run_allowed=true). eno1 shows 0 lab frames in every run (every `runs/*/eno1.pcap` is the 24-byte header).
- Preflight clock: guest minus home-pc 0.518 s, uncertainty 3.40 s.
- Text files: `/home/a1` was replaced by `$HOME`; pcaps untouched; verdict.json regenerated on the scrubbed copy (same verdicts). The stored `deploy/deploy-manifest.json` therefore hashes to `0264d57969b7da45f89e5a0034fb57c191571b15fe03a081bcb2c0df3a33cc82`; reversing the substitution reproduces the recorded hash exactly: `sed 's#\$HOME#/home/a1#g' deploy/deploy-manifest.json | shasum -a 256` gives `7b599b10…361ae`.
- Provenance incident (disclosed): the shared cargo target dir `scratchpad/target-shared` was overwritten by another agent at 02:16:34 (a build without `RMASSCAN_LAB_BUILD_COMMIT`), then at 02:18:27 rebuilt. The smoke process had loaded the binary at 02:12 and was unaffected. perf-r1 was started at 02:18:24 from the private binary `scratchpad/live-win2/bin/rmasscan-lab` (sha256 above, built in `live-win2/target`). All manifests and preflights of smoke and perf-r1 record the same binary sha256 `cfb589a6…` and `build_commit` = the commit; nothing was discarded.
- Guest build of `wire_scan.exe`: source `git archive --format=tar 847e218bbd69c6151d781078df7bf03b00716cf7 rmasscan` (sha256 `d652a07b4752d5bcd2a3a9e85caa6f9c9c55454cb071d7897bccb3d3f001cca0`), extracted to `C:\Users\lab\src\rmasscan-847e218`; built with `build-guest.ps1` (sha256 `4c7600a7094f5731b6bb798e16b609275487d681047767eefdf0d054e91249a1`):
  ```powershell
  $ErrorActionPreference='Stop'
  $env:RMASSCAN_SOURCE_COMMIT='847e218bbd69c6151d781078df7bf03b00716cf7'
  $env:RUSTFLAGS='-C target-feature=+crt-static'
  Set-Location C:\Users\lab\src\rmasscan-847e218\rmasscan
  cargo build --locked --release -p rmasscan-net --example wire_scan
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Copy-Item -Force target\release\examples\wire_scan.exe C:\Users\lab\t4\wire_scan.exe
  (Get-FileHash C:\Users\lab\t4\wire_scan.exe -Algorithm SHA256).Hash
  ```
