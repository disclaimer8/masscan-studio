# Part B, Rust harness (failure-r1)

`windows-suite --suite failure-r1 --plan failure`: 18 runs, 2026-10-25 01:07 to 02:16 (Europe/Lisbon, about 69 min).
Verdict: **overall PASS**, `{"FAIL":0,"INVALID":0,"NOT RUN":0,"PASS":19}` (18 runs + manifest). No INVALID, no discarded run, no `--rerun`.
- Code commit: `9ecbe32f82aac77d15575c855dfaa4c10c101ab4` (branch feat/rmasscan-stage2b-windows).
- Orchestrator/verifier: `rmasscan-lab` built on the Mac from that commit (`RMASSCAN_LAB_BUILD_COMMIT`), sha256 `5270672c5d748f15348c512d10d41f939aedc2f160f4293c8eebc561d11fd0a5`, run from a clean clone (`git_dirty=false`).
- home-pc binary (`$HOME/winvm/lab/bin/rmasscan-lab`, built from `git archive` of the commit with rustc 1.99.1): sha256 `2ad4d789280a167dd3a6ed1930682b9e89b7b773674139e642d7495fd3f1544b`, size 3127648; deploy manifest sha256 `a4d070d3d60af3ef71136dd13397e1b3aa847593d6107449f3ee3b9e7d895a7d` (copy in `deploy/deploy-manifest.json`).
- Guest `wire_scan.exe` (built on the guest from `git archive` of the commit, `RMASSCAN_SOURCE_COMMIT` = full sha, release, `+crt-static`): sha256 `362632ce174395e6a77aea7a2e97420a2e1e6dcf8bd9becbc1f12f5558d34c90`, size 629760; the same sha is in every `run.json` identity.
- Stand: sealed n2 (bridge wvb-n2, netns wvp-n2), binding `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}`, 198.18.0.1 / 52:54:00:04:80:a9, peer 198.18.0.2 / 02:57:4c:3d:2e:9b. Fixtures are the pinned masscan `8e6b3b0` ones reused from `functional/fixtures`.
- capture_schema 3; every run passed the suite raw-run gate (guest Verify with nonce, record-guest, full status raw_run_allowed=true). eno1 shows 0 lab frames in every run (`runs/*/capture.json`: `eno1.pcap.frames` = 0).
- Provenance warnings in the verdict: none. Home paths in text files were replaced by `$HOME`; pcaps and `checkpoint.bin` are untouched. The scrubbed copy was re-verified with `windows-verify` (same verdict).
- One environment note: the scp helper of the suite failed with "command output collection exceeded deadline" (exit 2, NOT RUN, refused before any remote mutation) three times while other ssh sessions were running against home-pc in parallel; with no parallel ssh it did not recur. Those attempts left no evidence here.
- Preflight clock: guest minus home-pc 0.59 s, uncertainty 3.5 s.
- `rxloss` reproduced the overflow: `Failed(RxLoss { kernel_drops: 67804 })` (kernel_drops is a lower bound, NPF scope), guest exit 3.
- `linkloss`: `TxUncertain`, exit 3. `overflow_queue`: `ConsumerTooSlow`, exit 3. After linkloss and at the end the stand status was up, raw_run_allowed=true.
- `perm_restricted_scan`: guest exit 2 (refused under the restricted token); `perm_restricted_inventory`: exit 5 (instructions); `perm_elevated_control`: exit 0.
- Repository copy: the two flood captures `runs/rxloss/peer.pcap` (36492900 bytes) and `runs/stop_load/peer.pcap` (13486902 bytes) are stored as `peer.pcap.gz` (`gzip -9n`, lossless), because together they would triple the size of the repository. Their original sha256 and size are in each run's `pcap-hashes-on-home-pc.txt`. Before re-verifying, run `gunzip -k runs/rxloss/peer.pcap.gz runs/stop_load/peer.pcap.gz`; without that step `windows-verify` cannot read those two runs. The verdict above was computed on the uncompressed captures, and a re-verify after `gunzip -k` gives the same result.

## Reproducibility notes (review W1: M1, M3, M4)
- **Deploy manifest hash.** `deploy/deploy-manifest.json` was scrubbed like the other text files (`/home/a1` -> `$HOME`, one occurrence), so the stored copy hashes to `ad34159b…`, not to the recorded `deploy_manifest_sha256` `a4d070d3d60af3ef71136dd13397e1b3aa847593d6107449f3ee3b9e7d895a7d`. Reversing the substitution reproduces the recorded hash exactly: `sed 's#\$HOME#/home/a1#g' deploy/deploy-manifest.json | shasum -a 256`.
- **Guest build of `wire_scan.exe`.** Source: `git archive --format=tar 9ecbe32 rmasscan` (sha256 `a406a16884dc9e35499a769827861b4311165403050a1d4376ef9b21745b93d2`; anyone can reproduce it from the repository), extracted to `C:\Users\lab\src\rmasscan-9ecbe32`. The operator built it with this scratch script, `build-guest.ps1` (sha256 `6e839a009667b41c31255372a029d17b747229c8e37707db7dc3621e57fede56`), because the `sync-and-test.sh` helper cannot set environment variables:
  ```powershell
  $ErrorActionPreference='Stop'
  $env:RMASSCAN_SOURCE_COMMIT='9ecbe32f82aac77d15575c855dfaa4c10c101ab4'
  $env:RUSTFLAGS='-C target-feature=+crt-static'
  Set-Location C:\Users\lab\src\rmasscan-9ecbe32\rmasscan
  cargo build --locked --release -p rmasscan-net --example wire_scan
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
  Copy-Item -Force target\release\examples\wire_scan.exe C:\Users\lab\t4\wire_scan.exe
  (Get-FileHash C:\Users\lab\t4\wire_scan.exe -Algorithm SHA256).Hash
  ```
  The exe reports its own `source_commit`, taken from `RMASSCAN_SOURCE_COMMIT`; the tar sha ties the built source to the commit.
- **scp shim.** Starting with the first successful smoke run, `scp` on the orchestrator's PATH was a pass-through logging shim (sha256 `449181547589e0ef950bd8c70e17ef4a5c1c15653c488f1aaf7e6db2099cd581`, computed on the unscrubbed file). It ran `/usr/bin/scp "$@"` unchanged and appended argv, timestamps and the exit code to a scratch log. Its content, with the scratch path replaced by `$SCRATCH`:
  ```bash
  #!/bin/bash
  echo "$(date +%T.%N) START $*" >> $SCRATCH/live-win/shim.log
  /usr/bin/scp "$@"; rc=$?
  echo "$(date +%T.%N) END rc=$rc" >> $SCRATCH/live-win/shim.log
  exit $rc
  ```
  pcaps are bound independently by the hashes taken on home-pc before the transfer (`pcap-hashes-on-home-pc.txt`). The JSON artifacts are hashed only after the transfer.
