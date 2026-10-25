# Smoke of the Rust harness, one run (rmasscan-lab 9ecbe32)

One live run `c01_one_addr_port_synack.run1` of `windows-suite --suite smoke-rust-9ecbe32 --plan functional --only c01_one_addr_port_synack.run1`.
Run verdict PASS; overall NOT RUN by design (27 planned runs not executed): `{"FAIL":0,"INVALID":0,"NOT RUN":27,"PASS":2}` (manifest + the run).
- Code commit: `9ecbe32f82aac77d15575c855dfaa4c10c101ab4` (branch feat/rmasscan-stage2b-windows).
- Orchestrator/verifier: `rmasscan-lab` built on the Mac from that commit (`RMASSCAN_LAB_BUILD_COMMIT`), sha256 `5270672c5d748f15348c512d10d41f939aedc2f160f4293c8eebc561d11fd0a5`, run from a clean clone (`git_dirty=false`).
- home-pc binary (`$HOME/winvm/lab/bin/rmasscan-lab`, built from `git archive` of the commit with rustc 1.99.1): sha256 `2ad4d789280a167dd3a6ed1930682b9e89b7b773674139e642d7495fd3f1544b`, size 3127648; deploy manifest sha256 `a4d070d3d60af3ef71136dd13397e1b3aa847593d6107449f3ee3b9e7d895a7d` (copy in `deploy/deploy-manifest.json`).
- Guest `wire_scan.exe` (built on the guest from `git archive` of the commit, `RMASSCAN_SOURCE_COMMIT` = full sha, release, `+crt-static`): sha256 `362632ce174395e6a77aea7a2e97420a2e1e6dcf8bd9becbc1f12f5558d34c90`, size 629760; the same sha is in every `run.json` identity.
- Stand: sealed n2 (bridge wvb-n2, netns wvp-n2), binding `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}`, 198.18.0.1 / 52:54:00:04:80:a9, peer 198.18.0.2 / 02:57:4c:3d:2e:9b. Fixtures are the pinned masscan `8e6b3b0` ones reused from `functional/fixtures`.
- capture_schema 3; every run passed the suite raw-run gate (guest Verify with nonce, record-guest, full status raw_run_allowed=true). eno1 shows 0 lab frames in every run (`runs/*/capture.json`: `eno1.pcap.frames` = 0).
- Provenance warnings in the verdict: none. Home paths in text files were replaced by `$HOME`; pcaps and `checkpoint.bin` are untouched. The scrubbed copy was re-verified with `windows-verify` (same verdict).
- One environment note: the scp helper of the suite failed with "command output collection exceeded deadline" (exit 2, NOT RUN, refused before any remote mutation) three times while other ssh sessions were running against home-pc in parallel; with no parallel ssh it did not recur. Those attempts left no evidence here.
- Preflight clock: guest minus home-pc 0.48 s, uncertainty 3.5 s.
- A second scratch smoke (`x01_foreign_replies.run1`, inject path) also passed, with eno1 0 frames; it is kept outside the repository.
- NEW-4 (process group of peer tools started through sudo), sampled on home-pc with ps during a live run: the `timeout` wrapper is the group leader (pgid = its pid) and the inner `sudo -n ip netns exec`, `rmasscan-lab peer listen`/`peer inject` and both `tcpdump` processes are all in that pgid. The group KILL therefore reaches them.
