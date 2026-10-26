# failure-r2 (part B, 18 runs)

Provenance: code commit `628fcad7118943642dc797a0432b62851fbe6c1d` (pinned, clean detached worktree, `git_dirty=false`); orchestrator `rmasscan-lab` built on the Mac with
`RMASSCAN_LAB_BUILD_COMMIT=628fcad7118943642dc797a0432b62851fbe6c1d` (sha256 `cd9990bdc12e1d0792772013e016381fdded520d70dcd747516625a28df50433`); home-pc `rmasscan-lab` sha256
`8eb4c633096ac871f3eed072fc066fb5716d1250ecbc26427be5929fa0456d44` from `git archive` (deploy manifest in `deploy/`); guest `wire_scan.exe` sha256
`091e834514d726f647678e802dcaad30a30aae43deddcd83167ca99cf08e8ae7` built from `git archive` on the guest (static CRT, `/DEPENDENTLOADFLAG:0x800`, dumpbin shows `0800 Dependent Load Flag`, see `../verification/guest-build-dumpbin-628fcad.log`).
Stand n2 (sealed), binding `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}` 198.18.0.1 -> 198.18.0.2 only, fixtures of masscan `8e6b3b0` reused unchanged. `--tx-mode sendqueue`.
Verdicts: `verdict-628fcad.json` is the verdict as produced by the 628fcad verifier; `verdict.json` is the FINAL verdict from the newer verifier `bbda664` (adds the perf wire-order-equals-plan check), run on this scrubbed copy. Both agree on every run.
Safety statement: every run was preceded and followed by a full `vm-lab status` with `raw_run_allowed: true`, guest Verify with nonce, peer capture on lab0 and an `eno1` capture with the lab filter. `eno1` showed 0 lab frames in every run; no safety trip, no exit 13. No firewall, route, DNS or NIC change; Npcap not touched; stand and VM not restarted.
Scrub: no personal paths occurred in this directory's text files (only `/home/a1` and `C:\Users\lab`, as in earlier rounds). Pcaps are uncompressed.

## Result

`verdict.json` overall **PASS** (19 items: manifest + 18 runs). `stop_*` x4 PASS: `stop_to_outcome_ms` stop_silent 37.4, stop_drain 44.9, stop_fullqueue 19.8, stop_load 9.0 (max 44.9 ms, bound < 1000), 0 SYN after the outcome. `linkloss` PASS: `Failed`, `tx_sent` 40, `tx_uncertain` 1, no checkpoint; the run took the one-frame `pcap_sendpacket` path (`tx_batches` 0, rate low), so no partial-transmit prefix case arose. `overflow_queue`, `rxloss`, `ckpt_*` x8, `perm_*` x3 PASS. `tx_over_budget` 0 in all runs; `tx_batches` 0 (single-frame path at these rates).
`eno1`: 19 `eno1.pcap` files (18 runs plus one discarded), 0 lab frames in total.

## NOT RUN / restarts

- First suite start: `stop_load` aborted before any capture started (Mac network error during the pre-run Verify: `scp failed (255): Read from remote host ... Can't assign requested address`; nothing sent). Evidence of that attempt in `runs_aborted/stop_load.r5ea61dc2fb7fad38dc39b889ce05cf31/`. A stale suite lock on home-pc (dead orchestrator's half-open `sh`+`cat`) was cleared by PID as documented; the stale partial dir was discarded with `--rerun --only stop_load` (`runs_discarded/stop_load.r2262d53c726507c9cc6f572a4bd159ca`, NOT RUN). Remaining tags were then run with `--only`.
- `linkloss` first attempt INVALID (end marker and flushed capture tail; tcpdump 177/177, 0 drops, eno1 0, status-post allowed). Reran alone with `--rerun --only linkloss`; first attempt in `runs_discarded/`. Reasons: `../failure-r2-rerun-reason.txt`.
