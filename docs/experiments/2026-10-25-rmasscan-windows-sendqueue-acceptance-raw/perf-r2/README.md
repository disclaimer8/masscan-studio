# perf-r2 (part C, 20 cells, rep-major)

Provenance: code commit `628fcad7118943642dc797a0432b62851fbe6c1d` (pinned, clean detached worktree, `git_dirty=false`); orchestrator `rmasscan-lab` built on the Mac with
`RMASSCAN_LAB_BUILD_COMMIT=628fcad7118943642dc797a0432b62851fbe6c1d` (sha256 `cd9990bdc12e1d0792772013e016381fdded520d70dcd747516625a28df50433`); home-pc `rmasscan-lab` sha256
`8eb4c633096ac871f3eed072fc066fb5716d1250ecbc26427be5929fa0456d44` from `git archive` (deploy manifest in `deploy/`); guest `wire_scan.exe` sha256
`091e834514d726f647678e802dcaad30a30aae43deddcd83167ca99cf08e8ae7` built from `git archive` on the guest (static CRT, `/DEPENDENTLOADFLAG:0x800`, dumpbin shows `0800 Dependent Load Flag`, see `../verification/guest-build-dumpbin-628fcad.log`).
Stand n2 (sealed), binding `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}` 198.18.0.1 -> 198.18.0.2 only, fixtures of masscan `8e6b3b0` reused unchanged. `--tx-mode sendqueue`.
Verdicts: `verdict-628fcad.json` is the verdict as produced by the 628fcad verifier; `verdict.json` is the FINAL verdict, regenerated on this scrubbed copy by the verifier built from commit `fb36d0cc682b` (final fix round; `bbda664` added the perf wire-order-equals-plan check, `fb36d0c` only neutralises the `perf_summary` latency note text). Against the `bbda664` verdict overall, totals and every per-run verdict are unchanged; only `provenance.verifier` and, in `perf-r2`, `perf_summary.notes` differ. Both agree on every run.
Safety statement: every run was preceded and followed by a full `vm-lab status` with `raw_run_allowed: true`, guest Verify with nonce, peer capture on lab0 and an `eno1` capture with the lab filter. `eno1` showed 0 lab frames in every run; no safety trip, no exit 13. No firewall, route, DNS or NIC change; Npcap not touched; stand and VM not restarted.
Scrub: no personal paths occurred in this directory's text files (only `/home/a1` and `C:\Users\lab`, as in earlier rounds). Pcaps are uncompressed.

## Result

`verdict.json` overall **PASS** (21 items); every cell PASS, `wire_order_matches_plan` true in all 20 (bbda664 check). `rate_gate`: 100 MET, 1000 MET, 10000 MET, 100000 OPEN (VM ceiling with sendqueue; honest finding, not a FAIL). `tx_over_budget` = 0 in all 20 cells; kernel drops 0 in all cells. Per-cell 100k wire pps: 16785, 29483, 19440, 27451, 22533 (two VM speed modes as in the spike).
Medians (perf-r1 for comparison):

| rate | r1 wire pps (median) | r1 gate | r2 wire pps (median) | r2 gate | r2 in-process | r2 CPU user/kernel ms | r2 peak WS | r2 join ms | r2 drain s | r2 tx_batch_max |
|---|---|---|---|---|---|---|---|---|---|---|
| 100 | 100.7 | MET | 100.5 | MET | 100.5 | 15/453 | 10.0 MB | 0.135 | 3.04 | 2 |
| 1000 | 1006.7 | MET | 1006.8 | MET | 1007.0 | 78/828 | 10.0 MB | 0.121 | 3.054234 | 13 |
| 10000 | 6444.6 | OPEN | 9964.9 | MET | 9967.2 | 234/3406 | 12.4 MB | 0.135 | 3.06 | 64 |
| 100000 | 6321.1 | OPEN | 22532.8 | OPEN | 22539.1 | 156/3921 | 14.0 MB | 0.127 | 3.08 | 64 |

Peer pcaps are kept uncompressed (largest 9.4 MB); no file exceeds 95 MB. `max_per_call` of the batched path is in `../verification/windows_live/wl4-latency` (send_batch max 4611 us, 0 calls over 50 ms).
`eno1`: 20 files, 0 lab frames in total.

## NOT RUN / restarts

None. No `--rerun`.
