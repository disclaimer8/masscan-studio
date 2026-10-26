# smoke functional (c01 one run)

Provenance: code commit `628fcad7118943642dc797a0432b62851fbe6c1d` (pinned, clean detached worktree, `git_dirty=false`); orchestrator `rmasscan-lab` built on the Mac with
`RMASSCAN_LAB_BUILD_COMMIT=628fcad7118943642dc797a0432b62851fbe6c1d` (sha256 `cd9990bdc12e1d0792772013e016381fdded520d70dcd747516625a28df50433`); home-pc `rmasscan-lab` sha256
`8eb4c633096ac871f3eed072fc066fb5716d1250ecbc26427be5929fa0456d44` from `git archive` (deploy manifest in `deploy/`); guest `wire_scan.exe` sha256
`091e834514d726f647678e802dcaad30a30aae43deddcd83167ca99cf08e8ae7` built from `git archive` on the guest (static CRT, `/DEPENDENTLOADFLAG:0x800`, dumpbin shows `0800 Dependent Load Flag`, see `../verification/guest-build-dumpbin-628fcad.log`).
Stand n2 (sealed), binding `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}` 198.18.0.1 -> 198.18.0.2 only, fixtures of masscan `8e6b3b0` reused unchanged. `--tx-mode sendqueue`.
Verdicts: `verdict-628fcad.json` is the verdict as produced by the 628fcad verifier; `verdict.json` is the FINAL verdict from the newer verifier `bbda664` (adds the perf wire-order-equals-plan check), run on this scrubbed copy. Both agree on every run.
Safety statement: every run was preceded and followed by a full `vm-lab status` with `raw_run_allowed: true`, guest Verify with nonce, peer capture on lab0 and an `eno1` capture with the lab filter. `eno1` showed 0 lab frames in every run; no safety trip, no exit 13. No firewall, route, DNS or NIC change; Npcap not touched; stand and VM not restarted.
Scrub: no personal paths occurred in this directory's text files (only `/home/a1` and `C:\Users\lab`, as in earlier rounds). Pcaps are uncompressed.

## Result

`verdict.json` overall NOT RUN by design (only one run planned): 27 NOT RUN by design, 2 PASS (manifest, c01 run1). eno1 0 lab frames. `perf.100.r1`: `tx_batches` 47, `tx_batch_max` 2, `tx_over_budget` 0; wire 100.8 pps.
