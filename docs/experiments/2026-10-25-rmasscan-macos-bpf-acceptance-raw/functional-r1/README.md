# Part A: macOS feth functional, functional-r1 (rmasscan-lab 717e45c, verifier 2989ace)

`macos-suite --suite functional-r1 --plan functional`, 24 runs plus 4 pause/resume groups, run 16:15 to 16:18 local 2026-10-25.
Verdict: overall PASS, `{"FAIL":0,"INVALID":0,"NOT RUN":0,"PASS":29}` (manifest + 24 runs + 4 groups). SYN bytes and order equal the C fixture without normalisation; Open/Closed results equal the wire truth with no duplicates; x01 rejects the foreign replies; `refuse_completed` sent no SYN.
No pair-quiet refusal, no rerun, no discarded or aborted run.

## Verdicts
c01 x2, c02 x2, c03 x2, c04 x2, c05 x2, c06 x2, x01 x2, pause_N0/N1/N8/N15, resume_N0/N1/N8/N15, complete_nopause, refuse_completed, group_pause_resume_N0/N1/N8/N15: all PASS.

## Uplink and safety
Uplink (`en0`) lab-filter captures: 0 frames in all 24 runs (every `runs/*/uplink.pcap` is the 24-byte header, `dropped by kernel` 0). `status-pre.json` and `status-post.json` show `raw_run_allowed: true` in every run. No foreign SYN, no suite exit 13. Frames were written only on the sealed pair; the peer-side guard refused nothing (x01 `guard_refused` 0).
x01 injected 60 frames per run (20 each of unscanned port, wrong cookie, wrong destination port); every frame marked as injected on the wire is one the injector recorded writing (3 kinds, sha256 per kind in `injector.json`); none became a result.

To re-verify: `rmasscan-lab macos-verify --dir functional-r1` (built from `2989ace`) on a scratch copy; captures are stored uncompressed.

## Provenance
- Code commit under test: `717e45c7c7fc1340b4dc24cb1ecb65c1c6e22e0f` (clean detached worktree, `git_dirty=false` in every manifest).
- Verifier: `macos-verify` built from `2989ace` (re-verification accepted by the controller; the first verdicts of the same evidence from the `717e45c` verifier were all INVALID because `net.inet.icmp.icmplim` does not exist on Darwin 27 and are superseded).
- Orchestrator `rmasscan-lab` (macOS, `RMASSCAN_LAB_BUILD_COMMIT` = the commit, private `CARGO_TARGET_DIR`, `CARGO_INCREMENTAL=0`): sha256 `e07510ce09e8612d1bfc4fe913974179e5fb70190c8c1574b888c83fd61b678a`.
- Scanner `wire_scan` (`cargo build --locked --release -p rmasscan-net --example wire_scan`, `RMASSCAN_SOURCE_COMMIT` = the commit): sha256 `3446f3c8403028d5c3f3b5b045374cef9989023a03d5222f0bd5f95324dc7951`, size 830432; the same sha256 is in every `meta.json` and the manifest.
- C-oracle fixtures (`fixtures/`, also copied into each suite directory): taken on minipc with the pinned masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614` by the `f72115a` lab build, binding src MAC `02:ac:00:00:00:01`, peer MAC `02:ac:00:00:00:02`, source IP `198.18.0.1`, `responder_open_ports` `8000,8001,8002,8003,8004,8005,8006,8007`, `all_valid: true`. The verifier pins only `responder_open_ports`, so the fixtures stay valid for `717e45c`.
- Stand: sealed `feth4201` (scanner, `02:ac:00:00:00:01`) and `feth4202` (peer, `198.18.0.2/30`), run id `m1`, uplink `en0`; the only scan target is `198.18.0.2`. BPF access was `granted` for every run except the two permission runs (`denied`).
- Text files: the user home directory was replaced by `$HOME`, the agent scratch directory by `$SCRATCH` and the worktree/repo by `$REPO`; `/home/a1` (minipc) by `$HOME`. Pcaps and checkpoint `.bin` files are untouched. Because the verifier checks every file of a run against `hashes-before-copy.txt`, that file was regenerated on the scrubbed copy (sha256 of the scrubbed text files, sha256 of the pcaps); the hashes taken before the copy and before the scrub are kept in this repository as `../original-precopy/<dir>.sha256` (see `../original-precopy/README.md`). `verdict.json` was regenerated on the scrubbed copy and its per-run results are identical to the in-place verdict.
- Run order of the whole acceptance: fixtures, functional-r1, perf-r1, failure-r1 (without linkloss and perm), then linkloss (two attempts) and, after the user's `bpf-access --revoke`, the two permission runs.

## Mac rules in force for this evidence
- No silent ports: `net.inet.tcp.syncookie = 1`, so a kernel port that drops SYNs cannot exist. `8099` and `8100-8119` are ordinary closed ports; `listeners.json` records `silent: []`, `silent_unavailable: darwin-syncookies`. x01 results must be a subset of the genuine wire replies, injected frames are identified by sha256; "empty receive path" is a NOT RUN note.
- 80 and 443 are closed (a non-root peer cannot bind them); the peer listens on `8000-8007`. Open truth for this evidence is derived from the wire (the peer witness), not only from the listeners.
- Closed-port RST rate limit: Darwin 27 has no `net.inet.icmp.icmplim`; the limiter is `net.inet.tcp.rst_rlc_enable` / `rst_rlc_bucket_ms`. A missing RST is not a scanner failure; results must contain every open port, nothing unknown and no duplicate.
- The host keeps wildcard listeners and the kernel sends teardown RSTs after completed handshakes; the verifier tolerates them under its rules (genuine wire replies only).
- The pair-quiet gate (interface counters must not move for about a second before a run) refuses a run with NOT RUN, rc 2, before anything is started, when stray traffic (mDNS-like, one to three frames) crosses the pair. The suite was restarted with `--only <remaining tags>` after each such refusal. No `--rerun`, nothing discarded.
- macOS does not give nanosecond pcap precision; `tcpdump` "received" is informational only.
