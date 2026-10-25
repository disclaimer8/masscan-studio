# Part C: macOS feth performance, perf-r1 (rmasscan-lab 717e45c, verifier 2989ace)

`macos-suite --suite perf-r1 --plan perf`, 20 cells (100/1k/10k/100k pps x 5, rep by rep), run 16:19 to 16:23 local 2026-10-25 (the 100k cells hold the wire rate).
Verdict: overall PASS, `{"FAIL":0,"INVALID":0,"NOT RUN":0,"PASS":21}` (manifest + 20 cells). No INVALID cell, no rerun, no discarded or aborted run, kernel drops 0.
Repository copy: the `peer.pcap` of the ten 10000 and 100000 pps cells (6 and 8 MB each) are stored as `peer.pcap.gz` (`gzip -9 -n`, lossless). The original sha256 and size of each are in `PCAP-GZ-ORIGINALS.txt` (and as the `peer.pcap` line of the run's `hashes-before-copy.txt`). To re-verify, work on a scratch copy and run `gunzip` there (not `gunzip -k` alone: with `-k` delete the leftover `peer.pcap.gz` afterwards, the verifier lists every file of a run) before `rmasscan-lab macos-verify --dir perf-r1`.

## perf_summary (medians over the 5 PASS cells per rate)
| rate pps | pass | rx_loss | median wire pps | rate_gate |
|---|---|---|---|---|
| 100 | 5 | 0 | 100.4 | MET |
| 1000 | 5 | 0 | 1014.0 | MET |
| 10000 | 5 | 0 | 10212.6 | MET |
| 100000 | 5 | 0 | 93808.6 | MET |

This measures a `feth` pair (kernel copy), not a physical NIC. The full per-cell values are in `verdict.json` (`perf_summary`).

## Uplink and safety
Uplink lab-filter captures: 0 frames in all 20 cells (24-byte headers). `raw_run_allowed: true` in every status-pre/post. No foreign SYN, no exit 13.
Pair-quiet NOT RUN restarts: 9 refusals during this suite (one to three frames of stray traffic on `feth4201` in the second before a cell, nothing started); each followed by `--only <remaining tags>`. One earlier restart attempt of mine was refused by the suite for a quoting mistake in `--only` ("unknown or unsafe tag", nothing started).

## Provenance
- Code commit under test: `717e45c7c7fc1340b4dc24cb1ecb65c1c6e22e0f` (clean detached worktree, `git_dirty=false` in every manifest).
- Verifier: `macos-verify` built from `2989ace` (re-verification accepted by the controller; the first verdicts of the same evidence from the `717e45c` verifier were all INVALID because `net.inet.icmp.icmplim` does not exist on Darwin 27 and are superseded).
- Orchestrator `rmasscan-lab` (macOS, `RMASSCAN_LAB_BUILD_COMMIT` = the commit, private `CARGO_TARGET_DIR`, `CARGO_INCREMENTAL=0`): sha256 `e07510ce09e8612d1bfc4fe913974179e5fb70190c8c1574b888c83fd61b678a`.
- Scanner `wire_scan` (`cargo build --locked --release -p rmasscan-net --example wire_scan`, `RMASSCAN_SOURCE_COMMIT` = the commit): sha256 `3446f3c8403028d5c3f3b5b045374cef9989023a03d5222f0bd5f95324dc7951`, size 830432; the same sha256 is in every `meta.json` and the manifest.
- C-oracle fixtures (`fixtures/`, also copied into each suite directory): taken on minipc with the pinned masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614` by the `f72115a` lab build, binding src MAC `02:ac:00:00:00:01`, peer MAC `02:ac:00:00:00:02`, source IP `198.18.0.1`, `responder_open_ports` `8000,8001,8002,8003,8004,8005,8006,8007`, `all_valid: true`. The verifier pins only `responder_open_ports`, so the fixtures stay valid for `717e45c`.
- Stand: sealed `feth4201` (scanner, `02:ac:00:00:00:01`) and `feth4202` (peer, `198.18.0.2/30`), run id `m1`, uplink `en0`; the only scan target is `198.18.0.2`. BPF access was `granted` for every run except the two permission runs (`denied`).
- Text files: `/Users/denyskolomiiets` was replaced by `$HOME`, the agent scratch directory by `$SCRATCH` and the worktree/repo by `$REPO`; `/home/a1` (minipc) by `$HOME`. Pcaps and checkpoint `.bin` files are untouched. Because the verifier checks every file of a run against `hashes-before-copy.txt`, that file was regenerated on the scrubbed copy (sha256 of the scrubbed text files, original sha256 for gzipped pcaps); the hashes taken before the copy and before the scrub are kept in `$SCRATCH/t7-evidence/<dir>.final-preCopy.sha256` (not in the repository). `verdict.json` was regenerated on the scrubbed copy and its per-run results are identical to the in-place verdict.
- Run order of the whole acceptance: fixtures, functional-r1, perf-r1, failure-r1 (without linkloss and perm), then linkloss (two attempts) and, after the user's `bpf-access --revoke`, the two permission runs.

## Mac rules in force for this evidence
- No silent ports: `net.inet.tcp.syncookie = 1`, so a kernel port that drops SYNs cannot exist. `8099` and `8100-8119` are ordinary closed ports; `listeners.json` records `silent: []`, `silent_unavailable: darwin-syncookies`. x01 results must be a subset of the genuine wire replies, injected frames are identified by sha256; "empty receive path" is a NOT RUN note.
- 80 and 443 are closed (a non-root peer cannot bind them); the peer listens on `8000-8007`. Open truth for this evidence is derived from the wire (the peer witness), not only from the listeners.
- Closed-port RST rate limit: Darwin 27 has no `net.inet.icmp.icmplim`; the limiter is `net.inet.tcp.rst_rlc_enable` / `rst_rlc_bucket_ms`. A missing RST is not a scanner failure; results must contain every open port, nothing unknown and no duplicate.
- The host keeps wildcard listeners and the kernel sends teardown RSTs after completed handshakes; the verifier tolerates them under its rules (genuine wire replies only).
- The pair-quiet gate (interface counters must not move for about a second before a run) refuses a run with NOT RUN, rc 2, before anything is started, when stray traffic (mDNS-like, one to three frames) crosses the pair. The suite was restarted with `--only <remaining tags>` after each such refusal. No `--rerun`, nothing discarded.
- macOS does not give nanosecond pcap precision; `tcpdump` "received" is informational only.
