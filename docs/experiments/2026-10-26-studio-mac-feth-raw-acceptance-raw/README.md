# Studio Mac feth raw acceptance: raw evidence

Raw files of the live windows of 2026-10-26 and 2026-10-27 on the sealed `feth` stand (`m1`: `feth4201` <-> `feth4202`, peer
`198.18.0.2`). The report is `../2026-10-26-studio-mac-feth-raw-acceptance.md`. Personal paths were scrubbed to
`$HOME`, `$REPO`, `$SCRATCH` when the files were written, so the hashes were never recomputed.

**GO evidence: `session-6b1deb5-r2/`**, on the final code `6b1deb5d0f88a1f31efb1d9f5eb538401bc66d85` (merge of `main` with the PR #28 network
guard in `studio-runner`; manifest `dirty: false`, profile `debug`).

| Binary | sha256 |
| --- | --- |
| `studio-ui` | `619f24de785b685cc1fc34d3ba102c6fbec322b47416daa4a1c68db18df36ba0` |
| `studio-runner` (bundle = installed) | `cf22b14834291a5f363e6d42e2dd9ff3d7fc180ae1216cc413c0d13c352380b6` |
| `rmasscan-lab` (verifier) | `c259a1b3c8d38ec5d58f7fdeb518b48ac9304822cab0bd43e2f8143071c05a07` |

History: the first windows (`session-05ab27f*`) ran on frozen commit `05ab27fb631da440539344cf8c600308149d4671` with runner
`e369e29dff4d89577ec58b87f5f86306312875c185305e00fe70ac23c4a943cb` (UI `eff51e58117f2cc7b6ed3690d3874a512a1ad4091db98a29339df14a921daa86`, lab
`e0e2f5170218763b51ed22045516a738efbafae4e0a54eaa9570b047d460733b`). The merge changed the runner bytes, so the window was repeated.

## Directories

| Directory | Meaning | Orchestrator rc | Verdict |
| --- | --- | --- | --- |
| `session-05ab27f/` | Attempt 1. The Studio Authorize dialog was shown at 20:27:13 and stayed unanswered; the UI gave up after 180 s ("Authorization timed out"). No scan started. | 10 | **NOT RUN** (`studio-verify` rc 2; `verification/session-05ab27f.verdict.json`). Uplink 0 frames, peer 2 frames (host mDNS only; `peer.pcap` withheld for privacy, see below). Not a code defect: the authorization service log shows the dialog shown and dismissed without credentials. |
| `session-05ab27f-r2/` | Attempt 2, same stand and same installed runner, dialog answered. Cases `s1_full`, `s2_pause`, `s3_stop`, then Lock. | 0 | **PASS 7/7** (`studio-verify` rc 0; `session-05ab27f-r2/verdict.json`). Uplink 0 frames, peer 1046 frames. |
| `session-6b1deb5-r2/` | **Final code.** Cases `s1_full`, `s2_pause`, `s3_stop`, then Lock; dialog answered. The peer witness uses the filter `not (ether src 02:ac:00:00:00:02 and udp port 5353)` (drops only the host's own mDNS, for privacy). | 0 | **PASS 7/7** (`studio-verify` rc 0; `session-6b1deb5-r2/verdict.json`). Uplink 0 frames, peer 1038 frames, 0 non-TCP/ARP. Checked for private strings before copying (0 hits). |
| `verification/` | Verifier outputs of all attempts, dry-run and gate-refusal summaries, status after `down`, scrubbed Mac, Linux and Windows test logs, `final.png` of attempt 2. | n/a | see the report |

Attempt 1 is kept as evidence of what happened; it is not a retry that hides a failure, and it is not counted as a
pass. The two attempts share one stand and one BPF grant (user actions B and F were done once per cycle: B and F twice
in total over the two cycles).

Four more attempts on the final branch are NOT copied; `verification/` holds one summary each (and the verdict or verify log where it is
free of private data): `session-d896d53` (NOT RUN before start: blind netstat refusal), `session-50d717e` (NOT RUN, Authorize
unanswered), `session-50d717e-r2` (INVALID by the orchestrator/verifier seam, behaviour checks PASS 6/6; its raw files are withheld for
privacy: host mDNS in `peer.pcap`, the host's application inventory in `leftover-listeners.txt` and `verdict.json`), `session-6b1deb5`
(NOT RUN, Authorize unanswered).

## Not in the repository

`session-50d717e-r2` (whole directory) is withheld for privacy: 4 frames of the host's own mDNS (host name, account name, device
services) and the host's application inventory. It is not GO evidence (INVALID).

`session-05ab27f/peer.pcap` (attempt 1) is withheld for privacy. Its 2 frames are only the host's own mDNS
announcements and queries seen on `feth4202` (the host name and home device names); they hold no lab frame and no scanner
frame. Its sha256 stays in `session-05ab27f/hashes-before-copy.txt` (`deb24aca7105d58c252162d00f9628b6ce16d7e39c4da2642d70e04143891559`)
as the record of what the witness captured. Attempt 1 is NOT RUN regardless of that file. The file was never part of a pushed
commit. Procedure note: review `tcpdump -r peer.pcap 'not tcp'` before copying a witness capture into the repository;
`198.18.0.2` is a host address, so mDNS on `feth4202` can recur.

`data/` (the SQLite file `history.sqlite3` and its lock file) is not copied (`sqlite3` is outside the language-guard
allowlist). The history is represented by `history.json` (dumped by Studio code through `studio-store` after the UI
exited) and `data.sha256` (hash of the SQLite file after the dump). `window.json` carries
`data_sha256_before_dump`, the hash before the dump opened the store; the two differ by design. The originals stay in
the scratch directory until the report commit and are deleted with it.

## Files in each session directory

`alf.txt` application firewall state; `bundle-manifest.json`, `provenance.json` hashes and commit; `status-pre.json`,
`status-post.json` stand gate before and after; `window.json` timing, pids, thresholds, invalid marks; `smoke.json`
chronicle of the UI run (actions, states, rows, timings); `history.json`, `data.sha256` history dump and its hash;
`peer.pcap` (withheld in `session-05ab27f/`, see above), `peer.err`, `peer.cmd.json` independent witness on `feth4202` (no filter in `session-05ab27f*`; the mDNS-dropping filter in `session-6b1deb5-r2`); `uplink.pcap`, `uplink.err`,
`uplink.cmd.json` witness on `en0` with the lab filter (24 bytes = empty pcap, 0 frames); `listeners-ready.txt`,
`listeners.log`, `host-listen-before.txt`, `host-listen-after.txt`, `leftover-listeners.txt`, `leftover-procs.txt`,
`pair-quiet.txt` gate and cleanup records; `sw_vers.txt`, `sysctl.txt` host facts; `ui.log`, `ui_rc.txt` UI output
and exit code; `final.png` last screen; `hashes-before-copy.txt` sha256 of every file before the copy (checked with
`shasum -a 256 -c` in the scratch directory before copying and on the copy after).

## Integrity

`MANIFEST.sha256` lists every file of this directory except itself (`shasum -a 256`, paths relative to this
directory). Check with `shasum -a 256 -c MANIFEST.sha256`.

## Observations

- Attempt 1: the Authorize dialog can sit unnoticed for its full 180 s. Recorded, not changed.
- `studio-verify` wording: for a missing Start it prints "the Start action of the case is in the chronicle" and for
  a UI that exited with rc 1 it prints "INVALID: the UI exited with code 0". The messages state the expectation, not
  the finding; the verdict words (NOT RUN, INVALID) are correct. Follow-up, not fixed in this stage.
- Host listeners were NOT recorded in either window: `host-listen-before.txt` and `host-listen-after.txt` hold only `rc 0`
  (netstat exited 0 with empty output, the reason was not kept), and `leftover-listeners.txt` is the empty output of a
  user-level `lsof` that sees only the user's own sockets. Do not read them as "no host listeners". The verifier now treats
  such a file as "not recorded" and judges the replies from the wire capture alone (complete peer capture required).
- `verification/*.reverify.json` and `.log` are the archives re-verified with the fixed verifier: r2 stays PASS 7/7, attempt 1
  stays NOT RUN (the withheld `peer.pcap` adds INVALID/NOT RUN reasons). The window directories are hash-pinned and were not
  changed; the old `verdict.json` and `verification/session-05ab27f.verdict.json` keep the original wording.
- The dry-run verdict in `verification/dryrun-05ab27f.verify.log` shows an INVALID host-listeners line for the same
  reason: the dry run records no host listeners.
