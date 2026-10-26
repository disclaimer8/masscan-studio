# Studio Mac feth raw acceptance: raw evidence

Raw files of the live window of 2026-10-26 on the sealed `feth` stand (`m1`: `feth4201` <-> `feth4202`, peer
`198.18.0.2`). The report is `../2026-10-26-studio-mac-feth-raw-acceptance.md`. Personal paths were scrubbed to
`$HOME`, `$REPO`, `$SCRATCH` when the files were written, so the hashes were never recomputed.

Frozen commit C = `05ab27fb631da440539344cf8c600308149d4671` (code identical to `3113a85`; it adds only the committed
plan). Bundle `studio/dist/build-1793039025527`, manifest `dirty: false`, profile `debug`.

| Binary | sha256 |
| --- | --- |
| `studio-ui` | `eff51e58117f2cc7b6ed3690d3874a512a1ad4091db98a29339df14a921daa86` |
| `studio-runner` (bundle = installed) | `e369e29dff4d89577ec58b87f5f86306312875c185305e00fe70ac23c4a943cb` |
| `rmasscan-lab` (verifier) | `e0e2f5170218763b51ed22045516a738efbafae4e0a54eaa9570b047d460733b` |

## Directories

| Directory | Meaning | Orchestrator rc | Verdict |
| --- | --- | --- | --- |
| `session-05ab27f/` | Attempt 1. The Studio Authorize dialog was shown at 20:27:13 and stayed unanswered; the UI gave up after 180 s ("Authorization timed out"). No scan started. | 10 | **NOT RUN** (`studio-verify` rc 2; `verification/session-05ab27f.verdict.json`). Uplink 0 frames, peer 2 frames (host mDNS only; `peer.pcap` withheld for privacy, see below). Not a code defect: the authorization service log shows the dialog shown and dismissed without credentials. |
| `session-05ab27f-r2/` | Attempt 2, same stand and same installed runner, dialog answered. Cases `s1_full`, `s2_pause`, `s3_stop`, then Lock. | 0 | **PASS 7/7** (`studio-verify` rc 0; `session-05ab27f-r2/verdict.json`). Uplink 0 frames, peer 1046 frames. |
| `verification/` | Verifier outputs of both attempts, dry-run and gate-refusal summaries, status after `down`, scrubbed Mac, Linux and Windows test logs, `final.png` of attempt 2. | n/a | see the report |

Attempt 1 is kept as evidence of what happened; it is not a retry that hides a failure, and it is not counted as a
pass. The two attempts share one stand and one BPF grant (user actions B and F were done once).

## Not in the repository

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
`peer.pcap` (withheld in `session-05ab27f/`, see above), `peer.err`, `peer.cmd.json` independent witness on `feth4202` (no filter); `uplink.pcap`, `uplink.err`,
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
- The dry-run verdict in `verification/dryrun-05ab27f.verify.log` also shows an INVALID host-listeners line: the
  dry run recorded no host listeners, so it is correctly not evidence.
- `shasum -a 256 -c hashes-before-copy.txt` in `session-05ab27f/` reports the withheld `peer.pcap` as missing (the only expected miss); all other lines match.
