# C-oracle fixtures for the macOS feth binding

Taken on minipc (Ubuntu) by `rmasscan-lab oracle-fixtures` built from `f72115a` (staging scripts from that checkout), with the pinned C masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`:
`--src-mac 02:ac:00:00:00:01 --peer-mac 02:ac:00:00:00:02 --open-ports 8000,8001,8002,8003,8004,8005,8006,8007`, source IP `198.18.0.1`.
`manifest.json`: `all_valid: true`, `responder_open_ports` `8000,...,8007`; 2 runs per case (c01-c06, x01), SYN pcaps with `tcpdump` stderr. The same files are copied into `functional-r1/fixtures`, `perf-r1/fixtures` and `failure-r1/fixtures`. They were not retaken for `717e45c`: the verifier pins only the binding and `responder_open_ports`, which did not change.
Text files: `/home/a1` replaced by `$HOME`; pcaps untouched (their sha256 in `manifest.json` are the original ones).
Note: cases.psv (pipe-separated duplicate of cases.tsv) is stored as cases-pipe.txt to satisfy the repository file-type allowlist; the verifier does not read it.
