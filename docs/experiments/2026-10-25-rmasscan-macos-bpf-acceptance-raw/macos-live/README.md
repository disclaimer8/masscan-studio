# macos_live: live adapter tests on the sealed feth stand

The six `#[ignore]` tests of `rmasscan/crates/rmasscan-net/tests/macos_live.rs`, run once in the final grant window of stage 2C.

## Provenance

- Test binary: `macos_live-9ed5063391360979` (debug), built from commit `3e3886e` in a private target directory; sha256 `d9f31dca3685cdb535f7fccd32462f586a8c69ef767218dffb4ad658b6dafa2b`.
- Run as the user (not root), directly from the test binary: `macos_live-9ed5063391360979 --ignored --test-threads=1` with `RMASSCAN_BPF_LAB_MANIFEST=/var/run/rmasscan-lab/m1.json` and `RMASSCAN_BPF_OUT_DIR=<this window's output directory>`. The exact procedure is in `rmasscan/docs/macos-feth-lab.md` (section "Live adapter tests") and report section 11.
- Stand `m1` sealed; revoke and `down` were done by the user after the window.
- The files are copied unscrubbed (no personal paths were found). The pre-copy hash list is `../original-precopy/macos-live.sha256` (15 files, the files of this directory except `README.md` and `MANIFEST.sha256`); `MANIFEST.sha256` here lists every file except itself: `shasum -a 256 -c MANIFEST.sha256`.

## Gates

| Gate | Result | File |
|---|---|---|
| `macos-lab status` before | `raw_run_allowed: true`, `bpf_access: granted` | `status-pre.json` |
| Application Firewall | `Firewall is disabled. (State = 0)` | `alf.txt` |
| Listener on 198.18.0.2 before | none | `leftover-listeners.txt` (empty) |
| Leftover lab processes before | none | `leftover-procs.txt` (empty) |
| Uplink witness `tcpdump -p -n -i en0` with the lab filter, whole window | rc 0; 0 packets captured, 820 received by filter (counted before the filter on macOS, informational), 0 dropped by kernel; `uplink.pcap` is the 24-byte header: **0 uplink lab frames** | `uplink.pcap`, `uplink.err`, `window.log` |
| `macos-lab status` after | `raw_run_allowed: true` | `status-post.json` |

## Result

`test result: ok. 6 passed; 0 failed; 0 ignored`, finished in 20.36 s (`test.log`).

| Test | KV file | Result |
|---|---|---|
| `full_scan` | `macos_live__full_scan.txt` | round0 Completed sent 20 received 18; round1 Completed sent 20 received 17; tx_errors 0; 8 open replies each round; `mac_check=os-masked` |
| `stop` | `macos_live__stop.txt` | Stopped at sent 452; witness 452 SYNs settled and 452 after, witness alive, drops 0 |
| `pause_resume` | `macos_live__pause_resume.txt` | leg1 Paused sent 4; leg2 Completed sent 8; next_index 12; no gaps or duplicates |
| `rx_loss` | `macos_live__rx_loss.txt` | Failed(RxLoss { kernel_drops: 6555 }); junk_sent 19661 via the peer guard; scanner received 103 |
| `uncertain` | `macos_live__uncertain.txt` | Failed(TxUncertain) at sent 3; witness 3 of 3 |
| `latency` | `macos_live__latency.txt` | `max_per_call`: max_us_recv 143, max_us_send 55, max_us_health 85, max_us_idle_recv 34087 (about 34.1 ms, within 50 ms; IO_BUDGET 33 ms); over50ms 0 for send, recv and health |

The idle receive maximum of 34.1 ms is the first live measurement of the per-call contract on `feth`. It is not a proven bound under mbuf exhaustion or on a physical NIC.
