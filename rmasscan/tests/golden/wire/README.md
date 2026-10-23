# Wire oracle fixtures (stage 2B-Linux, task 4)

Ordered outgoing TCP SYN streams of the **original pinned C masscan**
(`8e6b3b0c07a81e8ea61d557c06134a21a6881614`, binary sha256 `8afc8ec8...a2b25e2a3e`; not the
`--offline`-patched copy) captured on an isolated veth lab. These are the reference the Rust
engine/adapter must reproduce byte for byte in tasks 5 and 6.

## Lab (scripts/wire-lab.sh)

Two network namespaces joined by one veth pair. Sealed: no uplink, no bridge, no NAT, no default
route, `ip_forward=0`, IPv6 off. The veth is created inside the scanner namespace with its peer moved
straight into the peer namespace, so no lab link ever exists in the host namespace. The script asserts
the seal before any traffic and fails closed. Topology and routes are saved before the first scan
(`topology-before.txt`) and after the last (`topology-after.txt`).

Binding (explicit in both namespaces): scanner `veth-a` MAC `02:aa:00:00:00:01`, adapter IP
`10.200.0.100` (assigned to no interface), router MAC `02:aa:00:00:00:02` (peer `veth-b`, which owns
`10.200.0.2-5`), seed 1, rate 100, `--blackrock-rounds 14`, `--retries 0`, `--wait 3`, explicit
source port. No ARP is needed (router MAC is explicit, peer has a static neighbour entry).
The peer namespace runs a responder: ports 80 and 8080 listen (kernel SYN-ACK), every other port
answers RST. A host `/etc/masscan/masscan.conf`, if present, is masked inside a private mount
namespace for the oracle (the host file is never edited); its presence and sha are in the manifest.

Capture: `scripts/wire_capture.py record` (stdlib AF_PACKET) runs in the peer namespace, started
before the scanner. Readiness is an explicit ACK: the lab sends a marker frame and waits until the
recorder acknowledges having captured it. Each run records `PACKET_STATISTICS` drops, truncated frames
and the interface `rx_packets` delta against the frames captured. Any drop, truncation or counter
mismatch marks the run `valid: false`, and the comparator then reports INVALID, never PASS.

Cleanup only touches this run's namespaces, tracked child PIDs and `.work` files (no global kill,
no firewall/route/bridge changes). Verified on success, on error and on SIGINT/SIGTERM.

## Cases

| case | targets / ports | SYN | SYN-ACK | RST (peer) |
| --- | --- | --- | --- | --- |
| c01_one_addr_port_synack | 10.200.0.2 :80 | 1 | 1 | 0 |
| c02_one_addr_port_rst | 10.200.0.2 :81 | 1 | 0 | 1 |
| c03_multi_addr_ports | .2-.5 :80,81,443,8080 | 16 | 8 | 8 |
| c04_exclude | .2-.5 :80,81, exclude .3 | 6 | 3 | 3 |
| c05_srcport_single | .2-.3 :80,81, source port 50123 | 4 | 2 | 2 |
| c06_srcport_range | .2-.3 :80,81, source port 50000-50015 | 4 | 2 | 2 |

Each case was captured twice; `<case>.run1.pcap` is the fixture and `run2` proves the oracle is
deterministic (`repeat_compare: PASS` in the manifest). `<case>.echo` is the effective `--echo`
config.

## Comparing

    python3 scripts/verify-wire.py --expected EXPECTED.pcap --actual ACTUAL.pcap \
        [--expected-meta M.json --actual-meta M.json]
    python3 scripts/verify-wire.py --self-test

Compares the ordered list of IPv4/TCP frames with only SYN set, byte for byte. Timestamps, ARP,
RST, SYN-ACK and other frames are ignored. Exit 0 PASS, 1 FAIL, 2 INVALID (truncated or malformed
pcap, no SYN in the reference, or capture meta with drops/truncation).

## Regenerating

On the oracle host (needs root via `sudo -n`, ip, python3):
`scripts/wire-lab.sh --oracle ~/rmasscan-oracle/masscan/bin/masscan --out DIR`, then copy the
`*.pcap`, `*.echo`, `manifest.json` and `topology-*.txt` files here. `manifest.json` records the
oracle commit and sha256, harness hashes, commands, OS versions, binding, expected counts,
capture drops/truncation and pcap hashes. Not captured here: replies as comparison material,
timestamps, large captures.

`manifest.json` is scrubbed on generation (`wire_capture.py::scrub`): host home paths become
`$HOME/...` and raw per-run namespace names become `wl-scan-RUNID` / `wl-peer-RUNID`, like the
topology files. Oracle provenance (commit, sha256, version line) and every pcap hash are left
untouched. The `harness` hashes describe the scripts of the run that produced the fixtures
(stage 2B task 4); `wire-lab.sh`, `wire_capture.py` and `verify-wire.py` were extended afterwards for
the Rust suites (task 6), so they no longer match those hashes by design.

The Rust side of this wire lab (`--suite rust|perf`, `scripts/wire_suite.py`) is described in
`docs/experiments/2026-10-23-rmasscan-stage2b-linux.md`.
