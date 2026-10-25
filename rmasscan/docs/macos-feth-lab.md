# macOS `feth` lab (sealed stand)

Purpose: live raw frames on macOS only ever touch a sealed pair of `feth` interfaces. The stand is
created and removed by the user with `rmasscan-lab macos-lab`; agents never run `sudo`,
`ifconfig create`, `arp -S` or `chmod` on `/dev/bpf*`.

## Constants

| Item | Value |
| --- | --- |
| Scanner side | `feth4201`, MAC `02:ac:00:00:00:01`, no IPv4 address, up |
| Peer side | `feth4202`, MAC `02:ac:00:00:00:02`, `198.18.0.2/30`, up, peer of `feth4201` |
| Scanner source IP | `198.18.0.1` (assigned to nobody; permanent ARP `198.18.0.1 -> 02:ac:00:00:00:01` on `feth4202`) |
| Only scan target | `198.18.0.2` |
| Manifest | `$HOME/.rmasscan-lab/macos-m1.json` (`--run-id m1`), marker `macos-m1.json.mark`, lock `macos-m1.json.lock` |
| BPF nodes | `/dev/bpf0..15` |
| Uplink capture filter | `net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host 02:ac:00:00:00:01 or ether host 02:ac:00:00:00:02 or ether proto 0x88b5` |

## What the stand does not change

Default route, DNS, pf/firewall rules, real NICs, `net.inet.ip.forwarding`. There is no uplink, no
bridge and no route out of `feth*` except `198.18.0/30` on `feth4202`. Nothing is permanent: `feth`
interfaces, the ARP entry and BPF permissions do not survive a reboot. `down` removes everything it
created, including the manifest, the marker and the lock file. The only residue is the extra
`/dev/bpf4..15` nodes the kernel created (they vanish on reboot; modes return to `0600 root:wheel`).

All system tools are run by absolute path (`/sbin/ifconfig`, `/usr/sbin/arp`, `/sbin/route`,
`/usr/sbin/netstat`, `/usr/sbin/sysctl`, `/usr/bin/id`, `/usr/bin/dscl`), so a `PATH` kept by `sudo`
cannot substitute another binary.

## User commands (run by you, in your own terminal)

Create the directory yourself first, so it is owned by you (otherwise root creates it and hands it
over to you through `SUDO_UID`):

```sh
mkdir -p ~/.rmasscan-lab && chmod 700 ~/.rmasscan-lab
```

The directory must be a real directory (not a symlink), owned by you or root, and not group- or
world-writable; `macos-lab` refuses anything else. Build once, then use the binary path (`$BIN`,
for example `$CARGO_TARGET_DIR/debug/rmasscan-lab` or `rmasscan/target/release/rmasscan-lab`):

```sh
M="$HOME/.rmasscan-lab/macos-m1.json"

# print what up/down will run, changes nothing, needs no root
"$BIN" macos-lab plan   --run-id m1 --manifest "$M"

# create the stand (root)
sudo "$BIN" macos-lab up         --run-id m1 --manifest "$M"
# let group staff open /dev/bpf0..15: 0660 root:staff for this session (root); read the risk below
sudo "$BIN" macos-lab bpf-access --run-id m1 --manifest "$M" --grant
# check the stand (no root); prints JSON, rc 0 sealed, rc 3 not sealed
"$BIN" macos-lab status          --run-id m1 --manifest "$M"

# take the access back at any time (root), e.g. for the perm_denied runs
sudo "$BIN" macos-lab bpf-access --run-id m1 --manifest "$M" --revoke
# only for part B link loss on the peer side (root)
sudo "$BIN" macos-lab link       --run-id m1 --manifest "$M" --down    # and --up

# remove everything (root): arp -d, destroy both feth, set BPF to 0600 root:wheel, delete manifest/marker/lock
sudo "$BIN" macos-lab down       --run-id m1 --manifest "$M"
```

Order for a session: `up`, then `--grant`, scans and spike, `--revoke` for the `perm_denied` runs,
`--grant` again, and finally `down`. `down` is safe to repeat. If `up` or `down` reports a failed
rollback (exit 10), the manifest is kept with `state: "rollback-incomplete"` and the list of
objects `up` created; run `down` again, it acts on that record.

`up` also opens `/dev/bpf0..15` as root: this Mac only has `bpf0..3` at boot, and macOS creates
the next node when the highest existing one is opened. `up` opens the existing nodes, repeats
until `bpf15` exists, then closes them all. If the kernel stops creating nodes, `up` fails and
rolls back.

## Risk of a granted session

`0660 root:staff` covers every regular local account, because group `staff` is the primary group of
all macOS users. While `bpf-access --grant` is active, **any process of any account in group staff
can read and inject raw frames on every interface, including `en0`, without root**, until
`--revoke`, `down` or reboot. The sealed-stand guarantee then rests only on the scanner being
pointed at `feth4201` and on the uplink witness. Nodes the kernel creates later (`bpf16` and up)
stay `0600 root:wheel`. Run `--revoke` whenever no run is active.

`--revoke` and `down` always set `0600 root:wheel` (mode first, then group); they never apply a value read
from the user-writable manifest. The manifest keeps the modes seen before the first grant for
information only; if any differed from `0600 root:wheel` (a ChmodBPF Mac), `down` says so and you
restore them by hand. A grant that fails half way reverts the nodes it changed and exits 10.

## Printing rules (`status`; also run inside `up` before the first change and after the last)

1. `feth4201` and `feth4202` exist, MACs equal the constants, `status: active`, `peer:` points at each other.
2. No `inet` on `feth4201`; exactly `198.18.0.2` mask `0xfffffffc` on `feth4202`. Every `inet`
   line counts; one without a readable netmask fails the check.
3. `route -n get default`: interface and gateway equal those recorded by `up`, and not `feth*`.
4. `netstat -rn -f inet` is read by its header columns (an unreadable or short row fails the check):
   no route through `feth*` except destinations inside `198.18.0.0/30` on `feth4202`;
   `route -n get 8.8.8.8` is not through `feth*`. Also (`lab_routes`): `route -n get 198.18.0.1`
   goes via `feth4202`, `198.18.0.2` via `feth4202` or `lo0`, and no other route overlaps the /30
   (a VPN or fake-IP tool adding one would carry the replies to the uplink).
5. `arp -an`: `198.18.0.1` is `02:ac:00:00:00:01` on `feth4202`, `permanent` (macOS prints `2:ac:0:0:0:1`; MACs are normalised).
6. No `ifconfig` bridge lists a `member: feth*`; `sysctl net.inet.ip.forwarding` is `0`.
7. `/dev/bpf0..15` exist. `bpf_access` is `granted` (every existing node `0660`, group `staff`),
   `denied` (every existing node `0600`, or none) or `mixed`.
8. Before `up`: the names `feth4201/4202` do not exist, nothing overlaps `198.18.0.0/30` (routes
   or interface addresses, same `overlap` logic as `vm-lab`), and the manifest and marker are
   absent. A foreign stand is never reused or touched.

`status` also requires the manifest `state` to be `sealed`, and prints
`{"raw_run_allowed":bool,"checks":[{"name","ok","detail"}],"bpf_access":"granted|denied|mixed","uplink":"en0",...}`.
`raw_run_allowed` is true when every check passes. It does not require `granted`: callers read
`bpf_access` themselves, because the `perm_denied` runs need `denied`.

## Exit codes

| rc | Meaning |
| --- | --- |
| 0 | ok |
| 2 | NOT RUN: bad arguments, a foreign object, an untrusted lab directory, no root for `up/down/bpf-access/link`, lock held, no stand recorded |
| 3 | `status`: the stand is not sealed |
| 10 | partial `up` (rolled back, or `rollback-incomplete` with the manifest kept), partial `down` (manifest kept, repeat it), partial `grant`/`revoke` |

## Manifest

`run_id`, interface names, MACs, IP, `uplink` and `gateway` at `up` time, `created` (objects `up`
is creating or created, written before each step) and `arp_set`, `bpf_nodes`, `bpf_prev` (mode and
group of each `/dev/bpfN` before the first `--grant`, kept across revoke/grant cycles),
`created_utc`, `token` (16 random bytes as hex, also in the marker file; `down`, `bpf-access` and
`link` refuse when they differ), `state` (`creating`, `sealed`, `rollback-incomplete`).

## Witness and probes on macOS

`tcpdump` argv: `tcpdump -i IF -n -U --immediate-mode -s 0 -w PCAP [FILTER]`. `-Z`, `-B` and
`--time-stamp-precision=nano` are left out on purpose, not because Apple's tcpdump rejects them:
the default libpcap buffer already equals `debug.bpf_maxbufsize`, `-Z` means nothing without root,
and nanosecond precision is not offered by macOS BPF (to be confirmed by the spike). Counters come
from `netstat -I IF -b -d -n` (the `<Link#` row; columns `Ipkts`, `Opkts`, `Ierrs`, `Drop` are
found by header name, a missing column is an error and the evidence INVALID). The interface-drop
figure is `Ierrs + Drop`; `Drop` is the send-queue drop count, not the analogue of Linux
`rx_dropped`. A down interface is printed as `feth4202*` and still matches.
