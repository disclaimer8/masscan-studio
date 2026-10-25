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
| State (root-owned) | `/var/run/rmasscan-lab/<run-id>.json` (`--run-id m1`), marker `m1.json.mark`, lock `m1.json.lock`; the directory is made by `up`, is cleared at reboot, and nothing is written under `$HOME` |
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

All state (manifest, marker, lock) lives in the root-owned `/var/run/rmasscan-lab/`. `up` makes it with a
single `mkdir` (mode 0755, owner root, no parents); every command refuses it if it is a symlink, not
a directory, not owned by root or group/world-writable. Files in it are created with `O_EXCL` (never
following a symlink), mode 0644, owner root, and are read only if they are regular single-link files
owned by root (and by no one else), not group/world-writable, at most 1 MiB. Nothing in the lab chowns
a file. Root never writes, renames or unlinks anything
in a user-owned directory. `--manifest` is optional; if given it must be exactly
`/var/run/rmasscan-lab/<run-id>.json`, anything else is refused before any action. `status` (no root)
reads the same world-readable file. `/var/run` is cleared at reboot, so after a reboot `status`
reports "no stand recorded" (rc 3) and the `feth` interfaces are gone too. Build once, then use the binary path (`$BIN`,
for example `$CARGO_TARGET_DIR/debug/rmasscan-lab` or `rmasscan/target/release/rmasscan-lab`):

```sh
# print what up/down will run, changes nothing, needs no root
"$BIN" macos-lab plan   --run-id m1

# create the stand (root)
sudo "$BIN" macos-lab up         --run-id m1
# let group staff open /dev/bpf0..15: 0660 root:staff for this session (root); read the risk below
sudo "$BIN" macos-lab bpf-access --run-id m1 --grant
# check the stand (no root); prints JSON, rc 0 sealed, rc 3 not sealed
"$BIN" macos-lab status          --run-id m1

# take the access back at any time (root), e.g. for the perm_denied runs
sudo "$BIN" macos-lab bpf-access --run-id m1 --revoke
# link acts only on a sealed stand whose manifest lists feth4202 as created; --up rewrites the
# ARP entry only when it is absent or (incomplete), leaves a complete permanent one alone, and
# exits 10 (nothing overwritten) when a complete entry that is not the lab's is there.
# only for part B link loss on the peer side (root). Darwin drops the static ARP entry when
# feth4202 goes down (it comes back "(incomplete)"); --up brings the interface up and restores the
# entry (arp -d, then arp -S, both with the lab constants), verifies it, and exits 10 with the
# manual fallback "sudo arp -d 198.18.0.1 ifscope feth4202; sudo arp -S 198.18.0.1
# 02:ac:00:00:00:01 ifscope feth4202" if it is not back.
sudo "$BIN" macos-lab link       --run-id m1 --down    # and --up

# remove everything (root): arp -d, destroy both feth, set BPF to 0600 root:wheel, delete manifest/marker/lock
sudo "$BIN" macos-lab down       --run-id m1
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
from the manifest (which only root can change). The manifest keeps the modes seen before the first grant for
information only; if any differed from `0600 root:wheel` (a ChmodBPF Mac), `down` says so and you
restore them by hand.

**ChmodBPF cost:** on a Mac that has its own BPF access setup (Wireshark's ChmodBPF, `access_bpf`),
`--revoke` and `down` replace it with `0600 root:wheel`. That setup stays gone until the next reboot
(when its launch daemon re-applies it) or until you restore it by hand from the modes `down` printed. A grant that fails half way reverts the nodes it changed and exits 10.

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

## Taking BPF access away without a stand

`bpf-access --revoke` and `down` set every existing `/dev/bpf0..15` to `0600 root:wheel` first and
do not depend on a valid manifest, a sealed stand or even a usable state directory (with root, and
the lock when it can be taken). `down` still exits non-zero when it refused the interfaces. If the
lab itself cannot do it, run by hand:

```sh
sudo chmod 600 /dev/bpf{0..15}; sudo chgrp wheel /dev/bpf{0..15}
```

A `down` with a refused or damaged manifest prints this line in its error output.

## Live adapter tests: `macos_live`

Six `#[ignore]` tests drive the product adapter (`open_explicit` and the engine) on the stand. They are not part of CI or of
`cargo test`; run them in a grant window, as you (never root), with the stand up and BPF granted. The window gives the same
evidence class as the suite: status before and after, a lab-filtered capture on the uplink that must hold zero frames, and
hashes. The procedure that was used (first run: all six tests passed, 0 uplink lab frames):

```sh
# 0. Build the test binary in your own private target directory (no network, no BPF), keep its path:
cd "$REPO/rmasscan" && CARGO_TARGET_DIR="$TARGET" cargo test --locked -p rmasscan-net --test macos_live --no-run
BIN=<the executable path printed by the command above>     # .../deps/macos_live-<hash>
LAB=<path of the rmasscan-lab binary built from the same commit>
OUT="$SCRATCH/macos-live-out"; mkdir -p "$OUT"
FILTER='ether host 02:ac:00:00:00:01 or ether host 02:ac:00:00:00:02 or ether host 02:ac:00:00:00:11 or net 198.18.0.0/30'

# 1. Gates; stop at the first failure and run nothing:
"$LAB" macos-lab status --run-id m1 > "$OUT/status-pre.json"       # need "raw_run_allowed": true and "bpf_access": "granted"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate > "$OUT/alf.txt"   # need exactly: Firewall is disabled. (State = 0)
/usr/sbin/lsof -nP -iTCP@198.18.0.2 -sTCP:LISTEN > "$OUT/leftover-listeners.txt"    # need an empty file
/bin/ps -axo pid,command | grep -E 'wire_scan|tcpdump .*feth420|peer listen|capture dump' | grep -v grep \
  > "$OUT/leftover-procs.txt"                                        # need an empty file

# 2. Uplink witness for the whole window (default-route interface, here en0), then the tests:
/usr/sbin/tcpdump -p -n -i en0 -w "$OUT/uplink.pcap" "$FILTER" 2> "$OUT/uplink.err" &  TD=$!
sleep 2; kill -0 $TD                                                  # the witness must be running
RMASSCAN_BPF_LAB_MANIFEST=/var/run/rmasscan-lab/m1.json RMASSCAN_BPF_OUT_DIR="$OUT" \
  "$BIN" --ignored --test-threads=1 > "$OUT/test.log" 2>&1; echo "test rc=$?"

# 3. Stop the witness (INT, rc 0), check status after, count the uplink frames:
sleep 1; kill -INT $TD; wait $TD; echo "uplink tcpdump rc=$?"
"$LAB" macos-lab status --run-id m1 > "$OUT/status-post.json"        # raw_run_allowed must still be true
/usr/sbin/tcpdump -n -r "$OUT/uplink.pcap" 2>/dev/null | wc -l       # must be 0 (uplink.err: 0 captured, 0 dropped by kernel)
grep -E '^test |test result' "$OUT/test.log"
```

Afterwards revoke the BPF access and take the stand down (`macos-lab bpf-access --revoke`, `macos-lab down`). "Received by filter" in
`uplink.err` is counted before the filter on macOS and is informational. Equivalent without the window script: `cargo test --locked
-p rmasscan-net --test macos_live -- --ignored --test-threads=1` with the same two environment variables, but then the gates and the
witness are yours to run.

The manifest only confirms the stand (every value must equal the plan constants, `state` sealed). Each test writes `KV` lines to
`$OUT/macos_live__<test>.txt`: `full_scan`, `stop`, `pause_resume`, `rx_loss`, `uncertain`, `latency`. The peer is a second adapter on
`feth4202` plus, for `full_scan`, listeners the test itself opens on `198.18.0.2:8000-8007` (the only open ports on the Mac;
`80` and `443` are closed, because a non-root bind to them is `EACCES`, and Darwin has no silent ports, syncookies), so a
full scan sees exactly 8 open replies. `latency` records the maximum duration per call type (`max_us_recv`, `max_us_send`,
`max_us_health`, `max_us_idle_recv`) and asserts each call returns within 50 ms.

## Acceptance runs: `macos-suite` and `macos-verify`

`macos-suite` is macOS only and runs entirely as you, never as root. It needs the stand up and BPF granted
(or denied, for the two permission runs); it checks both and refuses a run it cannot prove (NOT RUN, rc 2,
adapter not opened). It never calls `sudo`; the link-loss run asks you to run `macos-lab link` yourself.

Per run it does, in this order: `macos-lab status --run-id m1` (rc 0, `raw_run_allowed`, and `bpf_access` is
`denied` for `perm_denied_scan` and `perm_inventory_control`, `granted` for everything else); restarts the peer
listeners (`peer listen`, ready and silent port proven); starts `tcpdump` on the default-route uplink with the
lab filter; starts the independent witness on `feth4202` (`capture dump`); sends three start markers from the
peer side and waits until they are in the witness pcap; only then starts `wire_scan`. After it: the peer side
counters go quiet, three end markers, `tcpdump` statistics (`captured == received`, no kernel drops), the uplink
interlock (any frame there is exit 13), `status-post.json`, sha256 of every file into `hashes-before-copy.txt`
in the work directory, the copy to `OUT/runs/<tag>.<nonce>/`, and the hashes checked again on the copy. A run
that fails after a frame may exist is kept under `OUT/runs_aborted/` the same way.

The lab writes frames only from the peer side, through the same safe adapter the product uses, and a guard
refuses everything else: source MAC `02:ac:00:00:00:02`, destination MAC `02:ac:00:00:00:01`, and either the
lab marker ethertype `0x88b5` or IPv4 from `198.18.0.2` to `198.18.0.1`. These frames are the start and end
markers, the foreign replies of x01 (three kinds: unscanned port, wrong cookie, wrong destination port; the
"other IP" kind of Linux and Windows would come from `198.18.0.3` and is not written), and the loss and load
floods of `rxloss` and `stop_load` (marker ethertype with `RMSP` at offset 18).

A permission run with BPF denied has no capture: no `tcpdump` can open BPF either. Its evidence is the
scanner's refusal (`PermissionDenied`, `opened_adapter false`, `tx_sent 0`) and the before/after interface
counters of the pair (`counters.json`), which are readable without BPF; counters that moved make the zero
frames unprovable (INVALID, rerunnable).

The suite lock is `$HOME/.rmasscan-lab/macos-suite.lock`, created with `create_new` and holding the pid and
start time. It is removed when the suite ends. A lock whose owner is dead is never removed automatically:
check that nothing runs and use `--remove-stale-lock`.

Build, from `rmasscan/`:

```sh
export RMASSCAN_SOURCE_COMMIT=$(git rev-parse HEAD)
RMASSCAN_LAB_BUILD_COMMIT=$RMASSCAN_SOURCE_COMMIT cargo build --locked --release -p rmasscan-lab
cargo build --locked --release -p rmasscan-net --example wire_scan
BIN=$PWD/target/release/rmasscan-lab; WS=$PWD/target/release/examples/wire_scan; C=$RMASSCAN_SOURCE_COMMIT
FIX=$PWD/../docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance-raw/fixtures
EV=$PWD/../docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance-raw
```

C-oracle fixtures for the Mac binding (once per stand MACs; on this Mac, ssh to minipc; nothing here touches
the stand; needs `sudo -n` on minipc and the Linux build of `rmasscan-lab` there):

```sh
"$BIN" oracle-fixtures --out "$FIX" --src-mac 02:ac:00:00:00:01 --peer-mac 02:ac:00:00:00:02 \
  --open-ports 8000,8001,8002,8003,8004,8005,8006,8007 --remote-lab /ABSOLUTE/PATH/ON/MINIPC/rmasscan-lab --host minipc
```

Order of the live runs (your commands are the `sudo` ones):

```sh
sudo "$BIN" macos-lab up --run-id m1                # stand up; BPF is still 0600 root:wheel (denied)

# failure plan, the two permission runs first: BPF must be denied
"$BIN" macos-suite --out "$EV/failure-r1" --suite failure-r1 --plan failure --commit "$C" --repo . \
  --wire-scan "$WS" --fixtures "$FIX" --only perm_denied_scan perm_inventory_control

sudo "$BIN" macos-lab bpf-access --run-id m1 --grant   # read the risk section first

# part A, functional (24 runs and the pause/resume groups)
"$BIN" macos-suite --out "$EV/functional-r1" --suite functional-r1 --plan functional --commit "$C" --repo . \
  --wire-scan "$WS" --fixtures "$FIX"
"$BIN" macos-verify --dir "$EV/functional-r1" --out "$EV/functional-r1/verdict.json"

# part B, the rest of the failure plan (same --out and --suite as the permission runs)
"$BIN" macos-suite --out "$EV/failure-r1" --suite failure-r1 --plan failure --commit "$C" --repo . \
  --wire-scan "$WS" --fixtures "$FIX" --only stop_silent stop_drain stop_fullqueue stop_load \
  overflow_queue rxloss ckpt_wrong_ports ckpt_wrong_seed ckpt_corrupt_next_index ckpt_corrupt_checksum \
  ckpt_truncated ckpt_empty ckpt_future_format ckpt_future_engine
# linkloss: the suite prints the commands when the scan starts; in a root shell, at that moment:
#   rmasscan-lab macos-lab link --run-id m1 --down ; sleep 3 ; rmasscan-lab macos-lab link --run-id m1 --up
"$BIN" macos-suite --out "$EV/failure-r1" --suite failure-r1 --plan failure --commit "$C" --repo . \
  --wire-scan "$WS" --fixtures "$FIX" --only linkloss
"$BIN" macos-verify --dir "$EV/failure-r1" --out "$EV/failure-r1/verdict.json"

# part C, performance: look first (20 cells), then try one repetition, then the full plan
"$BIN" macos-suite --list --plan perf        # prints the 20 tags, starts nothing
"$BIN" macos-suite --out "$EV/perf-r1" --suite perf-r1 --plan perf --reps 1 --commit "$C" --repo . \
  --wire-scan "$WS" --fixtures "$FIX"
# (a full run needs a new --out: a directory with a partial plan is extended with --only/--rerun, not re-planned)
"$BIN" macos-suite --out "$EV/perf-r2" --suite perf-r2 --plan perf --commit "$C" --repo . \
  --wire-scan "$WS" --fixtures "$FIX"
"$BIN" macos-verify --dir "$EV/perf-r2" --out "$EV/perf-r2/verdict.json"

sudo "$BIN" macos-lab bpf-access --run-id m1 --revoke
sudo "$BIN" macos-lab down --run-id m1
```

`--only` takes every tag after it. `--rerun` needs explicit `--only` tags and moves a run to `runs_discarded/`
only when the verifier judged it INVALID or NOT RUN without a behaviour failure; a FAIL, or any lab frame on
the uplink or foreign SYN, can never be repeated and the directory must be abandoned. Exit codes of
`macos-suite`: 0 all planned runs executed, 2 NOT RUN (refused before anything started), 10 abort, 11 rerun
refused, 12 schema too old, 13 isolation breach (a lab frame on the uplink), 130 interrupted. `macos-verify`:
0 PASS, 1 FAIL, 2 INVALID or NOT RUN. A verdict is never PASS while any run is missing, incomplete or has a
gate that did not hold.

On this macOS the OS hides interface MACs from an unprivileged process (`02:00:00:00:00:00`); the stand MACs are
fixed by `up` (`lladdr`) and re-read from `ifconfig`, and `wire_scan` reports `src_mac_check: "os-masked"`,
which the verifier accepts.

### Reading the captures on macOS

`tcpdump` prints `packets received by filter` from the BPF descriptor's receive counter, which on macOS counts
every packet the descriptor saw before its kernel filter. It is therefore recorded as information only and is
never read as a count of matched frames. On the uplink a lab frame is a frame in the lab-filtered pcap, or a
packet tcpdump `captured` (it passed the filter) without storing it; `dropped by kernel` above zero means a
matched frame may have been lost, so the capture is unproven (INVALID); ordinary traffic on `en0` is not a
breach. The same reading applies to the peer witness: its completeness is `captured` equal to the pcap
frames, no kernel drops, the interface counter window and the marker rules. Linux and Windows keep their own
(filtered `received`) rule. The uplink `tcpdump` runs without promiscuous mode (`-p`).

### Other rules of the suite

- Everything the lab writes, the end markers included, goes out of `feth4202` through the peer-side guard.
  `capture dump` on macOS accepts only `feth4201`, `feth4202` and the default-route uplink; only `feth4202`
  is ever opened for writing.
- `capture marker` and `capture responder` are Linux-lab tools and refuse on macOS (rc 2, with an explanation): they would write
  frames on a caller-chosen interface or bind wildcard ports outside the guard. The macOS suite uses neither.
- The scanner is stopped and reaped (INT, a few seconds, then KILL) before any witness on every error path.
- A tag that already has a run is refused unless `--rerun` moved it to `runs_discarded` under the discard rules.
- The macOS Application Firewall state is recorded in `alf.txt`; an enabled firewall refuses the run, because
  it can block or prompt for the unsigned peer listeners.
- `peer listen` on macOS binds only if `198.18.0.2` is on `feth4202`.
- Link loss: `macos-lab link --down` takes `feth4202` down, so the suite watches `feth4202` (the media state of
  `feth4201` is recorded next to each event). PROVISIONAL until the spike pins the Mac failure class: a down
  during the scan must end in a failure whose detail names a TX or link class; a scan that completed anyway, or
  failed for another reason, is INVALID.
- `perm_denied` runs: the claim is "zero frames crossed the pair", with the counters read before and after the
  scanner (`before_utc <= start`, `end <= after_utc`).
- x01 exercises three foreign-reply kinds on macOS. The "other IP" kind of Linux and Windows would come from
  `198.18.0.3`, which the guard forbids, so it is not written; it is covered by the Linux and Windows runs and
  the reply filtering is shared core code. The verifier checks that no `other_ip` frame was sent and that the
  guard refused nothing.

### Leftover processes (suite death)

Every run first reads `/bin/ps -axo pid,pgid,command` and refuses (NOT RUN, rc 2) while an earlier `wire_scan`, a
`tcpdump` naming `feth4201`, `feth4202` or the lab filter, `rmasscan-lab peer listen` or `capture dump` is alive;
the message lists their PIDs and the commands to stop them (this also stops a start while a spike `tcpdump` runs).
SIGHUP (closed terminal, dropped ssh) is a stop like INT and TERM. The lock file records the process groups of the
live children (`children=`); `--remove-stale-lock` refuses while one of them has a member. A leader that exits
leaves no member of its group behind: its exit is read from `ps` (zombie row) and the group is swept (SIGINT, one
second, SIGKILL) before the leader is reaped, so the group id cannot have been reused. A work directory left in
`OUT/.work/` blocks the next start and is walked by the verifier (a lab frame there is FAIL).

### Ports and closed-port RSTs on the Mac stand

The scan port set stays `80,443,8000-8007` (parity with the C oracle), but a non-root peer cannot bind 80 or 443
on macOS (EACCES) and there are no root listeners, ever. The peer listens on `8000-8007` only; 80 and 443 are
CLOSED and answer RST. The oracle fixtures are taken with `--open-ports 8000,...,8007` so that their truth is the
same, and the verifier requires that (`responder_open_ports`). The shared Windows and Linux tables are unchanged.
SYN-ACK is therefore exercised by `c03`, the pause/resume groups and the 8000-8007 part of the perf ports, not by
`c01`.

macOS rate-limits closed-port RSTs (the spike saw 74 of 100 under load). A missing RST is not a scanner failure
and not INVALID by itself: on the Mac stand the scanner's results must contain every open port, nothing unknown
and no duplicate, and must equal the replies the peer witness saw on the wire; no RST count is expected.
`sysctl -n net.inet.icmp.icmplim` is recorded in every run (`icmplim.txt`, `meta.json`).

### Further gates and notes (round 5)

- The `ps` gate fails closed: a non-zero `ps` exit, or a listing that does not show the suite itself, refuses the run.
- Before each run the packet counters of `feth4201` and `feth4202` are read twice, a second apart; any movement
  refuses the run (some other sender, such as a spike or a test binary, is active).
- `--remove-stale-lock` names a recorded process group only while one of its members is a lab command.
- A stop request before the scanner starts starts no scanner; the run's tools are also stopped when the run ends
  abnormally (drop), and writes to a hung-up terminal are ignored.
- The wall-clock and `src_mac_check` rules apply to scan summaries only; the inventory summary
  (`mode: "inventory"`) and a refused start are exempt.
- `stop_fullqueue` on the Mac needs two peer replies on the wire and results equal to them (fewer on the wire is
  INVALID); for perf, `stop_drain` and the pause/resume union every result must be a reply on the wire.
- `icmplim` must be an integer. `oracle-fixtures` picks its expected counts from the parsed `--open-ports` set.
- Coverage note: with 80 and 443 closed, SYN-ACK handling by source port (c05, c06) and in x01 is not exercised on
  the Mac; c03, pause/resume and the perf ports 8000-8007 cover it.

### No silent ports on the Mac (Darwin syncookies)

`net.inet.tcp.syncookie = 1` on this Darwin: the handshake completes even when the listen queue is full (a probe
on loopback completed 300 of 300 connects held open, at backlog 0, 1 and 2). A kernel "silent" port therefore cannot
exist, and the lab never changes sysctl, pf or the firewall to make one. Rules for the Mac stand only (Windows and
Linux are unchanged):

- `peer listen` opens `8000-8007` only; the suite never asks for `--silent` and never requires `silent_proven`.
  `ready` is still proven for the open listeners. `listeners.json` and the manifest record `"silent": []`,
  `"silent_proven": null`, `"silent_unavailable": "darwin-syncookies"` and the observed
  `sysctl -n net.inet.tcp.syncookie` (read only, absolute path; also in `meta.json`).
- 8099 and 8100-8119 are ordinary closed ports: an RST is expected, a missing RST is tolerated (the RST rate
  limit), they are never open.
- x01 (ports 80, 81, 443, 8099, all closed): the injector records the sha256 of every frame it wrote
  (`injected`); a frame on the wire marked as injected (IP id `0xf0e1`) must be one of them, and the rest is the
  genuine reply set. Results must be a subset of the genuine wire replies, with no open entry and no duplicate; a
  result for a port whose genuine reply is not on the wire means a foreign frame was accepted (FAIL). The
  foreign-reject properties are unchanged.
- `stop_silent` and `stop_load` require Stop mid-TX (`sent > 0 && sent < range`, stop within 1 s, no SYN after the
  outcome, threads joined, no fd leak) and results that are a subset of the genuine wire replies. The "empty
  receive path" property is recorded per run as the note `empty_receive_path: NOT RUN on macOS
  (darwin-syncookies)`; it does not change the verdict and is never a PASS claim.
- The oracle fixtures are unchanged: the SYN bytes and case arguments are the same, and the verifier pins only
  `responder_open_ports` (8000-8007), not a build commit.

### Pair-quiet windows and multicast strays (round 7)

- The pair-quiet gate reads the feth4201/feth4202 counters over up to three one-second windows and refuses only if
  every window moved (mDNS chatter on the pair moves the counters now and then). No evidence format changes.
- x01: multicast and broadcast frames (destination group bit) anywhere in the peer capture count as strays for the
  upper bound of discards ("no unexplained discards"); the lower bound and unicast strays stay in the
  first-SYN to last-SYN + 3 s window. A multicast frame is never a foreign reply.

### Live T7 findings (round 8)

- RST rate limit: Darwin 27 has no `net.inet.icmp.icmplim`. The suite now records
  `sysctl -n net.inet.tcp.rst_rlc_enable net.inet.tcp.rst_rlc_bucket_ms` raw in `rst_rlc.txt` (and `meta.rst_rlc`).
  The verifier only notes whatever is recorded (`notes.rst_rate_limit`, old `icmplim.txt` included); it never makes a
  run INVALID. A missing closed RST stays tolerated and results must still be genuine wire replies.
- Receive window: genuine wire replies are those from the first SYN to the scanner's own exit
  (`guest_finished_utc`; last SYN + wait if absent). Later replies are Darwin resetting embryonic connections when the
  lab stops its listener; they go to `notes.post_run_replies` ("post-run (listener teardown)") and are neither
  results nor a FAIL. The suite now stops the peer witness before the listeners. The window applies to c01-c06, x01,
  perf, the stop runs and the pause/resume union.
- Host wildcard listeners: 198.18.0.2 is a local address, so host services bound to `*` (5000, 7000, 49158) answer
  there. The suite records `host-listen-before.txt` and `host-listen-after.txt` (raw `netstat -an -p tcp`); the open
  truth is the lab listeners plus the `*.port` / `198.18.0.2.port` LISTEN sockets present in both. Without the record
  (717e45c) the open truth is the set of SYN-ACKs on the wire inside the window and needs a complete capture
  ("open truth derived from the wire (host listeners not recorded)"). A SYN-ACK without an open result is a FAIL.
- Injected frames are told by the injector's recorded sha256, not by IP id 0xf0e1 alone: genuine kernel RSTs carry
  that id once in 65536 frames (seen in the 100000 pps cells).

### Verifier tightening (round 9)

- Host LISTEN parser counts only `tcp4`/`tcp46` lines (tcp6-only sockets do not answer IPv4). A record whose first
  line is not `rc 0` (netstat failed) is "not recorded", never "no host listeners".
- perf, `stop_drain` and the pause/resume union: open results must equal the open SYN-ACKs inside the scanner's
  window that answer a SYN of this run (ack = SYN seq + 1, to the SYN's port); closed results stay a subset of the
  genuine RSTs, and a missing closed result is tolerated. A SYN-ACK retransmit of an earlier cell's half-open
  connection that lands in the window (live: port 5000 of perf.100000.r4 inside perf.100.r5) answers nothing of this
  run and is not a miss.
- Multicast strays (x01 upper bound) are Mac-only and limited to `[guest_started_utc, guest_finished_utc]`.
- A lab SYN-ACK retransmit of an in-window reply after the last end marker (the listeners now stop after the
  witness) is the note `post_run_synack_retransmits`; any other frame there is still an unflushed tail (INVALID).
