# Windows VM isolated test switch (stage 2B-Windows, task 2)

A virtual Ethernet switch on the VM host (`home-pc`) that joins a SECOND NIC of the Windows 11 test VM
to a dedicated Linux peer network namespace. rmasscan's Windows/Npcap adapter sends raw SYN packets
only on this link, only to the peer. The management NAT NIC is never used for scans.

```
Mac SSH -> home-pc -> existing QEMU NAT NIC (10.0.2.15) -> Windows management
Windows 2nd e1000e -> TAP wvt-ID -> bridge wvb-ID -> veth wvh-ID == lab0 in netns wvp-ID
   no host IP, no uplink, no forwarding/NAT.   198.18.0.0/30: Windows .1, Linux peer .2, no gateway, no DNS
```

## Isolation rules (enforced by `check_isolation`, run by `up` and `status`)

- The bridge is L2-only so the host IP stack never sees lab frames: `vlan_filtering 1` with the bridge's own (self) vid 1 removed (`bridge vlan del dev BR vid 1 self`; port VLANs stay, so TAP and veth still switch), NOARP on bridge/TAP/host veth, `arp_ignore=8`, `rp_filter=1`, `forwarding=0`, IPv6 off. Without this a lab-side ARP for the host's own address was answered with the bridge MAC and a SYN to the host's sshd could leak out via eno1.
- udev (`99-systemd.rules` running `systemd-sysctl`, `50-default.conf` `rp_filter=2`) rewrites per-device sysctls asynchronously after a device appears, so `up` and `status` run `udevadm settle` before applying/reading them and `status` re-reads every value. The kernel uses max(`conf.all`, `conf.<dev>`) for rp_filter, so the per-device value is the configured one, not the effective one; it is irrelevant here because no frame reaches the host IP stack. If NetworkManager is running, `up` also does a best-effort `nmcli device set <own dev> managed no` (runtime, own devices only); a missing or stopped NetworkManager is fine.
- Violations (any makes `status` not ok and raw-run forbidden): physical or foreign port on the bridge; any IP on bridge/TAP/veth; ARP on; wrong sysctls; self vlan present or vlan_filtering off; global `ip_forward != 0`; nftables/iptables rules mentioning the lab interfaces. `plan` also refuses on name/MAC/address/route collisions, `ip_forward=1`, and firewall rules naming the lab interfaces.
- No `ip_forward`, NAT, iptables/nftables, route or DNS change anywhere; `eno1`/`eno2`/`wlp*` are never touched.

## Ownership and lifecycle

Names derive from `--run-id` (`[a-z0-9]{1,8}`). `up` draws a random token stored in the manifest. Every link carries
ifalias `rmasscan-wvl:<run-id>:<token>`; the netns carries a marker file `/run/rmasscan-wvl/<ns>` with the token. A manifest
records an object only after it really exists. `down` deletes only objects whose LIVE mark equals the manifest token (a
same-named foreign object, or an object of another manifest with the same run-id, is skipped: exit 5). `up` refuses a
leftover manifest unless its state is `down`, and refuses a `lab.env` of another run-id. A failed `up` rolls back and
leaves state `down`. A second `down` is a no-op (exit 0). Creation failures never delete anything: if `ip link add` itself fails (name taken in the plan-to-create window) nothing is removed; only a device this call created is removed when a later step fails. up/down/status/record-guest are serialized per run-id with `flock` on `/run/rmasscan-wvl/<run-id>.lock`.

```
target/release/rmasscan-lab vm-lab plan   --run-id ID --manifest FILE          # read-only
target/release/rmasscan-lab vm-lab up     --run-id ID --manifest FILE [--tap-user U] [--lab-env ~/winvm/lab.env]
target/release/rmasscan-lab vm-lab status --run-id ID --manifest FILE [--host-only]
target/release/rmasscan-lab vm-lab down   --run-id ID --manifest FILE
target/release/rmasscan-lab vm-lab record-guest --run-id ID --manifest FILE [--guest-json F] [--verify-json F --nonce UNIQUE_NONCE]
```

Runs as root (re-execs through `sudo -n`; the TAP is owned by `--tap-user`, default `$SUDO_USER`).
Exit codes: 0 ok, 1 status not ok, 2 no manifest/Linux only, 3 refused, 4 up failed (rolled back), 5 foreign/unowned object skipped.

`status` (without `--host-only`) is `ok` / `raw_run_allowed` only when: the host invariants hold, the running qemu has
`-netdev tap,id=lab0,ifname=<TAP>` and `e1000e,netdev=lab0,mac=<MAC>` on its command line, holds `/dev/net/tun` with
`iff: <TAP>` in `/proc/<pid>/fdinfo`, the TAP has carrier (LOWER_UP), and `record-guest --verify-json --nonce` stored a guest
Verify (adapter Status `Up`, same MAC and GUID) actually produced after that qemu started. Import requires an unused
matching nonce and an actual verification timestamp at most 60 seconds old, not the time of copying the file.
The PowerShell Verify command takes `-VerificationNonce` and a fresh `-ReportPath` and refuses to overwrite a report.
It rewrites `vm` in the manifest from
these facts. `--host-only` never allows raw-run. Manifests from the first revision (no token) must be removed with that
revision's `down`.

## Guest side

`pwsh -NoProfile -File windows-vm-lab.ps1 -Manifest m.json -Action Inventory|Configure|Verify`.
The lab NIC is found by the manifest MAC (`52:54:00:xx:xx:xx`, derived from the run-id); zero or several
matches abort. `Configure` assigns only `198.18.0.1/30` (no gateway, DNS reset, no registration), refuses an
adapter that holds the management address or a default route, and writes `<Manifest>.guest.json` with GUID and
`\Device\NPF_{GUID}`; `record-guest` merges that into the manifest. `Verify` also requires the adapter Status `Up` and the recorded GUID, writes `<Manifest>.verify.json`, and re-checks that the management NIC
(10.0.2.x) still owns exactly one default route and the lab NIC has none.

## Why run.sh was changed instead of QMP hotplug

q35 has no PCIe root port in `~/winvm/run.sh`; QEMU cannot hotplug onto `pcie.0`. The lab NIC is therefore
cold-plugged: when `~/winvm/lab.env` (written by `up --lab-env`) exists and its TAP exists, run.sh appends
`-netdev tap,id=lab0,ifname=$LAB_TAP,script=no,downscript=no -device e1000e,netdev=lab0,mac=$LAB_MAC`.
The management `-netdev user ... hostfwd` line is unchanged (backup: `~/winvm/run.sh.pre-n2`).
A cold-plugged NIC stays bound to the TAP file descriptor it was started with. After `down` + `up` (a new
TAP) the VM must be restarted via run.sh (graceful `shutdown /s /t 0`); QMP `netdev_del`/`netdev_add` was
tried live and does NOT re-peer the e1000e (zero frames reach the new TAP), so `up` no longer attempts it and
records `vm.attached=false` with a note.

## Tests

`cargo test -p rmasscan-lab` (offline, in-memory fake host): busy bridge/TAP/netns
names, address conflict, foreign ownership kept by `down`, physical uplink rejected and rolled back, ambiguous
NIC, repeated `down`, incomplete `up`. This is VM correctness, not physical NIC or throughput evidence.
