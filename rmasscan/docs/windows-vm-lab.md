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

- bridge ports are exactly {TAP, veth host end}; any physical port (`/sys/class/net/X/device`) or foreign port is a violation and `up` rolls back its own objects;
- no IP on bridge/TAP/veth in the host namespace; IPv6 disabled on all three; STP off;
- no `ip_forward`, NAT, iptables/nftables, route, or DNS change anywhere; `eno1`/`eno2`/`wlp*` are never touched;
- `plan` refuses on name collision (bridge/TAP/veth/netns), MAC collision, or any host address/route overlapping `198.18.0.0/30`.

## Ownership and lifecycle

Names derive from `--run-id` (`[a-z0-9]{1,8}`). Every link gets ifalias `rmasscan-wvl:<run-id>`; every
created object is written to the manifest BEFORE it is created (write-ahead), so a crashed `up` is still
cleanable. `down` deletes only manifest-listed objects that still carry the mark; a foreign object with the
same name is left alone (exit 5). `up` refuses a leftover manifest (state `creating`/`up`). A second `down`
is a no-op (exit 0).

```
python3 rmasscan/scripts/windows-vm-lab.py plan   --run-id ID --manifest FILE          # read-only
python3 rmasscan/scripts/windows-vm-lab.py up     --run-id ID --manifest FILE [--tap-user U] [--lab-env ~/winvm/lab.env] [--qmp ~/winvm/qmp.sock]
python3 rmasscan/scripts/windows-vm-lab.py status --run-id ID --manifest FILE
python3 rmasscan/scripts/windows-vm-lab.py down   --run-id ID --manifest FILE
python3 rmasscan/scripts/windows-vm-lab.py record-guest --run-id ID --manifest FILE --guest-json FILE.guest.json
```

Runs as root (re-execs through `sudo -n`; the TAP is owned by `--tap-user`, default `$SUDO_USER`).
Exit codes: 0 ok, 1 status degraded, 2 no manifest/Linux only, 3 refused, 4 up failed (rolled back), 5 foreign object skipped.

## Guest side

`pwsh -NoProfile -File windows-vm-lab.ps1 -Manifest m.json -Action Inventory|Configure|Verify`.
The lab NIC is found by the manifest MAC (`52:54:00:xx:xx:xx`, derived from the run-id); zero or several
matches abort. `Configure` assigns only `198.18.0.1/30` (no gateway, DNS reset, no registration), refuses an
adapter that holds the management address or a default route, and writes `<Manifest>.guest.json` with GUID and
`\Device\NPF_{GUID}`; `record-guest` merges that into the manifest. `Verify` re-checks that the management NIC
(10.0.2.x) still owns exactly one default route and the lab NIC has none.

## Why run.sh was changed instead of QMP hotplug

q35 has no PCIe root port in `~/winvm/run.sh`; QEMU cannot hotplug onto `pcie.0`. The lab NIC is therefore
cold-plugged: when `~/winvm/lab.env` (written by `up --lab-env`) exists and its TAP exists, run.sh appends
`-netdev tap,id=lab0,ifname=$LAB_TAP,script=no,downscript=no -device e1000e,netdev=lab0,mac=$LAB_MAC`.
The management `-netdev user ... hostfwd` line is unchanged. After `down` + `up` (a new TAP), `up --qmp`
re-binds backend `lab0` with `netdev_del`/`netdev_add` to the new TAP. The manifest records the result in `vm`.

## Tests

`python3 -m unittest discover -s rmasscan/scripts/tests` (offline, in-memory fake host): busy bridge/TAP/netns
names, address conflict, foreign ownership kept by `down`, physical uplink rejected and rolled back, ambiguous
NIC, repeated `down`, incomplete `up`. This is VM correctness, not physical NIC or throughput evidence.
