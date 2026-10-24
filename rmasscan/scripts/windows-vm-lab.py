#!/usr/bin/env python3
"""Isolated virtual Ethernet test switch for the Windows 11 test VM (stage 2B-Windows, task 2).

Runs on the Ubuntu VM host (home-pc), as root (re-execs through `sudo -n`).

  windows-vm-lab.py plan   --run-id ID --manifest FILE       read-only: checks + what `up` would create
  windows-vm-lab.py up     --run-id ID --manifest FILE [--tap-user U] [--lab-env FILE]
  windows-vm-lab.py status --run-id ID --manifest FILE [--host-only]
  windows-vm-lab.py down   --run-id ID --manifest FILE
  windows-vm-lab.py record-guest --run-id ID --manifest FILE [--guest-json F] [--verify-json F]

Topology (no host IP, no uplink, no forwarding/NAT, nothing touches eno1/eno2/wlp*):

  Windows 2nd e1000e -> TAP wvt-ID -> bridge wvb-ID -> veth wvh-ID == lab0 in netns wvp-ID
  198.18.0.0/30: Windows .1, Linux peer .2, no gateway, no DNS.

The bridge is L2-only: vlan_filtering with the bridge's own (self) vid 1 removed, so no frame is ever
delivered to the host IP stack; plus NOARP, arp_ignore=8, rp_filter=1, forwarding=0, IPv6 off on
bridge/TAP/host veth. `status` is `ok` (raw-run allowed) only when all of that still holds, the VM is
truly attached (qemu cmdline + TAP fd + carrier) and a guest Verify record is fresh.

Ownership: every link carries ifalias `rmasscan-wvl:ID:NONCE`, the netns a marker file
/run/rmasscan-wvl/<ns> holding the same token; NONCE is random per manifest. `down` deletes only
objects whose live mark matches the manifest token. A second `down` is a no-op.
"""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import time

NET = ipaddress.ip_network("198.18.0.0/30")
WIN_IP, PEER_IP, PREFIX = "198.18.0.1", "198.18.0.2", 30
RUN_RE = re.compile(r"^[a-z0-9]{1,8}$")
ALIAS_PREFIX = "rmasscan-wvl:"
PEER_IF = "lab0"
MGMT_MAC = "52:54:00:12:34:56"
MARK_DIR = "/run/rmasscan-wvl"


class LabError(Exception):
    pass


def derive(run_id):
    if not RUN_RE.match(run_id or ""):
        raise LabError("run-id must match [a-z0-9]{1,8}")
    h = hashlib.sha256(run_id.encode()).digest()
    d = {
        "run_id": run_id,
        "bridge": "wvb-" + run_id,
        "tap": "wvt-" + run_id,
        "veth_host": "wvh-" + run_id,
        "netns": "wvp-" + run_id,
        "peer_if": PEER_IF,
        "windows_mac": "52:54:00:%02x:%02x:%02x" % (h[0], h[1], h[2]),
        "peer_mac": "02:57:4c:%02x:%02x:%02x" % (h[3], h[4], h[5]),
        "veth_host_mac": "02:57:4d:%02x:%02x:%02x" % (h[6], h[7], h[8]),
    }
    macs = [d["windows_mac"], d["peer_mac"], d["veth_host_mac"], MGMT_MAC]
    if len(set(macs)) != len(macs):
        raise LabError("derived MACs collide for run-id %s; pick another" % run_id)
    return d


def alias_of(d, token):
    return "%s%s:%s" % (ALIAS_PREFIX, d["run_id"], token)


def norm_mac(m):
    return (m or "").lower().replace("-", ":")


# ---------------------------------------------------------------- host abstraction
class RealHost:
    LOCK_TRIES = 300  # x 0.1 s

    def sh(self, *cmd, check=True):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode:
            raise LabError("%s: %s" % (" ".join(cmd), r.stderr.strip()))
        return r.stdout

    def links(self):
        out = {}
        for l in json.loads(self.sh("ip", "-j", "-d", "addr", "show") or "[]"):
            n = l["ifname"]
            flags = l.get("flags", [])
            out[n] = {
                "kind": (l.get("linkinfo") or {}).get("info_kind", ""),
                "master": l.get("master"),
                "alias": l.get("ifalias", ""),
                "physical": os.path.exists("/sys/class/net/%s/device" % n),
                "mac": norm_mac(l.get("address")),
                "addrs": [a["local"] + "/" + str(a["prefixlen"]) for a in l.get("addr_info", [])],
                "noarp": "NOARP" in flags,
                "lower_up": "LOWER_UP" in flags,
                "vlan_filtering": bool(((l.get("linkinfo") or {}).get("info_data") or {}).get("vlan_filtering")),
            }
        return out

    def routes(self):
        return [r.get("dst", "") for r in json.loads(self.sh("ip", "-j", "route", "show") or "[]")]

    def netns_list(self):
        return {l.split()[0] for l in self.sh("ip", "netns", "list").splitlines() if l.strip()}

    def sysctl(self, key):
        try:
            with open("/proc/sys/" + key.replace(".", "/")) as f:
                return f.read().strip()
        except OSError:
            return None

    def bridge_self_vlans(self, br):
        r = subprocess.run(["bridge", "-j", "vlan", "show", "dev", br], capture_output=True, text=True)
        if r.returncode:
            return None
        return [v["vlan"] for e in json.loads(r.stdout or "[]") if e.get("ifname") == br for v in e.get("vlans", [])]

    def fw_refs(self, names):
        hits = []
        for cmd in (["nft", "list", "ruleset"], ["iptables-save"], ["ip6tables-save"]):
            r = subprocess.run(cmd, capture_output=True, text=True)
            for line in (r.stdout if r.returncode == 0 else "").splitlines():
                if any(re.search(r'(?<![\w-])%s(?![\w-])' % re.escape(n), line) for n in names):
                    hits.append("%s: %s" % (cmd[0], line.strip()))
        return hits

    def netns_mark_read(self, ns):
        try:
            with open(os.path.join(MARK_DIR, ns)) as f:
                return f.read().strip()
        except OSError:
            return None

    def netns_mark_write(self, ns, token):
        os.makedirs(MARK_DIR, mode=0o755, exist_ok=True)
        fd = os.open(os.path.join(MARK_DIR, ns), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")

    def netns_mark_remove(self, ns):
        try:
            os.remove(os.path.join(MARK_DIR, ns))
        except OSError:
            pass

    def vm_facts(self, d):
        """What the running qemu really holds: cmdline netdev+MAC, TAP fd, start time."""
        want_if, want_mac = "ifname=" + d["tap"], "mac=" + d["windows_mac"]
        boot = 0
        try:
            with open("/proc/stat") as f:
                boot = int([l for l in f if l.startswith("btime")][0].split()[1])
        except (OSError, IndexError, ValueError):
            pass
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                with open("/proc/%s/cmdline" % pid, "rb") as f:
                    argv = f.read().decode(errors="replace").split("\0")
            except OSError:
                continue
            if not argv or "qemu-system" not in argv[0]:
                continue
            tap_ok = any(a.startswith("tap,") and "id=lab0" in a and want_if in a.split(",") for a in argv)
            mac_ok = any(a.startswith("e1000e,") and "netdev=lab0" in a and want_mac in a.split(",") for a in argv)
            fd_iff = False
            try:
                for fd in os.listdir("/proc/%s/fd" % pid):
                    if os.readlink("/proc/%s/fd/%s" % (pid, fd)) == "/dev/net/tun":
                        with open("/proc/%s/fdinfo/%s" % (pid, fd)) as f:
                            if ("iff:\t" + d["tap"]) in f.read().splitlines():
                                fd_iff = True
            except OSError:
                pass
            start = 0
            try:
                with open("/proc/%s/stat" % pid) as f:
                    start = boot + int(f.read().rsplit(")", 1)[1].split()[19]) / os.sysconf("SC_CLK_TCK")
            except (OSError, IndexError, ValueError):
                pass
            if tap_ok or mac_ok:
                return {"pid": int(pid), "cmdline_ok": tap_ok and mac_ok, "fd_iff": fd_iff, "start": start}
        return {"pid": None, "cmdline_ok": False, "fd_iff": False, "start": 0}

    def _unmanage(self, name):
        """Best effort: if NetworkManager is running, tell it to leave OUR new device alone (it could run
        DHCP/link-local on it). Never fatal: absent/not-running NM is fine; status re-checks the result."""
        if subprocess.run(["which", "nmcli"], capture_output=True).returncode:
            return
        r = subprocess.run(["nmcli", "-t", "-f", "RUNNING", "general"], capture_output=True, text=True)
        if r.returncode or r.stdout.strip() != "running":
            return
        subprocess.run(["nmcli", "device", "set", name, "managed", "no"], capture_output=True)
        for _ in range(30):
            r = subprocess.run(["nmcli", "-t", "-f", "DEVICE,STATE", "device"], capture_output=True, text=True)
            if "%s:unmanaged" % name in r.stdout.split("\n"):
                return
            time.sleep(0.1)

    def settle(self):
        """The 99-systemd.rules `systemd-sysctl` hook (50-default.conf: rp_filter=2) rewrites per-device sysctls
        asynchronously after a device appears; wait for udev before applying or reading them. (The kernel uses
        max(conf.all, conf.dev) for rp_filter, so the per-device value is the configured, not effective, one;
        it is irrelevant here because no frame reaches the host IP stack.)"""
        subprocess.run(["udevadm", "settle", "--timeout=5"], capture_output=True)

    def _l2only(self, name):
        self._unmanage(name)
        self.settle()
        self.sh("ip", "link", "set", name, "arp", "off")
        self.sh("sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % name)
        for k, v in (("arp_ignore", "8"), ("rp_filter", "1"), ("forwarding", "0")):
            self.sh("sysctl", "-qw", "net.ipv4.conf.%s.%s=%s" % (name, k, v))

    def _create(self, name, add_cmd, rest):
        """`add_cmd` creates the device: if it fails (e.g. name taken) nothing of ours exists, so NOTHING is
        deleted. Only after it succeeded may a later failure remove the device this call just created."""
        self.sh(*add_cmd)
        try:
            rest()
        except Exception:
            self.sh("ip", "link", "del", name, check=False)
            raise

    @contextlib.contextmanager
    def lock(self, run_id):
        os.makedirs(MARK_DIR, mode=0o755, exist_ok=True)
        fd = os.open(os.path.join(MARK_DIR, run_id + ".lock"), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            for _ in range(self.LOCK_TRIES):
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.1)
            else:
                raise LabError("another windows-vm-lab command holds the lock for run-id %s" % run_id)
            yield
        finally:
            os.close(fd)

    def create_bridge(self, name, alias):
        def rest():
            self.sh("ip", "link", "set", name, "alias", alias)
            self._l2only(name)
            self.sh("bridge", "vlan", "del", "dev", name, "vid", "1", "self")
            self.sh("ip", "link", "set", name, "up")
        self._create(name, ("ip", "link", "add", name, "type", "bridge", "stp_state", "0", "vlan_filtering", "1"), rest)

    def create_tap(self, name, alias, user):
        def rest():
            self.sh("ip", "link", "set", name, "alias", alias)
            self._l2only(name)
        self._create(name, ("ip", "tuntap", "add", "dev", name, "mode", "tap", "user", user), rest)

    def create_veth(self, host_if, peer_if, ns, alias, host_mac, peer_mac):
        def rest():
            self.sh("ip", "link", "set", host_if, "alias", alias)
            self._l2only(host_if)
        self._create(host_if, ("ip", "link", "add", host_if, "address", host_mac, "type", "veth",
                               "peer", "name", peer_if, "address", peer_mac, "netns", ns), rest)

    def enslave(self, name, bridge):
        self.sh("ip", "link", "set", name, "master", bridge)
        self.sh("ip", "link", "set", name, "up")

    def netns_add(self, ns):
        self.sh("ip", "netns", "add", ns)

    def peer_config(self, ns, ifname, ip):
        self.sh("ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
        self.sh("ip", "-n", ns, "link", "set", "lo", "up")
        self.sh("ip", "-n", ns, "addr", "add", "%s/%d" % (ip, PREFIX), "dev", ifname)
        self.sh("ip", "-n", ns, "link", "set", ifname, "up")

    def link_del(self, name):
        self.sh("ip", "link", "del", name)

    def netns_del(self, ns):
        self.sh("ip", "netns", "del", ns)


# ---------------------------------------------------------------- manifest
def read_manifest(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except ValueError as e:
        raise LabError("manifest unreadable: %s" % e)


def write_manifest(path, m):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(m, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)
    uid = os.environ.get("SUDO_UID")
    if uid and os.geteuid() == 0:
        try:
            os.chown(path, int(uid), int(os.environ.get("SUDO_GID", uid)))
        except OSError:
            pass


# ---------------------------------------------------------------- checks
def owned(link, d, token):
    return link.get("alias") == alias_of(d, token)


def _overlap(cidr):
    try:
        return ipaddress.ip_interface(cidr).network.overlaps(NET)
    except ValueError:
        return False


def plan(host, d, manifest):
    """Read-only. Returns (problems, actions)."""
    problems = []
    links, nss = host.links(), host.netns_list()
    for key in ("bridge", "tap", "veth_host"):
        if d[key] in links:
            fam = links[d[key]].get("alias", "").startswith(ALIAS_PREFIX + d["run_id"] + ":")
            problems.append("name busy: link %s (%s)" % (d[key], "another manifest of this run-id" if fam else "FOREIGN"))
    if d["netns"] in nss:
        problems.append("name busy: netns %s" % d["netns"])
    if manifest is not None and manifest.get("state") != "down":
        problems.append("manifest exists with state=%s: run `down` first" % manifest.get("state"))
    mine = {d["windows_mac"], d["peer_mac"], d["veth_host_mac"]}
    for n, l in links.items():
        if norm_mac(l.get("mac")) in mine:
            problems.append("MAC %s already used by host link %s" % (l["mac"], n))
        for a in l.get("addrs", []):
            if _overlap(a):
                problems.append("address conflict: %s on %s overlaps %s" % (a, n, NET))
    for r in host.routes():
        if r and r != "default" and _overlap(r):
            problems.append("route conflict: %s overlaps %s" % (r, NET))
    if host.sysctl("net.ipv4.ip_forward") != "0":
        problems.append("global net.ipv4.ip_forward is %s (must be 0)" % host.sysctl("net.ipv4.ip_forward"))
    for h in host.fw_refs([d["bridge"], d["tap"], d["veth_host"]]):
        problems.append("firewall rule already references lab interfaces: " + h)
    actions = [
        "create bridge %s: L2-only (vlan_filtering, self vid 1 removed, NOARP, arp_ignore=8, rp_filter=1, fwd=0, ipv6 off)" % d["bridge"],
        "create tap %s (same hardening), enslave to %s" % (d["tap"], d["bridge"]),
        "create netns %s + owner marker; veth %s <-> %s in netns (same hardening on host end), enslave host end" % (d["netns"], d["veth_host"], PEER_IF),
        "set %s/%d on %s in netns %s only (no gateway/DNS)" % (PEER_IP, PREFIX, PEER_IF, d["netns"]),
        "verify isolation (ports == {tap, veth}, no physical port, no host IP, L2-only, forwarding 0, no firewall refs)",
    ]
    return problems, actions


def check_isolation(host, d):
    """Violations of the sealed-switch invariants for this run's bridge."""
    v = []
    host.settle()
    links = host.links()
    br = links.get(d["bridge"])
    if br is None:
        return ["bridge %s missing" % d["bridge"]]
    allowed = {d["tap"], d["veth_host"]}
    for n, l in links.items():
        if l.get("master") == d["bridge"]:
            if l.get("physical"):
                v.append("physical uplink %s enslaved to bridge" % n)
            elif n not in allowed:
                v.append("unexpected port %s on bridge" % n)
    mine = [d["bridge"]] + [n for n in sorted(allowed) if n in links]
    for n in mine:
        l = links[n]
        if l.get("addrs"):
            v.append("%s has host IP %s" % (n, l["addrs"]))
        if not l.get("noarp"):
            v.append("%s is not NOARP" % n)
        for k, want in (("arp_ignore", "8"), ("rp_filter", "1"), ("forwarding", "0")):
            got = host.sysctl("net.ipv4.conf.%s.%s" % (n, k))
            if got != want:
                v.append("%s: %s=%s (want %s)" % (n, k, got, want))
        if host.sysctl("net.ipv6.conf.%s.disable_ipv6" % n) != "1":
            v.append("%s: ipv6 not disabled" % n)
        if n != d["bridge"] and l.get("master") != d["bridge"]:
            v.append("%s not enslaved to bridge" % n)
    if not br.get("vlan_filtering"):
        v.append("bridge vlan_filtering is off (self vlan cannot be removed)")
    sv = host.bridge_self_vlans(d["bridge"])
    if sv is None:
        v.append("cannot read bridge self vlans")
    elif sv:
        v.append("bridge self vlan present %s: frames reach the host IP stack" % sv)
    if host.sysctl("net.ipv4.ip_forward") != "0":
        v.append("global ip_forward=%s" % host.sysctl("net.ipv4.ip_forward"))
    for h in host.fw_refs(mine):
        v.append("firewall references lab interface: " + h)
    return v


def select_adapter(adapters, mac):
    """Unique adapter by MAC from a guest Inventory; ambiguity or absence is an error."""
    want = norm_mac(mac)
    if want == MGMT_MAC:
        raise LabError("refusing: MAC %s is the management NIC" % want)
    hits = [a for a in adapters if norm_mac(a.get("MacAddress") or a.get("mac")) == want]
    if len(hits) != 1:
        raise LabError("lab NIC ambiguous/absent: %d adapters match MAC %s" % (len(hits), want))
    return hits[0]


def vm_attachment(host, d, links=None):
    f = host.vm_facts(d)
    links = links if links is not None else host.links()
    tap = links.get(d["tap"], {})
    f["carrier"] = bool(tap.get("lower_up"))
    f["attached"] = bool(f["pid"] and f["cmdline_ok"] and f["fd_iff"] and f["carrier"])
    return f


# ---------------------------------------------------------------- commands
def cmd_plan(host, a):
    d = derive(a.run_id)
    problems, actions = plan(host, d, read_manifest(a.manifest))
    print(json.dumps({"run_id": a.run_id, "names": d, "problems": problems, "actions": actions,
                      "net": str(NET), "ok": not problems}, indent=2))
    return 0 if not problems else 3


def cmd_up(host, a):
    d = derive(a.run_id)
    problems, _ = plan(host, d, read_manifest(a.manifest))
    if a.lab_env and os.path.exists(a.lab_env):
        with open(a.lab_env) as f:
            if ("LAB_RUN_ID=%s\n" % a.run_id) not in f.read():
                problems.append("lab.env %s belongs to another run-id" % a.lab_env)
    if problems:
        print("REFUSED (nothing created or removed):\n  " + "\n  ".join(problems), file=sys.stderr)
        return 3
    token = secrets.token_hex(8)
    alias = alias_of(d, token)
    m = {"schema": 2, "run_id": a.run_id, "token": token, "state": "creating", "names": d, "created": [],
         "lab": {"net": str(NET), "windows_ip": WIN_IP, "peer_ip": PEER_IP, "prefix": PREFIX,
                 "gateway": None, "dns": None},
         "guest": {"guid": None, "npf": None}, "vm": {"attached": False}}
    write_manifest(a.manifest, m)

    def step(kind, name, fn):
        fn()  # ownership is recorded only after the object really exists
        m["created"].append({"kind": kind, "name": name, "at": time.time()})
        write_manifest(a.manifest, m)

    try:
        step("link", d["bridge"], lambda: host.create_bridge(d["bridge"], alias))
        step("link", d["tap"], lambda: host.create_tap(d["tap"], alias, a.tap_user))
        host.enslave(d["tap"], d["bridge"])

        def mk_ns():
            host.netns_add(d["netns"])
            host.netns_mark_write(d["netns"], token)
        step("netns", d["netns"], mk_ns)
        step("link", d["veth_host"], lambda: host.create_veth(
            d["veth_host"], PEER_IF, d["netns"], alias, d["veth_host_mac"], d["peer_mac"]))
        host.enslave(d["veth_host"], d["bridge"])
        host.peer_config(d["netns"], PEER_IF, PEER_IP)
        viol = check_isolation(host, d)
        if viol:
            raise LabError("isolation check failed: " + "; ".join(viol))
    except Exception as e:
        print("up failed: %s; rolling back own objects" % e, file=sys.stderr)
        if _teardown(host, d, token) == 0:
            m["state"] = "down"
            write_manifest(a.manifest, m)
        return 4
    m["vm"] = {"attached": False, "note": "restart the VM via ~/winvm/run.sh to bind the new TAP"}
    if a.lab_env:
        tmp = a.lab_env + ".tmp"
        with open(tmp, "w") as f:
            f.write("LAB_RUN_ID=%s\nLAB_TAP=%s\nLAB_MAC=%s\n" % (a.run_id, d["tap"], d["windows_mac"]))
        os.replace(tmp, a.lab_env)
        m["lab_env"] = a.lab_env
    m["state"] = "up"
    write_manifest(a.manifest, m)
    print("up: %s" % a.manifest)
    return 0


def _teardown(host, d, token):
    """Remove only objects whose LIVE mark carries this manifest's token."""
    rc = 0
    links, nss = host.links(), host.netns_list()
    for n in (d["tap"], d["veth_host"], d["bridge"]):
        if n not in links:
            continue
        if not owned(links[n], d, token):
            print("SKIP %s: live mark %r is not this manifest's (left untouched)" % (n, links[n].get("alias")), file=sys.stderr)
            rc = 5
            continue
        host.link_del(n)
    ns = d["netns"]
    if ns in nss:
        if host.netns_mark_read(ns) == token:
            host.netns_del(ns)
            host.netns_mark_remove(ns)
        else:
            print("SKIP netns %s: owner marker is not this manifest's (left untouched)" % ns, file=sys.stderr)
            rc = 5
    elif host.netns_mark_read(ns) == token:
        host.netns_mark_remove(ns)
    return rc


def cmd_down(host, a):
    d = derive(a.run_id)
    m = read_manifest(a.manifest)
    if m is None:
        print("down: no manifest, nothing owned by run-id %s (no-op)" % a.run_id)
        return 0
    if m.get("run_id") != a.run_id or not m.get("token"):
        print("REFUSED: manifest belongs to run-id %s / has no token" % m.get("run_id"), file=sys.stderr)
        return 3
    if m.get("state") == "down":
        print("down: already down (no-op)")
        return 0
    rc = _teardown(host, d, m["token"])
    env = m.get("lab_env")
    if env and os.path.exists(env):
        with open(env) as f:
            if "LAB_RUN_ID=%s\n" % a.run_id in f.read():
                os.remove(env)
    m["state"] = "down" if rc == 0 else "down-incomplete"
    m["vm"] = {"attached": False}
    write_manifest(a.manifest, m)
    print("down: %s" % m["state"])
    return rc


def guest_fresh(m, vm):
    g = m.get("guest") or {}
    v = g.get("verify") or {}
    d = m["names"]
    return bool(v.get("ok") and v.get("status") == "Up" and norm_mac(v.get("mac")) == d["windows_mac"]
                and v.get("guid") and v.get("guid") == g.get("guid")
                and v.get("recorded_at", 0) >= vm.get("start", 1e18))


def cmd_status(host, a):
    d = derive(a.run_id)
    m = read_manifest(a.manifest)
    if m is None:
        print(json.dumps({"state": "absent"}))
        return 2
    links, nss = host.links(), host.netns_list()
    tok = m.get("token")
    objs = {}
    for ent in m.get("created", []):
        n = ent["name"]
        if ent["kind"] == "netns":
            objs[n] = "present, owned" if n in nss and host.netns_mark_read(n) == tok else ("FOREIGN" if n in nss else "MISSING")
        else:
            objs[n] = "present, owned" if n in links and owned(links[n], d, tok) else ("FOREIGN" if n in links else "MISSING")
    up = m["state"] == "up"
    viol = check_isolation(host, d) if up else []
    host_ok = up and len(objs) == 4 and all(v == "present, owned" for v in objs.values()) and not viol
    vm = vm_attachment(host, d, links) if up else {"attached": False}
    gf = guest_fresh(m, vm) if up else False
    full = bool(host_ok and vm["attached"] and gf)
    ok = host_ok if a.host_only else full
    if up and not a.host_only:  # live manifest follows facts, not hopes
        m["vm"] = {k: vm[k] for k in ("attached", "pid", "cmdline_ok", "fd_iff", "carrier", "start")}
        m["status_checked_at"] = time.time()
        write_manifest(a.manifest, m)
    print(json.dumps({"state": m["state"], "objects": objs, "isolation_violations": viol, "host_ok": host_ok,
                      "vm": vm, "guest_verify_fresh": gf, "raw_run_allowed": full, "ok": ok}, indent=2))
    return 0 if ok else 1


def cmd_record_guest(host, a):
    m = read_manifest(a.manifest)
    if m is None or m["run_id"] != a.run_id or m.get("state") != "up":
        raise LabError("no 'up' manifest for run-id")
    mac = m["names"]["windows_mac"]
    try:
        if a.guest_json:
            with open(a.guest_json) as f:
                g = json.load(f)
            ad = select_adapter(g["adapters"], mac)
            m["guest"].update({"guid": ad["InterfaceGuid"], "npf": "\\Device\\NPF_" + ad["InterfaceGuid"],
                               "name": ad.get("Name"), "ifindex": ad.get("ifIndex")})
        if a.verify_json:
            with open(a.verify_json) as f:
                v = json.load(f)
            lab = v["lab"]
            m["guest"]["verify"] = {"ok": bool(v["ok"]), "status": lab["Status"], "mac": norm_mac(lab["MacAddress"]),
                                    "guid": lab["InterfaceGuid"], "recorded_at": time.time()}
    except (KeyError, TypeError, ValueError) as e:
        raise LabError("malformed guest record: %r" % e)
    write_manifest(a.manifest, m)
    print(json.dumps(m["guest"]))
    return 0


def main(argv=None, host=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["plan", "up", "status", "down", "record-guest"])
    p.add_argument("--run-id", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--tap-user", default=os.environ.get("SUDO_USER") or "root")
    p.add_argument("--lab-env")
    p.add_argument("--guest-json")
    p.add_argument("--verify-json")
    p.add_argument("--host-only", action="store_true", help="status: skip VM attachment and guest record")
    a = p.parse_args(argv)
    a.manifest = os.path.abspath(a.manifest)
    if host is None:
        if sys.platform != "linux":
            print("FATAL: Linux only", file=sys.stderr)
            return 2
        if os.geteuid() != 0:
            os.execvp("sudo", ["sudo", "-n", sys.executable, os.path.abspath(__file__)] + (argv if argv is not None else sys.argv[1:]))
        host = RealHost()
    try:
        fn = {"plan": cmd_plan, "up": cmd_up, "status": cmd_status, "down": cmd_down,
              "record-guest": cmd_record_guest}[a.cmd]
        if a.cmd == "plan":
            return fn(host, a)
        with host.lock(a.run_id):  # serialize every mutating command (also the manifest writes) per run-id
            return fn(host, a)
    except LabError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
