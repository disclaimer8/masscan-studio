#!/usr/bin/env python3
"""Isolated virtual Ethernet test switch for the Windows 11 test VM (stage 2B-Windows, task 2).

Runs on the Ubuntu VM host (home-pc), as root (re-execs through `sudo -n`).

  windows-vm-lab.py plan   --run-id ID --manifest FILE       read-only: checks + what `up` would create
  windows-vm-lab.py up     --run-id ID --manifest FILE [--tap-user U] [--lab-env FILE]
  windows-vm-lab.py status --run-id ID --manifest FILE
  windows-vm-lab.py down   --run-id ID --manifest FILE [--lab-env FILE]
  windows-vm-lab.py record-guest --run-id ID --manifest FILE --guest-json FILE

Topology (no host IP, no uplink, no forwarding/NAT, nothing touches eno1/eno2/wlp*):

  Windows 2nd e1000e -> TAP wvt-ID -> bridge wvb-ID -> veth wvh-ID == lab0 in netns wvp-ID
  198.18.0.0/30: Windows .1, Linux peer .2, no gateway, no DNS.

Ownership: every link carries ifalias `rmasscan-wvl:ID`; the netns is owned through the manifest
write-ahead `created` list. `down` removes only objects that carry this run-id's mark, never uses
pkill/iptables/route changes, and a second `down` is a no-op.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys

NET = ipaddress.ip_network("198.18.0.0/30")
WIN_IP, PEER_IP, PREFIX = "198.18.0.1", "198.18.0.2", 30
RUN_RE = re.compile(r"^[a-z0-9]{1,8}$")
ALIAS_PREFIX = "rmasscan-wvl:"
PEER_IF = "lab0"


class LabError(Exception):
    pass


def derive(run_id):
    if not RUN_RE.match(run_id or ""):
        raise LabError("run-id must match [a-z0-9]{1,8}")
    h = hashlib.sha256(run_id.encode()).digest()
    return {
        "run_id": run_id,
        "alias": ALIAS_PREFIX + run_id,
        "bridge": "wvb-" + run_id,
        "tap": "wvt-" + run_id,
        "veth_host": "wvh-" + run_id,
        "netns": "wvp-" + run_id,
        "peer_if": PEER_IF,
        "windows_mac": "52:54:00:%02x:%02x:%02x" % (h[0], h[1], h[2]),
        "peer_mac": "02:57:4c:%02x:%02x:%02x" % (h[3], h[4], h[5]),
    }


def norm_mac(m):
    return (m or "").lower().replace("-", ":")


# ---------------------------------------------------------------- host abstraction
class RealHost:
    def sh(self, *cmd, check=True):
        r = subprocess.run(cmd, capture_output=True, text=True)
        if check and r.returncode:
            raise LabError("%s: %s" % (" ".join(cmd), r.stderr.strip()))
        return r.stdout

    def links(self):
        out = {}
        for l in json.loads(self.sh("ip", "-j", "-d", "addr", "show") or "[]"):
            n = l["ifname"]
            out[n] = {
                "kind": (l.get("linkinfo") or {}).get("info_kind", ""),
                "master": l.get("master"),
                "alias": l.get("ifalias", ""),
                "physical": os.path.exists("/sys/class/net/%s/device" % n),
                "mac": norm_mac(l.get("address")),
                "addrs": [a["local"] + "/" + str(a["prefixlen"]) for a in l.get("addr_info", [])],
            }
        return out

    def routes(self):
        return [r.get("dst", "") for r in json.loads(self.sh("ip", "-j", "route", "show") or "[]")]

    def netns_list(self):
        return {l.split()[0] for l in self.sh("ip", "netns", "list").splitlines() if l.strip()}

    def netns_links(self, ns):
        return json.loads(self.sh("ip", "-j", "-n", ns, "link", "show") or "[]")

    def create_bridge(self, name, alias):
        self.sh("ip", "link", "add", name, "type", "bridge", "stp_state", "0")
        self.sh("ip", "link", "set", name, "alias", alias)
        self._no_v6(name)
        self.sh("ip", "link", "set", name, "up")

    def create_tap(self, name, alias, user):
        self.sh("ip", "tuntap", "add", "dev", name, "mode", "tap", "user", user)
        self.sh("ip", "link", "set", name, "alias", alias)
        self._no_v6(name)

    def create_veth(self, host_if, peer_if, ns, alias, host_mac, peer_mac):
        self.sh("ip", "link", "add", host_if, "address", host_mac, "type", "veth",
                "peer", "name", peer_if, "address", peer_mac, "netns", ns)
        self.sh("ip", "link", "set", host_if, "alias", alias)
        self._no_v6(host_if)

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

    def _no_v6(self, name):
        self.sh("sysctl", "-qw", "net.ipv6.conf.%s.disable_ipv6=1" % name)


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
def owned(link, d):
    return link.get("alias") == d["alias"]


def plan(host, d, manifest):
    """Read-only. Returns (problems, actions)."""
    problems = []
    links, nss = host.links(), host.netns_list()
    for key in ("bridge", "tap", "veth_host"):
        if d[key] in links:
            problems.append("name busy: link %s (%s)" % (d[key], "own mark" if owned(links[d[key]], d) else "FOREIGN"))
    if d["netns"] in nss:
        problems.append("name busy: netns %s" % d["netns"])
    if manifest is not None and manifest.get("state") != "down":
        problems.append("manifest exists with state=%s: run `down` first" % manifest.get("state"))
    for n, l in links.items():
        if norm_mac(l.get("mac")) in (d["windows_mac"], d["peer_mac"]):
            problems.append("MAC %s already used by host link %s" % (l["mac"], n))
        for a in l.get("addrs", []):
            if _overlap(a):
                problems.append("address conflict: %s on %s overlaps %s" % (a, n, NET))
    for r in host.routes():
        if r and r != "default" and _overlap(r):
            problems.append("route conflict: %s overlaps %s" % (r, NET))
    actions = [
        "create bridge %s (no IP, stp off, ipv6 off)" % d["bridge"],
        "create tap %s, enslave to %s" % (d["tap"], d["bridge"]),
        "create netns %s; veth %s <-> %s in netns, enslave host end to %s" % (d["netns"], d["veth_host"], PEER_IF, d["bridge"]),
        "set %s/%d on %s in netns %s only (no gateway/DNS)" % (PEER_IP, PREFIX, PEER_IF, d["netns"]),
        "verify isolation (bridge slaves == {tap, veth}, no physical port, no host IP)",
    ]
    return problems, actions


def _overlap(cidr):
    try:
        return ipaddress.ip_interface(cidr).network.overlaps(NET)
    except ValueError:
        return False


def check_isolation(host, d):
    """Violations of the sealed-switch invariants for this run's bridge."""
    v = []
    links = host.links()
    br = links.get(d["bridge"])
    if br is None:
        return ["bridge %s missing" % d["bridge"]]
    if br.get("addrs"):
        v.append("bridge has host IP %s" % br["addrs"])
    allowed = {d["tap"], d["veth_host"]}
    for n, l in links.items():
        if l.get("master") == d["bridge"]:
            if l.get("physical"):
                v.append("physical uplink %s enslaved to bridge" % n)
            elif n not in allowed:
                v.append("unexpected port %s on bridge" % n)
    for n in allowed:
        if n in links:
            if links[n].get("addrs"):
                v.append("%s has host IP %s" % (n, links[n]["addrs"]))
            if links[n].get("master") != d["bridge"]:
                v.append("%s not enslaved to bridge" % n)
    return v


def select_adapter(adapters, mac):
    """Unique adapter by MAC from a guest Inventory; ambiguity or absence is an error."""
    want = norm_mac(mac)
    hits = [a for a in adapters if norm_mac(a.get("MacAddress") or a.get("mac")) == want]
    if len(hits) != 1:
        raise LabError("lab NIC ambiguous/absent: %d adapters match MAC %s" % (len(hits), want))
    return hits[0]


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
    if problems:
        print("REFUSED (nothing created or removed):\n  " + "\n  ".join(problems), file=sys.stderr)
        return 3
    m = {"schema": 1, "run_id": a.run_id, "state": "creating", "names": d, "created": [],
         "lab": {"net": str(NET), "windows_ip": WIN_IP, "peer_ip": PEER_IP, "prefix": PREFIX,
                 "gateway": None, "dns": None},
         "guest": {"guid": None, "npf": None}, "vm": {"attached": False}}
    write_manifest(a.manifest, m)

    def step(kind, name, fn):
        m["created"].append({"kind": kind, "name": name})  # write-ahead: owned even if fn dies midway
        write_manifest(a.manifest, m)
        fn()

    try:
        step("link", d["bridge"], lambda: host.create_bridge(d["bridge"], d["alias"]))
        step("link", d["tap"], lambda: host.create_tap(d["tap"], d["alias"], a.tap_user))
        host.enslave(d["tap"], d["bridge"])
        step("netns", d["netns"], lambda: host.netns_add(d["netns"]))
        step("link", d["veth_host"], lambda: host.create_veth(
            d["veth_host"], PEER_IF, d["netns"], d["alias"], d["peer_mac"][:-2] + "ff", d["peer_mac"]))
        host.enslave(d["veth_host"], d["bridge"])
        host.peer_config(d["netns"], PEER_IF, PEER_IP)
        viol = check_isolation(host, d)
        if viol:
            raise LabError("isolation check failed: " + "; ".join(viol))
    except Exception as e:
        print("up failed: %s; rolling back own objects" % e, file=sys.stderr)
        _teardown(host, a.manifest, m, d)
        return 4
    # QMP netdev_del/netdev_add on a cold-plugged e1000e does NOT re-peer the NIC (verified live):
    # after any down+up the VM must be restarted with run.sh to attach to the new TAP.
    m["vm"] = {"attached": False, "note": "restart the VM via ~/winvm/run.sh to bind the new TAP"}
    if a.lab_env:
        with open(a.lab_env, "w") as f:
            f.write("LAB_RUN_ID=%s\nLAB_TAP=%s\nLAB_MAC=%s\n" % (a.run_id, d["tap"], d["windows_mac"]))
        m["lab_env"] = a.lab_env
    m["state"] = "up"
    write_manifest(a.manifest, m)
    print("up: %s" % a.manifest)
    return 0


def _teardown(host, path, m, d):
    """Remove only objects recorded in this manifest AND carrying this run's mark."""
    rc = 0
    links, nss = host.links(), host.netns_list()
    for ent in reversed(m.get("created", [])):
        k, n = ent["kind"], ent["name"]
        if k == "link":
            if n not in links:
                continue
            if not owned(links[n], d):
                print("SKIP %s: not marked %s (foreign object left untouched)" % (n, d["alias"]), file=sys.stderr)
                rc = 5
                continue
            host.link_del(n)
        elif k == "netns" and n in nss:
            host.netns_del(n)
    return rc


def cmd_down(host, a):
    d = derive(a.run_id)
    m = read_manifest(a.manifest)
    if m is None:
        print("down: no manifest, nothing owned by run-id %s (no-op)" % a.run_id)
        return 0
    if m.get("run_id") != a.run_id:
        print("REFUSED: manifest belongs to run-id %s" % m.get("run_id"), file=sys.stderr)
        return 3
    if m.get("state") == "down":
        print("down: already down (no-op)")
        return 0
    rc = _teardown(host, a.manifest, m, d)
    env = m.get("lab_env")
    if env and os.path.exists(env):
        with open(env) as f:
            if "LAB_RUN_ID=%s\n" % a.run_id in f.read():
                os.remove(env)
    m["state"] = "down" if rc == 0 else "down-incomplete"
    write_manifest(a.manifest, m)
    print("down: %s" % m["state"])
    return rc


def cmd_status(host, a):
    d = derive(a.run_id)
    m = read_manifest(a.manifest)
    if m is None:
        print(json.dumps({"state": "absent"}))
        return 2
    links, nss = host.links(), host.netns_list()
    objs = {}
    for ent in m.get("created", []):
        n = ent["name"]
        objs[n] = ("netns present" if n in nss else "MISSING") if ent["kind"] == "netns" else (
            "present, owned" if n in links and owned(links[n], d) else
            "FOREIGN" if n in links else "MISSING")
    viol = check_isolation(host, d) if m["state"] == "up" else []
    ok = m["state"] == "up" and all(v.startswith("present") or v == "netns present" for v in objs.values()) and not viol
    print(json.dumps({"state": m["state"], "objects": objs, "isolation_violations": viol,
                      "vm": m.get("vm"), "guest": m.get("guest"), "ok": ok}, indent=2))
    return 0 if ok else 1


def cmd_record_guest(host, a):
    m = read_manifest(a.manifest)
    if m is None or m["run_id"] != a.run_id:
        raise LabError("no manifest for run-id")
    with open(a.guest_json) as f:
        g = json.load(f)
    ad = select_adapter(g["adapters"], m["names"]["windows_mac"])
    m["guest"] = {"guid": ad["InterfaceGuid"], "npf": "\\Device\\NPF_" + ad["InterfaceGuid"],
                  "name": ad.get("Name"), "ifindex": ad.get("ifIndex")}
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
    a = p.parse_args(argv)
    a.manifest = os.path.abspath(a.manifest)
    if host is None:
        if sys.platform != "linux":
            print("FATAL: Linux only", file=sys.stderr)
            return 2
        if os.geteuid() != 0 and a.cmd != "plan":
            os.execvp("sudo", ["sudo", "-n", sys.executable, os.path.abspath(__file__)] + (argv if argv is not None else sys.argv[1:]))
        host = RealHost()
    try:
        return {"plan": cmd_plan, "up": cmd_up, "status": cmd_status, "down": cmd_down,
                "record-guest": cmd_record_guest}[a.cmd](host, a)
    except LabError as e:
        print("ERROR: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
