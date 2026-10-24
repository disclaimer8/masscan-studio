#!/usr/bin/env python3
"""C oracle reference SYN frames for the Windows wire stand (stage 2B-Windows, task 4A).

Test tool (stdlib only), NOT product code. Runs on the operator machine and drives the oracle host
(`ssh minipc`, the pinned original C masscan built by build-oracle.sh) through `wire-lab.sh`, the SAME sealed
two-namespace + one-veth lab (no uplink, no bridge, no NAT; only its own namespaces) that produced the Linux
fixtures. The only difference is the binding: the Windows stand's source IP, source MAC and peer (router) MAC,
the same seed/rate/ports/source-port settings as each Windows case. No MAC or IP is ever normalised afterwards.

  windows-oracle-fixtures.py --out DIR --peer-mac 02:57:4c:3d:2e:9b [--host minipc]

Output DIR: manifest.json (verifier format: oracle sha256 + revision, binding, fixtures with sha256),
wire-lab-manifest.json (the raw lab manifest), env.json, isolation.json, commands.txt, topology-*.txt, one
<case>.run<N>.pcap / .capture.json / .scan.txt / .echo per case and run. Nothing stays on the oracle host.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("windows_wire_verify", os.path.join(HERE, "windows_wire_verify.py"))
V = importlib.util.module_from_spec(_s)
_s.loader.exec_module(V)

GUEST_MAC = "52:54:00:04:80:a9"
SRC_IP = "198.18.0.1"
ORACLE_REL = "rmasscan-oracle/masscan/bin/masscan"
PIN = "8e6b3b0c07a81e8ea61d557c06134a21a6881614"
LAB_FILES = ["wire-lab.sh", "wire_capture.py", "verify-wire.py", "windows_wire_verify.py"]


def ssh(host, cmd, timeout=900, check=True):
    r = subprocess.run(["ssh", "-o", "BatchMode=yes", host, cmd], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        raise SystemExit("ssh %s: rc=%d\n%s\n%s" % (host, r.returncode, r.stdout[-1500:], r.stderr[-1500:]))
    return r


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def convert(raw, out_dir):
    """wire-lab manifest -> the verifier's fixtures/manifest.json (no values are altered)."""
    b = raw["binding"]
    fixtures, valid = {}, bool(raw.get("all_valid"))
    for c in raw["cases"]:
        for i, run in enumerate(c["runs"], 1):
            fn = run["pcap"]
            fixtures["%s.run%d" % (c["name"], i)] = {
                "file": "fixtures/" + fn, "sha256": sha256_file(os.path.join(out_dir, fn)),
                "capture_valid": bool(run["valid"]), "observed": run["observed"], "expected": c["expected"]}
            valid &= bool(run["valid"])
        valid &= c["repeat_compare"]["result"] == "PASS"  # the two C runs of a case are byte-identical
    o = raw["oracle"]
    return {
        "schema": 1, "all_valid": valid,
        "oracle": {"sha256": o["sha256"], "git_commit": o["git_commit"], "git_tree_clean": o["git_tree_clean"],
                   "variant": o.get("variant"), "version_line": o.get("version_line"), "pinned_revision": PIN,
                   "host": "minipc"},
        "binding": {"src_ip": b["adapter_ip"], "src_mac": b["adapter_mac"], "router_mac": b["router_mac"],
                    "seed": b["seed"], "rate": b["rate"], "blackrock_rounds": b["blackrock_rounds"], "retries": b["retries"],
                    "wait": b["wait"], "responder_open_ports": b["responder_open_ports"]},
        "fixtures": fixtures,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--peer-mac", required=True, help="MAC of lab0 in the Windows stand's peer namespace")
    ap.add_argument("--host", default="minipc")
    a = ap.parse_args()
    if os.path.exists(a.out) and os.listdir(a.out):
        raise SystemExit("refusing to reuse a non-empty %s" % a.out)
    os.makedirs(a.out, exist_ok=True)
    work = "t4-fixtures-%d" % int(time.time())
    open_ports = ",".join(str(p) for p in V.LISTEN_OPEN)
    try:
        ssh(a.host, "mkdir -p ~/%s/scripts" % work)
        subprocess.run(["scp", "-q"] + [os.path.join(HERE, f) for f in LAB_FILES] + ["%s:%s/scripts/" % (a.host, work)], check=True)
        cases = V.cases_psv()
        r = subprocess.run(["ssh", "-o", "BatchMode=yes", a.host, "cat > ~/%s/cases.psv" % work], input=cases, text=True, capture_output=True)
        if r.returncode:
            raise SystemExit(r.stderr)
        env = {"WIRELAB_MAC_A": GUEST_MAC, "WIRELAB_MAC_B": a.peer_mac, "WIRELAB_IP_ADAPTER": SRC_IP, "WIRELAB_IP_A_LINK": "",
               "WIRELAB_PEER_IPS": V.PEER_IP, "WIRELAB_PEER_PREFIX": "30", "WIRELAB_OPEN_PORTS": open_ports,
               "WIRELAB_CASES_FILE": "$HOME/%s/cases.psv" % work}
        envs = " ".join("%s=%s" % (k, shlex.quote(v) if not v.startswith("$") else '"%s"' % v) for k, v in env.items())
        cmd = "cd ~/%s && %s bash scripts/wire-lab.sh --oracle \"$HOME/%s\" --out out" % (work, envs, ORACLE_REL)
        print("oracle host:", cmd, flush=True)
        r = ssh(a.host, cmd, timeout=1800, check=False)
        open(os.path.join(a.out, "wire-lab.log"), "w").write(r.stdout + "\n--- stderr ---\n" + r.stderr)
        subprocess.run(["scp", "-q", "-r", "%s:%s/out/." % (a.host, work), a.out], check=True)
        left = ssh(a.host, "ip netns list | grep -c wl- || true", check=False).stdout.strip()
        open(os.path.join(a.out, "cleanup.txt"), "w").write("lab namespaces left on the oracle host after the run: %s\n" % left)
        if r.returncode:
            raise SystemExit("wire-lab.sh failed rc=%d (see wire-lab.log)" % r.returncode)
    finally:
        ssh(a.host, "rm -rf ~/%s" % work, check=False)
    raw = json.load(open(os.path.join(a.out, "manifest.json")))
    os.rename(os.path.join(a.out, "manifest.json"), os.path.join(a.out, "wire-lab-manifest.json"))
    fx = convert(raw, a.out)
    with open(os.path.join(a.out, "manifest.json"), "w") as f:
        json.dump(fx, f, indent=1, sort_keys=True)
    print("fixtures: %d pcaps, all_valid=%s, oracle sha256 %s revision %s" % (len(fx["fixtures"]), fx["all_valid"], fx["oracle"]["sha256"], fx["oracle"]["git_commit"]))
    return 0 if fx["all_valid"] else 3


if __name__ == "__main__":
    sys.exit(main())
