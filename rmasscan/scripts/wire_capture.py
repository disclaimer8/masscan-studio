#!/usr/bin/env python3
"""Independent wire-lab helper (stdlib AF_PACKET). Test tool, not product code.

Subcommands (all but `manifest`/`env` are Linux only, run inside the lab netns):
  record     capture every frame on an interface to a classic pcap + JSON meta
  marker     send the readiness marker frame the recorder acknowledges
  responder  listen on TCP ports so the peer answers SYN with SYN-ACK / RST
  env        write environment/oracle/binding facts
  manifest   assemble manifest.json from a wire-lab output directory
"""
import argparse
import hashlib
import json
import os
import platform
import re
import signal
import socket
import struct
import subprocess
import sys
import time

MARKER_ETHERTYPE = 0x88B5  # IEEE local experimental ethertype
MARKER_PAYLOAD = b"WIRELAB-READY"
PACKET_OUTGOING = 4
SOL_PACKET, PACKET_STATISTICS = 263, 6
SNAPLEN = 65535


_HOME_RE = re.compile(r"/(?:home|Users)/[^/\s\"']+|/root(?=/)")
_NS_RE = re.compile(r"wl-(scan|peer)-[0-9]+-[0-9]+")


def scrub(obj):
    """Remove the host user name and raw per-run namespace names from a JSON-able
    object: absolute home paths become $HOME, namespaces become wl-scan-RUNID /
    wl-peer-RUNID. Hashes and every other value are left untouched."""
    if isinstance(obj, str):
        return _NS_RE.sub(lambda m: "wl-%s-RUNID" % m.group(1), _HOME_RE.sub("$HOME", obj))
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {scrub(k): scrub(v) for k, v in obj.items()}
    return obj


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def read_counter(iface, name):
    with open("/sys/class/net/%s/statistics/%s" % (iface, name)) as f:
        return int(f.read())


# ------------------------------------------------------------------ record
def cmd_record(a):
    stop = {"flag": False}

    def on_sig(_n, _f):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, on_sig)
    signal.signal(signal.SIGINT, on_sig)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024 * 1024)
    s.bind((a.iface, 0))
    s.settimeout(0.1)
    try:
        s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)  # reset kernel counters
    except OSError:
        pass
    rx0 = read_counter(a.iface, "rx_packets")
    n_in = n_out = n_trunc = 0
    acked = False
    with open(a.pcap, "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, SNAPLEN, 1))
        # Readiness: socket is bound and counters baselined; the lab now sends a
        # marker frame and waits for the ack file, which proves frames reach us.
        open(a.ready, "w").write("bound\n")

        def drain(timeout_budget):
            nonlocal n_in, n_out, n_trunc, acked
            while True:
                try:
                    data, _anc, flags, addr = s.recvmsg(SNAPLEN + 1)
                except (socket.timeout, BlockingIOError):
                    return
                ts = time.time()
                truncated = bool(flags & socket.MSG_TRUNC)
                if truncated:
                    n_trunc += 1
                if addr[2] == PACKET_OUTGOING:
                    n_out += 1
                else:
                    n_in += 1
                data = data[:SNAPLEN]
                out.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(data),
                                      len(data) if not truncated else len(data) + 1))
                out.write(data)
                if (not acked and len(data) >= 14 + len(MARKER_PAYLOAD)
                        and data[12:14] == struct.pack(">H", MARKER_ETHERTYPE)
                        and data[14:14 + len(MARKER_PAYLOAD)] == MARKER_PAYLOAD):
                    acked = True
                    open(a.ack, "w").write("ack\n")

        while not stop["flag"]:
            drain(0.1)
        time.sleep(0.2)  # let in-flight frames land, then drain to empty
        s.settimeout(0.05)
        drain(0.05)
        try:
            tp_packets, tp_drops = struct.unpack("II", s.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        except OSError:
            tp_packets, tp_drops = -1, -1
        out.flush()
    rx1 = read_counter(a.iface, "rx_packets")
    rx_delta = rx1 - rx0
    meta = {
        "iface": a.iface,
        "pcap": os.path.basename(a.pcap),
        "marker_acked": acked,
        "frames_in": n_in,
        "frames_out": n_out,
        "kernel_tp_packets": tp_packets,
        "drops": tp_drops,
        "truncated_frames": n_trunc,
        "snaplen": SNAPLEN,
        "iface_rx_delta": rx_delta,
        # The pcap is written with caplen==len for non-truncated frames; a frame
        # larger than snaplen is recorded with len=caplen+1 so verify-wire rejects it.
        "rx_counter_mismatch": rx_delta != n_in,
    }
    meta["valid"] = bool(acked and tp_drops == 0 and n_trunc == 0 and rx_delta == n_in)
    with open(a.meta, "w") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")
    return 0


# ------------------------------------------------------------------ marker
def cmd_marker(a):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    frame = mac_bytes(a.dst) + mac_bytes(a.src) + struct.pack(">H", MARKER_ETHERTYPE) + MARKER_PAYLOAD.ljust(46, b"\0")
    for _ in range(3):
        s.send(frame)
        time.sleep(0.05)
    return 0


# --------------------------------------------------------------- responder
def cmd_responder(a):
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__("flag", True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("flag", True))
    socks = []
    for p in [int(x) for x in a.ports.split(",") if x]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.listen(128)
        socks.append(s)  # kernel answers SYN-ACK here; closed ports get RST
    open(a.ready, "w").write("listening %s\n" % a.ports)
    while not stop["flag"]:
        time.sleep(0.1)
    return 0


# --------------------------------------------------------------------- env
def run_out(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:  # noqa: BLE001
        return "unavailable: %s" % e


def cmd_env(a):
    osr = {}
    try:
        for line in open("/etc/os-release"):
            if "=" in line:
                k, v = line.rstrip().split("=", 1)
                osr[k] = v.strip('"')
    except OSError:
        pass
    here = os.path.dirname(os.path.abspath(__file__))
    oracle_src = os.path.abspath(os.path.join(os.path.dirname(a.oracle), ".."))
    conf = "/etc/masscan/masscan.conf"
    conf_info = {"path": conf, "exists": os.path.exists(conf)}
    if conf_info["exists"]:
        conf_info["size"] = os.path.getsize(conf)
        conf_info["sha256"] = sha256_file(conf)
    conf_info["masked_in_lab"] = a.conf_masked == "1"
    env = {
        "oracle": {
            "path": a.oracle,
            "sha256": sha256_file(a.oracle),
            "git_commit": run_out(["git", "-C", oracle_src, "rev-parse", "HEAD"]),
            "git_tree_clean": run_out(["git", "-C", oracle_src, "status", "--porcelain", "--untracked-files=all"]) == "",
            "variant": "original pinned binary (NOT the --offline-patched copy)",
            "version_line": next((l for l in run_out([a.oracle, "--version"]).splitlines() if "version" in l.lower()), ""),
        },
        "harness": {n: sha256_file(os.path.join(here, n)) for n in ("wire-lab.sh", "wire_capture.py", "verify-wire.py", "wire_suite.py")
                    if os.path.exists(os.path.join(here, n))},
        "host": {
            "os_pretty": osr.get("PRETTY_NAME", ""),
            "kernel": platform.release(),
            "arch": platform.machine(),
            "python": platform.python_version(),
            "iproute2": run_out(["ip", "-V"]),
        },
        "masscan_conf": conf_info,
        "namespaces": {"scanner": a.ns_a, "peer": a.ns_b},
        "binding": {
            "scanner_iface": a.iface_a,
            "peer_iface": a.iface_b,
            "adapter_mac": a.mac_a,
            "router_mac": a.mac_b,
            "adapter_ip": a.ip_a,
            "peer_ips": a.peer_ips,
            "seed": a.seed,
            "rate": a.rate,
            "blackrock_rounds": 14,
            "retries": 0,
            "wait": 3,
            "responder_open_ports": a.open_ports,
        },
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(a.out, "w") as f:
        json.dump(env, f, indent=2, sort_keys=True)
        f.write("\n")
    return 0


# ---------------------------------------------------------------- manifest
def classify(frames, mac_a, mac_b):
    """Count by role from the peer-side capture."""
    ma, mb = mac_bytes(mac_a), mac_bytes(mac_b)
    c = {"syn_from_scanner": 0, "synack_from_peer": 0, "rst_from_peer": 0, "rst_from_scanner": 0, "marker": 0, "other": 0}
    for f in frames:
        ok = len(f) >= 54 and f[12:14] == b"\x08\x00" and f[23] == 6
        flags = f[14 + (f[14] & 0x0F) * 4 + 13] & 0x3F if ok else None
        src = f[6:12]
        if ok and src == ma and flags == 0x02:
            c["syn_from_scanner"] += 1
        elif ok and src == mb and flags == 0x12:
            c["synack_from_peer"] += 1
        elif ok and src == mb and flags & 0x04:
            c["rst_from_peer"] += 1
        elif ok and src == ma and flags & 0x04:
            c["rst_from_scanner"] += 1
        elif f[12:14] == struct.pack(">H", MARKER_ETHERTYPE):
            c["marker"] += 1
        else:
            c["other"] += 1
    return c


def cmd_manifest(a):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib.util
    spec = importlib.util.spec_from_file_location("verify_wire", os.path.join(os.path.dirname(os.path.abspath(__file__)), "verify-wire.py"))
    vw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vw)

    d = a.dir
    env = json.load(open(os.path.join(d, "env.json")))
    b = env["binding"]
    cases = []
    all_valid = True
    for line in open(os.path.join(d, "cases.tsv")):
        line = line.rstrip("\n")
        if not line:
            continue
        name, exp_syn, exp_synack, exp_rst, scan_args = line.split("\t")
        exp_syn, exp_synack, exp_rst = int(exp_syn), int(exp_synack), int(exp_rst)
        runs = []
        for r in (1, 2):
            pcap = "%s.run%d.pcap" % (name, r)
            meta = json.load(open(os.path.join(d, "%s.run%d.capture.json" % (name, r))))
            _lt, frames = vw.read_pcap(open(os.path.join(d, pcap), "rb").read())
            counts = classify(frames, b["adapter_mac"], b["router_mac"])
            counts_ok = (counts["syn_from_scanner"] == exp_syn and counts["synack_from_peer"] == exp_synack
                         and counts["rst_from_peer"] == exp_rst)
            valid = bool(meta["valid"]) and counts_ok
            all_valid &= valid
            runs.append({
                "pcap": pcap,
                "pcap_sha256": sha256_file(os.path.join(d, pcap)),
                "pcap_bytes": os.path.getsize(os.path.join(d, pcap)),
                "capture": meta,
                "observed": counts,
                "counts_match_expected": counts_ok,
                "valid": valid,
            })
        code, msg = vw.compare_bytes(open(os.path.join(d, runs[0]["pcap"]), "rb").read(),
                                     open(os.path.join(d, runs[1]["pcap"]), "rb").read(),
                                     runs[0]["capture"], runs[1]["capture"])
        all_valid &= code == 0
        cases.append({
            "name": name,
            "masscan_args": scan_args.split(" "),
            "effective_echo_file": "%s.echo" % name,
            "effective_echo_sha256": sha256_file(os.path.join(d, "%s.echo" % name)),
            "expected": {"syn": exp_syn, "synack": exp_synack, "rst": exp_rst},
            "runs": runs,
            "repeat_compare": {"result": {0: "PASS", 1: "FAIL", 2: "INVALID"}[code], "detail": msg},
            "fixture_pcap": runs[0]["pcap"],
        })
    manifest = {
        "schema": "rmasscan-wire-manifest/1",
        "purpose": "Ordered outgoing-SYN stream of the original pinned C masscan on an isolated veth lab; "
                   "the Rust engine must reproduce it byte for byte. Timestamps, ARP, RST and replies are not compared.",
        "oracle": env["oracle"],
        "harness": env["harness"],
        "host": env["host"],
        "masscan_conf": env["masscan_conf"],
        "namespaces": env["namespaces"],
        "binding": env["binding"],
        "isolation": json.load(open(os.path.join(d, "isolation.json"))),
        "commands": open(os.path.join(d, "commands.txt")).read().splitlines(),
        "comparison_rule": "verify-wire.py: byte-compare the ordered list of IPv4/TCP frames with only SYN set; "
                           "capture drops, truncation, rx-counter mismatch or truncated pcap => INVALID (never PASS)",
        "all_valid": bool(all_valid),
        "cases": cases,
        "created_utc": env["created_utc"],
    }
    manifest = scrub(manifest)  # no host user name / raw namespace names in a committed file
    with open(os.path.join(d, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print("manifest: %d cases, all_valid=%s" % (len(cases), all_valid))
    return 0 if all_valid else 3


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("record")
    p.add_argument("--iface", required=True)
    p.add_argument("--pcap", required=True)
    p.add_argument("--meta", required=True)
    p.add_argument("--ready", required=True)
    p.add_argument("--ack", required=True)
    p.set_defaults(fn=cmd_record)
    p = sub.add_parser("marker")
    p.add_argument("--iface", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--dst", required=True)
    p.set_defaults(fn=cmd_marker)
    p = sub.add_parser("responder")
    p.add_argument("--ports", required=True)
    p.add_argument("--ready", required=True)
    p.set_defaults(fn=cmd_responder)
    p = sub.add_parser("env")
    for k in ("out", "oracle", "ns-a", "ns-b", "iface-a", "iface-b", "mac-a", "mac-b", "ip-a", "peer-ips",
              "seed", "rate", "open-ports", "conf-masked"):
        p.add_argument("--" + k, required=True)
    p.set_defaults(fn=cmd_env)
    p = sub.add_parser("manifest")
    p.add_argument("--dir", required=True)
    p.set_defaults(fn=cmd_manifest)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
