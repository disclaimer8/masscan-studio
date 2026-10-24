#!/usr/bin/env python3
"""Peer-side helpers for the Windows wire stand (stage 2B-Windows, task 4A). Linux, root, stdlib only.
Test tool, NOT product code. Every subcommand is meant to run INSIDE the lab peer namespace
(`sudo ip netns exec wvp-n2 python3 windows_wire_peer.py ...`) and refuses to run elsewhere.

  listen    explicit listeners: OPEN ports answer SYN-ACK, one SILENT port never answers (its accept queue is
            full, the kernel drops SYNs), every other port gets the kernel's RST
  marker    send the readiness marker frame (ethertype 0x88b5) that proves the capture is live
  counters  print "rx tx" packets of the lab interface
  inject    after the first scanner SYN, send FOREIGN replies (other IP / unscanned port / wrong cookie to the
            silent port / wrong destination port); every frame carries IPv4 id 0xF0E1
"""
import argparse
import json
import os
import signal
import socket
import struct
import sys
import time

ADDR = "198.18.0.2"
FOREIGN_IP_ID = 0xF0E1
MARKER_ETHERTYPE = 0x88B5
MARKER_PAYLOAD = b"WIRELAB-READY"  # default payload; "WIRELAB-END" is the end-of-capture marker


def guard_netns():
    names = sorted(n for _, n in socket.if_nameindex())
    if names != ["lab0", "lo"]:
        sys.exit("refusing: not in the lab peer netns, interfaces = %r" % names)


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(">%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def tcp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, seq, ack, ipid):
    """Ethernet + IPv4 + TCP with valid checksums (so rejection is the scanner's logic, not a bad checksum)."""
    sip, dip = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 1024, 0, 0)
    pseudo = sip + dip + struct.pack(">BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack(">H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), ipid, 0, 64, 6, 0, sip, dip)
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b"\x08\x00" + ip + tcp


def cmd_listen(a):
    guard_netns()
    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__("flag", True))
    signal.signal(signal.SIGINT, lambda *_: stop.__setitem__("flag", True))
    socks = []
    open_ports = [int(x) for x in a.open.split(",") if x]
    for p in open_ports:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ADDR, p))
        s.listen(128)
        socks.append(s)
    silent = int(a.silent) if a.silent else None
    clients = []
    silent_proven = None
    if silent:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ADDR, silent))
        s.listen(0)
        socks.append(s)
        # fill the accept queue: the first connection is queued (never accepted); a further one must time out
        for _ in range(2):
            c = socket.socket()
            c.settimeout(1.0)
            try:
                c.connect((ADDR, silent))
                clients.append(c)
            except OSError:
                silent_proven = True  # the SYN was dropped: nothing answers on this port any more
                c.close()
                break
        else:
            silent_proven = False
    info = {"open": open_ports, "silent": [silent] if silent else [], "silent_proven": silent_proven,
            "ready": silent_proven is not False, "bind": ADDR, "pid": os.getpid()}
    with open(a.ready, "w") as f:
        json.dump(info, f)
    while not stop["flag"]:
        time.sleep(0.1)
    return 0


def cmd_marker(a):
    guard_netns()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    frame = mac_bytes(a.dst) + mac_bytes(a.src) + struct.pack(">H", MARKER_ETHERTYPE) + \
        (a.payload.encode() if a.payload else MARKER_PAYLOAD).ljust(46, b"\0")
    for _ in range(3):
        s.send(frame)
        time.sleep(0.05)
    return 0


def cmd_counters(a):
    guard_netns()
    vals = []
    for n in ("rx_packets", "tx_packets"):
        with open("/sys/class/net/%s/statistics/%s" % (a.iface, n)) as f:
            vals.append(int(f.read()))
    print("%d %d" % tuple(vals))
    return 0


def foreign_kinds(peer_mac, guest_mac, src_ip, sport, silent):
    """kind -> frame. All are SYN-ACKs the scanner must NOT turn into results."""
    mk = lambda ip, rp, dp, ack: tcp_frame(peer_mac, guest_mac, ip, src_ip, rp, dp, 0x12, 7, ack, FOREIGN_IP_ID)  # noqa: E731
    return {
        "other_ip": mk("198.18.0.3", 80, sport, 0xDEADBEEF),
        "unscanned_port": mk(ADDR, 9999, sport, 0xDEADBEEF),
        "wrong_cookie": mk(ADDR, silent, sport, 0xDEADBEEF),
        "wrong_dst_port": mk(ADDR, 80, sport + 1, 0xDEADBEEF),
    }


def cmd_inject(a):
    guard_netns()
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((a.iface, 0))
    s.settimeout(0.05)
    gm = mac_bytes(a.guest_mac)
    deadline = time.time() + a.wait_first
    seen = False
    while time.time() < deadline and not seen:  # block until the scan's first SYN is on the wire
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        if addr[2] != 4 and data[6:12] == gm and len(data) >= 54 and data[12:14] == b"\x08\x00" and data[23] == 6 \
                and (data[14 + (data[14] & 0xF) * 4 + 13] & 0x3F) == 0x02:
            seen = True
    frames = foreign_kinds(a.peer_mac, a.guest_mac, a.src_ip, a.sport, a.silent)
    counts = {k: 0 for k in frames}
    t_first = None
    end = time.time() + a.duration
    while seen and time.time() < end:
        for k, f in frames.items():
            s.send(f)
            counts[k] += 1
            t_first = t_first or time.time()
        time.sleep(a.interval)
    out = {"first_syn_seen": seen, "sent_total": sum(counts.values()), "kinds": counts, "interval_s": a.interval,
           "duration_s": a.duration, "ipid": FOREIGN_IP_ID, "first_sent_at": t_first}
    with open(a.out, "w") as f:
        json.dump(out, f)
    return 0 if seen else 3


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("listen")
    p.add_argument("--open", required=True)
    p.add_argument("--silent", default="")
    p.add_argument("--ready", required=True)
    p.set_defaults(fn=cmd_listen)
    p = sub.add_parser("marker")
    p.add_argument("--iface", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--dst", required=True)
    p.add_argument("--payload", default="")
    p.set_defaults(fn=cmd_marker)
    p = sub.add_parser("counters")
    p.add_argument("--iface", required=True)
    p.set_defaults(fn=cmd_counters)
    p = sub.add_parser("inject")
    p.add_argument("--iface", required=True)
    p.add_argument("--peer-mac", required=True)
    p.add_argument("--guest-mac", required=True)
    p.add_argument("--src-ip", required=True)
    p.add_argument("--sport", type=int, required=True)
    p.add_argument("--silent", type=int, required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--wait-first", type=float, default=60.0)
    p.add_argument("--duration", type=float, default=2.0)
    p.add_argument("--interval", type=float, default=0.1)
    p.set_defaults(fn=cmd_inject)
    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
