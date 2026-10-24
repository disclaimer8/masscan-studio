#!/usr/bin/env python3
"""Junk-frame generator for the isolated Windows lab (stage 2B-Windows, task 2).

Runs INSIDE the peer netns (sudo ip netns exec wvp-n2 python3 flood.py ...).
Sends only on lab0, only to the lab guest MAC, ethertype 0x88b5 (IEEE local
experimental), payload = u32 seq + b"RMSP" + zero pad to 60 bytes. Refuses to
run when anything other than lo/lab0 is visible, so it can never touch the
host network namespace.
"""
import argparse, json, signal, socket, struct, sys, time

GUEST_MAC = "52:54:00:04:80:a9"
IFACE = "lab0"

ap = argparse.ArgumentParser()
ap.add_argument("--count", type=int, default=0, help="stop after N frames (0 = until duration/signal)")
ap.add_argument("--duration", type=float, default=0.0, help="stop after S seconds (0 = until count/signal)")
ap.add_argument("--pps", type=int, default=0, help="target frames/s (0 = as fast as possible)")
ap.add_argument("--start-at", type=float, default=0.0, help="epoch seconds to wait for")
ap.add_argument("--out", required=True)
a = ap.parse_args()

names = sorted(n for _, n in socket.if_nameindex())
if names != sorted(["lo", IFACE]):
    sys.exit("refusing: not in the lab netns, interfaces = %r" % names)
if not a.count and not a.duration:
    sys.exit("need --count or --duration")

with open("/sys/class/net/%s/address" % IFACE) as f:
    src = bytes(int(x, 16) for x in f.read().strip().split(":"))
dst = bytes(int(x, 16) for x in GUEST_MAC.split(":"))
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((IFACE, 0))

stop = False
def on_sig(*_):
    global stop
    stop = True
signal.signal(signal.SIGINT, on_sig)
signal.signal(signal.SIGTERM, on_sig)

while a.start_at and time.time() < a.start_at and not stop:
    time.sleep(0.005)

hdr = dst + src + struct.pack("!H", 0x88B5)
sent = errors = 0
t_first = time.time()
t0 = time.monotonic()
deadline = t0 + a.duration if a.duration else None
seq = 0
while not stop:
    if a.count and sent >= a.count:
        break
    if deadline and time.monotonic() >= deadline:
        break
    frame = (hdr + struct.pack("!I", seq) + b"RMSP").ljust(60, b"\0")
    try:
        s.send(frame)
        sent += 1
    except OSError:
        errors += 1
    seq += 1
    if a.pps and sent % 100 == 0:
        ahead = t0 + sent / a.pps - time.monotonic()
        if ahead > 0:
            time.sleep(ahead)
t_last = time.time()
res = {"sent": sent, "errors": errors, "t_first": t_first, "t_last": t_last,
       "seconds": t_last - t_first, "pps_avg": sent / max(t_last - t_first, 1e-9),
       "iface": IFACE, "dst_mac": GUEST_MAC}
with open(a.out, "w") as f:
    json.dump(res, f)
print(json.dumps(res))
