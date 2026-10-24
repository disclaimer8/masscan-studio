#!/usr/bin/env python3
"""Toggle the link of the lab NIC's netdev (id lab0) through QMP set_link.

usage: qmp_link.py up|down
Only the netdev named lab0 (the lab NIC of the n2 stand) can be addressed; the
management NIC (n0) is never named. VM-local, reversible, touches nothing else.
"""
import json, os, socket, sys, time

NAME = "lab0"
SOCK = os.path.expanduser("~/winvm/qmp.sock")

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("up", "down"):
        sys.exit(__doc__)
    up = sys.argv[1] == "up"
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(5)
    s.connect(SOCK)
    f = s.makefile("rw")
    greeting = json.loads(f.readline())
    assert "QMP" in greeting, greeting
    def call(cmd, args=None):
        msg = {"execute": cmd}
        if args:
            msg["arguments"] = args
        f.write(json.dumps(msg) + "\n"); f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                return r
    r = call("qmp_capabilities"); assert "return" in r, r
    r = call("set_link", {"name": NAME, "up": up})
    print(time.time(), "set_link", NAME, "up" if up else "down", json.dumps(r))
    sys.exit(0 if "return" in r else 1)

main()
