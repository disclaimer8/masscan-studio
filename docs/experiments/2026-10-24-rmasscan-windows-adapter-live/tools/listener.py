#!/usr/bin/env python3
"""TCP listeners for the peer netns (sudo ip netns exec wvp-n2 python3 listener.py PORT...).

Binds 198.18.0.2:PORT only (refuses elsewhere) so the kernel answers SYN with
SYN-ACK on those ports; every other port answers RST. Accepts and closes.
"""
import selectors, socket, sys

ADDR = "198.18.0.2"
names = sorted(n for _, n in socket.if_nameindex())
if names != ["lab0", "lo"]:
    sys.exit("refusing: not in the lab netns, interfaces = %r" % names)
sel = selectors.DefaultSelector()
for p in sys.argv[1:]:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ADDR, int(p))); s.listen(128); s.setblocking(False)
    sel.register(s, selectors.EVENT_READ)
print("listening", sys.argv[1:], flush=True)
while True:
    for key, _ in sel.select():
        try:
            c, _ = key.fileobj.accept(); c.close()
        except OSError:
            pass
