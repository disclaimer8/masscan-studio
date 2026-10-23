#!/usr/bin/env python3
"""Compare the ordered stream of outgoing TCP SYN frames of two classic pcaps.

Independent test tool (stdlib only), not product code.

  verify-wire.py --expected EXP.pcap --actual ACT.pcap
                 [--expected-meta EXP.json] [--actual-meta ACT.json]
  verify-wire.py --self-test

Only frames that are IPv4/TCP with exactly the SYN flag (no ACK/RST/FIN) are
compared, byte for byte, in capture order. Timestamps, ARP, RST, SYN-ACK and
every other frame are ignored.

Exit codes: 0 PASS, 1 FAIL (streams differ), 2 INVALID (a pcap is truncated or
malformed, or a capture meta reports drops/truncation). INVALID is never PASS.
"""
import argparse
import json
import struct
import sys

PASS, FAIL, INVALID = 0, 1, 2


class PcapError(Exception):
    pass


def read_pcap(data):
    """Parse classic pcap bytes -> (linktype, [frame bytes]). Strict."""
    if len(data) < 24:
        raise PcapError("pcap global header truncated (%d bytes)" % len(data))
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise PcapError("bad pcap magic %r" % magic)
    _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(end + "HHiIII", data[4:24])
    frames, off = [], 24
    while off < len(data):
        if off + 16 > len(data):
            raise PcapError("pcap record header truncated at offset %d" % off)
        _s, _u, caplen, origlen = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        if caplen != origlen:
            raise PcapError("frame %d snapped (caplen %d != len %d)" % (len(frames), caplen, origlen))
        if off + caplen > len(data):
            raise PcapError("pcap record body truncated at offset %d" % off)
        frames.append(bytes(data[off:off + caplen]))
        off += caplen
    return linktype, frames


def is_syn(frame):
    if len(frame) < 14 + 20 + 20 or frame[12:14] != b"\x08\x00":
        return False
    ihl = (frame[14] & 0x0F) * 4
    if frame[14] >> 4 != 4 or ihl < 20 or frame[23] != 6:
        return False
    if struct.unpack(">H", frame[20:22])[0] & 0x1FFF:  # fragment offset
        return False
    t = 14 + ihl
    if len(frame) < t + 14:
        return False
    return (frame[t + 13] & 0x3F) == 0x02  # SYN, nothing else


def syn_stream(frames):
    return [f for f in frames if is_syn(f)]


def meta_problem(meta):
    """Return a reason string when a capture meta makes a comparison invalid."""
    if meta is None:
        return None
    if meta.get("drops", 0) or meta.get("kernel_drops", 0):
        return "capture reports drops=%s" % (meta.get("drops") or meta.get("kernel_drops"))
    if meta.get("truncated_frames", 0) or meta.get("truncated", False):
        return "capture reports truncated frames"
    if meta.get("rx_counter_mismatch", False):
        return "capture frame count != interface rx counter"
    if meta.get("valid") is False:
        return "capture meta marked invalid"
    return None


def compare_streams(exp, act):
    """-> (code, message) for two lists of SYN frames."""
    for i in range(min(len(exp), len(act))):
        if exp[i] != act[i]:
            diff = [j for j in range(min(len(exp[i]), len(act[i]))) if exp[i][j] != act[i][j]]
            return FAIL, "SYN #%d differs (len %d vs %d, first differing byte %s)" % (
                i, len(exp[i]), len(act[i]), diff[0] if diff else "length")
    if len(exp) != len(act):
        return FAIL, "SYN count differs: expected %d, actual %d" % (len(exp), len(act))
    return PASS, "%d SYN frames identical and in order" % len(exp)


def compare_bytes(exp_bytes, act_bytes, exp_meta=None, act_meta=None):
    for name, meta in (("expected", exp_meta), ("actual", act_meta)):
        why = meta_problem(meta)
        if why:
            return INVALID, "%s: %s" % (name, why)
    try:
        _, ef = read_pcap(exp_bytes)
    except PcapError as e:
        return INVALID, "expected pcap: %s" % e
    try:
        _, af = read_pcap(act_bytes)
    except PcapError as e:
        return INVALID, "actual pcap: %s" % e
    es, as_ = syn_stream(ef), syn_stream(af)
    if not es:
        return INVALID, "expected pcap contains no SYN frames"
    return compare_streams(es, as_)


# ---------------------------------------------------------------- self test
def _syn(dport, seq=1, sport=40000, dst=2):
    eth = bytes.fromhex("02aa00000002") + bytes.fromhex("02aa00000001") + b"\x08\x00"
    ip = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, 0x1234, 0, 255, 6, 0,
                               bytes([10, 200, 0, 100]), bytes([10, 200, 0, dst])))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, 0x02, 1024, 0, 0)
    return eth + bytes(ip) + tcp


def _rst(dport):
    f = bytearray(_syn(dport))
    f[14 + 20 + 13] = 0x04
    return bytes(f)


def _arp():
    return bytes.fromhex("ffffffffffff02aa00000001") + b"\x08\x06" + b"\x00" * 28


def _pcap(frames, big=False):
    e = ">" if big else "<"
    out = bytearray(struct.pack(e + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, f in enumerate(frames):
        out += struct.pack(e + "IIII", i, 0, len(f), len(f)) + f
    return bytes(out)


def self_test():
    a, b, c, d = _syn(80), _syn(81, seq=2), _syn(443, seq=3), _syn(22, seq=4)
    base = [a, b, c, d]
    results = []

    def check(name, got, want):
        ok = got == want
        results.append(ok)
        print("%s %-34s -> %s (want %s)" % ("ok  " if ok else "FAIL", name, got, want))

    def run(exp, act, **kw):
        return compare_bytes(_pcap(exp), act if isinstance(act, bytes) else _pcap(act), **kw)[0]

    check("equal", run(base, base), PASS)
    check("equal, big-endian pcap", compare_bytes(_pcap(base), _pcap(base, True))[0], PASS)
    check("equal ignoring ARP/RST/timestamps", run(base, [_arp(), a, _rst(80), b, c, _arp(), d]), PASS)
    check("reordered", run(base, [b, a, c, d]), FAIL)
    check("dropped", run(base, [a, b, d]), FAIL)
    check("duplicated", run(base, [a, b, b, c, d]), FAIL)
    check("extra trailing", run(base, base + [a]), FAIL)
    mut = bytearray(c)
    mut[14 + 20 + 4 + 3] ^= 0x01  # one seq byte of a SYN
    check("mutated SYN byte", run(base, [a, b, bytes(mut), d]), FAIL)
    mut = bytearray(b)
    mut[38] ^= 0x80  # MAC / ip area byte (dst ip)
    check("mutated SYN ip byte", run(base, [a, bytes(mut), c, d]), FAIL)
    good = _pcap(base)
    check("truncated body", compare_bytes(good, good[:-7])[0], INVALID)
    check("truncated record header", compare_bytes(good, good[:24 + 16 + len(a) + 5])[0], INVALID)
    check("truncated global header", compare_bytes(good, good[:10])[0], INVALID)
    check("truncated expected", compare_bytes(good[:-3], good)[0], INVALID)
    check("bad magic", compare_bytes(good, b"\x00" * 64)[0], INVALID)
    check("no SYNs in expected", compare_bytes(_pcap([_arp()]), good)[0], INVALID)
    check("capture drops make it INVALID", compare_bytes(good, good, act_meta={"drops": 3})[0], INVALID)
    check("capture truncation INVALID", compare_bytes(good, good, exp_meta={"truncated_frames": 1})[0], INVALID)
    check("rx counter mismatch INVALID", compare_bytes(good, good, act_meta={"rx_counter_mismatch": True})[0], INVALID)
    check("clean meta still PASS", compare_bytes(good, good, exp_meta={"drops": 0}, act_meta={"drops": 0, "truncated_frames": 0})[0], PASS)
    n_ok = sum(results)
    print("self-test: %d/%d checks passed" % (n_ok, len(results)))
    return 0 if n_ok == len(results) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--expected")
    ap.add_argument("--actual")
    ap.add_argument("--expected-meta")
    ap.add_argument("--actual-meta")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not (a.expected and a.actual):
        ap.error("--expected and --actual are required")

    def load(p):
        with open(p, "rb") as f:
            return f.read()

    def jload(p):
        if not p:
            return None
        with open(p) as f:
            return json.load(f)

    code, msg = compare_bytes(load(a.expected), load(a.actual), jload(a.expected_meta), jload(a.actual_meta))
    print("%s: %s" % ({PASS: "PASS", FAIL: "FAIL", INVALID: "INVALID"}[code], msg))
    return code


if __name__ == "__main__":
    sys.exit(main())
