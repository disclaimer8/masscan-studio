"""Tests of the offline Windows wire verifier (scripts/windows_wire_verify.py) and of the pure parts of the
orchestrator (scripts/windows-wire-suite.py). Stdlib unittest, no Npcap, no lab:

  python3 -I rmasscan/scripts/tests/test_windows_wire.py

A synthetic, internally consistent artifact set (all planned runs) is built in a temp dir; every
negative test breaks exactly ONE thing and demands that the verdict stops being PASS."""
import copy
import hashlib
import importlib.util
import json
import os
import struct
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name, fname):
    s = importlib.util.spec_from_file_location(name, os.path.join(HERE, "..", fname))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


V = load("wwv", "windows_wire_verify.py")
S = load("wws", "windows-wire-suite.py")
P = load("wwp", "windows_wire_peer.py")

GUEST = "52:54:00:04:80:a9"
PEER = "02:57:4c:3d:2e:9b"
SRC_IP, PEER_IP = "198.18.0.1", "198.18.0.2"
COMMIT = "c" * 40
EXE = "e" * 64


ITEMS = {i["tag"]: i for i in V.planned(None) + V.planned_b()}
LISTEN_SILENT = [V.SILENT_PORT]


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ipb(s):
    return bytes(int(x) for x in s.split("."))


def frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, seq=0, ack=0, ipid=0x1234):
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40, ipid, 0, 64, 6, 0, ipb(src_ip), ipb(dst_ip))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 1024, 0, 0)
    return mac(dst_mac) + mac(src_mac) + b"\x08\x00" + ip + tcp


def syn(sport, dport):
    return frame(GUEST, PEER, SRC_IP, PEER_IP, sport, dport, 0x02, seq=sport * 65536 + dport)


def reply(case_sport, dport):
    flags = 0x12 if dport in V.LISTEN_OPEN else 0x14
    return frame(PEER, GUEST, PEER_IP, SRC_IP, dport, case_sport, flags, seq=7, ack=1)


def marker(payload=b"WIRELAB-READY"):
    return mac(GUEST) + mac(PEER) + b"\x88\xb5" + payload.ljust(46, b"\0")


def pcap(frames_ts):
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for t, f in frames_ts:
        out += struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(f), len(f)) + f
    return bytes(out)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def case_syns(case):
    sp = V.sport_range(case["source_port"])[0]
    return [syn(sp, p) for p in V.port_list(case["ports"])]


def case_replies(case, silent_answers=True):
    sp = V.sport_range(case["source_port"])[0]
    return [reply(sp, p) for p in V.port_list(case["ports"]) if silent_answers or p != V.SILENT_PORT]


def wj(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f)


def bw(path, data):
    with open(path, "wb") as f:
        f.write(data)


def tcpd(n):
    return {"captured": n, "received": n, "dropped_kernel": 0, "dropped_if": 0}


def write_run(root, tag, syns, replies, rj_extra, rc=0, extra_files=None, extra_peer_frames=(), sub="runs", end_marker=True):
    """One consistent run directory; returns its path."""
    d = os.path.join(root, sub, tag)
    os.makedirs(d)
    t = 1000.0
    pf = [(t, marker())]
    t += 1
    for f in syns:
        pf.append((t, f))
        t += 0.01
    for f in replies:
        pf.append((t, f))
        t += 0.01
    for tt, f in extra_peer_frames:
        pf.append((tt, f))
    if end_marker:
        t_end = max(t for t, _f in pf) + 2.0
        pf += [(t_end + i * 0.05, marker(V.END_PAYLOAD)) for i in range(3)]
    pf.sort(key=lambda x: x[0])
    peer = pcap(pf)
    eno = pcap([])
    bw(os.path.join(d, "peer.pcap"), peer)
    bw(os.path.join(d, "eno1.pcap"), eno)
    n = len(pf)
    n_tx = sum(1 for _t, f in pf if f[6:12] == mac(PEER))  # frames the peer sent (marker counted as peer tx)
    n_tx += sum(1 for _t, f in pf if f[12:14] == b"\x88\xb5" and f[6:12] != mac(PEER))
    n_rx = n - n_tx
    cap = {
        "capture_schema": 2,
        "peer": {"filter": "", "cmd": ["tcpdump", "-i", "lab0", "--immediate-mode"], "listening": True, "tcpdump": tcpd(n),
                 "pcap": {"sha256": sha(peer), "size": len(peer), "frames": n},
                 "counters": {"rx_before": 10, "tx_before": 20, "rx_ready": 10, "tx_ready": 20,
                              "rx_end": 10 + n_rx, "tx_end": 20 + n_tx}},
        "eno1": {"filter": "net 198.18.0.0/30", "cmd": ["tcpdump", "-i", "eno1", "--immediate-mode"], "listening": True, "tcpdump": tcpd(0),
                 "pcap": {"sha256": sha(eno), "size": len(eno), "frames": 0}},
        "quiet": {"reached": True, "quiet_s": 1.5},
    }
    wj(os.path.join(d, "capture.json"), cap)
    wj(os.path.join(d, "meta.json"), {"guest_exit": rc, "exe_sha256": EXE, "capture_started_utc": 1.0,
                                       "guest_started_utc": 2.0, "guest_finished_utc": 3.0, "capture_stopped_utc": 4.0})
    rj = {"identity": {"source_commit": COMMIT, "binary_sha256": EXE, "os": {"family": "windows"}}}
    rj.update(rj_extra)
    wj(os.path.join(d, "run.json"), rj)
    item = ITEMS.get(tag) or ITEMS.get(tag.rsplit(".", 1)[0])
    if item:
        man = {"binding": {"iface": "\\Device\\NPF_{X}"}}
        bind = V.Binding({"src_ip": SRC_IP, "src_mac": GUEST, "router_mac": PEER})
        for fname, kd in [("argv.json", V.KIND_ARGV.get(item["kind"]) or V.KIND_ARGV_B.get(item["kind"]))] + (
                [(V.KIND_SIDE_ARGV.get(item["kind"]) or V.KIND_SIDE_ARGV_B.get(item["kind"]))] if (
                    item["kind"] in V.KIND_SIDE_ARGV or item["kind"] in V.KIND_SIDE_ARGV_B) else []):
            cname, extra = kd(item)
            cc = cname if isinstance(cname, dict) or cname is None else V.case_by_name(cname)
            want = dict(V.base_argv(cc, man, bind) if cc else {}, **extra)
            argv = [x for k, v in want.items() for x in ((k,) if v is True else (k, "x.bin" if v == V.ANY else v))]
            wj(os.path.join(d, fname), {"exe": "x", "argv": argv})
    wj(os.path.join(d, "status-pre.json"), {"raw_run_allowed": True, "isolation_violations": []})
    wj(os.path.join(d, "status-post.json"), {"raw_run_allowed": True, "isolation_violations": []})
    wj(os.path.join(d, "guest-verify.json"), {"ok": True, "errors": []})
    wj(os.path.join(d, "listeners.json"), {"open": V.LISTEN_OPEN, "ready": True, "silent": LISTEN_SILENT, "silent_proven": True})
    for k, v in (extra_files or {}).items():
        if isinstance(v, bytes):
            bw(os.path.join(d, k), v)
        else:
            wj(os.path.join(d, k), v)
    return d


def job_of(case, wait=3):
    return {"iface": "\\Device\\NPF_{X}", "src_ip": SRC_IP, "src_mac": GUEST, "router_mac": PEER, "source_port": case["source_port"],
            "targets": case["targets"], "exclude": case["exclude"], "ports": case["ports"], "seed": case.get("seed", 1), "rate": case.get("rate", 100),
            "wait": case.get("wait", wait), "retries": 0, "shard": "1/1", "blackrock_rounds": 14}


def full_json(case, replies_sorted, sent=None, **kw):
    n = case["syn"] if sent is None else sent
    d = {"status": "ok", "reason": "Completed", "fail_detail": "", "range": case["syn"], "start_index": 0,
         "expected_total": case["syn"], "sent": n, "next_index": case["syn"], "received": len(replies_sorted),
         "discarded": 0, "duplicates": 0, "rx_health": {"kernel_drops": 0}, "scan_id": "11" * 16, "attempt_id": "aa" * 16,
         "resumed_from_attempt": None, "replies": replies_sorted, "reply_total": len(replies_sorted),
         "reply_unique": len(replies_sorted), "checkpoint": False, "checkpoint_next_index": None,
         "net": {"tx_sent": n, "tx_uncertain": 0, "tx_errors": 0, "rx_errors": 0, "kernel_drops": 0}, "job": job_of(case)}
    d.update(kw)
    return d


def build(root, foreign=True):
    """A complete, passing artifact set for every planned run."""
    os.makedirs(os.path.join(root, "fixtures"))
    fixtures = {}
    for c in V.CASES + [V.FOREIGN_CASE]:
        for r in (1, 2):
            data = pcap([(1.0, marker())] + [(2.0 + i * 0.01, f) for i, f in enumerate(case_syns(c) + case_replies(c))])
            fn = "fixtures/%s.run%d.pcap" % (c["name"], r)
            bw(os.path.join(root, fn), data)
            fixtures["%s.run%d" % (c["name"], r)] = {"file": fn, "sha256": sha(data)}
    wj(os.path.join(root, "fixtures", "manifest.json"),
       {"oracle": {"sha256": "a" * 64, "git_commit": "8e6b3b0c07a81e8ea61d557c06134a21a6881614", "git_tree_clean": True},
        "binding": {"src_ip": SRC_IP, "src_mac": GUEST, "router_mac": PEER, "seed": 1, "rate": 100},
        "all_valid": True, "fixtures": fixtures})
    wj(os.path.join(root, "manifest.json"),
       {"code_commit": COMMIT, "capture_schema": 2, "exe": {"sha256": EXE},
        "binding": {"iface": "\\Device\\NPF_{X}", "src_ip": SRC_IP, "src_mac": GUEST, "router_mac": PEER}})
    for c in V.CASES + [V.FOREIGN_CASE]:
        for r in (1, 2):
            tag = "%s.run%d" % (c["name"], r)
            exp = V.expected_replies(c)
            extra, files, efr = {}, {}, ()
            if c is V.FOREIGN_CASE:
                sp = 40000
                fr = [frame(PEER, GUEST, "198.18.0.3", SRC_IP, 80, sp, 0x12, ack=5, ipid=V.FOREIGN_IP_ID),
                      frame(PEER, GUEST, PEER_IP, SRC_IP, 9999, sp, 0x12, ack=5, ipid=V.FOREIGN_IP_ID),
                      frame(PEER, GUEST, PEER_IP, SRC_IP, V.SILENT_PORT, sp, 0x12, ack=0xdeadbeef, ipid=V.FOREIGN_IP_ID),
                      frame(PEER, GUEST, PEER_IP, SRC_IP, 80, 40001, 0x12, ack=5, ipid=V.FOREIGN_IP_ID)]
                efr = [(1001.005 + i * 0.001, f) for i, f in enumerate(fr)]
                files["injector.json"] = {"sent_total": 4, "kinds": {"other_ip": 1, "unscanned_port": 1, "wrong_cookie": 1,
                                                                    "wrong_dst_port": 1}}
            fj = full_json(c, exp, discarded=4 if c is V.FOREIGN_CASE else 0)
            write_run(root, tag, case_syns(c), case_replies(c, silent_answers=False), fj, extra_files=files,
                      extra_peer_frames=efr)
    pc = V.case_by_name(V.PAUSE_CASE)
    syns, reps = case_syns(pc), case_replies(pc)
    exp = V.expected_replies(pc)
    open_set = lambda fr: sorted("%s:%d:%s" % (PEER_IP, V.port_list(pc["ports"])[syns.index(s)], "open" if V.port_list(pc["ports"])[syns.index(s)] in V.LISTEN_OPEN else "closed") for s in fr)  # noqa: E731
    for n in V.PAUSE_NS:
        a = full_json(pc, open_set(syns[:n]), sent=n, reason="Paused", next_index=n, checkpoint=True, checkpoint_next_index=n)
        a["range"] = 16
        write_run(root, "pause_N%d" % n, syns[:n], reps[:n], a, extra_files={"checkpoint.bin": b"cp%d" % n})
        b = full_json(pc, open_set(syns[n:]), sent=16 - n, start_index=n, attempt_id="bb" * 16, resumed_from_attempt="aa" * 16)
        write_run(root, "resume_N%d" % n, syns[n:], reps[n:], b)
    write_run(root, "complete_nopause", syns, reps, full_json(pc, exp))
    write_run(root, "refuse_completed", [], [], {"status": "error", "error": "AlreadyCompleted", "opened_adapter": False, "tx_sent": 0,
                                                 "job": job_of(pc)}, rc=4)
    return root


# ------------------------------------------------------------------ part B builder
def b_walls(n_syn, outcome_after=0.5, offset=50.0):
    """wall/timing fields consistent with a pcap whose first scanner SYN is at 1001.0 and whose SYNs are 10 ms apart."""
    first, last = 1001.0, 1001.0 + 0.01 * (n_syn - 1)
    t0 = first - 0.002 - offset
    return ({"t0_utc_ms": int(t0 * 1000), "started_utc_ms": int(t0 * 1000), "outcome_utc_ms": int((last + outcome_after - offset) * 1000),
             "join_done_utc_ms": int((last + outcome_after - offset) * 1000) + 1}, {"first_send_s": 0.002})


def b_rj(case, sent, reason="Stopped", fail_detail="", replies=(), stop=True, observe=1500, **kw):
    wall, tm = b_walls(max(sent, 1))
    replies = sorted(replies)
    tm.update(stop_requested=stop, stop_to_outcome_ms=12.0 if stop else None, join_ms=0.3, total_s=3.0)
    rj = {"status": "ok", "reason": reason, "fail_detail": fail_detail, "range": case["syn"], "start_index": 0,
          "expected_total": case["syn"], "sent": sent, "next_index": sent, "received": len(replies), "discarded": 0, "duplicates": 0,
          "rx_health": {"kernel_drops": 0}, "scan_id": "11" * 16, "attempt_id": "aa" * 16, "resumed_from_attempt": None,
          "replies": replies, "reply_total": len(replies), "reply_unique": len(replies), "checkpoint": False, "checkpoint_hex": None,
          "checkpoint_next_index": None,
          "net": {"tx_sent": sent, "tx_uncertain": 0, "tx_errors": 0, "rx_errors": 0, "kernel_drops": 0, "rx_packets": 5},
          "tx_sent_at_join": sent, "tx_sent_after_observe": sent, "observe_ms": observe, "timing": tm, "wall": wall,
          "workers": {"tx_tid": 101, "rx_tid": 102, "tx_alive_after_join": False, "rx_alive_after_join": False, "settle_ms": 0.1},
          "resources": {"fds_before_open": 110, "fds_open": 141, "fds_after_join": 111}, "job": job_of(case)}
    rj.update(kw)
    return rj


def flood_frames(n, t_first=1000.5, t_last=1005.0):
    f = mac(GUEST) + mac(PEER) + V.FLOOD_ETHERTYPE + b"\0" * 46
    return [(t_first + (t_last - t_first) * i / max(n - 1, 1), f) for i in range(n)]


def build_b(root):
    global LISTEN_SILENT
    LISTEN_SILENT = V.SILENT_PORTS
    try:
        return _build_b(root)
    finally:
        LISTEN_SILENT = [V.SILENT_PORT]


def _build_b(root):
    """A complete passing artifact set of the part B plan."""
    os.makedirs(os.path.join(root, "fixtures"))
    shutil_copy_fixtures(root)
    wj(os.path.join(root, "manifest.json"),
       {"code_commit": COMMIT, "capture_schema": 2, "plan": "failure", "exe": {"sha256": EXE},
        "binding": {"iface": "\\Device\\NPF_{X}", "src_ip": SRC_IP, "src_mac": GUEST, "router_mac": PEER},
        "listeners": {"open": V.LISTEN_OPEN, "silent": V.SILENT_PORTS}})
    kw = lambda **k: k  # noqa: E731

    def run(tag, case, syns, replies, rj, rc=0, files=None, extra=()):
        write_run(root, tag, syns, replies, rj, rc=rc, extra_files=files, extra_peer_frames=extra)

    def sy(case, n):
        return case_syns(case)[:n]
    for sc, (cname, _x) in V.STOP_SCENARIOS.items():
        c = V.case_by_name(cname)
        sent = {"silent": 3, "load": 3, "drain": 2, "fullqueue": 2}[sc]
        reps = case_replies(c, silent_answers=False)[:sent] if sc in ("drain", "fullqueue") else []
        rj = b_rj(c, sent, replies=V.expected_replies(c) if sc in ("drain", "fullqueue") else [])
        if sc == "drain":
            rj["timing"]["total_s"] = 3.2
        if sc == "load":
            rj["net"]["rx_packets"] = 40000
        files, extra = {}, ()
        if sc == "load":
            fl = flood_frames(300)
            extra = fl
            files = {"flood.json": {"sent": 300, "errors": 0, "t_first": fl[0][0], "t_last": fl[-1][0], "pps_avg": 20000.0, "size": 60}}
        run("stop_%s" % sc, c, sy(c, sent), reps, rj, files=files, extra=extra)
    c = V.case_by_name("pb_overflow_queue")
    run("overflow_queue", c, sy(c, 3), [], b_rj(c, 3, reason="Failed", fail_detail="ConsumerTooSlow", stop=False,
                                                 replies=V.expected_replies(c)[:1]), rc=3)
    c = V.case_by_name("pb_linkloss")
    rj = b_rj(c, 40, reason="Failed", fail_detail="TxUncertain", stop=False, observe=500)
    rj["net"]["tx_uncertain"] = 1
    outcome = 1001.0 + 0.01 * 39 + 0.5
    run("linkloss", c, sy(c, 40), [], rj, rc=3, files={"linkloss.json": {"first_syn_seen": True, "events": [
        {"t": outcome - 0.2, "set_link": "down", "reply": {"return": {}}}, {"t": outcome + 1.0, "set_link": "up", "reply": {"return": {}}}]}})
    wj(os.path.join(root, "runs", "linkloss", "meta.json"), dict(json.load(open(os.path.join(root, "runs", "linkloss", "meta.json"))),
                                                               checkpoint_file_exists=False))
    pc = V.case_by_name(V.PAUSE_CASE)
    for v, (ov, want) in V.CKPT_VARIANTS.items():
        c = dict(pc, **ov)
        run("ckpt_%s" % v, c, [], [], {"status": "error", "stage": "resume-preflight", "error": want, "message": "x", "opened_adapter": False,
                                       "tx_sent": 0, "job": job_of(c)}, rc=4)
    c = V.case_by_name("pb_perm_scan")
    ident = {"source_commit": COMMIT, "binary_sha256": EXE, "os": {"family": "windows"}, "elevated": False, "restricted_token": True}
    run("perm_restricted_scan", c, [], [], {"status": "error", "stage": "open", "error": "PermissionDenied", "message": "x",
                                              "opened_adapter": False, "tx_sent": 0, "job": job_of(c), "identity": ident}, rc=5)
    for t in ("perm_restricted_scan",):
        wj(os.path.join(root, "runs", t, "meta.json"), dict(json.load(open(os.path.join(root, "runs", t, "meta.json"))),
                                                          restricted_via="runas /trustlevel:0x20000 (windows_wire_runas.cmd)"))
    run("perm_restricted_inventory", c, [], [], {"status": "ok", "mode": "inventory", "opened_adapter": False, "tx_sent": 0,
                                                   "devices": [{"name": "\\Device\\NPF_Loopback", "loopback": True}],
                                                   "access_hint": "Npcap may be installed in Administrators-only mode", "identity": ident}, rc=5)
    c1 = V.case_by_name("c01_one_addr_port_synack")
    wj(os.path.join(root, "runs", "perm_restricted_inventory", "meta.json"),
       dict(json.load(open(os.path.join(root, "runs", "perm_restricted_inventory", "meta.json"))),
            restricted_via="runas /trustlevel:0x20000 (windows_wire_runas.cmd)"))
    run("perm_elevated_control", c1, case_syns(c1), case_replies(c1, silent_answers=False), full_json(c1, V.expected_replies(c1)))
    c = V.case_by_name("pb_rxloss")
    rj = b_rj(c, 16, reason="Failed", fail_detail="RxLoss { kernel_drops: 420 }", stop=False, observe=500,
              replies=V.expected_replies(c)[:3])
    rj["rx_health"] = {"kernel_drops": 420}
    rj["net"].update(kernel_drops=420, rx_packets=9000)
    fl = flood_frames(500, 1000.2, 1002.0)
    run("rxloss", c, sy(c, 16), [], rj, rc=3, extra=fl, files={
        "flood.json": {"sent": 500, "errors": 0, "t_first": fl[0][0], "t_last": fl[-1][0], "pps_avg": 15000.0, "size": 600},
        "nic.json": {"before": {"stats": {"ReceivedUnicastPackets": 1000}}, "after": {"stats": {"ReceivedUnicastPackets": 10420}}}})
    wj(os.path.join(root, "runs", "rxloss", "meta.json"), dict(json.load(open(os.path.join(root, "runs", "rxloss", "meta.json"))),
                                                             checkpoint_file_exists=False))
    return root


def shutil_copy_fixtures(root):
    src = tempfile.mkdtemp()
    build(src)
    import shutil
    shutil.rmtree(os.path.join(root, "fixtures"))
    shutil.copytree(os.path.join(src, "fixtures"), os.path.join(root, "fixtures"))
    shutil.rmtree(src)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = build(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, *p):
        return os.path.join(self.root, *p)

    def verdict(self):
        return V.verify_dir(self.root)

    def run_verdict(self, tag):
        return [r for r in self.verdict()["runs"] if r["tag"] == tag][0]["verdict"]

    def edit_json(self, rel, fn):
        p = self.path(*rel.split("/"))
        d = json.load(open(p))
        fn(d)
        wj(p, d)

    # ------------------------------------------------------------ positive
    def test_complete_consistent_set_passes(self):
        v = self.verdict()
        bad = [(r["tag"], c) for r in v["runs"] + v["groups"] for c in r["checks"] if c["result"] != "PASS"]
        self.assertEqual(bad, [])
        self.assertEqual(v["overall"], "PASS")
        self.assertGreaterEqual(v["totals"]["PASS"], 24)

    # ------------------------------------------------------------ missing artifacts: NOT RUN
    def test_missing_manifest_is_not_run(self):
        os.unlink(self.path("manifest.json"))
        self.assertEqual(self.verdict()["overall"], "NOT RUN")

    def test_missing_fixture_manifest_is_not_run(self):
        os.unlink(self.path("fixtures", "manifest.json"))
        self.assertEqual(self.verdict()["overall"], "NOT RUN")

    def test_missing_peer_pcap_is_not_run_never_pass(self):
        os.unlink(self.path("runs", "c01_one_addr_port_synack.run1", "peer.pcap"))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "NOT RUN")
        self.assertNotEqual(self.verdict()["overall"], "PASS")

    def test_missing_planned_run_is_not_run(self):
        import shutil
        shutil.rmtree(self.path("runs", "pause_N8"))
        v = self.verdict()
        self.assertEqual([r["verdict"] for r in v["runs"] if r["tag"] == "pause_N8"], ["NOT RUN"])
        self.assertEqual([g["verdict"] for g in v["groups"] if g["tag"].endswith("N8")], ["NOT RUN"])
        self.assertNotEqual(v["overall"], "PASS")

    def test_missing_eno1_pcap_is_not_run(self):
        os.unlink(self.path("runs", "c02_one_addr_port_rst.run1", "eno1.pcap"))
        self.assertEqual(self.run_verdict("c02_one_addr_port_rst.run1"), "NOT RUN")

    def test_missing_status_post_is_not_run(self):
        os.unlink(self.path("runs", "c03_multi_ports.run2", "status-post.json"))
        self.assertEqual(self.run_verdict("c03_multi_ports.run2"), "NOT RUN")

    def test_empty_directory_is_never_pass(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertNotEqual(V.verify_dir(d)["overall"], "PASS")

    # ------------------------------------------------------------ invalid capture: INVALID
    def test_truncated_pcap_is_invalid(self):
        p = self.path("runs", "c01_one_addr_port_synack.run1", "peer.pcap")
        data = open(p, "rb").read()
        bw(p, data[:-7])
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_pcap_edited_after_hashing_is_invalid(self):
        p = self.path("runs", "c01_one_addr_port_synack.run1", "peer.pcap")
        data = bytearray(open(p, "rb").read())
        data[-1] ^= 1
        bw(p, bytes(data))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_tcpdump_drops_are_invalid(self):
        for key in ("dropped_kernel", "dropped_if"):
            with self.subTest(key):
                self.setUp()
                self.edit_json("runs/c04_exclude.run1/capture.json", lambda d, k=key: d["peer"]["tcpdump"].__setitem__(k, 1))
                self.assertEqual(self.run_verdict("c04_exclude.run1"), "INVALID")
                self.tearDown()

    def test_captured_not_equal_received_is_invalid(self):
        self.edit_json("runs/c04_exclude.run1/capture.json", lambda d: d["peer"]["tcpdump"].__setitem__("received", 99))
        self.assertEqual(self.run_verdict("c04_exclude.run1"), "INVALID")

    def test_counter_window_mismatch_is_invalid(self):
        self.edit_json("runs/c05_srcport_single.run1/capture.json", lambda d: d["peer"]["counters"].__setitem__("rx_end", 10_000))
        self.assertEqual(self.run_verdict("c05_srcport_single.run1"), "INVALID")

    def test_no_quiescence_is_invalid(self):
        self.edit_json("runs/c06_srcport_range.run1/capture.json", lambda d: d["quiet"].__setitem__("reached", False))
        self.assertEqual(self.run_verdict("c06_srcport_range.run1"), "INVALID")

    def test_capture_not_proven_live_marker_is_invalid(self):
        d = self.path("runs", "c06_srcport_range.run2")
        # rebuild the pcap without the marker and keep every recorded hash consistent
        import re  # noqa: F401
        _lt, fr = V.vw.read_pcap_records(open(os.path.join(d, "peer.pcap"), "rb").read())
        fr = [(t, f) for t, f in fr if f[12:14] != b"\x88\xb5"]
        data = pcap(fr)
        bw(os.path.join(d, "peer.pcap"), data)

        def fix(c):
            c["peer"]["pcap"] = {"sha256": sha(data), "size": len(data), "frames": len(fr)}
            c["peer"]["tcpdump"] = tcpd(len(fr))
            c["peer"]["counters"]["tx_end"] -= 1
        self.edit_json("runs/c06_srcport_range.run2/capture.json", fix)
        self.assertEqual(self.run_verdict("c06_srcport_range.run2"), "INVALID")

    def test_eno1_lab_frame_is_a_failure(self):
        d = self.path("runs", "c01_one_addr_port_synack.run2")
        data = pcap([(5.0, syn(40000, 80))])
        bw(os.path.join(d, "eno1.pcap"), data)

        def fix(c):
            c["eno1"]["pcap"] = {"sha256": sha(data), "size": len(data), "frames": 1}
            c["eno1"]["tcpdump"] = tcpd(1)
        self.edit_json("runs/c01_one_addr_port_synack.run2/capture.json", fix)
        self.assertNotEqual(self.run_verdict("c01_one_addr_port_synack.run2"), "PASS")

    def test_stand_not_green_is_invalid(self):
        self.edit_json("runs/c01_one_addr_port_synack.run1/status-post.json", lambda d: d.__setitem__("raw_run_allowed", False))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")
        self.edit_json("runs/c02_one_addr_port_rst.run1/status-pre.json", lambda d: d.__setitem__("isolation_violations", ["x"]))
        self.assertEqual(self.run_verdict("c02_one_addr_port_rst.run1"), "INVALID")

    def test_guest_verify_failed_is_invalid(self):
        self.edit_json("runs/c01_one_addr_port_synack.run1/guest-verify.json", lambda d: d.__setitem__("ok", False))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_log_from_another_build_is_invalid(self):
        self.edit_json("runs/c01_one_addr_port_synack.run1/run.json", lambda d: d["identity"].__setitem__("binary_sha256", "0" * 64))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")
        self.edit_json("runs/c02_one_addr_port_rst.run1/run.json", lambda d: d["identity"].__setitem__("source_commit", "unknown"))
        self.assertEqual(self.run_verdict("c02_one_addr_port_rst.run1"), "INVALID")

    def test_capture_stopped_before_guest_finished_is_invalid(self):
        self.edit_json("runs/c01_one_addr_port_synack.run1/meta.json", lambda d: d.__setitem__("capture_stopped_utc", 2.5))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_fixture_for_another_binding_is_invalid_not_normalised(self):
        self.edit_json("fixtures/manifest.json", lambda d: d["binding"].__setitem__("src_mac", "02:aa:00:00:00:01"))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_fixture_hash_mismatch_is_invalid(self):
        p = self.path("fixtures", "c01_one_addr_port_synack.run1.pcap")
        bw(p, open(p, "rb").read() + b"")
        self.edit_json("fixtures/manifest.json", lambda d: d["fixtures"]["c01_one_addr_port_synack.run1"].__setitem__("sha256", "0" * 64))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    # ------------------------------------------------------------ behaviour failures: FAIL
    def test_syn_difference_is_fail(self):
        d = self.path("runs", "c03_multi_ports.run1")
        _lt, fr = V.vw.read_pcap_records(open(os.path.join(d, "peer.pcap"), "rb").read())
        out, done = [], False
        for t, f in fr:
            if vw_is_syn(f) and not done:
                f = bytearray(f)
                f[14 + 20 + 7] ^= 1  # sequence number byte
                f, done = bytes(f), True
            out.append((t, f))
        data = pcap(out)
        bw(os.path.join(d, "peer.pcap"), data)
        self.edit_json("runs/c03_multi_ports.run1/capture.json",
                       lambda c: c["peer"].__setitem__("pcap", {"sha256": sha(data), "size": len(data), "frames": len(out)}))
        self.assertEqual(self.run_verdict("c03_multi_ports.run1"), "FAIL")

    def test_syn_order_difference_is_fail(self):
        d = self.path("runs", "c03_multi_ports.run2")
        _lt, fr = V.vw.read_pcap_records(open(os.path.join(d, "peer.pcap"), "rb").read())
        idx = [i for i, (_t, f) in enumerate(fr) if vw_is_syn(f)]
        fr[idx[0]], fr[idx[1]] = (fr[idx[0]][0], fr[idx[1]][1]), (fr[idx[1]][0], fr[idx[0]][1])
        data = pcap(fr)
        bw(os.path.join(d, "peer.pcap"), data)
        self.edit_json("runs/c03_multi_ports.run2/capture.json",
                       lambda c: c["peer"].__setitem__("pcap", {"sha256": sha(data), "size": len(data), "frames": len(fr)}))
        self.assertEqual(self.run_verdict("c03_multi_ports.run2"), "FAIL")

    def test_wrong_results_are_fail(self):
        self.edit_json("runs/c01_one_addr_port_synack.run1/run.json",
                       lambda d: d.update(replies=["198.18.0.2:80:closed"]))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "FAIL")

    def test_null_or_nonzero_rx_health_is_fail(self):
        for val in (None, 3):
            with self.subTest(val):
                self.setUp()
                self.edit_json("runs/c01_one_addr_port_synack.run1/run.json", lambda d, v=val: d["rx_health"].__setitem__("kernel_drops", v))
                self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "FAIL")
                self.tearDown()

    def test_outcome_other_than_completed_is_fail(self):
        self.edit_json("runs/c01_one_addr_port_synack.run1/run.json", lambda d: d.update(reason="Failed"))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "FAIL")

    def test_job_echo_must_match_the_case(self):
        self.edit_json("runs/c05_srcport_single.run1/run.json", lambda d: d["job"].__setitem__("source_port", "40000"))
        self.assertNotEqual(self.run_verdict("c05_srcport_single.run1"), "PASS")

    def test_foreign_reply_accepted_as_result_is_fail(self):
        tag = "x01_foreign_replies.run1"
        self.edit_json("runs/%s/run.json" % tag, lambda d: d.update(replies=sorted(d["replies"] + ["198.18.0.2:%d:open" % V.SILENT_PORT])))
        self.assertEqual(self.run_verdict(tag), "FAIL")

    def test_foreign_frames_missing_from_wire_is_invalid(self):
        tag = "x01_foreign_replies.run2"
        self.edit_json("runs/%s/injector.json" % tag, lambda d: d.__setitem__("sent_total", 9))
        self.assertEqual(self.run_verdict(tag), "INVALID")

    def test_foreign_run_without_injector_is_not_run(self):
        os.unlink(self.path("runs", "x01_foreign_replies.run1", "injector.json"))
        self.assertEqual(self.run_verdict("x01_foreign_replies.run1"), "NOT RUN")

    # ------------------------------------------------------------ pause / resume
    def groups(self):
        return {g["tag"]: g["verdict"] for g in self.verdict()["groups"]}

    def test_pause_resume_groups_pass(self):
        self.assertEqual(set(self.groups().values()), {"PASS"})
        self.assertEqual(len(self.groups()), 4)

    def test_resume_that_repeats_a_probe_is_fail(self):
        d = self.path("runs", "resume_N8")
        _lt, fr = V.vw.read_pcap_records(open(os.path.join(d, "peer.pcap"), "rb").read())
        extra = [(t, f) for t, f in fr if vw_is_syn(f)][:1]
        data = pcap(sorted(fr + [(9999.0, extra[0][1])], key=lambda x: x[0]))
        bw(os.path.join(d, "peer.pcap"), data)
        n = len(fr) + 1
        self.edit_json("runs/resume_N8/capture.json", lambda c: (c["peer"].__setitem__("pcap", {"sha256": sha(data), "size": len(data), "frames": n}),
                                                                c["peer"].__setitem__("tcpdump", tcpd(n)),
                                                                c["peer"]["counters"].__setitem__("rx_end", c["peer"]["counters"]["rx_end"] + 1)))
        self.assertNotEqual(self.groups()["group_pause_resume_N8"], "PASS")

    def test_same_attempt_id_is_fail(self):
        self.edit_json("runs/resume_N1/run.json", lambda d: d.update(attempt_id="aa" * 16))
        self.assertEqual(self.groups()["group_pause_resume_N1"], "FAIL")

    def test_changed_scan_id_is_fail(self):
        self.edit_json("runs/resume_N1/run.json", lambda d: d.update(scan_id="22" * 16))
        self.assertEqual(self.groups()["group_pause_resume_N1"], "FAIL")

    def test_pause_leg_that_did_not_pause_is_fail(self):
        self.edit_json("runs/pause_N15/run.json", lambda d: d.update(reason="Completed"))
        self.assertEqual(self.run_verdict("pause_N15"), "FAIL")
        self.assertNotEqual(self.groups()["group_pause_resume_N15"], "PASS")

    def test_completed_job_that_was_resumed_is_fail(self):
        self.edit_json("runs/refuse_completed/run.json", lambda d: d.update(status="ok", opened_adapter=True))
        self.assertEqual(self.run_verdict("refuse_completed"), "FAIL")

    def test_refusal_with_a_syn_on_the_wire_is_fail(self):
        d = self.path("runs", "refuse_completed")
        data = pcap([(1000.0, marker()), (1001.0, syn(40000, 8000))] + [(1003.0 + i * 0.05, marker(V.END_PAYLOAD)) for i in range(3)])
        bw(os.path.join(d, "peer.pcap"), data)
        self.edit_json("runs/refuse_completed/capture.json", lambda c: (c["peer"].__setitem__("pcap", {"sha256": sha(data), "size": len(data), "frames": 5}),
                                                                       c["peer"].__setitem__("tcpdump", tcpd(5)),
                                                                       c["peer"]["counters"].update(rx_end=c["peer"]["counters"]["rx_before"] + 1,
                                                                                                    tx_end=c["peer"]["counters"]["tx_before"] + 4)))
        self.assertEqual(self.run_verdict("refuse_completed"), "FAIL")

    # ------------------------------------------------------------ M1: capture tail
    def rewrite_peer(self, tag, mut):
        d = self.path("runs", tag)
        _lt, fr = V.vw.read_pcap_records(open(os.path.join(d, "peer.pcap"), "rb").read())
        fr = mut(fr)
        data = pcap(fr)
        bw(os.path.join(d, "peer.pcap"), data)
        n_tx = sum(1 for _t, f in fr if f[6:12] == mac(PEER) or f[12:14] == b"\x88\xb5")

        def fix(c):
            c["peer"]["pcap"] = {"sha256": sha(data), "size": len(data), "frames": len(fr)}
            c["peer"]["tcpdump"] = tcpd(len(fr))
            c["peer"]["counters"].update(rx_end=10 + len(fr) - n_tx, tx_end=20 + n_tx)
        self.edit_json("runs/%s/capture.json" % tag, fix)

    def test_missing_end_marker_is_invalid(self):
        self.rewrite_peer("c01_one_addr_port_synack.run1", lambda fr: [x for x in fr if x[1][14:25] != V.END_PAYLOAD])
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_frame_after_the_end_marker_is_invalid(self):
        self.rewrite_peer("c01_one_addr_port_synack.run1", lambda fr: fr + [(max(t for t, _f in fr) + 1, reply(40000, 80))])
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_capture_without_immediate_mode_is_invalid(self):
        self.edit_json("runs/c02_one_addr_port_rst.run1/capture.json", lambda d: d["eno1"].__setitem__("cmd", ["tcpdump"]))
        self.assertEqual(self.run_verdict("c02_one_addr_port_rst.run1"), "INVALID")

    def test_older_schema_directory_and_run_do_not_require_the_end_marker(self):
        self.edit_json("manifest.json", lambda d: d.pop("capture_schema"))
        self.edit_json("runs/c01_one_addr_port_synack.run1/capture.json", lambda d: d.pop("capture_schema"))
        self.rewrite_peer("c01_one_addr_port_synack.run1", lambda fr: [x for x in fr if x[1][14:25] != V.END_PAYLOAD])
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "PASS")

    def test_schema2_run_in_a_schema1_directory_cannot_skip_the_end_marker(self):
        # reviewer's attack: drop the END markers and delete capture_schema from the directory manifest
        self.edit_json("manifest.json", lambda d: d.pop("capture_schema"))
        self.rewrite_peer("c01_one_addr_port_synack.run1", lambda fr: [x for x in fr if x[1][14:25] != V.END_PAYLOAD])
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "INVALID")

    def test_run_older_than_its_directory_is_invalid(self):
        self.edit_json("runs/c02_one_addr_port_rst.run1/capture.json", lambda d: d.pop("capture_schema"))
        self.assertEqual(self.run_verdict("c02_one_addr_port_rst.run1"), "INVALID")

    # ------------------------------------------------------------ I1b: behaviour FAIL beats INVALID
    def truncate_peer(self, base, tag):
        p = self.path(base, tag, "peer.pcap")
        bw(p, open(p, "rb").read()[:-7])

    def test_invalid_run_with_failed_outcome_is_overall_fail(self):
        t = "c03_multi_ports.run1"
        self.truncate_peer("runs", t)
        self.edit_json("runs/%s/run.json" % t, lambda d: d.update(reason="Failed"))
        v = self.verdict()
        self.assertEqual([r["verdict"] for r in v["runs"] if r["tag"] == t], ["INVALID"])
        self.assertEqual(v["overall"], "FAIL")
        self.assertIn(t, v["behaviour_fail"])
        self.assertEqual(V.run_status(self.root, t), ("INVALID", True))
        self.assertFalse(S.may_discard(*S.rerun_verdict(self.root, t)))

    def test_discarded_invalid_run_with_accepted_foreign_result_is_overall_fail(self):
        t = "x01_foreign_replies.run1"
        self.edit_json("runs/%s/capture.json" % t, lambda d: d["quiet"].__setitem__("reached", False))
        self.edit_json("runs/%s/run.json" % t, lambda d: d.update(replies=sorted(d["replies"] + ["198.18.0.2:8099:open"])))
        self.discard(t)
        c = V.FOREIGN_CASE
        write_run(self.path(), t, case_syns(c), case_replies(c, silent_answers=False), full_json(c, V.expected_replies(c), discarded=4),
                  extra_files={"injector.json": {"sent_total": 4, "kinds": {"other_ip": 1, "unscanned_port": 1, "wrong_cookie": 1,
                                                                            "wrong_dst_port": 1}}})
        v = self.verdict()
        self.assertEqual(v["discarded"][0]["verdict"], "INVALID")
        self.assertTrue(v["discarded"][0]["behaviour_fail"])
        self.assertEqual(v["overall"], "FAIL")

    def test_may_discard_needs_invalid_and_no_behaviour_failure(self):
        self.assertTrue(S.may_discard("INVALID", False))
        self.assertFalse(S.may_discard("INVALID", True))
        self.assertFalse(S.may_discard("NOT RUN", True))

    # ------------------------------------------------------------ NB1-NB3
    def test_missing_continuous_pcap_is_not_run_not_a_crash(self):
        os.unlink(self.path("runs", "c03_multi_ports.run1", "peer.pcap"))
        v = self.verdict()  # must not raise
        self.assertEqual({g["verdict"] for g in v["groups"]}, {"NOT RUN"})
        self.assertNotEqual(v["overall"], "PASS")

    def test_missing_leg_pcap_makes_its_group_not_run(self):
        os.unlink(self.path("runs", "pause_N8", "peer.pcap"))
        g = {x["tag"]: x["verdict"] for x in self.verdict()["groups"]}
        self.assertEqual(g["group_pause_resume_N8"], "NOT RUN")

    def test_stray_upper_bound_is_invalid_not_fail_when_the_capture_is_incomplete(self):
        t = "x01_foreign_replies.run1"
        self.edit_json("runs/%s/run.json" % t, lambda d: d.update(discarded=6))  # 2 unexplained discards, no stray in the pcap
        self.edit_json("runs/%s/capture.json" % t, lambda d: d["quiet"].__setitem__("reached", False))
        r = [x for x in self.verdict()["runs"] if x["tag"] == t][0]
        self.assertEqual(r["verdict"], "INVALID")
        self.assertFalse(r["behaviour_fail"])
        self.assertEqual(S.rerun_verdict(self.root, t), ("INVALID", False))

    def test_r3_1_discards_below_injected_plus_seen_strays_fail_even_with_a_bad_capture(self):
        # a stray is visible in the pcap, discarded == injected (a foreign duplicate was absorbed), capture incomplete
        t = "x01_foreign_replies.run1"
        self.add_stray(t, 0.5)
        self.edit_json("runs/%s/capture.json" % t, lambda d: d["quiet"].__setitem__("reached", False))
        r = [x for x in self.verdict()["runs"] if x["tag"] == t][0]
        self.assertTrue(r["behaviour_fail"])
        self.assertEqual(self.verdict()["overall"], "FAIL")
        self.assertFalse(S.may_discard(*S.rerun_verdict(self.root, t)))

    def test_nb3b_consistently_wrong_argv_and_run_is_invalid_and_rerunnable(self):
        # harness bug: argv.json asks for ports 80,81 and the run, its echo and its results agree with that wrong job
        t = "c05_srcport_single.run1"
        self.edit_json("runs/%s/argv.json" % t, lambda d: d["argv"].__setitem__(d["argv"].index("--ports") + 1, "80,81"))

        def wrong(d):
            d["job"]["ports"] = "80,81"
            d.update(sent=2, next_index=2, range=2, expected_total=2, replies=["198.18.0.2:80:open", "198.18.0.2:81:closed"],
                     reply_total=2, reply_unique=2)
            d["net"]["tx_sent"] = 2
        self.edit_json("runs/%s/run.json" % t, wrong)
        v, bf = S.rerun_verdict(self.root, t)
        self.assertEqual((v, bf), ("INVALID", False))
        self.assertTrue(S.may_discard(v, bf))
        self.assertNotEqual(self.verdict()["overall"], "FAIL")

    def test_every_part_a_kind_has_an_argument_definition_with_its_extra_flags(self):
        man = {"binding": {"iface": "i"}}
        self.assertEqual(V.KIND_ARGV["pause"](ITEMS["pause_N8"])[1]["--pause-after"], "8")
        self.assertEqual(V.KIND_ARGV["complete_nopause"](ITEMS["complete_nopause"])[1]["--pause-after"], "16")
        self.assertIn("refuse_completed", V.KIND_SIDE_ARGV)
        for it in V.planned(None):
            self.assertIn(it["kind"], V.KIND_ARGV, man)

    def test_pause_after_argument_must_match_n(self):
        self.edit_json("runs/pause_N8/argv.json", lambda d: d["argv"].__setitem__(d["argv"].index("--pause-after") + 1, "7"))
        self.assertEqual(V.run_status(self.root, "pause_N8"), ("INVALID", False))

    def test_broadcast_frame_in_the_window_is_a_stray(self):
        t = "x01_foreign_replies.run1"
        bc = b"\xff" * 6 + mac(PEER) + b"\x08\x06" + b"\x00" * 28
        self.rewrite_peer(t, lambda fr: sorted(fr + [(min(tt for tt, f in fr if V.vw.is_syn(f)) + 0.5, bc)], key=lambda x: x[0]))
        self.assertEqual(self.run_verdict(t), "FAIL")
        self.edit_json("runs/%s/run.json" % t, lambda d: d.update(discarded=5))
        self.assertEqual(self.run_verdict(t), "PASS")

    def test_frame_from_the_guest_is_never_a_stray(self):
        t = "x01_foreign_replies.run1"
        out = b"\xff" * 6 + mac(GUEST) + b"\x08\x06" + b"\x00" * 28
        self.rewrite_peer(t, lambda fr: sorted(fr + [(min(tt for tt, f in fr if V.vw.is_syn(f)) + 0.5, out)], key=lambda x: x[0]))
        self.assertEqual(self.run_verdict(t), "PASS")

    def test_job_echo_mismatch_with_correct_argv_is_fail_but_wrong_argv_is_invalid(self):
        self.edit_json("runs/c05_srcport_single.run1/run.json", lambda d: d["job"].__setitem__("source_port", "40000"))
        self.assertEqual(V.run_status(self.root, "c05_srcport_single.run1"), ("FAIL", True))
        self.edit_json("runs/c05_srcport_single.run2/argv.json", lambda d: d["argv"].__setitem__(d["argv"].index("--source-port") + 1, "40000"))
        self.edit_json("runs/c05_srcport_single.run2/run.json", lambda d: d["job"].__setitem__("source_port", "40000"))
        self.assertEqual(V.run_status(self.root, "c05_srcport_single.run2"), ("INVALID", False))
        self.assertTrue(S.may_discard(*S.rerun_verdict(self.root, "c05_srcport_single.run2")))

    def test_missing_argv_json_is_not_run(self):
        os.unlink(self.path("runs", "c01_one_addr_port_synack.run1", "argv.json"))
        self.assertEqual(self.run_verdict("c01_one_addr_port_synack.run1"), "NOT RUN")

    # ------------------------------------------------------------ M3b: strays
    def add_stray(self, tag, t_off):
        arp = mac(GUEST) + mac(PEER) + b"\x08\x06" + b"\x00" * 28
        self.rewrite_peer(tag, lambda fr: sorted(fr + [(min(t for t, f in fr if V.vw.is_syn(f)) + t_off, arp)], key=lambda x: x[0]))

    def test_stray_frame_in_rx_window_is_counted_and_required(self):
        t = "x01_foreign_replies.run1"
        self.add_stray(t, 0.5)
        self.assertEqual(self.run_verdict(t), "FAIL")  # discarded is still 4, now 5 expected
        self.edit_json("runs/%s/run.json" % t, lambda d: d.update(discarded=5))
        v = self.verdict()
        r = [x for x in v["runs"] if x["tag"] == t][0]
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["notes"]["strays_in_rx_window"], 1)

    def test_stray_after_the_rx_window_is_not_counted(self):
        t = "x01_foreign_replies.run1"
        self.add_stray(t, -0.5)
        self.assertEqual(self.run_verdict(t), "PASS")


    # ------------------------------------------------------------ M3: discarded == injected
    def test_foreign_frames_not_all_discarded_is_fail(self):
        for val in (3, 5, None):
            with self.subTest(val):
                self.setUp()
                self.edit_json("runs/x01_foreign_replies.run1/run.json", lambda d, v=val: d.__setitem__("discarded", v))
                self.assertEqual(self.run_verdict("x01_foreign_replies.run1"), "FAIL")
                self.tearDown()

    def test_duplicates_beyond_genuine_retransmits_is_fail(self):
        self.edit_json("runs/x01_foreign_replies.run2/run.json", lambda d: d.__setitem__("duplicates", 9))
        self.assertEqual(self.run_verdict("x01_foreign_replies.run2"), "FAIL")

    # ------------------------------------------------------------ I1: runs_discarded
    def discard(self, tag, stamp="1"):
        os.makedirs(self.path("runs_discarded"), exist_ok=True)
        os.rename(self.path("runs", tag), self.path("runs_discarded", "%s.%s" % (tag, stamp)))

    def test_discarded_fail_run_makes_overall_fail_and_is_listed(self):
        t = "c03_multi_ports.run1"
        self.edit_json("runs/%s/run.json" % t, lambda d: d.update(reason="Failed"))
        self.discard(t)
        # a clean replacement under runs/
        write_run(self.path(), t, case_syns(V.case_by_name("c03_multi_ports")), case_replies(V.case_by_name("c03_multi_ports")),
                  full_json(V.case_by_name("c03_multi_ports"), V.expected_replies(V.case_by_name("c03_multi_ports"))))
        v = self.verdict()
        self.assertEqual(v["overall"], "FAIL")
        self.assertEqual([(r["tag"], r["verdict"]) for r in v["discarded"]], [(t + ".1", "FAIL")])
        self.assertEqual(v["discarded_totals"]["FAIL"], 1)

    def test_discarded_invalid_run_is_listed_but_allowed(self):
        t = "c03_multi_ports.run1"
        self.edit_json("runs/%s/capture.json" % t, lambda d: d["quiet"].__setitem__("reached", False))
        self.discard(t)
        c = V.case_by_name("c03_multi_ports")
        write_run(self.path(), t, case_syns(c), case_replies(c), full_json(c, V.expected_replies(c)))
        v = self.verdict()
        self.assertEqual(v["overall"], "PASS")
        self.assertEqual([r["verdict"] for r in v["discarded"]], ["INVALID"])

    def test_discarded_pass_run_is_not_allowed(self):
        t = "c03_multi_ports.run1"
        self.discard(t)
        c = V.case_by_name("c03_multi_ports")
        write_run(self.path(), t, case_syns(c), case_replies(c), full_json(c, V.expected_replies(c)))
        self.assertEqual(self.verdict()["overall"], "INVALID")

    def test_unknown_discarded_directory_is_fail(self):
        os.makedirs(self.path("runs_discarded", "nonsense.5"))
        self.assertEqual(self.verdict()["overall"], "FAIL")

    def test_rerun_policy_only_invalid_or_incomplete_may_be_discarded(self):
        self.assertTrue(S.may_discard("INVALID"))
        self.assertTrue(S.may_discard("NOT RUN"))
        self.assertFalse(S.may_discard("FAIL"))
        self.assertFalse(S.may_discard("PASS"))
        self.edit_json("runs/c01_one_addr_port_synack.run1/run.json", lambda d: d.update(reason="Failed"))
        self.assertFalse(S.may_discard(*S.rerun_verdict(self.root, "c01_one_addr_port_synack.run1")))
        self.assertFalse(S.may_discard(*S.rerun_verdict(self.root, "c02_one_addr_port_rst.run1")))  # PASS

    def test_cases_psv_lists_six_classes_plus_the_foreign_case(self):
        lines = V.cases_psv().strip().splitlines()
        self.assertEqual(len(lines), 7)
        self.assertEqual(len(V.CASES), 6)
        self.assertTrue(all(len(l.split("|")) == 5 for l in lines))


class PartBTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = build_b(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    path = VerifierTests.path
    edit_json = VerifierTests.edit_json
    rewrite_peer = VerifierTests.rewrite_peer
    verdict = VerifierTests.verdict
    run_verdict = VerifierTests.run_verdict

    def status(self, tag):
        return V.run_status(self.root, tag)

    def edit_run(self, tag, fn):
        self.edit_json("runs/%s/run.json" % tag, fn)

    def test_complete_part_b_set_passes(self):
        v = self.verdict()
        self.assertEqual([(r["tag"], c["name"]) for r in v["runs"] for c in r["checks"] if c["result"] != "PASS"], [])
        self.assertEqual(v["overall"], "PASS")
        self.assertEqual(len(v["runs"]), 1 + 18)

    def test_every_planned_part_b_kind_has_an_argument_definition(self):
        for it in V.planned_b():
            self.assertTrue(it["kind"] in V.KIND_ARGV or it["kind"] in V.KIND_ARGV_B, it)

    def test_missing_part_b_run_is_not_run(self):
        import shutil
        shutil.rmtree(self.path("runs", "linkloss"))
        self.assertEqual(self.run_verdict("linkloss"), "NOT RUN")
        self.assertNotEqual(self.verdict()["overall"], "PASS")

    # ---- stop
    def test_stop_latency_over_a_second_is_fail(self):
        self.edit_run("stop_silent", lambda d: d["timing"].__setitem__("stop_to_outcome_ms", 1200.0))
        self.assertEqual(self.status("stop_silent"), ("FAIL", True))

    def test_stop_without_a_measured_latency_is_fail(self):
        self.edit_run("stop_drain", lambda d: d["timing"].__setitem__("stop_to_outcome_ms", None))
        self.assertEqual(self.status("stop_drain"), ("FAIL", True))

    def test_stop_with_a_checkpoint_or_another_outcome_is_fail(self):
        self.edit_run("stop_silent", lambda d: d.update(checkpoint=True))
        self.assertEqual(self.status("stop_silent"), ("FAIL", True))
        self.edit_run("stop_drain", lambda d: d.update(reason="Completed"))
        self.assertEqual(self.status("stop_drain"), ("FAIL", True))

    def test_engine_worker_alive_after_join_is_fail(self):
        self.edit_run("stop_fullqueue", lambda d: d["workers"].__setitem__("rx_alive_after_join", True))
        self.assertEqual(self.status("stop_fullqueue"), ("FAIL", True))

    def test_unidentified_workers_are_fail_not_pass(self):
        self.edit_run("stop_silent", lambda d: d["workers"].__setitem__("tx_tid", None))
        self.assertEqual(self.status("stop_silent"), ("FAIL", True))

    def test_total_process_threads_are_not_used(self):
        # total thread counts differ before/after (Windows system workers) and that must not matter
        self.edit_run("stop_silent", lambda d: d["resources"].update(threads_before=4, threads_after_join=9))
        self.assertEqual(self.status("stop_silent"), ("PASS", False))

    def test_leaked_adapter_handles_are_fail(self):
        self.edit_run("stop_silent", lambda d: d["resources"].__setitem__("fds_after_join", 141))
        self.assertEqual(self.status("stop_silent"), ("FAIL", True))

    def test_syn_after_the_terminal_outcome_is_fail(self):
        # outcome = last SYN + 0.5 s; add one more scanner SYN 0.3 s after the outcome
        t = "stop_silent"
        c = V.case_by_name("pb_stop_silent")
        late = 1001.0 + 0.01 * 2 + 0.5 + 0.3
        self.rewrite_peer(t, lambda fr: fr + [(late, case_syns(c)[3])])
        self.edit_run(t, lambda d: d["net"].update(tx_sent=4) or d.update(sent=4, next_index=4, tx_sent_at_join=4, tx_sent_after_observe=4))
        self.assertEqual(self.status(t), ("FAIL", True))

    def test_wire_syn_count_must_equal_tx_sent(self):
        t = "stop_silent"
        self.edit_run(t, lambda d: d["net"].__setitem__("tx_sent", 5) or d.update(sent=5, tx_sent_at_join=5, tx_sent_after_observe=5))
        self.assertEqual(self.status(t)[0], "FAIL")

    def test_syn_after_outcome_with_a_lossy_capture_is_invalid_not_fail(self):
        t = "stop_silent"
        c = V.case_by_name("pb_stop_silent")
        self.rewrite_peer(t, lambda fr: fr + [(1001.0 + 0.02 + 0.8, case_syns(c)[3])])
        self.edit_run(t, lambda d: d["net"].update(tx_sent=4) or d.update(sent=4, next_index=4, tx_sent_at_join=4, tx_sent_after_observe=4))
        self.edit_json("runs/%s/capture.json" % t, lambda d: d["quiet"].__setitem__("reached", False))
        self.assertEqual(self.status(t), ("INVALID", False))

    def test_clock_offset_is_recorded_from_the_wire(self):
        r = [x for x in self.verdict()["runs"] if x["tag"] == "stop_silent"][0]
        self.assertAlmostEqual(r["notes"]["clock_offset_ms"], 50000.0, delta=5)
        self.assertEqual(r["notes"]["syn_after_outcome"], 0)
        self.assertIn("alignment", r["notes"])

    def test_stop_silent_with_replies_is_fail(self):
        self.edit_run("stop_silent", lambda d: d.update(reply_total=1, replies=["198.18.0.2:80:open"]))
        self.assertEqual(self.status("stop_silent"), ("FAIL", True))

    def test_stop_drain_that_waited_the_full_wait_is_fail(self):
        self.edit_run("stop_drain", lambda d: d["timing"].__setitem__("total_s", 10.5))
        self.assertEqual(self.status("stop_drain"), ("FAIL", True))

    def test_stop_load_needs_the_flood_on_the_wire(self):
        os.unlink(self.path("runs", "stop_load", "flood.json"))
        self.assertEqual(self.run_verdict("stop_load"), "NOT RUN")
        self.edit_json("runs/stop_load/capture.json", lambda d: None)

    def test_stop_load_flood_count_must_match_the_pcap(self):
        self.edit_json("runs/stop_load/flood.json", lambda d: d.__setitem__("sent", 301))
        self.assertEqual(self.status("stop_load")[0], "INVALID")

    def test_stop_load_flood_must_overlap_the_scan(self):
        self.edit_json("runs/stop_load/flood.json", lambda d: d.__setitem__("t_last", 1001.1))
        self.assertEqual(self.status("stop_load")[0], "INVALID")

    # ---- queue overflow
    def test_queue_overflow_must_be_consumer_too_slow(self):
        self.edit_run("overflow_queue", lambda d: d.update(fail_detail="RxLoss { kernel_drops: 3 }"))
        self.assertEqual(self.status("overflow_queue"), ("FAIL", True))

    # ---- link loss
    def test_linkloss_must_end_in_failed_tx_uncertain_without_checkpoint(self):
        self.edit_run("linkloss", lambda d: d.update(fail_detail="TxError"))
        self.assertEqual(self.status("linkloss"), ("FAIL", True))

    def test_linkloss_checkpoint_file_is_fail(self):
        self.edit_json("runs/linkloss/meta.json", lambda d: d.__setitem__("checkpoint_file_exists", True))
        self.assertEqual(self.status("linkloss"), ("FAIL", True))

    def test_linkloss_without_link_events_is_not_run_and_without_proof_is_invalid(self):
        os.unlink(self.path("runs", "linkloss", "linkloss.json"))
        self.assertEqual(self.run_verdict("linkloss"), "NOT RUN")

    def test_linkloss_set_link_that_the_stand_rejected_is_invalid(self):
        def bad(d):
            d["events"][0]["reply"] = {"error": {"desc": "x"}}
        self.edit_json("runs/linkloss/linkloss.json", bad)
        self.assertEqual(self.status("linkloss")[0], "INVALID")

    def test_linkloss_failure_long_after_the_disconnect_is_invalid(self):
        def late(d):
            d["events"][0]["t"] -= 10
        self.edit_json("runs/linkloss/linkloss.json", late)
        self.assertEqual(self.status("linkloss")[0], "INVALID")

    # ---- checkpoint refusals
    def test_every_checkpoint_variant_is_refused_before_the_adapter_opens(self):
        for v in V.CKPT_VARIANTS:
            self.assertEqual(self.status("ckpt_" + v), ("PASS", False), v)

    def test_checkpoint_refusal_that_opened_the_adapter_is_fail(self):
        self.edit_run("ckpt_truncated", lambda d: d.update(opened_adapter=True))
        self.assertEqual(self.status("ckpt_truncated"), ("FAIL", True))

    def test_checkpoint_refusal_with_the_wrong_reason_is_fail(self):
        self.edit_run("ckpt_wrong_seed", lambda d: d.update(error="BadChecksum"))
        self.assertEqual(self.status("ckpt_wrong_seed"), ("FAIL", True))

    def test_checkpoint_refusal_with_a_syn_on_the_wire_is_fail(self):
        c = V.case_by_name(V.PAUSE_CASE)
        self.rewrite_peer("ckpt_empty", lambda fr: fr + [(1001.0, case_syns(c)[0])])
        self.assertEqual(self.status("ckpt_empty"), ("FAIL", True))

    def test_checkpoint_wrong_ports_variant_needs_matching_argv(self):
        self.edit_json("runs/ckpt_wrong_ports/argv.json", lambda d: d["argv"].__setitem__(d["argv"].index("--ports") + 1, "8000-8015"))
        self.assertEqual(self.status("ckpt_wrong_ports"), ("INVALID", False))

    # ---- permissions
    def test_restricted_run_must_have_been_started_through_runas(self):
        self.edit_json("runs/perm_restricted_scan/meta.json", lambda d: d.pop("restricted_via"))
        self.assertEqual(self.status("perm_restricted_scan")[0], "INVALID")

    def test_restricted_scan_refusals_accepted_are_only_the_documented_ones(self):
        self.edit_run("perm_restricted_scan", lambda d: d.update(error="InterfaceMismatch(\"no Npcap device\")"))
        self.assertEqual(self.status("perm_restricted_scan"), ("FAIL", True))  # rc is still 5, not 2
        self.setUp()
        self.edit_json("runs/perm_restricted_scan/meta.json", lambda d: d.__setitem__("guest_exit", 2))
        self.edit_run("perm_restricted_scan", lambda d: d.update(error="InterfaceMismatch(\"no Npcap device\")"))
        self.assertEqual(self.status("perm_restricted_scan"), ("PASS", False))

    def test_restricted_scan_that_ran_is_fail(self):
        self.edit_run("perm_restricted_scan", lambda d: d.update(tx_sent=1, opened_adapter=True))
        self.assertEqual(self.status("perm_restricted_scan"), ("FAIL", True))

    def test_restricted_inventory_must_hide_the_adapters(self):
        self.edit_run("perm_restricted_inventory", lambda d: d["devices"].append({"name": "NPF_X", "loopback": False}))
        self.assertEqual(self.status("perm_restricted_inventory"), ("FAIL", True))

    # ---- RX overflow
    def test_rx_overflow_not_reproduced_is_not_run_never_pass(self):
        def none(d):
            d.update(reason="Completed", fail_detail="", rx_health={"kernel_drops": 0})
        self.edit_run("rxloss", none)
        self.assertEqual(self.run_verdict("rxloss"), "NOT RUN")
        self.assertNotEqual(self.verdict()["overall"], "PASS")

    def test_rx_overflow_unknown_health_is_not_run(self):
        self.edit_run("rxloss", lambda d: d.update(rx_health={"kernel_drops": None}))
        self.assertEqual(self.run_verdict("rxloss"), "NOT RUN")

    def test_rxloss_count_in_the_outcome_must_equal_the_measured_drops(self):
        self.edit_run("rxloss", lambda d: d.update(fail_detail="RxLoss { kernel_drops: 7 }"))
        self.assertEqual(self.status("rxloss"), ("FAIL", True))

    def test_rxloss_with_a_checkpoint_is_fail(self):
        self.edit_json("runs/rxloss/meta.json", lambda d: d.__setitem__("checkpoint_file_exists", True))
        self.assertEqual(self.status("rxloss"), ("FAIL", True))
        self.setUp()
        self.edit_run("rxloss", lambda d: d.update(checkpoint=True))
        self.assertEqual(self.status("rxloss"), ("FAIL", True))

    def test_rxloss_records_the_independent_count(self):
        r = [x for x in self.verdict()["runs"] if x["tag"] == "rxloss"][0]
        ind = r["notes"]["independent_count"]
        self.assertEqual((ind["kernel_drops_n"], ind["nic_rx_delta"], ind["rx_read_by_handle"], ind["nic_minus_read"]),
                         (420, 9420, 9000, 420))

    def test_rxloss_drops_beyond_the_nic_count_are_fail(self):
        self.edit_json("runs/rxloss/nic.json", lambda d: d["after"]["stats"].__setitem__("ReceivedUnicastPackets", 1100))
        self.assertEqual(self.status("rxloss"), ("FAIL", True))

    def test_rxloss_drops_beyond_the_peer_flood_are_fail(self):
        self.edit_json("runs/rxloss/flood.json", lambda d: d.__setitem__("sent", 100))
        self.assertNotEqual(self.status("rxloss")[0], "PASS")

    def test_rxloss_unreadable_nic_counters_are_not_run(self):
        self.edit_json("runs/rxloss/nic.json", lambda d: d.update(before={"error": "Access denied"}, after={"error": "Access denied"}))
        self.assertEqual(self.status("rxloss")[0], "NOT RUN")

    def test_rxloss_without_independent_inputs_is_not_run(self):
        os.unlink(self.path("runs", "rxloss", "nic.json"))
        self.assertEqual(self.run_verdict("rxloss"), "NOT RUN")

    # ---- argv gate for part B
    def test_wrong_stop_argument_is_a_harness_error(self):
        self.edit_json("runs/stop_silent/argv.json", lambda d: d["argv"].__setitem__(d["argv"].index("--stop-after-ms") + 1, "2000"))
        self.edit_run("stop_silent", lambda d: d["timing"].__setitem__("stop_to_outcome_ms", 5000.0))
        self.assertEqual(self.status("stop_silent"), ("INVALID", False))
        self.assertTrue(S.may_discard(*S.rerun_verdict(self.root, "stop_silent")))

    def test_unexpected_extra_flag_is_a_harness_error(self):
        self.edit_json("runs/rxloss/argv.json", lambda d: d["argv"].append("--allow-foreign-source-mac"))
        self.assertEqual(self.status("rxloss")[0], "INVALID")

    def test_plan_is_taken_from_the_manifest(self):
        self.assertEqual(len(V.planned({"plan": "failure"})), 18)
        self.assertEqual(len(V.planned({})), 24)


def vw_is_syn(f):
    return V.vw.is_syn(f)


class OrchestratorPureTests(unittest.TestCase):
    def test_tcpdump_stats_parser(self):
        err = "tcpdump: listening on lab0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n" \
              "57 packets captured\n57 packets received by filter\n0 packets dropped by kernel\n"
        self.assertEqual(S.parse_tcpdump(err), {"listening": True, "captured": 57, "received": 57, "dropped_kernel": 0, "dropped_if": 0})
        err2 = err + "1 packet dropped by interface\n"
        self.assertEqual(S.parse_tcpdump(err2)["dropped_if"], 1)
        self.assertIsNone(S.parse_tcpdump("garbage")["captured"])

    def test_argv_for_case_has_every_explicit_parameter(self):
        c = V.case_by_name("c04_exclude")
        a = S.scan_argv(c, "\\Device\\NPF_{X}", GUEST, PEER)
        self.assertEqual(a[a.index("--exclude") + 1], c["exclude"])
        self.assertEqual(a[a.index("--src-mac") + 1], GUEST)
        self.assertEqual(a[a.index("--router-mac") + 1], PEER)
        self.assertEqual(a[a.index("--seed") + 1], "1")
        self.assertEqual(a[a.index("--wait") + 1], "3")
        self.assertNotIn("--allow-foreign-source-mac", a)

    def test_quiescence_waits_for_unchanged_counters(self):
        vals = iter([1, 2, 3, 3, 3, 3, 3, 3, 3, 3])
        t = {"now": 0.0}
        ok = S.wait_quiet(lambda: next(vals), quiet_s=1.0, poll_s=0.5, timeout_s=30, clock=lambda: t["now"],
                          sleep=lambda s: t.__setitem__("now", t["now"] + s))
        self.assertTrue(ok)
        self.assertAlmostEqual(t["now"], 2.5)  # counters last changed at 1.5 s, then 1.0 s of quiet

    def test_quiescence_times_out_on_endless_traffic(self):
        c = {"n": 0}

        def read():
            c["n"] += 1
            return c["n"]
        t = {"now": 0.0}
        self.assertFalse(S.wait_quiet(read, quiet_s=1.0, poll_s=0.5, timeout_s=5, clock=lambda: t["now"],
                                      sleep=lambda s: t.__setitem__("now", t["now"] + s)))

    def test_ports_spec(self):
        self.assertEqual(S.ports_spec(V.SILENT_PORTS), "8099-8119")
        self.assertEqual(S.ports_spec([80, 443, 8000, 8001]), "80,443,8000-8001")

    def test_checkpoint_mutations(self):
        body = b"RMSPCKPT" + (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes(range(16)) + bytes(16) + bytes(32) + (8).to_bytes(8, "big")
        good = body + hashlib.sha256(body).digest()
        self.assertEqual(len(good), 120)
        ok = lambda b: len(b) == 120 and hashlib.sha256(b[:-32]).digest() == b[-32:]  # noqa: E731
        self.assertTrue(ok(S.mutate_checkpoint("wrong_ports", good)))
        self.assertTrue(ok(S.mutate_checkpoint("future_format", good)))
        self.assertEqual(S.mutate_checkpoint("future_format", good)[8:12], (99).to_bytes(4, "big"))
        self.assertEqual(S.mutate_checkpoint("future_engine", good)[12:16], (99).to_bytes(4, "big"))
        self.assertTrue(ok(S.mutate_checkpoint("future_engine", good)))
        self.assertFalse(ok(S.mutate_checkpoint("corrupt_next_index", good)))
        self.assertNotEqual(S.mutate_checkpoint("corrupt_next_index", good)[87], good[87])
        self.assertFalse(ok(S.mutate_checkpoint("corrupt_checksum", good)))
        self.assertEqual(len(S.mutate_checkpoint("truncated", good)), 60)
        self.assertEqual(S.mutate_checkpoint("empty", good), b"")

    def test_argv_sent_by_the_orchestrator_passes_the_verifiers_argument_gate_for_every_part_b_kind(self):
        man = {"binding": {"iface": S.LAB_NIC}}
        bind = V.Binding({"src_ip": S.SRC_IP, "src_mac": S.GUEST_MAC, "router_mac": PEER})
        for it in V.planned_b():
            if it["kind"] == "case":
                continue
            kd = V.KIND_ARGV_B[it["kind"]]
            argv = S.argv_from_def(kd, it, PEER, {"--checkpoint-out": "p.bin", "--resume-checkpoint": "q.bin"})
            r = V.Run(it["tag"])
            with tempfile.TemporaryDirectory() as d:
                wj(os.path.join(d, "argv.json"), {"exe": "x", "argv": argv})
                self.assertTrue(V.check_argv_file(r, d, "argv.json", kd, it, man, bind), (it["tag"], r.checks))
        # the forge helper of a refusal run too
        it = [i for i in V.planned_b() if i["tag"] == "ckpt_empty"][0]
        kd = V.KIND_SIDE_ARGV_B["ckpt_refuse"][1]
        r = V.Run("x")
        with tempfile.TemporaryDirectory() as d:
            wj(os.path.join(d, "forge-argv.json"), {"exe": "x", "argv": S.argv_from_def(kd, it, PEER, {"--checkpoint-out": "p.bin"})})
            self.assertTrue(V.check_argv_file(r, d, "forge-argv.json", kd, it, man, bind), r.checks)

    def test_flood_and_silent_helpers_of_the_peer_tool(self):
        self.assertEqual(P.parse_ports("8099,8100-8102"), [8099, 8100, 8101, 8102])
        self.assertEqual(P.parse_ports(""), [])

    def test_foreign_frames_are_marked_and_valid_ipv4(self):
        frames = S.foreign_frames(PEER, GUEST, SRC_IP, 40000)
        self.assertEqual(set(frames), {"other_ip", "unscanned_port", "wrong_cookie", "wrong_dst_port"})
        for kind, f in frames.items():
            i = V.tcp_info(f)
            self.assertEqual(i[7], V.FOREIGN_IP_ID, kind)
            self.assertEqual(i[1], GUEST)
            self.assertEqual(i[3], SRC_IP)
            self.assertEqual(i[6] & 0x12, 0x12)
            self.assertEqual(P.checksum(f[14:34]), 0, kind)  # valid IPv4 header checksum


if __name__ == "__main__":
    unittest.main()
