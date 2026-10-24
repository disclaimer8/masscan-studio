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


def marker():
    return mac(GUEST) + mac(PEER) + b"\x88\xb5" + b"WIRELAB-READY".ljust(46, b"\0")


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


def write_run(root, tag, syns, replies, rj_extra, rc=0, extra_files=None, extra_peer_frames=()):
    """One consistent run directory; returns its path."""
    d = os.path.join(root, "runs", tag)
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
        "peer": {"filter": "", "cmd": ["tcpdump", "-i", "lab0"], "listening": True, "tcpdump": tcpd(n),
                 "pcap": {"sha256": sha(peer), "size": len(peer), "frames": n},
                 "counters": {"rx_before": 10, "tx_before": 20, "rx_ready": 10, "tx_ready": 20,
                              "rx_end": 10 + n_rx, "tx_end": 20 + n_tx}},
        "eno1": {"filter": "net 198.18.0.0/30", "cmd": ["tcpdump", "-i", "eno1"], "listening": True, "tcpdump": tcpd(0),
                 "pcap": {"sha256": sha(eno), "size": len(eno), "frames": 0}},
        "quiet": {"reached": True, "quiet_s": 1.5},
    }
    wj(os.path.join(d, "capture.json"), cap)
    wj(os.path.join(d, "meta.json"), {"guest_exit": rc, "exe_sha256": EXE, "capture_started_utc": 1.0,
                                       "guest_started_utc": 2.0, "guest_finished_utc": 3.0, "capture_stopped_utc": 4.0})
    rj = {"identity": {"source_commit": COMMIT, "binary_sha256": EXE, "os": {"family": "windows"}}}
    rj.update(rj_extra)
    wj(os.path.join(d, "run.json"), rj)
    wj(os.path.join(d, "status-pre.json"), {"raw_run_allowed": True, "isolation_violations": []})
    wj(os.path.join(d, "status-post.json"), {"raw_run_allowed": True, "isolation_violations": []})
    wj(os.path.join(d, "guest-verify.json"), {"ok": True, "errors": []})
    wj(os.path.join(d, "listeners.json"), {"open": V.LISTEN_OPEN, "ready": True, "silent": [V.SILENT_PORT], "silent_proven": True})
    for k, v in (extra_files or {}).items():
        if isinstance(v, bytes):
            bw(os.path.join(d, k), v)
        else:
            wj(os.path.join(d, k), v)
    return d


def job_of(case, wait=3):
    return {"iface": "\\Device\\NPF_{X}", "src_ip": SRC_IP, "src_mac": GUEST, "router_mac": PEER, "source_port": case["source_port"],
            "targets": case["targets"], "exclude": case["exclude"], "ports": case["ports"], "seed": 1, "rate": 100,
            "wait": wait, "retries": 0, "shard": "1/1", "blackrock_rounds": 14}


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
       {"code_commit": COMMIT, "exe": {"sha256": EXE},
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
            write_run(root, tag, case_syns(c), case_replies(c, silent_answers=False), full_json(c, exp), extra_files=files,
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
        data = pcap([(1000.0, marker()), (1001.0, syn(40000, 8000))])
        bw(os.path.join(d, "peer.pcap"), data)
        self.edit_json("runs/refuse_completed/capture.json", lambda c: (c["peer"].__setitem__("pcap", {"sha256": sha(data), "size": len(data), "frames": 2}),
                                                                       c["peer"].__setitem__("tcpdump", tcpd(2)),
                                                                       c["peer"]["counters"].update(rx_end=c["peer"]["counters"]["rx_before"] + 1,
                                                                                                    tx_end=c["peer"]["counters"]["tx_before"] + 1)))
        self.assertEqual(self.run_verdict("refuse_completed"), "FAIL")

    def test_cases_psv_lists_six_classes_plus_the_foreign_case(self):
        lines = V.cases_psv().strip().splitlines()
        self.assertEqual(len(lines), 7)
        self.assertEqual(len(V.CASES), 6)
        self.assertTrue(all(len(l.split("|")) == 5 for l in lines))


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
