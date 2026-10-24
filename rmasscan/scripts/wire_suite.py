#!/usr/bin/env python3
"""Rust wire acceptance suites for the sealed lab (stage 2B-Linux, task 6).

Independent test driver (stdlib only), NOT product code. It is started by
`wire-lab.sh --suite rust|perf` AFTER the lab was built and its seal asserted
(two namespaces, one veth, no uplink/bridge/NAT). It runs as root inside the
lab and only ever executes things through `ip netns exec <this run's ns>`.

  rust  wire parity against the C fixtures, real pause/resume (pcap concat),
        resume rejections, Stop at rate=1 (silence / RX drain / full queue),
        queue overflow, veth removal mid-scan (always LAST: it destroys the veth)
  perf  C vs Rust at 100/1k/10k/100k pps, repeats, tcpdump capture, steady-state
        rate from the captured wire, CPU/RSS via wait4 rusage, stop time

Every capture that is incomplete is INVALID and is never normalised or counted.
Results: <out>/results.json (+ per-run files). Own children are killed on
SIGTERM/SIGINT; nothing global is touched (no pkill, no firewall/route change).
"""
import argparse
import atexit
import importlib.util
import json
import os
import re
import signal
import statistics
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("verify_wire", os.path.join(HERE, "verify-wire.py"))
vw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vw)

CHILDREN = []
CHECKS = []
A = None  # parsed args


def kill_children(*_):
    for p in CHILDREN:
        try:
            if p.poll() is None:
                p.terminate()
        except OSError:
            pass
    time.sleep(0.2)
    for p in CHILDREN:
        try:
            if p.poll() is None:
                p.kill()
        except OSError:
            pass


def on_signal(signum, _frame):
    kill_children()
    save_results(partial=True)
    sys.exit(128 + signum)


atexit.register(kill_children)
signal.signal(signal.SIGTERM, on_signal)
signal.signal(signal.SIGINT, on_signal)


def popen(argv, **kw):
    p = subprocess.Popen(argv, **kw)
    CHILDREN.append(p)
    return p


def nsx(ns, argv):
    return ["ip", "netns", "exec", ns] + [str(x) for x in argv]


def chk(group, name, ok, detail=""):
    """ok: True PASS, False FAIL, None NOT RUN / INVALID (never counted as PASS)."""
    CHECKS.append({"group": group, "name": name,
                   "result": "PASS" if ok is True else ("FAIL" if ok is False else "NOT RUN"),
                   "detail": detail})
    print("[%s] %-4s %s %s" % (group, CHECKS[-1]["result"], name, detail), flush=True)


def save_results(partial=False):
    if A is None:
        return
    out = {"partial": partial, "checks": CHECKS,
           "totals": {k: sum(1 for c in CHECKS if c["result"] == k) for k in ("PASS", "FAIL", "NOT RUN")}}
    out.update(EXTRA)
    with open(os.path.join(A.out, "results.json"), "w") as f:
        json.dump(out, f, indent=2, sort_keys=True)
        f.write("\n")


EXTRA = {}


def wait_file(path, secs):
    end = time.time() + secs
    while time.time() < end:
        if os.path.exists(path):
            return True
        time.sleep(0.02)
    return False


# ------------------------------------------------------------------ responder
class Responder:
    """TCP listeners in the peer ns (open: 80, 8080; everything else gets the kernel's RST).

    Restarted before every run: closing the listener drops its half-open request sockets, so SYN-ACK
    retransmissions of an earlier run cannot bleed into the next capture."""
    cur = None

    @classmethod
    def fresh(cls):
        if cls.cur is not None:
            cls.cur.terminate()
            cls.cur.wait()
        ready = os.path.join(A.work, "responder.ready")
        if os.path.exists(ready):
            os.unlink(ready)
        cls.cur = popen(nsx(A.ns_b, ["python3", os.path.join(HERE, "wire_capture.py"), "responder", "--ports",
                                     "80,8080", "--ready", ready]),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_file(ready, 10):
            raise RuntimeError("responder not ready")


# ------------------------------------------------------------------ captures
class PyRecorder:
    """The stage-1 recorder (wire_capture.py record): both directions, marker ack."""

    def __init__(self, tag):
        self.tag = tag
        self.pcap = os.path.join(A.out, tag + ".pcap")
        self.meta = os.path.join(A.out, tag + ".capture.json")
        self.ready = os.path.join(A.work, tag + ".rec.ready")
        self.ack = os.path.join(A.work, tag + ".rec.ack")
        for p in (self.ready, self.ack):
            if os.path.exists(p):
                os.unlink(p)

    def start(self):
        self.p = popen(nsx(A.ns_b, ["python3", os.path.join(HERE, "wire_capture.py"), "record", "--iface", A.iface_b,
                                    "--pcap", self.pcap, "--meta", self.meta, "--ready", self.ready, "--ack", self.ack]),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_file(self.ready, 10):
            raise RuntimeError("recorder not ready (%s)" % self.tag)
        subprocess.run(nsx(A.ns_a, ["python3", os.path.join(HERE, "wire_capture.py"), "marker", "--iface", A.iface_a,
                                    "--src", A.mac_a, "--dst", A.mac_b]), check=True)
        if not wait_file(self.ack, 10):
            raise RuntimeError("recorder never acknowledged the marker (%s)" % self.tag)

    def stop(self):
        time.sleep(0.5)
        self.p.terminate()
        self.p.wait()
        meta = json.load(open(self.meta))
        return meta


def read_frames(path):
    return vw.read_pcap_records(open(path, "rb").read())[1]


def mac_of(frame, off):
    return ":".join("%02x" % b for b in frame[off:off + 6])


def tcp_info(f):
    """(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags) of an IPv4/TCP frame, else None."""
    if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
        return None
    ihl = (f[14] & 0x0F) * 4
    t = 14 + ihl
    if len(f) < t + 14:
        return None
    ip = lambda o: ".".join(str(b) for b in f[o:o + 4])
    sp, dp = struct.unpack(">HH", f[t:t + 4])
    return mac_of(f, 6), mac_of(f, 0), ip(26), ip(30), sp, dp, f[t + 13] & 0x3F


def peer_replies(frames):
    """Replies the PEER sent: set of 'ip:port:open|closed' (SYN-ACK / RST)."""
    out = []
    for _t, f in frames:
        i = tcp_info(f)
        if not i or i[0] != A.mac_b:
            continue
        if i[6] & 0x12 == 0x12:
            out.append("%s:%d:open" % (i[2], i[4]))
        elif i[6] & 0x04:
            out.append("%s:%d:closed" % (i[2], i[4]))
    return out


def scanner_syns(frames):
    return [(t, f) for t, f in frames if vw.is_syn(f) and mac_of(f, 6) == A.mac_a]


# ------------------------------------------------------------------ rust runs
def rust_args(targets, ports, rate=100, wait=3, source_port="40000", exclude=None, iface=None, src_mac=None, seed=1):
    a = ["--iface", iface or A.iface_a, "--src-ip", A.ip_a, "--src-mac", src_mac or A.mac_a, "--router-mac", A.mac_b,
         "--targets", targets, "--ports", ports, "--seed", seed, "--rate", rate, "--wait", wait,
         "--source-port", source_port]
    if exclude:
        a += ["--exclude", exclude]
    return a


def run_rust(tag, args, record=True, timeout=90, rec_cls=PyRecorder, ready_action=None):
    """Run one harness invocation in the scanner ns; returns a result dict."""
    rec = None
    Responder.fresh()
    if record:
        rec = rec_cls(tag)
        rec.start()
    ready = os.path.join(A.work, tag + ".ready")
    if os.path.exists(ready):
        os.unlink(ready)
    cmd = nsx(A.ns_a, [A.rust_bin] + args + ["--ready-file", ready])
    t0 = time.monotonic()
    p = popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    extra = None
    if ready_action:
        extra = ready_action(p, ready)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        out += "\n{\"status\":\"error\",\"error\":\"TIMEOUT\"}"
    wall = time.monotonic() - t0
    meta = rec.stop() if rec else None
    line = [l for l in out.splitlines() if l.startswith("{")]
    try:
        summary = json.loads(line[-1]) if line else {}
    except ValueError:
        summary = {"status": "error", "error": "unparsable stdout"}
    open(os.path.join(A.out, tag + ".summary.json"), "w").write(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    if err.strip():
        open(os.path.join(A.out, tag + ".stderr.txt"), "w").write(err)
    return {"rc": p.returncode, "s": summary, "wall": wall, "meta": meta, "extra": extra,
            "pcap": rec.pcap if rec else None, "stderr": err}


def syn_cmp(expected_pcap, actual_pcaps, metas):
    code, msg = vw.compare_bytes(open(expected_pcap, "rb").read(), [open(p, "rb").read() for p in actual_pcaps],
                                 None, metas)
    return code, msg


def code_name(code):
    return {0: "PASS", 1: "FAIL", 2: "INVALID"}[code]


# ------------------------------------------------------------------ suite: rust
CASES = [  # name, targets, ports, exclude, source_port, (syn, synack, rst)
    ("c01_one_addr_port_synack", "10.200.0.2", "80", None, "40000", (1, 1, 0)),
    ("c02_one_addr_port_rst", "10.200.0.2", "81", None, "40000", (1, 0, 1)),
    ("c03_multi_addr_ports", "10.200.0.2-10.200.0.5", "80,81,443,8080", None, "40000", (16, 8, 8)),
    ("c04_exclude", "10.200.0.2-10.200.0.5", "80,81", "10.200.0.3", "40000", (6, 3, 3)),
    ("c05_srcport_single", "10.200.0.2-10.200.0.3", "80,81", None, "50123", (4, 2, 2)),
    ("c06_srcport_range", "10.200.0.2-10.200.0.3", "80,81", None, "50000-50015", (4, 2, 2)),
]
C03 = CASES[2]


def suite_parity():
    for name, targets, ports, excl, sp, (e_syn, e_ack, e_rst) in CASES:
        fixture = os.path.join(A.fixtures, name + ".run1.pcap")
        c_replies = sorted(peer_replies(read_frames(fixture)))
        for run in (1, 2):
            tag = "rust.%s.run%d" % (name, run)
            r = run_rust(tag, rust_args(targets, ports, source_port=sp, exclude=excl))
            s = r["s"]
            ok_run = r["rc"] == 0 and s.get("reason") == "Completed" and r["meta"] and r["meta"]["valid"]
            if not ok_run:
                chk("parity", tag, None if (r["meta"] and not r["meta"]["valid"]) else False,
                    "rc=%s reason=%s capture_valid=%s err=%s" % (r["rc"], s.get("reason"), r["meta"] and r["meta"]["valid"],
                                                                 s.get("message") or s.get("error")))
                continue
            code, msg = syn_cmp(fixture, [r["pcap"]], [r["meta"]])
            chk("parity", tag + " SYN stream vs C oracle fixture", code == 0 if code != 2 else None,
                "%s: %s" % (code_name(code), msg))
            mine = sorted(s["replies"])
            chk("parity", tag + " replies == C reply set", mine == c_replies,
                "rust=%d c=%d open=%d closed=%d" % (len(mine), len(c_replies),
                                                    sum(x.endswith(":open") for x in mine),
                                                    sum(x.endswith(":closed") for x in mine)))
            wire = peer_replies(read_frames(r["pcap"]))
            # The Rust scanner (unlike C) never answers a SYN-ACK with RST, so the peer kernel may retransmit its
            # SYN-ACK inside `wait`. Those wire duplicates must be suppressed by dedup, never delivered twice.
            chk("parity", tag + " no duplicate results; wire replies == results, extra wire copies are suppressed dups",
                s["reply_total"] == s["reply_unique"] == len(mine) == s["received"]
                and sorted(set(wire)) == mine and s["received"] + s["duplicates"] <= len(wire),
                "results=%s unique=%s wire_replies=%d suppressed_duplicates=%s discarded=%s" % (
                    s["reply_total"], s["reply_unique"], len(wire), s["duplicates"], s["discarded"]))
            chk("parity", tag + " counts (syn/open/closed) as expected",
                s["sent"] == e_syn and sum(x.endswith(":open") for x in mine) == e_ack
                and sum(x.endswith(":closed") for x in mine) == e_rst,
                "sent=%s want %s/%s/%s" % (s["sent"], e_syn, e_ack, e_rst))
            chk("parity", tag + " nothing sent beyond Sent",
                s["net"]["tx_sent"] == s["sent"] and s["net"]["tx_uncertain"] == 0 and s["net"]["tx_errors"] == 0,
                "net.tx_sent=%s would_block=%s" % (s["net"]["tx_sent"], s["net"]["tx_would_block"]))


def read_cp(path):
    return open(path, "rb").read()


def suite_pause_resume():
    name, targets, ports, excl, sp, _ = C03
    base = rust_args(targets, ports, source_port=sp)
    cont_pcap = os.path.join(A.out, "rust.%s.run1.pcap" % name)
    cont_meta = json.load(open(os.path.join(A.out, "rust.%s.run1.capture.json" % name)))
    fixture = os.path.join(A.fixtures, name + ".run1.pcap")
    cont_sum = json.load(open(os.path.join(A.out, "rust.%s.run1.summary.json" % name)))
    cont_set = sorted(cont_sum["replies"])
    rng = cont_sum["range"]
    A1, A2 = "aa" * 16, "bb" * 16
    mid_cp = None
    SCAN = "11" * 16
    EXTRA["pause_resume"] = []
    for n in (0, 1, rng // 2, rng - 1):
        tag = "pr_N%d" % n
        cp = os.path.join(A.out, tag + ".checkpoint.bin")
        l1 = run_rust(tag + ".pause", base + ["--scan-id", SCAN, "--attempt-id", A1, "--pause-after", n,
                                              "--checkpoint-out", cp])
        s1 = l1["s"]
        ok1 = (l1["rc"] == 0 and s1.get("reason") == "Paused" and s1.get("sent") == n and s1.get("next_index") == n
               and s1.get("checkpoint") is True and s1["net"]["tx_sent"] == n and l1["meta"]["valid"])
        chk("pause", "N=%d pause leg: Paused, sent=%d, checkpoint next_index=%d" % (n, n, n), ok1 if l1["meta"]["valid"] else None,
            "rc=%s reason=%s sent=%s next=%s cp=%s" % (l1["rc"], s1.get("reason"), s1.get("sent"), s1.get("next_index"), s1.get("checkpoint")))
        if not ok1:
            continue
        l2 = run_rust(tag + ".resume", base + ["--scan-id", SCAN, "--attempt-id", A2, "--resume-checkpoint", cp])
        s2 = l2["s"]
        ok2 = (l2["rc"] == 0 and s2.get("reason") == "Completed" and s2.get("sent") == rng - n and l2["meta"]["valid"])
        chk("pause", "N=%d resume leg: Completed, sent=%d" % (n, rng - n), ok2 if l2["meta"]["valid"] else None,
            "rc=%s reason=%s sent=%s" % (l2["rc"], s2.get("reason"), s2.get("sent")))
        if not ok2:
            continue
        # byte equality of pause+resume vs continuous Rust trace and vs the C oracle fixture
        for label, exp in (("continuous Rust trace", cont_pcap), ("C oracle fixture", fixture)):
            code, msg = syn_cmp(exp, [l1["pcap"], l2["pcap"]], [l1["meta"], l2["meta"]])
            chk("pause", "N=%d pcap(pause)+pcap(resume) == %s" % (n, label), code == 0 if code != 2 else None,
                "%s: %s" % (code_name(code), msg))
        chk("pause", "N=%d scan_id preserved, attempt_id changed, origin recorded" % n,
            s1["scan_id"] == s2["scan_id"] == SCAN and s1["attempt_id"] == A1 and s2["attempt_id"] == A2
            and s2["resumed_from_attempt"] == A1 and s1["resumed_from_attempt"] is None,
            "scan=%s.. a1=%s.. a2=%s.. from=%s.." % (s2["scan_id"][:6], s1["attempt_id"][:6], s2["attempt_id"][:6],
                                                      (s2["resumed_from_attempt"] or "")[:6]))
        union = sorted(s1["replies"] + s2["replies"])
        chk("pause", "N=%d replies of both legs == continuous set, no duplicates" % n,
            union == cont_set and len(set(union)) == len(union),
            "legs=%d+%d union=%d continuous=%d" % (len(s1["replies"]), len(s2["replies"]), len(set(union)), len(cont_set)))
        chk("pause", "N=%d no probe lost or added across the seam (SYN counts)" % n,
            len(scanner_syns(read_frames(l1["pcap"]))) == n and len(scanner_syns(read_frames(l2["pcap"]))) == rng - n,
            "pause=%d resume=%d total=%d" % (len(scanner_syns(read_frames(l1["pcap"]))),
                                              len(scanner_syns(read_frames(l2["pcap"]))), rng))
        EXTRA["pause_resume"].append({"n": n, "checkpoint_sha256": __import__("hashlib").sha256(read_cp(cp)).hexdigest(),
                                      "pause_pcap": os.path.basename(l1["pcap"]), "resume_pcap": os.path.basename(l2["pcap"])})
        if n == rng // 2:
            mid_cp = cp

    # N == range: the decorator never fires, the job completes: no checkpoint
    tag = "pr_completed"
    cpc = os.path.join(A.out, tag + ".checkpoint.bin")
    r = run_rust(tag, base + ["--scan-id", SCAN, "--attempt-id", A1, "--pause-after", rng, "--checkpoint-out", cpc])
    s = r["s"]
    chk("pause", "completed job: pause-after=range ends Completed with NO checkpoint",
        r["rc"] == 0 and s.get("reason") == "Completed" and s.get("checkpoint") is False and not os.path.exists(cpc),
        "reason=%s checkpoint=%s" % (s.get("reason"), s.get("checkpoint")))
    forged = os.path.join(A.out, "forged_completed.checkpoint.bin")
    subprocess.run([str(x) for x in [A.rust_bin] + base + ["--scan-id", SCAN, "--attempt-id", A1, "--forge-checkpoint-next-index", rng,
                                                          "--checkpoint-out", forged]], check=True, capture_output=True)
    rej = run_rust("rej_completed", base + ["--scan-id", SCAN, "--attempt-id", A2, "--resume-checkpoint", forged])
    reject_check("completed job (next_index == range)", rej, "AlreadyCompleted")

    # rejections, all against the REAL mid-scan checkpoint
    cp = mid_cp
    cases = [
        ("changed rate", base_with(targets, ports, sp, rate=200), A2, SCAN, cp, "JobMismatch"),
        ("changed binding (source MAC)", base_with(targets, ports, sp, src_mac="02:aa:00:00:00:09"), A2, SCAN, cp, "JobMismatch"),
        ("changed binding (interface name)", base_with(targets, ports, sp, iface="veth-x"), A2, SCAN, cp, "JobMismatch"),
        ("changed targets", base_with("10.200.0.2-10.200.0.4", ports, sp), A2, SCAN, cp, "JobMismatch"),
        ("changed ports", base_with(targets, "80,81,443", sp), A2, SCAN, cp, "JobMismatch"),
        ("changed seed", base_with(targets, ports, sp, seed=2), A2, SCAN, cp, "JobMismatch"),
        ("different scan_id", base_with(targets, ports, sp), A2, "22" * 16, cp, "ScanIdMismatch"),
        ("attempt_id reused", base_with(targets, ports, sp), A1, SCAN, cp, "AttemptIdReused"),
    ]
    for label, args, att, scan, cpf, want in cases:
        rej = run_rust("rej_" + re.sub(r"\W+", "_", label), args + ["--scan-id", scan, "--attempt-id", att,
                                                                  "--resume-checkpoint", cpf])
        reject_check(label, rej, want)
    raw = bytearray(read_cp(cp))
    for label, data, want in (("corrupt checkpoint (1 bit flipped in next_index)", bytes(raw[:83]) + bytes([raw[83] ^ 1]) + bytes(raw[84:]), "BadChecksum"),
                              ("corrupt checkpoint (bad checksum byte)", bytes(raw[:-1]) + bytes([raw[-1] ^ 0xFF]), "BadChecksum"),
                              ("truncated checkpoint", bytes(raw[:60]), "Malformed"),
                              ("empty checkpoint", b"", "Malformed")):
        bad = os.path.join(A.out, "bad.checkpoint.bin")
        open(bad, "wb").write(data)
        rej = run_rust("rej_" + re.sub(r"\W+", "_", label), base + ["--scan-id", SCAN, "--attempt-id", A2,
                                                                  "--resume-checkpoint", bad])
        reject_check(label, rej, want)


def base_with(targets, ports, sp, **kw):
    return rust_args(targets, ports, source_port=sp, **kw)


def reject_check(label, r, want):
    s = r["s"]
    syns = len(scanner_syns(read_frames(r["pcap"]))) if r["pcap"] else -1
    ok = (r["rc"] == 4 and s.get("status") == "error" and str(s.get("error", "")).startswith(want) and s.get("opened_adapter") is False
          and s.get("tx_sent") == 0 and syns == 0 and r["meta"]["valid"])
    chk("reject", "%s rejected before the adapter opens (%s)" % (label, want), ok if r["meta"]["valid"] else None,
        "rc=%s error=%s opened=%s wire_syns=%s" % (r["rc"], s.get("error"), s.get("opened_adapter"), syns))


# ------------------------------------------------------------------ suite: stop
def leak_ok(s):
    res = s["resources"]
    return res["threads_after_join"] == res["threads_before"] and res["fds_after_join"] <= res["fds_before_open"]


def stop_common(tag, r, extra_ok=True):
    s = r["s"]
    ok_reason = s.get("reason") == "Stopped"
    chk("stop", tag + ": Stopped, no checkpoint, stop->outcome < 1 s, join < 1 s",
        r["rc"] == 0 and ok_reason and s.get("checkpoint") is False and s["timing"]["stop_to_outcome_ms"] is not None
        and s["timing"]["stop_to_outcome_ms"] < 1000 and s["timing"]["join_ms"] < 1000,
        "reason=%s stop_to_outcome=%sms join=%sms" % (s.get("reason"), s["timing"]["stop_to_outcome_ms"], s["timing"]["join_ms"]))
    chk("stop", tag + ": no TX after Stop (stats frozen over %d ms, wire SYN count == tx_sent)" % s["observe_ms"],
        s["tx_sent_at_join"] == s["tx_sent_after_observe"] == s["net"]["tx_sent"]
        and r["meta"]["valid"] and len(scanner_syns(read_frames(r["pcap"]))) == s["net"]["tx_sent"],
        "tx_sent=%s at_join=%s after_observe=%s wire_syns=%s" % (s["net"]["tx_sent"], s["tx_sent_at_join"],
                                                                 s["tx_sent_after_observe"],
                                                                 len(scanner_syns(read_frames(r["pcap"])))))
    chk("stop", tag + ": no live workers, no leaked fds after join", leak_ok(s),
        "threads %s->%s (immediately %s, settled in %sms) fds %s->(open %s)->%s" % (s["resources"]["threads_before"], s["resources"]["threads_after_join"], s["resources"]["threads_after_join_immediate"], s["resources"]["threads_settle_ms"],
                                                  s["resources"]["fds_before_open"], s["resources"]["fds_open"],
                                                  s["resources"]["fds_after_join"]))


def suite_stop():
    # silence: nobody answers (10.200.0.77.. not owned by the peer)
    r = run_rust("stop_silence", rust_args("10.200.0.77", "1-100", rate=1, wait=10) + ["--stop-after-ms", 2500, "--observe-ms", 1500])
    stop_common("rate=1 silence", r)
    chk("stop", "rate=1 silence: really silent (no replies) and Stop hit mid-TX",
        r["s"].get("reply_total") == 0 and 0 < r["s"].get("sent", 0) < r["s"].get("range", 0),
        "sent=%s range=%s replies=%s" % (r["s"].get("sent"), r["s"].get("range"), r["s"].get("reply_total")))
    # RX drain: both probes sent, wait=10 s drain is running, then Stop
    r = run_rust("stop_drain", rust_args("10.200.0.2", "80,81", rate=1, wait=10) + ["--stop-in-drain", "--observe-ms", 1500])
    stop_common("rate=1 during RX drain", r)
    chk("stop", "rate=1 during RX drain: Stop skipped the 10 s wait", r["s"].get("timing", {}).get("total_s", 99) < 6,
        "total=%ss sent=%s" % (r["s"].get("timing", {}).get("total_s"), r["s"].get("sent")))
    # full queue: capacity 2, 2 replies arrive, nobody reads events, then Stop in the drain
    r = run_rust("stop_fullqueue", rust_args("10.200.0.2", "80,81", rate=1, wait=10) +
                 ["--result-capacity", 2, "--no-consume", "--stop-after-ms", 4500, "--observe-ms", 1500])
    stop_common("rate=1 with a FULL result queue", r)
    chk("stop", "full queue: both replies sit unread in the queue (capacity 2) and nothing was lost",
        r["s"].get("reply_total") == 2 and r["s"].get("reason") == "Stopped",
        "replies=%s reason=%s" % (r["s"].get("reply_total"), r["s"].get("reason")))
    # overflow: capacity 1 with 2 replies -> Failed(ConsumerTooSlow), no checkpoint, TX halted
    r = run_rust("overflow", rust_args("10.200.0.2", "80,81,82,83,84,85", rate=1, wait=10) +
                 ["--result-capacity", 1, "--no-consume", "--observe-ms", 1500])
    s = r["s"]
    chk("stop", "queue overflow: Failed(ConsumerTooSlow), no checkpoint, TX stopped, no leaks",
        r["rc"] == 3 and s.get("reason") == "Failed" and "ConsumerTooSlow" in s.get("fail_detail", "")
        and s.get("checkpoint") is False and s["tx_sent_at_join"] == s["tx_sent_after_observe"] and leak_ok(s)
        and s["sent"] < s["range"],
        "reason=%s %s sent=%s/%s" % (s.get("reason"), s.get("fail_detail"), s.get("sent"), s.get("range")))
    # Pause is also bounded (informational companion)
    pf = os.path.join(A.work, "pause.file")
    if os.path.exists(pf):
        os.unlink(pf)
    r = run_rust("pause_rate1", rust_args("10.200.0.77", "1-100", rate=1, wait=1) + ["--pause-file", pf, "--observe-ms", 500],
                 ready_action=lambda p, ready: (wait_file(ready, 10), time.sleep(1.5), open(pf, "w").close()))
    s = r["s"]
    chk("stop", "rate=1 external Pause: Paused with a checkpoint at the confirmed boundary, tx_sent == next_index",
        r["rc"] == 0 and s.get("reason") == "Paused" and s.get("checkpoint") is True and s["next_index"] == s["sent"] == s["net"]["tx_sent"],
        "reason=%s sent=%s next=%s" % (s.get("reason"), s.get("sent"), s.get("next_index")))


def suite_veth_removal():
    cp = os.path.join(A.out, "veth_removal.checkpoint.bin")
    marks = {}

    def action(p, ready):
        if not wait_file(ready, 10):
            return None
        time.sleep(1.0)
        marks["t"] = time.monotonic()
        subprocess.run(["ip", "-n", A.ns_a, "link", "del", A.iface_a], check=True)
        return marks["t"]

    t_end = []
    r = run_rust("veth_removal", rust_args("10.200.0.2-10.200.0.5", "1-100", rate=50, wait=3) +
                 ["--checkpoint-out", cp, "--observe-ms", 500], record=False, ready_action=action)
    s = r["s"]
    exit_after = (time.monotonic() - marks["t"]) if "t" in marks else None
    chk("veth", "veth removed mid-scan -> Failed with a diagnosable TX/RX error, exit code 3",
        r["rc"] == 3 and s.get("reason") == "Failed" and ("TxError" in s.get("fail_detail", "") or "RxError" in s.get("fail_detail", "")),
        "reason=%s detail=%s" % (s.get("reason"), s.get("fail_detail")))
    chk("veth", "veth removed: NO checkpoint (summary says none, no file, no CheckpointReady)",
        s.get("checkpoint") is False and s.get("checkpoint_hex") is None and not os.path.exists(cp),
        "checkpoint=%s file=%s" % (s.get("checkpoint"), os.path.exists(cp)))
    chk("veth", "veth removed: partial scan, no TX after failure, no live workers, no leaked fds",
        0 < s.get("sent", 0) < s.get("range", 0) and s["tx_sent_at_join"] == s["tx_sent_after_observe"] and leak_ok(s),
        "sent=%s/%s threads %s->%s fds %s->%s exit %.2fs after removal" % (
            s.get("sent"), s.get("range"), s["resources"]["threads_before"], s["resources"]["threads_after_join"],
            s["resources"]["fds_before_open"], s["resources"]["fds_after_join"], exit_after or -1))
    chk("veth", "veth removed: process ended promptly (< 5 s incl. 3 s wait skipped by Failed)",
        exit_after is not None and exit_after < 5, "%.2fs" % (exit_after or -1))
    EXTRA["veth_removal"] = {"fail_detail": s.get("fail_detail"), "exit_after_removal_s": exit_after,
                             "net": s.get("net")}


def run_rust_suite():
    suite_parity()
    suite_pause_resume()
    suite_stop()
    suite_veth_removal()  # LAST: destroys the veth pair


# ------------------------------------------------------------------ suite: perf
class DumpRec:
    """tcpdump (C, TPACKET_V3) capture of BOTH directions on the peer veth for high rates.

    Complete iff no kernel/interface drops, captured == pcap frames == "received by filter", and the capture count lies inside the
    rx+tx packet-counter delta window of the peer veth (read just before and just after tcpdump stops).
    Anything else is INVALID."""

    def __init__(self, tag):
        self.tag = tag
        self.pcap = os.path.join(A.work, tag + ".pcap")
        self.err = os.path.join(A.work, tag + ".tcpdump.err")
        self.meta = None

    def rx(self):
        tot = 0
        for n in ("rx_packets", "tx_packets"):
            out = subprocess.run(nsx(A.ns_b, ["cat", "/sys/class/net/%s/statistics/%s" % (A.iface_b, n)]),
                                 capture_output=True, text=True).stdout
            tot += int(out.strip())
        return tot

    def start(self):
        self.rx_before_start = self.rx()
        self.ef = open(self.err, "w")
        self.p = popen(nsx(A.ns_b, ["tcpdump", "-i", A.iface_b, "-n", "-s", "0", "-B", "262144",
                                    "--time-stamp-precision=nano", "-Z", "root", "-w", self.pcap]),
                       stdout=subprocess.DEVNULL, stderr=self.ef)
        end = time.time() + 15
        while time.time() < end:
            if "listening on" in open(self.err).read():
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("tcpdump not listening")
        time.sleep(0.3)
        self.rx0 = self.rx()  # counters right after tcpdump is listening

    def stop(self):
        # Quiesce first. tcpdump (libpcap TPACKET_V3) retires a partially filled ring block only after the capture
        # timeout (tcpdump uses 1000 ms), and SIGINT breaks the loop WITHOUT processing that block, so the last frame
        # (typically a SYN-ACK retransmit from the peer, since the Rust scanner never RSTs half-open sockets) can be
        # counted in "received by filter" yet missing from the pcap. Stop only after the peer veth counters were
        # unchanged for QUIET_S (> the retire timeout) so every received frame has been retired to userspace.
        # The completeness check below is unchanged and strict.
        QUIET_S, POLL_S = 1.5, 0.25
        prev, quiet_since, end = -1, None, time.time() + 20
        while time.time() < end:
            time.sleep(POLL_S)
            cur = self.rx()
            if cur != prev:
                prev, quiet_since = cur, time.time()
            elif time.time() - quiet_since >= QUIET_S:
                break
        rx1 = self.rx()  # counters just BEFORE tcpdump is stopped
        self.p.send_signal(signal.SIGINT)
        self.p.wait()
        rx2 = self.rx()  # counters just AFTER tcpdump exited
        self.ef.close()
        txt = open(self.err).read()
        g = lambda pat: int(re.search(pat, txt).group(1)) if re.search(pat, txt) else -1
        cap, recv, kdrop, idrop = (g(r"(\d+) packets? captured"), g(r"(\d+) packets? received by filter"),
                                   g(r"(\d+) packets? dropped by kernel"), g(r"(\d+) packets? dropped by interface"))
        frames = read_frames(self.pcap)
        from_a = len(scanner_syns(frames))
        # The peer kernel keeps retransmitting SYN-ACKs for half-open sockets (the Rust scanner never RSTs
        # them), so a frame can land between the counter reads and tcpdump's stop. The capture count must
        # lie inside [rx1 - rx0, rx2 - rx_before_start]; fewer frames than the lower bound is a LOSS.
        delta = rx1 - self.rx0
        d_hi = rx2 - self.rx_before_start
        self.meta = {"tcpdump_captured": cap, "received_by_filter": recv, "kernel_drops": kdrop,
                     "interface_drops": max(idrop, 0), "pcap_frames": len(frames), "scanner_syn_frames": from_a,
                     "iface_rxtx_delta_lo": delta, "iface_rxtx_delta_hi": d_hi,
                     "valid": bool(cap >= 0 and kdrop == 0 and idrop <= 0 and cap == len(frames) == recv and delta <= cap <= d_hi)}
        self.frames = frames
        return self.meta


PERF = {  # rate: (targets, ports, expected_open, expected_closed, stop-probe ports)
    100: ("10.200.0.0/24", "79-80", None, None, "70-80"),
    1000: ("10.200.0.0/22", "78-80", None, None, "50-80"),
    10000: ("10.200.0.0/22", "51-80", None, None, "1-100"),
    100000: ("10.200.0.0/22", "1-300", None, None, "1-1000"),
}


def expected_replies(targets, ports):
    # the peer owns .2-.5; ports 80 and 8080 are open there
    lo, hi = [int(x) for x in ports.split("-")]
    n = hi - lo + 1
    openp = 1 if lo <= 80 <= hi else 0
    return 4 * openp, 4 * (n - openp)


def n_probes(targets, ports):
    lo, hi = [int(x) for x in ports.split("-")]
    bits = int(targets.split("/")[1])
    return (1 << (32 - bits)) * (hi - lo + 1)


def c_args(targets, ports, rate, wait, out_txt):
    return [targets, "-p" + ports, "--source-port", "40000", "--interface", A.iface_a, "--adapter-ip", A.ip_a,
            "--adapter-mac", A.mac_a, "--router-mac", A.mac_b, "--seed", "1", "--rate", rate,
            "--blackrock-rounds", "14", "--retries", "0", "--wait", wait, "-oL", out_txt]


def wrap_c(argv):
    if A.conf_masked == "1":
        return nsx(A.ns_a, ["unshare", "-m", "sh", "-c", 'mount --bind "$0" /etc/masscan && exec "$@"', A.empty_dir, A.oracle] + argv)
    return nsx(A.ns_a, [A.oracle] + argv)


MEASURED_HWM = [0]


def measured(argv, stop_sig_at=None, stop_file_at=None, timeout=120, stop_file=None):
    """Run argv, return (rc, rusage, wall, t_stop, t_exit, stdout, stderr). wait4 gives per-process CPU/RSS."""
    so = open(os.path.join(A.work, "perf.stdout"), "w")
    se = open(os.path.join(A.work, "perf.stderr"), "w")
    p = popen(argv, stdout=so, stderr=se, cwd=A.work)  # C writes paused.conf into its cwd on SIGINT
    t0 = time.monotonic()
    t_stop = None
    deadline = t0 + timeout
    done = None
    hwm = [0]
    last_sample = 0.0

    def sample_hwm():
        # ru_maxrss of a forked+exec'd child includes the parent's pre-exec RSS (the driver holds big
        # captures), so the process peak is sampled from /proc/<pid>/status VmHWM instead.
        try:
            for line in open("/proc/%d/status" % p.pid):
                if line.startswith("VmHWM:"):
                    hwm[0] = max(hwm[0], int(line.split()[1]))
                    break
        except OSError:
            pass

    while True:
        if time.monotonic() - last_sample > 0.02:
            last_sample = time.monotonic()
            sample_hwm()
        wpid, status, ru = os.wait4(p.pid, os.WNOHANG)
        if wpid:
            done = (status, ru)
            break
        now = time.monotonic()
        if stop_sig_at is not None and t_stop is None and now - t0 >= stop_sig_at:
            t_stop = now
            os.kill(p.pid, signal.SIGINT)
        if stop_file_at is not None and t_stop is None and now - t0 >= stop_file_at:
            t_stop = now
            open(stop_file, "w").close()
        if now > deadline:
            p.kill()
            os.wait4(p.pid, 0)
            done = (-9, None)
            break
        time.sleep(0.002)
    t_exit = time.monotonic()
    p.returncode = 0
    so.close()
    se.close()
    status, ru = done
    rc = os.waitstatus_to_exitcode(status) if status != -9 else -9
    MEASURED_HWM[0] = hwm[0]
    return rc, ru, t_exit - t0, t_stop, t_exit, open(so.name).read(), open(se.name).read()


def perf_cell(impl, rate, rep):
    targets, ports, _, _, stop_ports = PERF[rate]
    total = n_probes(targets, ports)
    wait = 1
    tag = "perf.%s.%d.r%d" % (impl, rate, rep)
    exp_open, exp_closed = expected_replies(targets, ports)
    Responder.fresh()
    rec = DumpRec(tag)
    rec.start()
    txt = os.path.join(A.work, tag + ".scan.txt")
    if impl == "c":
        argv = wrap_c(c_args(targets, ports, rate, wait, txt))
    else:
        argv = nsx(A.ns_a, [A.rust_bin] + rust_args(targets, ports, rate=rate, wait=wait))
    rc, ru, wall, _, _, so, se = measured(argv)
    meta = rec.stop()
    syn_ts = [t for t, _f in scanner_syns(rec.frames)]
    cell = {"impl": impl, "rate": rate, "rep": rep, "rc": rc, "probes": total, "wall_s": round(wall, 3),
            "capture": meta, "transmitted_wire": len(syn_ts),
            "cpu_user_s": round(ru.ru_utime, 3) if ru else None, "cpu_sys_s": round(ru.ru_stime, 3) if ru else None,
            "max_rss_kb": MEASURED_HWM[0] or None, "expected_open": exp_open, "expected_closed": exp_closed}
    wire_r = peer_replies(rec.frames)
    cell["peer_replies_on_wire"] = len(wire_r)
    cell["peer_open_on_wire"] = sum(1 for x in set(wire_r) if x.endswith(":open"))
    cell["peer_closed_on_wire"] = sum(1 for x in set(wire_r) if x.endswith(":closed"))
    cell["steady_pps_wire"] = vw.steady_state_rate(syn_ts)
    cell["naive_pps_wall"] = round(total / wall, 1)  # includes startup + wait: shown only to make the bias visible
    if impl == "rust":
        try:
            s = json.loads([l for l in so.splitlines() if l.startswith("{")][-1])
        except (IndexError, ValueError):
            s = {}
        cell["transmitted_stats"] = s.get("net", {}).get("tx_sent")
        cell["received_open"] = sum(1 for x in s.get("replies", []) if x.endswith(":open"))
        cell["received_closed"] = sum(1 for x in s.get("replies", []) if x.endswith(":closed"))
        cell["steady_pps_inprocess"] = s.get("timing", {}).get("steady_pps")
        cell["tx_would_block"] = s.get("net", {}).get("tx_would_block")
        cell["net_kernel_drops"] = s.get("net", {}).get("kernel_drops")
        cell["rx_packets"] = s.get("net", {}).get("rx_packets")
        cell["reason"] = s.get("reason")
        cell["complete"] = s.get("reason") == "Completed"
        cell["rx_dedup_suppressed"] = s.get("duplicates")
    else:
        opens = [l for l in open(txt).read().splitlines() if l.startswith("open ")] if os.path.exists(txt) else []
        uniq = {tuple(l.split()[2:4]) for l in opens}
        cell["received_open"] = len(uniq)
        cell["received_open_lines"] = len(opens)
        cell["received_closed"] = None  # C -oL reports open ports only
        cell["complete"] = rc == 0
    # VALID is about the MEASUREMENT of the send rate: complete wire capture and every probe transmitted.
    # Scanner-side reply completeness is a separate column (rx_complete), never folded into VALID.
    tx_ok = rc == 0 and len(syn_ts) == total and (cell.get("transmitted_stats", total) == total)
    cell["rx_complete"] = (cell["received_open"] == cell["peer_open_on_wire"] and
                           (cell["received_closed"] is None or cell["received_closed"] == cell["peer_closed_on_wire"]))
    cell["valid"] = bool(meta["valid"] and tx_ok)
    why = []
    if not meta["valid"]:
        why.append("capture incomplete: %s" % json.dumps(meta, sort_keys=True))
    if not tx_ok:
        why.append("not every probe was transmitted (wire %d of %d, rc=%s)" % (len(syn_ts), total, rc))
    cell["invalid_reason"] = "; ".join(why) or None
    if os.path.exists(rec.pcap):
        os.unlink(rec.pcap)
    # --- stop probe: long scan, Stop/SIGINT 2.0 s in, measure time to exit and frames after
    st_ports = stop_ports
    Responder.fresh()
    srec = DumpRec(tag + ".stop")
    srec.start()
    s_total = n_probes(targets, st_ports)
    stxt = os.path.join(A.work, tag + ".stop.scan.txt")
    sf = os.path.join(A.work, tag + ".stopfile")
    if os.path.exists(sf):
        os.unlink(sf)
    if impl == "c":
        argv = wrap_c(c_args(targets, st_ports, rate, wait, stxt))
        rc2, ru2, wall2, t_stop, t_exit, so2, _ = measured(argv, stop_sig_at=2.0)
    else:
        argv = nsx(A.ns_a, [A.rust_bin] + rust_args(targets, st_ports, rate=rate, wait=wait) + ["--stop-file", sf, "--observe-ms", 0])
        rc2, ru2, wall2, t_stop, t_exit, so2, _ = measured(argv, stop_file_at=2.0, stop_file=sf)
    smeta = srec.stop()
    syns2 = len(scanner_syns(srec.frames))
    cell["stop"] = {"rc": rc2, "probes": s_total, "stop_to_exit_s": round(t_exit - t_stop, 3) if t_stop else None,
                    "wall_s": round(wall2, 3), "wire_syns": syns2, "capture_valid": smeta["valid"],
                    "stopped_early": syns2 < s_total}
    if impl == "rust":
        try:
            s2 = json.loads([l for l in so2.splitlines() if l.startswith("{")][-1])
            cell["stop"].update({"reason": s2.get("reason"), "stop_to_outcome_ms": s2["timing"]["stop_to_outcome_ms"],
                                 "join_ms": s2["timing"]["join_ms"], "tx_sent": s2["net"]["tx_sent"]})
        except (IndexError, ValueError, KeyError):
            cell["stop"]["reason"] = "unparsable"
    if os.path.exists(srec.pcap):
        os.unlink(srec.pcap)
    print("[perf] %-4s %6d rep%d valid=%s wire=%d/%d steady=%s cpu=%.2f+%.2fs rss=%sKB stop=%ss" % (
        impl, rate, rep, cell["valid"], len(syn_ts), total,
        "%.0f" % cell["steady_pps_wire"] if cell["steady_pps_wire"] else None,
        cell["cpu_user_s"] or 0, cell["cpu_sys_s"] or 0, cell["max_rss_kb"], cell["stop"]["stop_to_exit_s"]), flush=True)
    return cell


def run_perf_suite():
    cells = []
    rates = [int(x) for x in A.rates.split(",")]
    for rate in rates:
        for rep in range(1, A.reps + 1):
            for impl in ("c", "rust"):  # interleaved to share thermal/noise conditions
                try:
                    cells.append(perf_cell(impl, rate, rep))
                except Exception as e:  # noqa: BLE001
                    cells.append({"impl": impl, "rate": rate, "rep": rep, "valid": False, "invalid_reason": "driver error: %r" % e})
                    print("[perf] ERROR", impl, rate, rep, repr(e), flush=True)
                EXTRA["perf_cells"] = cells
                save_results(partial=True)
    summ = []
    for rate in rates:
        row = {"rate": rate}
        for impl in ("c", "rust"):
            cs = [c for c in cells if c["impl"] == impl and c["rate"] == rate]
            ok = [c for c in cs if c.get("valid")]
            row[impl + "_valid"] = len(ok)
            row[impl + "_invalid"] = len(cs) - len(ok)
            med = lambda key, src=ok: (statistics.median([c[key] for c in src if c.get(key) is not None])
                                       if [c for c in src if c.get(key) is not None] else None)
            row[impl + "_steady_pps_median"] = med("steady_pps_wire")
            row[impl + "_transmitted_median"] = med("transmitted_wire")
            row[impl + "_cpu_user_median"] = med("cpu_user_s")
            row[impl + "_cpu_sys_median"] = med("cpu_sys_s")
            row[impl + "_rss_kb_median"] = med("max_rss_kb")
            row[impl + "_rx_incomplete_runs"] = sum(1 for c in cs if c.get("rx_complete") is False)
            row[impl + "_capture_invalid_runs"] = sum(1 for c in cs if c.get("capture") and not c["capture"]["valid"])
            if impl == "rust":
                row["rust_kernel_drops_per_run"] = [c.get("net_kernel_drops") for c in cs]
                row["rust_would_block_total"] = sum((c.get("tx_would_block") or 0) for c in cs)
            row[impl + "_stop_s_median"] = (statistics.median([c["stop"]["stop_to_exit_s"] for c in cs
                                                               if c.get("stop") and c["stop"].get("stop_to_exit_s") is not None])
                                            if any(c.get("stop") and c["stop"].get("stop_to_exit_s") is not None for c in cs) else None)
        c, r = row["c_steady_pps_median"], row["rust_steady_pps_median"]
        row["rust_over_c"] = (r / c) if (c and r) else None
        row["within_20pct"] = (0.8 <= row["rust_over_c"] <= 1.2) if row["rust_over_c"] else None
        summ.append(row)
    EXTRA["perf_summary"] = summ
    chk("perf", "perf matrix complete: every cell VALID (incomplete captures are INVALID, not normalised)",
        all(c.get("valid") for c in cells), "%d/%d cells valid" % (sum(1 for c in cells if c.get("valid")), len(cells)))
    # Scanner-side reply completeness is asserted SEPARATELY from capture validity: a reintroduced reply loss
    # (e.g. the RX socket queuing our own outgoing frames at 100k pps) must fail here even if every capture is VALID.
    bad = [(r["rate"], r["rust_rx_incomplete_runs"], r["rust_kernel_drops_per_run"]) for r in summ
           if r["rust_rx_incomplete_runs"] != 0 or any(d != 0 for d in r["rust_kernel_drops_per_run"])]
    chk("perf", "all rates: Rust received every in-job reply (0 rx-incomplete runs, 0 kernel drops)", not bad,
        "per rate (rx_incomplete_runs, kernel_drops_per_run): " + "; ".join(
            "%d: %d, %s" % (r["rate"], r["rust_rx_incomplete_runs"], r["rust_kernel_drops_per_run"]) for r in summ))
    for row in summ:
        chk("perf", "%d pps: Rust steady-state pps within +-20%% of C" % row["rate"], row["within_20pct"],
            "rust/c=%s (rust %s vs c %s)" % ("%.3f" % row["rust_over_c"] if row["rust_over_c"] else "n/a",
                                              row["rust_steady_pps_median"], row["c_steady_pps_median"]))


def main():
    global A
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", required=True, choices=["rust", "perf"])
    for k in ("out", "work", "ns-a", "ns-b", "iface-a", "iface-b", "mac-a", "mac-b", "ip-a", "rust-bin", "oracle", "fixtures",
              "conf-masked", "empty-dir"):
        ap.add_argument("--" + k, required=(k not in ("fixtures", "empty-dir")), default="")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--rates", default="100,1000,10000,100000")
    A = ap.parse_args()
    t0 = time.time()
    if A.suite == "rust":
        run_rust_suite()
    else:
        run_perf_suite()
    EXTRA["suite"] = A.suite
    EXTRA["elapsed_s"] = round(time.time() - t0, 1)
    save_results()
    bad = [c for c in CHECKS if c["result"] == "FAIL"]
    nr = [c for c in CHECKS if c["result"] == "NOT RUN"]
    print("suite %s: %d PASS, %d FAIL, %d NOT RUN" % (A.suite, sum(1 for c in CHECKS if c["result"] == "PASS"), len(bad), len(nr)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
