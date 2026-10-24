#!/usr/bin/env python3
"""Offline verifier of the Windows wire acceptance artifacts (stage 2B-Windows, task 4A).

Independent test tool (stdlib only), NOT product code. It reads the artifacts of one
`windows-wire-suite.py` run on any OS (Mac, Linux, Windows) WITHOUT Npcap, a VM or a lab, and
reuses the Linux comparator `verify-wire.py` for the byte comparison of SYN streams.

  windows_wire_verify.py --dir FUNCTIONAL_DIR [--out verdict.json]
  windows_wire_verify.py --cases-psv           print the case list in wire-lab.sh WIRELAB_CASES_FILE form

Layout of FUNCTIONAL_DIR (written by windows-wire-suite.py and windows-oracle-fixtures.py):

  manifest.json            code commit, wire_scan.exe sha256, binding, oracle, fixtures, planned runs
  fixtures/manifest.json   C oracle fixtures (same binding, no normalisation), oracle sha256 + revision
  fixtures/<case>.run<N>.pcap
  runs/<tag>/              argv.json run.json meta.json capture.json peer.pcap eno1.pcap
                           status-pre.json status-post.json guest-verify.json listeners.json
                           (+ injector.json for the foreign-reply runs)

Verdict per run (worst wins): NOT RUN (an artifact is missing) > INVALID (the evidence cannot be trusted:
incomplete or unproven capture, drops, different builds, stand not green) > FAIL (the evidence is sound
and the behaviour is wrong) > PASS. The process exits 0 only when at least one run is planned and EVERY
planned run is PASS. A missing pcap/manifest or an invalid capture is never PASS.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("verify_wire", os.path.join(HERE, "verify-wire.py"))
vw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vw)

PASS, FAIL, INVALID, NOT_RUN = "PASS", "FAIL", "INVALID", "NOT RUN"
ORDER = [NOT_RUN, INVALID, FAIL, PASS]  # worst first

MARKER_ETHERTYPE = b"\x88\xb5"
END_PAYLOAD = b"WIRELAB-END"
FOREIGN_IP_ID = 0xF0E1  # IPv4 identification of every injected foreign reply (peer tool + verifier agree)

# ------------------------------------------------------------------ the spec
# Listeners the peer binds explicitly (nothing is discovered by the product); every other port answers RST.
# 8080/8081 are deliberately avoided: a stale listener of an earlier task still owns them in the lab netns.
LISTEN_OPEN = [80, 443] + list(range(8000, 8008))
# One port is SILENT: its listener's accept queue is full, so the kernel drops SYNs and nothing legitimate ever
# answers. A reply from it can only be foreign; it is the strict test that a bad cookie never becomes a result.
SILENT_PORT = 8099
PEER_IP = "198.18.0.2"

# name, targets, ports, exclude, source_port, expected SYN count. One lab peer address: the "multi address"
# class of the Linux suite becomes a multi-port class, and exclusions are exercised on a /30 whose other
# three addresses are excluded (nothing is ever sent to them).
CASES = [
    dict(name="c01_one_addr_port_synack", targets=PEER_IP, ports="80", exclude=None, source_port="40000", syn=1),
    dict(name="c02_one_addr_port_rst", targets=PEER_IP, ports="81", exclude=None, source_port="40000", syn=1),
    dict(name="c03_multi_ports", targets=PEER_IP, ports="8000-8015", exclude=None, source_port="40000", syn=16),
    dict(name="c04_exclude", targets="198.18.0.0/30", ports="80,81,443,82", exclude="198.18.0.0-198.18.0.1,198.18.0.3",
         source_port="40000", syn=4),
    dict(name="c05_srcport_single", targets=PEER_IP, ports="80,81,443,82", exclude=None, source_port="50123", syn=4),
    dict(name="c06_srcport_range", targets=PEER_IP, ports="80,81,443,82", exclude=None, source_port="50000-50015", syn=4),
]
FOREIGN_CASE = dict(name="x01_foreign_replies", targets=PEER_IP, ports="80,81,443,%d" % SILENT_PORT, exclude=None,
                    source_port="40000", syn=4)
PAUSE_CASE = "c03_multi_ports"
PAUSE_NS = [0, 1, 8, 15]
SEED, RATE, WAIT = 1, 100, 3


def case_by_name(name):
    for c in CASES + [FOREIGN_CASE]:
        if c["name"] == name:
            return c
    raise KeyError(name)


def port_list(spec):
    out = []
    for tok in spec.split(","):
        lo, _, hi = tok.partition("-")
        out.extend(range(int(lo), int(hi or lo) + 1))
    return out


def sport_range(spec):
    lo, _, hi = spec.partition("-")
    return int(lo), int(hi or lo)


def expected_replies(case, silent_answers=False):
    """Sorted 'ip:port:open|closed' derived ONLY from the peer's configured listeners. The silent port never
    answers on the Windows stand (silent_answers=False); the C fixture lab has no silent port (it answers RST)."""
    return sorted("%s:%d:%s" % (PEER_IP, p, "open" if p in LISTEN_OPEN else "closed")
                  for p in port_list(case["ports"]) if silent_answers or p != SILENT_PORT)


def masscan_args(case):
    a = "%s -p%s --source-port %s" % (case["targets"], case["ports"], case["source_port"])
    if case["exclude"]:
        a += " --exclude %s" % case["exclude"]
    return a


def cases_psv():
    """Cases for the C oracle lab (wire-lab.sh WIRELAB_CASES_FILE): the foreign-reply case is included for its
    SYN stream; there the silent port answers RST like any closed port."""
    lines = []
    for c in CASES + [FOREIGN_CASE]:
        exp = expected_replies(c, silent_answers=True)
        n_open = sum(x.endswith(":open") for x in exp)
        lines.append("%s|%d|%d|%d|%s" % (c["name"], c["syn"], n_open, len(exp) - n_open, masscan_args(c)))
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ helpers
class Run:
    """Collects named checks; the verdict is the worst result."""

    def __init__(self, tag):
        self.tag = tag
        self.checks = []
        self.notes = {}
        # None: the argv check did not run; True: argv.json matches the expected definition of this run kind;
        # False: it does not. A run whose argv is not proven right cannot blame the scanner for anything.
        self.argv_ok = None

    def add(self, name, result, detail="", beh=False):
        # beh: a capture-independent BEHAVIOUR check (outcome, results, health, counters, job echo). A FAIL there
        # is a failure of the scanner, whatever the state of the capture, and can never be rerun away.
        self.checks.append({"name": name, "result": result, "detail": str(detail), "behaviour": bool(beh)})

    def check(self, name, cond, detail="", bad=FAIL, beh=False):
        self.add(name, PASS if cond else bad, detail, beh)
        return bool(cond)

    @property
    def behaviour_fail(self):
        return self.argv_ok is True and any(c["behaviour"] and c["result"] == FAIL for c in self.checks)

    def _results(self):
        # a FAIL in a run whose argv is wrong or unchecked is the harness' fault: INVALID, rerunnable
        return [INVALID if (c["result"] == FAIL and self.argv_ok is not True) else c["result"] for c in self.checks]

    @property
    def verdict(self):
        res = self._results()
        for v in ORDER:
            if v in res:
                return v
        return NOT_RUN  # no check at all is never PASS

    def summary(self):
        return {"tag": self.tag, "verdict": self.verdict, "behaviour_fail": self.behaviour_fail, "notes": self.notes,
                "checks": self.checks}


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def read_json(path):
    with open(path) as f:
        return json.load(f)


def try_json(path):
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def mac_of(frame, off):
    return ":".join("%02x" % b for b in frame[off:off + 6])


def tcp_info(f):
    """(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, ipid, ack) of an IPv4/TCP frame, else None."""
    if len(f) < 54 or f[12:14] != b"\x08\x00" or f[23] != 6:
        return None
    ihl = (f[14] & 0x0F) * 4
    t = 14 + ihl
    if len(f) < t + 20:
        return None

    def ip(o):
        return ".".join(str(b) for b in f[o:o + 4])

    sp, dp = struct.unpack(">HH", f[t:t + 4])
    ack = struct.unpack(">I", f[t + 8:t + 12])[0]
    return (mac_of(f, 6), mac_of(f, 0), ip(26), ip(30), sp, dp, f[t + 13] & 0x3F, struct.unpack(">H", f[18:20])[0], ack)


class Binding:
    def __init__(self, b):
        self.src_ip = b["src_ip"]
        self.src_mac = b["src_mac"].lower()
        self.peer_mac = b["router_mac"].lower()


def scanner_syns(frames, bind, sports):
    """The scanner's SYNs: exact SYN flag, guest MAC -> peer MAC, adapter IP -> peer IP, a scan source port."""
    out = []
    for _t, f in frames:
        if not vw.is_syn(f):
            continue
        i = tcp_info(f)
        if (i and i[0] == bind.src_mac and i[1] == bind.peer_mac and i[2] == bind.src_ip and i[3] == PEER_IP
                and sports[0] <= i[4] <= sports[1]):
            out.append((_t, f))
    return out


def peer_replies(frames, bind, sports=None, genuine_only=True):
    """Unique replies the PEER sent to the scanner: 'ip:port:open|closed' from SYN-ACK / RST."""
    out = []
    for _t, f in frames:
        i = tcp_info(f)
        if not i or i[0] != bind.peer_mac or i[1] != bind.src_mac or i[3] != bind.src_ip:
            continue
        if genuine_only and i[7] == FOREIGN_IP_ID:
            continue
        if sports is not None and not (sports[0] <= i[5] <= sports[1]):
            continue
        if i[6] & 0x12 == 0x12:
            out.append("%s:%d:open" % (i[2], i[4]))
        elif i[6] & 0x04:
            out.append("%s:%d:closed" % (i[2], i[4]))
    return out


def load_pcap(run, path, label):
    """-> (frames-with-timestamps | None, bytes | None). Missing -> NOT RUN, malformed -> INVALID."""
    if not os.path.isfile(path):
        run.add("%s present" % label, NOT_RUN, "missing %s" % os.path.basename(path))
        return None, None
    data = open(path, "rb").read()
    try:
        _lt, frames = vw.read_pcap_records(data)
    except vw.PcapError as e:
        run.add("%s is a complete pcap" % label, INVALID, str(e))
        return None, data
    run.add("%s is a complete pcap" % label, PASS, "%d frames" % len(frames))
    return frames, data


# ------------------------------------------------------------------ capture / stand validity
def tcpdump_ok(st):
    return (isinstance(st, dict) and all(isinstance(st.get(k), int) and not isinstance(st.get(k), bool)
                                         for k in ("captured", "received", "dropped_kernel", "dropped_if")))


def verify_capture(run, man, d, cap, peer_frames, peer_bytes, eno_frames, eno_bytes, meta):
    """Everything that decides whether the wire evidence of ONE run is complete and trustworthy (-> INVALID)."""
    inv = lambda name, cond, detail="": run.check(name, cond, detail, bad=INVALID)  # noqa: E731
    peer, eno = cap.get("peer") or {}, cap.get("eno1") or {}
    for who, c, data, frames in (("peer", peer, peer_bytes, peer_frames), ("eno1", eno, eno_bytes, eno_frames)):
        if frames is None:
            continue
        rec = c.get("pcap") or {}
        inv("%s pcap sha256/size/frames equal the values hashed before cleanup" % who,
            rec.get("sha256") == sha256_bytes(data) and rec.get("size") == len(data) and rec.get("frames") == len(frames),
            "recorded=%s actual=%s/%d/%d" % (rec, sha256_bytes(data)[:12], len(data), len(frames)))
        st = c.get("tcpdump")
        inv("%s tcpdump statistics recorded" % who, tcpdump_ok(st), st)
        if tcpdump_ok(st):
            inv("%s capture has no kernel or interface drops" % who, st["dropped_kernel"] == 0 and st["dropped_if"] == 0, st)
            inv("%s captured == received by filter == frames in the pcap" % who,
                st["captured"] == st["received"] == len(frames), "%s vs pcap %d" % (st, len(frames)))
        inv("%s tcpdump confirmed listening before the guest started" % who, c.get("listening") is True)
        inv("%s filter recorded" % who, isinstance(c.get("filter"), str) and bool(c.get("cmd")))
    if peer_frames is not None:
        cn = peer.get("counters") or {}
        keys = ("rx_before", "tx_before", "rx_ready", "tx_ready", "rx_end", "tx_end")
        if inv("peer interface counters recorded", all(isinstance(cn.get(k), int) for k in keys), cn):
            lo = (cn["rx_end"] - cn["rx_ready"]) + (cn["tx_end"] - cn["tx_ready"])
            hi = (cn["rx_end"] - cn["rx_before"]) + (cn["tx_end"] - cn["tx_before"])
            inv("peer pcap frames lie in the lab0 rx+tx counter window [%d, %d]" % (lo, hi),
                lo <= len(peer_frames) <= hi, "frames=%d" % len(peer_frames))
        markers = [t for t, f in peer_frames if f[12:14] == MARKER_ETHERTYPE]
        inv("readiness marker is in the peer pcap (capture proven live before the guest ran)", len(markers) >= 1,
            "markers=%d" % len(markers))
        schema = cap.get("capture_schema") or 1
        inv("run capture_schema is not older than the directory's (%s)" % (man.get("capture_schema") or 1),
            schema >= (man.get("capture_schema") or 1), "run=%s dir=%s" % (schema, man.get("capture_schema") or 1))
        if schema >= 2:
            ends = [t for t, f in peer_frames if f[12:14] == MARKER_ETHERTYPE and f[14:14 + len(END_PAYLOAD)] == END_PAYLOAD]
            late = [t for t, f in peer_frames if f[12:14] != MARKER_ETHERTYPE and ends and t > max(ends)]
            inv("end marker is in the peer pcap and nothing else follows it (the capture tail was flushed)",
                len(ends) >= 1 and not late, "end_markers=%d frames_after=%d" % (len(ends), len(late)))
            inv("capture ran with --immediate-mode", "--immediate-mode" in (peer.get("cmd") or []) and
                "--immediate-mode" in (eno.get("cmd") or []), peer.get("cmd"))
        else:
            run.add("end marker not required: this run's capture_schema is 1 (older capture, tail protection absent)", PASS)
        q = cap.get("quiet") or {}
        inv("capture reached quiescence before it was stopped (peer counters unchanged)",
            q.get("reached") is True and isinstance(q.get("quiet_s"), (int, float)) and q["quiet_s"] >= 1.0, q)
        t = [meta.get(k) for k in ("capture_started_utc", "guest_started_utc", "guest_finished_utc", "capture_stopped_utc")]
        inv("capture started before the guest and stopped after it (UTC order)",
            all(isinstance(x, (int, float)) for x in t) and t == sorted(t), t)
    if eno_frames is not None:
        run.check("eno1 saw 0 lab packets (isolation)", len(eno_frames) == 0, "eno1 frames=%d" % len(eno_frames))
    # stand state
    for name in ("status-pre", "status-post"):
        s = try_json(os.path.join(d, name + ".json"))
        if s is None:
            run.add("%s.json present" % name, NOT_RUN, "missing or not JSON")
        else:
            inv("%s: raw_run_allowed true, no isolation violations" % name,
                s.get("raw_run_allowed") is True and not s.get("isolation_violations"),
                "raw_run_allowed=%s violations=%s" % (s.get("raw_run_allowed"), s.get("isolation_violations")))
    gv = try_json(os.path.join(d, "guest-verify.json"))
    if gv is None:
        run.add("guest-verify.json present", NOT_RUN, "missing or not JSON")
    else:
        inv("guest Verify ok before the run", gv.get("ok") is True, gv.get("errors"))
    li = try_json(os.path.join(d, "listeners.json"))
    if li is None:
        run.add("listeners.json present", NOT_RUN, "missing or not JSON")
    else:
        inv("peer listeners are exactly the configured open ports plus the proven-silent port",
            sorted(li.get("open", [])) == sorted(LISTEN_OPEN) and li.get("ready") is True
            and li.get("silent") == [SILENT_PORT] and li.get("silent_proven") is True, li)


def verify_identity(run, man, rj, meta):
    inv = lambda name, cond, detail="": run.check(name, cond, detail, bad=INVALID)  # noqa: E731
    ident = (rj or {}).get("identity") or {}
    exe = man.get("exe") or {}
    inv("run.json comes from the manifest's commit (not another build)",
        ident.get("source_commit") == man.get("code_commit") and bool(man.get("code_commit")),
        "run=%s manifest=%s" % (ident.get("source_commit"), man.get("code_commit")))
    inv("run.json binary sha256 == the wire_scan.exe built from that commit",
        ident.get("binary_sha256") == exe.get("sha256") and bool(exe.get("sha256")),
        "run=%s manifest=%s" % (ident.get("binary_sha256"), exe.get("sha256")))
    inv("guest hashed the same exe before the run", meta.get("exe_sha256") == exe.get("sha256"),
        "meta=%s" % meta.get("exe_sha256"))
    inv("the run was a Windows process", (ident.get("os") or {}).get("family") == "windows", ident.get("os"))


# ------------------------------------------------------------------ functional checks
SCAN_ID, ATTEMPT_1, ATTEMPT_2 = "11" * 16, "aa" * 16, "bb" * 16
ANY = "<any>"  # the flag must be present, its value is a run-local path


def base_argv(case, man, bind):
    a = {"--iface": man["binding"]["iface"], "--src-ip": bind.src_ip, "--src-mac": bind.src_mac,
         "--router-mac": bind.peer_mac, "--targets": case["targets"], "--ports": case["ports"], "--seed": str(SEED),
         "--rate": str(RATE), "--wait": str(WAIT), "--source-port": case["source_port"]}
    if case["exclude"]:
        a["--exclude"] = case["exclude"]
    return a


# kind -> (case name, function(item) -> extra flags). Every kind defines ALL of its flags: an unexpected flag is a
# harness error just like a missing or wrong one. Part B kinds are registered in KIND_ARGV_B (see below).
KIND_ARGV = {
    "case": lambda it: (it["case"], {}),
    "foreign": lambda it: (it["case"], {}),
    "pause": lambda it: (PAUSE_CASE, {"--scan-id": SCAN_ID, "--attempt-id": ATTEMPT_1, "--pause-after": str(it["n"]),
                                      "--checkpoint-out": ANY}),
    "resume": lambda it: (PAUSE_CASE, {"--scan-id": SCAN_ID, "--attempt-id": ATTEMPT_2, "--resume-checkpoint": ANY}),
    "complete_nopause": lambda it: (PAUSE_CASE, {"--scan-id": SCAN_ID, "--attempt-id": ATTEMPT_1, "--pause-after": "16",
                                                 "--checkpoint-out": ANY}),
    "refuse_completed": lambda it: (PAUSE_CASE, {"--scan-id": SCAN_ID, "--attempt-id": ATTEMPT_2, "--resume-checkpoint": ANY}),
}
# side argv files some kinds write next to argv.json (offline helper invocations)
KIND_SIDE_ARGV = {
    "refuse_completed": ("forge-argv.json", lambda it: (PAUSE_CASE, {"--scan-id": SCAN_ID, "--attempt-id": ATTEMPT_1,
                                                                     "--forge-checkpoint-next-index": "16", "--checkpoint-out": ANY})),
}


def parse_argv(av):
    out, i = {}, 0
    while i < len(av):
        t = av[i]
        if t.startswith("--"):
            if i + 1 < len(av) and not av[i + 1].startswith("--"):
                out[t] = av[i + 1]
                i += 2
                continue
            out[t] = True
        else:
            out["<positional %d>" % i] = t
        i += 1
    return out


def check_argv_file(run, d, fname, kind_def, item, man, bind):
    a = try_json(os.path.join(d, fname))
    if a is None:
        run.add("%s present" % fname, NOT_RUN, "missing or not JSON")
        return False
    got = parse_argv([str(x) for x in a.get("argv", [])])
    case_name, extra = kind_def(item)
    want = dict(base_argv(case_by_name(case_name), man, bind), **extra)
    bad = {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v and not (v == ANY and k in got)}
    bad.update({k: (v, None) for k, v in got.items() if k not in want})
    return run.check("%s matches the argument definition of run kind %r (harness input)" % (fname, item["kind"]), not bad,
                     bad or "ok", bad=INVALID)


def verify_argv(run, item, man, d, bind):
    """Central argv gate: until it is PASS no check of this run can count as a scanner failure."""
    kd = KIND_ARGV.get(item["kind"]) or KIND_ARGV_B.get(item["kind"])
    if kd is None:
        run.add("run kind has an argument definition", INVALID, item["kind"])
        run.argv_ok = False
        return False
    ok = check_argv_file(run, d, "argv.json", kd, item, man, bind)
    side = KIND_SIDE_ARGV.get(item["kind"]) or KIND_SIDE_ARGV_B.get(item["kind"])
    if side:
        ok = check_argv_file(run, d, side[0], side[1], item, man, bind) and ok
    run.argv_ok = bool(ok)
    return run.argv_ok


KIND_ARGV_B = {}
KIND_SIDE_ARGV_B = {}


def job_matches(run, rj, case, bind, man, d):
    job = (rj or {}).get("job") or {}
    want = {"iface": man["binding"]["iface"], "src_ip": bind.src_ip, "src_mac": bind.src_mac, "router_mac": bind.peer_mac,
            "source_port": case["source_port"], "targets": case["targets"], "exclude": case["exclude"],
            "ports": case["ports"], "seed": SEED, "rate": RATE, "wait": WAIT, "retries": 0, "shard": "1/1",
            "blackrock_rounds": 14}
    bad = {k: (job.get(k), v) for k, v in want.items() if job.get(k) != v}
    # the engine echoed another job than the (verified) argv asked for: a scanner failure; with a wrong argv the
    # Run maps every FAIL to INVALID
    run.check("run.json job echo == the case and the binding", not bad, bad or "ok", beh=True)


def health_measured_zero(rj):
    h = (rj or {}).get("rx_health") or {}
    d = h.get("kernel_drops")
    n = ((rj or {}).get("net") or {}).get("kernel_drops")
    return isinstance(d, int) and not isinstance(d, bool) and d == 0 and isinstance(n, int) and not isinstance(n, bool) and n == 0


def net_clean(rj):
    n = (rj or {}).get("net") or {}
    return n.get("tx_uncertain") == 0 and n.get("tx_errors") == 0 and n.get("rx_errors") == 0


def load_fixture(run, root, man, fx, case_name):
    """-> (fixture SYN-stream pcap bytes, fixture frames) after proving the fixture is the one the manifest names."""
    ent = (fx.get("fixtures") or {}).get("%s.run1" % case_name)
    if not ent:
        run.add("fixture for %s listed" % case_name, NOT_RUN, "no entry in fixtures/manifest.json")
        return None, None
    path = os.path.join(root, ent["file"])
    if not os.path.isfile(path):
        run.add("fixture %s present" % ent["file"], NOT_RUN, "missing")
        return None, None
    data = open(path, "rb").read()
    run.check("fixture sha256 == fixtures/manifest.json", sha256_bytes(data) == ent.get("sha256"),
              "%s vs %s" % (sha256_bytes(data)[:12], str(ent.get("sha256"))[:12]), bad=INVALID)
    try:
        _lt, frames = vw.read_pcap_records(data)
    except vw.PcapError as e:
        run.add("fixture is a complete pcap", INVALID, str(e))
        return None, None
    return data, frames


def verify_fixture_binding(run, fx, man, bind):
    """The C fixtures must have been generated for THE SAME binding: no MAC/IP normalisation is allowed."""
    b = fx.get("binding") or {}
    want = {"src_ip": bind.src_ip, "src_mac": bind.src_mac, "router_mac": bind.peer_mac, "seed": SEED, "rate": RATE}
    bad = {k: (b.get(k), v) for k, v in want.items() if str(b.get(k)).lower() != str(v).lower()}
    run.check("fixtures were generated for the same source IP/MAC and peer MAC (no normalisation)", not bad,
              bad or "ok", bad=INVALID)
    o = fx.get("oracle") or {}
    run.check("fixtures name the oracle binary sha256 and the pinned revision",
              bool(o.get("sha256")) and bool(o.get("git_commit")) and o.get("git_tree_clean") is True and fx.get("all_valid") is True,
              {k: o.get(k) for k in ("sha256", "git_commit", "git_tree_clean")}, bad=INVALID)


def fixture_frames_match_binding(run, frames, bind, sports):
    syns = scanner_syns(frames, bind, sports)
    n_syn = sum(1 for _t, f in frames if vw.is_syn(f))
    run.check("every SYN in the C fixture carries the guest MAC, peer MAC and adapter IP", len(syns) == n_syn and n_syn > 0,
              "binding-matching=%d all=%d" % (len(syns), n_syn), bad=INVALID)


def verify_continuous(run, root, man, fx, d, case, peer_frames, peer_bytes, rj, rc, bind):
    """One complete run against the C oracle fixture and the configured listeners."""
    sports = sport_range(case["source_port"])
    exp = expected_replies(case)
    n_open = sum(x.endswith(":open") for x in exp)
    job_matches(run, rj, case, bind, man, d)
    run.check("guest exit code 0", rc == 0, "rc=%s" % rc, beh=True)
    run.check("outcome Completed", (rj or {}).get("status") == "ok" and rj.get("reason") == "Completed",
              "status=%s reason=%s detail=%s" % ((rj or {}).get("status"), (rj or {}).get("reason"), (rj or {}).get("fail_detail")), beh=True)
    run.check("sent == next_index == range == expected SYN count (%d)" % case["syn"],
              rj.get("sent") == rj.get("next_index") == rj.get("range") == rj.get("expected_total") == case["syn"],
              {k: rj.get(k) for k in ("sent", "next_index", "range", "expected_total")}, beh=True)
    run.check("rx_health.kernel_drops is a MEASURED 0 (not null)", health_measured_zero(rj),
              "rx_health=%s net.kernel_drops=%s" % (rj.get("rx_health"), (rj.get("net") or {}).get("kernel_drops")), beh=True)
    run.check("net.tx_sent == sent, no uncertain/error TX, no RX errors",
              (rj.get("net") or {}).get("tx_sent") == rj.get("sent") and net_clean(rj), rj.get("net"), beh=True)
    run.check("results == expected Open/Closed from the peer's listeners (%d open, %d closed)" % (n_open, len(exp) - n_open),
              rj.get("replies") == exp and rj.get("reply_total") == rj.get("reply_unique") == len(exp),
              "got=%s want=%s total=%s unique=%s" % (rj.get("replies"), exp, rj.get("reply_total"), rj.get("reply_unique")), beh=True)
    if peer_frames is None:
        return
    fdata, fframes = load_fixture(run, root, man, fx, case["name"])
    if fframes is not None:
        fixture_frames_match_binding(run, fframes, bind, sports)
        code, msg = vw.compare_bytes(fdata, peer_bytes)
        run.add("SYN bytes and order == C oracle fixture (byte-exact)", {0: PASS, 1: FAIL, 2: INVALID}[code], msg)
        # a SYN from anyone else on the wire would be hidden by the comparison above only if it were not a SYN
        n_all = sum(1 for _t, f in peer_frames if vw.is_syn(f))
        n_scan = len(scanner_syns(peer_frames, bind, sports))
        run.check("no SYN on the wire other than the scanner's", n_all == n_scan == case["syn"],
                  "all=%d scanner=%d want=%d" % (n_all, n_scan, case["syn"]))
        c_replies = sorted(set(peer_replies(fframes, bind)))
        c_exp = expected_replies(case, silent_answers=True)
        run.check("C oracle replies on the wire == expected from the listeners (cross-check of the stand)",
                  c_replies == c_exp, "c=%s want=%s" % (c_replies, c_exp))
    wire = peer_replies(peer_frames, bind, sports)
    run.check("peer replies on the wire == results (extra copies are suppressed duplicates)",
              sorted(set(wire)) == exp and rj.get("received", 0) + rj.get("duplicates", 0) <= len(wire),
              "wire=%d unique=%s received=%s duplicates=%s" % (len(wire), sorted(set(wire)), rj.get("received"), rj.get("duplicates")))


def stray_frames(peer_frames, bind, sports):
    """Frames addressed to the guest that are neither injected, genuine scan replies nor the lab markers, inside the
    scan's receive window (first SYN .. last SYN + wait). The engine counts every non-reply frame it receives as
    discarded, e.g. the peer kernel's unicast ARP probe, so they are part of the expected `discarded`."""
    syns = scanner_syns(peer_frames, bind, sports)
    if not syns:
        return []
    t0, t1 = syns[0][0], syns[-1][0] + WAIT
    out = []
    for t, f in peer_frames:
        # what the guest's Npcap RX can see: unicast to the guest or broadcast/multicast, never the guest's own frames
        to_guest = f[0:6] == mac_b(bind.src_mac) or bool(f[0] & 1)
        if not (t0 <= t <= t1) or not to_guest or f[6:12] == mac_b(bind.src_mac) or f[12:14] == MARKER_ETHERTYPE:
            continue
        i = tcp_info(f)
        if i and i[7] == FOREIGN_IP_ID:
            continue
        if i and i[0] == bind.peer_mac and i[3] == bind.src_ip and sports[0] <= i[5] <= sports[1] and (i[6] & 0x12 == 0x12 or i[6] & 0x04):
            continue
        out.append((t, f))
    return out


def mac_b(m):
    return bytes(int(x, 16) for x in m.split(":"))


def verify_foreign(run, peer_frames, rj, case, bind, inj):
    """Replies with another IP / port / cookie are on the wire and must not have become results."""
    sports = sport_range(case["source_port"])
    exp = expected_replies(case)
    run.check("no foreign reply became a result (results == listener truth exactly)", rj.get("replies") == exp,
              "got=%s want=%s" % (rj.get("replies"), exp), beh=True)
    if inj is None:
        run.add("injector.json present", NOT_RUN, "missing")
        return
    sent = inj.get("sent_total")
    d = rj.get("discarded")
    strays_seen = stray_frames(peer_frames, bind, sports) if peer_frames is not None else []
    # capture-independent floor: every injected frame AND every stray frame seen in the pcap was discarded by the
    # engine. A lossy capture can only hide strays, never invent them, so a count below this floor is a scanner failure.
    run.check("engine discarded >= injected + strays seen (nothing absorbed as a result or duplicate)",
              isinstance(d, int) and isinstance(sent, int) and d >= sent + len(strays_seen),
              "discarded=%s injected=%s strays_seen=%d" % (d, sent, len(strays_seen)), beh=True)
    if peer_frames is None:
        return
    foreign = [(t, f) for t, f in peer_frames if (tcp_info(f) or (0,) * 9)[7] == FOREIGN_IP_ID]
    kinds = inj.get("kinds") or {}
    run.check("every injected foreign frame is in the peer pcap (they really reached the wire)",
              inj.get("sent_total", 0) > 0 and len(foreign) == inj.get("sent_total") and
              all(inj["kinds"].get(k, 0) > 0 for k in ("other_ip", "unscanned_port", "wrong_cookie", "wrong_dst_port")),
              "injected=%s on_wire=%d kinds=%s" % (inj.get("sent_total"), len(foreign), kinds), bad=INVALID)
    syns = scanner_syns(peer_frames, bind, sports)
    if syns and foreign:
        t0, t1 = syns[0][0], syns[-1][0] + WAIT
        inside = [t for t, _f in foreign if t0 <= t <= t1]
        run.check("foreign frames arrived inside the scan's receive window", len(inside) >= 1,
                  "inside=%d of %d" % (len(inside), len(foreign)), bad=INVALID)
    strays = strays_seen
    run.notes["strays_in_rx_window"] = len(strays)
    run.notes["injected"] = sent
    # the upper bound needs a COMPLETE capture (a stray the capture lost would explain extra discards): FAIL only
    # when the capture is proven complete, else INVALID (rerunnable)
    proven = not any(c["result"] in (INVALID, NOT_RUN) for c in run.checks)
    run.check("engine discarded <= injected + strays (no unexplained discards)",
              isinstance(d, int) and d <= sent + len(strays), "discarded=%s injected=%s strays=%d capture_proven_complete=%s" % (d, sent, len(strays), proven),
              bad=FAIL if proven else INVALID, beh=proven)
    genuine = len(peer_replies(peer_frames, bind, sports))
    run.check("duplicates are genuine peer retransmits only (received + duplicates <= genuine replies on the wire)",
              isinstance(rj.get("duplicates"), int) and rj.get("received", 0) + rj["duplicates"] <= genuine,
              "received=%s duplicates=%s genuine_on_wire=%d" % (rj.get("received"), rj.get("duplicates"), genuine))


# ------------------------------------------------------------------ run dispatch
def load_run(man, root, item, rel=None):
    """Common loading + validity for one planned run. -> (Run, ctx|None). rel: directory relative to root."""
    run = Run(item["tag"])
    rel = rel or os.path.join("runs", item["tag"])
    d = os.path.join(root, rel)
    if not os.path.isdir(d):
        run.add("run directory present", NOT_RUN, "missing %s" % rel)
        return run, None
    bind = Binding(man["binding"])
    rj = try_json(os.path.join(d, "run.json"))
    meta = try_json(os.path.join(d, "meta.json"))
    cap = try_json(os.path.join(d, "capture.json"))
    for name, v in (("run.json", rj), ("meta.json", meta), ("capture.json", cap)):
        if v is None:
            run.add("%s present" % name, NOT_RUN, "missing or not JSON")
    peer_frames, peer_bytes = load_pcap(run, os.path.join(d, "peer.pcap"), "peer.pcap")
    eno_frames, eno_bytes = load_pcap(run, os.path.join(d, "eno1.pcap"), "eno1.pcap")
    if rj is None or meta is None or cap is None:
        return run, None
    verify_identity(run, man, rj, meta)
    verify_capture(run, man, d, cap, peer_frames, peer_bytes, eno_frames, eno_bytes, meta)
    return run, dict(d=d, rj=rj, meta=meta, cap=cap, peer_frames=peer_frames, peer_bytes=peer_bytes, bind=bind)


def verify_item(man, fx, root, item, ctxs, rel=None):
    run, ctx = load_run(man, root, item, rel)
    ctxs[item["tag"]] = ctx
    if ctx is None:
        return run
    rj, rc, bind = ctx["rj"], ctx["meta"].get("guest_exit"), ctx["bind"]
    kind = item["kind"]
    verify_argv(run, item, man, ctx["d"], bind)
    if fx:
        verify_fixture_binding(run, fx, man, bind)
    else:
        run.add("fixtures/manifest.json present", NOT_RUN, "missing")
    if kind in ("case", "foreign"):
        case = case_by_name(item["case"])
        if fx:
            verify_continuous(run, root, man, fx, ctx["d"], case, ctx["peer_frames"], ctx["peer_bytes"], rj, rc, bind)
        else:
            run.add("fixtures/manifest.json present", NOT_RUN, "missing")
        if kind == "foreign":
            verify_foreign(run, ctx["peer_frames"], rj, case, bind, try_json(os.path.join(ctx["d"], "injector.json")))
    elif kind == "pause":
        verify_pause_leg(run, root, man, fx, item, ctx)
    elif kind == "resume":
        verify_resume_leg(run, root, man, fx, item, ctx)
    elif kind == "complete_nopause":
        case = case_by_name(PAUSE_CASE)
        run.check("pause-after == range ends Completed with NO checkpoint",
                  rc == 0 and rj.get("reason") == "Completed" and rj.get("checkpoint") is False and rj.get("sent") == case["syn"],
                  {k: rj.get(k) for k in ("reason", "checkpoint", "sent")}, beh=True)
        run.check("rx_health measured 0", health_measured_zero(rj), rj.get("rx_health"), beh=True)
    elif kind == "refuse_completed":
        sports = sport_range(case_by_name(PAUSE_CASE)["source_port"])
        frames = ctx["peer_frames"]
        run.check("completed job is refused (AlreadyCompleted) before the adapter opens",
                  rc == 4 and rj.get("status") == "error" and str(rj.get("error", "")).startswith("AlreadyCompleted")
                  and rj.get("opened_adapter") is False and rj.get("tx_sent") == 0,
                  {k: rj.get(k) for k in ("status", "error", "opened_adapter", "tx_sent")} | {"rc": rc}, beh=True)
        if frames is not None:
            run.check("no scanner SYN reached the wire", len(scanner_syns(frames, bind, sports)) == 0,
                      "syns=%d" % len(scanner_syns(frames, bind, sports)))
    else:
        run.add("known run kind", FAIL, kind)
    return run


def verify_pause_leg(run, root, man, fx, item, ctx):
    rj, rc, n = ctx["rj"], ctx["meta"].get("guest_exit"), item["n"]
    case = case_by_name(PAUSE_CASE)
    job_matches(run, rj, case, ctx["bind"], man, ctx["d"])
    run.check("N=%d pause leg: rc 0, Paused, sent=%d, next_index=%d, checkpoint written" % (n, n, n),
              rc == 0 and rj.get("reason") == "Paused" and rj.get("sent") == n and rj.get("next_index") == n
              and rj.get("checkpoint") is True and rj.get("checkpoint_next_index") == n,
              {k: rj.get(k) for k in ("reason", "sent", "next_index", "checkpoint", "checkpoint_next_index")} | {"rc": rc}, beh=True)
    run.check("N=%d pause leg: rx_health measured 0, net.tx_sent == %d" % (n, n),
              health_measured_zero(rj) and (rj.get("net") or {}).get("tx_sent") == n and net_clean(rj), rj.get("net"), beh=True)
    cp = os.path.join(ctx["d"], "checkpoint.bin")
    run.check("checkpoint file recorded", os.path.isfile(cp), cp, bad=NOT_RUN)


def verify_resume_leg(run, root, man, fx, item, ctx):
    rj, rc, n = ctx["rj"], ctx["meta"].get("guest_exit"), item["n"]
    case = case_by_name(PAUSE_CASE)
    job_matches(run, rj, case, ctx["bind"], man, ctx["d"])
    run.check("N=%d resume leg: rc 0, Completed, sent=%d" % (n, case["syn"] - n),
              rc == 0 and rj.get("reason") == "Completed" and rj.get("sent") == case["syn"] - n
              and rj.get("start_index") == n and rj.get("next_index") == case["syn"],
              {k: rj.get(k) for k in ("reason", "sent", "start_index", "next_index")} | {"rc": rc}, beh=True)
    run.check("N=%d resume leg: rx_health measured 0" % n, health_measured_zero(rj) and net_clean(rj), rj.get("rx_health"), beh=True)


def verify_pause_groups(man, fx, root, runs_by_tag, ctxs):
    """pause leg + resume leg == continuous == C oracle (bytes and order); identities; reply union."""
    out = []
    case = case_by_name(PAUSE_CASE)
    sports = sport_range(case["source_port"])
    exp = expected_replies(case)
    for n in PAUSE_NS:
        run = Run("group_pause_resume_N%d" % n)
        a, b = "pause_N%d" % n, "resume_N%d" % n
        ca, cb = ctxs.get(a), ctxs.get(b)
        if ca is None or cb is None:
            run.add("both legs have usable artifacts", NOT_RUN, "pause=%s resume=%s" % (ca is not None, cb is not None))
            out.append(run)
            continue
        cont = ctxs.get("c03_multi_ports.run1")
        needed = [a, b, "c03_multi_ports.run1"]
        usable = all(ctxs.get(t) is not None and ctxs[t]["peer_bytes"] is not None and ctxs[t]["peer_frames"] is not None
                     for t in needed)
        if not usable:
            run.add("pause leg, resume leg and the continuous run have usable captures", NOT_RUN,
                    {t: (ctxs.get(t) is not None and ctxs[t]["peer_bytes"] is not None) for t in needed})
            out.append(run)
            continue
        bad_legs = [t for t in (a, b) if runs_by_tag[t].verdict != PASS]
        if bad_legs:
            vs = [runs_by_tag[t].verdict for t in bad_legs]
            run.add("both legs PASS on their own", NOT_RUN if NOT_RUN in vs else INVALID if INVALID in vs else FAIL,
                    {t: runs_by_tag[t].verdict for t in bad_legs})
            out.append(run)
            continue
        run.argv_ok = True  # both legs PASS on their own, so their argv was verified
        ra, rb = ca["rj"], cb["rj"]
        run.check("scan_id constant, attempt_id new, resume origin recorded",
                  ra["scan_id"] == rb["scan_id"] and ra["attempt_id"] != rb["attempt_id"]
                  and rb.get("resumed_from_attempt") == ra["attempt_id"] and ra.get("resumed_from_attempt") is None,
                  "scan=%s.. a1=%s.. a2=%s.. from=%s.." % (ra["scan_id"][:6], ra["attempt_id"][:6], rb["attempt_id"][:6],
                                                           str(rb.get("resumed_from_attempt"))[:6]))
        fdata, _fframes = load_fixture(run, root, man, fx or {}, case["name"]) if fx else (None, None)
        legs = [ca["peer_bytes"], cb["peer_bytes"]]
        if fdata is not None:
            code, msg = vw.compare_bytes(fdata, legs)
            run.add("N=%d pause SYNs + resume SYNs == C oracle (bytes and order)" % n, {0: PASS, 1: FAIL, 2: INVALID}[code], msg)
        code, msg = vw.compare_bytes(cont["peer_bytes"], legs)
        run.add("N=%d pause SYNs + resume SYNs == continuous Rust run (bytes and order)" % n,
                {0: PASS, 1: FAIL, 2: INVALID}[code], msg)
        na = len(scanner_syns(ca["peer_frames"], ca["bind"], sports))
        nb = len(scanner_syns(cb["peer_frames"], cb["bind"], sports))
        run.check("no probe lost or added across the seam (SYN counts %d + %d)" % (n, case["syn"] - n),
                  na == n and nb == case["syn"] - n, "pause=%d resume=%d" % (na, nb))
        union = sorted(ra["replies"] + rb["replies"])
        run.check("replies of both legs == expected, no duplicates", union == exp and len(set(union)) == len(union),
                  "legs=%d+%d union=%d" % (len(ra["replies"]), len(rb["replies"]), len(set(union))))
        out.append(run)
    return out


def planned(man):
    items = []
    for c in CASES:
        for r in (1, 2):
            items.append(dict(tag="%s.run%d" % (c["name"], r), kind="case", case=c["name"], repeat=r))
    for r in (1, 2):
        items.append(dict(tag="%s.run%d" % (FOREIGN_CASE["name"], r), kind="foreign", case=FOREIGN_CASE["name"], repeat=r))
    for n in PAUSE_NS:
        items.append(dict(tag="pause_N%d" % n, kind="pause", n=n))
        items.append(dict(tag="resume_N%d" % n, kind="resume", n=n))
    items.append(dict(tag="complete_nopause", kind="complete_nopause"))
    items.append(dict(tag="refuse_completed", kind="refuse_completed"))
    return items


def verify_dir(root):
    """-> verdict dict. The plan is the spec above, NOT whatever happens to be on disk: a run that is absent is NOT RUN."""
    result = {"schema": 1, "dir": os.path.basename(os.path.abspath(root)), "runs": [], "groups": []}
    man = try_json(os.path.join(root, "manifest.json"))
    if man is None:
        r = Run("manifest")
        r.add("manifest.json present and valid JSON", NOT_RUN, "missing")
        result["runs"].append(r.summary())
        return finish(result)
    fx = try_json(os.path.join(root, "fixtures", "manifest.json"))
    run0 = Run("manifest")
    for k in ("code_commit", "exe", "binding"):
        run0.check("manifest.%s present" % k, bool(man.get(k)), bad=NOT_RUN)
    run0.check("manifest.exe.sha256 present", bool((man.get("exe") or {}).get("sha256")), bad=NOT_RUN)
    run0.check("fixtures/manifest.json present", fx is not None, bad=NOT_RUN)
    result["runs"].append(run0.summary())
    if run0.verdict != PASS:
        return finish(result)
    ctxs, by_tag = {}, {}
    for item in planned(man):
        r = verify_item(man, fx, root, item, ctxs)
        by_tag[item["tag"]] = r
        result["runs"].append(r.summary())
    for g in verify_pause_groups(man, fx, root, by_tag, ctxs):
        result["groups"].append(g.summary())
    result["discarded"] = verify_discarded(man, fx, root)
    return finish(result)


def verify_discarded(man, fx, root):
    """Every run moved to runs_discarded/ is verified and listed. INVALID/NOT RUN may be superseded by a rerun;
    a PASS or FAIL may not (finish() makes overall FAIL for a FAIL, INVALID for a PASS that was discarded)."""
    out = []
    base = os.path.join(root, "runs_discarded")
    if not os.path.isdir(base):
        return out
    by_tag = {i["tag"]: i for i in planned(man)}
    for name in sorted(os.listdir(base)):
        if not os.path.isdir(os.path.join(base, name)):
            continue
        tag = name.rsplit(".", 1)[0]
        item = by_tag.get(tag)
        if item is None:
            r = Run(name)
            r.argv_ok = True
            r.add("discarded run belongs to a planned tag", FAIL, "unknown tag %s" % tag)
        else:
            r = verify_item(man, fx, root, dict(item, tag=name), {}, rel=os.path.join("runs_discarded", name))
        s = r.summary()
        s["tag"] = name
        out.append(s)
    return out


def finish(result):
    verdicts = [r["verdict"] for r in result["runs"]] + [g["verdict"] for g in result["groups"]]
    disc = [r["verdict"] for r in result.get("discarded", [])]
    result["totals"] = {v: verdicts.count(v) for v in ORDER}
    result["discarded_totals"] = {v: disc.count(v) for v in ORDER}
    result["overall"] = PASS if verdicts and all(v == PASS for v in verdicts) else (
        NOT_RUN if NOT_RUN in verdicts else INVALID if INVALID in verdicts else FAIL)
    beh = [r["tag"] for r in result["runs"] + result["groups"] + result.get("discarded", []) if r.get("behaviour_fail")]
    result["behaviour_fail"] = beh
    if beh:  # a behaviour failure wins over INVALID/NOT RUN, in a kept or a discarded run
        result["overall"] = FAIL
    elif FAIL in disc:  # a behaviour failure can never be rerun away
        result["overall"] = FAIL
    elif PASS in disc and result["overall"] == PASS:  # a PASS must not be discarded either
        result["overall"] = INVALID
    return result


def run_status(root, tag):
    """(verdict, behaviour_fail) of runs/<tag> alone (used by the orchestrator before it discards a run)."""
    man = try_json(os.path.join(root, "manifest.json"))
    fx = try_json(os.path.join(root, "fixtures", "manifest.json"))
    item = {i["tag"]: i for i in planned(man or {})}.get(tag)
    if man is None or item is None:
        return NOT_RUN, False
    r = verify_item(man, fx, root, item, {})
    return r.verdict, r.behaviour_fail


def run_verdict(root, tag):
    return run_status(root, tag)[0]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir")
    ap.add_argument("--out")
    ap.add_argument("--cases-psv", action="store_true")
    a = ap.parse_args()
    if a.cases_psv:
        sys.stdout.write(cases_psv())
        return 0
    if not a.dir:
        ap.error("--dir is required")
    res = verify_dir(a.dir)
    if a.out:
        with open(a.out, "w") as f:
            json.dump(res, f, indent=1, sort_keys=True)
            f.write("\n")
    for r in res["runs"] + res["groups"] + res.get("discarded", []):
        bad = [c for c in r["checks"] if c["result"] != PASS]
        print("%-8s %s%s" % (r["verdict"], r["tag"], "" if not bad else "  <- " + "; ".join("%s: %s [%s]" % (c["result"], c["name"], c["detail"][:160]) for c in bad[:3])))
    print("overall: %s  %s  discarded: %s  behaviour_fail: %s" % (res["overall"], res["totals"], res.get("discarded_totals"),
                                                                 res.get("behaviour_fail")))
    return 0 if res["overall"] == PASS else (1 if res["overall"] == FAIL else 2)


if __name__ == "__main__":
    sys.exit(main())
