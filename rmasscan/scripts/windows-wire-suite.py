#!/usr/bin/env python3
"""Orchestrator of the Windows wire acceptance on the isolated lab stand (stage 2B-Windows, task 4A).

Runs on the operator machine (Mac/Linux), drives home-pc (the VM host) and the Windows guest over ssh. Test
tool (stdlib only), NOT product code. It never brings the stand up or down, never restarts the VM and never
touches firewall/routes/NICs; it only starts and stops its OWN peer-side listeners, injector and captures.

  windows-wire-suite.py --out DIR --commit FULL_SHA --guest-exe C:\\...\\wire_scan.exe --fixtures DIR [--only TAG ...]

For EVERY raw run, in this order (any failure of a gate stops the suite; the run directory is kept):
  1. guest Verify (windows-vm-lab.ps1) + record-guest + the full `status` with raw_run_allowed true
  2. peer-side explicit listeners (open ports + one proven-silent port), restarted for every run
  3. peer capture (tcpdump -i lab0, all frames, full snaplen) and eno1 capture, both confirmed listening;
     a marker frame proves the peer capture is live BEFORE the guest starts
  4. the guest runs wire_scan.exe with an argv ARRAY (JSON file, no shell quoting) via windows_wire_run.ps1
  5. listeners stopped, peer counters waited quiet (drain), captures stopped, pcaps hashed on home-pc BEFORE
     anything is copied or cleaned
  6. `status` again; artifacts copied back; capture.json/meta.json written for the offline verifier
Verdicts are NOT produced here: `windows_wire_verify.py --dir DIR` reads the artifacts offline.
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, os.path.join(HERE, fname))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


V = _load("windows_wire_verify", "windows_wire_verify.py")
P = _load("windows_wire_peer", "windows_wire_peer.py")

NS = "wvp-n2"
LAB = "$HOME/winvm/lab"
RUN_ID = "n2"
MAN = LAB + "/n2.json"
LAB_NIC = "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}"
GUEST_MAC = "52:54:00:04:80:a9"
PEER_MAC_DEFAULT = "02:57:4c:3d:2e:9b"
SRC_IP = "198.18.0.1"
REMOTE = "~/winvm/t4"           # tools on home-pc (made absolute in main(): sudo shells have another $HOME)
REMOTE_EV = "~/winvm/t4-ev"      # per-run scratch on home-pc (removed after the copy is verified)
GUEST_HOME = "C:\\Users\\lab\\"
GUEST_DIR = GUEST_HOME + "t4"
SCAN_ID, ATTEMPT_1, ATTEMPT_2 = "11" * 16, "aa" * 16, "bb" * 16
QMP_SOCK = "$HOME/winvm/qmp.sock"
QUIET_S = 1.5
CAPTURE_SCHEMA = 2  # 2: --immediate-mode + end marker before SIGINT (recorded per run in capture.json)
CTL = os.path.expanduser("~/.ssh/wws-%C")
SSH_BASE = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto", "-o", "ControlPersist=300",
            "-o", "ControlPath=" + CTL]


class SuiteAbort(Exception):
    pass


# ------------------------------------------------------------------ pure helpers (unit tested)
def scan_argv(case, iface, src_mac, peer_mac, extra=()):
    """The exact argv of wire_scan.exe: every parameter explicit, nothing implicit."""
    a = ["--iface", iface, "--src-ip", SRC_IP, "--src-mac", src_mac, "--router-mac", peer_mac,
         "--targets", case["targets"], "--ports", case["ports"], "--seed", str(V.SEED), "--rate", str(V.RATE),
         "--wait", str(V.WAIT), "--source-port", case["source_port"]]
    if case["exclude"]:
        a += ["--exclude", case["exclude"]]
    return a + [str(x) for x in extra]


def parse_tcpdump(err):
    """Statistics tcpdump prints on SIGINT. Unparsed values stay None (never silently 0)."""
    def num(rx):
        m = re.search(rx, err)
        return int(m.group(1)) if m else None
    return {"listening": "listening on" in err, "captured": num(r"(\d+) packets? captured"),
            "received": num(r"(\d+) packets? received by filter"), "dropped_kernel": num(r"(\d+) packets? dropped by kernel"),
            "dropped_if": num(r"(\d+) packets? dropped by interface") or 0}


def wait_quiet(read, quiet_s, poll_s, timeout_s, clock=time.time, sleep=time.sleep):
    """Block until read() was unchanged for quiet_s; True if it got quiet, False on timeout."""
    prev, quiet_since, end = None, clock(), clock() + timeout_s
    while clock() < end:
        sleep(poll_s)
        cur = read()
        now = clock()
        if cur != prev:
            prev, quiet_since = cur, now
        elif now - quiet_since >= quiet_s:
            return True
    return False


def foreign_frames(peer_mac, guest_mac, src_ip, sport):
    return P.foreign_kinds(peer_mac, guest_mac, src_ip, sport, V.SILENT_PORT)


# ------------------------------------------------------------------ transport
def log(msg):
    print("[%s] %s" % (time.strftime("%H:%M:%S"), msg), flush=True)


def sh(argv, timeout=120, check=True, input=None):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input)
    if check and r.returncode:
        raise SuiteAbort("%s -> rc=%d: %s" % (" ".join(shlex.quote(x) for x in argv)[:200], r.returncode, (r.stderr or r.stdout).strip()[:400]))
    return r


def home(cmd, timeout=120, check=True):
    """Run a shell command string on home-pc."""
    return sh(["ssh"] + SSH_BASE + ["home-pc", cmd], timeout=timeout, check=check)


def guest(cmd, timeout=300, check=True):
    """Run a command line in the guest (default shell cmd.exe; only simple tokens are passed)."""
    return sh(["ssh"] + SSH_BASE + ["-J", "home-pc", "-p", "2222", "lab@127.0.0.1", cmd], timeout=timeout, check=check)


def from_home(remote, local):
    sh(["scp", "-q"] + SSH_BASE + ["home-pc:" + remote, local])


def to_home(local, remote):
    sh(["scp", "-q"] + SSH_BASE + [local, "home-pc:" + remote])


def grel(path):
    """scp paths in the guest are relative to the home directory."""
    return (path[len(GUEST_HOME):] if path.startswith(GUEST_HOME) else path).replace("\\", "/")


def from_guest(remote, local):
    sh(["scp", "-q"] + SSH_BASE + ["-J", "home-pc", "-P", "2222", "lab@127.0.0.1:" + grel(remote), local])


def to_guest(local, remote):
    sh(["scp", "-q"] + SSH_BASE + ["-J", "home-pc", "-P", "2222", local, "lab@127.0.0.1:" + grel(remote)])


def peer_ns(cmd, sudo=True):
    """Shell fragment: run `cmd` (a string) as root inside the lab peer namespace."""
    return "%sip netns exec %s %s" % ("sudo -n " if sudo else "", NS, cmd)


def ports_spec(ports):
    """[8099, 8100, ..., 8119] -> '8099,8100-8119' (the peer tool's list syntax)."""
    out, ps = [], sorted(ports)
    i = 0
    while i < len(ps):
        j = i
        while j + 1 < len(ps) and ps[j + 1] == ps[j] + 1:
            j += 1
        out.append(str(ps[i]) if i == j else "%d-%d" % (ps[i], ps[j]))
        i = j + 1
    return ",".join(out)


def peer_mac():
    out = home(peer_ns("cat /sys/class/net/lab0/address")).stdout.strip().lower()
    if not re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", out):
        raise SuiteAbort("cannot read the peer lab0 MAC: %r" % out)
    return out


def counters():
    out = home(peer_ns("python3 %s/windows_wire_peer.py counters --iface lab0" % REMOTE)).stdout.split()
    return int(out[0]), int(out[1])


def remote_bg(cmd, pidfile, errfile, outfile="/dev/null"):
    """Start `cmd` as root in the background on home-pc; its PID is written to pidfile."""
    inner = "echo $$ > %s; exec %s" % (pidfile, cmd)
    home("nohup sudo -n sh -c %s > %s 2> %s < /dev/null &" % (shlex.quote(inner), outfile, errfile), timeout=30)


def remote_wait(cond, secs, what):
    end = time.time() + secs
    while time.time() < end:
        if home(cond, check=False).returncode == 0:
            return
        time.sleep(0.2)
    raise SuiteAbort("timeout waiting for " + what)


def remote_stop(pidfile, sig="INT"):
    home("[ -s %s ] && sudo -n kill -%s $(cat %s) 2>/dev/null; true" % (pidfile, sig, pidfile), check=False)


def remote_wait_exit(pidfile, secs=20):
    end = time.time() + secs
    while time.time() < end:
        if home("[ -s %s ] && [ -d /proc/$(cat %s) ]" % (pidfile, pidfile), check=False).returncode != 0:
            return True
        time.sleep(0.2)
    return False


# ------------------------------------------------------------------ gates
def gate(ev, evdir_remote):
    """Guest Verify + record-guest + full status: raw_run_allowed must be true, else stop."""
    guest("cd C:\\Users\\lab && pwsh -NoProfile -File windows-vm-lab.ps1 -Manifest n2.json -Action Verify", check=False)
    from_guest("n2.json.verify.json", os.path.join(ev, "guest-verify.json"))
    to_home(os.path.join(ev, "guest-verify.json"), evdir_remote + "/guest-verify.json")
    py = "python3 %s/windows-vm-lab.py" % LAB
    home("%s record-guest --run-id %s --manifest %s --verify-json %s/guest-verify.json" % (py, RUN_ID, MAN, evdir_remote),
         timeout=60)
    return status(ev, "status-pre.json")


def status(ev, name):
    r = home("python3 %s/windows-vm-lab.py status --run-id %s --manifest %s" % (LAB, RUN_ID, MAN), timeout=90, check=False)
    with open(os.path.join(ev, name), "w") as f:
        f.write(r.stdout)
    try:
        d = json.loads(r.stdout)
    except ValueError:
        d = {}
    return d


# ------------------------------------------------------------------ one raw run
def do_run(item, argv, args, pm, injector=False, pre_guest=None, opts=None):
    """One gated, captured raw run. Returns after copying every artifact into <out>/runs/<tag>/.
    Whatever happens, this run's own listeners, injector and captures are stopped before returning."""
    tag = item["tag"]
    ev = os.path.join(args.out, "runs", tag)
    if os.path.exists(ev):
        raise SuiteAbort("%s exists; move it away (--rerun) instead of overwriting evidence" % ev)
    os.makedirs(ev)
    rev = "%s/%s/%s" % (REMOTE_EV, args.suite, tag)
    home("rm -rf %s && mkdir -p %s" % (rev, rev))
    ok = False
    try:
        res = _do_run(item, argv, args, pm, injector, pre_guest, tag, ev, rev, opts or {})
        ok = True
        return res
    finally:
        for n in ("listener", "inject", "flood", "linkloss", "peer", "eno1"):
            remote_stop(rev + "/%s.pid" % n, "TERM")
        if not ok:  # keep what the aborted run left on home-pc next to the evidence
            sh(["scp", "-q", "-r"] + SSH_BASE + ["home-pc:" + rev + "/.", ev], check=False)
        home("rm -rf %s" % rev, check=False)


def _do_run(item, argv, args, pm, injector, pre_guest, tag, ev, rev, opts):
    meta = {"tag": tag, "kind": item["kind"], "argv_file": "argv.json"}
    with open(os.path.join(ev, "argv.json"), "w") as f:
        json.dump({"exe": args.guest_exe, "argv": argv}, f, indent=1)
    st = gate(ev, rev)
    if st.get("raw_run_allowed") is not True or st.get("isolation_violations"):
        raise SuiteAbort("status gate: raw_run_allowed=%s violations=%s (see %s)" % (st.get("raw_run_allowed"), st.get("isolation_violations"), ev))
    if pre_guest:
        pre_guest(ev)
    # listeners (explicit; restarted for every run so SYN-ACK retransmits of an earlier run cannot bleed in)
    lis_pid, lis_ready = rev + "/listener.pid", rev + "/listener.json"
    silent = V.SILENT_PORTS if args.plan == "failure" else [V.SILENT_PORT]
    remote_bg(peer_ns("python3 %s/windows_wire_peer.py listen --open %s --silent %s --ready %s" % (
        REMOTE, ",".join(str(p) for p in V.LISTEN_OPEN), ports_spec(silent), lis_ready), sudo=False), lis_pid, rev + "/listener.err")
    remote_wait("[ -s %s ]" % lis_ready, 30, "listeners")
    from_home(lis_ready, os.path.join(ev, "listeners.json"))
    # captures
    peer_filter = ""
    eno_filter = ("net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host %s or ether host %s "
                  "or ether proto 0x88b5 or ether proto 0x88b6" % (GUEST_MAC, pm))
    peer_cmd = peer_ns("tcpdump -i lab0 -n -U --immediate-mode -B 16384 -s 0 -Z root -w %s/peer.pcap %s" % (rev, peer_filter), sudo=False).strip()
    eno_cmd = "tcpdump -i eno1 -n -U --immediate-mode -B 4096 -s 0 -Z root -w %s/eno1.pcap %s" % (rev, shlex.quote(eno_filter))
    rx0, tx0 = counters()
    remote_bg(peer_cmd, rev + "/peer.pid", rev + "/peer.err")
    remote_bg(eno_cmd, rev + "/eno1.pid", rev + "/eno1.err")
    remote_wait("grep -q 'listening on' %s/peer.err && grep -q 'listening on' %s/eno1.err" % (rev, rev), 20, "tcpdump listening")
    rx1, tx1 = counters()
    t_cap = time.time()
    home(peer_ns("python3 %s/windows_wire_peer.py marker --iface lab0 --src %s --dst %s" % (REMOTE, pm, GUEST_MAC)))
    remote_wait("[ $(tcpdump -nr %s/peer.pcap ether proto 0x88b5 2>/dev/null | wc -l) -ge 1 ]" % rev, 15, "marker in the peer capture")
    # optional injector of foreign replies (waits for the scan's first SYN)
    inj_pid = None
    if injector:
        inj_pid = rev + "/inject.pid"
        sp = V.sport_range(V.case_by_name(item["case"])["source_port"])[0]
        remote_bg(peer_ns("python3 %s/windows_wire_peer.py inject --iface lab0 --peer-mac %s --guest-mac %s --src-ip %s --sport %d "
                          "--silent %d --out %s/injector.json --wait-first 120 --duration 2.0" % (REMOTE, pm, GUEST_MAC, SRC_IP, sp, V.SILENT_PORT, rev), sudo=False),
                  inj_pid, rev + "/inject.err")
        time.sleep(0.5)
    # RX load / overflow: a flood of junk frames to the guest MAC, on lab0 only
    flood_pid = None
    if opts.get("flood"):
        fl = opts["flood"]
        flood_pid = rev + "/flood.pid"
        remote_bg(peer_ns("python3 %s/windows_wire_peer.py flood --guest-mac %s --pps %d --size %d --duration %s --out %s/flood.json" % (
            REMOTE, GUEST_MAC, fl["pps"], fl["size"], fl["duration"], rev), sudo=False), flood_pid, rev + "/flood.err")
        time.sleep(float(fl.get("lead", 1.0)))
    # NIC disconnect: wait for the first SYN, QMP set_link down, hold until the guest run ended, up (always restored)
    ll_pid = ll_stop = None
    if opts.get("linkloss"):
        ll_pid, ll_stop = rev + "/linkloss.pid", rev + "/linkloss.stop"
        home("rm -f %s" % ll_stop)
        remote_bg(peer_ns("python3 %s/windows_wire_peer.py linkloss --guest-mac %s --sock %s --down-after 2.0 --hold-max 40 "
                          "--stop-file %s --out %s/linkloss.json" % (REMOTE, GUEST_MAC, QMP_SOCK, ll_stop, rev), sudo=False),
                  ll_pid, rev + "/linkloss.err")
        time.sleep(0.5)
    # the guest run
    to_guest(os.path.join(ev, "argv.json"), "t4/in/%s.argv.json" % tag.replace("/", "_"))
    g_out = "%s\\out\\%s\\%s" % (GUEST_DIR, args.suite, tag)
    t_g0 = time.time()
    meta["guest_started_utc"] = t_g0
    run_cmd = "pwsh -NoProfile -File %s\\windows_wire_run.ps1 -ArgvFile %s\\in\\%s.argv.json -OutDir %s" % (GUEST_DIR, GUEST_DIR, tag, g_out)
    if opts.get("restricted"):
        # a restricted (non-elevated, reduced) token: runas /trustlevel:0x20000. The helper keeps this ssh session alive
        # until the restricted process finished (the session's job object would kill it otherwise).
        gr = guest("%s\\windows_wire_runas.cmd %s\\in\\%s.argv.json %s 150" % (GUEST_DIR, GUEST_DIR, tag, g_out),
                   timeout=min(args.run_timeout, 200), check=False)
        meta["restricted_via"] = "runas /trustlevel:0x20000 (windows_wire_runas.cmd)"
        meta["guest_finished_utc"] = time.time()
        meta["guest_ssh_rc"] = gr.returncode
    else:
        gr = guest(run_cmd, timeout=args.run_timeout, check=False)
        meta["guest_finished_utc"] = time.time()
        meta["guest_ssh_rc"] = gr.returncode
    # a checkpoint file must not exist after a failed or refused run
    if opts.get("checkpoint_path"):
        meta["checkpoint_file_exists"] = "yes" in guest("cmd /c if exist %s echo yes" % opts["checkpoint_path"], timeout=30, check=False).stdout
    if flood_pid:
        remote_stop(flood_pid, "TERM")
        remote_wait_exit(flood_pid, 20)
    if ll_pid:
        home("touch %s" % ll_stop)
        remote_wait_exit(ll_pid, 30)
        for _ in range(60):  # the stand must be green again (link up, guest NIC Up) before anything else runs
            if status(ev, "status-link-restored.json").get("raw_run_allowed") is True:
                break
            time.sleep(1.0)
    # drain: stop the listeners first (no SYN-ACK retransmit tail), then wait for the peer to go quiet
    remote_stop(lis_pid, "TERM")
    if inj_pid:
        remote_wait_exit(inj_pid, 15)
    quiet = wait_quiet(counters, QUIET_S, 0.5, 40)
    # end marker: a distinctive lab-only frame that must reach the pcap BEFORE SIGINT, so that frames still
    # buffered inside tcpdump (they are older than the marker) are flushed or the run is INVALID
    home(peer_ns("python3 %s/windows_wire_peer.py marker --iface lab0 --src %s --dst %s --payload WIRELAB-END" % (REMOTE, pm, GUEST_MAC)))
    end_seen = False
    try:
        remote_wait("[ $(tcpdump -nr %s/peer.pcap -A ether proto 0x88b5 2>/dev/null | grep -c WIRELAB-END) -ge 3 ]" % rev, 15, "end marker in the peer capture")
        end_seen = True
    except SuiteAbort:
        pass
    meta["end_marker_seen"] = end_seen
    rx2, tx2 = counters()
    remote_stop(rev + "/peer.pid")
    remote_stop(rev + "/eno1.pid")
    ok_p = remote_wait_exit(rev + "/peer.pid", 20)
    ok_e = remote_wait_exit(rev + "/eno1.pid", 20)
    meta["capture_stopped_utc"] = time.time()
    meta["capture_started_utc"] = t_cap
    # hash BEFORE any copy or cleanup
    hs = home("cd %s && sha256sum peer.pcap eno1.pcap && stat -c '%%n %%s' peer.pcap eno1.pcap" % rev).stdout
    sums = {}
    for line in hs.splitlines():
        p = line.split()
        if len(p[0]) == 64:
            sums[p[1]] = {"sha256": p[0]}
        else:
            sums[p[0]]["size"] = int(p[1])
    with open(os.path.join(ev, "pcap-hashes-on-home-pc.txt"), "w") as f:
        f.write(hs)
    for n in ("peer.pcap", "eno1.pcap", "peer.err", "eno1.err", "listener.err", "inject.err", "injector.json", "flood.json",
              "flood.err", "linkloss.json", "linkloss.err"):
        sh(["scp", "-q"] + SSH_BASE + ["home-pc:%s/%s" % (rev, n), os.path.join(ev, n)], check=False)
    # guest outputs
    for n in ("stdout.txt", "stderr.txt", "exit.txt", "runner.json", "nic.json", "runner.log", "runner.rc"):
        try:
            from_guest("%s\\%s" % (g_out, n), os.path.join(ev, "guest-" + n))
        except SuiteAbort as e:
            meta.setdefault("guest_copy_errors", []).append(str(e)[:200])
    st_post = status(ev, "status-post.json")
    # run.json = the harness' single JSON line
    rjson, rc = {}, None
    try:
        lines = [l for l in open(os.path.join(ev, "guest-stdout.txt"), encoding="utf-8-sig").read().splitlines() if l.startswith("{")]
        rjson = json.loads(lines[-1])
        rc = int(open(os.path.join(ev, "guest-exit.txt")).read().strip())
    except (OSError, ValueError, IndexError) as e:
        meta["run_json_error"] = str(e)
    if rjson:
        with open(os.path.join(ev, "run.json"), "w") as f:
            json.dump(rjson, f, indent=1, sort_keys=True)
    runner = {}
    try:
        runner = json.load(open(os.path.join(ev, "guest-runner.json"), encoding="utf-8-sig"))
    except (OSError, ValueError):
        pass
    if os.path.exists(os.path.join(ev, "guest-nic.json")):
        os.replace(os.path.join(ev, "guest-nic.json"), os.path.join(ev, "nic.json"))
    meta.update(guest_exit=rc, exe_sha256=runner.get("exe_sha256"), guest_times=runner.get("times"))
    pe, ee = (open(os.path.join(ev, n + ".err")).read() if os.path.exists(os.path.join(ev, n + ".err")) else "" for n in ("peer", "eno1"))
    cap = {
        "capture_schema": CAPTURE_SCHEMA,
        "peer": dict(filter=peer_filter or "(none: every frame on lab0)", cmd=peer_cmd.split(), exited=ok_p,
                     tcpdump={k: v for k, v in parse_tcpdump(pe).items() if k != "listening"}, listening=parse_tcpdump(pe)["listening"],
                     pcap=dict(sums.get("peer.pcap", {}), frames=count_frames(os.path.join(ev, "peer.pcap"))),
                     counters=dict(rx_before=rx0, tx_before=tx0, rx_ready=rx1, tx_ready=tx1, rx_end=rx2, tx_end=tx2)),
        "eno1": dict(filter=eno_filter, cmd=eno_cmd.split(), exited=ok_e,
                     tcpdump={k: v for k, v in parse_tcpdump(ee).items() if k != "listening"}, listening=parse_tcpdump(ee)["listening"],
                     pcap=dict(sums.get("eno1.pcap", {}), frames=count_frames(os.path.join(ev, "eno1.pcap")))),
        "quiet": {"reached": quiet, "quiet_s": QUIET_S if quiet else 0},
        "status_post_raw_run_allowed": st_post.get("raw_run_allowed"),
    }
    with open(os.path.join(ev, "capture.json"), "w") as f:
        json.dump(cap, f, indent=1, sort_keys=True)
    with open(os.path.join(ev, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1, sort_keys=True)
    # transfer integrity: what is on disk here is what was hashed on home-pc
    for n in ("peer.pcap", "eno1.pcap"):
        local = V.sha256_bytes(open(os.path.join(ev, n), "rb").read()) if os.path.exists(os.path.join(ev, n)) else None
        if local != sums.get(n, {}).get("sha256"):
            raise SuiteAbort("%s: copy differs from the hash taken on home-pc" % n)
    log("%s: done guest_rc=%s peer_frames=%s eno1_frames=%s quiet=%s" % (tag, rc, cap["peer"]["pcap"]["frames"], cap["eno1"]["pcap"]["frames"], quiet))
    return ev


def count_frames(path):
    try:
        return len(V.vw.read_pcap_records(open(path, "rb").read())[1])
    except (OSError, V.vw.PcapError):
        return None


# ------------------------------------------------------------------ plan
def checkpoint_path(args, n):
    return "%s\\cp\\%s\\N%d.bin" % (GUEST_DIR, args.suite, n)


def argv_from_def(kd, item, pm, paths):
    """argv of wire_scan.exe built from the verifier's own argument definition of this run kind, so what is sent and what
    the verifier expects cannot drift apart. ANY values are run-local paths from `paths`."""
    cname, extra = kd(item)
    bind = V.Binding({"src_ip": SRC_IP, "src_mac": GUEST_MAC, "router_mac": pm})
    case = cname if isinstance(cname, dict) or cname is None else V.case_by_name(cname)
    want = dict(V.base_argv(case, {"binding": {"iface": LAB_NIC}}, bind) if case else {}, **extra)
    argv = []
    for k, v in want.items():
        argv.append(k)
        if v is True:
            continue
        argv.append(paths[k] if v == V.ANY else str(v))
    return argv


def mutate_checkpoint(variant, data):
    """The checkpoint a refusal run is given, made from a valid one: layout MAGIC(8) fmt(4) engine(4) scan(16) attempt(16)
    digest(32) next_index(8) + sha256(body)(32)."""
    import hashlib

    def reseal(body):
        return body + hashlib.sha256(body).digest()
    if variant in ("wrong_ports", "wrong_seed"):
        return data  # a valid checkpoint of ANOTHER job: the resume asks for a different job
    if variant == "corrupt_next_index":
        return data[:87] + bytes([data[87] ^ 1]) + data[88:]
    if variant == "corrupt_checksum":
        return data[:-1] + bytes([data[-1] ^ 0xFF])
    if variant == "truncated":
        return data[:60]
    if variant == "empty":
        return b""
    if variant == "future_format":
        return reseal(data[:8] + (99).to_bytes(4, "big") + data[12:-32])
    if variant == "future_engine":
        return reseal(data[:12] + (99).to_bytes(4, "big") + data[16:-32])
    raise ValueError(variant)


def ckpt_paths(args, tag):
    base = "%s\\cp\\%s\\%s" % (GUEST_DIR, args.suite, tag)
    return base + ".forged.bin", base + ".bin"


def run_guest_argv(args, ev, name, argv, out_leaf):
    """Run the EXE offline helper on the guest (forge): argv file + runner; returns the guest out dir."""
    with open(os.path.join(ev, name), "w") as f:
        json.dump({"exe": args.guest_exe, "argv": argv}, f, indent=1)
    to_guest(os.path.join(ev, name), "t4/in/%s.%s" % (os.path.basename(ev), name))
    out = "%s\\out\\%s\\%s.%s" % (GUEST_DIR, args.suite, os.path.basename(ev), out_leaf)
    guest("pwsh -NoProfile -File %s\\windows_wire_run.ps1 -ArgvFile %s\\in\\%s.%s -OutDir %s" % (
        GUEST_DIR, GUEST_DIR, os.path.basename(ev), name, out))
    return out


def prepare_ckpt(args, ev, item, pm):
    """forge a VALID checkpoint of the pause job (offline, no adapter, no packet), fetch it, mutate it, push the result."""
    p0, p1 = ckpt_paths(args, item["tag"])
    kd = V.KIND_SIDE_ARGV_B["ckpt_refuse"][1]
    out = run_guest_argv(args, ev, "forge-argv.json", argv_from_def(kd, item, pm, {"--checkpoint-out": p0}), "forge")
    from_guest(out + "\\stdout.txt", os.path.join(ev, "forge-stdout.txt"))
    from_guest(p0, os.path.join(ev, "checkpoint-forged.bin"))
    data = open(os.path.join(ev, "checkpoint-forged.bin"), "rb").read()
    used = mutate_checkpoint(item["variant"], data)
    with open(os.path.join(ev, "checkpoint-used.bin"), "wb") as f:
        f.write(used)
    to_guest(os.path.join(ev, "checkpoint-used.bin"), p1)


def run_plan_b(args, pm):
    items = [it for it in V.planned_b() if not args.only or it["tag"] in args.only]
    for it in items:
        k, tag = it["kind"], it["tag"]
        cp = "%s\\cp\\%s\\%s.bin" % (GUEST_DIR, args.suite, tag)
        if k == "case":  # the elevated control: the very same c01 scan as part A
            do_run(it, scan_argv(V.case_by_name(it["case"]), LAB_NIC, GUEST_MAC, pm), args, pm)
        elif k == "stop":
            opts = {"flood": dict(V.FLOOD_STOP)} if it["scenario"] == "load" else {}
            do_run(it, argv_from_def(V.KIND_ARGV_B[k], it, pm, {}), args, pm, opts=opts)
        elif k == "overflow_queue":
            do_run(it, argv_from_def(V.KIND_ARGV_B[k], it, pm, {}), args, pm)
        elif k == "linkloss":
            do_run(it, argv_from_def(V.KIND_ARGV_B[k], it, pm, {"--checkpoint-out": cp}), args, pm,
                   opts={"linkloss": True, "checkpoint_path": cp})
        elif k == "rxloss":
            do_run(it, argv_from_def(V.KIND_ARGV_B[k], it, pm, {"--checkpoint-out": cp}), args, pm,
                   opts={"flood": dict(V.FLOOD_OVERFLOW), "checkpoint_path": cp})
        elif k == "ckpt_refuse":
            p0, p1 = ckpt_paths(args, tag)
            do_run(it, argv_from_def(V.KIND_ARGV_B[k], it, pm, {"--resume-checkpoint": p1}), args, pm,
                   pre_guest=lambda ev, it=it: prepare_ckpt(args, ev, it, pm))
        elif k == "perm_restricted":
            do_run(it, argv_from_def(V.KIND_ARGV_B[k], it, pm, {}), args, pm, opts={"restricted": True})
        else:
            raise SuiteAbort("no orchestration for run kind %s" % k)


def run_plan(args, pm):
    if args.plan == "failure":
        return run_plan_b(args, pm)
    base = lambda c, extra=(): scan_argv(c, LAB_NIC, GUEST_MAC, pm, extra)  # noqa: E731
    pc = V.case_by_name(V.PAUSE_CASE)
    items = []
    for it in V.planned(None):
        if args.only and it["tag"] not in args.only:
            continue
        items.append(it)
    for it in items:
        k = it["kind"]
        if k in ("case", "foreign"):
            c = V.case_by_name(it["case"])
            do_run(it, base(c), args, pm, injector=(k == "foreign"))
        elif k == "pause":
            do_run(it, base(pc, ["--scan-id", SCAN_ID, "--attempt-id", ATTEMPT_1, "--pause-after", it["n"],
                                 "--checkpoint-out", checkpoint_path(args, it["n"])]), args, pm)
            fetch_checkpoint(args, it)
        elif k == "resume":
            do_run(it, base(pc, ["--scan-id", SCAN_ID, "--attempt-id", ATTEMPT_2, "--resume-checkpoint", checkpoint_path(args, it["n"])]), args, pm)
        elif k == "complete_nopause":
            do_run(it, base(pc, ["--scan-id", SCAN_ID, "--attempt-id", ATTEMPT_1, "--pause-after", len_syn(pc),
                                 "--checkpoint-out", checkpoint_path(args, 16)]), args, pm)
        elif k == "refuse_completed":
            cp = checkpoint_path(args, 99)
            forge = base(pc, ["--scan-id", SCAN_ID, "--attempt-id", ATTEMPT_1, "--forge-checkpoint-next-index", len_syn(pc), "--checkpoint-out", cp])
            do_run(it, base(pc, ["--scan-id", SCAN_ID, "--attempt-id", ATTEMPT_2, "--resume-checkpoint", cp]), args, pm,
                   pre_guest=lambda ev, f=forge: forge_checkpoint(args, ev, f))


def may_discard(verdict, behaviour_fail=False):
    """Only a run that is INVALID (or never completed: NOT RUN) AND whose behaviour checks did not fail may be set
    aside and rerun. A scanner failure is never rerun away, even when the capture was also bad."""
    return verdict in (V.INVALID, V.NOT_RUN) and not behaviour_fail


def rerun_verdict(out, tag):
    """(verdict, behaviour_fail) the offline verifier gives runs/<tag> now. PASS and FAIL runs are evidence."""
    return V.run_status(out, tag)


def len_syn(c):
    return c["syn"]


def forge_checkpoint(args, ev, forge_argv):
    """Offline mode of wire_scan.exe (never opens the adapter, never sends): creates a checkpoint at next_index == range."""
    with open(os.path.join(ev, "forge-argv.json"), "w") as f:
        json.dump({"exe": args.guest_exe, "argv": forge_argv}, f, indent=1)
    to_guest(os.path.join(ev, "forge-argv.json"), "t4/in/%s.forge.json" % os.path.basename(ev))
    out = "%s\\out\\%s\\%s.forge" % (GUEST_DIR, args.suite, os.path.basename(ev))
    guest("pwsh -NoProfile -File %s\\windows_wire_run.ps1 -ArgvFile %s\\in\\%s.forge.json -OutDir %s" % (GUEST_DIR, GUEST_DIR, os.path.basename(ev), out))
    from_guest(out + "\\stdout.txt", os.path.join(ev, "forge-stdout.txt"))


def fetch_checkpoint(args, it):
    ev = os.path.join(args.out, "runs", it["tag"])
    try:
        from_guest(checkpoint_path(args, it["n"]), os.path.join(ev, "checkpoint.bin"))
    except SuiteAbort as e:
        log("no checkpoint copied for %s: %s" % (it["tag"], str(e)[:120]))


# ------------------------------------------------------------------ main
def write_manifest(args, pm):
    fx_src = os.path.join(args.fixtures, "manifest.json")
    fx = json.load(open(fx_src))
    exe = guest("pwsh -NoProfile -File %s\\windows_wire_hash.ps1 -Path %s" % (GUEST_DIR, args.guest_exe)).stdout.split()
    man = {
        "schema": 1, "capture_schema": CAPTURE_SCHEMA, "suite": args.suite, "code_commit": args.commit,
        "exe": {"sha256": exe[0], "size": int(exe[1]), "guest_path": args.guest_exe,
                "build": "git archive of code_commit -> ~/winvm/sync-and-test.sh; RMASSCAN_SOURCE_COMMIT=code_commit; "
                         "RUSTFLAGS='-C target-feature=+crt-static'; cargo build --locked --release -p rmasscan-net --example wire_scan"},
        "binding": {"iface": LAB_NIC, "src_ip": SRC_IP, "src_mac": GUEST_MAC, "router_mac": pm, "peer_ip": V.PEER_IP,
                    "seed": V.SEED, "rate": V.RATE, "wait": V.WAIT},
        "stand": {"run_id": RUN_ID, "netns": NS, "manifest": MAN},
        "listeners": {"open": V.LISTEN_OPEN, "silent": V.SILENT_PORTS if args.plan == "failure" else [V.SILENT_PORT]},
        "plan": args.plan,
        "pause": {"case": V.PAUSE_CASE, "n": V.PAUSE_NS},
        "oracle": fx.get("oracle"),
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(man, f, indent=1, sort_keys=True)
    dst = os.path.join(args.out, "fixtures")
    if not os.path.exists(dst):
        shutil.copytree(args.fixtures, dst)


def prepare(args):
    global REMOTE, REMOTE_EV, QMP_SOCK
    rh = home("echo $HOME").stdout.strip()
    REMOTE, REMOTE_EV, QMP_SOCK = rh + "/winvm/t4", rh + "/winvm/t4-ev", rh + "/winvm/qmp.sock"
    home("mkdir -p %s %s" % (REMOTE, REMOTE_EV))
    to_home(os.path.join(HERE, "windows_wire_peer.py"), REMOTE + "/windows_wire_peer.py")
    guest("cmd /c if not exist %s\\in mkdir %s\\in" % (GUEST_DIR, GUEST_DIR))
    guest("cmd /c if not exist %s\\cp\\%s mkdir %s\\cp\\%s" % (GUEST_DIR, args.suite, GUEST_DIR, args.suite))
    to_guest(os.path.join(HERE, "windows_wire_run.ps1"), "t4/windows_wire_run.ps1")
    to_guest(os.path.join(HERE, "windows_wire_hash.ps1"), "t4/windows_wire_hash.ps1")
    for helper in ("windows_wire_runas.cmd", "windows_wire_restricted.cmd"):
        to_guest(os.path.join(HERE, helper), "t4/" + helper)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, help="functional evidence directory")
    ap.add_argument("--commit", required=True, help="full sha of the code commit the exe was built from")
    ap.add_argument("--guest-exe", required=True)
    ap.add_argument("--fixtures", required=True, help="directory with the C oracle fixtures (manifest.json + pcaps)")
    ap.add_argument("--suite", default="functional")
    ap.add_argument("--plan", choices=["functional", "failure"], default="functional",
                    help="functional: part A (C-oracle parity, pause/resume); failure: part B (stop, link loss, checkpoint refusals, "
                         "permissions, RX overflow)")
    ap.add_argument("--only", nargs="*", default=[], help="run only these tags")
    ap.add_argument("--rerun", action="store_true", help="move an existing run dir to runs_discarded/ before rerunning it")
    ap.add_argument("--run-timeout", type=int, default=240)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()
    if args.list:
        for it in (V.planned_b() if args.plan == "failure" else V.planned(None)):
            print(it["tag"], it["kind"])
        return 0
    os.makedirs(args.out, exist_ok=True)
    # offline policy checks first: nothing touches the stand and no run is moved unless EVERY requested tag may be
    old = V.try_json(os.path.join(args.out, "manifest.json"))
    if old is not None and (old.get("capture_schema") or 1) < CAPTURE_SCHEMA:
        log("STOP: %s is capture_schema %s; this orchestrator writes schema %d. Use a new directory." % (
            args.out, old.get("capture_schema") or 1, CAPTURE_SCHEMA))
        return 12
    moves = []
    if args.rerun:
        for t in args.only:
            src = os.path.join(args.out, "runs", t)
            if os.path.exists(src):
                v, bf = rerun_verdict(args.out, t)
                if not may_discard(v, bf):
                    log("STOP: runs/%s is %s%s; only an INVALID (or incomplete) run without a failed behaviour check "
                        "may be discarded and rerun" % (t, v, " with a failed behaviour check" if bf else ""))
                    return 11
                moves.append((t, src))
    prepare(args)
    pm = peer_mac()
    for t, src in moves:
        dst = os.path.join(args.out, "runs_discarded")
        os.makedirs(dst, exist_ok=True)
        os.rename(src, os.path.join(dst, "%s.%d" % (t, int(time.time()))))
    if not os.path.exists(os.path.join(args.out, "manifest.json")):
        write_manifest(args, pm)
    try:
        run_plan(args, pm)
    except SuiteAbort as e:
        log("STOP: %s" % e)
        return 10
    log("all planned runs executed; verify offline with windows_wire_verify.py --dir %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
