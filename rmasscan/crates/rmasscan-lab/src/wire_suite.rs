use crate::windows_suite::{command, hash, opt, read_json, required, strings, write_json};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
#[cfg(test)]
thread_local! {
    /// Test seam: the process stop flag is global, so tests raise a per-thread one instead.
    pub(crate) static TEST_STOP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn stop_requested() -> bool {
    #[cfg(test)]
    if TEST_STOP.with(std::cell::Cell::get) {
        return true;
    }
    rmasscan_net::lab_io::stop_requested()
}
/// Signal a process directly. `command()` kills its own child as soon as the stop flag is up, so a
/// cleanup kill sent through it would die before it ran (final review M-2).
fn signal_process(sig: &str, pid: u32) {
    let _ = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}
pub(crate) fn capture_complete(
    cap: Option<u64>,
    recv: Option<u64>,
    kd: Option<u64>,
    id: Option<u64>,
    frames: u64,
    lo: u64,
    hi: u64,
) -> bool {
    cap == Some(frames)
        && recv == Some(frames)
        && kd == Some(0)
        && id == Some(0)
        && lo <= frames
        && frames <= hi
}
/// The Stop stage of a perf cell counts only if its own capture is valid, the scanner exited 0, the stop
/// took effect before the last probe and, for Rust, the engine reported `Stopped`.
pub(crate) fn stop_stage_valid(stop: &Value, implementation: &str) -> bool {
    stop["capture_valid"] == true
        && stop["rc"] == 0
        && stop["stopped_early"] == true
        && (implementation == "c" || stop["reason"] == "Stopped")
}
/// Scanner-side reply completeness against the capture: unique replies the peer sent to the
/// scanner. C reports open ports only (`received_closed` is `None`); Rust must also match the
/// RST set. Exact equality, no tolerance, and an unreported open count is never complete.
pub(crate) fn rx_is_complete(
    received_open: Option<u64>,
    received_closed: Option<u64>,
    wire_open: u64,
    wire_closed: u64,
) -> bool {
    received_open == Some(wire_open) && received_closed.is_none_or(|c| c == wire_closed)
}
pub(crate) fn rx_health_ok(s: &Value) -> bool {
    s["reason"] == "Completed" && s["rx_health"]["kernel_drops"].as_u64() == Some(0)
}
fn leak_ok(s: &Value) -> bool {
    s["resources"]["threads_after_join"].as_u64().is_some()
        && s["resources"]["threads_after_join"] == s["resources"]["threads_before"]
        && matches!((s["resources"]["fds_after_join"].as_u64(),s["resources"]["fds_before_open"].as_u64()),(Some(a),Some(b)) if a<=b)
}
/// A summary counter that may be absent. An absent counter equals nothing, not even another
/// absent one, and is ordered against nothing, so a missing field can never satisfy a check.
#[derive(Clone, Copy, Debug)]
struct Num(Option<u64>);
impl PartialEq for Num {
    fn eq(&self, o: &Self) -> bool {
        matches!((self.0, o.0), (Some(a), Some(b)) if a == b)
    }
}
impl PartialEq<u64> for Num {
    fn eq(&self, o: &u64) -> bool {
        self.0 == Some(*o)
    }
}
impl PartialEq<Num> for u64 {
    fn eq(&self, o: &Num) -> bool {
        o.0 == Some(*self)
    }
}
impl PartialOrd for Num {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.0?.cmp(&o.0?))
    }
}
impl PartialOrd<u64> for Num {
    fn partial_cmp(&self, o: &u64) -> Option<std::cmp::Ordering> {
        Some(self.0?.cmp(o))
    }
}
impl Num {
    fn saturating_add(self, o: Num) -> Num {
        Num(self.0.zip(o.0).map(|(a, b)| a.saturating_add(b)))
    }
}
fn n(s: &Value, k: &str) -> Num {
    Num(s[k].as_u64())
}
fn sorted_replies(s: &Value) -> Vec<String> {
    let mut r = s["replies"]
        .as_array()
        .map(|v| {
            v.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    r.sort();
    r
}
fn spawn(a: &[String], out: &Path, err: &Path) -> Result<Child, String> {
    Command::new(&a[0])
        .args(&a[1..])
        .stdout(Stdio::from(
            fs::File::create(out).map_err(|e| e.to_string())?,
        ))
        .stderr(Stdio::from(
            fs::File::create(err).map_err(|e| e.to_string())?,
        ))
        .spawn()
        .map_err(|e| e.to_string())
}
struct OwnedChild(Option<Child>);
impl OwnedChild {
    fn stop(&mut self, sig: &str) -> Result<(), String> {
        self.stop_within(sig, 20)
    }
    /// Signal the child and wait up to `secs` for it to exit, then kill it and fail.
    fn stop_within(&mut self, sig: &str, secs: u64) -> Result<(), String> {
        if let Some(p) = &mut self.0
            && p.try_wait().map_err(|e| e.to_string())?.is_none()
        {
            signal_process(sig, p.id());
            let t = Instant::now();
            while p.try_wait().map_err(|e| e.to_string())?.is_none() {
                if stop_requested() {
                    p.kill().map_err(|e| e.to_string())?;
                    p.wait().map_err(|e| e.to_string())?;
                    return Err("suite interrupted during child cleanup".into());
                }
                if t.elapsed() > Duration::from_secs(secs) {
                    p.kill().map_err(|e| e.to_string())?;
                    p.wait().map_err(|e| e.to_string())?;
                    return Err("child failed to stop".into());
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
        self.0 = None;
        Ok(())
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(p) = &mut self.0 {
            let _ = p.kill();
            let _ = p.wait();
        }
    }
}
/// Wait for `ready` to appear, but fail at once if the process exits first (a missing tcpdump or a
/// permission error would otherwise cost the whole timeout), reporting its stderr.
fn wait_ready(p: &mut OwnedChild, ready: &Path, secs: u64, err: &Path) -> Result<(), String> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if ready.exists() {
            return Ok(());
        }
        if let Some(c) = &mut p.0
            && let Some(st) = c.try_wait().map_err(|e| e.to_string())?
        {
            p.0 = None;
            return Err(format!(
                "capture witness exited ({st}) before it was ready: {}",
                fs::read_to_string(err)
                    .unwrap_or_default()
                    .chars()
                    .take(300)
                    .collect::<String>()
            ));
        }
        if stop_requested() {
            return Err("suite interrupted".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("capture witness (tcpdump) not ready".into())
}
fn wait_file(p: &Path, secs: u64) -> bool {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if stop_requested() {
            return false;
        }
        if p.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    false
}
#[derive(Clone)]
struct Case {
    name: &'static str,
    targets: &'static str,
    ports: &'static str,
    exclude: Option<&'static str>,
    sp: &'static str,
    syn: u64,
    open: u64,
    closed: u64,
}
fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "c01_one_addr_port_synack",
            targets: "10.200.0.2",
            ports: "80",
            exclude: None,
            sp: "40000",
            syn: 1,
            open: 1,
            closed: 0,
        },
        Case {
            name: "c02_one_addr_port_rst",
            targets: "10.200.0.2",
            ports: "81",
            exclude: None,
            sp: "40000",
            syn: 1,
            open: 0,
            closed: 1,
        },
        Case {
            name: "c03_multi_addr_ports",
            targets: "10.200.0.2-10.200.0.5",
            ports: "80,81,443,8080",
            exclude: None,
            sp: "40000",
            syn: 16,
            open: 8,
            closed: 8,
        },
        Case {
            name: "c04_exclude",
            targets: "10.200.0.2-10.200.0.5",
            ports: "80,81",
            exclude: Some("10.200.0.3"),
            sp: "40000",
            syn: 6,
            open: 3,
            closed: 3,
        },
        Case {
            name: "c05_srcport_single",
            targets: "10.200.0.2-10.200.0.3",
            ports: "80,81",
            exclude: None,
            sp: "50123",
            syn: 4,
            open: 2,
            closed: 2,
        },
        Case {
            name: "c06_srcport_range",
            targets: "10.200.0.2-10.200.0.3",
            ports: "80,81",
            exclude: None,
            sp: "50000-50015",
            syn: 4,
            open: 2,
            closed: 2,
        },
    ]
}
struct Config {
    out: PathBuf,
    work: PathBuf,
    nsa: String,
    nsb: String,
    ifa: String,
    ifb: String,
    maca: String,
    macb: String,
    ipa: String,
    rust: String,
    oracle: String,
    fixtures: Option<PathBuf>,
    masked: bool,
    empty: String,
    lab: String,
}
/// `--fixtures` as a directory; empty means none (never the working directory).
fn fixtures_arg(v: &str) -> Option<PathBuf> {
    (!v.is_empty()).then(|| PathBuf::from(v))
}
impl Config {
    fn fixture(&self, name: &str) -> Option<PathBuf> {
        self.fixtures.as_ref().map(|d| d.join(name))
    }
}
struct Driver {
    c: Config,
    checks: Vec<Value>,
    extra: Value,
    responder: OwnedChild,
}
struct Run {
    rc: i32,
    s: Value,
    meta: Value,
    pcap: Option<PathBuf>,
    wall: f64,
}
/// Where a capture's pcap lives: the rust suite keeps it as evidence, perf deletes it per cell.
#[derive(Clone, Copy)]
enum Evidence {
    Keep,
    Scratch,
}
struct Recorder {
    tag: String,
    pcap: PathBuf,
    meta: PathBuf,
    process: OwnedChild,
}
#[derive(Default)]
struct Action {
    pause: Option<PathBuf>,
    remove_link: bool,
    stop_file: Option<PathBuf>,
    stop_sig: bool,
}
impl Driver {
    fn ns(&self, peer: bool, args: &[String]) -> Vec<String> {
        let mut a = strings(&[
            "ip",
            "netns",
            "exec",
            if peer { &self.c.nsb } else { &self.c.nsa },
        ]);
        a.extend_from_slice(args);
        a
    }
    fn lab(&self, sub: &str, args: &[&str]) -> Vec<String> {
        let mut a = vec![self.c.lab.clone(), sub.into()];
        a.extend(strings(args));
        a
    }
    fn check(&mut self, g: &str, name: &str, ok: Option<bool>, detail: Value) {
        let result = match ok {
            Some(true) => "PASS",
            Some(false) => "FAIL",
            None => "NOT RUN",
        };
        println!("[{g}] {result} {name}");
        self.checks
            .push(json!({"group":g,"name":name,"result":result,"detail":detail}));
    }
    fn save(&self, partial: bool) -> Result<(), String> {
        let mut v = self.extra.clone();
        v["partial"] = json!(partial);
        v["checks"] = json!(self.checks);
        v["totals"] = json!({"PASS":self.checks.iter().filter(|v|v["result"]=="PASS").count(),"FAIL":self.checks.iter().filter(|v|v["result"]=="FAIL").count(),"NOT RUN":self.checks.iter().filter(|v|v["result"]=="NOT RUN").count()});
        write_json(self.c.out.join("results.json"), &v)
    }
    fn fresh(&mut self) -> Result<(), String> {
        self.responder.stop("TERM")?;
        let ready = self
            .c
            .work
            .join(format!("responder-{}.ready", crate::windows_suite::nonce()));
        let args = self.ns(
            true,
            &self.lab(
                "capture",
                &[
                    "responder",
                    "--ports",
                    "80,8080",
                    "--ready",
                    &ready.to_string_lossy(),
                ],
            ),
        );
        self.responder = OwnedChild(Some(spawn(
            &args,
            &self.c.work.join("responder.out"),
            &self.c.work.join("responder.err"),
        )?));
        if !wait_file(&ready, 10) {
            return Err("responder not ready".into());
        }
        Ok(())
    }
    fn rust_args(
        &self,
        targets: &str,
        ports: &str,
        rate: u64,
        wait: u64,
        sp: &str,
        exclude: Option<&str>,
    ) -> Vec<String> {
        let mut a = strings(&[
            "--iface",
            &self.c.ifa,
            "--src-ip",
            &self.c.ipa,
            "--src-mac",
            &self.c.maca,
            "--router-mac",
            &self.c.macb,
            "--targets",
            targets,
            "--ports",
            ports,
            "--seed",
            "1",
            "--rate",
            &rate.to_string(),
            "--wait",
            &wait.to_string(),
            "--source-port",
            sp,
        ]);
        if let Some(e) = exclude {
            a.extend(strings(&["--exclude", e]));
        }
        a
    }
    fn record_hash(&mut self, tag: &str, path: &Path) -> Result<Value, String> {
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        let frames = crate::pcap::read_pcap_records(&bytes).map(|(_, r)| r.len());
        let mut rec = json!({"tag":tag,"file":path.file_name().map(|s|s.to_string_lossy()),"sha256":hash(path)?,"size_bytes":bytes.len(),"pcap_frames":frames.as_ref().ok()});
        if let Err(e) = frames {
            rec["pcap_error"] = json!(e);
        }
        if !self.extra["pcaps"].is_array() {
            self.extra["pcaps"] = json!([])
        }
        self.extra["pcaps"]
            .as_array_mut()
            .ok_or("pcap array")?
            .push(rec.clone());
        Ok(rec)
    }
    fn capture_paths(&self, tag: &str, evidence: Evidence) -> (PathBuf, PathBuf) {
        let pcap = match evidence {
            Evidence::Keep => self.c.out.join(format!("{tag}.pcap")),
            Evidence::Scratch => self.c.work.join(format!("{tag}.pcap")),
        };
        (pcap, self.c.out.join(format!("{tag}.capture.json")))
    }
    /// Start the tcpdump witness in the peer namespace (`capture dump`), prove it is live with a
    /// scanner-side start marker, and return the handle.
    fn recorder(&self, tag: &str, evidence: Evidence) -> Result<Recorder, String> {
        let (pcap, meta) = self.capture_paths(tag, evidence);
        let ready = self
            .c
            .work
            .join(format!("{tag}.{}.ready", crate::windows_suite::nonce()));
        let ack = ready.with_extension("ack");
        let a = self.ns(
            true,
            &self.lab(
                "capture",
                &[
                    "dump",
                    "--iface",
                    &self.c.ifb,
                    "--pcap",
                    &pcap.to_string_lossy(),
                    "--meta",
                    &meta.to_string_lossy(),
                    "--ready",
                    &ready.to_string_lossy(),
                    "--ack",
                    &ack.to_string_lossy(),
                    "--end-dst",
                    &self.c.maca,
                ],
            ),
        );
        let rec_err = self.c.work.join(format!("{tag}.rec.err"));
        let mut process = OwnedChild(Some(spawn(
            &a,
            &self.c.work.join(format!("{tag}.rec.out")),
            &rec_err,
        )?));
        wait_ready(&mut process, &ready, 30, &rec_err)?;
        command(
            &self.ns(
                false,
                &self.lab(
                    "capture",
                    &[
                        "marker",
                        "--iface",
                        &self.c.ifa,
                        "--src",
                        &self.c.maca,
                        "--dst",
                        &self.c.macb,
                    ],
                ),
            ),
            20,
            true,
        )?;
        if !wait_file(&ack, 15) {
            return Err("capture start marker not captured by tcpdump".into());
        }
        Ok(Recorder {
            tag: tag.into(),
            pcap,
            meta,
            process,
        })
    }
    /// Finalise the witness (quiescence, end markers, tcpdump stop) and return its verdict meta,
    /// completed with the evidence hash and the scanner-SYN count.
    fn stop_recorder(&mut self, r: &mut Recorder) -> Result<Value, String> {
        // quiescence (<= 20 s) + end markers (<= 15 s) + tcpdump stop (<= 30 s)
        r.process.stop_within("TERM", 90)?;
        let mut meta = read_json(&r.meta)?;
        let frames = self.frames(&r.pcap)?;
        let rec = self.record_hash(&r.tag, &r.pcap)?;
        meta["scanner_syn_frames"] = json!(self.syns(&frames, None).len());
        if meta["pcap_sha256"] != rec["sha256"] {
            meta["valid"] = json!(false);
            meta["invalid_reasons"] = json!(["pcap changed after the witness hashed it"]);
        }
        write_json(&r.meta, &meta)?;
        Ok(meta)
    }
    fn frames(&self, p: &Path) -> Result<Vec<(f64, Vec<u8>)>, String> {
        crate::pcap::read_pcap_records(&fs::read(p).map_err(|e| e.to_string())?).map(|(_, r)| r)
    }
    fn syns<'a>(
        &self,
        frames: &'a [(f64, Vec<u8>)],
        ports: Option<(u16, u16)>,
    ) -> Vec<(f64, &'a [u8])> {
        frames
            .iter()
            .filter_map(|(t, f)| {
                let i = tcp(f)?;
                (i.flags == 2
                    && i.src_mac == self.c.maca
                    && i.dst_mac == self.c.macb
                    && i.src_ip == self.c.ipa
                    && ports.is_none_or(|(lo, hi)| lo <= i.sp && i.sp <= hi))
                .then_some((*t, f.as_slice()))
            })
            .collect()
    }
    fn replies(&self, frames: &[(f64, Vec<u8>)], ports: Option<(u16, u16)>) -> Vec<String> {
        frames
            .iter()
            .filter_map(|(_, f)| {
                let i = tcp(f)?;
                if i.src_mac != self.c.macb
                    || i.dst_mac != self.c.maca
                    || i.dst_ip != self.c.ipa
                    || ports.is_some_and(|(lo, hi)| i.dp < lo || i.dp > hi)
                {
                    return None;
                }
                let state = if i.flags & 0x12 == 0x12 {
                    "open"
                } else if i.flags & 4 != 0 {
                    "closed"
                } else {
                    return None;
                };
                Some(format!("{}:{}:{state}", i.src_ip, i.sp))
            })
            .collect()
    }
    fn run_rust(
        &mut self,
        tag: &str,
        mut args: Vec<String>,
        record: bool,
        action: Action,
    ) -> Result<Run, String> {
        self.fresh()?;
        let mut rec = if record {
            Some(self.recorder(tag, Evidence::Keep)?)
        } else {
            None
        };
        let ready = self
            .c
            .work
            .join(format!("{tag}.{}.ready", crate::windows_suite::nonce()));
        args.extend(strings(&["--ready-file", &ready.to_string_lossy()]));
        let mut a = vec![self.c.rust.clone()];
        a.extend(args);
        let a = self.ns(false, &a);
        let so = self.c.out.join(format!("{tag}.stdout.txt"));
        let se = self.c.out.join(format!("{tag}.stderr.txt"));
        let t = Instant::now();
        let mut p = OwnedChild(Some(spawn(&a, &so, &se)?));
        if action.pause.is_some() || action.remove_link {
            if !wait_file(&ready, 10) {
                return Err("scanner did not become ready".into());
            }
            thread::sleep(Duration::from_millis(if action.remove_link {
                1000
            } else {
                1500
            }));
            if action.remove_link {
                let at = Instant::now();
                command(
                    &strings(&["ip", "-n", &self.c.nsa, "link", "del", &self.c.ifa]),
                    10,
                    true,
                )?;
                self.extra["removal_monotonic_offset"] = json!(at.duration_since(t).as_secs_f64());
            }
            if let Some(p) = action.pause {
                fs::write(p, []).map_err(|e| e.to_string())?;
            }
        }
        let rc = wait_child(&mut p, 90)?;
        let wall = t.elapsed().as_secs_f64();
        let meta = if let Some(r) = &mut rec {
            self.stop_recorder(r)?
        } else {
            Value::Null
        };
        let stdout = fs::read_to_string(&so).map_err(|e| e.to_string())?;
        let mut s = last_json(&stdout);
        if rc == 124 {
            s = json!({"status":"error","error":"TIMEOUT"})
        }
        write_json(self.c.out.join(format!("{tag}.summary.json")), &s)?;
        Ok(Run {
            rc,
            s,
            meta,
            pcap: rec.map(|r| r.pcap),
            wall,
        })
    }
    fn compare(&self, exp: &Path, runs: &[&Run]) -> Result<(i32, String), String> {
        let exp = fs::read(exp).map_err(|e| e.to_string())?;
        let acts = runs
            .iter()
            .map(|r| fs::read(r.pcap.as_ref().ok_or("capture absent")?).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let metas = runs.iter().map(|r| r.meta.clone()).collect::<Vec<_>>();
        Ok(crate::pcap::compare_bytes(
            &exp,
            &acts.iter().map(Vec::as_slice).collect::<Vec<_>>(),
            None,
            &metas,
        ))
    }
    fn oracle(&mut self) -> Result<(), String> {
        let env = read_json(self.c.out.join("env.json"))?["oracle"].clone();
        const PIN: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";
        self.check(
            "oracle",
            "oracle built from pinned revision",
            Some(env["git_commit"] == PIN),
            env.clone(),
        );
        self.check(
            "oracle",
            "oracle source tree clean",
            Some(env["git_tree_clean"] == true),
            env.clone(),
        );
        self.check(
            "oracle",
            "original binary, not offline patched",
            Some(
                env["variant"]
                    .as_str()
                    .is_some_and(|s| s.contains("NOT the --offline-patched")),
            ),
            env.clone(),
        );
        if let Some(manifest) = self.c.fixture("manifest.json").filter(|p| p.exists()) {
            let fx = read_json(manifest)?;
            self.check(
                "oracle",
                "lab oracle binary hash equals fixture oracle",
                Some(env["sha256"].is_string() && env["sha256"] == fx["oracle"]["sha256"]),
                json!({"lab":env["sha256"],"fixture":fx["oracle"]["sha256"]}),
            );
            self.check(
                "oracle",
                "fixture revision pinned and captures all valid",
                Some(fx["oracle"]["git_commit"] == PIN && fx["all_valid"] == true),
                fx,
            );
        }
        self.extra["oracle"] = env;
        Ok(())
    }
    fn parity(&mut self) -> Result<(), String> {
        for c in cases() {
            let fx = self
                .c
                .fixture(&format!("{}.run1.pcap", c.name))
                .ok_or("the rust suite needs --fixtures")?;
            let mut cr = self.replies(&self.frames(&fx)?, None);
            cr.sort();
            for rep in 1..=2 {
                let tag = format!("rust.{}.run{rep}", c.name);
                let r = self.run_rust(
                    &tag,
                    self.rust_args(c.targets, c.ports, 100, 3, c.sp, c.exclude),
                    true,
                    Action::default(),
                )?;
                let s = &r.s;
                let valid = r.meta["valid"] == true;
                let ok = r.rc == 0 && s["reason"] == "Completed" && valid;
                if !ok {
                    self.check(
                        "parity",
                        &tag,
                        if valid { Some(false) } else { None },
                        json!({"rc":r.rc,"summary":s,"capture":r.meta}),
                    );
                    continue;
                }
                let (code, msg) = self.compare(&fx, &[&r])?;
                self.check(
                    "parity",
                    &format!("{tag} SYN stream vs C oracle"),
                    if code == 2 { None } else { Some(code == 0) },
                    json!(msg),
                );
                let mine = sorted_replies(s);
                self.check(
                    "parity",
                    &format!("{tag} replies equal C reply set"),
                    Some(mine == cr),
                    json!({"rust":mine,"c":cr}),
                );
                let wire =
                    self.replies(&self.frames(r.pcap.as_ref().ok_or("pcap missing")?)?, None);
                let unique = wire
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                self.check(
                    "parity",
                    &format!("{tag} dedup and exact wire results"),
                    Some(
                        n(s, "reply_total") == n(s, "reply_unique")
                            && n(s, "received") == mine.len() as u64
                            && n(s, "reply_total") == mine.len() as u64
                            && unique == mine
                            && n(s, "received").saturating_add(n(s, "duplicates"))
                                <= wire.len() as u64,
                    ),
                    json!({"summary":s,"wire_replies":wire.len()}),
                );
                self.check(
                    "parity",
                    &format!("{tag} expected SYN/open/closed counts"),
                    Some(
                        n(s, "sent") == c.syn
                            && mine.iter().filter(|v| v.ends_with(":open")).count() as u64
                                == c.open
                            && mine.iter().filter(|v| v.ends_with(":closed")).count() as u64
                                == c.closed,
                    ),
                    s.clone(),
                );
                self.check(
                    "parity",
                    &format!("{tag} measured zero RX drops"),
                    Some(rx_health_ok(s)),
                    s["rx_health"].clone(),
                );
                self.check(
                    "parity",
                    &format!("{tag} no TX beyond Sent"),
                    Some(
                        n(&s["net"], "tx_sent") == n(s, "sent")
                            && n(&s["net"], "tx_uncertain") == 0
                            && n(&s["net"], "tx_errors") == 0,
                    ),
                    s["net"].clone(),
                );
                self.save(true)?;
            }
        }
        Ok(())
    }
    fn reject(&mut self, label: &str, r: &Run, want: &str) -> Result<(), String> {
        let count = self
            .syns(
                &self.frames(r.pcap.as_ref().ok_or("rejection capture missing")?)?,
                None,
            )
            .len();
        let s = &r.s;
        self.check(
            "reject",
            label,
            if r.meta["valid"] == true {
                Some(
                    r.rc == 4
                        && s["status"] == "error"
                        && s["error"].as_str().is_some_and(|x| x.starts_with(want))
                        && s["opened_adapter"] == false
                        && n(s, "tx_sent") == 0
                        && count == 0,
                )
            } else {
                None
            },
            json!({"wanted":want,"rc":r.rc,"summary":s,"wire_syns":count}),
        );
        Ok(())
    }
    fn pause_resume(&mut self) -> Result<(), String> {
        let c = cases()[2].clone();
        let base = self.rust_args(c.targets, c.ports, 100, 3, c.sp, None);
        let cont = self.c.out.join(format!("rust.{}.run1.pcap", c.name));
        let sum = read_json(
            self.c
                .out
                .join(format!("rust.{}.run1.summary.json", c.name)),
        )?;
        let full = sorted_replies(&sum);
        let range = sum["range"].as_u64().ok_or("continuous range missing")?;
        if range != 16 {
            return Err("continuous pause case range differs from oracle 16".into());
        }
        let fixture = self
            .c
            .fixture(&format!("{}.run1.pcap", c.name))
            .ok_or("the rust suite needs --fixtures")?;
        const SCAN: &str = "11111111111111111111111111111111";
        const A1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const A2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let mut mid = None;
        self.extra["pause_resume"] = json!([]);
        for x in [0, 1, range / 2, range - 1] {
            let tag = format!("pr_N{x}");
            let cp = self.c.out.join(format!("{tag}.checkpoint.bin"));
            let mut a = base.clone();
            a.extend(strings(&[
                "--scan-id",
                SCAN,
                "--attempt-id",
                A1,
                "--pause-after",
                &x.to_string(),
                "--checkpoint-out",
                &cp.to_string_lossy(),
            ]));
            let r1 = self.run_rust(&format!("{tag}.pause"), a, true, Action::default())?;
            let s1 = &r1.s;
            let ok = r1.rc == 0
                && s1["reason"] == "Paused"
                && n(s1, "sent") == x
                && n(s1, "next_index") == x
                && s1["checkpoint"] == true
                && n(&s1["net"], "tx_sent") == x
                && r1.meta["valid"] == true;
            self.check(
                "pause",
                &format!("N={x} pause confirmed boundary"),
                if r1.meta["valid"] == true {
                    Some(ok)
                } else {
                    None
                },
                s1.clone(),
            );
            if !ok {
                continue;
            }
            let raw = fs::read(&cp).map_err(|e| e.to_string())?;
            self.check(
                "pause",
                &format!("N={x} checkpoint bytes match summary"),
                Some(raw.len() == 120 && hex(&raw) == s1["checkpoint_hex"].as_str().unwrap_or("")),
                json!({"size":raw.len(),"sha256":hash(&cp)?}),
            );
            let mut a = base.clone();
            a.extend(strings(&[
                "--scan-id",
                SCAN,
                "--attempt-id",
                A2,
                "--resume-checkpoint",
                &cp.to_string_lossy(),
            ]));
            let r2 = self.run_rust(&format!("{tag}.resume"), a, true, Action::default())?;
            let s2 = &r2.s;
            let ok = r2.rc == 0
                && s2["reason"] == "Completed"
                && n(s2, "sent") == range - x
                && r2.meta["valid"] == true;
            self.check(
                "pause",
                &format!("N={x} resume Completed"),
                if r2.meta["valid"] == true {
                    Some(ok)
                } else {
                    None
                },
                s2.clone(),
            );
            if !ok {
                continue;
            }
            for (label, exp) in [("continuous Rust", &cont), ("C oracle", &fixture)] {
                let (code, msg) = self.compare(exp, &[&r1, &r2])?;
                self.check(
                    "pause",
                    &format!("N={x} concatenated captures == {label}"),
                    if code == 2 { None } else { Some(code == 0) },
                    json!(msg),
                );
            }
            self.check(
                "pause",
                &format!("N={x} scan identity and changed attempt"),
                Some(
                    s1["scan_id"] == SCAN
                        && s2["scan_id"] == SCAN
                        && s1["attempt_id"] == A1
                        && s2["attempt_id"] == A2
                        && s2["resumed_from_attempt"] == A1
                        && s1["resumed_from_attempt"].is_null(),
                ),
                json!({"pause":s1,"resume":s2}),
            );
            let mut union = sorted_replies(s1);
            union.extend(sorted_replies(s2));
            union.sort();
            self.check(
                "pause",
                &format!("N={x} reply union equals continuous without duplicates"),
                Some(union == full && union.iter().collect::<BTreeSet<_>>().len() == union.len()),
                json!({"union":union,"continuous":full}),
            );
            let n1 = self
                .syns(&self.frames(r1.pcap.as_ref().ok_or("pause pcap")?)?, None)
                .len() as u64;
            let n2 = self
                .syns(&self.frames(r2.pcap.as_ref().ok_or("resume pcap")?)?, None)
                .len() as u64;
            self.check(
                "pause",
                &format!("N={x} no lost or added probe across seam"),
                Some(n1 == x && n2 == range - x),
                json!([n1, n2, range]),
            );
            self.extra["pause_resume"].as_array_mut().ok_or("pause result array")?.push(json!({"n":x,"checkpoint_sha256":hash(&cp)?,"pause_pcap":r1.pcap.and_then(|p|p.file_name().map(|s|s.to_string_lossy().into_owned())),"resume_pcap":r2.pcap.and_then(|p|p.file_name().map(|s|s.to_string_lossy().into_owned()))}));
            if x == range / 2 {
                mid = Some(cp);
            }
            self.save(true)?;
        }
        let cp = self.c.out.join("pr_completed.checkpoint.bin");
        let mut a = base.clone();
        a.extend(strings(&[
            "--scan-id",
            SCAN,
            "--attempt-id",
            A1,
            "--pause-after",
            &range.to_string(),
            "--checkpoint-out",
            &cp.to_string_lossy(),
        ]));
        let r = self.run_rust("pr_completed", a, true, Action::default())?;
        self.check(
            "pause",
            "pause-after=range ends Completed without checkpoint",
            Some(
                r.rc == 0
                    && r.s["reason"] == "Completed"
                    && r.s["checkpoint"] == false
                    && !cp.exists(),
            ),
            r.s,
        );
        let forged = self.c.out.join("forged_completed.checkpoint.bin");
        let mut forge = vec![self.c.rust.clone()];
        forge.extend(base.clone());
        forge.extend(strings(&[
            "--scan-id",
            SCAN,
            "--attempt-id",
            A1,
            "--forge-checkpoint-next-index",
            &range.to_string(),
            "--checkpoint-out",
            &forged.to_string_lossy(),
        ]));
        command(&forge, 30, true)?;
        let mut a = base.clone();
        a.extend(strings(&[
            "--scan-id",
            SCAN,
            "--attempt-id",
            A2,
            "--resume-checkpoint",
            &forged.to_string_lossy(),
        ]));
        let r = self.run_rust("rej_completed", a, true, Action::default())?;
        self.reject(
            "completed checkpoint rejected before adapter",
            &r,
            "AlreadyCompleted",
        )?;
        let Some(cp) = mid else {
            self.check(
                "reject",
                "real mid-scan checkpoint required for rejection matrix",
                None,
                json!("midpoint pause/resume failed"),
            );
            return Ok(());
        };
        for (label, key, val, want) in [
            ("changed_rate", "--rate", "200", "JobMismatch"),
            (
                "changed_binding_source_MAC",
                "--src-mac",
                "02:aa:00:00:00:09",
                "JobMismatch",
            ),
            (
                "changed_binding_interface_name",
                "--iface",
                "veth-x",
                "JobMismatch",
            ),
            (
                "changed_targets",
                "--targets",
                "10.200.0.2-10.200.0.4",
                "JobMismatch",
            ),
            ("changed_ports", "--ports", "80,81,443", "JobMismatch"),
            ("changed_seed", "--seed", "2", "JobMismatch"),
            (
                "different_scan_id",
                "--scan-id",
                "22222222222222222222222222222222",
                "ScanIdMismatch",
            ),
            ("attempt_id_reused", "--attempt-id", A1, "AttemptIdReused"),
        ] {
            let mut a = base.clone();
            a.extend(strings(&[
                "--scan-id",
                SCAN,
                "--attempt-id",
                A2,
                "--resume-checkpoint",
                &cp.to_string_lossy(),
            ]));
            set_arg(&mut a, key, val)?;
            let r = self.run_rust(&format!("rej_{label}"), a, true, Action::default())?;
            self.reject(label, &r, want)?;
        }
        let raw = fs::read(&cp).map_err(|e| e.to_string())?;
        for (variant, want) in [
            ("corrupt_next_index", "BadChecksum"),
            ("corrupt_checksum", "BadChecksum"),
            ("truncated", "Malformed"),
            ("empty", "Malformed"),
        ] {
            let bad = self.c.out.join(format!("bad.{variant}.checkpoint.bin"));
            fs::write(
                &bad,
                crate::windows_suite::mutate_checkpoint(variant, &raw)?,
            )
            .map_err(|e| e.to_string())?;
            let mut a = base.clone();
            a.extend(strings(&[
                "--scan-id",
                SCAN,
                "--attempt-id",
                A2,
                "--resume-checkpoint",
                &bad.to_string_lossy(),
            ]));
            let r = self.run_rust(&format!("rej_{variant}"), a, true, Action::default())?;
            self.reject(variant, &r, want)?;
        }
        Ok(())
    }
    fn stop_common(&mut self, tag: &str, r: &Run) -> Result<(), String> {
        let s = &r.s;
        let timing = &s["timing"];
        self.check(
            "stop",
            &format!("{tag}: bounded Stop and join, no checkpoint"),
            Some(
                r.rc == 0
                    && s["reason"] == "Stopped"
                    && s["checkpoint"] == false
                    && timing["stop_to_outcome_ms"]
                        .as_f64()
                        .is_some_and(|n| n < 1000.0)
                    && timing["join_ms"].as_f64().is_some_and(|n| n < 1000.0),
            ),
            s.clone(),
        );
        let wire = self
            .syns(
                &self.frames(r.pcap.as_ref().ok_or("stop capture missing")?)?,
                None,
            )
            .len() as u64;
        self.check(
            "stop",
            &format!("{tag}: TX frozen after Stop and wire matches"),
            Some(
                n(s, "tx_sent_at_join") == n(s, "tx_sent_after_observe")
                    && n(s, "tx_sent_at_join") == n(&s["net"], "tx_sent")
                    && r.meta["valid"] == true
                    && wire == n(&s["net"], "tx_sent"),
            ),
            json!({"wire_syns":wire,"summary":s}),
        );
        self.check(
            "stop",
            &format!("{tag}: no leaked workers or descriptors"),
            Some(leak_ok(s)),
            s["resources"].clone(),
        );
        Ok(())
    }
    fn stops(&mut self) -> Result<(), String> {
        for (tag, targets, ports, extra) in [
            (
                "stop_silence",
                "10.200.0.77",
                "1-100",
                strings(&["--stop-after-ms", "2500", "--observe-ms", "1500"]),
            ),
            (
                "stop_drain",
                "10.200.0.2",
                "80,81",
                strings(&["--stop-in-drain", "--observe-ms", "1500"]),
            ),
            (
                "stop_fullqueue",
                "10.200.0.2",
                "80,81",
                strings(&[
                    "--result-capacity",
                    "2",
                    "--no-consume",
                    "--stop-after-ms",
                    "4500",
                    "--observe-ms",
                    "1500",
                ]),
            ),
        ] {
            let mut a = self.rust_args(targets, ports, 1, 10, "40000", None);
            a.extend(extra);
            let r = self.run_rust(tag, a, true, Action::default())?;
            self.stop_common(tag, &r)?;
            let ok = match tag {
                "stop_silence" => {
                    n(&r.s, "reply_total") == 0
                        && n(&r.s, "sent") > 0
                        && n(&r.s, "sent") < n(&r.s, "range")
                }
                "stop_drain" => r.s["timing"]["total_s"].as_f64().is_some_and(|n| n < 6.0),
                _ => n(&r.s, "reply_total") == 2 && r.s["reason"] == "Stopped",
            };
            self.check("stop", &format!("{tag}: scenario exercised"), Some(ok), r.s);
        }
        let mut a = self.rust_args("10.200.0.2", "80,81,82,83,84,85", 1, 10, "40000", None);
        a.extend(strings(&[
            "--result-capacity",
            "1",
            "--no-consume",
            "--observe-ms",
            "1500",
        ]));
        let r = self.run_rust("overflow", a, true, Action::default())?;
        let s = &r.s;
        self.check(
            "stop",
            "queue overflow Failed(ConsumerTooSlow), no checkpoint, TX halted, no leaks",
            Some(
                r.rc == 3
                    && s["reason"] == "Failed"
                    && s["fail_detail"]
                        .as_str()
                        .is_some_and(|v| v.contains("ConsumerTooSlow"))
                    && s["checkpoint"] == false
                    && n(s, "tx_sent_at_join") == n(s, "tx_sent_after_observe")
                    && leak_ok(s)
                    && n(s, "sent") < n(s, "range"),
            ),
            s.clone(),
        );
        let pf = self
            .c
            .work
            .join(format!("pause-{}.file", crate::windows_suite::nonce()));
        let mut a = self.rust_args("10.200.0.77", "1-100", 1, 1, "40000", None);
        a.extend(strings(&[
            "--pause-file",
            &pf.to_string_lossy(),
            "--observe-ms",
            "500",
        ]));
        let r = self.run_rust(
            "pause_rate1",
            a,
            true,
            Action {
                pause: Some(pf),
                ..Action::default()
            },
        )?;
        let s = &r.s;
        self.check(
            "stop",
            "rate=1 external Pause checkpoint at confirmed boundary",
            Some(
                r.rc == 0
                    && s["reason"] == "Paused"
                    && s["checkpoint"] == true
                    && n(s, "next_index") == n(s, "sent")
                    && n(s, "sent") == n(&s["net"], "tx_sent"),
            ),
            s.clone(),
        );
        Ok(())
    }
    fn rx_overflow(&mut self) -> Result<(), String> {
        let cp = self.c.out.join("rx_overflow.checkpoint.bin");
        if cp.exists() {
            return Err("refusing stale RX overflow checkpoint".into());
        }
        let mut a = self.rust_args("10.200.0.0/24", "1-100", 10000, 1, "40000", None);
        a.extend(strings(&[
            "--rx-stall-ms",
            "2500",
            "--checkpoint-out",
            &cp.to_string_lossy(),
            "--observe-ms",
            "500",
        ]));
        let r = self.run_rust("rx_overflow", a, true, Action::default())?;
        let s = &r.s;
        self.extra["rx_overflow"] = json!({"rc":r.rc,"reason":s["reason"],"fail_detail":s["fail_detail"],"rx_health":s["rx_health"],"net":s["net"],"checkpoint":s["checkpoint"],"checkpoint_file":cp.exists(),"sent":s["sent"],"range":s["range"]});
        let measured = s["rx_health"]["kernel_drops"]
            .as_u64()
            .is_some_and(|v| v > 0);
        self.check(
            "rxloss",
            "RX overflow reproduced: measured kernel drops > 0",
            if measured { Some(true) } else { None },
            self.extra["rx_overflow"].clone(),
        );
        if !measured {
            return Ok(());
        }
        self.check(
            "rxloss",
            "overflow Failed(RxLoss) with nonzero exit",
            Some(
                r.rc == 3
                    && s["reason"] == "Failed"
                    && s["fail_detail"]
                        .as_str()
                        .is_some_and(|v| v.contains("RxLoss")),
            ),
            s.clone(),
        );
        self.check(
            "rxloss",
            "overflow no checkpoint file or hex",
            Some(s["checkpoint"] == false && s["checkpoint_hex"].is_null() && !cp.exists()),
            s.clone(),
        );
        self.check(
            "rxloss",
            "overflow TX halted, no leaked workers/descriptors",
            Some(n(s, "tx_sent_at_join") == n(s, "tx_sent_after_observe") && leak_ok(s)),
            s.clone(),
        );
        Ok(())
    }
    fn veth_removal(&mut self) -> Result<(), String> {
        let cp = self.c.out.join("veth_removal.checkpoint.bin");
        let mut a = self.rust_args("10.200.0.2-10.200.0.5", "1-100", 50, 3, "40000", None);
        a.extend(strings(&[
            "--checkpoint-out",
            &cp.to_string_lossy(),
            "--observe-ms",
            "500",
        ]));
        let r = self.run_rust(
            "veth_removal",
            a,
            false,
            Action {
                remove_link: true,
                ..Action::default()
            },
        )?;
        let elapsed = self.extra["removal_monotonic_offset"]
            .as_f64()
            .map(|t| r.wall - t);
        let s = &r.s;
        self.check(
            "veth",
            "removed link fails with diagnosable TX/RX error and exit 3",
            Some(
                r.rc == 3
                    && s["reason"] == "Failed"
                    && s["fail_detail"]
                        .as_str()
                        .is_some_and(|v| v.contains("TxError") || v.contains("RxError")),
            ),
            s.clone(),
        );
        self.check(
            "veth",
            "removed link: no checkpoint",
            Some(s["checkpoint"] == false && s["checkpoint_hex"].is_null() && !cp.exists()),
            s.clone(),
        );
        self.check(
            "veth",
            "removed link: partial scan, frozen TX, no leaks",
            Some(
                n(s, "sent") > 0
                    && n(s, "sent") < n(s, "range")
                    && n(s, "tx_sent_at_join") == n(s, "tx_sent_after_observe")
                    && leak_ok(s),
            ),
            s.clone(),
        );
        self.check(
            "veth",
            "removed link: process exits under 5s",
            Some(elapsed.is_some_and(|v| v < 5.0)),
            json!(elapsed),
        );
        self.extra["veth_removal"] =
            json!({"fail_detail":s["fail_detail"],"exit_after_removal_s":elapsed,"net":s["net"]});
        Ok(())
    }
    fn c_args(&self, targets: &str, ports: &str, rate: u64, txt: &Path) -> Vec<String> {
        let a = strings(&[
            targets,
            &format!("-p{ports}"),
            "--source-port",
            "40000",
            "--interface",
            &self.c.ifa,
            "--adapter-ip",
            &self.c.ipa,
            "--adapter-mac",
            &self.c.maca,
            "--router-mac",
            &self.c.macb,
            "--seed",
            "1",
            "--rate",
            &rate.to_string(),
            "--blackrock-rounds",
            "14",
            "--retries",
            "0",
            "--wait",
            "1",
            "-oL",
            &txt.to_string_lossy(),
        ]);
        let mut cmd = if self.c.masked {
            strings(&[
                "unshare",
                "-m",
                "sh",
                "-c",
                "mount --bind \"$0\" /etc/masscan && exec \"$@\"",
                &self.c.empty,
                &self.c.oracle,
            ])
        } else {
            vec![self.c.oracle.clone()]
        };
        cmd.extend(a);
        self.ns(false, &cmd)
    }
    fn measured(
        &self,
        tag: &str,
        argv: &[String],
        stop: Action,
    ) -> Result<(i32, f64, Option<f64>, String, Value), String> {
        let so = self.c.work.join(format!("{tag}.stdout"));
        let se = self.c.work.join(format!("{tag}.stderr"));
        let usage = self.c.work.join(format!("{tag}.rusage"));
        let mut wrapped = strings(&[GNU_TIME, "-v", "-o", &usage.to_string_lossy()]);
        wrapped.extend_from_slice(argv);
        let mut p = OwnedChild(Some(
            Command::new(&wrapped[0])
                .args(&wrapped[1..])
                .current_dir(&self.c.work)
                .stdout(Stdio::from(
                    fs::File::create(&so).map_err(|e| e.to_string())?,
                ))
                .stderr(Stdio::from(
                    fs::File::create(&se).map_err(|e| e.to_string())?,
                ))
                .spawn()
                .map_err(|e| e.to_string())?,
        ));
        let t = Instant::now();
        let mut sent = None;
        let mut hwm = 0;
        let rc = loop {
            let child = p.0.as_mut().ok_or("measured child absent")?;
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                break st.code().unwrap_or(-1);
            }
            let children =
                fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id()))
                    .unwrap_or_default();
            let process = children
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<u32>().ok());
            if stop_requested() {
                if let Some(pid) = process {
                    signal_process("TERM", pid);
                }
                return Err("suite interrupted".into());
            }
            if let Some(pid) = process
                && let Ok(s) = fs::read_to_string(format!("/proc/{pid}/status"))
                && let Some(v) = s
                    .lines()
                    .find(|s| s.starts_with("VmHWM:"))
                    .and_then(|s| s.split_whitespace().nth(1))
                    .and_then(|s| s.parse::<u64>().ok())
            {
                hwm = hwm.max(v);
            }
            if sent.is_none()
                && t.elapsed().as_secs_f64() >= 2.0
                && (stop.stop_sig || stop.stop_file.is_some())
            {
                if stop.stop_sig {
                    let pid = process.ok_or("cannot identify measured C scanner PID")?;
                    command(&strings(&["kill", "-INT", &pid.to_string()]), 5, true)?;
                }
                if let Some(file) = &stop.stop_file {
                    fs::write(file, []).map_err(|e| e.to_string())?;
                }
                sent = Some(t.elapsed().as_secs_f64());
            }
            if t.elapsed() > Duration::from_secs(120) {
                if let Some(pid) = process {
                    let _ = command(&strings(&["kill", "-KILL", &pid.to_string()]), 5, false);
                }
                let _ = child.kill();
                let _ = child.wait();
                break 124;
            }
            thread::sleep(Duration::from_millis(2));
        };
        let wall = t.elapsed().as_secs_f64();
        p.0 = None;
        let raw = fs::read_to_string(&usage).unwrap_or_default();
        let metric = |name: &str| gnu_time_metric(&raw, name);
        let ru = json!({"cpu_user_s":metric("User time (seconds):"),"cpu_sys_s":metric("System time (seconds):"),"max_rss_kb":if hwm>0{Some(hwm)}else{None},"rusage_max_rss_kb":metric("Maximum resident set size (kbytes):"),"cpu_method":"GNU time wait4, child /proc VmHWM sampled"});
        Ok((
            rc,
            wall,
            sent.map(|s| wall - s),
            fs::read_to_string(so).map_err(|e| e.to_string())?,
            ru,
        ))
    }
    fn perf_cell(&mut self, implementation: &str, rate: u64, rep: u64) -> Result<Value, String> {
        let (targets, ports, stop_ports) = perf_case(rate)?;
        let total = probes(targets, ports)?;
        let (exp_open, exp_closed) = expected_replies(ports)?;
        let tag = format!("perf.{implementation}.{rate}.r{rep}");
        self.fresh()?;
        let mut rec = self.recorder(&tag, Evidence::Scratch)?;
        let txt = self.c.work.join(format!("{tag}.scan.txt"));
        let argv = if implementation == "c" {
            self.c_args(targets, ports, rate, &txt)
        } else {
            let mut a = vec![self.c.rust.clone()];
            a.extend(self.rust_args(targets, ports, rate, 1, "40000", None));
            self.ns(false, &a)
        };
        let (rc, wall, _, so, ru) = self.measured(&tag, &argv, Action::default())?;
        let meta = self.stop_recorder(&mut rec)?;
        let frames = self.frames(&rec.pcap)?;
        let syns = self.syns(&frames, Some((40000, 40000)));
        let times = syns.iter().map(|(t, _)| *t).collect::<Vec<_>>();
        let replies = self.replies(&frames, Some((40000, 40000)));
        let unique = replies.iter().collect::<BTreeSet<_>>();
        let wire_open = unique.iter().filter(|v| v.ends_with(":open")).count();
        let wire_closed = unique.iter().filter(|v| v.ends_with(":closed")).count();
        let mut cell = json!({"impl":implementation,"rate":rate,"rep":rep,"rc":rc,"probes":total,"wall_s":wall,"capture":meta,"transmitted_wire":syns.len(),"cpu_user_s":ru["cpu_user_s"],"cpu_sys_s":ru["cpu_sys_s"],"max_rss_kb":ru["max_rss_kb"],"cpu_method":ru["cpu_method"],"expected_open":exp_open,"expected_closed":exp_closed,"peer_replies_on_wire":replies.len(),"peer_open_on_wire":wire_open,"peer_closed_on_wire":wire_closed,"steady_pps_wire":crate::pcap::steady_state_rate(&times),"naive_pps_wall":total as f64/wall});
        if implementation == "rust" {
            let s = last_json(&so);
            let replies = sorted_replies(&s);
            cell["received_open"] = json!(replies.iter().filter(|v| v.ends_with(":open")).count());
            cell["received_closed"] =
                json!(replies.iter().filter(|v| v.ends_with(":closed")).count());
            for (dest, src) in [
                ("transmitted_stats", "tx_sent"),
                ("tx_would_block", "tx_would_block"),
                ("net_kernel_drops", "kernel_drops"),
                ("rx_packets", "rx_packets"),
            ] {
                cell[dest] = s["net"][src].clone();
            }
            cell["steady_pps_inprocess"] = s["timing"]["steady_pps"].clone();
            cell["rx_health_kernel_drops"] = s["rx_health"]["kernel_drops"].clone();
            cell["rx_health_ok"] = json!(rx_health_ok(&s));
            cell["reason"] = s["reason"].clone();
            cell["complete"] = json!(s["reason"] == "Completed");
            cell["rx_dedup_suppressed"] = s["duplicates"].clone();
            write_json(self.c.out.join(format!("{tag}.summary.json")), &s)?;
        } else {
            let data = fs::read_to_string(&txt).unwrap_or_default();
            let lines = data
                .lines()
                .filter(|l| l.starts_with("open "))
                .collect::<Vec<_>>();
            let uniq = lines
                .iter()
                .map(|l| l.split_whitespace().skip(2).take(2).collect::<Vec<_>>())
                .collect::<BTreeSet<_>>();
            cell["received_open"] = json!(uniq.len());
            cell["received_open_lines"] = json!(lines.len());
            cell["received_closed"] = Value::Null;
            cell["complete"] = json!(rc == 0);
        }
        let tx = rc == 0
            && syns.len() as u64 == total
            && (implementation == "c" || cell["transmitted_stats"].as_u64() == Some(total));
        // C reports null for closed ports; any other non-integer must not pass as "absent".
        let received_closed = (!cell["received_closed"].is_null())
            .then(|| cell["received_closed"].as_u64().unwrap_or(u64::MAX));
        cell["rx_complete"] = json!(rx_is_complete(
            cell["received_open"].as_u64(),
            received_closed,
            wire_open as u64,
            wire_closed as u64
        ));
        cell["valid"] = json!(meta["valid"] == true && tx);
        cell["invalid_reason"] = if cell["valid"] == true {
            Value::Null
        } else {
            json!(format!(
                "capture_valid={} every_probe_transmitted={tx} wire={}/{} rc={rc}",
                meta["valid"],
                syns.len(),
                total
            ))
        };
        self.save(true)?;
        fs::remove_file(&rec.pcap).map_err(|e| e.to_string())?;
        self.fresh()?;
        let sttag = format!("{tag}.stop");
        let mut rec = self.recorder(&sttag, Evidence::Scratch)?;
        let sf = self
            .c
            .work
            .join(format!("{tag}.{}.stopfile", crate::windows_suite::nonce()));
        let stxt = self.c.work.join(format!("{tag}.stop.scan.txt"));
        let argv = if implementation == "c" {
            self.c_args(targets, stop_ports, rate, &stxt)
        } else {
            let mut a = vec![self.c.rust.clone()];
            a.extend(self.rust_args(targets, stop_ports, rate, 1, "40000", None));
            a.extend(strings(&[
                "--stop-file",
                &sf.to_string_lossy(),
                "--observe-ms",
                "0",
            ]));
            self.ns(false, &a)
        };
        let action = Action {
            stop_sig: implementation == "c",
            stop_file: if implementation == "rust" {
                Some(sf)
            } else {
                None
            },
            ..Action::default()
        };
        let (rc, wall, stop_time, stdout, _) = self.measured(&sttag, &argv, action)?;
        let meta = self.stop_recorder(&mut rec)?;
        let frames = self.frames(&rec.pcap)?;
        let syns = self.syns(&frames, Some((40000, 40000))).len() as u64;
        let sttotal = probes(targets, stop_ports)?;
        cell["stop"] = json!({"rc":rc,"probes":sttotal,"stop_to_exit_s":stop_time,"wall_s":wall,"wire_syns":syns,"capture_valid":meta["valid"],"stopped_early":syns<sttotal});
        if implementation == "rust" {
            let s = last_json(&stdout);
            cell["stop"]["reason"] = s["reason"].clone();
            cell["stop"]["stop_to_outcome_ms"] = s["timing"]["stop_to_outcome_ms"].clone();
            cell["stop"]["join_ms"] = s["timing"]["join_ms"].clone();
            cell["stop"]["tx_sent"] = s["net"]["tx_sent"].clone();
        }
        cell["stop"]["valid"] = json!(stop_stage_valid(&cell["stop"], implementation));
        self.save(true)?;
        fs::remove_file(rec.pcap).map_err(|e| e.to_string())?;
        println!(
            "[perf] {implementation} {rate} rep{rep} valid={} steady={}",
            cell["valid"], cell["steady_pps_wire"]
        );
        Ok(cell)
    }
    fn perf(&mut self, rates: &[u64], reps: u64) -> Result<(), String> {
        let mut cells = vec![];
        for &rate in rates {
            for rep in 1..=reps {
                for implementation in ["c", "rust"] {
                    // An interrupted run is partial: it must neither start further cells (each would respawn a
                    // responder) nor be written up as a complete matrix with every remaining cell failed.
                    if stop_requested() {
                        self.extra["perf_cells"] = json!(cells);
                        self.extra["interrupted"] = json!(true);
                        self.save(true)?;
                        return Err(format!(
                            "suite interrupted: perf run is partial ({} of {} cells recorded)",
                            cells.len(),
                            rates.len() as u64 * reps * 2
                        ));
                    }
                    match self.perf_cell(implementation, rate, rep) {
                        Ok(c) => cells.push(c),
                        Err(e) => {
                            if stop_requested() {
                                self.extra["perf_cells"] = json!(cells);
                                self.extra["interrupted"] = json!(true);
                                self.save(true)?;
                                return Err(format!(
                                    "suite interrupted: perf run is partial ({e})"
                                ));
                            }
                            cells.push(json!({"impl":implementation,"rate":rate,"rep":rep,"valid":false,"invalid_reason":format!("driver error: {e}")}))
                        }
                    }
                    self.extra["perf_cells"] = json!(cells);
                    self.save(true)?;
                }
            }
        }
        self.perf_summarize(&cells, rates);
        Ok(())
    }
    fn perf_summarize(&mut self, cells: &[Value], rates: &[u64]) {
        let mut rows = vec![];
        for &rate in rates {
            let mut row = json!({"rate":rate});
            for implementation in ["c", "rust"] {
                let cs = cells
                    .iter()
                    .filter(|c| c["impl"] == implementation && c["rate"] == rate)
                    .collect::<Vec<_>>();
                let valid = cs
                    .iter()
                    .copied()
                    .filter(|c| c["valid"] == true)
                    .collect::<Vec<_>>();
                row[format!("{implementation}_valid")] = json!(valid.len());
                row[format!("{implementation}_invalid")] = json!(cs.len() - valid.len());
                for (src, dst) in [
                    ("steady_pps_wire", "steady_pps_median"),
                    ("transmitted_wire", "transmitted_median"),
                    ("cpu_user_s", "cpu_user_median"),
                    ("cpu_sys_s", "cpu_sys_median"),
                    ("max_rss_kb", "rss_kb_median"),
                ] {
                    row[format!("{implementation}_{dst}")] = json!(median(
                        valid.iter().filter_map(|c| c[src].as_f64()).collect()
                    ));
                }
                row[format!("{implementation}_rx_incomplete_runs")] =
                    json!(cs.iter().filter(|c| c["rx_complete"] == false).count());
                row[format!("{implementation}_capture_invalid_runs")] = json!(
                    cs.iter()
                        .filter(|c| c["capture"].is_object() && c["capture"]["valid"] != true)
                        .count()
                );
                // LR N4: the witness uses tcpdump -U --immediate-mode, which can drop frames in the kernel at
                // 100k pps and make a cell INVALID for capture reasons. Show the drops of every cell and the
                // reasons; INVALID cells stay out of the medians and the matrix check, never normalised.
                row[format!("{implementation}_capture_kernel_drops_per_run")] = json!(
                    cs.iter()
                        .map(|c| c["capture"]["kernel_drops"].clone())
                        .collect::<Vec<_>>()
                );
                row[format!("{implementation}_capture_invalid_reasons")] = json!(
                    cs.iter()
                        .filter_map(|c| c["capture"]["invalid_reasons"].as_array())
                        .flatten()
                        .cloned()
                        .collect::<Vec<_>>()
                );
                // An INVALID Stop stage (bad capture, non-zero exit, no early stop, wrong Rust outcome) is out of the
                // median and counted apart, like an INVALID main run.
                row[format!("{implementation}_stop_s_median")] = json!(median(
                    cs.iter()
                        .filter(|c| c["stop"]["valid"] == true)
                        .filter_map(|c| c["stop"]["stop_to_exit_s"].as_f64())
                        .collect()
                ));
                row[format!("{implementation}_stop_invalid_runs")] =
                    json!(cs.iter().filter(|c| c["stop"]["valid"] != true).count());
                if implementation == "rust" {
                    row["rust_kernel_drops_per_run"] = json!(
                        cs.iter()
                            .map(|c| c["net_kernel_drops"].clone())
                            .collect::<Vec<_>>()
                    );
                    row["rust_rx_health_drops_per_run"] = json!(
                        cs.iter()
                            .map(|c| c["rx_health_kernel_drops"].clone())
                            .collect::<Vec<_>>()
                    );
                    row["rust_rx_health_bad_runs"] =
                        json!(cs.iter().filter(|c| c["rx_health_ok"] != true).count());
                    row["rust_would_block_total"] = json!(
                        cs.iter()
                            .filter_map(|c| c["tx_would_block"].as_u64())
                            .sum::<u64>()
                    );
                }
            }
            let ratio = match (
                row["rust_steady_pps_median"].as_f64(),
                row["c_steady_pps_median"].as_f64(),
            ) {
                (Some(r), Some(c)) if c > 0.0 && r > 0.0 => Some(r / c),
                _ => None,
            };
            row["rust_over_c"] = json!(ratio);
            row["within_20pct"] = json!(ratio.map(|r| (0.8..=1.2).contains(&r)));
            rows.push(row);
        }
        self.check(
            "perf",
            "matrix complete: every cell VALID",
            Some(
                !cells.is_empty()
                    && cells
                        .iter()
                        .all(|c| c["valid"] == true && c["stop"]["valid"] == true),
            ),
            json!({"cells":cells.len(),"valid":cells.iter().filter(|c|c["valid"]==true).count(),"stop_valid":cells.iter().filter(|c|c["stop"]["valid"]==true).count()}),
        );
        self.check(
            "perf",
            "every Rust run Completed with measured zero RX drops",
            Some(rows.iter().all(|r| r["rust_rx_health_bad_runs"] == 0)),
            json!("per-rate rows are in perf_summary"),
        );
        self.check(
            "perf",
            "every in-job Rust reply received and zero kernel drops",
            Some(rows.iter().all(|r| {
                r["rust_rx_incomplete_runs"] == 0
                    && r["rust_kernel_drops_per_run"]
                        .as_array()
                        .is_some_and(|a| a.iter().all(|d| d.as_u64() == Some(0)))
            })),
            json!("per-rate rows are in perf_summary"),
        );
        for row in &rows {
            self.check(
                "perf",
                &format!("{} pps Rust steady rate within 20% of C", row["rate"]),
                row["within_20pct"].as_bool(),
                json!({"rate":row["rate"],"rust_over_c":row["rust_over_c"],"within_20pct":row["within_20pct"]}),
            );
        }
        self.extra["perf_summary"] = json!(rows);
    }
}
/// The perf cells read CPU and RSS from GNU `/usr/bin/time -v`.
const GNU_TIME: &str = "/usr/bin/time";
fn gnu_time_metric(report: &str, name: &str) -> Option<f64> {
    report
        .lines()
        .find_map(|l| l.trim().strip_prefix(name)?.trim().parse::<f64>().ok())
}
/// A `time -v` report from GNU time: it prints the peak RSS line; BSD and busybox time do not.
fn gnu_time_report_ok(report: &str) -> bool {
    gnu_time_metric(report, "Maximum resident set size (kbytes):").is_some()
        && gnu_time_metric(report, "User time (seconds):").is_some()
}
/// Refuse a perf run on a host without GNU time before any scanner starts.
fn preflight_gnu_time(work: &Path) -> Result<(), String> {
    let report = work.join("gnu-time-preflight.txt");
    let ok = Command::new(GNU_TIME)
        .args(["-v", "-o"])
        .arg(&report)
        .arg("true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("{GNU_TIME}: {e}"))?
        .success();
    let text = fs::read_to_string(&report).unwrap_or_default();
    let _ = fs::remove_file(&report);
    if ok && gnu_time_report_ok(&text) {
        Ok(())
    } else {
        Err(format!(
            "the perf suite needs GNU time at {GNU_TIME} (apt install time): CPU and RSS come from `time -v`"
        ))
    }
}
fn wait_child(p: &mut OwnedChild, timeout: u64) -> Result<i32, String> {
    let t = Instant::now();
    loop {
        if stop_requested() {
            return Err("suite interrupted".into());
        }
        let child = p.0.as_mut().ok_or("child missing")?;
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            let code = status.code().unwrap_or(-1);
            p.0 = None;
            return Ok(code);
        }
        if t.elapsed() > Duration::from_secs(timeout) {
            child.kill().map_err(|e| e.to_string())?;
            child.wait().map_err(|e| e.to_string())?;
            p.0 = None;
            return Ok(124);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn last_json(so: &str) -> Value {
    so.lines()
        .rev()
        .find(|l| l.starts_with('{'))
        .and_then(|l| serde_json::from_str(l).ok())
        .unwrap_or_else(|| json!({"status":"error","error":"unparsable stdout"}))
}
fn set_arg(a: &mut [String], key: &str, val: &str) -> Result<(), String> {
    let i = a
        .iter()
        .position(|s| s == key)
        .ok_or_else(|| format!("missing argument {key}"))?;
    if i + 1 >= a.len() {
        return Err("missing argument value".into());
    }
    a[i + 1] = val.into();
    Ok(())
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
struct Tcp {
    src_mac: String,
    dst_mac: String,
    src_ip: String,
    dst_ip: String,
    sp: u16,
    dp: u16,
    flags: u8,
}
fn tcp(f: &[u8]) -> Option<Tcp> {
    if f.len() < 54 || f[12..14] != [8, 0] || f[14] >> 4 != 4 || f[23] != 6 {
        return None;
    }
    let ihl = (f[14] & 15) as usize * 4;
    if ihl < 20 {
        return None;
    }
    let t = 14 + ihl;
    if f.len() < t + 14 {
        return None;
    }
    let mac = |o| {
        f[o..o + 6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let ip = |o| {
        f[o..o + 4]
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".")
    };
    Some(Tcp {
        src_mac: mac(6),
        dst_mac: mac(0),
        src_ip: ip(26),
        dst_ip: ip(30),
        sp: u16::from_be_bytes([f[t], f[t + 1]]),
        dp: u16::from_be_bytes([f[t + 2], f[t + 3]]),
        flags: f[t + 13] & 0x3f,
    })
}
fn perf_case(rate: u64) -> Result<(&'static str, &'static str, &'static str), String> {
    match rate {
        100 => Ok(("10.200.0.0/24", "79-80", "70-80")),
        1000 => Ok(("10.200.0.0/22", "78-80", "50-80")),
        10000 => Ok(("10.200.0.0/22", "51-80", "1-100")),
        100000 => Ok(("10.200.0.0/22", "1-300", "1-1000")),
        _ => Err(format!("unsupported performance rate {rate}")),
    }
}
fn port_bounds(p: &str) -> Result<(u64, u64), String> {
    let (lo, hi) = p.split_once('-').ok_or("expected port range")?;
    let lo = lo.parse::<u64>().map_err(|e| e.to_string())?;
    let hi = hi.parse::<u64>().map_err(|e| e.to_string())?;
    if lo > hi || hi > 65535 {
        return Err("invalid port range".into());
    }
    Ok((lo, hi))
}
fn probes(targets: &str, ports: &str) -> Result<u64, String> {
    let bits = targets
        .split_once('/')
        .ok_or("expected CIDR")?
        .1
        .parse::<u32>()
        .map_err(|e| e.to_string())?;
    if bits > 32 {
        return Err("invalid CIDR".into());
    }
    let (lo, hi) = port_bounds(ports)?;
    Ok((1u64 << (32 - bits)) * (hi - lo + 1))
}
fn expected_replies(ports: &str) -> Result<(u64, u64), String> {
    let (lo, hi) = port_bounds(ports)?;
    let open = u64::from(lo <= 80 && 80 <= hi);
    Ok((4 * open, 4 * (hi - lo + 1 - open)))
}
fn median(mut v: Vec<f64>) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let m = v.len() / 2;
    Some(if v.len().is_multiple_of(2) {
        (v[m - 1] + v[m]) / 2.0
    } else {
        v[m]
    })
}
/// Options of `wire-suite`.
pub(crate) const WIRE_SUITE_OPTIONS: &[&str] = &[
    "self-test",
    "suite",
    "reps",
    "rates",
    "out",
    "work",
    "ns-a",
    "ns-b",
    "iface-a",
    "iface-b",
    "mac-a",
    "mac-b",
    "ip-a",
    "rust-bin",
    "oracle",
    "fixtures",
    "conf-masked",
    "empty-dir",
];
pub fn run(args: &[String]) -> Result<i32, String> {
    let o = crate::windows_suite::options_for("wire-suite", args, WIRE_SUITE_OPTIONS)?;
    if o.contains_key("self-test") {
        return Err(
            "--self-test was removed: the suite helpers are unit tests; run cargo test -p rmasscan-lab"
                .into(),
        );
    }
    if o.contains_key("help") {
        println!(
            "wire-suite --suite rust|perf --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC --ip-a IP --rust-bin PATH --oracle PATH --conf-masked 0|1 [--fixtures DIR] [--empty-dir DIR] [--rates 100,1000,10000,100000] [--reps 5]"
        );
        return Ok(0);
    }
    let suite = required(&o, "suite")?;
    if !matches!(suite.as_str(), "rust" | "perf") {
        return Err("unknown wire suite".into());
    }
    let reps = opt(&o, "reps", "5")
        .parse::<u64>()
        .map_err(|_| "invalid reps")?;
    if reps == 0 {
        return Err("reps must be positive".into());
    }
    let rates = opt(&o, "rates", "100,1000,10000,100000")
        .split(',')
        .map(|s| s.parse::<u64>().map_err(|_| "bad rate".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    for &r in &rates {
        perf_case(r)?;
    }
    let c = Config {
        out: PathBuf::from(required(&o, "out")?),
        work: PathBuf::from(required(&o, "work")?),
        nsa: required(&o, "ns-a")?,
        nsb: required(&o, "ns-b")?,
        ifa: required(&o, "iface-a")?,
        ifb: required(&o, "iface-b")?,
        maca: required(&o, "mac-a")?,
        macb: required(&o, "mac-b")?,
        ipa: required(&o, "ip-a")?,
        rust: required(&o, "rust-bin")?,
        oracle: required(&o, "oracle")?,
        fixtures: fixtures_arg(&opt(&o, "fixtures", "")),
        masked: required(&o, "conf-masked")? == "1",
        empty: opt(&o, "empty-dir", ""),
        lab: std::env::current_exe()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .into_owned(),
    };
    if c.out.join("results.json").exists() {
        return Err("refusing to overwrite prior suite results".into());
    }
    for id in [&c.nsa, &c.nsb, &c.ifa, &c.ifb] {
        if !crate::windows_suite::safe_id(id) {
            return Err("unsafe lab namespace or interface".into());
        }
    }
    if c.nsa == c.nsb {
        return Err("scanner and peer namespaces must differ".into());
    }
    if !crate::windows_suite::valid_mac(&c.maca) || !crate::windows_suite::valid_mac(&c.macb) {
        return Err("invalid lab MAC".into());
    }
    if suite == "rust" && !c.fixture("manifest.json").is_some_and(|p| p.exists()) {
        return Err("Rust suite requires oracle fixtures manifest".into());
    }
    fs::create_dir_all(&c.out).map_err(|e| e.to_string())?;
    fs::create_dir_all(&c.work).map_err(|e| e.to_string())?;
    if suite == "perf" {
        preflight_gnu_time(&c.work)?;
    }
    let isolation = read_json(c.out.join("isolation.json"))?;
    if !isolation_permits(&isolation) {
        return Err(format!(
            "lab isolation attestation does not permit raw suite: {isolation}"
        ));
    }
    let mut d = Driver {
        c,
        checks: vec![],
        extra: json!({"suite":suite}),
        responder: OwnedChild(None),
    };
    rmasscan_net::lab_io::install_signal_handlers().map_err(|e| e.to_string())?;
    let t = Instant::now();
    let result = (|| {
        d.oracle()?;
        if suite == "rust" {
            d.parity()?;
            d.pause_resume()?;
            d.stops()?;
            d.rx_overflow()?;
            d.veth_removal()?;
        } else {
            d.perf(&rates, reps)?;
        }
        Ok::<(), String>(())
    })();
    d.extra["elapsed_s"] = json!(t.elapsed().as_secs_f64());
    if let Err(e) = &result {
        d.extra["driver_error"] = json!(e);
    }
    d.save(result.is_err())?;
    result?;
    Ok(i32::from(d.checks.iter().any(|c| c["result"] == "FAIL")))
}
fn isolation_permits(v: &Value) -> bool {
    ["uplink", "bridge", "nat", "default_route"]
        .iter()
        .all(|k| v[*k] == false)
        && v["ip_forward"].as_u64() == Some(0)
        && v["ipv6"] == "disabled"
        && v["veth_created_inside_scanner_ns_peer_moved_to_peer_ns"] == true
        && v["host_link_list_unchanged"] == true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn driver() -> Driver {
        Driver {
            c: Config {
                out: PathBuf::new(),
                work: PathBuf::new(),
                nsa: "wl-a".into(),
                nsb: "wl-b".into(),
                ifa: "veth-a".into(),
                ifb: "veth-b".into(),
                maca: "02:aa:00:00:00:01".into(),
                macb: "02:aa:00:00:00:02".into(),
                ipa: "10.200.0.100".into(),
                rust: "/tmp/wire_scan".into(),
                oracle: "/tmp/oracle".into(),
                fixtures: None,
                masked: false,
                empty: String::new(),
                lab: "/tmp/rmasscan-lab".into(),
            },
            checks: vec![],
            extra: json!({}),
            responder: OwnedChild(None),
        }
    }
    fn golden() -> PathBuf {
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../tests/golden/wire")
    }
    #[test]
    fn archived_isolation_all_fields_are_required() {
        let raw = read_json(golden().join("manifest.json")).unwrap();
        let good = &raw["isolation"];
        assert!(isolation_permits(good));
        for k in [
            "uplink",
            "bridge",
            "nat",
            "default_route",
            "ip_forward",
            "ipv6",
            "veth_created_inside_scanner_ns_peer_moved_to_peer_ns",
            "host_link_list_unchanged",
        ] {
            let mut bad = good.clone();
            bad[k] = Value::Null;
            assert!(!isolation_permits(&bad), "{k}");
        }
    }
    #[test]
    fn six_archived_cases_keep_exact_wire_counts_and_binding() {
        let d = driver();
        for c in cases() {
            let records = d
                .frames(&golden().join(format!("{}.run1.pcap", c.name)))
                .unwrap();
            assert_eq!(d.syns(&records, None).len() as u64, c.syn, "{}", c.name);
            let replies = d.replies(&records, None);
            assert_eq!(
                replies.iter().filter(|x| x.ends_with(":open")).count() as u64,
                c.open
            );
            assert_eq!(
                replies.iter().filter(|x| x.ends_with(":closed")).count() as u64,
                c.closed
            );
        }
    }
    #[test]
    fn foreign_mac_ip_port_and_synack_never_count_as_scanner_syn() {
        let d = driver();
        let records = d
            .frames(&golden().join("c01_one_addr_port_synack.run1.pcap"))
            .unwrap();
        let original = d.syns(&records, None)[0].1.to_vec();
        for offset in [0, 6, 26, 34] {
            let mut f = original.clone();
            f[offset] ^= 1;
            assert!(d.syns(&[(0.0, f)], Some((40000, 40000))).is_empty());
        }
        let mut f = original;
        f[47] = 0x12;
        assert!(d.syns(&[(0.0, f)], None).is_empty());
    }
    #[test]
    fn reply_filter_rejects_other_mac_ip_and_source_port() {
        let d = driver();
        let records = d
            .frames(&golden().join("c01_one_addr_port_synack.run1.pcap"))
            .unwrap();
        let original = records
            .iter()
            .find(|(_, f)| tcp(f).is_some_and(|i| i.flags == 0x12))
            .unwrap()
            .1
            .clone();
        for offset in [0, 6, 30, 36] {
            let mut f = original.clone();
            f[offset] ^= 1;
            assert!(d.replies(&[(0.0, f)], Some((40000, 40000))).is_empty());
        }
        assert_eq!(d.replies(&[(0.0, original)], Some((40000, 40000))).len(), 1);
    }
    #[test]
    fn full_performance_matrix_preserves_counts_and_stop_ranges() {
        for (rate, want) in [(100, 512), (1000, 3072), (10000, 30720), (100000, 307200)] {
            let (targets, ports, stop) = perf_case(rate).unwrap();
            assert_eq!(probes(targets, ports).unwrap(), want);
            assert!(probes(targets, stop).unwrap() > rate * 2);
            assert_eq!(expected_replies(ports).unwrap().0, 4);
        }
        assert!(perf_case(999).is_err());
        assert_eq!(median(vec![1.0, 2.0, 4.0, 8.0]), Some(3.0));
        assert_eq!(median(vec![]), None);
    }
    #[test]
    fn commands_use_namespace_and_current_rust_tools_without_interpreters() {
        let d = driver();
        let a = d.ns(
            true,
            &d.lab("capture", &["responder", "--ports", "80,8080"]),
        );
        assert_eq!(&a[..4], strings(&["ip", "netns", "exec", "wl-b"]));
        assert!(a.contains(&"/tmp/rmasscan-lab".into()));
        assert!(!a.iter().any(|x| x.contains(concat!("py", "thon"))));
        let a = d.rust_args("10.200.0.2", "80", 100, 3, "50123", Some("10.200.0.3"));
        assert_eq!(
            crate::windows_suite::arg_value(&a, "--source-port"),
            Some("50123")
        );
        assert_eq!(
            crate::windows_suite::arg_value(&a, "--exclude"),
            Some("10.200.0.3")
        );
    }
    #[test]
    fn capture_tail_loss_never_passes() {
        assert!(capture_complete(
            Some(100),
            Some(100),
            Some(0),
            Some(0),
            100,
            98,
            101
        ));
        assert!(!capture_complete(
            Some(99),
            Some(100),
            Some(0),
            Some(0),
            99,
            98,
            101
        ));
        assert!(!capture_complete(None, None, None, None, 0, 0, 0));
        assert!(!capture_complete(
            Some(100),
            Some(100),
            Some(1),
            Some(0),
            100,
            98,
            101
        ));
    }
    #[test]
    fn unknown_and_boolean_rx_drop_counts_never_pass() {
        for d in [
            serde_json::Value::Null,
            serde_json::json!(false),
            serde_json::json!(3),
        ] {
            assert!(!rx_health_ok(
                &serde_json::json!({"reason":"Completed","rx_health":{"kernel_drops":d}})
            ));
        }
        assert!(rx_health_ok(
            &serde_json::json!({"reason":"Completed","rx_health":{"kernel_drops":0}})
        ));
    }
}

#[cfg(test)]
#[path = "wire_suite_tests.rs"]
mod suite_tests;
