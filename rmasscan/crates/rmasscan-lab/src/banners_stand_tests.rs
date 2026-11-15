//! Fixtures of the TCP banner case of the Windows and macOS stands. The reference is the banners window's own
//! generator of `t01_tcp4` (`banners_verify::tests::Sim`, the product's stack in C's place, as every TCP fixture of that
//! window); a stand run is simulated here the same way: the plan's SYNs on the stand binding, the peer kernel and the
//! scenario scripts of `TCP_SCENARIOS`, the product's stack (`rmasscan_proto::tcp_stack_factory`) and its frames
//! (`TcpFrameBuilder::from_plan`), the records it writes. Nothing here touches a network.
use super::*;
use crate::{
    autodetect_verify::tests::Sim as AdSim,
    banners_verify::{TcpStep, tests::Sim as BSim},
    link::{END_PAYLOAD, START_PAYLOAD},
    pcap,
};
use rmasscan_core::stack::{ConnAddrs, ConnKey, SegmentIn, SegmentOut, StackOutput, TableParams};
use std::{path::PathBuf, sync::OnceLock};

const T0: f64 = 1_900_000_000.0;

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "rmasscan-bstand-{name}-{}-{}",
        std::process::id(),
        crate::windows_suite::nonce()
    ));
    fs::create_dir_all(&d).unwrap();
    d
}
/// The Linux window with `t01_tcp4` alone, written once: its generator's case directory and a verdict that says PASS.
pub(crate) fn linux_window() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let root = scratch("linux");
        BSim::tcp(&bv::tcp_case(REFERENCE_CASE).unwrap()).write(&root);
        fs::write(
            root.join(REFERENCE_VERDICT),
            json!({"runs":[{"tag":"manifest","verdict":PASS},{"tag":REFERENCE_CASE,"verdict":PASS}],"overall":PASS})
                .to_string(),
        )
        .unwrap();
        root
    })
}

fn ones(data: &[u8], init: u32) -> u32 {
    let mut s = init;
    for c in data.chunks(2) {
        s += (u32::from(c[0]) << 8) | u32::from(*c.get(1).unwrap_or(&0));
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    s
}
/// An IPv4 TCP frame with right sums, a plain 20-byte header and the given TTL and IP id (a kernel's segment).
#[allow(clippy::too_many_arguments)]
fn kernel_seg(
    from: [u8; 6],
    to: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(to);
    f.extend(from);
    f.extend([8, 0]);
    let total = 40 + payload.len();
    f.extend([
        0x45,
        0,
        (total >> 8) as u8,
        total as u8,
        0x12,
        0x34,
        0x40,
        0,
        ttl,
        6,
        0,
        0,
    ]);
    f.extend(src.octets());
    f.extend(dst.octets());
    let s = !(ones(&f[14..34], 0) as u16);
    f[24..26].copy_from_slice(&s.to_be_bytes());
    let mut t = Vec::new();
    t.extend(ports.0.to_be_bytes());
    t.extend(ports.1.to_be_bytes());
    t.extend(seq.to_be_bytes());
    t.extend(ack.to_be_bytes());
    t.extend([0x50, flags, 0xfa, 0xf0, 0, 0, 0, 0]);
    t.extend(payload);
    let mut pseudo = Vec::new();
    pseudo.extend(src.octets());
    pseudo.extend(dst.octets());
    pseudo.extend([0, 6]);
    pseudo.extend((t.len() as u16).to_be_bytes());
    let s = !(ones(&t, ones(&pseudo, 0)) as u16);
    t[16..18].copy_from_slice(&s.to_be_bytes());
    f.extend(t);
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}
fn marker(from: [u8; 6], to: [u8; 6], payload: &[u8]) -> Vec<u8> {
    crate::link::marker_frame(to, from, payload)
}
/// The peer's who-has for the source, the guest kernel's 42-byte reply and rmasscan's 60-byte one in C's form.
fn arp_exchange(st: &av::Stand) -> [Vec<u8>; 3] {
    let arp = |dst: [u8; 6],
               src: [u8; 6],
               op: u8,
               sha: [u8; 6],
               spa: Ipv4Addr,
               tha: [u8; 6],
               tpa: Ipv4Addr| {
        let mut f = Vec::new();
        f.extend(dst);
        f.extend(src);
        f.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, op]);
        f.extend(sha);
        f.extend(spa.octets());
        f.extend(tha);
        f.extend(tpa.octets());
        f
    };
    let req = arp(
        [0xff; 6],
        st.peer_mac,
        1,
        st.peer_mac,
        PEER,
        [0; 6],
        st.scanner_ip,
    );
    let os = arp(
        st.peer_mac,
        st.scanner_mac,
        2,
        st.scanner_mac,
        st.scanner_ip,
        st.peer_mac,
        PEER,
    );
    let mut c = os.clone();
    c.resize(60, 0);
    [req, os, c]
}

/// The peer of one connection: its kernel and its scenario's script (`capture::run_script`).
struct PeerConn {
    port: u16,
    sport: u16,
    syn_seq: u32,
    sc: &'static TcpScenario,
    snd_nxt: u32,
    rcv_nxt: u32,
    established: bool,
    pc: usize,
    ready_at: f64,
    unread: usize,
    eof: bool,
    done: bool,
    dead: bool,
    end_at: Option<f64>,
}
/// One line of the `-oL` document.
#[derive(Clone)]
pub(crate) enum Line {
    Open {
        port: u16,
        ts: u32,
    },
    Banner {
        port: u16,
        ts: u32,
        app: u16,
        payload: Vec<u8>,
    },
}
/// A run of the case on a simulated stand.
pub(crate) struct StandSim {
    pub(crate) case: StandCase,
    pub(crate) frames: Frames,
    pub(crate) lines: Vec<Line>,
    pub(crate) exit: i32,
    /// The document's bytes, rendered from `lines` unless a test set them.
    pub(crate) doc: Option<Vec<u8>>,
    pub(crate) extra: Vec<(String, Vec<u8>)>,
}
impl StandSim {
    pub(crate) fn new(c: StandCase) -> Self {
        let (frames, lines) = simulate(&c);
        StandSim {
            case: c,
            frames,
            lines,
            exit: 0,
            doc: None,
            extra: Vec::new(),
        }
    }
    pub(crate) fn render(&self) -> Vec<u8> {
        if let Some(d) = &self.doc {
            return d.clone();
        }
        let mut b = String::from("#masscan\n");
        for l in &self.lines {
            match l {
                Line::Open { port, ts } => b.push_str(&format!("open tcp {port} {PEER} {ts}\n")),
                Line::Banner {
                    port,
                    ts,
                    app,
                    payload,
                } => b.push_str(&format!(
                    "banner tcp {port} {PEER} {ts} {} {}\n",
                    rmasscan_proto::app_name(*app),
                    rmasscan_proto::normalize_string(payload)
                )),
            }
        }
        b.push_str("# end\n");
        b.into_bytes()
    }
    pub(crate) fn stderr(&self) -> String {
        let st = av::stand(self.case.plan);
        let mac = av::dash(st.scanner_mac);
        let (iface, mac_src) = if self.case.plan == Plan::Windows {
            ("Ethernet 2 (detected: route to 198.18.0.2)", "detected")
        } else {
            ("feth4201 (given)", "given")
        };
        format!(
            "[+] interface = {iface}\n[+] source-mac = {mac} ({mac_src})\n[+] source-ip = 198.18.0.1 (given)\n[+] router-mac = {} (given)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n[+] finished: Completed, sent 2, replies 2, open 2\n",
            av::dash(st.peer_mac)
        )
    }
    /// The run directory's files before hashing.
    pub(crate) fn files(&self) -> Vec<(String, Vec<u8>)> {
        let c = &self.case;
        let win = c.plan == Plan::Windows;
        let name = |n: &str| {
            if win {
                format!("guest-{n}")
            } else {
                n.to_owned()
            }
        };
        let pretty = |v: Value| serde_json::to_vec_pretty(&v).unwrap();
        let banners: Vec<Value> = c
            .ports
            .iter()
            .map(|(p, sp)| json!({"port": p, "scenario_port": sp, "peer": 2}))
            .collect();
        let mut f: Vec<(String, Vec<u8>)> = vec![
            (
                av::ARGV_JSON.into(),
                serde_json::to_vec(&ArgvRecord { argv: c.argv() }).unwrap(),
            ),
            (EXPECT_JSON.into(), serde_json::to_vec(&c.expect()).unwrap()),
            (
                LISTENERS_JSON.into(),
                pretty(
                    json!({"open":[],"silent":[],"silent_proven":null,"ready":true,"bind":"198.18.0.2","pid":4242,"banners":banners}),
                ),
            ),
            (OUTPUT.into(), self.render()),
            (av::PEER_PCAP.into(), pcap::encode(&self.frames)),
            (
                av::CAPTURE_JSON.into(),
                if win {
                    AdSim::witness(&self.frames)
                } else {
                    AdSim::published_witness(&self.frames)
                },
            ),
            (name("stdout.txt"), Vec::new()),
            (name("stderr.txt"), self.stderr().into_bytes()),
            (name("exit.txt"), format!("{}\n", self.exit).into_bytes()),
        ];
        if win {
            f.push(("eno1.pcap".into(), pcap::encode(&Vec::new())));
            f.push(("eno1.err".into(), b"tcpdump: listening on eno1, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n".to_vec()));
            f.push((
                "guest-firewall.json".into(),
                pretty(json!({"profiles":[{"Name":"Public","Enabled":true,"DefaultInboundAction":"Block"}],"lab_nic":{"name":"Ethernet 2","category":"Public"}})),
            ));
            let st = json!({"host_ok":true,"isolation_violations":[],"ok":true,"raw_run_allowed":true,"state":"up"});
            for n in ["status-pre.json", "status-post.json"] {
                f.push((n.into(), pretty(st.clone())));
            }
        } else {
            f.push(("uplink.pcap".into(), pcap::encode(&Vec::new())));
            f.push(("uplink.err".into(), b"tcpdump: listening on en0, link-type EN10MB (Ethernet), snapshot length 524288 bytes\n0 packets captured\n731 packets received by filter\n0 packets dropped by kernel\n".to_vec()));
            f.push((
                "alf.txt".into(),
                b"rc 0\nstdout:\nFirewall is disabled. (State = 0)\nstderr:\n".to_vec(),
            ));
            let st = json!({"bpf_access":"granted","raw_run_allowed":true,"uplink":"en0","run_id":"m1","checks":[]});
            for n in ["status-pre.json", "status-post.json"] {
                f.push((n.into(), pretty(st.clone())));
            }
        }
        f.extend(self.extra.iter().cloned());
        f
    }
    /// `root/runs/<tag>` with its hashes.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let d = root.join("runs").join(self.case.tag);
        fs::create_dir_all(&d).unwrap();
        let mut files = self.files();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hashes = String::new();
        for (n, b) in &files {
            let p = d.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b).unwrap();
            hashes.push_str(&format!("{}  {n}\n", sha(b)));
        }
        fs::write(d.join("hashes-before-copy.txt"), hashes).unwrap();
        d
    }
}

/// A run of the case on a simulated stand: the plan's SYNs 10 ms apart, the peer kernel (Windows: its who-has for the
/// source, answered by the guest's kernel and rmasscan), the scenario scripts, the product's stack with `--banners`
/// and its frames, the records it writes, the markers. Time advances in 1 ms ticks, the stack ticks every 10 ms.
fn simulate(c: &StandCase) -> (Frames, Vec<Line>) {
    let st = av::stand(c.plan);
    let plan = c.ready_plan().unwrap();
    let builder = rmasscan_core::tcp_frame::TcpFrameBuilder::from_plan(&plan);
    let probes = crate::pair_verify::plan_probes(&plan).unwrap().0;
    let mut stack = rmasscan_proto::tcp_stack_factory(
        rmasscan_proto::TcpBannerSettings::default(),
        CONNECTION_TIMEOUT,
    )
    .new_table(TableParams {
        seed: 1,
        capacity: 4096,
        banner_byte_budget: 1 << 29,
    });
    let src = st.scanner_ip;
    let key_of = |port: u16, sport: u16| ConnKey {
        addrs: ConnAddrs::V4 {
            local: u32::from(src),
            remote: u32::from(PEER),
        },
        local_port: sport,
        remote_port: port,
    };
    let peer = |pc: &PeerConn, seq: u32, ack: u32, flags: u8, payload: &[u8]| {
        kernel_seg(
            st.peer_mac,
            st.scanner_mac,
            PEER,
            src,
            (pc.port, pc.sport),
            seq,
            ack,
            flags,
            payload,
            64,
        )
    };
    let mut fr: Frames = vec![(T0, marker(st.peer_mac, st.scanner_mac, START_PAYLOAD))];
    let mut lines = Vec::new();
    let mut conns: Vec<PeerConn> = probes
        .iter()
        .map(|p| {
            let h = tcp_head(p).unwrap();
            PeerConn {
                port: h.dp,
                sport: h.sp,
                syn_seq: h.seq,
                sc: c.scenario(h.dp).unwrap(),
                snd_nxt: 0,
                rcv_nxt: h.seq.wrapping_add(1),
                established: false,
                pc: 0,
                ready_at: 0.0,
                unread: 0,
                eof: false,
                done: false,
                dead: false,
                end_at: None,
            }
        })
        .collect();
    let mut pending: Vec<(f64, usize, Vec<u8>)> = Vec::new();
    let first = T0 + 0.6;
    let scan_end = first + (probes.len() - 1) as f64 * 0.01 + f64::from(WAIT);
    let mut t = first;
    let mut tick = 0u64;
    while t <= scan_end + 1e-9 {
        let now = ((t - T0) * 1e6) as u64;
        let mut out = StackOutput::default();
        for (i, p) in probes.iter().enumerate() {
            let at = first + i as f64 * 0.01;
            if (at - t).abs() > 0.0004 {
                continue;
            }
            fr.push((at, p.clone()));
            if i == 0 && c.plan == Plan::Windows {
                let [q, os, ours] = arp_exchange(&st);
                fr.push((at + 0.0002, q));
                fr.push((at + 0.0003, os));
                fr.push((at + 0.0004, ours));
            }
            let pc = &mut conns[i];
            let isn = 0x3000_0000u32.wrapping_add((i as u32) << 20);
            pc.snd_nxt = isn.wrapping_add(1);
            let f = peer(pc, isn, pc.syn_seq.wrapping_add(1), 0x12, &[]);
            pending.push((at + 0.001, i, f));
        }
        for (i, pc) in conns.iter_mut().enumerate() {
            if !pc.established || pc.done || pc.dead || t < pc.ready_at {
                continue;
            }
            let mut send = |pc: &mut PeerConn, flags: u8, payload: &[u8]| {
                let f = peer(pc, pc.snd_nxt, pc.rcv_nxt, flags, payload);
                pending.push((t + 0.0007, i, f));
                pc.snd_nxt = pc
                    .snd_nxt
                    .wrapping_add(payload.len() as u32 + u32::from(flags & 0x01));
            };
            loop {
                match pc.sc.steps.get(pc.pc) {
                    Some(TcpStep::Write(b)) => {
                        send(pc, 0x18, b);
                        pc.pc += 1;
                        pc.ready_at = t + 0.2;
                        break;
                    }
                    Some(TcpStep::Recv | TcpStep::Peek) if pc.unread > 0 => {
                        if pc.sc.steps[pc.pc] == TcpStep::Recv {
                            pc.unread = 0;
                        }
                        pc.pc += 1;
                    }
                    Some(TcpStep::Recv | TcpStep::Peek) if pc.eof => {
                        send(pc, 0x11, &[]);
                        pc.done = true;
                        break;
                    }
                    Some(_) => break,
                    None => {
                        let end = *pc.end_at.get_or_insert(t + 1.0);
                        if pc.eof || t >= end {
                            send(pc, 0x11, &[]);
                            pc.done = true;
                        }
                        break;
                    }
                }
            }
        }
        pending.sort_by(|a, b| a.0.total_cmp(&b.0));
        let n = pending.iter().take_while(|x| x.0 <= t + 0.0009).count();
        let due: Vec<(f64, usize, Vec<u8>)> = pending.drain(..n).collect();
        let mut sent: Vec<(f64, SegmentOut)> = Vec::new();
        for (at, i, f) in due {
            fr.push((at, f.clone()));
            let h = tcp_head(&f).unwrap();
            let pc = &conns[i];
            if h.flags == 0x12 {
                lines.push(Line::Open {
                    port: pc.port,
                    ts: at as u32,
                });
            }
            let seg = SegmentIn {
                key: key_of(pc.port, pc.sport),
                seq: h.seq,
                ack: h.ack,
                flags: h.flags,
                ttl: 64,
                payload: &h.payload,
            };
            let mut o = StackOutput::default();
            stack.on_segment(((at - T0) * 1e6) as u64, &seg, &mut o);
            sent.extend(o.segments.into_iter().map(|g| (at + 0.0002, g)));
            out.banners.extend(o.banners);
        }
        if tick.is_multiple_of(10) {
            let mut o = StackOutput::default();
            stack.on_tick(now, &mut o);
            sent.extend(o.segments.into_iter().map(|g| (t + 0.0002, g)));
            out.banners.extend(o.banners);
        }
        for (at, g) in sent {
            fr.push((at, builder.build(&g)));
            let i = conns
                .iter()
                .position(|pc| key_of(pc.port, pc.sport) == g.key)
                .unwrap();
            let pc = &mut conns[i];
            if g.flags & 0x04 != 0 {
                pc.dead = true;
                continue;
            }
            if !pc.established && g.flags & 0x10 != 0 && g.ack == pc.snd_nxt {
                pc.established = true;
                pc.ready_at = at;
            }
            let mut ack = false;
            if !g.payload.is_empty() && g.seq == pc.rcv_nxt {
                pc.rcv_nxt = pc.rcv_nxt.wrapping_add(g.payload.len() as u32);
                pc.unread += g.payload.len();
                ack = true;
            }
            if g.flags & 0x01 != 0 && g.seq.wrapping_add(g.payload.len() as u32) == pc.rcv_nxt {
                pc.rcv_nxt = pc.rcv_nxt.wrapping_add(1);
                pc.eof = true;
                ack = true;
            }
            if ack {
                let f = peer(pc, pc.snd_nxt, pc.rcv_nxt, 0x10, &[]);
                pending.push((at + 0.0005, i, f));
            }
        }
        for b in out.banners.into_iter().flatten() {
            lines.push(Line::Banner {
                port: b.port,
                ts: t as u32,
                app: b.app,
                payload: b.payload,
            });
        }
        t += 0.001;
        tick += 1;
    }
    let mut o = StackOutput::default();
    while stack.finish(usize::MAX, &mut o) {}
    for b in o.banners.into_iter().flatten() {
        lines.push(Line::Banner {
            port: b.port,
            ts: scan_end as u32,
            app: b.app,
            payload: b.payload,
        });
    }
    fr.sort_by(|a, b| a.0.total_cmp(&b.0));
    let end = fr.last().map_or(T0, |x| x.0) + 1.0;
    for k in 0..3 {
        fr.push((
            end + f64::from(k) * 0.05,
            marker(st.peer_mac, st.scanner_mac, END_PAYLOAD),
        ));
    }
    (fr, lines)
}

/// An evidence directory of the case: the manifest, the reference copied from the Linux window, the run.
fn write_dir(sim: &StandSim) -> PathBuf {
    let root = scratch(sim.case.tag);
    fs::write(
        root.join("manifest.json"),
        json!({MANIFEST_KEY: sim.case.plan, "schema": 1}).to_string(),
    )
    .unwrap();
    copy_reference(linux_window(), &root).unwrap();
    sim.write(&root);
    root
}
fn judge(sim: &StandSim) -> Value {
    let root = write_dir(sim);
    let v = verify_dir(&root);
    let _ = fs::remove_dir_all(&root);
    v
}
fn run_of<'a>(v: &'a Value, tag: &str) -> &'a Value {
    array(&v["runs"]).iter().find(|r| r["tag"] == tag).unwrap()
}
fn bad(v: &Value) -> Vec<String> {
    array(&v["runs"])
        .iter()
        .flat_map(|r| {
            array(&r["checks"])
                .iter()
                .filter(|c| c["result"] != PASS)
                .map(move |c| {
                    format!(
                        "{} {}: {} ({})",
                        r["tag"], c["result"], c["name"], c["detail"]
                    )
                })
        })
        .collect()
}
/// The result of the first check of `run` whose name contains `needle`.
fn check<'a>(v: &'a Value, run: &str, needle: &str) -> &'a str {
    array(&run_of(v, run)["checks"])
        .iter()
        .find(|c| s(&c["name"]).contains(needle))
        .map(|c| s(&c["result"]))
        .unwrap_or_else(|| panic!("no check {needle:?} in {run}"))
}
/// Rebuild every frame of rmasscan's stack on the connection to `port` whose payload is not empty with `payload`,
/// in the stack's own form.
fn with_scanner_payload(sim: &mut StandSim, port: u16, payload: &[u8]) {
    let plan = sim.case.ready_plan().unwrap();
    let builder = rmasscan_core::tcp_frame::TcpFrameBuilder::from_plan(&plan);
    let st = av::stand(sim.case.plan);
    for (_, f) in sim.frames.iter_mut() {
        let Some(h) = tcp_head(f) else { continue };
        if f[6..12] != st.scanner_mac || h.dp != port || h.payload.is_empty() || h.flags & 0x02 != 0
        {
            continue;
        }
        let IpAddr::V4(local) = h.src else { continue };
        *f = builder.build(&SegmentOut {
            key: ConnKey {
                addrs: ConnAddrs::V4 {
                    local: u32::from(local),
                    remote: u32::from(PEER),
                },
                local_port: h.sp,
                remote_port: h.dp,
            },
            seq: h.seq,
            ack: h.ack,
            flags: h.flags,
            payload: payload.to_vec(),
            window: None,
        });
    }
}

#[test]
fn the_case_table_scans_the_http_and_ssh_scenarios_with_the_stands_binding() {
    assert_eq!(
        WINDOWS.argv().join(" "),
        "198.18.0.2 -p22,80 --banners --connection-timeout 8 --adapter-ip 198.18.0.1 --router-mac 02-57-4c-3d-2e-9b -oL output.txt --seed 1 --rate 100 --wait 14 --source-port 40000 --retries 0"
    );
    assert_eq!(
        MACOS.argv().join(" "),
        "198.18.0.2 -p2222,8080 --banners --connection-timeout 8 --adapter feth4201 --adapter-ip 198.18.0.1 --adapter-mac 02-ac-00-00-00-01 --router-ip 198.18.0.2 --router-mac 02-ac-00-00-00-02 -oL output.txt --seed 1 --rate 100 --wait 14 --source-port 40000 --retries 0"
    );
    assert_eq!(WINDOWS.banners_arg(), "22,80");
    assert_eq!(MACOS.banners_arg(), "2222=22,8080=80");
    // The listener takes what the table says.
    for c in [WINDOWS, MACOS] {
        let b = crate::peer::banner_ports(&c.banners_arg()).unwrap();
        for ((p, sc), (q, sp)) in b.iter().zip(&c.ports) {
            assert_eq!((*p, sc.port, sc.peer), (*q, *sp, 2));
            assert_eq!(c.scenario(*p), Some(*sc));
        }
        assert!(
            hello_table_problems(&c).is_empty(),
            "{:?}",
            hello_table_problems(&c)
        );
        // The scenarios are the window's: the HTTP response with a title, the SSH ident (TCP_SCENARIOS, peer .2).
        let apps: Vec<&[&str]> = c
            .ports
            .iter()
            .map(|(p, _)| c.scenario(*p).unwrap().apps)
            .collect();
        assert_eq!(apps, [&["ssh"][..], &["http.server", "title", "http"][..]]);
        // The flags are the binding the autodetect window proved on the stand (w04, m03), plus the given source.
        let st = av::stand(c.plan);
        assert!(c.argv().contains(&av::dash(st.peer_mac)));
        assert_eq!(c.expect().source, st.scanner_ip.to_string());
    }
    // The mapping is only sound because C sends the same on both ports: an HTTP scenario on a port without C's HTTP
    // hello, or SSH on a hello port, would be refused.
    for ports in [[(2222, 22), (8081, 80)], [(23, 22), (8080, 80)]] {
        let c = StandCase { ports, ..MACOS };
        assert_eq!(hello_table_problems(&c).len(), 1, "{ports:?}");
    }
    assert_eq!(c_hello(80), c_hello(8080));
    assert!(c_hello(80).is_some_and(|h| h.starts_with("474554202f20")));
    assert_eq!((c_hello(22), c_hello(2222)), (None, None));
}

#[test]
fn both_stands_pass_with_cs_records_of_the_same_scenarios() {
    for c in [WINDOWS, MACOS] {
        let v = judge(&StandSim::new(c));
        assert_eq!(v["overall"], PASS, "{}: {:#?}", c.tag, bad(&v));
        let r = run_of(&v, c.tag);
        // The verdict is by records: C's, with the macOS ports mapped.
        assert_eq!(
            r["notes"]["banners_by_app"],
            json!({"http": 1, "http.server": 1, "ssh": 1, "title": 1})
        );
        let refs = array(&run_of(&v, REFERENCE_DIR)["notes"]["c_records"]);
        assert_eq!(refs.len(), 6, "{refs:?}");
        if c.plan == Plan::Windows {
            assert!(s(&r["notes"]["windows_no_rst"]).starts_with("holds"));
            assert_eq!(
                r["notes"]["guest_firewall"]["lab_nic"]["category"],
                "Public"
            );
            // The guest kernel's ARP reply and rmasscan's: one each to the peer's who-has.
            assert_eq!(r["notes"]["wire"]["host_arp_replies"], 1);
            assert_eq!(r["notes"]["wire"]["rmasscan_arp_answers"], 1);
        } else {
            assert_eq!(r["notes"]["port_map"], json!(["2222 -> 22", "8080 -> 80"]));
        }
    }
}

#[test]
fn a_lost_banner_fails() {
    for c in [WINDOWS, MACOS] {
        let mut sim = StandSim::new(c);
        let before = sim.lines.len();
        sim.lines.retain(
            |l| !matches!(l, Line::Banner { app, .. } if rmasscan_proto::app_name(*app) == "title"),
        );
        assert_eq!(sim.lines.len() + 1, before);
        let v = judge(&sim);
        assert_eq!(v["overall"], FAIL, "{:#?}", bad(&v));
        assert_eq!(check(&v, c.tag, "equal C's records"), FAIL);
        assert_eq!(check(&v, c.tag, "applications its scenario declares"), FAIL);
        assert_eq!(run_of(&v, c.tag)["behaviour_fail"], true);
    }
}

#[test]
fn a_foreign_hello_fails_although_the_records_are_cs() {
    for c in [WINDOWS, MACOS] {
        let http = c.ports[1].0;
        let ssh = c.ports[0].0;
        for (port, payload) in [
            // another request on the HTTP port: the peer's script answers it all the same
            (http, &b"GET / HTTP/1.1\r\nHost: 198.18.0.2\r\n\r\n"[..]),
            // another ident back to the SSH server
            (ssh, &b"SSH-2.0-rmasscan\r\n"[..]),
        ] {
            let mut sim = StandSim::new(c);
            with_scanner_payload(&mut sim, port, payload);
            let v = judge(&sim);
            assert_eq!(v["overall"], FAIL, "{port}: {:#?}", bad(&v));
            assert_eq!(
                check(&v, c.tag, "payload segments on each connection are C's"),
                FAIL
            );
            // The records cannot tell: the server answered the foreign hello as it answers C's.
            assert_eq!(check(&v, c.tag, "equal C's records"), PASS);
        }
    }
}

#[test]
fn an_extra_or_misplaced_record_of_rmasscan_fails() {
    let mut sim = StandSim::new(WINDOWS);
    sim.lines.push(Line::Banner {
        port: 80,
        ts: 1,
        app: 1,
        payload: b"x".to_vec(),
    });
    let v = judge(&sim);
    assert_eq!(v["overall"], FAIL);
    assert_eq!(check(&v, WINDOWS.tag, "equal C's records"), FAIL);
    // M1: a banner before its connection's open record.
    let mut sim = StandSim::new(WINDOWS);
    let i = sim
        .lines
        .iter()
        .position(|l| matches!(l, Line::Banner { port: 22, .. }))
        .unwrap();
    let b = sim.lines.remove(i);
    sim.lines.insert(0, b);
    let v = judge(&sim);
    assert_eq!(check(&v, WINDOWS.tag, "(M1)"), FAIL);
    // A document without its footer.
    let mut sim = StandSim::new(MACOS);
    let mut d = sim.render();
    d.truncate(d.len() - "# end\n".len());
    sim.doc = Some(d);
    assert_eq!(check(&judge(&sim), MACOS.tag, "`# end` footer"), FAIL);
}

#[test]
fn a_frame_of_the_guests_own_stack_is_invalid_and_refutes_the_readme_claim() {
    // The guest's TCP/IP stack resets the SYN-ACK it has no socket for: TTL 128, its own IP id and window.
    let st = av::stand(Plan::Windows);
    let mut sim = StandSim::new(WINDOWS);
    let (t, synack) = sim
        .frames
        .iter()
        .find(|(_, f)| {
            f[6..12] == st.peer_mac && tcp_head(f).is_some_and(|h| h.flags == 0x12 && h.sp == 80)
        })
        .cloned()
        .unwrap();
    let h = tcp_head(&synack).unwrap();
    let rst = kernel_seg(
        st.scanner_mac,
        st.peer_mac,
        st.scanner_ip,
        PEER,
        (h.dp, h.sp),
        h.ack,
        0,
        0x04,
        &[],
        128,
    );
    sim.frames.push((t + 0.0001, rst));
    sim.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let v = judge(&sim);
    assert_eq!(v["overall"], INVALID, "{:#?}", bad(&v));
    assert_eq!(check(&v, WINDOWS.tag, "guest's own TCP/IP stack"), INVALID);
    assert!(s(&run_of(&v, WINDOWS.tag)["notes"]["windows_no_rst"]).starts_with("refuted"));
    assert_eq!(run_of(&v, WINDOWS.tag)["behaviour_fail"], false);
}

#[test]
fn a_frame_of_the_macs_kernel_for_the_source_is_invalid_never_rmasscans_fail() {
    let st = av::stand(Plan::Macos);
    let mut sim = StandSim::new(MACOS);
    let (t, synack) = sim
        .frames
        .iter()
        .find(|(_, f)| f[6..12] == st.peer_mac && tcp_head(f).is_some_and(|h| h.flags == 0x12))
        .cloned()
        .unwrap();
    let h = tcp_head(&synack).unwrap();
    let rst = kernel_seg(
        st.scanner_mac,
        st.peer_mac,
        st.scanner_ip,
        PEER,
        (h.dp, h.sp),
        h.ack,
        0,
        0x04,
        &[],
        64,
    );
    sim.frames.push((t + 0.0001, rst));
    sim.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let v = judge(&sim);
    assert_eq!(v["overall"], INVALID, "{:#?}", bad(&v));
    assert_eq!(check(&v, MACOS.tag, "Mac's kernel"), INVALID);
}

#[test]
fn a_rst_of_rmasscans_stack_fails() {
    // rmasscan's own form (the builder's frame) resetting the HTTP connection right after its SYN-ACK.
    let st = av::stand(Plan::Windows);
    let mut sim = StandSim::new(WINDOWS);
    let (t, synack) = sim
        .frames
        .iter()
        .find(|(_, f)| {
            f[6..12] == st.peer_mac && tcp_head(f).is_some_and(|h| h.flags == 0x12 && h.sp == 80)
        })
        .cloned()
        .unwrap();
    let h = tcp_head(&synack).unwrap();
    let plan = WINDOWS.ready_plan().unwrap();
    let rst = rmasscan_core::tcp_frame::TcpFrameBuilder::from_plan(&plan).build(&SegmentOut {
        key: ConnKey {
            addrs: ConnAddrs::V4 {
                local: u32::from(st.scanner_ip),
                remote: u32::from(PEER),
            },
            local_port: h.dp,
            remote_port: h.sp,
        },
        seq: h.ack,
        ack: 0,
        flags: 0x04,
        payload: Vec::new(),
        window: None,
    });
    sim.frames.push((t + 0.0001, rst));
    sim.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let v = judge(&sim);
    assert_eq!(
        check(&v, WINDOWS.tag, "no RST of rmasscan"),
        FAIL,
        "{:#?}",
        bad(&v)
    );
    assert_eq!(v["overall"], FAIL);
}

#[test]
fn a_peer_that_does_not_stream_its_scenario_is_the_stands_not_rmasscans() {
    // The HTTP response cut short on the wire: the records then differ from C's, but the stand is to blame.
    let st = av::stand(Plan::Windows);
    let mut sim = StandSim::new(WINDOWS);
    sim.frames.retain(|(_, f)| {
        !(f[6..12] == st.peer_mac
            && tcp_head(f).is_some_and(|h| h.sp == 80 && !h.payload.is_empty()))
    });
    let v = judge(&sim);
    assert_eq!(v["overall"], INVALID, "{:#?}", bad(&v));
    assert_eq!(check(&v, WINDOWS.tag, "streamed the scenario"), INVALID);
    assert_eq!(run_of(&v, WINDOWS.tag)["behaviour_fail"], false);
}

#[test]
fn the_reference_must_be_a_pass_of_t01_with_its_recorded_hashes() {
    // The suites refuse a window whose t01_tcp4 is not PASS, or whose files changed since that window's own copy.
    let linux = scratch("linux-bad");
    BSim::tcp(&bv::tcp_case(REFERENCE_CASE).unwrap()).write(&linux);
    let out = scratch("out-bad");
    assert!(
        copy_reference(&linux, &out)
            .unwrap_err()
            .contains("verdict.json")
    );
    let verdict =
        |v: &str| json!({"runs":[{"tag":REFERENCE_CASE,"verdict":v}],"overall":v}).to_string();
    fs::write(linux.join(REFERENCE_VERDICT), verdict(INVALID)).unwrap();
    assert!(
        copy_reference(&linux, &out)
            .unwrap_err()
            .contains("not PASS")
    );
    fs::write(linux.join(REFERENCE_VERDICT), verdict(PASS)).unwrap();
    let doc = linux
        .join("runs")
        .join(REFERENCE_CASE)
        .join(REFERENCE_STEP)
        .join(OUTPUT);
    let good = fs::read(&doc).unwrap();
    fs::write(&doc, b"#masscan\n# end\n").unwrap();
    assert!(
        copy_reference(&linux, &out)
            .unwrap_err()
            .contains("differs")
    );
    fs::write(&doc, &good).unwrap();
    let src = copy_reference(&linux, &out).unwrap();
    assert_eq!(src.run_verdict, PASS);
    // A second copy of the same is kept; another one is refused.
    assert_eq!(copy_reference(&linux, &out).unwrap(), src);
    fs::write(
        linux.join(REFERENCE_VERDICT),
        json!({"runs":[{"tag":REFERENCE_CASE,"verdict":PASS}],"overall":NOT_RUN}).to_string(),
    )
    .unwrap();
    assert!(
        copy_reference(&linux, &out)
            .unwrap_err()
            .contains("another reference")
    );
    // A copy changed after it was taken proves nothing: the reference and the case are INVALID, never PASS or FAIL.
    let sim = StandSim::new(WINDOWS);
    let root = write_dir(&sim);
    let copied = root.join(REFERENCE_DIR).join(REFERENCE_STEP).join(OUTPUT);
    let text = fs::read_to_string(&copied)
        .unwrap()
        .replace("rmasscan-lab", "rmasscan-lub");
    fs::write(&copied, text).unwrap();
    let v = verify_dir(&root);
    assert_eq!(v["overall"], INVALID, "{:#?}", bad(&v));
    assert_eq!(run_of(&v, REFERENCE_DIR)["verdict"], INVALID);
    assert_eq!(run_of(&v, WINDOWS.tag)["verdict"], INVALID);
    assert_eq!(
        check(&v, WINDOWS.tag, "C reference of the scenarios is proven"),
        INVALID
    );
    for d in [linux, out, root] {
        let _ = fs::remove_dir_all(d);
    }
}

#[test]
fn the_reference_is_read_from_a_window_the_banners_verifier_judged() {
    // The copy reads the verdict banners-verify writes: its t01_tcp4 run, judged on the generator's case.
    let linux = scratch("linux-real");
    BSim::tcp(&bv::tcp_case(REFERENCE_CASE).unwrap()).write(&linux);
    let verdict = bv::verify_dir(&linux);
    assert_eq!(
        run_verdict(&verdict, REFERENCE_CASE).as_deref(),
        Some(PASS),
        "{verdict:#}"
    );
    fs::write(linux.join(REFERENCE_VERDICT), verdict.to_string()).unwrap();
    let out = scratch("out-real");
    let src = copy_reference(&linux, &out).unwrap();
    assert_eq!(
        (src.case.as_str(), src.step.as_str()),
        (REFERENCE_CASE, REFERENCE_STEP)
    );
    let mut r = Run::new(REFERENCE_DIR);
    let rf = judge_reference(&mut r, &out, &WINDOWS).expect("a proven reference");
    // What C sent on the two connections: the HTTP request of its hello table and the SSH ident of src/proto-ssh.c.
    assert_eq!(
        rf.payloads[&80],
        [hex_bytes(&c_hello(80).unwrap())],
        "{:?}",
        rf.payloads
    );
    assert_eq!(rf.payloads[&22], [b"SSH-2.0-OPENSSH_7.9\r\n".to_vec()]);
    for d in [linux, out] {
        let _ = fs::remove_dir_all(d);
    }
}
fn hex_bytes(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_stand_verifiers_hand_the_directory_over_and_missing_evidence_is_never_a_pass() {
    for c in [WINDOWS, MACOS] {
        let root = write_dir(&StandSim::new(c));
        let own = verify_dir(&root);
        assert_eq!(own["overall"], PASS);
        let by = if c.plan == Plan::Windows {
            crate::verify::verify_dir(&root)
        } else {
            crate::macos_verify::verify_dir(&root)
        };
        assert_eq!(by, own);
        assert!(crate::verify::safety_trips(&root).is_empty());
        assert_eq!(run_status(&root, c.tag), (PASS.to_owned(), false));
        // No run: NOT RUN.
        fs::remove_dir_all(root.join("runs")).unwrap();
        assert_eq!(verify_dir(&root)["overall"], NOT_RUN);
        let _ = fs::remove_dir_all(&root);
    }
    // A missing output document, or a missing reference, is NOT RUN.
    let mut sim = StandSim::new(WINDOWS);
    sim.doc = Some(Vec::new());
    let root = write_dir(&sim);
    fs::remove_dir_all(root.join(REFERENCE_DIR)).unwrap();
    assert_eq!(verify_dir(&root)["overall"], NOT_RUN);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn an_unexplained_frame_of_the_scanner_or_a_syn_off_the_plan_fails() {
    let st = av::stand(Plan::Windows);
    let plan = WINDOWS.ready_plan().unwrap();
    let builder = rmasscan_core::tcp_frame::TcpFrameBuilder::from_plan(&plan);
    // A stack frame of a connection the stand never opened.
    let mut sim = StandSim::new(WINDOWS);
    let stray = builder.build(&SegmentOut {
        key: ConnKey {
            addrs: ConnAddrs::V4 {
                local: u32::from(st.scanner_ip),
                remote: u32::from(PEER),
            },
            local_port: 40000,
            remote_port: 443,
        },
        seq: 1,
        ack: 1,
        flags: 0x10,
        payload: Vec::new(),
        window: None,
    });
    let t = sim.frames[1].0;
    sim.frames.push((t + 0.5, stray));
    sim.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let v = judge(&sim);
    assert_eq!(
        check(&v, WINDOWS.tag, "belongs to a connection"),
        FAIL,
        "{:#?}",
        bad(&v)
    );
    // The SYNs in another order than the plan's.
    let mut sim = StandSim::new(WINDOWS);
    let at: Vec<usize> = sim
        .frames
        .iter()
        .enumerate()
        .filter(|(_, (_, f))| crate::pcap::is_syn(f))
        .map(|(i, _)| i)
        .collect();
    let (a, b) = (sim.frames[at[0]].1.clone(), sim.frames[at[1]].1.clone());
    sim.frames[at[0]].1 = b;
    sim.frames[at[1]].1 = a;
    let v = judge(&sim);
    assert_eq!(
        check(&v, WINDOWS.tag, "SYNs on the wire are the product plan's"),
        FAIL
    );
}

#[test]
fn the_guests_own_traffic_is_counted_and_never_blamed_on_rmasscan_or_the_stand() {
    // The guest asks for the peer's address itself (a 42-byte request) and the peer answers; it also sends an IPv6
    // router solicitation. Neither is a frame of the scan.
    let st = av::stand(Plan::Windows);
    let mut sim = StandSim::new(WINDOWS);
    let [req, ..] = arp_exchange(&st);
    let mut ask = Vec::new();
    ask.extend([0xff; 6]);
    ask.extend(st.scanner_mac);
    ask.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 1]);
    ask.extend(st.scanner_mac);
    ask.extend(st.scanner_ip.octets());
    ask.extend([0; 6]);
    ask.extend(PEER.octets());
    let mut answer = req.clone();
    answer[0..6].copy_from_slice(&st.scanner_mac);
    answer[21] = 2;
    answer[32..38].copy_from_slice(&st.scanner_mac);
    answer[38..42].copy_from_slice(&st.scanner_ip.octets());
    let mut rs = vec![0x33, 0x33, 0, 0, 0, 2];
    rs.extend(st.scanner_mac);
    rs.extend([0x86, 0xdd]);
    rs.extend([0x60, 0, 0, 0, 0, 8, 58, 255]);
    rs.extend([0u8; 32]);
    rs.extend([133, 0, 0, 0, 0, 0, 0, 0]);
    let t = sim.frames[1].0;
    sim.frames
        .extend([(t + 3.0, ask), (t + 3.0001, answer), (t + 4.0, rs)]);
    sim.frames.sort_by(|a, b| a.0.total_cmp(&b.0));
    let v = judge(&sim);
    assert_eq!(v["overall"], PASS, "{:#?}", bad(&v));
    let w = &run_of(&v, WINDOWS.tag)["notes"]["wire"];
    assert_eq!(
        (w["host_frames_counted"].as_u64(), w["peer_noise"].as_u64()),
        (Some(2), Some(1))
    );
}
