//! Synthetic, hermetic IPv6 evidence. The probes come from the scan plan (`ReadyPlan` + its cursor, the product's own
//! plan); every answer of the peer (SYN-ACK, RST, the NA), the scanner side's own frames (the NS, the ARP who-has, the
//! kernel's RST), the documents in C's byte forms and the `[+]` lines are built here by hand, never with the
//! verifier's parsers or the product's NDP codec. One rule at a time is broken. Nothing touches a network.
use super::*;
use crate::{
    autodetect_verify::{
        ArgvRecord, HASHES, MANIFEST_JSON,
        tests::{
            LAB_ID, Sim as AdSim, T0, TEARDOWN, arp_request, linux_isolation, marker,
            status_fragments,
        },
    },
    link::{END_PAYLOAD, START_PAYLOAD},
    pcap,
    protocols_verify::{
        ResponderRecord,
        tests::{bad, erased, has, ip_frame, run_of, sum16},
    },
    verify::{self, FAIL, INVALID, PASS},
    windows_suite::nonce,
};
use std::{fs, path::PathBuf};

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("rml-ipv6-verify-{}", nonce()));
    fs::create_dir_all(&d).unwrap();
    d
}

// ------------------------------------------------------------------ frames by hand

const SCANNER_MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 1];
const PEER_MAC: [u8; 6] = [2, 0xaa, 0, 0, 0, 2];
const SCANNER_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TTL: u8 = 64;
/// What C prints as the ttl of an IPv6 record (a stale value, never the hop limit; its -oB keeps the low byte).
const C_STALE_TTL6: u32 = 0;

fn pseudo_sum(p: &[u8]) -> u32 {
    let mut init = 0u32;
    for c in p.chunks(2) {
        init += (u32::from(c[0]) << 8) | u32::from(c[1]);
    }
    init
}
/// An Ethernet + IPv6 frame around `l4` (next header `next`, checksum field at `sum_at` set when given), optionally
/// behind a Hop-by-Hop header with the Router Alert option (MLD).
#[allow(clippy::too_many_arguments)]
fn ip6_frame(
    dmac: [u8; 6],
    smac: [u8; 6],
    s: Ipv6Addr,
    d: Ipv6Addr,
    next: u8,
    hop: u8,
    mut l4: Vec<u8>,
    sum_at: Option<usize>,
    hbh: bool,
) -> Vec<u8> {
    if let Some(at) = sum_at {
        l4[at..at + 2].fill(0);
        let mut pseudo = Vec::new();
        pseudo.extend(s.octets());
        pseudo.extend(d.octets());
        pseudo.extend((l4.len() as u32).to_be_bytes());
        pseudo.extend([0, 0, 0, next]);
        let v = sum16(&l4, pseudo_sum(&pseudo));
        l4[at..at + 2].copy_from_slice(&v.to_be_bytes());
    }
    let mut payload = Vec::new();
    let first = if hbh {
        payload.extend([next, 0, 5, 2, 0, 0, 1, 0]);
        0
    } else {
        next
    };
    payload.extend(l4);
    let mut f = Vec::new();
    f.extend(dmac);
    f.extend(smac);
    f.extend([0x86, 0xdd, 0x60, 0, 0, 0]);
    f.extend((payload.len() as u16).to_be_bytes());
    f.extend([first, hop]);
    f.extend(s.octets());
    f.extend(d.octets());
    f.extend(payload);
    f
}
fn probe_dst(p: &[u8]) -> IpAddr {
    if p[12..14] == [8, 0] {
        IpAddr::V4(Ipv4Addr::new(p[30], p[31], p[32], p[33]))
    } else {
        IpAddr::V6(v6_at(p, 38))
    }
}
fn l4_at(p: &[u8]) -> usize {
    if p[12..14] == [8, 0] { 34 } else { 54 }
}
fn ports(p: &[u8]) -> (u16, u16) {
    let at = l4_at(p);
    (be16(p, at), be16(p, at + 2))
}
fn tcp_l4(sp: u16, dp: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sp.to_be_bytes());
    t[2..4].copy_from_slice(&dp.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&64240_u16.to_be_bytes());
    t
}
/// The peer's TCP answer to probe `p` (SYN-ACK 0x12 or RST-ACK 0x14), from its destination, TTL / hop limit 64.
fn tcp_reply(p: &[u8], flags: u8) -> Vec<u8> {
    let (sp, dp) = ports(p);
    let seq = be32(p, l4_at(p) + 4);
    let l4 = tcp_l4(dp, sp, 0x5000_0000, seq.wrapping_add(1), flags);
    match probe_dst(p) {
        IpAddr::V4(d) => ip_frame(SCANNER_MAC, PEER_MAC, d, SCANNER_IP, 6, l4),
        IpAddr::V6(d) => ip6_frame(
            SCANNER_MAC,
            PEER_MAC,
            d,
            scanner6(),
            6,
            TTL,
            l4,
            Some(16),
            false,
        ),
    }
}
/// The scanner kernel's RST to SYN-ACK `r`.
fn scanner_rst(r: &[u8]) -> Vec<u8> {
    let at = l4_at(r);
    let l4 = tcp_l4(be16(r, at + 2), be16(r, at), be32(r, at + 8), 0, 0x04);
    if r[12..14] == [8, 0] {
        ip_frame(
            PEER_MAC,
            SCANNER_MAC,
            SCANNER_IP,
            Ipv4Addr::new(r[26], r[27], r[28], r[29]),
            6,
            l4,
        )
    } else {
        ip6_frame(
            PEER_MAC,
            SCANNER_MAC,
            scanner6(),
            v6_at(r, 22),
            6,
            64,
            l4,
            Some(16),
            false,
        )
    }
}
/// C's own RST to reply `r` (a SYN-ACK or the RST of a closed port), as live 7b r1 caught it: tcp_send_RST builds it
/// from the scan's template (tcp_create_packet), so flags 0x04, the reply's acknowledgment as its sequence number,
/// acknowledgment 0, window 1200 and the template's MSS option (78 bytes over IPv6).
fn c_rst(r: &[u8]) -> Vec<u8> {
    let at = l4_at(r);
    let mut l4 = tcp_l4(be16(r, at + 2), be16(r, at), be32(r, at + 8), 0, 0x04);
    l4[12] = 0x60;
    l4[14..16].copy_from_slice(&1200_u16.to_be_bytes());
    l4.extend([2, 4, 0x05, 0xb4]);
    if r[12..14] == [8, 0] {
        ip_frame(
            PEER_MAC,
            SCANNER_MAC,
            SCANNER_IP,
            Ipv4Addr::new(r[26], r[27], r[28], r[29]),
            6,
            l4,
        )
    } else {
        ip6_frame(
            PEER_MAC,
            SCANNER_MAC,
            scanner6(),
            v6_at(r, 22),
            6,
            255,
            l4,
            Some(16),
            false,
        )
    }
}
/// A peer TCP reply on a step's wire (SYN-ACK or RST-ACK), by its flags.
fn peer_tcp_reply(f: &[u8]) -> bool {
    if f[6..12] != PEER_MAC {
        return false;
    }
    let at = match &f[12..14] {
        [8, 0] if f[23] == 6 => 34,
        [0x86, 0xdd] if f[20] == 6 => 54,
        _ => return false,
    };
    matches!(f.get(at + 13), Some(0x12 | 0x14))
}
/// Every TCP reply of a step's wire, followed 0.1 ms later by C's own RST to it.
fn with_c_resets(frames: &Frames) -> Frames {
    let mut out = Frames::new();
    for (t, f) in frames {
        out.push((*t, f.clone()));
        if peer_tcp_reply(f) {
            out.push((t + 0.0001, c_rst(f)));
        }
    }
    out.sort_by(|a, b| a.0.total_cmp(&b.0));
    out
}
fn ll_scanner() -> Ipv6Addr {
    IPV6_SCANNER_LL.parse().unwrap()
}
fn group_of(ip: Ipv6Addr) -> (Ipv6Addr, [u8; 6]) {
    let o = ip.octets();
    let mut g = [0u8; 16];
    g[0] = 0xff;
    g[1] = 0x02;
    g[11] = 1;
    g[12] = 0xff;
    g[13..16].copy_from_slice(&o[13..16]);
    (Ipv6Addr::from(g), [0x33, 0x33, 0xff, o[13], o[14], o[15]])
}
/// An NS from `smac`/`src` for `target` (to its solicited-node group), with a Source Link-Layer Address option.
fn ns_frame(smac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let (g, gm) = group_of(target);
    let mut l4 = vec![135, 0, 0, 0, 0, 0, 0, 0];
    l4.extend(target.octets());
    l4.extend([1, 1]);
    l4.extend(smac);
    ip6_frame(gm, smac, src, g, 58, 255, l4, Some(2), false)
}
/// rmasscan's NS for the router, from its global address.
fn rm_ns() -> Vec<u8> {
    ns_frame(SCANNER_MAC, scanner6(), router6())
}
/// An NA from `smac`/`src` to `dmac`/`dst` for `target` with `flags`, and a Target Link-Layer Address option.
fn na_frame(smac: [u8; 6], dmac: [u8; 6], src: Ipv6Addr, dst: Ipv6Addr, flags: u8) -> Vec<u8> {
    let mut l4 = vec![136, 0, 0, 0, flags, 0, 0, 0];
    l4.extend(src.octets());
    l4.extend([2, 1]);
    l4.extend(smac);
    ip6_frame(dmac, smac, src, dst, 58, 255, l4, Some(2), false)
}
/// The peer kernel's NA to rmasscan's NS: from the router, Solicited and Override.
fn peer_na() -> Vec<u8> {
    na_frame(PEER_MAC, SCANNER_MAC, router6(), scanner6(), 0x60)
}
/// An MLDv2 report (ICMPv6 143 to ff02::16 behind a Hop-by-Hop Router Alert) from `smac`/`src`.
fn mld_report(smac: [u8; 6], src: Ipv6Addr) -> Vec<u8> {
    let mut l4 = vec![143, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0];
    l4.extend(group_of(src).0.octets());
    let dst: Ipv6Addr = "ff02::16".parse().unwrap();
    ip6_frame(
        [0x33, 0x33, 0, 0, 0, 0x16],
        smac,
        src,
        dst,
        58,
        1,
        l4,
        Some(2),
        true,
    )
}
fn next_hop_request() -> Vec<u8> {
    let mut f = arp_request(&stand(), GATEWAY);
    f.resize(60, 0);
    f
}
fn next_hop_reply() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(SCANNER_MAC);
    f.extend(PEER_MAC);
    f.extend([8, 6, 0, 1, 8, 0, 6, 4, 0, 2]);
    f.extend(PEER_MAC);
    f.extend(GATEWAY.octets());
    f.extend(SCANNER_MAC);
    f.extend(SCANNER_IP.octets());
    f
}

// ------------------------------------------------------------------ records and documents by hand

/// What the stand answers probe `p` with, as a record of `who` (time aside): C's IPv6 ttl is stale.
fn stand_rec(p: &[u8], who: Who) -> Rec {
    let port = ports(p).1;
    let open = TCP_OPEN.contains(&port);
    let ip = probe_dst(p);
    Rec {
        st: if open { St::Open } else { St::Closed },
        ip,
        port,
        reason: Some(if open { "syn-ack" } else { "rst-ack" }.into()),
        ttl: Some(if who == Who::Oracle && ip.is_ipv6() {
            C_STALE_TTL6
        } else {
            u32::from(TTL)
        }),
        ts: None,
    }
}
fn ip_c(ip: IpAddr) -> String {
    // The stand's addresses print the same in C's form and Rust's (no lone zero group to compress).
    ip.to_string()
}
fn render(out: Out, recs: &[Rec], complete: bool) -> Vec<u8> {
    let mut b = Vec::new();
    match out {
        Out::List => {
            b.extend(b"#masscan\n");
            for r in recs {
                b.extend(
                    format!(
                        "{} tcp {} {} {}\n",
                        r.st.name(),
                        r.port,
                        ip_c(r.ip),
                        r.ts.unwrap()
                    )
                    .bytes(),
                );
            }
            if complete {
                b.extend(b"# end\n");
            }
        }
        Out::Json => {
            b.extend(b"[\n");
            for (i, r) in recs.iter().enumerate() {
                if i > 0 {
                    b.extend(b",\n");
                }
                b.extend(format!("{{   \"ip\": \"{}\",   \"timestamp\": \"{}\", \"ports\": [ {{\"port\": {}, \"proto\": \"tcp\", \"status\": \"{}\", \"reason\": \"{}\", \"ttl\": {}}} ] }}\n",
                    ip_c(r.ip), r.ts.unwrap(), r.port, r.st.name(), r.reason.as_deref().unwrap(), r.ttl.unwrap()).bytes());
            }
            if complete {
                b.extend(b"]\n");
            }
        }
        Out::Binary => {
            let mut head = format!("masscan/1.1\ns:{}\n", recs[0].ts.unwrap()).into_bytes();
            head.resize(99, 0);
            b.extend(head);
            for r in recs {
                let reason = match r.reason.as_deref() {
                    Some("syn-ack") => 0x12,
                    Some("rst-ack") => 0x14,
                    _ => 0,
                };
                let ts = (r.ts.unwrap() as u32).to_be_bytes();
                match r.ip {
                    IpAddr::V4(a) => {
                        b.push(if r.st == St::Open { 6 } else { 7 });
                        b.push(13);
                        b.extend(ts);
                        b.extend(a.octets());
                        b.push(6);
                        b.extend(r.port.to_be_bytes());
                        b.push(reason);
                        b.push(r.ttl.unwrap() as u8); // C: (unsigned char)ttl
                    }
                    IpAddr::V6(a) => {
                        b.push(if r.st == St::Open { 10 } else { 11 });
                        b.push(26);
                        b.extend(ts);
                        b.push(6);
                        b.extend(r.port.to_be_bytes());
                        b.push(reason);
                        b.push(r.ttl.unwrap() as u8); // C: (unsigned char)ttl
                        b.push(6);
                        b.extend(a.octets());
                    }
                }
            }
            if complete {
                let mut foot = b"masscan/1.1".to_vec();
                foot.resize(99, 0);
                b.extend(foot);
            }
        }
        Out::Stdout => unreachable!("no case of the suite"),
    }
    b
}

const PLUS_V01: &str = "[+] interface = veth-a (detected: route to [fd00:198:18::2])\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = [fd00:198:18::1] (detected)\n[+] router-ip = [fe80::aa:ff:fe00:2] (interface default gateway)\n[+] router-mac-ipv6 = 02-aa-00-00-00-02 (ndp: NDP requests, 1 ms)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n";
const PLUS_V02: &str = "[+] interface = veth-a (detected: route to 198.18.0.2)\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = 198.18.0.1 (detected)\n[+] router-ip = 198.18.0.2 (interface default gateway)\n[+] source-ip = [fd00:198:18::1] (detected)\n[+] router-ip = [fe80::aa:ff:fe00:2] (interface default gateway)\n[+] router-mac = 02-aa-00-00-00-02 (arp: 1 requests, 1 ms)\n[+] router-mac-ipv6 = 02-aa-00-00-00-02 (ndp: NDP requests, 1 ms)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n";
const PLUS_V03: &str = "[+] interface = veth-a (detected: route to [fd00:198:18::2])\n[+] source-mac = 02-aa-00-00-00-01 (detected)\n[+] source-ip = [fd00:198:18::1] (detected)\n[+] router-mac-ipv6 = 02-aa-00-00-00-02 (given)\n[+] seed = 1 (given)\n[+] source-port = 40000 (given)\n";
const ORACLE_STDERR: &str = "Starting masscan 1.3.9-integration (http://bit.ly/14GZzcT) at 2027-01-15 08:01:40 GMT\nInitiating SYN Stealth Scan\nScanning 4 hosts [2 ports/host]\nrate:  0.00-kpps, 100.00% done, waiting 3-secs, found=8       \r[-] Passed the wait window but still running, forcing exit...\n";
fn rm_stderr(tag: &str, ns: usize, sent: usize, recs: &[Rec]) -> String {
    let plus = match tag {
        "v01_ndp_and_tcp6_syn" => PLUS_V01,
        "v02_mixed_v4_v6" => PLUS_V02,
        _ => PLUS_V03,
    }
    .replace("NDP requests", &format!("{ns} requests"));
    let open = recs.iter().filter(|r| r.st == St::Open).count();
    format!(
        "{plus}{}{}\r[+] finished: Completed, sent {sent}, replies {}, open {open}\n",
        status_fragments()[0],
        " ".repeat(77),
        recs.len()
    )
}

// ------------------------------------------------------------------ the generator

#[derive(Clone)]
pub(crate) struct StepSim {
    pub(crate) spec: StepSpec,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: String,
    pub(crate) exit: i32,
    pub(crate) frames: Frames,
    pub(crate) doc: Option<Vec<u8>>,
    pub(crate) argv: Vec<String>,
    /// The records it reported, in order (for the tests that break one).
    pub(crate) recs: Vec<Rec>,
    pub(crate) responder: ResponderRecord,
}
pub(crate) struct Sim {
    pub(crate) tag: &'static str,
    pub(crate) steps: Vec<StepSim>,
    pub(crate) expect: Ipv6Expect,
    pub(crate) stack: Ipv6Stack,
    pub(crate) extra: Vec<(String, Vec<u8>)>,
    pub(crate) omit: Vec<String>,
}

fn side_stack(iface: &str, addrs: &[&str], ll: &str) -> SideStack {
    let mut a: Vec<Addr6> = addrs
        .iter()
        .map(|x| Addr6 {
            address: (*x).into(),
            prefixlen: 64,
            scope: "global".into(),
            flags: vec!["nodad".into()],
        })
        .collect();
    a.push(Addr6 {
        address: ll.into(),
        prefixlen: 64,
        scope: "link".into(),
        flags: Vec::new(),
    });
    SideStack {
        iface: iface.into(),
        sysctls: IPV6_SYSCTLS
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        addresses: a,
    }
}
/// The stand's IPv6 as the suite reads it on a ready stand.
pub(crate) fn stack() -> Ipv6Stack {
    Ipv6Stack {
        scanner: side_stack("veth-a", &[IPV6_SCANNER], IPV6_SCANNER_LL),
        peer: side_stack("veth-b", &IPV6_PEERS, IPV6_PEER_LL),
    }
}
/// `capture isolation --mode ipv6` on the stand: the autodetect record with the IPv6 stand's.
pub(crate) fn ipv6_isolation() -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(&linux_isolation()).unwrap();
    v["mode"] = json!("ipv6");
    v["ipv6"] = json!({"lab_veth_only": true, "prefix": "fd00:198:18::/64",
        "scanner": {"addresses": ["fd00:198:18::1/64", "fe80::aa:ff:fe00:1/64"],
            "routes": ["fd00:198:18::/64 dev veth-a", "fe80::/64 dev veth-a", "default via fe80::aa:ff:fe00:2 dev veth-a"],
            "permanent_neighbours": ["fd00:198:18::2 lladdr 02:aa:00:00:00:02"],
            "route_get_probe": "2001:db8::1 from :: via fe80::aa:ff:fe00:2 dev veth-a proto boot src fd00:198:18::1 metric 1024 pref medium"},
        "peer": {"addresses": ["fd00:198:18::2/64", "fe80::aa:ff:fe00:2/64"], "routes": ["fd00:198:18::/64 dev veth-b"],
            "permanent_neighbours": ["fd00:198:18::1 lladdr 02:aa:00:00:00:01"], "route_get_probe": "unreachable"}});
    serde_json::to_vec_pretty(&v).unwrap()
}

/// The peer capture of one step and the records the stand's answers give, in reply order: the start marker, the
/// IPv4 next-hop ARP of a scan with IPv4 targets, rmasscan's NS and the peer's NA (a step that resolves the IPv6 next
/// hop, `ns` of them), each probe 10 ms apart with its answer 1 ms later (and the scanner kernel's RST to a SYN-ACK),
/// the end markers.
fn wire(c: &CaseSpec, who: Who, ns: usize, t0: f64, probes: &[Vec<u8>]) -> (Frames, Vec<Rec>) {
    let st = stand();
    let mut fr: Frames = vec![(t0, marker(&st, START_PAYLOAD))];
    if c.has_ipv4() {
        fr.push((t0 + 0.2, next_hop_request()));
        fr.push((t0 + 0.201, next_hop_reply()));
    }
    if who == Who::Rmasscan && !c.router_mac_given {
        for k in 0..ns {
            let t = t0 + 0.3 + k as f64 * 0.01;
            fr.push((t, rm_ns()));
            fr.push((t + 0.0005, peer_na()));
        }
    }
    let mut recs = Vec::new();
    let mut last = t0;
    for (i, p) in probes.iter().enumerate() {
        let t = t0 + 0.6 + i as f64 * 0.01;
        fr.push((t, p.clone()));
        let a = t + 0.001;
        let mut rec = stand_rec(p, who);
        rec.ts = Some(a as u64);
        if rec.st == St::Open {
            let r = tcp_reply(p, 0x12);
            fr.push((a, r.clone()));
            fr.push((a + 0.0005, scanner_rst(&r)));
        } else {
            fr.push((a, tcp_reply(p, 0x14)));
        }
        recs.push(rec);
        last = a;
    }
    for k in 0..3 {
        fr.push((last + 1.0 + f64::from(k) * 0.05, marker(&st, END_PAYLOAD)));
    }
    (fr, recs)
}

impl Sim {
    pub(crate) fn new(tag: &'static str) -> Sim {
        Sim::with_ns(tag, 1)
    }
    /// `ns`: how many NS rmasscan's resolver sent (each answered).
    pub(crate) fn with_ns(tag: &'static str, ns: usize) -> Sim {
        let c = case(tag).unwrap();
        let probes = plan_stream(&c).unwrap();
        let mut steps_ = Vec::new();
        for (i, spec) in steps(tag).unwrap().into_iter().enumerate() {
            let t0 = T0 + 100.0 * i as f64;
            let (frames, recs) = wire(&c, spec.who, ns, t0, &probes);
            let shown: Vec<Rec> = recs
                .iter()
                .filter(|r| c.show_closed || r.st != St::Closed)
                .cloned()
                .collect();
            let oracle = spec.who == Who::Oracle;
            let doc = spec.out.file().map(|_| render(spec.out, &shown, !oracle));
            steps_.push(StepSim {
                argv: spec.argv.clone(),
                stderr: if oracle {
                    ORACLE_STDERR.into()
                } else {
                    rm_stderr(tag, ns, probes.len(), &recs)
                },
                spec,
                stdout: Vec::new(),
                exit: 0,
                frames,
                doc,
                recs: shown,
                responder: ResponderRecord::default(),
            });
        }
        Sim {
            tag,
            steps: steps_,
            expect: expect(tag).unwrap(),
            stack: stack(),
            extra: Vec::new(),
            omit: Vec::new(),
        }
    }
    pub(crate) fn step_mut(&mut self, name: &str) -> &mut StepSim {
        self.steps.iter_mut().find(|s| s.spec.name == name).unwrap()
    }
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let json = |v: &dyn erased::Ser| v.bytes();
        let mut f: Vec<(String, Vec<u8>)> = vec![
            (EXPECT_JSON.into(), json(&self.expect)),
            (ISOLATION_JSON.into(), ipv6_isolation()),
            (ISOLATION_POST_JSON.into(), ipv6_isolation()),
            (IPV6_STACK_JSON.into(), json(&self.stack)),
        ];
        for s in &self.steps {
            let n = s.spec.name;
            f.push((
                format!("{n}/argv.json"),
                json(&ArgvRecord {
                    argv: s.argv.clone(),
                }),
            ));
            f.push((format!("{n}/stdout.txt"), s.stdout.clone()));
            f.push((format!("{n}/stderr.txt"), s.stderr.clone().into_bytes()));
            f.push((
                format!("{n}/exit.txt"),
                format!("{}\n", s.exit).into_bytes(),
            ));
            f.push((format!("{n}/peer.pcap"), pcap::encode(&s.frames)));
            f.push((format!("{n}/capture.json"), AdSim::witness(&s.frames)));
            f.push((
                format!("{n}/peer.err"),
                format!("{} packets captured\n", s.frames.len()).into_bytes(),
            ));
            f.push((format!("{n}/{RESPONDER_JSON}"), json(&s.responder)));
            if let (Some(name), Some(d)) = (s.spec.out.file(), &s.doc) {
                f.push((format!("{n}/{name}"), d.clone()));
            }
        }
        f.extend(self.extra.iter().cloned());
        f.retain(|(n, _)| !self.omit.contains(n));
        f
    }
    /// The case directory under `root/runs/<tag>`, with `manifest.json` at the root if none is there yet.
    pub(crate) fn write(&self, root: &Path) -> PathBuf {
        let man = root.join(MANIFEST_JSON);
        if !man.exists() {
            fs::write(&man, json!({"ipv6": "linux", "lab_id": LAB_ID}).to_string()).unwrap();
        }
        let d = root.join("runs").join(self.tag);
        fs::create_dir_all(&d).unwrap();
        let mut files = self.files();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hashes = String::new();
        for (n, b) in &files {
            let p = d.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b).unwrap();
            hashes.push_str(&format!("{}  {n}\n", verify::sha(b)));
        }
        if !self.omit.iter().any(|o| o == HASHES) {
            fs::write(d.join(HASHES), hashes).unwrap();
        }
        d
    }
}

fn all_cases(root: &Path) {
    for tag in planned_tags() {
        Sim::new(tag).write(root);
    }
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
}
fn judge_one(sim: &Sim) -> (String, Vec<String>) {
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, sim.tag).clone();
    fs::remove_dir_all(&root).unwrap();
    (s(&run["verdict"]).to_owned(), bad(&run))
}
/// The index of the first frame of `frames` that `pick` selects.
fn find(frames: &Frames, pick: impl Fn(&[u8]) -> bool) -> usize {
    frames.iter().position(|(_, f)| pick(f)).unwrap()
}
fn is_v6_syn(f: &[u8]) -> bool {
    f[6..12] == SCANNER_MAC
        && f.get(12..14) == Some(&[0x86, 0xdd][..])
        && f.get(54 + 13) == Some(&2)
}

// ------------------------------------------------------------------ the pure pieces

#[test]
fn the_case_table_gives_the_oracle_rmasscans_argv_plus_its_two_named_extras_in_cs_target_form() {
    let st = steps("v01_ndp_and_tcp6_syn").unwrap();
    assert_eq!(
        st.iter().map(|s| s.name).collect::<Vec<_>>(),
        ["json", "oracle-json", "binary", "oracle-binary"]
    );
    assert_eq!(
        st[0].argv,
        [
            "[fd00:198:18::2]-[fd00:198:18::5]",
            "-p80,81",
            "-oJ",
            "output.json",
            "--show",
            "open,closed",
            "--seed",
            "1",
            "--rate",
            "100",
            "--wait",
            "3",
            "--source-port",
            "40000"
        ]
    );
    let mut want = st[0].argv.clone();
    want.extend(
        [
            "--adapter-ip",
            "fd00:198:18::1",
            "--router-mac-ipv6",
            "02-aa-00-00-00-02",
        ]
        .map(String::from),
    );
    assert_eq!(st[1].argv, want);
    // v03 gives both scanners the router MAC; the oracle adds only the source
    let st = steps("v03_explicit_router_mac_ipv6").unwrap();
    assert!(
        st[0]
            .argv
            .ends_with(&["--router-mac-ipv6".into(), "02-aa-00-00-00-02".into()])
    );
    assert_eq!(
        st[1].argv[st[0].argv.len()..],
        ["--adapter-ip", "fd00:198:18::1"]
    );
    // R3: only TCP ports; the mixed case is the one with IPv4 targets
    for c in CASES {
        assert!(!c.ports.contains(':'), "{}", c.tag);
        assert_eq!(c.has_ipv4(), c.tag == "v02_mixed_v4_v6");
    }
    assert_eq!(NEXT_HOP_NS_MAX, 10);
    assert_eq!(
        responder_args(),
        [
            "--ports",
            "80,8080",
            "--tcp6-ips",
            "fd00:198:18::2,fd00:198:18::3,fd00:198:18::4,fd00:198:18::5"
        ]
    );
}

#[test]
fn the_plan_sends_ipv6_syns_in_c_frames_and_the_mixed_plan_keeps_the_ipv4_bytes_and_index_map() {
    let v01 = plan_stream(&case("v01_ndp_and_tcp6_syn").unwrap()).unwrap();
    assert_eq!(v01.len(), 8, "4 peers x 2 ports");
    for f in &v01 {
        // 78 bytes: Ethernet, IPv6, TCP with MSS (T3), to the peer MAC from the scanner MAC and fd00:198:18::1
        assert_eq!(f.len(), 78);
        assert_eq!(
            (&f[0..6], &f[6..12], &f[12..14]),
            (&PEER_MAC[..], &SCANNER_MAC[..], &[0x86, 0xdd][..])
        );
        assert_eq!(v6_at(f, 22), scanner6());
        assert!(peers6().contains(&v6_at(f, 38)));
        assert_eq!(f[54 + 13], 0x02);
        assert_eq!(be16(f, 54), SOURCE_PORT);
    }
    let v02 = plan_stream(&case("v02_mixed_v4_v6").unwrap()).unwrap();
    assert_eq!(v02.len(), 16);
    let probes: Vec<Probe> = v02
        .iter()
        .enumerate()
        .map(|(i, f)| probe_of(i as f64, f, &stand()).unwrap())
        .collect();
    assert_eq!(v4_bytes_invariant(&probes).unwrap(), 8);
    assert_eq!(v6_low_indices(&probes).unwrap(), (8, 8));
    // an IPv4 probe swapped with its neighbour of the other family breaks the index map
    let mut swapped = probes.clone();
    let (a, b) = (
        swapped.iter().position(|p| p.ip.is_ipv4()).unwrap(),
        swapped.iter().position(|p| p.ip.is_ipv6()).unwrap(),
    );
    swapped.swap(a, b);
    assert!(v6_low_indices(&swapped).is_err());
    assert_eq!(
        v4_bytes_invariant(&swapped).unwrap(),
        8,
        "the bytes are still the plan's"
    );
    // one IPv4 byte changed breaks the bytes
    let mut changed = probes.clone();
    let at = changed.iter().position(|p| p.ip.is_ipv4()).unwrap();
    changed[at].frame[18] ^= 1;
    assert!(
        v4_bytes_invariant(&changed)
            .unwrap_err()
            .contains("differs")
    );
}

#[test]
fn the_ns_and_na_forms_are_recognized_by_hand_and_nothing_near_them() {
    let st = stand();
    assert!(is_next_hop_ns(&rm_ns(), &st));
    assert!(is_stand_na(&peer_na(), &st, scanner6(), router6()));
    // the solicited-node group of the router
    assert_eq!(
        solicited(router6()),
        (
            "ff02::1:ff00:2".parse().unwrap(),
            [0x33, 0x33, 0xff, 0, 0, 2]
        )
    );
    // an NS for another target, from the link-local, or with a bad sum is not the resolver's
    assert!(!is_next_hop_ns(
        &ns_frame(SCANNER_MAC, scanner6(), peers6()[0]),
        &st
    ));
    assert!(!is_next_hop_ns(
        &ns_frame(SCANNER_MAC, ll_scanner(), router6()),
        &st
    ));
    let mut f = rm_ns();
    f[57] ^= 1;
    assert!(!is_next_hop_ns(&f, &st));
    // an NA with the Router flag, without Override, or from another address is not the stand's
    assert!(!is_stand_na(
        &na_frame(PEER_MAC, SCANNER_MAC, router6(), scanner6(), 0xe0),
        &st,
        scanner6(),
        router6()
    ));
    assert!(!is_stand_na(
        &na_frame(PEER_MAC, SCANNER_MAC, router6(), scanner6(), 0x40),
        &st,
        scanner6(),
        router6()
    ));
    assert!(!is_stand_na(
        &na_frame(PEER_MAC, SCANNER_MAC, peers6()[0], scanner6(), 0x60),
        &st,
        scanner6(),
        router6()
    ));
    // MLD behind its Hop-by-Hop header is found as kernel noise
    let p = mld_report(PEER_MAC, peers6()[0]);
    let q = pkt(&p).unwrap();
    assert!(q.ext && q.proto == 58);
    assert_eq!(noise(&q, true), Some("mld"));
}

#[test]
fn the_parsers_read_cs_ipv6_and_mixed_documents() {
    let recs = vec![
        Rec {
            st: St::Open,
            ip: "fd00:198:18::2".parse().unwrap(),
            port: 80,
            reason: Some("syn-ack".into()),
            ttl: Some(64),
            ts: Some(1_800_000_000),
        },
        Rec {
            st: St::Closed,
            ip: "198.18.0.3".parse().unwrap(),
            port: 81,
            reason: Some("rst-ack".into()),
            ttl: Some(64),
            ts: Some(1_800_000_001),
        },
    ];
    for out in [Out::Json, Out::Binary, Out::List] {
        for complete in [true, false] {
            let d = parse_doc(out, &render(out, &recs, complete)).unwrap();
            assert_eq!(d.complete, complete, "{out:?}");
            let want: Vec<Rec> = recs
                .iter()
                .map(|r| match out {
                    Out::List => Rec {
                        reason: None,
                        ttl: None,
                        ..r.clone()
                    },
                    _ => r.clone(),
                })
                .collect();
            assert_eq!(d.records, want, "{out:?}");
        }
    }
    // the golden of the format stage, written by C's --readscan: IPv6 types 10/11 and IPv4 types 6/7 in one file
    let golden = fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/golden/formats/outputs/ipv6.open-closed.binary.out"),
    )
    .unwrap();
    let e = parse_doc(Out::Binary, &golden).unwrap_err();
    assert!(
        e.contains("R3"),
        "the golden holds UDP over IPv6, which this suite never scans: {e}"
    );
    // an IPv6 address not in C's form, or a UDP record, is no record of this suite
    let t = String::from_utf8(render(Out::Json, &recs, true))
        .unwrap()
        .replace("fd00:198:18::2", "fd00:198:18:0:0:0:0:2");
    assert!(parse_doc(Out::Json, t.as_bytes()).is_err());
    let t = String::from_utf8(render(Out::List, &recs, true))
        .unwrap()
        .replace(" tcp ", " udp ");
    assert!(
        parse_doc(Out::List, t.as_bytes())
            .unwrap_err()
            .contains("R3")
    );
    // a cut binary record is an error, not a cut file
    let mut b = render(Out::Binary, &recs, false);
    b.pop();
    assert!(parse_doc(Out::Binary, &b).is_err());
}

#[test]
fn the_stack_rules_name_a_tentative_address_and_every_other_unready_state() {
    assert_eq!(stack_problem(&stack()), None);
    let mut s = stack();
    s.scanner.addresses[0].flags.push("tentative".into());
    assert!(
        stack_problem(&s)
            .unwrap()
            .contains("fd00:198:18::1 on veth-a is tentative")
    );
    let mut s = stack();
    s.peer.addresses[4].flags.push("dadfailed".into());
    assert!(stack_problem(&s).unwrap().contains("dadfailed"));
    let mut s = stack();
    s.peer.sysctls[2].1 = "1".into();
    assert!(stack_problem(&s).unwrap().contains("IPv6 settings"));
    let mut s = stack();
    s.scanner.addresses.pop();
    assert!(stack_problem(&s).unwrap().contains("IPv6 addresses"));
    // `ip -6 -j addr` as the suite reads it: the true flags only
    let a = addresses_of(&json!([{"ifname":"veth-a","addr_info":[
        {"family":"inet6","local":"fd00:198:18::1","prefixlen":64,"scope":"global","tentative":true,"nodad":true,"valid_life_time":4294967295u64},
        {"family":"inet6","local":"fe80::aa:ff:fe00:1","prefixlen":64,"scope":"link"}]}]))
    .unwrap();
    assert_eq!(a[0].flags, ["nodad", "tentative"]);
    assert!(a[1].flags.is_empty());
}

#[test]
fn ipv6_privacy_allows_the_stand_and_names_any_other_address() {
    let text = "[+] router-ip = [fe80::aa:ff:fe00:2] (interface default gateway) to [fd00:198:18::3]:80 via capture::dump at 08:01:40 02:aa:00:00:00:01";
    let toks = ipv6_tokens(text);
    assert_eq!(toks.len(), 2, "{toks:?}");
    assert!(toks.iter().all(|t| ipv6_allowed(*t, true)));
    let leak: Ipv6Addr = "2a00:1450:4001::1".parse().unwrap();
    assert_eq!(ipv6_tokens("src 2a00:1450:4001::1, more"), [leak]);
    assert!(!ipv6_allowed(leak, false));
    // another host's link-local is never allowed, the documentation prefix only outside a scanner's text
    assert!(!ipv6_allowed(
        "fe80::1c2b:3cff:fe4d:5e6f".parse().unwrap(),
        false
    ));
    assert!(ipv6_allowed("2001:db8::1".parse().unwrap(), false));
    assert!(!ipv6_allowed("2001:db8::1".parse().unwrap(), true));
}

// ------------------------------------------------------------------ whole directories

#[test]
fn the_generator_passes_every_case_and_the_verdict_rederives_byte_for_byte() {
    let root = scratch();
    all_cases(&root);
    let res = verify_dir(&root);
    for tag in planned_tags() {
        let run = run_of(&res, tag);
        assert_eq!(run["verdict"], PASS, "{tag}: {:#?}", bad(run));
        let notes = array(&run["notes"]["deviations"]);
        assert_eq!(notes.len(), case(tag).unwrap().deviations.len(), "{tag}");
    }
    assert_eq!(res["overall"], PASS, "{}", res["totals"]);
    assert!(array(&res["safety_trips"]).is_empty());
    // C's stale IPv6 ttl was in the oracle's documents and was never compared
    let n = run_of(&res, "v01_ndp_and_tcp6_syn")["notes"]["deviations"].to_string();
    assert!(
        n.contains("16 IPv6 records of C with a ttl, 16 of them not the reply's hop limit"),
        "{n}"
    );
    let again = verify_dir(&root);
    assert_eq!(
        serde_json::to_string_pretty(&res).unwrap(),
        serde_json::to_string_pretty(&again).unwrap()
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_probe_byte_that_differs_from_the_oracle_fails() {
    // The oracle's IPv6 SYN differs in its TCP window (no field a reply is matched on): rmasscan no longer equals C.
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("oracle-json");
    let at = find(&s.frames, is_v6_syn);
    s.frames[at].1[54 + 14] ^= 0x01;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "json: the probes equal the C oracle's"),
        "{b:#?}"
    );
    // The detail says where: the first probe that differs (the oracle's first IPv6 SYN is its first probe).
    let first = sim.step_mut("oracle-json").frames[..at]
        .iter()
        .filter(|(_, f)| is_v6_syn(f))
        .count();
    assert!(
        b[0].ends_with(&format!("first difference at Some({first})")),
        "{b:#?}"
    );
    assert_eq!(b.len(), 1, "{b:#?}");
}

#[test]
fn the_stands_syn_check_names_the_ipv4_syns_it_counts() {
    // `av::foreign_syns` counts IPv4 SYNs only; a scanner IPv6 frame off the stand is the frame check's (above).
    let root = scratch();
    all_cases(&root);
    let res = verify_dir(&root);
    let names: Vec<String> = array(&run_of(&res, "v02_mixed_v4_v6")["checks"])
        .iter()
        .map(|c| s(&c["name"]).to_owned())
        .collect();
    assert!(
        names.iter().any(|n| n
            == "no IPv4 SYN on the binary capture from outside the stand binding or to an address off the stand"),
        "{names:#?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with("no SYN on")),
        "{names:#?}"
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_extra_scanner_frame_fails_rmasscan_and_invalidates_the_oracle() {
    // rmasscan sends an ICMPv6 Echo Request to a peer: no probe, no named class.
    let echo = ip6_frame(
        PEER_MAC,
        SCANNER_MAC,
        scanner6(),
        peers6()[0],
        58,
        64,
        vec![128, 0, 0, 0, 0, 1, 0, 1],
        Some(2),
        false,
    );
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("binary");
    let t = s.frames[3].0 + 0.0001;
    s.frames.insert(3, (t, echo.clone()));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: every frame of the scanner MAC is a probe"
        ) && b.iter().any(|x| x.contains("ICMPv6 type 128")),
        "{b:#?}"
    );
    // the same frame on the oracle's step is a broken stand
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("oracle-binary");
    let t = s.frames[3].0 + 0.0001;
    s.frames.insert(3, (t, echo));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, INVALID, "oracle-binary: every frame of the scanner MAC"),
        "{b:#?}"
    );
}

#[test]
fn an_ns_count_over_the_resolvers_bound_fails() {
    // 11 NS, each answered, and the [+] line says 11: more than NDP_TIMEOUT / NDP_INTERVAL allows.
    let sim = Sim::with_ns("v01_ndp_and_tcp6_syn", 11);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "next_hop_ns 11 of at most 10"), "{b:#?}");
    assert!(
        has(&b, FAIL, "rmasscan resolved its IPv6 next hop by NDP"),
        "{b:#?}"
    );
    // ten are within the bound
    let (v, b) = judge_one(&Sim::with_ns("v01_ndp_and_tcp6_syn", 10));
    assert_eq!(v, PASS, "{b:#?}");
    // an NS count the [+] line does not match
    let mut sim = Sim::with_ns("v01_ndp_and_tcp6_syn", 2);
    let s = sim.step_mut("json");
    s.stderr = s.stderr.replace("(ndp: 2 requests", "(ndp: 1 requests");
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "json: rmasscan resolved its IPv6 next hop by NDP"),
        "{b:#?}"
    );
    // an NS for a target that is neither the router nor a peer is the scanner's own extra frame (an NS for a peer's ULA
    // is the stand noise `scanner_ns_for_peer`: a_scanner_kernel_ns_for_a_peer_is_named_noise_and_invalid)
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    let at = find(&s.frames, |f| f == rm_ns());
    s.frames.insert(
        at,
        (
            s.frames[at].0 - 0.001,
            ns_frame(SCANNER_MAC, scanner6(), "fd00:198:18::9".parse().unwrap()),
        ),
    );
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "not the resolver's solicitation"), "{b:#?}");
}

#[test]
fn router_mac_ipv6_must_bypass_ndp_and_the_oracle_never_solicits() {
    // v03: rmasscan solicits although --router-mac-ipv6 was given.
    let mut sim = Sim::new("v03_explicit_router_mac_ipv6");
    let s = sim.step_mut("json");
    let t = s.frames[1].0;
    s.frames.insert(1, (t - 0.01, rm_ns()));
    s.frames.insert(2, (t - 0.0095, peer_na()));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "next_hop_ns 1 of at most 0"), "{b:#?}");
    assert!(has(&b, FAIL, "--router-mac-ipv6 bypasses NDP"), "{b:#?}");
    // an IPv6 probe of v03 to another MAC than the given one
    let mut sim = Sim::new("v03_explicit_router_mac_ipv6");
    let s = sim.step_mut("json");
    let at = find(&s.frames, is_v6_syn);
    s.frames[at].1[5] = 9;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "--router-mac-ipv6 bypasses NDP"), "{b:#?}");
    // the oracle's step with an NS: C was given the router MAC, so a solicitation is a broken stand
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("oracle-json");
    let t = s.frames[1].0;
    s.frames.insert(1, (t - 0.01, rm_ns()));
    s.frames.insert(2, (t - 0.0095, peer_na()));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(has(&b, INVALID, "deviation ndp-ns-not-rs"), "{b:#?}");
}

#[test]
fn a_v4_probe_out_of_the_invariant_order_fails() {
    // v02: rmasscan sends two of its probes, an IPv4 and an IPv6 one, in the other order (each still answered).
    let mut sim = Sim::new("v02_mixed_v4_v6");
    let s = sim.step_mut("binary");
    let syn = |f: &[u8]| {
        f[6..12] == SCANNER_MAC && pkt(f).and_then(|p| tcp(&p)).is_some_and(|x| x.flags == 2)
    };
    let a = find(&s.frames, |f| syn(f) && f[12..14] == [8, 0]);
    let b6 = find(&s.frames, |f| syn(f) && f[12..14] == [0x86, 0xdd]);
    let (fa, fb) = (s.frames[a].1.clone(), s.frames[b6].1.clone());
    s.frames[a].1 = fb;
    s.frames[b6].1 = fa;
    // the replies follow their probes (the stand answers whatever came)
    let (ra, rb) = (
        find(&s.frames, |f| {
            f[6..12] == PEER_MAC && f[..] == tcp_reply(&s.frames[b6].1, 0x12)[..]
                || f[..] == tcp_reply(&s.frames[b6].1, 0x14)[..]
        }),
        find(&s.frames, |f| {
            f[6..12] == PEER_MAC && f[..] == tcp_reply(&s.frames[a].1, 0x12)[..]
                || f[..] == tcp_reply(&s.frames[a].1, 0x14)[..]
        }),
    );
    let (xa, xb) = (s.frames[ra].1.clone(), s.frames[rb].1.clone());
    s.frames[ra].1 = xb;
    s.frames[rb].1 = xa;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "binary: v4-order invariant, order"), "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the probes on the wire equal the plan"),
        "{b:#?}"
    );
    // one IPv4 probe byte that is not the IPv4-only plan's (its IP id)
    let mut sim = Sim::new("v02_mixed_v4_v6");
    let s = sim.step_mut("list");
    let at = find(&s.frames, |f| syn(f) && f[12..14] == [8, 0]);
    s.frames[at].1[18] ^= 1;
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(has(&b, FAIL, "list: v4-order invariant, bytes"), "{b:#?}");
}

#[test]
fn a_document_record_missing_or_a_wrong_ipv6_ttl_of_rmasscan_fails() {
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    let recs: Vec<Rec> = s.recs[1..].to_vec();
    s.doc = Some(render(Out::Json, &recs, true));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "json: the document holds the records of the replies on its wire"
        ),
        "{b:#?}"
    );
    assert!(
        has(&b, FAIL, "json: the records equal the C oracle's"),
        "{b:#?}"
    );
    // rmasscan's IPv6 ttl is the hop limit (64); C's stale value from rmasscan is a FAIL against its own wire only
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("binary");
    let mut recs = s.recs.clone();
    recs[0].ttl = Some(C_STALE_TTL6);
    s.doc = Some(render(Out::Binary, &recs, true));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert_eq!(b.len(), 1, "{b:#?}");
    assert!(
        has(&b, FAIL, "binary: the document holds the records"),
        "{b:#?}"
    );
}

#[test]
fn a_tentative_address_before_the_case_is_not_run() {
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    sim.stack.scanner.addresses[0]
        .flags
        .push("tentative".into());
    let (v, b) = judge_one(&sim);
    assert_eq!(v, NOT_RUN, "{b:#?}");
    assert!(
        has(&b, NOT_RUN, "ipv6-stack.json: the stand's IPv6 was ready")
            && b.iter().any(|x| x.contains("tentative")),
        "{b:#?}"
    );
    // and a missing stack record is NOT RUN too
    let mut sim = Sim::new("v03_explicit_router_mac_ipv6");
    sim.omit.push(IPV6_STACK_JSON.into());
    let (v, b) = judge_one(&sim);
    assert_eq!(v, NOT_RUN, "{b:#?}");
}

#[test]
fn a_peer_answer_of_the_wrong_form_is_invalid() {
    // The peer's NA carries the Router flag: the stand is not the one designed (no forwarding).
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    let at = find(&s.frames, |f| f == peer_na());
    s.frames[at].1 = na_frame(PEER_MAC, SCANNER_MAC, router6(), scanner6(), 0xe0);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "json: the stand answered every probe the stand's way"
        ),
        "{b:#?}"
    );
    // a closed port answered with a SYN-ACK
    let mut sim = Sim::new("v03_explicit_router_mac_ipv6");
    let s = sim.step_mut("oracle-json");
    let p81 = find(&s.frames, |f| is_v6_syn(f) && be16(f, 54 + 2) == 81);
    let rst = tcp_reply(&s.frames[p81].1, 0x14);
    let at = find(&s.frames, |f| f == rst);
    s.frames[at].1 = tcp_reply(&s.frames[p81].1, 0x12);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "the stand answered every probe the stand's way"
        ),
        "{b:#?}"
    );
    // an NS left unanswered
    let mut sim = Sim::new("v02_mixed_v4_v6");
    let s = sim.step_mut("list");
    let at = find(&s.frames, |f| f == peer_na());
    s.frames.remove(at);
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        b.iter().any(|x| x.contains("0 NA, 0 of the stand's form")),
        "{b:#?}"
    );
}

#[test]
fn kernel_noise_in_a_step_is_named_and_invalid_never_fail() {
    for (who, f) in [
        ("binary", mld_report(PEER_MAC, peers6()[0])),
        ("oracle-binary", mld_report(SCANNER_MAC, scanner6())),
        (
            "binary",
            ns_frame(SCANNER_MAC, Ipv6Addr::UNSPECIFIED, scanner6()),
        ),
        ("binary", ns_frame(PEER_MAC, peers6()[0], scanner6())),
    ] {
        let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
        let s = sim.step_mut(who);
        let t = s.frames[2].0 + 0.0001;
        s.frames.insert(2, (t, f));
        let (v, b) = judge_one(&sim);
        assert_eq!(v, INVALID, "{b:#?}");
        assert!(has(&b, INVALID, "no kernel noise of either side"), "{b:#?}");
        assert!(!b.iter().any(|x| x.starts_with(FAIL)), "{b:#?}");
    }
}

#[test]
fn a_probe_off_the_stand_is_a_safety_fail() {
    let mut sim = Sim::new("v03_explicit_router_mac_ipv6");
    let s = sim.step_mut("json");
    let at = find(&s.frames, is_v6_syn);
    let mut f = s.frames[at].1.clone();
    f[38..54].copy_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
    s.frames.insert(at + 1, (s.frames[at].0 + 0.0001, f));
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run = run_of(&res, sim.tag);
    assert_eq!(run["verdict"], FAIL);
    assert_eq!(run["safety_trip"], true, "{:#?}", bad(run));
    assert!(
        bad(run).iter().any(|x| x.contains("2001:db8::9")),
        "{:#?}",
        bad(run)
    );
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_ipv6_address_off_the_stand_in_a_text_file_is_invalid() {
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    s.stderr = s.stderr.replace(
        "[fd00:198:18::1] (detected)",
        "[2a00:1450:4001::1] (detected)",
    );
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, INVALID, "privacy: json/stderr.txt")
            && b.iter()
                .any(|x| x.contains("IPv6 address 2a00:1450:4001::1")),
        "{b:#?}"
    );
}

#[test]
fn the_oracle_is_held_to_its_own_wire_but_not_to_an_ipv6_ttl() {
    // The oracle's IPv6 records with a ttl equal to the hop limit pass as well as the stale ones.
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("oracle-binary");
    let recs: Vec<Rec> = s
        .recs
        .iter()
        .map(|r| Rec {
            ttl: Some(u32::from(TTL)),
            ..r.clone()
        })
        .collect();
    s.doc = Some(render(Out::Binary, &recs, false));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, PASS, "{b:#?}");
    // but an oracle record with another port is a broken oracle (INVALID), never a FAIL of rmasscan
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("oracle-json");
    let mut recs = s.recs.clone();
    recs[0].port = 8080;
    s.doc = Some(render(Out::Json, &recs, false));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
}

/// The verdict and exit code of `ipv6-verify` on one case written alone.
fn verdict_and_exit(sim: &Sim) -> (String, Vec<String>, i32) {
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run_ = run_of(&res, sim.tag).clone();
    let code = run(&["--dir".to_owned(), root.to_string_lossy().into_owned()]).unwrap();
    fs::remove_dir_all(&root).unwrap();
    (s(&run_["verdict"]).to_owned(), bad(&run_), code)
}

#[test]
fn rmasscan_without_its_ndp_is_its_own_fail_never_a_broken_stand() {
    // No NS at all, the [+] line saying 0: the run is rmasscan's FAIL (exit 1), not INVALID.
    let (v, b, code) = verdict_and_exit(&Sim::with_ns("v01_ndp_and_tcp6_syn", 0));
    assert_eq!((v.as_str(), code), (FAIL, 1), "{b:#?}");
    assert!(
        has(&b, FAIL, "json: rmasscan resolved its IPv6 next hop by NDP"),
        "{b:#?}"
    );
    assert!(!b.iter().any(|x| x.starts_with(INVALID)), "{b:#?}");
    // `(ndp: 1` printed, but the NS and its NA stripped from the wire: the same.
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    for step in ["json", "binary"] {
        let s = sim.step_mut(step);
        s.frames.retain(|(_, f)| *f != rm_ns() && *f != peer_na());
    }
    let (v, b, code) = verdict_and_exit(&sim);
    assert_eq!((v.as_str(), code), (FAIL, 1), "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "binary: rmasscan resolved its IPv6 next hop by NDP"
        ),
        "{b:#?}"
    );
    assert!(!b.iter().any(|x| x.starts_with(INVALID)), "{b:#?}");
    // rmasscan printing another source than the one it detects is its FAIL too (the detection check)
    let mut sim = Sim::new("v03_explicit_router_mac_ipv6");
    let s = sim.step_mut("json");
    s.stderr = s
        .stderr
        .replace("[fd00:198:18::1] (detected)", "[fd00:198:18::1] (given)");
    let (v, b, code) = verdict_and_exit(&sim);
    assert_eq!((v.as_str(), code), (FAIL, 1), "{b:#?}");
    assert!(has(&b, FAIL, "json: [+] lines are the stand's"), "{b:#?}");
}

#[test]
fn a_scanner_kernel_ns_for_a_peer_is_named_noise_and_invalid() {
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    let at = find(&s.frames, |f| {
        f[6..12] == PEER_MAC
            && pkt(f)
                .and_then(|p| tcp(&p))
                .is_some_and(|x| x.flags == 0x12)
    });
    let t = s.frames[at].0 + 0.0001;
    s.frames
        .insert(at + 1, (t, ns_frame(SCANNER_MAC, scanner6(), peers6()[0])));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert!(
        has(&b, INVALID, "no kernel noise of either side")
            && b.iter().any(|x| x.contains("scanner_ns_for_peer")),
        "{b:#?}"
    );
    assert!(!b.iter().any(|x| x.starts_with(FAIL)), "{b:#?}");
}

#[test]
fn the_products_ns_passes_the_verifiers_hand_written_resolver_form() {
    // The codec cross-check: rmasscan-core's own NS encoder, with the stand's MAC, source and router, is the form the
    // verifier names `next_hop_ns`; the verifier's hand-built NS is the same 86 bytes.
    let f = rmasscan_core::ndp::PendingNdp::new(
        SCANNER_MAC,
        u128::from(scanner6()),
        u128::from(router6()),
    )
    .request_frame();
    assert!(is_next_hop_ns(&f, &stand()));
    assert_eq!(f.to_vec(), rm_ns());
}

#[test]
fn cs_own_reset_of_each_first_reply_is_named_on_the_oracles_step_and_never_rmasscans() {
    // Live 7b r1: C resets each distinct reply that passes its cookie check and dedup, the closed port's RST as well
    // as the SYN-ACK (main.c:1048-1101: `TCP_IS_SYNACK || TCP_IS_RST`, then tcp_send_RST), in both families.
    let mut sim = Sim::new("v02_mixed_v4_v6");
    for name in ["oracle-binary", "oracle-list"] {
        let s = sim.step_mut(name);
        s.frames = with_c_resets(&s.frames);
    }
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run_ = run_of(&res, sim.tag).clone();
    fs::remove_dir_all(&root).unwrap();
    assert_eq!(s(&run_["verdict"]), PASS, "{:#?}", bad(&run_));
    for name in ["oracle-binary", "oracle-list"] {
        let n = &run_["notes"]["scanner_frames"][name];
        // 16 probes, 8 open and 8 closed: the kernel's 8 resets and C's 8 of the SYN-ACKs, C's 8 of the RSTs
        assert_eq!(n["rst_to_syn_ack"], 16, "{n}");
        assert_eq!(n["at_most"]["rst_to_syn_ack"], 16, "{n}");
        assert_eq!(n["rst_to_rst"], 8, "{n}");
        assert_eq!(n["at_most"]["rst_to_rst"], 8, "{n}");
        assert_eq!(n["unexplained"], 0, "{n}");
    }
    // a second reset of C for the same RST is over the bound: a broken oracle (INVALID), never rmasscan's FAIL
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("oracle-json");
    s.frames = with_c_resets(&s.frames);
    let i = s
        .frames
        .iter()
        .position(|(_, f)| f[6..12] == PEER_MAC && f.get(54 + 13) == Some(&0x14))
        .unwrap();
    let (t, again) = (s.frames[i].0 + 0.0002, c_rst(&s.frames[i].1));
    s.frames.insert(i + 2, (t, again));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, INVALID, "{b:#?}");
    assert_eq!(b.len(), 1, "{b:#?}");
    assert!(
        has(
            &b,
            INVALID,
            "oracle-json: the named scanner-side frames stay within their bounds"
        ) && b[0].contains("rst_to_rst 5 of at most 4"),
        "{b:#?}"
    );
    // rmasscan has no RST path and no kernel answers an RST: the same frame on rmasscan's step is its FAIL
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    let i = s
        .frames
        .iter()
        .position(|(_, f)| f[6..12] == PEER_MAC && f.get(54 + 13) == Some(&0x14))
        .unwrap();
    let (t, rst) = (s.frames[i].0 + 0.0001, c_rst(&s.frames[i].1));
    s.frames.insert(i + 1, (t, rst));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert_eq!(b.len(), 1, "{b:#?}");
    assert!(
        has(
            &b,
            FAIL,
            "json: the named scanner-side frames stay within their bounds"
        ) && b[0].contains("rst_to_rst 1 of at most 0"),
        "{b:#?}"
    );
}

/// A step's verdict, its failing checks and the case's notes.
fn judge_with_notes(sim: &Sim) -> (String, Vec<String>, Value) {
    let root = scratch();
    sim.write(&root);
    fs::write(root.join(av::TEARDOWN_JSON), format!("{TEARDOWN}\n")).unwrap();
    let res = verify_dir(&root);
    let run_ = run_of(&res, sim.tag).clone();
    fs::remove_dir_all(&root).unwrap();
    (s(&run_["verdict"]).to_owned(), bad(&run_), run_)
}
/// A JSON document with every record's ttl `from` replaced by `to`, as text.
fn json_ttl(doc: &[u8], from: &str, to: &str) -> Vec<u8> {
    let t = String::from_utf8(doc.to_vec()).unwrap();
    let n = format!("\"ttl\": {from}}}");
    assert!(t.contains(&n), "{t}");
    t.replace(&n, &format!("\"ttl\": {to}}}")).into_bytes()
}

#[test]
fn cs_ipv6_json_ttl_may_be_any_32_bit_value_and_rmasscans_stays_a_byte() {
    // Live 7b r1: C prints `"ttl": %u` of parsed.ip_ttl (out-json.c:51), which it sets for IPv4 only
    // (proto-preprocess.c:127): r1's oracle-json documents held 320995840 and 2497958912 (its -oB keeps the low byte).
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let step = sim.step_mut("oracle-json");
    step.doc = Some(json_ttl(step.doc.as_ref().unwrap(), "0", "320995840"));
    let (v, b, run_) = judge_with_notes(&sim);
    assert_eq!(
        (v.as_str(), b.clone()),
        (PASS, Vec::<String>::new()),
        "{b:#?}"
    );
    // counted with the -oB document's: 8 records each, none the hop limit
    let n = run_["notes"].to_string();
    assert!(
        n.contains("16 IPv6 records of C with a ttl, 16 of them not the reply's hop limit"),
        "{n}"
    );
    let named = array(&run_["checks"]).iter().any(|c| {
        c["result"] == PASS
            && s(&c["name"])
                == format!("oracle-json: output.json is a well-formed document{IPV6_DOC_RULE}")
    });
    assert!(named, "the oracle's check names the allowance");
    // the parser's rule itself: only an IPv6 record of C's may exceed a byte; C's IPv4 ttl is the header's byte
    let t4 = "[\n{   \"ip\": \"198.18.0.2\",   \"timestamp\": \"1800000100\", \"ports\": [ {\"port\": 80, \"proto\": \"tcp\", \"status\": \"open\", \"reason\": \"syn-ack\", \"ttl\": 300} ] }\n]\n";
    let t6 = t4.replace("198.18.0.2", "fd00:198:18::2");
    assert!(parse_doc_of(Out::Json, t4.as_bytes(), Who::Oracle).is_err());
    assert!(parse_doc_of(Out::Json, t4.replace("300", "64").as_bytes(), Who::Oracle).is_ok());
    assert_eq!(
        parse_doc_of(Out::Json, t6.as_bytes(), Who::Oracle)
            .unwrap()
            .records[0]
            .ttl,
        Some(300)
    );
    assert!(parse_doc_of(Out::Json, t6.as_bytes(), Who::Rmasscan).is_err());
    assert!(parse_doc(Out::Json, t6.as_bytes()).is_err());
    // rmasscan prints the reply's hop limit, a byte: the same value in its document is malformed, its own FAIL
    let mut sim = Sim::new("v01_ndp_and_tcp6_syn");
    let s = sim.step_mut("json");
    s.doc = Some(json_ttl(s.doc.as_ref().unwrap(), "64", "320995840"));
    let (v, b) = judge_one(&sim);
    assert_eq!(v, FAIL, "{b:#?}");
    assert!(
        has(&b, FAIL, "json: output.json is a well-formed document"),
        "{b:#?}"
    );
}
