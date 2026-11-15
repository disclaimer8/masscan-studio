//! Namespace-bound peer tools for the isolated wire laboratory.
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    mod qmp {
        use super::*;
        use std::{
            io::{BufRead, BufReader, Write},
            os::unix::net::UnixListener,
            sync::mpsc,
            thread,
        };

        /// A one-connection QMP server. `script` gets the received lines one at a time and returns the
        /// lines to send back for each (None closes the connection). Returns the lines it received.
        fn serve(
            tag: &str,
            greeting: &str,
            script: impl Fn(usize, &str) -> Option<Vec<String>> + Send + 'static,
        ) -> (String, thread::JoinHandle<Vec<String>>) {
            let path = std::env::temp_dir().join(format!("qmp-{tag}-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let l = UnixListener::bind(&path).unwrap();
            let (tx, rx) = mpsc::channel::<()>();
            let greeting = greeting.to_owned();
            let h = thread::spawn(move || {
                tx.send(()).unwrap();
                let (mut s, _) = l.accept().unwrap();
                writeln!(s, "{greeting}").unwrap();
                let mut r = BufReader::new(s.try_clone().unwrap());
                let mut got = Vec::new();
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let line = line.trim().to_owned();
                    let reply = script(got.len(), &line);
                    got.push(line);
                    match reply {
                        Some(out) => {
                            for o in out {
                                writeln!(s, "{o}").unwrap();
                            }
                        }
                        None => break,
                    }
                }
                let _ = std::fs::remove_file(path);
                got
            });
            rx.recv().unwrap();
            (
                std::env::temp_dir()
                    .join(format!("qmp-{tag}-{}.sock", std::process::id()))
                    .to_string_lossy()
                    .into_owned(),
                h,
            )
        }
        const GREETING: &str = r#"{"QMP":{"version":{},"capabilities":[]}}"#;

        #[test]
        fn set_link_sends_capabilities_then_set_link_on_lab0_only_with_the_requested_state() {
            for up in [false, true] {
                let (sock, h) = serve(&format!("ok{up}"), GREETING, |i, _| {
                    Some(match i {
                        // an asynchronous event before the reply must be skipped, not mistaken for it
                        1 => vec![
                            r#"{"event":"NIC_RX_FILTER_CHANGED"}"#.into(),
                            r#"{"return":{}}"#.into(),
                        ],
                        _ => vec![r#"{"return":{}}"#.into()],
                    })
                });
                let reply = qmp_set_link(&sock, up).unwrap();
                assert_eq!(reply, json!({"return":{}}));
                let got = h.join().unwrap();
                assert_eq!(got.len(), 2, "{got:?}");
                assert_eq!(
                    serde_json::from_str::<Value>(&got[0]).unwrap(),
                    json!({"execute":"qmp_capabilities"})
                );
                assert_eq!(
                    serde_json::from_str::<Value>(&got[1]).unwrap(),
                    json!({"execute":"set_link","arguments":{"name":"lab0","up":up}})
                );
            }
        }

        #[test]
        fn a_qmp_error_reply_an_eof_or_a_bad_greeting_is_an_error_never_success() {
            let (sock, h) = serve("err", GREETING, |i, _| {
                Some(if i == 0 {
                    vec![r#"{"return":{}}"#.into()]
                } else {
                    vec![r#"{"error":{"class":"DeviceNotFound","desc":"no lab0"}}"#.into()]
                })
            });
            let e = qmp_set_link(&sock, false).unwrap_err();
            assert!(
                e.contains("QMP error") && e.contains("DeviceNotFound"),
                "{e}"
            );
            h.join().unwrap();

            let (sock, h) = serve("eof", GREETING, |i, _| {
                if i == 0 {
                    Some(vec![r#"{"return":{}}"#.into()])
                } else {
                    None
                }
            });
            assert_eq!(qmp_set_link(&sock, true).unwrap_err(), "QMP EOF");
            h.join().unwrap();

            let (sock, h) = serve("greet", r#"{"hello":1}"#, |_, _| Some(vec![]));
            assert_eq!(
                qmp_set_link(&sock, true).unwrap_err(),
                "invalid QMP greeting"
            );
            let _ = h.join();

            assert!(qmp_set_link("/nonexistent/qmp.sock", true).is_err());
        }
    }
    #[test]
    fn port_ranges_reject_reverse_and_zero() {
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("0").is_err());
        assert_eq!(
            parse_ports("80,443,900-902").unwrap(),
            vec![80, 443, 900, 901, 902]
        );
    }
    #[test]
    fn foreign_replies_have_valid_checksums() {
        let frames = foreign_frames(
            "02:57:4c:01:02:03",
            "52:54:00:01:02:03",
            "198.18.0.1",
            41000,
            8080,
        )
        .unwrap();
        assert_eq!(frames.len(), 4);
        for (_, f) in frames {
            assert_eq!(checksum(&f[14..34]), 0);
            let mut p = f[26..34].to_vec();
            p.extend([0, 6, 0, 20]);
            p.extend(&f[34..]);
            assert_eq!(checksum(&p), 0);
            assert_eq!(&f[18..20], &[0xf0, 0xe1]);
        }
    }
    #[test]
    fn malformed_syn_is_never_indexed() {
        for n in 0..100 {
            assert!(!is_syn(&vec![0; n], &[0; 6]));
        }
    }
    #[test]
    fn banner_ports_take_the_scenarios_of_198_18_0_2_and_refuse_the_rest() {
        let b = banner_ports("22,80").unwrap();
        assert_eq!(
            b.iter()
                .map(|(p, s)| (*p, s.port, s.peer))
                .collect::<Vec<_>>(),
            [(22, 22, 2), (80, 80, 2)]
        );
        // The macOS stand: the scenarios of 80 and 22 on ports a user may bind.
        let b = banner_ports("8080=80,2222=22").unwrap();
        assert_eq!(
            b.iter().map(|(p, s)| (*p, s.port)).collect::<Vec<_>>(),
            [(8080, 80), (2222, 22)]
        );
        assert!(banner_ports("").unwrap().is_empty());
        for bad in [
            "443",
            "8080",
            "0=80",
            "80,80",
            "80,8080=80",
            "x",
            "80=x",
            "70000",
        ] {
            assert!(banner_ports(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn a_banner_socket_answers_each_connection_with_its_scenario() {
        use std::io::{Read, Write};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        let sc = |p| banner_ports(p).unwrap()[0].1;
        let (http, ssh) = (sc("80"), sc("22"));
        let mut socks = Vec::new();
        let mut addrs = Vec::new();
        for s in [http, ssh] {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.set_nonblocking(true).unwrap();
            addrs.push(l.local_addr().unwrap());
            socks.push((l, s));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let h = thread::spawn(move || serve_banners(&socks, &move || st.load(Ordering::SeqCst)));
        let read_all = |c: &mut TcpStream| {
            let mut got = Vec::new();
            c.read_to_end(&mut got).unwrap();
            got
        };
        // HTTP: the server waits for the request, answers it, then closes after the client's FIN.
        let mut c = TcpStream::connect(addrs[0]).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        let mut head = vec![0u8; http.stream().len()];
        c.read_exact(&mut head).unwrap();
        assert_eq!(head, http.stream());
        c.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(read_all(&mut c).is_empty());
        // SSH: the server speaks first, reads the client's ident, then closes.
        let mut c = TcpStream::connect(addrs[1]).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut ident = vec![0u8; ssh.stream().len()];
        c.read_exact(&mut ident).unwrap();
        assert_eq!(ident, ssh.stream());
        c.write_all(b"SSH-2.0-OPENSSH_7.9\r\n").unwrap();
        assert!(read_all(&mut c).is_empty());
        stop.store(true, Ordering::SeqCst);
        h.join().unwrap().unwrap();
    }
}
use crate::link;
use clap::{Parser, Subcommand};
use rmasscan_engine::{Rx, SendStatus};
use rmasscan_net::lab_io;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}
fn save(path: &str, v: &Value) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
fn mac(s: &str) -> Result<[u8; 6], String> {
    let b: Vec<_> = s
        .split(':')
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<_, _>>()
        .map_err(|_| "invalid MAC")?;
    b.try_into().map_err(|_| "invalid MAC length".into())
}
fn checksum(b: &[u8]) -> u16 {
    let mut n: u32 = b
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn parse_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out = vec![];
    for t in s.split(',').filter(|s| !s.is_empty()) {
        let (lo, hi) = t.split_once('-').unwrap_or((t, t));
        let lo: u16 = lo.parse().map_err(|_| "invalid port")?;
        let hi: u16 = hi.parse().map_err(|_| "invalid port")?;
        if lo == 0 || hi < lo {
            return Err("invalid port range".into());
        }
        out.extend(lo..=hi);
    }
    Ok(out)
}
fn frame(
    src: [u8; 6],
    dst: [u8; 6],
    sip: Ipv4Addr,
    dip: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> Vec<u8> {
    let mut f = vec![0; 54];
    f[..6].copy_from_slice(&dst);
    f[6..12].copy_from_slice(&src);
    f[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    f[14] = 0x45;
    f[16..18].copy_from_slice(&40_u16.to_be_bytes());
    f[18..20].copy_from_slice(&0xf0e1_u16.to_be_bytes());
    f[22] = 64;
    f[23] = 6;
    f[26..30].copy_from_slice(&sip.octets());
    f[30..34].copy_from_slice(&dip.octets());
    f[34..36].copy_from_slice(&sport.to_be_bytes());
    f[36..38].copy_from_slice(&dport.to_be_bytes());
    f[38..42].copy_from_slice(&7_u32.to_be_bytes());
    f[42..46].copy_from_slice(&0xdeadbeef_u32.to_be_bytes());
    f[46] = 0x50;
    f[47] = 0x12;
    f[48..50].copy_from_slice(&1024_u16.to_be_bytes());
    let c = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&c.to_be_bytes());
    let mut p = f[26..34].to_vec();
    p.extend([0, 6, 0, 20]);
    p.extend(&f[34..]);
    let c = checksum(&p);
    f[50..52].copy_from_slice(&c.to_be_bytes());
    f
}
pub(crate) fn foreign_frames(
    peer: &str,
    guest: &str,
    ip: &str,
    sport: u16,
    silent: u16,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let pm = mac(peer)?;
    let gm = mac(guest)?;
    let dip: Ipv4Addr = ip.parse().map_err(|_| "invalid IPv4")?;
    let dp = sport
        .checked_add(1)
        .ok_or("source port must be below 65535")?;
    Ok([
        (
            "other_ip",
            frame(pm, gm, Ipv4Addr::new(198, 18, 0, 3), dip, 80, sport),
        ),
        (
            "unscanned_port",
            frame(pm, gm, Ipv4Addr::new(198, 18, 0, 2), dip, 9999, sport),
        ),
        (
            "wrong_cookie",
            frame(pm, gm, Ipv4Addr::new(198, 18, 0, 2), dip, silent, sport),
        ),
        (
            "wrong_dst_port",
            frame(pm, gm, Ipv4Addr::new(198, 18, 0, 2), dip, 80, dp),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v))
    .collect())
}
fn is_syn(f: &[u8], gm: &[u8; 6]) -> bool {
    if f.len() < 54 || &f[6..12] != gm || f[12..14] != [8, 0] || f[14] >> 4 != 4 || f[23] != 6 {
        return false;
    }
    let ihl = usize::from(f[14] & 15) * 4;
    if ihl < 20 {
        return false;
    }
    f.get(14 + ihl + 13).is_some_and(|b| b & 0x3f == 2)
}
fn seconds(n: f64) -> Result<Duration, String> {
    if !n.is_finite() || n < 0.0 || n > 86400.0 {
        Err("duration must be finite and within 0..86400 seconds".into())
    } else {
        Ok(Duration::from_secs_f64(n))
    }
}
fn wait_syn(rx: &mut dyn Rx, gm: &str, wait: f64) -> Result<bool, String> {
    let gm = mac(gm)?;
    let start = Instant::now();
    let wait = seconds(wait)?;
    let mut b = vec![0; 65535];
    while start.elapsed() < wait && !lab_io::stop_requested() {
        // The adapter already drops outgoing, truncated and foreign-interface frames.
        if let Some(n) = rx
            .recv(&mut b, Duration::from_millis(50))
            .map_err(|e| e.to_string())?
            && is_syn(&b[..n], &gm)
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn guard() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("peer helpers require Linux".into());
    }
    let mut names = fs::read_dir("/sys/class/net")
        .map_err(|e| e.to_string())?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    names.sort();
    if names != ["lab0", "lo"] {
        return Err(format!(
            "refusing: not in lab peer netns, interfaces = {names:?}"
        ));
    }
    Ok(())
}
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}
#[derive(Subcommand)]
enum Cmd {
    Listen {
        #[arg(long, default_value = "")]
        open: String,
        #[arg(long, default_value = "")]
        silent: String,
        /// The TCP banner cases of the Windows VM and macOS feth stands: `PORT[=SCENARIO_PORT],..`
        /// ([`banner_ports`]).
        #[arg(long, default_value = "")]
        banners: String,
        #[arg(long)]
        ready: String,
    },
    Marker {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        src: String,
        #[arg(long)]
        dst: String,
        #[arg(long, default_value = "")]
        payload: String,
    },
    Counters {
        #[arg(long)]
        iface: String,
    },
    Flood {
        #[arg(long, default_value = "lab0")]
        iface: String,
        #[arg(long)]
        guest_mac: String,
        #[arg(long, default_value_t = 10000)]
        pps: u64,
        #[arg(long, default_value_t = 60)]
        size: usize,
        #[arg(long)]
        duration: f64,
        #[arg(long)]
        out: String,
    },
    #[command(alias = "foreign")]
    Inject {
        #[arg(long)]
        iface: String,
        #[arg(long)]
        peer_mac: String,
        #[arg(long)]
        guest_mac: String,
        #[arg(long)]
        src_ip: String,
        #[arg(long)]
        sport: u16,
        #[arg(long)]
        silent: u16,
        #[arg(long)]
        out: String,
        #[arg(long, default_value_t = 60.0)]
        wait_first: f64,
        #[arg(long, default_value_t = 2.0)]
        duration: f64,
        #[arg(long, default_value_t = 0.1)]
        interval: f64,
    },
    Linkloss {
        #[arg(long, default_value = "lab0")]
        iface: String,
        #[arg(long)]
        guest_mac: String,
        #[arg(long)]
        sock: String,
        #[arg(long, default_value_t = 2.0)]
        down_after: f64,
        #[arg(long, default_value_t = 15.0)]
        hold_max: f64,
        #[arg(long, default_value_t = 120.0)]
        wait_first: f64,
        #[arg(long)]
        stop_file: String,
        #[arg(long)]
        out: String,
    },
}
/// `--banners PORT[=SCENARIO_PORT],..` of `peer listen` (the TCP banner case of the Windows VM and macOS feth stands,
/// `banners_stand`): each port answers with the scenario `banners_verify::TCP_SCENARIOS` holds for 198.18.0.2 on
/// SCENARIO_PORT (the port itself without `=`). The macOS stand needs the mapping: a non-root process cannot bind a
/// reserved port on a given address there, so its HTTP and SSH scenarios run on 8080 and 2222. A port without a
/// scenario of 198.18.0.2, a port given twice or a scenario given twice is refused.
pub(crate) fn banner_ports(
    spec: &str,
) -> Result<Vec<(u16, &'static crate::banners_verify::TcpScenario)>, String> {
    let ip = std::net::IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2));
    let mut out: Vec<(u16, &'static crate::banners_verify::TcpScenario)> = Vec::new();
    for item in spec.split(',').filter(|s| !s.is_empty()) {
        let (p, sp) = item.split_once('=').unwrap_or((item, item));
        let p: u16 = p
            .parse()
            .map_err(|_| format!("invalid banner port {item:?}"))?;
        let sp: u16 = sp
            .parse()
            .map_err(|_| format!("invalid banner scenario port {item:?}"))?;
        if p == 0 {
            return Err("invalid banner port 0".into());
        }
        let sc = crate::banners_verify::tcp_scenario(sp, ip)
            .ok_or_else(|| format!("no TCP scenario of 198.18.0.2 on port {sp}"))?;
        if out.iter().any(|(q, s)| *q == p || std::ptr::eq(*s, sc)) {
            return Err(format!("banner port or scenario given twice: {item:?}"));
        }
        out.push((p, sc));
    }
    Ok(out)
}
/// Accept on every banner socket until `stop`: each connection runs its scenario's script on its own thread
/// (`capture::run_script`, the banners window's peer), which ends with the connection.
fn serve_banners(
    socks: &[(TcpListener, &'static crate::banners_verify::TcpScenario)],
    stop: &dyn Fn() -> bool,
) -> Result<(), String> {
    while !stop() {
        for (l, sc) in socks {
            match l.accept() {
                Ok((c, _)) => {
                    let sc: &'static crate::banners_verify::TcpScenario = sc;
                    thread::spawn(move || {
                        let _ = crate::capture::run_script(c, sc);
                    });
                }
                // A connection the scanner reset before it was accepted is no failure of the listener.
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                    ) => {}
                Err(e) => return Err(format!("banner listener on {:?}: {e}", l.local_addr())),
            }
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
/// `peer listen`: TCP listeners on the peer address 198.18.0.2 (it exists only on the peer side of the lab, so
/// binding it anywhere else fails), the silent ones with a zero backlog, the banner ones ([`banner_ports`]) answering
/// each connection with their scenario. Linux (inside the peer namespace) and macOS.
fn listen(open: &str, silent: &str, banners: &str, ready: &str) -> Result<i32, String> {
    let open = parse_ports(open)?;
    let silent = parse_ports(silent)?;
    let banners = banner_ports(banners)?;
    if let Some((p, _)) = banners
        .iter()
        .find(|(p, _)| open.contains(p) || silent.contains(p))
    {
        return Err(format!(
            "port {p} is both a banner port and an --open or --silent one"
        ));
    }
    let ip = Ipv4Addr::new(198, 18, 0, 2);
    let mut sockets = vec![];
    let mut clients = vec![];
    let mut scenario_socks = vec![];
    for &p in &open {
        sockets.push(TcpListener::bind((ip, p)).map_err(|e| e.to_string())?);
    }
    for &(p, sc) in &banners {
        let l = TcpListener::bind((ip, p)).map_err(|e| format!("banner port {p}: {e}"))?;
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        scenario_socks.push((l, sc));
    }
    for &p in &silent {
        sockets.push(lab_io::silent_listener(ip, p).map_err(|e| e.to_string())?);
        clients.push(
            TcpStream::connect_timeout(&SocketAddr::from((ip, p)), Duration::from_secs(1))
                .map_err(|e| e.to_string())?,
        );
    }
    let mut proven = true;
    for &p in &silent {
        match TcpStream::connect_timeout(&SocketAddr::from((ip, p)), Duration::from_millis(500)) {
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            _ => proven = false,
        }
    }
    let mut rec = json!({"open":open,"silent":silent,"silent_proven":if silent.is_empty(){Value::Null}else{json!(proven)},"ready":proven,"bind":"198.18.0.2","pid":std::process::id()});
    if !banners.is_empty() {
        rec["banners"] = json!(
            banners
                .iter()
                .map(|(p, sc)| json!({"port": p, "scenario_port": sc.port, "peer": sc.peer, "about": sc.about, "apps": sc.apps}))
                .collect::<Vec<_>>()
        );
    }
    save(ready, &rec)?;
    if scenario_socks.is_empty() {
        while !lab_io::stop_requested() {
            thread::sleep(Duration::from_millis(100));
        }
    } else {
        serve_banners(&scenario_socks, &lab_io::stop_requested)?;
    }
    drop((sockets, clients, scenario_socks));
    Ok(0)
}

fn iface_guard(iface: &str) -> Result<(), String> {
    if iface != "lab0" {
        Err("only lab0 is permitted".into())
    } else {
        Ok(())
    }
}
#[cfg(unix)]
fn qmp_set_link(path: &str, up: bool) -> Result<Value, String> {
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::net::UnixStream,
    };
    let s = UnixStream::connect(path).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let mut r = BufReader::new(s);
    fn read(r: &mut BufReader<UnixStream>) -> Result<Value, String> {
        let mut line = String::new();
        if r.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("QMP EOF".into());
        }
        serde_json::from_str(&line).map_err(|e| e.to_string())
    }
    if read(&mut r)?.get("QMP").is_none() {
        return Err("invalid QMP greeting".into());
    }
    for cmd in [
        json!({"execute":"qmp_capabilities"}),
        json!({"execute":"set_link","arguments":{"name":"lab0","up":up}}),
    ] {
        writeln!(r.get_mut(), "{cmd}").map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if Instant::now() > deadline {
                return Err("QMP response deadline".into());
            }
            let reply = read(&mut r)?;
            if reply.get("error").is_some() {
                return Err(format!("QMP error: {reply}"));
            }
            if reply.get("return").is_some() {
                if cmd["execute"] == "set_link" {
                    return Ok(reply);
                }
                break;
            }
        }
    }
    Err("QMP missing response".into())
}
#[cfg(not(unix))]
fn qmp_set_link(_path: &str, _up: bool) -> Result<Value, String> {
    Err("QMP Unix socket requires Unix".into())
}
pub fn run(args: &[String]) -> Result<i32, String> {
    let a = Args::try_parse_from(std::iter::once("peer".into()).chain(args.iter().cloned()))
        .map_err(|e| e.to_string())?;
    #[cfg(target_os = "macos")]
    if let Cmd::Counters { iface } = &a.cmd {
        // The macOS lab has no namespace: the peer-side counters come from netstat.
        if !matches!(iface.as_str(), "feth4201" | "feth4202") {
            return Err("only the macOS lab interfaces feth4201/feth4202 are permitted".into());
        }
        if !link::safe_iface(iface) {
            return Err("invalid interface".into());
        }
        let c = crate::dump::netstat_counters(iface)?;
        println!("{} {}", c.ipkts, c.opkts);
        return Ok(0);
    }
    #[cfg(target_os = "macos")]
    if let Cmd::Listen {
        open,
        silent,
        banners,
        ready,
    } = &a.cmd
    {
        // The listeners are the one peer helper the macOS lab needs: they bind 198.18.0.2, which exists
        // only on the peer side of the stand, so they cannot serve anything anywhere else.
        let ifc = std::process::Command::new("/sbin/ifconfig")
            .arg("feth4202")
            .output()
            .map_err(|e| format!("ifconfig: {e}"))?;
        let holds = crate::macos_lab::parse_ifconfig(&String::from_utf8_lossy(&ifc.stdout))
            .inets
            .iter()
            .any(|(ip, _)| ip == "198.18.0.2");
        if !holds {
            return Err(
                "refusing to listen: 198.18.0.2 is not on feth4202 (the stand is not up)".into(),
            );
        }
        lab_io::install_signal_handlers().map_err(|e| e.to_string())?;
        return listen(open, silent, banners, ready);
    }
    guard()?;
    lab_io::install_signal_handlers().map_err(|e| e.to_string())?;
    match a.cmd {
        Cmd::Listen {
            open,
            silent,
            banners,
            ready,
        } => listen(&open, &silent, &banners, &ready),
        Cmd::Marker {
            iface,
            src,
            dst,
            payload,
        } => {
            iface_guard(&iface)?;
            let f = link::marker_frame(
                mac(&dst)?,
                mac(&src)?,
                if payload.is_empty() {
                    link::START_PAYLOAD
                } else {
                    payload.as_bytes()
                },
            );
            let mut l = link::open(&iface)?;
            for _ in 0..3 {
                link::send_blocking(&mut *l.tx, &f, link::SEND_PATIENCE, &lab_io::stop_requested)?;
                thread::sleep(Duration::from_millis(50));
            }
            Ok(0)
        }
        Cmd::Counters { iface } => {
            iface_guard(&iface)?;
            let mut vals = vec![];
            for n in ["rx_packets", "tx_packets"] {
                vals.push(
                    fs::read_to_string(format!("/sys/class/net/{iface}/statistics/{n}"))
                        .map_err(|e| e.to_string())?
                        .trim()
                        .parse::<u64>()
                        .map_err(|e| e.to_string())?,
                );
            }
            println!("{} {}", vals[0], vals[1]);
            Ok(0)
        }
        Cmd::Inject {
            iface,
            peer_mac,
            guest_mac,
            src_ip,
            sport,
            silent,
            out,
            wait_first,
            duration,
            interval,
        } => {
            iface_guard(&iface)?;
            let frames = foreign_frames(&peer_mac, &guest_mac, &src_ip, sport, silent)?;
            let duration_d = seconds(duration)?;
            let interval_d = seconds(interval)?;
            let mut l = link::open(&iface)?;
            let seen = wait_syn(&mut *l.rx, &guest_mac, wait_first)?;
            let mut counts: BTreeMap<String, u64> = frames.keys().map(|k| (k.clone(), 0)).collect();
            let mut first = None;
            let start = Instant::now();
            while seen && start.elapsed() < duration_d && !lab_io::stop_requested() {
                for (k, f) in &frames {
                    link::send_blocking(
                        &mut *l.tx,
                        f,
                        link::SEND_PATIENCE,
                        &lab_io::stop_requested,
                    )?;
                    *counts.get_mut(k).unwrap() += 1;
                    first.get_or_insert_with(now);
                }
                thread::sleep(interval_d);
            }
            save(
                &out,
                &json!({"first_syn_seen":seen,"sent_total":counts.values().sum::<u64>(),"kinds":counts,"interval_s":interval,"duration_s":duration,"ipid":0xf0e1,"first_sent_at":first}),
            )?;
            Ok(if seen { 0 } else { 3 })
        }
        Cmd::Flood {
            iface,
            guest_mac,
            pps,
            size,
            duration,
            out,
        } => {
            iface_guard(&iface)?;
            if !(22..=65535).contains(&size) {
                return Err("frame size must be 22..65535".into());
            }
            let duration = seconds(duration)?;
            let src = mac(
                fs::read_to_string(format!("/sys/class/net/{iface}/address"))
                    .map_err(|e| e.to_string())?
                    .trim(),
            )?;
            let mut f = mac(&guest_mac)?.to_vec();
            f.extend(src);
            f.extend(0x88b6_u16.to_be_bytes());
            f.extend([0; 4]);
            f.extend(b"RMSP");
            f.resize(size, 0);
            let mut l = link::open(&iface)?;
            let (mut sent, mut errors, mut blocked, mut seq) = (0_u64, 0_u64, 0_u64, 0_u32);
            let mut fatal: Option<String> = None;
            let first = now();
            let start = Instant::now();
            while start.elapsed() < duration && !lab_io::stop_requested() {
                f[14..18].copy_from_slice(&seq.to_be_bytes());
                match l.tx.send(&f, Duration::from_millis(50)) {
                    Ok(SendStatus::Sent) => {
                        sent += 1;
                        seq = seq.wrapping_add(1);
                    }
                    // Device queue full: back-pressure, not an error. The same frame is offered
                    // again, as the earlier blocking sender did.
                    Ok(SendStatus::WouldBlockUnsent) => {
                        blocked += 1;
                        continue;
                    }
                    Ok(SendStatus::Uncertain) => {
                        errors += 1;
                        seq = seq.wrapping_add(1);
                    }
                    // The adapter closes itself after a fatal error; spinning would only count
                    // failures, so stop and say why.
                    Err(e) => {
                        errors += 1;
                        fatal = Some(e.to_string());
                        break;
                    }
                }
                if pps > 0 && sent > 0 && sent % 50 == 0 {
                    let target = Duration::from_secs_f64(sent as f64 / pps as f64);
                    while target > start.elapsed()
                        && start.elapsed() < duration
                        && !lab_io::stop_requested()
                    {
                        thread::sleep(
                            target
                                .saturating_sub(start.elapsed())
                                .min(Duration::from_millis(100)),
                        );
                    }
                }
            }
            let last = now();
            save(
                &out,
                &json!({"sent":sent,"errors":errors,"t_first":first,"t_last":last,"size":size,"pps_target":pps,"pps_avg":sent as f64/(last-first).max(1e-9),"ethertype":0x88b6,"iface":iface,"dst_mac":guest_mac,"would_block":blocked,"fatal_error":fatal}),
            )?;
            Ok(if fatal.is_some() { 4 } else { 0 })
        }
        Cmd::Linkloss {
            iface,
            guest_mac,
            sock,
            down_after,
            hold_max,
            wait_first,
            stop_file,
            out,
        } => {
            iface_guard(&iface)?;
            let down_after = seconds(down_after)?;
            let hold = seconds(hold_max)?;
            let mut l = link::open(&iface)?;
            let seen = wait_syn(&mut *l.rx, &guest_mac, wait_first)?;
            let mut events = vec![];
            let mut failure = None;
            if seen {
                let wait = Instant::now();
                while wait.elapsed() < down_after && !lab_io::stop_requested() {
                    thread::sleep(Duration::from_millis(50));
                }
                if !lab_io::stop_requested() {
                    match qmp_set_link(&sock, false) {
                        Ok(r) => events.push(json!({"t":now(),"set_link":"down","reply":r})),
                        Err(e) => failure = Some(e),
                    }
                    let start = Instant::now();
                    while failure.is_none()
                        && start.elapsed() < hold
                        && !Path::new(&stop_file).exists()
                        && !lab_io::stop_requested()
                    {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
                match qmp_set_link(&sock, true) {
                    Ok(r) => events.push(json!({"t":now(),"set_link":"up","reply":r})),
                    Err(e) => {
                        events.push(json!({"t":now(),"set_link":"up","error":e}));
                        failure = Some(e);
                    }
                }
            }
            save(
                &out,
                &json!({"events":events,"first_syn_seen":seen,"error":failure}),
            )?;
            if let Some(e) = failure {
                return Err(e);
            }
            Ok(if seen { 0 } else { 3 })
        }
    }
}
