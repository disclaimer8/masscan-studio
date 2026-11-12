//! Sealed Linux capture support and portable evidence manifests.
use crate::link;
use rmasscan_net::lab_io;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

pub fn classify(frames: &[(f64, Vec<u8>)], scanner: [u8; 6], peer: [u8; 6]) -> Value {
    let mut result = json!({"syn_from_scanner":0,"synack_from_peer":0,"rst_from_peer":0,"rst_from_scanner":0,"marker":0,"other":0});
    for (_, f) in frames {
        let ihl = f.get(14).map_or(0, |x| usize::from(x & 15) * 4);
        let tcp = f.len() >= 54
            && f[12..14] == [8, 0]
            && f[14] >> 4 == 4
            && ihl >= 20
            && f[23] == 6
            && f.len() >= 14 + ihl + 20;
        let flags = if tcp { f[14 + ihl + 13] & 0x3f } else { 0 };
        let src = f.get(6..12).unwrap_or_default();
        let key = if tcp && src == scanner && flags == 2 {
            "syn_from_scanner"
        } else if tcp && src == peer && flags == 0x12 {
            "synack_from_peer"
        } else if tcp && src == peer && flags & 4 != 0 {
            "rst_from_peer"
        } else if tcp && src == scanner && flags & 4 != 0 {
            "rst_from_scanner"
        } else if f.get(12..14) == Some(&[0x88, 0xb5]) {
            "marker"
        } else {
            "other"
        };
        result[key] = json!(result[key].as_u64().unwrap_or(0) + 1);
    }
    result
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}
fn read_json(path: impl AsRef<Path>) -> Result<Value, String> {
    serde_json::from_slice(&fs::read(path).map_err(err)?).map_err(err)
}
fn write_json(path: impl AsRef<Path>, v: &Value) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(v).map_err(err)?;
    bytes.push(b'\n');
    fs::write(path, bytes).map_err(err)
}
fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn sha(path: impl AsRef<Path>) -> Result<String, String> {
    Ok(hex_digest(&fs::read(path).map_err(err)?))
}
fn mac(s: &str) -> Result<[u8; 6], String> {
    let v = s
        .split(':')
        .map(|x| u8::from_str_radix(x, 16).map_err(err))
        .collect::<Result<Vec<_>, _>>()?;
    v.try_into().map_err(|_| "MAC needs six octets".into())
}
fn command(argv: &[&str]) -> String {
    match Command::new(argv[0]).args(&argv[1..]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        Ok(o) => format!("unavailable: {}", String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => format!("unavailable: {e}"),
    }
}

fn opts(args: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        if !k.starts_with("--") {
            return Err(format!("unexpected {k}"));
        }
        let v = it.next().ok_or_else(|| format!("missing {k}"))?;
        if out.insert(k[2..].to_string(), v.clone()).is_some() {
            return Err(format!("duplicate {k}"));
        }
    }
    Ok(out)
}
fn get<'a>(a: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str, String> {
    a.get(k)
        .map(String::as_str)
        .ok_or_else(|| format!("--{k} required"))
}

fn marker(a: &BTreeMap<String, String>) -> Result<i32, String> {
    let payload = a
        .get("payload")
        .map_or(link::START_PAYLOAD, |p| p.as_bytes());
    let f = link::marker_frame(mac(get(a, "dst")?)?, mac(get(a, "src")?)?, payload);
    let mut l = link::open(get(a, "iface")?)?;
    for _ in 0..3 {
        link::send_blocking(&mut *l.tx, &f, link::SEND_PATIENCE, &lab_io::stop_requested)?;
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(0)
}
fn port_list(ports: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for p in ports.split(',').filter(|s| !s.is_empty()) {
        let p = p.parse::<u16>().map_err(err)?;
        if p == 0 {
            return Err("port zero".into());
        }
        out.push(p);
    }
    Ok(out)
}
/// The peer's listeners: the TCP ports (`--ports`; the kernel answers SYN-ACK there and resets every other port) and,
/// for the protocols stand, UDP and SCTP:
/// - `--udp-ports P,.. --udp-ips A,..`: one UDP socket per address and port (a reply leaves from the address the
///   datagram went to), each datagram answered once with `protocols_verify::UDP_REPLY`; the kernel sends ICMP 3/3
///   for every other port;
/// - `--sctp-iface IF --sctp-open P,..`: every SCTP INIT on the link `IF` answered on the link with
///   `protocols_verify::sctp_reply` (INIT-ACK on the open ports, ABORT elsewhere). The host kernel must have no SCTP
///   (the suite checks it): no SCTP socket is ever opened here, so no module is loaded either;
/// - `--tcp6-ips A,..` (the IPv6 stand): the `--ports` listeners again on each of these IPv6 addresses.
///
/// Each UDP socket and the SCTP link has its own thread, so a reply leaves within the probe's own interval.
fn responder(a: &BTreeMap<String, String>) -> Result<i32, String> {
    lab_io::install_signal_handlers().map_err(err)?;
    let ports = get(a, "ports")?;
    let mut listeners = Vec::new();
    for p in port_list(ports)? {
        listeners
            .push(std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, p)).map_err(err)?);
    }
    // The IPv6 stand (`wire-lab.sh --suite ipv6`): the same ports on each peer IPv6 address. A listener per address
    // never claims IPv4 (only `::` does, with `bindv6only` 0), and an address that is still tentative cannot be
    // bound, so the responder never says ready on a stand whose addresses are not usable yet.
    if let Some(ips) = a.get("tcp6-ips") {
        for ip in ips.split(',') {
            let ip: std::net::Ipv6Addr = ip.parse().map_err(err)?;
            for p in port_list(ports)? {
                listeners.push(std::net::TcpListener::bind((ip, p)).map_err(err)?);
            }
        }
    }
    // Every answerer polls `halt` beside the stop request: one that fails stops the others (see `supervise`).
    let halt = std::sync::Arc::new(AtomicBool::new(false));
    let mut workers: Vec<Worker> = Vec::new();
    let mut said = format!("listening {ports}");
    if let Some(ips) = a.get("tcp6-ips") {
        said.push_str(&format!(" tcp6 {ips}"));
    }
    if let Some(udp) = a.get("udp-ports") {
        for ip in get(a, "udp-ips")?.split(',') {
            let ip: std::net::Ipv4Addr = ip.parse().map_err(err)?;
            for p in port_list(udp)? {
                let s = std::net::UdpSocket::bind((ip, p)).map_err(err)?;
                s.set_read_timeout(Some(Duration::from_millis(100)))
                    .map_err(err)?;
                let h = halt.clone();
                workers.push(std::thread::spawn(move || udp_answers(&s, &h)));
            }
        }
        said.push_str(&format!(" udp {udp}"));
    }
    if let Some(iface) = a.get("sctp-iface") {
        let open = port_list(get(a, "sctp-open")?)?;
        let mac = link::iface_mac(iface)?;
        let l = link::open(iface)?;
        let h = halt.clone();
        workers.push(std::thread::spawn(move || sctp_answers(l, mac, &open, &h)));
        said.push_str(&format!(" sctp {iface} open {}", get(a, "sctp-open")?));
    }
    fs::write(get(a, "ready")?, format!("{said}\n")).map_err(err)?;
    let done = supervise(
        workers,
        &halt,
        &lab_io::stop_requested,
        Duration::from_millis(100),
    );
    drop(listeners);
    done.map(|()| 0)
}
type Worker = std::thread::JoinHandle<Result<(), String>>;
/// The responder's answerers until the stop request. One that ends before it has failed: `halt` is set at once, so
/// every other answerer ends at its next poll (100 ms), and the responder ends with the first failure, which `main`
/// prints to its stderr (`responder.err.txt`) with exit 2, instead of waiting for SIGTERM. Without answerers (no
/// `--udp-ports`, no `--sctp-iface`) this is the plain wait for the stop request of the TCP-only responder.
fn supervise(
    workers: Vec<Worker>,
    halt: &AtomicBool,
    stop: &dyn Fn() -> bool,
    tick: Duration,
) -> Result<(), String> {
    while !stop() && !workers.iter().any(|w| w.is_finished()) {
        std::thread::sleep(tick);
    }
    let early = !stop();
    halt.store(true, Ordering::SeqCst);
    // The answerers that already ended first: theirs is the error that stopped the responder.
    let (ended, running): (Vec<Worker>, Vec<Worker>) =
        workers.into_iter().partition(|w| w.is_finished());
    let mut failure = None;
    for w in ended.into_iter().chain(running) {
        if let Err(e) = w
            .join()
            .unwrap_or_else(|_| Err("a responder thread panicked".into()))
        {
            failure.get_or_insert(e);
        }
    }
    match failure {
        Some(e) => Err(e),
        None if early => Err("a responder answerer ended before the stop request".into()),
        None => Ok(()),
    }
}
/// Answer every datagram on `s` once with the stand's reply, until the stop request or `halt`.
fn udp_answers(s: &std::net::UdpSocket, halt: &AtomicBool) -> Result<(), String> {
    let mut buf = [0u8; 2048];
    while !lab_io::stop_requested() && !halt.load(Ordering::SeqCst) {
        match s.recv_from(&mut buf) {
            Ok((_, from)) => {
                s.send_to(crate::protocols_verify::UDP_REPLY, from)
                    .map_err(err)?;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            // The scanner host's kernel answers a reply with ICMP 3/3; Linux may hand that to the socket as an error.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            Err(e) => return Err(format!("udp responder: {e}")),
        }
    }
    Ok(())
}
/// Answer every SCTP INIT on the link with `protocols_verify::sctp_reply`, until the stop request or `halt`.
fn sctp_answers(
    mut l: link::Link,
    mac: [u8; 6],
    open: &[u16],
    halt: &AtomicBool,
) -> Result<(), String> {
    let mut buf = vec![0u8; 65536];
    let stopped = || lab_io::stop_requested() || halt.load(Ordering::SeqCst);
    while !stopped() {
        let n =
            l.rx.recv(&mut buf, Duration::from_millis(100))
                .map_err(|e| format!("sctp responder: {e:?}"))?;
        if let Some(reply) =
            n.and_then(|n| crate::protocols_verify::sctp_reply(&buf[..n], mac, open))
        {
            link::send_blocking(&mut *l.tx, &reply, link::SEND_PATIENCE, &stopped)?;
        }
    }
    Ok(())
}
/// Hashes of the harness that is actually executing (L M4): the running binary, and the exact
/// scripts the caller names (wire-lab.sh passes its own path and the helper it sourced, never a
/// compile-time path). A named script that cannot be read is an error, not a silent omission.
/// With `--deploy-manifest` the running binary must be one the manifest vouches for, which
/// binds the run to the commit the manifest records.
fn harness_record(a: &BTreeMap<String, String>) -> Result<Value, String> {
    let exe = std::env::current_exe().map_err(err)?;
    let exe_sha = sha(&exe)?;
    let mut harness = json!({"rmasscan-lab":exe_sha,"wire-lab.sh":sha(get(a, "wire-lab-sh")?)?,"lab-process-group.sh":sha(get(a, "process-group-sh")?)?});
    if let Ok(path) = get(a, "deploy-manifest") {
        let m = read_json(path)?;
        let vouched: Vec<String> = m["binaries"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|b| b["sha256"].as_str().map(str::to_owned))
            .collect();
        if m["kind"] != crate::deploy::MANIFEST_KIND || !vouched.contains(&exe_sha) {
            return Err("the running rmasscan-lab is not in the deploy manifest".into());
        }
        harness["deploy"] = json!({"manifest_sha256":sha(path)?,"commit":m["commit"]});
    }
    Ok(harness)
}
fn environment(a: &BTreeMap<String, String>) -> Result<i32, String> {
    let oracle = get(a, "oracle")?;
    let src = Path::new(oracle)
        .parent()
        .and_then(Path::parent)
        .and_then(Path::to_str)
        .ok_or("oracle path needs source parent")?;
    let conf = Path::new("/etc/masscan/masscan.conf");
    let mut ci =
        json!({"path":conf,"exists":conf.exists(),"masked_in_lab":get(a,"conf-masked")?=="1"});
    if conf.exists() {
        ci["sha256"] = json!(sha(conf)?);
        ci["size"] = json!(fs::metadata(conf).map_err(err)?.len());
    }
    let harness = harness_record(a)?;
    let os = fs::read_to_string("/etc/os-release").unwrap_or_default();
    let pretty = os
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .unwrap_or("")
        .trim_matches('"');
    let env = json!({"oracle":{"path":oracle,"sha256":sha(oracle)?,"git_commit":command(&["git","-C",src,"rev-parse","HEAD"]),"git_tree_clean":command(&["git","-C",src,"status","--porcelain","--untracked-files=all"]).is_empty(),"variant":"original pinned binary (NOT the --offline-patched copy)","version_line":command(&[oracle,"--version"])},"harness":harness,"host":{"os_pretty":pretty,"kernel":command(&["uname","-r"]),"arch":std::env::consts::ARCH,"tool":"rmasscan-lab Rust","iproute2":command(&["ip","-V"])},"masscan_conf":ci,"namespaces":{"scanner":get(a,"ns-a")?,"peer":get(a,"ns-b")?},"binding":{"scanner_iface":get(a,"iface-a")?,"peer_iface":get(a,"iface-b")?,"adapter_mac":get(a,"mac-a")?,"router_mac":get(a,"mac-b")?,"adapter_ip":get(a,"ip-a")?,"peer_ips":get(a,"peer-ips")?,"seed":get(a,"seed")?,"rate":get(a,"rate")?,"blackrock_rounds":14,"retries":0,"wait":3,"responder_open_ports":get(a,"open-ports")?},"created_utc":command(&["date","-u","+%Y-%m-%dT%H:%M:%SZ"])});
    write_json(get(a, "out")?, &env)?;
    Ok(0)
}
fn manifest(a: &BTreeMap<String, String>) -> Result<i32, String> {
    let d = Path::new(get(a, "dir")?);
    let env = read_json(d.join("env.json"))?;
    let b = &env["binding"];
    let ma = mac(b["adapter_mac"].as_str().ok_or("missing adapter MAC")?)?;
    let mb = mac(b["router_mac"].as_str().ok_or("missing router MAC")?)?;
    let mut cases = Vec::new();
    let mut all_valid = true;
    for row in fs::read_to_string(d.join("cases.tsv"))
        .map_err(err)?
        .lines()
        .filter(|r| !r.is_empty())
    {
        let fields = row.splitn(5, '\t').collect::<Vec<_>>();
        if fields.len() != 5 {
            return Err("bad cases.tsv".into());
        }
        let name = fields[0];
        if name.contains('/') || name.contains('\\') || name == ".." {
            return Err("invalid case name".into());
        }
        let exp = fields[1..4]
            .iter()
            .map(|s| s.parse::<u64>().map_err(err))
            .collect::<Result<Vec<_>, _>>()?;
        let mut runs = Vec::new();
        let mut bytes = Vec::new();
        let mut metas = Vec::new();
        for r in 1..=2 {
            let pcap = format!("{name}.run{r}.pcap");
            let meta = read_json(d.join(format!("{name}.run{r}.capture.json")))?;
            let raw = fs::read(d.join(&pcap)).map_err(err)?;
            let (_, frames) = crate::pcap::read_pcap_records(&raw)?;
            let counts = classify(&frames, ma, mb);
            let matches = counts["syn_from_scanner"] == exp[0]
                && counts["synack_from_peer"] == exp[1]
                && counts["rst_from_peer"] == exp[2];
            let valid = meta["valid"] == true && matches;
            all_valid &= valid;
            runs.push(json!({"pcap":pcap,"pcap_sha256":hex_digest(&raw),"pcap_bytes":raw.len(),"capture":meta,"observed":counts,"counts_match_expected":matches,"valid":valid}));
            bytes.push(raw);
            metas.push(meta);
        }
        let (code, msg) =
            crate::pcap::compare_bytes(&bytes[0], &[&bytes[1]], Some(&metas[0]), &metas[1..]);
        all_valid &= code == 0;
        let echo = format!("{name}.echo");
        cases.push(json!({"name":name,"masscan_args":fields[4].split_whitespace().collect::<Vec<_>>(),"effective_echo_file":echo,"effective_echo_sha256":sha(d.join(&echo))?,"expected":{"syn":exp[0],"synack":exp[1],"rst":exp[2]},"fixture_pcap":runs[0]["pcap"],"runs":runs,"repeat_compare":{"result":(["PASS","FAIL","INVALID"][code as usize]),"detail":msg}}));
    }
    let mut m = env.clone();
    m["schema"] = json!("rmasscan-wire-manifest/1");
    m["purpose"] = json!(
        "Independent pinned C oracle SYN bytes on isolated veth; Rust engine must match byte for byte."
    );
    m["isolation"] = read_json(d.join("isolation.json"))?;
    m["commands"] = json!(
        fs::read_to_string(d.join("commands.txt"))
            .map_err(err)?
            .lines()
            .collect::<Vec<_>>()
    );
    m["comparison_rule"] = json!(
        "rmasscan-lab verify-wire: byte exact ordered SYN stream; incomplete capture is INVALID"
    );
    m["all_valid"] = json!(all_valid && !cases.is_empty());
    m["cases"] = json!(cases);
    scrub(&mut m);
    write_json(d.join("manifest.json"), &m)?;
    println!("manifest: all_valid={}", m["all_valid"]);
    Ok(if m["all_valid"] == true { 0 } else { 3 })
}
/// Remove personal paths and run-specific namespace names from published JSON, in values and in
/// object keys (the semantics of the regexes
/// `/(?:home|Users)/[^/\s"']+|/root(?=/)` -> `$HOME` and `wl-(scan|peer)-[0-9]+-[0-9]+` ->
/// `wl-\1-RUNID`). Hashes and every other value are left untouched.
pub fn scrub(v: &mut Value) {
    match v {
        Value::String(s) => *s = scrub_str(s),
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => {
            let old = std::mem::take(m);
            for (k, mut val) in old {
                scrub(&mut val);
                m.insert(scrub_str(&k), val);
            }
        }
        _ => {}
    }
}
/// [`scrub`] of one string (a log line, an error message).
pub(crate) fn scrub_str(s: &str) -> String {
    let home = scrub_home(s);
    scrub_namespaces(&home)
}
fn scrub_home(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        if let Some(tail) = rest
            .strip_prefix("/home/")
            .or_else(|| rest.strip_prefix("/Users/"))
        {
            // At least one character that is not '/', whitespace or a quote.
            let user = tail
                .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(tail.len());
            if user > 0 {
                out.push_str("$HOME");
                i += rest.len() - tail.len() + user;
                continue;
            }
        }
        if rest.starts_with("/root/") {
            out.push_str("$HOME");
            i += "/root".len();
            continue;
        }
        let ch = rest.chars().next().unwrap_or_default();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}
fn scrub_namespaces(s: &str) -> String {
    let digits = |t: &str| t.bytes().take_while(u8::is_ascii_digit).count();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        for kind in ["scan", "peer"] {
            let Some(tail) = rest.strip_prefix(&format!("wl-{kind}-")) else {
                continue;
            };
            let a = digits(tail);
            if a == 0 || tail.as_bytes().get(a) != Some(&b'-') {
                continue;
            }
            let b = digits(&tail[a + 1..]);
            if b == 0 {
                continue;
            }
            out.push_str(&format!("wl-{kind}-RUNID"));
            i += rest.len() - tail.len() + a + 1 + b;
            // resume scanning after the match
            return scrub_namespaces_tail(out, &s[i..]);
        }
        let ch = rest.chars().next().unwrap_or_default();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}
fn scrub_namespaces_tail(mut head: String, tail: &str) -> String {
    head.push_str(&scrub_namespaces(tail));
    head
}
/// What an autodetect suite rewrites in everything it writes to evidence, on top of [`scrub`]: its own `--out` (to
/// `$OUT`) and private work directory (to `$WORK`), by their paths as given, made absolute and resolved, and the
/// account that started it (to `$USER`, see [`account`]): a bare name, and the dash-joined forms `-Users-NAME`,
/// `-home-NAME` a tool makes of a path. One helper for the Linux, macOS and Windows suites.
#[derive(Clone, Debug, Default)]
pub(crate) struct Scrubber {
    /// (path, placeholder), the longest path first.
    prefixes: Vec<(String, &'static str)>,
    account: Option<String>,
}
/// A character of a path component or a name: a path or a name ends at any other.
fn name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}
impl Scrubber {
    pub(crate) fn new(out: &Path, work: Option<&Path>, account: Option<&str>) -> Self {
        let mut prefixes: Vec<(String, &'static str)> = Vec::new();
        for (p, placeholder) in std::iter::once((out, "$OUT")).chain(work.map(|w| (w, "$WORK"))) {
            let raw = p.to_string_lossy().into_owned();
            // A relative form only with a separator in it: a bare `out` would also be a word of a message.
            let forms = [
                raw.contains(['/', '\\']).then_some(raw),
                std::path::absolute(p)
                    .ok()
                    .map(|a| a.to_string_lossy().into_owned()),
                fs::canonicalize(p)
                    .ok()
                    .map(|a| a.to_string_lossy().into_owned()),
            ];
            for f in forms.into_iter().flatten() {
                let f = f.trim_end_matches(['/', '\\']).to_owned();
                if f.len() > 1 && !prefixes.iter().any(|(q, _)| *q == f) {
                    prefixes.push((f, placeholder));
                }
            }
        }
        prefixes.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        Scrubber {
            prefixes,
            account: account.map(str::to_owned),
        }
    }
    /// One string (a record's value or key, a log line).
    pub(crate) fn str(&self, s: &str) -> String {
        let mut t = s.to_owned();
        for (p, placeholder) in &self.prefixes {
            // A path, not the start of a longer name (`--out` `/x/out` is not `/x/out.bak` or `/x/outer`).
            t = replace_bounded(&t, p, placeholder, |head, after| {
                !head.chars().next_back().is_some_and(name_char) && !after.is_some_and(name_char)
            });
        }
        if let Some(a) = &self.account {
            // The name as a word (`alice`, `\Users\alice`, `alice.local`, `alice@host`; not `malice`, `alice_x`,
            // `alice-mbp`, `--alice`), or as the tail of a dash-joined path (`-Users-alice/`, `-Users-alice-repo`). A `:`
            // joins a word too: a short name that is hex (`a1`) never rewrites a byte of a MAC or IPv6 address.
            let word = |c: Option<char>| {
                c.is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':'))
            };
            t = replace_bounded(&t, a, "$USER", |head, after| {
                let dashed = head.ends_with("-Users-") || head.ends_with("-home-");
                (!word(head.chars().next_back()) && !word(after))
                    || (dashed && !after.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_'))
            });
        }
        scrub_str(&t)
    }
    /// Every string of a record, keys included.
    pub(crate) fn value(&self, v: &mut Value) {
        match v {
            Value::String(s) => *s = self.str(s),
            Value::Array(a) => a.iter_mut().for_each(|x| self.value(x)),
            Value::Object(m) => {
                let old = std::mem::take(m);
                for (k, mut val) in old {
                    self.value(&mut val);
                    m.insert(self.str(&k), val);
                }
            }
            _ => {}
        }
    }
    /// A text record another tool wrote into the run (`macos-lab status`), rewritten in place when it changes. A
    /// file that is not UTF-8 is left as it is (the verifier still scans it).
    #[cfg(any(target_os = "macos", test))]
    pub(crate) fn file(&self, path: &Path) -> Result<(), String> {
        let b = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let Ok(text) = String::from_utf8(b) else {
            return Ok(());
        };
        let s = self.str(&text);
        if s != text {
            fs::write(path, s).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        Ok(())
    }
}
/// `s` with every occurrence of `needle` that `bounded(text before it, char after it)` accepts replaced by `with`.
fn replace_bounded(
    s: &str,
    needle: &str,
    with: &str,
    bounded: impl Fn(&str, Option<char>) -> bool,
) -> String {
    if needle.is_empty() {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for (i, _) in s.match_indices(needle) {
        let end = i + needle.len();
        if bounded(&s[..i], s[end..].chars().next()) {
            out.push_str(&s[last..i]);
            out.push_str(with);
            last = end;
        }
    }
    out.push_str(&s[last..]);
    out
}
/// The account a suite was started by, which its evidence never names: `$SUDO_USER` when it is set and not root,
/// else `$USER`. Root names no one (it is the lab's own account, and a word of the stand's texts: "root verified"),
/// so it is never rewritten.
pub(crate) fn account(sudo_user: Option<&str>, user: Option<&str>) -> Option<String> {
    let named = |u: Option<&str>| {
        u.map(str::trim)
            .filter(|u| !u.is_empty() && *u != "root")
            .map(str::to_owned)
    };
    named(sudo_user).or_else(|| named(user))
}
/// [`account`] of this process's environment.
pub(crate) fn account_from_env() -> Option<String> {
    account(
        std::env::var("SUDO_USER").ok().as_deref(),
        std::env::var("USER").ok().as_deref(),
    )
}
fn isolation(a: &BTreeMap<String, String>) -> Result<i32, String> {
    fn checked(args: &[&str]) -> Result<String, String> {
        let o = Command::new(args[0])
            .args(&args[1..])
            .output()
            .map_err(err)?;
        if !o.status.success() {
            return Err(format!(
                "isolation query failed: {args:?}: {}",
                String::from_utf8_lossy(&o.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    }
    let (autodetect, scan_control, ipv6) = match a.get("mode").map(String::as_str) {
        None | Some("default") => (false, false, false),
        Some("autodetect") => (true, false, false),
        // The scan-control stand: the autodetect stand plus one more veth pair (`SECOND_*`), in the same namespaces.
        Some("scan-control") => (true, true, false),
        // The IPv6 stand: the autodetect stand with IPv6 raised on the lab veth pair only (`check_ipv6_side`).
        Some("ipv6") => (true, false, true),
        Some(other) => return Err(format!("unknown isolation mode {other}")),
    };
    let mut ipv6_sides = serde_json::Map::new();
    let before = fs::read_to_string(get(a, "host-links-before")?).map_err(err)?;
    let now_links = checked(&["ip", "-o", "link"])?;
    let mut names = now_links
        .lines()
        .filter_map(|l| l.split(": ").nth(1))
        .collect::<Vec<_>>();
    names.sort();
    if before.trim() != names.join("\n") {
        return Err("host link list changed or baseline does not match".into());
    }
    let mut v = json!({"uplink":false,"bridge":false,"nat":false,"default_route":false,"ip_forward":0,"ipv6":"disabled","veth_created_inside_scanner_ns_peer_moved_to_peer_ns":true,"host_link_list_unchanged":true,"verified_by":"Rust capture isolation: live namespace links, routes, forwarding, IPv6 and host link baseline; plus wire-lab lifecycle assertions"});
    let mut endpoints = Vec::new();
    let mut second_links: Vec<Value> = Vec::new();
    for (k, opt) in [("scanner", "ns-a"), ("peer", "ns-b")] {
        let ns = get(a, opt)?;
        let mode = if autodetect {
            IsolationMode::Autodetect
        } else {
            IsolationMode::Default
        };
        let side = if k == "scanner" {
            Side::Scanner
        } else {
            Side::Peer
        };
        let links: Value =
            serde_json::from_str(&checked(&["ip", "-n", ns, "-d", "-j", "link"])?).map_err(err)?;
        let routes: Value =
            serde_json::from_str(&checked(&["ip", "-n", ns, "-j", "route", "show"])?)
                .map_err(err)?;
        let forwarding = checked(&[
            "ip",
            "netns",
            "exec",
            ns,
            "cat",
            "/proc/sys/net/ipv4/ip_forward",
        ])?;
        let (links, routes, second) = if scan_control {
            let (l, r, sec) = split_second_link(&links, &routes, side)?;
            (l, r, Some(sec))
        } else {
            (links, routes, None)
        };
        check_isolation_snapshot(&links, &routes, &forwarding, mode, side)?;
        let endpoint = links
            .as_array()
            .and_then(|ls| ls.iter().find(|x| x["ifname"] != "lo"))
            .ok_or("veth missing")?;
        if let Some(sec) = second {
            let sec_if = sec["ifname"].as_str().ok_or("second link name missing")?;
            if checked(&[
                "ip",
                "netns",
                "exec",
                ns,
                "cat",
                &format!("/proc/sys/net/ipv6/conf/{sec_if}/disable_ipv6"),
            ])? != "1"
            {
                return Err("IPv6 not disabled on the second lab veth".into());
            }
            second_links.push(sec);
        }
        let iface = endpoint["ifname"]
            .as_str()
            .ok_or("interface name missing")?;
        if iface.contains('/') {
            return Err("invalid namespace interface".into());
        }
        if ipv6 {
            // IPv6 on the lab veth with the stand's settings, addresses, routes and neighbours, nothing else.
            let files: Vec<String> = IPV6_SYSCTLS
                .iter()
                .map(|(k, _)| format!("/proc/sys/net/ipv6/conf/{iface}/{k}"))
                .collect();
            let mut cat = vec!["ip", "netns", "exec", ns, "cat"];
            cat.extend(files.iter().map(String::as_str));
            let values = checked(&cat)?;
            let sysctls: Vec<(String, String)> = IPV6_SYSCTLS
                .iter()
                .zip(values.lines().chain(std::iter::repeat("")))
                .map(|((k, _), v)| ((*k).to_owned(), v.trim().to_owned()))
                .collect();
            let json6 = |args: &[&str]| -> Result<Value, String> {
                let mut full = vec!["ip", "-n", ns, "-6", "-j"];
                full.extend(args);
                serde_json::from_str(&checked(&full)?).map_err(err)
            };
            let route_get6 = Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    ns,
                    "ip",
                    "-6",
                    "route",
                    "get",
                    IPV6_ROUTE_PROBE,
                ])
                .output()
                .map_err(err)?;
            let got = route_get6.status.success().then(|| {
                String::from_utf8_lossy(&route_get6.stdout)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            });
            let rec = check_ipv6_side(
                side,
                iface,
                &Ipv6Snapshot {
                    addrs: json6(&["addr", "show", "dev", iface])?,
                    routes: json6(&["route", "show"])?,
                    neigh: json6(&["neigh", "show"])?,
                    sysctls,
                    route_get: got,
                },
            )?;
            ipv6_sides.insert(k.to_owned(), rec);
        } else {
            if checked(&[
                "ip",
                "netns",
                "exec",
                ns,
                "cat",
                &format!("/proc/sys/net/ipv6/conf/{iface}/disable_ipv6"),
            ])? != "1"
            {
                return Err("IPv6 not disabled on lab veth".into());
            }
            if !checked(&["ip", "-n", ns, "-6", "route", "show", "default"])?.is_empty() {
                return Err("IPv6 default route in lab".into());
            }
        }
        let route_get = Command::new("ip")
            .args(["netns", "exec", ns, "ip", "route", "get", "8.8.8.8"])
            .output()
            .map_err(err)?;
        if mode == IsolationMode::Autodetect && side == Side::Scanner {
            if !route_get.status.success() {
                return Err("scanner namespace has no route to 8.8.8.8 via the peer".into());
            }
            let out = String::from_utf8_lossy(&route_get.stdout);
            check_route_get(&out, iface)?;
            // The IPv6 stand's IPv6 neighbours are judged by `check_ipv6_side`; here the IPv4 ones only.
            let neigh = if ipv6 {
                checked(&["ip", "-n", ns, "-4", "-j", "neigh", "show"])?
            } else {
                checked(&["ip", "-n", ns, "-j", "neigh", "show"])?
            };
            check_isolation_neighbours(&serde_json::from_str(&neigh).map_err(err)?, iface)?;
            v[format!("{k}_route_get_8_8_8_8")] = json!(out.lines().next().unwrap_or_default());
        } else {
            if route_get.status.success() {
                return Err("lab has route to external IP".into());
            }
            v[format!("{k}_route_get_8_8_8_8")] =
                json!(String::from_utf8_lossy(&route_get.stderr).trim());
        }
        v[format!("{k}_routes")] = json!(
            checked(&["ip", "-n", ns, "route", "show"])?
                .lines()
                .collect::<Vec<_>>()
        );
        v[format!("{k}_links")] = json!(
            checked(&["ip", "-n", ns, "-o", "link"])?
                .lines()
                .collect::<Vec<_>>()
        );
        endpoints.push(endpoint.clone());
    }
    for (left, right) in [(0, 1), (1, 0)] {
        let e = &endpoints[left];
        let p = &endpoints[right];
        if e["link_index"].as_u64().is_none() || e["link_index"] != p["ifindex"] {
            return Err("namespace veth endpoints are not paired".into());
        }
    }
    if scan_control {
        for (left, right) in [(0, 1), (1, 0)] {
            let (e, p) = (&second_links[left], &second_links[right]);
            if e["link_index"].as_u64().is_none() || e["link_index"] != p["ifindex"] {
                return Err("second namespace veth endpoints are not paired".into());
            }
        }
        v["second_link"] = json!({"scanner": SECOND_SCANNER_IF, "peer": SECOND_PEER_IF, "adapter_ip": SECOND_ADAPTER_IP});
    }
    if ipv6 {
        v["ipv6"] = json!({"lab_veth_only": true, "prefix": IPV6_PREFIX, "scanner": ipv6_sides["scanner"],
            "peer": ipv6_sides["peer"]});
    }
    if autodetect {
        v["mode"] = json!(if scan_control {
            "scan-control"
        } else if ipv6 {
            "ipv6"
        } else {
            "autodetect"
        });
        v["default_route"] = isolation_default_route(
            IsolationMode::Autodetect,
            endpoints[0]["ifname"].as_str().ok_or("veth missing")?,
        );
    }
    write_json(get(a, "out")?, &v)?;
    Ok(0)
}

/// Which namespace of the lab pair a snapshot describes (autodetect mode only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Scanner,
    Peer,
}

/// Sealed-lab mode of `capture isolation`. `Default` is the original sealed lab (no default route
/// anywhere). `Autodetect` is the stand for the scanner's auto-detection: the scanner namespace has
/// exactly the connected route and a default route via the peer, plus permanent neighbours.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IsolationMode {
    Default,
    Autodetect,
}

const AUTODETECT_NET: &str = "198.18.0.0/24";
const AUTODETECT_GATEWAY: &str = "198.18.0.2";
const AUTODETECT_NEIGHBOURS: [&str; 4] = ["198.18.0.2", "198.18.0.3", "198.18.0.4", "198.18.0.5"];

fn autodetect_via(iface: &str) -> String {
    format!("via {AUTODETECT_GATEWAY} dev {iface}")
}

/// The `default_route` field of isolation.json, recorded as it is.
pub fn isolation_default_route(mode: IsolationMode, scanner_iface: &str) -> Value {
    match mode {
        IsolationMode::Default => json!(false),
        IsolationMode::Autodetect => {
            json!({"scanner_ns": autodetect_via(scanner_iface), "peer_ns": false})
        }
    }
}

/// Whether a recorded isolation.json document permits a run in `mode`.
pub fn isolation_permits(v: &Value, mode: IsolationMode) -> bool {
    let default_ok = match mode {
        IsolationMode::Default => v["default_route"] == false,
        IsolationMode::Autodetect => {
            v["default_route"]["scanner_ns"] == autodetect_via("veth-a")
                && v["default_route"]["peer_ns"] == false
                && v["default_route"].as_object().map(|o| o.len()) == Some(2)
        }
    };
    ["uplink", "bridge", "nat"].iter().all(|k| v[*k] == false)
        && default_ok
        && v["ip_forward"].as_u64() == Some(0)
        && v["ipv6"] == "disabled"
        && v["veth_created_inside_scanner_ns_peer_moved_to_peer_ns"] == true
        && v["host_link_list_unchanged"] == true
}

/// The IPv6 stand (`wire-lab.sh --suite ipv6`): the autodetect stand with IPv6 raised on the lab veth pair (and the
/// namespaces' `lo`) only. ULA `fd00:198:18::/64`; the link-local addresses are the EUI-64 ones of the stand MACs
/// (`addr_gen_mode` 0); the scanner namespace's IPv6 default route goes via the peer's link-local address.
pub const IPV6_PREFIX: &str = "fd00:198:18::/64";
pub const IPV6_SCANNER: &str = "fd00:198:18::1";
pub const IPV6_PEERS: [&str; 4] = [
    "fd00:198:18::2",
    "fd00:198:18::3",
    "fd00:198:18::4",
    "fd00:198:18::5",
];
pub const IPV6_SCANNER_LL: &str = "fe80::aa:ff:fe00:1";
pub const IPV6_PEER_LL: &str = "fe80::aa:ff:fe00:2";
/// A documentation address (RFC 3849) whose route proves the seal: via the peer from the scanner namespace, none
/// from the peer namespace (the IPv6 counterpart of the `8.8.8.8` probe).
pub const IPV6_ROUTE_PROBE: &str = "2001:db8::1";
/// The IPv6 settings of every lab veth end on the IPv6 stand (`/proc/sys/net/ipv6/conf/<veth>/<key>`), in the order
/// `capture isolation` and `ipv6-suite` read them: IPv6 on, no Duplicate Address Detection (no DAD NS, no tentative
/// address), no router discovery (no RS, no RA processed), no forwarding (the peer answers NS without the router
/// flag and routes nothing), EUI-64 link-local addresses.
pub const IPV6_SYSCTLS: [(&str, &str); 6] = [
    ("disable_ipv6", "0"),
    ("accept_dad", "0"),
    ("accept_ra", "0"),
    ("router_solicitations", "0"),
    ("forwarding", "0"),
    ("addr_gen_mode", "0"),
];
/// Address flags (`ip -j addr`) that make an address unusable for the stand: not yet (or never) valid, or about to go.
pub const IPV6_UNUSABLE_FLAGS: [&str; 4] = ["tentative", "dadfailed", "optimistic", "deprecated"];
const STAND_SCANNER_MAC: &str = "02:aa:00:00:00:01";
const STAND_PEER_MAC: &str = "02:aa:00:00:00:02";

/// What `capture isolation --mode ipv6` reads of one namespace's IPv6: `ip -6 -j addr show dev <veth>`,
/// `ip -6 -j route show`, `ip -6 -j neigh show`, the veth's [`IPV6_SYSCTLS`] (key, value read) and the first line of
/// `ip -6 route get` [`IPV6_ROUTE_PROBE`] (`None` when it failed).
pub struct Ipv6Snapshot {
    pub addrs: Value,
    pub routes: Value,
    pub neigh: Value,
    pub sysctls: Vec<(String, String)>,
    pub route_get: Option<String>,
}

fn v6(s: &str) -> Option<std::net::Ipv6Addr> {
    s.parse().ok()
}
/// Inside `fd00:198:18::/64` or `fe80::/64`.
fn on_stand6(ip: std::net::Ipv6Addr) -> bool {
    let s = ip.segments();
    s[..4] == [0xfd00, 0x198, 0x18, 0] || s[..4] == [0xfe80, 0, 0, 0]
}

/// One side of the IPv6 stand as `snap` shows it: the veth's settings are [`IPV6_SYSCTLS`]; its addresses are exactly
/// the stand's (scanner `fd00:198:18::1/64` and its link-local, peer `fd00:198:18::2-5/64` and its link-local), none
/// tentative, failed, optimistic or deprecated; the main table holds exactly the connected ULA and link-local routes
/// (and on the scanner side the default route via the peer's link-local address; `::1` on `lo` is tolerated); every
/// IPv6 neighbour is on the stand, and the other side's ULA and link-local addresses are permanent neighbours with its
/// MAC (no kernel learns, and later probes, the other side's link-local); the
/// documentation address routes via the peer from the scanner side and not at all from the peer side. The record
/// kept in `isolation.json`, or why the side is not the stand.
pub fn check_ipv6_side(side: Side, iface: &str, snap: &Ipv6Snapshot) -> Result<Value, String> {
    let want_sysctls: Vec<(String, String)> = IPV6_SYSCTLS
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    if snap.sysctls != want_sysctls {
        return Err(format!(
            "IPv6 settings of {iface} are {:?}, not the stand's {want_sysctls:?}",
            snap.sysctls
        ));
    }
    // `other`: the other side's addresses that must be permanent neighbours here, its ULAs and its link-local
    // address (a learnt link-local entry is probed by NUD with a unicast NS, which the live r1 of 7b caught in a step;
    // on the scanner side it is the router of the default route, which the kernel probes on a route lookup too).
    let (own, own_ll, other, other_mac): (Vec<&str>, &str, Vec<&str>, &str) = match side {
        Side::Scanner => (
            vec![IPV6_SCANNER],
            IPV6_SCANNER_LL,
            [IPV6_PEERS.as_slice(), &[IPV6_PEER_LL]].concat(),
            STAND_PEER_MAC,
        ),
        Side::Peer => (
            IPV6_PEERS.to_vec(),
            IPV6_PEER_LL,
            vec![IPV6_SCANNER, IPV6_SCANNER_LL],
            STAND_SCANNER_MAC,
        ),
    };
    // addresses
    let links = snap
        .addrs
        .as_array()
        .ok_or("invalid IPv6 address inventory")?;
    if links.len() != 1 || links[0]["ifname"] != iface {
        return Err(format!(
            "the IPv6 address inventory is not that of {iface} alone"
        ));
    }
    let mut addrs = Vec::new();
    for a in links[0]["addr_info"].as_array().ok_or("no addr_info")? {
        let ip = a["local"]
            .as_str()
            .and_then(v6)
            .ok_or("an address that is no IPv6 address")?;
        if a["family"] != "inet6" {
            return Err(format!("{ip} is not inet6"));
        }
        if let Some(f) = IPV6_UNUSABLE_FLAGS.iter().find(|f| a[**f] == true) {
            return Err(format!("{ip} on {iface} is {f}"));
        }
        addrs.push((ip, a["prefixlen"].as_u64().unwrap_or(0)));
    }
    addrs.sort();
    let mut want: Vec<(std::net::Ipv6Addr, u64)> = own
        .iter()
        .chain([&own_ll])
        .filter_map(|s| v6(s).map(|ip| (ip, 64)))
        .collect();
    want.sort();
    if addrs != want {
        return Err(format!(
            "IPv6 addresses of {iface} are {addrs:?}, not the stand's {want:?}"
        ));
    }
    // routes
    let routes = snap
        .routes
        .as_array()
        .ok_or("invalid IPv6 route inventory")?;
    let mut need: Vec<(String, Option<String>)> = vec![
        (IPV6_PREFIX.to_owned(), None),
        ("fe80::/64".to_owned(), None),
    ];
    if side == Side::Scanner {
        need.push(("default".to_owned(), Some(IPV6_PEER_LL.to_owned())));
    }
    let mut seen = Vec::new();
    for r in routes {
        let (dst, dev) = (
            r["dst"].as_str().unwrap_or(""),
            r["dev"].as_str().unwrap_or(""),
        );
        let gw = r["gateway"].as_str().map(str::to_owned);
        if dev == "lo" && dst == "::1" && gw.is_none() {
            continue;
        }
        if dev != iface || !need.contains(&(dst.to_owned(), gw.clone())) {
            return Err(format!("unexpected IPv6 route {dst} via {gw:?} dev {dev}"));
        }
        seen.push((dst.to_owned(), gw));
    }
    seen.sort();
    need.sort();
    if seen != need {
        return Err(format!("IPv6 routes are {seen:?}, not exactly {need:?}"));
    }
    // neighbours
    let neigh = snap
        .neigh
        .as_array()
        .ok_or("invalid IPv6 neighbour inventory")?;
    for n in neigh {
        if !n["dst"].as_str().and_then(v6).is_some_and(on_stand6) {
            return Err(format!("IPv6 neighbour outside the stand: {}", n["dst"]));
        }
    }
    for ip in &other {
        let ok = neigh.iter().any(|n| {
            n["dst"].as_str().and_then(v6) == v6(ip)
                && n["dev"] == iface
                && n["lladdr"] == other_mac
                && n["state"]
                    .as_array()
                    .is_some_and(|s| s.iter().any(|x| x == "PERMANENT"))
        });
        if !ok {
            return Err(format!(
                "IPv6 neighbour {ip} is not permanent with {other_mac} on {iface}"
            ));
        }
    }
    // the seal
    let route_get = match (side, &snap.route_get) {
        (Side::Scanner, Some(l))
            if l.starts_with(&format!("{IPV6_ROUTE_PROBE} "))
                && l.contains(&format!(" via {IPV6_PEER_LL} dev {iface}")) =>
        {
            l.clone()
        }
        (Side::Peer, None) => "unreachable".to_owned(),
        (_, got) => {
            return Err(format!(
                "ip -6 route get {IPV6_ROUTE_PROBE} gave {got:?} (the scanner routes it via {IPV6_PEER_LL} dev {iface}, the peer nowhere)"
            ));
        }
    };
    Ok(json!({
        "addresses": addrs.iter().map(|(ip, n)| format!("{ip}/{n}")).collect::<Vec<_>>(),
        "routes": seen.iter().map(|(d, g)| match g {
            Some(g) => format!("{d} via {g} dev {iface}"),
            None => format!("{d} dev {iface}"),
        }).collect::<Vec<_>>(),
        "permanent_neighbours": other.iter().map(|ip| format!("{ip} lladdr {other_mac}")).collect::<Vec<_>>(),
        "sysctls": snap.sysctls.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>(),
        "route_get_probe": route_get,
    }))
}

/// Whether an `isolation.json` permits a run on the IPv6 stand: written by `capture isolation --mode ipv6` (which
/// writes it only once both sides passed [`check_ipv6_side`]), and the autodetect stand's seal holds for the rest.
pub fn isolation_permits_ipv6(v: &Value) -> bool {
    let mut rest = v.clone();
    rest["ipv6"] = json!("disabled");
    v["mode"] == "ipv6"
        && v["ipv6"]["lab_veth_only"] == true
        && v["ipv6"]["prefix"] == IPV6_PREFIX
        && v["ipv6"]["scanner"].is_object()
        && v["ipv6"]["peer"].is_object()
        && isolation_permits(&rest, IsolationMode::Autodetect)
}

/// The second veth pair of the scan-control stand (`wire-lab.sh --suite scan-control`), for `--adapter[1]`: no
/// address on either end, a /32 route to [`SECOND_ADAPTER_IP`] on the peer end only; the scanner binds the address
/// itself (`--adapter-ip[1]`, it is assigned to no interface).
pub const SECOND_SCANNER_IF: &str = "veth-a2";
pub const SECOND_PEER_IF: &str = "veth-b2";
pub const SECOND_ADAPTER_IP: &str = "198.18.0.6";

/// Splits a scan-control namespace snapshot into the primary stand (what [`check_isolation_snapshot`] judges,
/// unchanged), its routes, and the second link's record, after checking that the namespace holds exactly `lo` and two
/// veths, that the second link is a veth without a master, that the scanner end of it has no route at all and that
/// the peer end has exactly the /32 route to [`SECOND_ADAPTER_IP`] (no gateway, no default).
pub fn split_second_link(
    links: &Value,
    routes: &Value,
    side: Side,
) -> Result<(Value, Value, Value), String> {
    let second_name = match side {
        Side::Scanner => SECOND_SCANNER_IF,
        Side::Peer => SECOND_PEER_IF,
    };
    let all = links.as_array().ok_or("invalid interface inventory")?;
    if all.len() != 3 || all.iter().filter(|l| l["ifname"] == "lo").count() != 1 {
        return Err("a scan-control namespace must contain only lo and two veths".into());
    }
    let second = all
        .iter()
        .find(|l| l["ifname"] == second_name)
        .ok_or_else(|| format!("the second link {second_name} is missing"))?;
    if second["linkinfo"]["info_kind"] != "veth" || !second["master"].is_null() {
        return Err("foreign link or bridge master on the second link".into());
    }
    let primary: Vec<Value> = all
        .iter()
        .filter(|l| l["ifname"] != second_name)
        .cloned()
        .collect();
    let routes = routes.as_array().ok_or("invalid route inventory")?;
    let on_second: Vec<&Value> = routes.iter().filter(|r| r["dev"] == second_name).collect();
    match side {
        Side::Scanner if !on_second.is_empty() => {
            return Err("the scanner end of the second link has a route".into());
        }
        Side::Peer
            if on_second.len() != 1
                || on_second[0]["dst"] != SECOND_ADAPTER_IP
                || !on_second[0]["gateway"].is_null() =>
        {
            return Err("the peer end of the second link must have exactly the /32 route to the second adapter address".into());
        }
        _ => {}
    }
    let rest: Vec<Value> = routes
        .iter()
        .filter(|r| r["dev"] != second_name)
        .cloned()
        .collect();
    Ok((json!(primary), json!(rest), second.clone()))
}

pub fn check_isolation_snapshot(
    links: &Value,
    routes: &Value,
    forwarding: &str,
    mode: IsolationMode,
    side: Side,
) -> Result<(), String> {
    let links = links.as_array().ok_or("invalid interface inventory")?;
    if links.len() != 2 || links.iter().filter(|l| l["ifname"] == "lo").count() != 1 {
        return Err("namespace must contain only lo and its veth".into());
    }
    let veth = links
        .iter()
        .find(|l| l["ifname"] != "lo")
        .ok_or("veth missing")?;
    if veth["linkinfo"]["info_kind"] != "veth" || !veth["master"].is_null() {
        return Err("foreign link or bridge master in namespace".into());
    }
    let routes = routes.as_array().ok_or("invalid route inventory")?;
    match (mode, side) {
        (IsolationMode::Autodetect, Side::Scanner) => {
            let dev = veth["ifname"].as_str().ok_or("veth name missing")?;
            let connected = routes.iter().filter(|r| {
                r["dst"] == AUTODETECT_NET && r["gateway"].is_null() && r["dev"] == dev
            });
            let default = routes.iter().filter(|r| {
                r["dst"] == "default" && r["gateway"] == AUTODETECT_GATEWAY && r["dev"] == dev
            });
            if routes.len() != 2 || connected.count() != 1 || default.count() != 1 {
                return Err("scanner namespace routes are not exactly the connected route and the default route via the peer".into());
            }
        }
        (IsolationMode::Default, _) | (IsolationMode::Autodetect, Side::Peer) => {
            if routes.len() > 1
                || routes
                    .iter()
                    .any(|r| r["dst"] == "default" || !r["gateway"].is_null())
            {
                return Err("unexpected route or gateway in lab".into());
            }
        }
    }
    if forwarding.trim() != "0" {
        return Err("namespace forwarding enabled or unknown".into());
    }
    Ok(())
}

/// Scanner namespace neighbours: 198.18.0.2-5 permanent on the lab veth, nothing from outside the /24.
pub fn check_isolation_neighbours(neigh: &Value, iface: &str) -> Result<(), String> {
    let list = neigh.as_array().ok_or("invalid neighbour inventory")?;
    for want in AUTODETECT_NEIGHBOURS {
        let ok = list.iter().any(|n| {
            n["dst"] == want
                && n["dev"] == iface
                && n["state"]
                    .as_array()
                    .is_some_and(|s| s.iter().any(|x| x == "PERMANENT"))
        });
        if !ok {
            return Err(format!("neighbour {want} is not permanent on {iface}"));
        }
    }
    if list.iter().any(|n| {
        !n["dst"]
            .as_str()
            .is_some_and(|d| d.starts_with("198.18.0."))
    }) {
        return Err("neighbour outside the lab network".into());
    }
    Ok(())
}

/// `ip route get 8.8.8.8` in the scanner namespace must go via the peer on the lab veth.
pub fn check_route_get(out: &str, iface: &str) -> Result<(), String> {
    let first = out.lines().next().unwrap_or_default();
    if first.starts_with(&format!("8.8.8.8 {} ", autodetect_via(iface)))
        || first == format!("8.8.8.8 {}", autodetect_via(iface))
    {
        Ok(())
    } else {
        Err(format!("route get 8.8.8.8 is not via the peer: {first}"))
    }
}

/// macOS: `capture marker` and `capture responder` are Linux-lab tools (CAP_NET_RAW inside a
/// network namespace). On a Mac they would write frames on any interface the process can open
/// (`marker`) or bind wildcard ports on every interface (`responder`), outside the lab guard
/// that every macOS writer goes through (`GuardedTx`, `injection_allowed`). The macOS suite
/// uses neither, so both refuse with rc 2 and an explanation; Linux and Windows are unchanged.
fn macos_refusal(cmd: &str, macos: bool) -> Option<String> {
    if !macos || !matches!(cmd, "marker" | "responder") {
        return None;
    }
    Some(format!(
        "capture {cmd} is refused on macOS: it is a Linux-lab tool that writes frames on a caller-chosen interface or binds wildcard ports without the lab guard. The macOS suite never uses it; start markers and listeners through `macos-suite` (guarded `peer` and `capture dump` on feth4202 only)"
    ))
}

pub fn run(args: &[String]) -> Result<i32, String> {
    let (cmd, rest) = args.split_first().ok_or("capture subcommand required")?;
    if let Some(why) = macos_refusal(cmd, cfg!(target_os = "macos")) {
        eprintln!("{why}");
        return Ok(2);
    }
    let a = opts(rest)?;
    match cmd.as_str() {
        "dump" => crate::dump::run(&a),
        "marker" => marker(&a),
        "responder" => responder(&a),
        "env" => environment(&a),
        "manifest" => manifest(&a),
        "isolation" => isolation(&a),
        "summary" => {
            println!("{}", read_json(get(&a, "meta")?)?);
            Ok(0)
        }
        _ => Err(format!("unknown capture command {cmd}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn veth(name: &str, index: u64, peer_index: u64) -> Value {
        json!({"ifname":name,"ifindex":index,"link_index":peer_index,"linkinfo":{"info_kind":"veth"},"master":null})
    }
    fn scan_control_links(side: Side) -> Value {
        let (p, s) = match side {
            Side::Scanner => ("veth-a", SECOND_SCANNER_IF),
            Side::Peer => ("veth-b", SECOND_PEER_IF),
        };
        json!([{"ifname":"lo"}, veth(p, 2, 3), veth(s, 4, 5)])
    }
    #[test]
    fn the_second_link_is_split_off_and_the_primary_stand_is_judged_as_before() {
        let routes = json!([{"dst":"198.18.0.0/24","dev":"veth-a"},{"dst":"default","gateway":"198.18.0.2","dev":"veth-a"}]);
        let (l, r, sec) =
            split_second_link(&scan_control_links(Side::Scanner), &routes, Side::Scanner).unwrap();
        assert_eq!(sec["ifname"], SECOND_SCANNER_IF);
        assert!(
            check_isolation_snapshot(&l, &r, "0", IsolationMode::Autodetect, Side::Scanner).is_ok()
        );
        let routes = json!([{"dst":"198.18.0.0/24","dev":"veth-b"},{"dst":SECOND_ADAPTER_IP,"dev":"veth-b2"}]);
        let (l, r, sec) =
            split_second_link(&scan_control_links(Side::Peer), &routes, Side::Peer).unwrap();
        assert_eq!(sec["ifname"], SECOND_PEER_IF);
        assert!(
            check_isolation_snapshot(&l, &r, "0", IsolationMode::Autodetect, Side::Peer).is_ok()
        );
    }
    #[test]
    fn a_third_link_a_master_or_a_stray_route_on_the_second_link_breaks_the_seal() {
        let peer_routes = json!([{"dst":"198.18.0.0/24","dev":"veth-b"},{"dst":SECOND_ADAPTER_IP,"dev":"veth-b2"}]);
        let scan_routes = json!([{"dst":"198.18.0.0/24","dev":"veth-a"},{"dst":"default","gateway":"198.18.0.2","dev":"veth-a"}]);
        let go = |links: Value, routes: &Value, side| split_second_link(&links, routes, side);
        // an extra link, or only the primary one
        let mut four = scan_control_links(Side::Scanner);
        four.as_array_mut().unwrap().push(veth("veth-x", 6, 7));
        assert!(go(four, &scan_routes, Side::Scanner).is_err());
        assert!(
            go(
                json!([{"ifname":"lo"},veth("veth-a", 2, 3)]),
                &scan_routes,
                Side::Scanner
            )
            .is_err()
        );
        // the second link under a bridge, or not a veth
        let mut mastered = scan_control_links(Side::Scanner);
        mastered[2]["master"] = json!("br0");
        assert!(go(mastered, &scan_routes, Side::Scanner).is_err());
        let mut bridge = scan_control_links(Side::Scanner);
        bridge[2]["linkinfo"]["info_kind"] = json!("bridge");
        assert!(go(bridge, &scan_routes, Side::Scanner).is_err());
        // a route on the scanner end of the second link
        let mut stray = scan_routes.clone();
        stray
            .as_array_mut()
            .unwrap()
            .push(json!({"dst":"198.18.0.0/24","dev":"veth-a2"}));
        assert!(go(scan_control_links(Side::Scanner), &stray, Side::Scanner).is_err());
        // the peer end: no route, a gateway, a default route, the wrong destination
        for bad in [
            json!([{"dst":"198.18.0.0/24","dev":"veth-b"}]),
            json!([{"dst":"198.18.0.0/24","dev":"veth-b"},{"dst":SECOND_ADAPTER_IP,"gateway":"198.18.0.2","dev":"veth-b2"}]),
            json!([{"dst":"198.18.0.0/24","dev":"veth-b"},{"dst":"default","dev":"veth-b2"}]),
            json!([{"dst":"198.18.0.0/24","dev":"veth-b"},{"dst":"198.18.0.7","dev":"veth-b2"}]),
        ] {
            assert!(
                go(scan_control_links(Side::Peer), &bad, Side::Peer).is_err(),
                "{bad}"
            );
        }
        assert!(go(scan_control_links(Side::Peer), &peer_routes, Side::Peer).is_ok());
    }
    #[test]
    fn macos_refuses_marker_and_responder_with_an_explanation_and_leaves_the_rest() {
        for cmd in ["marker", "responder"] {
            let why = macos_refusal(cmd, true).expect("refused on macOS");
            assert!(
                why.contains("refused on macOS") && why.contains(cmd),
                "{why}"
            );
            assert_eq!(
                macos_refusal(cmd, false),
                None,
                "Linux/Windows unchanged: {cmd}"
            );
        }
        for cmd in ["dump", "env", "manifest", "isolation", "summary", "bogus"] {
            assert_eq!(macos_refusal(cmd, true), None, "{cmd} is not refused here");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_run_returns_rc_2_for_marker_and_responder_before_opening_anything() {
        let words = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // en0 and a bogus MAC pair: were the guard missing, `marker` would try to open /dev/bpf*.
        let marker = words(&[
            "marker",
            "--iface",
            "en0",
            "--dst",
            "ff:ff:ff:ff:ff:ff",
            "--src",
            "02:ac:00:00:00:01",
        ]);
        assert_eq!(run(&marker), Ok(2));
        let responder = words(&[
            "responder",
            "--ports",
            "8000",
            "--ready",
            "/nonexistent/ready",
        ]);
        assert_eq!(run(&responder), Ok(2));
    }

    /// Runs `supervise` on its own thread: its result, or `None` when it has not ended within `limit`.
    fn supervised(
        workers: Vec<Worker>,
        halt: std::sync::Arc<AtomicBool>,
        stop: bool,
        limit: Duration,
    ) -> Option<Result<(), String>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(supervise(
                workers,
                &halt,
                &move || stop,
                Duration::from_millis(5),
            ));
        });
        rx.recv_timeout(limit).ok()
    }
    /// A worker that runs until it is halted, as the UDP and SCTP answerers do.
    fn healthy(halt: &std::sync::Arc<AtomicBool>) -> Worker {
        let h = halt.clone();
        std::thread::spawn(move || {
            while !h.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        })
    }

    #[test]
    fn a_responder_worker_that_fails_ends_the_responder_at_once_with_its_error() {
        let limit = Duration::from_secs(5);
        // One answerer fails while two others are healthy: the responder ends with that error, not at SIGTERM.
        let halt = std::sync::Arc::new(AtomicBool::new(false));
        let failing: Worker = std::thread::spawn(|| {
            std::thread::sleep(Duration::from_millis(20));
            Err("udp responder: Network is down (os error 100)".to_owned())
        });
        let workers = vec![healthy(&halt), failing, healthy(&halt)];
        assert_eq!(
            supervised(workers, halt, false, limit),
            Some(Err("udp responder: Network is down (os error 100)".into())),
            "the responder must end with the failed worker's error"
        );
        // A worker that ends without an error before the stop request has failed too.
        let halt = std::sync::Arc::new(AtomicBool::new(false));
        let quiet: Worker = std::thread::spawn(|| Ok(()));
        let got = supervised(vec![healthy(&halt), quiet], halt, false, limit);
        assert!(
            matches!(&got, Some(Err(e)) if e.contains("ended before the stop request")),
            "{got:?}"
        );
        // The stop request ends healthy workers: no error.
        let halt = std::sync::Arc::new(AtomicBool::new(false));
        let workers = vec![healthy(&halt), healthy(&halt)];
        assert_eq!(supervised(workers, halt, true, limit), Some(Ok(())));
        // Without workers (no --udp-ports, no --sctp-iface) it waits for the stop request alone, as before.
        let halt = std::sync::Arc::new(AtomicBool::new(false));
        assert_eq!(
            supervised(Vec::new(), halt.clone(), false, Duration::from_millis(200)),
            None,
            "without a stop request the TCP-only responder keeps running"
        );
        assert_eq!(supervised(Vec::new(), halt, true, limit), Some(Ok(())));
    }

    #[test]
    fn the_udp_answerer_replies_once_per_datagram_and_ends_on_halt() {
        let s = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let at = s.local_addr().unwrap();
        let halt = std::sync::Arc::new(AtomicBool::new(false));
        let h = halt.clone();
        let w = std::thread::spawn(move || udp_answers(&s, &h));
        let c = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        c.send_to(b"probe", at).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = c.recv_from(&mut buf).unwrap();
        assert_eq!((&buf[..n], from), (crate::protocols_verify::UDP_REPLY, at));
        halt.store(true, Ordering::SeqCst);
        let started = std::time::Instant::now();
        assert_eq!(w.join().unwrap(), Ok(()));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }
    fn scratch(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("rmasscan-harness-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }
    #[test]
    fn harness_hashes_the_scripts_it_is_given_and_never_omits_one() {
        let d = scratch("scripts");
        let (wl, pg) = (d.join("wire-lab.sh"), d.join("pg.sh"));
        fs::write(&wl, "one").unwrap();
        fs::write(&pg, "two").unwrap();
        let a = args(&[
            ("wire-lab-sh", wl.to_str().unwrap()),
            ("process-group-sh", pg.to_str().unwrap()),
        ]);
        let h = harness_record(&a).unwrap();
        assert_eq!(h["wire-lab.sh"], hex_digest(b"one"));
        assert_eq!(h["lab-process-group.sh"], hex_digest(b"two"));
        assert_eq!(
            h["rmasscan-lab"],
            sha(std::env::current_exe().unwrap()).unwrap()
        );
        assert!(h.get("deploy").is_none());
        // A path that is absent, or an omitted argument, is an error and not a missing key.
        let gone = args(&[
            ("wire-lab-sh", d.join("absent").to_str().unwrap()),
            ("process-group-sh", pg.to_str().unwrap()),
        ]);
        assert!(harness_record(&gone).is_err());
        assert!(harness_record(&args(&[("wire-lab-sh", wl.to_str().unwrap())])).is_err());
        let _ = fs::remove_dir_all(d);
    }
    #[test]
    fn a_deploy_manifest_binds_the_running_binary_to_a_commit() {
        let d = scratch("deploy");
        let (wl, pg, manifest) = (d.join("wl.sh"), d.join("pg.sh"), d.join("m.json"));
        fs::write(&wl, "a").unwrap();
        fs::write(&pg, "b").unwrap();
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
        let mk = |bytes: &[u8]| crate::deploy::build_manifest(commit, "/x/lab", bytes, "", 1.0);
        let a = args(&[
            ("wire-lab-sh", wl.to_str().unwrap()),
            ("process-group-sh", pg.to_str().unwrap()),
            ("deploy-manifest", manifest.to_str().unwrap()),
        ]);
        write_json(&manifest, &mk(&exe)).unwrap();
        let h = harness_record(&a).unwrap();
        assert_eq!(h["deploy"]["commit"], commit);
        assert_eq!(h["deploy"]["manifest_sha256"], sha(&manifest).unwrap());
        write_json(&manifest, &mk(b"some other build")).unwrap();
        assert!(
            harness_record(&a).is_err(),
            "a binary the manifest does not list"
        );
        let _ = fs::remove_dir_all(d);
    }
    #[test]
    fn classifies_only_complete_tcp_headers_and_directions() {
        let scanner = [1; 6];
        let peer = [2; 6];
        let mut syn = vec![0u8; 54];
        syn[6..12].copy_from_slice(&scanner);
        syn[12..14].copy_from_slice(&[8, 0]);
        syn[14] = 0x45;
        syn[23] = 6;
        syn[47] = 2;
        let mut reply = syn.clone();
        reply[6..12].copy_from_slice(&peer);
        reply[47] = 0x12;
        let mut short = syn.clone();
        short[14] = 0x4f;
        let c = classify(&[(0., syn), (0., reply), (0., short)], scanner, peer);
        assert_eq!(c["syn_from_scanner"], 1);
        assert_eq!(c["synack_from_peer"], 1);
        assert_eq!(c["other"], 1);
    }

    #[test]
    fn scrub_removes_home_paths_and_run_namespaces_in_values_and_keys() {
        let mut v = json!({
            "/home/alice/work/x": ["/Users/den.k/repo/a b", "ns wl-scan-123-456 and wl-peer-7-89 done"],
            "k": {"p": "/root/lab", "q": "/home/bob", "r": "path='/Users/c' \"/home/d\""},
            "n": 5, "t": true, "z": null, "h": "00ff/home/"
        });
        scrub(&mut v);
        assert_eq!(
            v["$HOME/work/x"][0], "$HOME/repo/a b",
            "keys are scrubbed too"
        );
        assert_eq!(
            v["$HOME/work/x"][1],
            "ns wl-scan-RUNID and wl-peer-RUNID done"
        );
        assert_eq!(v["k"]["p"], "$HOME/lab");
        assert_eq!(v["k"]["q"], "$HOME", "ends at the end of the string");
        assert_eq!(
            v["k"]["r"], "path='$HOME' \"$HOME\"",
            "quotes end the user name"
        );
        assert_eq!(
            (v["n"].clone(), v["t"].clone(), v["z"].clone()),
            (json!(5), json!(true), Value::Null)
        );
        assert_eq!(
            v["h"], "00ff/home/",
            "an empty user name is not a home path"
        );
    }

    #[test]
    fn a_suites_scrubber_writes_its_out_work_and_account_as_placeholders() {
        // The first macOS window at 6c87e94: `--out` under a scratch directory whose path names the account.
        let out = Path::new(
            "/private/tmp/claude-501/-Users-alice/0946/scratchpad/autodetect-out/macos-r1",
        );
        let o = out.display();
        // Strings, not joins: the hermetic tests also run on Windows.
        let work = format!("{o}/.work");
        let sc = Scrubber::new(out, Some(Path::new(&work)), Some("alice"));
        for (input, want) in [
            (
                format!("{o}/.work/m01_user_masked.r1/peer.unfiltered"),
                "$WORK/m01_user_masked.r1/peer.unfiltered",
            ),
            (format!("--dir {o}"), "--dir $OUT"),
            (
                format!("'{o}/runs/m01_user_masked'"),
                "'$OUT/runs/m01_user_masked'",
            ),
            (format!("{o}"), "$OUT"),
            // A sibling of --out is not --out; its account name still goes.
            (
                format!("{o}.bak/x"),
                "/private/tmp/claude-501/-Users-$USER/0946/scratchpad/autodetect-out/macos-r1.bak/x",
            ),
            (
                "-Users-alice-masscan-studio".into(),
                "-Users-$USER-masscan-studio",
            ),
            ("/x/-home-alice/masscan".into(), "/x/-home-$USER/masscan"),
            ("/Users/alice/x".into(), "$HOME/x"),
            ("/home/alice".into(), "$HOME"),
            ("C:\\Users\\alice\\t4".into(), "C:\\Users\\$USER\\t4"),
            ("run by alice.".into(), "run by $USER."),
            ("alice@host".into(), "$USER@host"),
            // Words that only contain the name, and the namespace rule of `scrub`.
            (
                "malice alice_x alice-mbp --alice".into(),
                "malice alice_x alice-mbp --alice",
            ),
            ("ns wl-scan-12-34".into(), "ns wl-scan-RUNID"),
        ] {
            assert_eq!(sc.str(&input), want, "{input}");
        }
        // Values and keys of a record, and nothing else of it.
        let mut v = json!({format!("{o}/k"): [format!("{o}/.work/a"), "alice", 5, true]});
        sc.value(&mut v);
        assert_eq!(v, json!({"$OUT/k": ["$WORK/a", "$USER", 5, true]}));
        // A short hex account name never rewrites a byte of a MAC, an IPv6 address or a hash; as a word it goes.
        let sc = Scrubber::new(out, None, Some("a1"));
        assert_eq!(
            sc.str("link/ether 02:a1:00:00:00:01 fe80::a1 a1b2 /home/a1/x run by a1"),
            "link/ether 02:a1:00:00:00:01 fe80::a1 a1b2 $HOME/x run by $USER"
        );
        // Without a work directory or an account, only --out goes.
        let sc = Scrubber::new(out, None, None);
        assert_eq!(sc.str(&format!("{o}/.work/a alice")), "$OUT/.work/a alice");
        // A trailing separator on --out changes nothing.
        let sc = Scrubber::new(Path::new("/srv/out/"), None, None);
        assert_eq!(sc.str("/srv/out/.work/a /srv/out"), "$OUT/.work/a $OUT");
        assert_eq!(sc.str("/srv/outer/a"), "/srv/outer/a");
    }

    #[test]
    fn a_tools_text_record_is_rewritten_in_place_and_other_bytes_are_left_alone() {
        let d =
            std::env::temp_dir().join(format!("rml-scrub-file-{}", crate::windows_suite::nonce()));
        fs::create_dir_all(&d).unwrap();
        let out = format!("{}/out", d.display());
        let sc = Scrubber::new(Path::new(&out), None, Some("alice"));
        let status = d.join("status-pre.json");
        fs::write(&status, format!("{{\"note\":\"alice in {out}/.work\"}}\n")).unwrap();
        sc.file(&status).unwrap();
        assert_eq!(
            fs::read_to_string(&status).unwrap(),
            "{\"note\":\"$USER in $OUT/.work\"}\n"
        );
        // Not UTF-8: untouched (the verifier still scans it); a missing file is an error.
        let raw = d.join("x.txt");
        let bytes = [b'a', 0xff, b'l', b'i', b'c', b'e'];
        fs::write(&raw, bytes).unwrap();
        sc.file(&raw).unwrap();
        assert_eq!(fs::read(&raw).unwrap(), bytes);
        assert!(sc.file(&d.join("missing.json")).is_err());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_account_is_sudo_user_unless_root_then_user_and_root_is_none() {
        assert_eq!(
            account(Some("alice"), Some("root")).as_deref(),
            Some("alice")
        );
        assert_eq!(account(Some("root"), Some("bob")).as_deref(), Some("bob"));
        assert_eq!(account(None, Some("bob")).as_deref(), Some("bob"));
        assert_eq!(account(Some(""), Some("root")), None);
        assert_eq!(account(None, None), None);
    }

    #[test]
    fn scrub_namespace_pattern_is_exactly_wl_kind_digits_dash_digits() {
        for (input, want) in [
            ("wl-scan-12-34", "wl-scan-RUNID"),
            ("wl-scan-12-34-extra", "wl-scan-RUNID-extra"),
            (
                "a wl-peer-1-2, wl-peer-3-4",
                "a wl-peer-RUNID, wl-peer-RUNID",
            ),
            ("wl-scan-12", "wl-scan-12"),
            ("wl-scan-12-", "wl-scan-12-"),
            ("wl-scan-x-1", "wl-scan-x-1"),
            ("wl-other-1-2", "wl-other-1-2"),
            ("/rootkit/x /roots", "/rootkit/x /roots"),
        ] {
            let mut v = json!(input);
            scrub(&mut v);
            assert_eq!(v, want, "{input}");
        }
    }

    /// One side of the IPv6 stand as iproute2 6.19 prints it (`ip -6 -j addr|route|neigh`; key names as in its
    /// `print_bool`/`print_string` calls: `tentative`, `nodad`, `state: ["PERMANENT"]`).
    pub(crate) fn ipv6_snapshot(side: Side) -> Ipv6Snapshot {
        // The other side's ULA addresses and its link-local address are permanent neighbours (7b r1: a learnt
        // link-local entry is probed by NUD, and such an NS fell into a step).
        let (iface, ulas, ll, others, mac): (&str, Vec<&str>, &str, Vec<&str>, &str) = match side {
            Side::Scanner => (
                "veth-a",
                vec![IPV6_SCANNER],
                IPV6_SCANNER_LL,
                [IPV6_PEERS.as_slice(), &[IPV6_PEER_LL]].concat(),
                STAND_PEER_MAC,
            ),
            Side::Peer => (
                "veth-b",
                IPV6_PEERS.to_vec(),
                IPV6_PEER_LL,
                vec![IPV6_SCANNER, IPV6_SCANNER_LL],
                STAND_SCANNER_MAC,
            ),
        };
        let mut info: Vec<Value> = ulas
            .iter()
            .map(|a| {
                json!({"family":"inet6","local":a,"prefixlen":64,"scope":"global","nodad":true,
                "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64})
            })
            .collect();
        info.push(
            json!({"family":"inet6","local":ll,"prefixlen":64,"scope":"link",
            "valid_life_time":4294967295u64,"preferred_life_time":4294967295u64}),
        );
        let mut routes = vec![
            json!({"dst":IPV6_PREFIX,"dev":iface,"protocol":"kernel","metric":256,"flags":[],"pref":"medium"}),
            json!({"dst":"fe80::/64","dev":iface,"protocol":"kernel","metric":256,"flags":[],"pref":"medium"}),
        ];
        if side == Side::Scanner {
            routes.push(json!({"dst":"default","gateway":IPV6_PEER_LL,"dev":iface,"metric":1024,"flags":[],"pref":"medium"}));
        }
        Ipv6Snapshot {
            addrs: json!([{"ifindex":2,"ifname":iface,"flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,
                "addr_info":info}]),
            routes: json!(routes),
            neigh: json!(
                others
                    .iter()
                    .map(|ip| json!({"dst":ip,"dev":iface,"lladdr":mac,"state":["PERMANENT"]}))
                    .collect::<Vec<_>>()
            ),
            sysctls: IPV6_SYSCTLS
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            route_get: (side == Side::Scanner).then(|| {
                format!("{IPV6_ROUTE_PROBE} from :: via {IPV6_PEER_LL} dev veth-a proto boot src {IPV6_SCANNER} metric 1024 pref medium")
            }),
        }
    }

    #[test]
    fn the_ipv6_stand_passes_its_seal_and_every_single_departure_breaks_it() {
        for (side, iface) in [(Side::Scanner, "veth-a"), (Side::Peer, "veth-b")] {
            let rec = check_ipv6_side(side, iface, &ipv6_snapshot(side)).unwrap();
            assert!(rec["addresses"].as_array().unwrap().len() >= 2, "{rec}");
            // `::1` on lo (an older kernel lists it in main) is tolerated
            let mut s = ipv6_snapshot(side);
            s.routes
                .as_array_mut()
                .unwrap()
                .push(json!({"dst":"::1","dev":"lo","protocol":"kernel","metric":256}));
            assert!(check_ipv6_side(side, iface, &s).is_ok());
        }
        type Break = fn(&mut Ipv6Snapshot);
        let cases: [(&str, Side, Break, &str); 15] = [
            (
                "tentative",
                Side::Scanner,
                |s| s.addrs[0]["addr_info"][0]["tentative"] = json!(true),
                "tentative",
            ),
            (
                "dadfailed",
                Side::Peer,
                |s| s.addrs[0]["addr_info"][4]["dadfailed"] = json!(true),
                "dadfailed",
            ),
            (
                "another address",
                Side::Scanner,
                |s| s.addrs[0]["addr_info"][0]["local"] = json!("fd00:198:18::9"),
                "IPv6 addresses",
            ),
            (
                "DAD on",
                Side::Scanner,
                |s| s.sysctls[1].1 = "1".into(),
                "IPv6 settings",
            ),
            (
                "router solicitations",
                Side::Peer,
                |s| s.sysctls[3].1 = "-1".into(),
                "IPv6 settings",
            ),
            (
                "forwarding peer",
                Side::Peer,
                |s| s.sysctls[4].1 = "1".into(),
                "IPv6 settings",
            ),
            (
                "a default route on the peer",
                Side::Peer,
                |s| {
                    s.routes
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"dst":"default","gateway":IPV6_SCANNER_LL,"dev":"veth-b"}))
                },
                "unexpected IPv6 route",
            ),
            (
                "no default route on the scanner",
                Side::Scanner,
                |s| {
                    s.routes.as_array_mut().unwrap().pop();
                },
                "IPv6 routes are",
            ),
            (
                "a default via another gateway",
                Side::Scanner,
                |s| s.routes[2]["gateway"] = json!("fe80::1"),
                "unexpected IPv6 route",
            ),
            (
                "a neighbour off the stand",
                Side::Scanner,
                |s| {
                    s.neigh
                        .as_array_mut()
                        .unwrap()
                        .push(json!({"dst":"2001:db8::7","dev":"veth-a","state":["STALE"]}))
                },
                "outside the stand",
            ),
            (
                "a learnt, not permanent neighbour",
                Side::Peer,
                |s| s.neigh[0]["state"] = json!(["REACHABLE"]),
                "not permanent",
            ),
            // 7b r1: the router's link-local learnt by the scanner kernel (REACHABLE after its router probe), the
            // scanner's learnt by the peer: both later probed by NUD, the unicast NS fell into a step
            (
                "the router's link-local learnt, not permanent, on the scanner side",
                Side::Scanner,
                |s| s.neigh[4]["state"] = json!(["REACHABLE"]),
                "IPv6 neighbour fe80::aa:ff:fe00:2 is not permanent",
            ),
            (
                "the scanner's link-local missing on the peer side",
                Side::Peer,
                |s| {
                    s.neigh.as_array_mut().unwrap().pop();
                },
                "IPv6 neighbour fe80::aa:ff:fe00:1 is not permanent",
            ),
            (
                "the scanner cannot route out",
                Side::Scanner,
                |s| s.route_get = None,
                "route get",
            ),
            (
                "the peer routes out",
                Side::Peer,
                |s| s.route_get = Some(format!("{IPV6_ROUTE_PROBE} via fe80::1 dev veth-b")),
                "route get",
            ),
        ];
        for (what, side, f, needle) in cases {
            let iface = if side == Side::Scanner {
                "veth-a"
            } else {
                "veth-b"
            };
            let mut s = ipv6_snapshot(side);
            f(&mut s);
            let e = check_ipv6_side(side, iface, &s).expect_err(what);
            assert!(e.contains(needle), "{what}: {e}");
        }
    }

    #[test]
    fn an_ipv6_record_permits_only_the_ipv6_stand_and_never_an_older_suite() {
        let mut v = json!({"uplink":false,"bridge":false,"nat":false,"ip_forward":0,
            "veth_created_inside_scanner_ns_peer_moved_to_peer_ns":true,"host_link_list_unchanged":true,
            "default_route": isolation_default_route(IsolationMode::Autodetect, "veth-a"), "mode":"ipv6",
            "ipv6":{"lab_veth_only":true,"prefix":IPV6_PREFIX,"scanner":{},"peer":{}}});
        assert!(isolation_permits_ipv6(&v));
        // an older suite's rule still wants IPv6 disabled: the IPv6 stand never passes for the autodetect stand
        assert!(!isolation_permits(&v, IsolationMode::Autodetect));
        let mut w = v.clone();
        w["mode"] = json!("autodetect");
        assert!(!isolation_permits_ipv6(&w));
        let mut w = v.clone();
        w["ipv6"] = json!("disabled");
        assert!(!isolation_permits_ipv6(&w));
        v["uplink"] = json!(true);
        assert!(!isolation_permits_ipv6(&v));
    }
}
