//! Sealed Linux capture support and portable evidence manifests.
use rmasscan_net::lab_io::{self, RawSocket};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
fn counter(iface: &str) -> Result<u64, String> {
    if iface.contains('/') || iface == ".." {
        return Err("invalid interface".into());
    }
    fs::read_to_string(format!("/sys/class/net/{iface}/statistics/rx_packets"))
        .map_err(err)?
        .trim()
        .parse()
        .map_err(err)
}

pub fn capture_valid(meta: &Value) -> bool {
    meta["marker_acked"] == true
        && meta["drops"] == 0
        && meta["truncated_frames"] == 0
        && meta["rx_counter_mismatch"] == false
        && meta["frames_in"]
            .as_u64()
            .zip(meta["frames_out"].as_u64())
            .and_then(|(a, b)| a.checked_add(b))
            .is_some_and(|n| meta["kernel_tp_packets"].as_u64() == Some(n))
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

/// Same role as the original recorder; all raw descriptors remain in rmasscan-net.
fn record(a: &BTreeMap<String, String>) -> Result<i32, String> {
    let iface = get(a, "iface")?;
    let pcap = get(a, "pcap")?;
    let meta = get(a, "meta")?;
    let ready = get(a, "ready")?;
    let ack = get(a, "ack")?;
    lab_io::install_signal_handlers().map_err(err)?;
    let sock = RawSocket::open(iface).map_err(err)?;
    sock.stats().map_err(err)?;
    let rx0 = counter(iface)?;
    let mut out = fs::File::create(pcap).map_err(err)?;
    out.write_all(&crate::pcap::encode(&Vec::new()))
        .map_err(err)?;
    fs::write(ready, "bound\n").map_err(err)?;
    let (mut incoming, mut outgoing, mut truncated, mut acked) = (0u64, 0u64, 0u64, false);
    let mut buf = vec![0; 65535];
    let mut deadline = None;
    loop {
        if lab_io::stop_requested() && deadline.is_none() {
            std::thread::sleep(Duration::from_millis(200));
            deadline = Some(Instant::now() + Duration::from_secs(1));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        let Some(r) = sock
            .recv(
                &mut buf,
                Duration::from_millis(if deadline.is_some() { 50 } else { 100 }),
            )
            .map_err(err)?
        else {
            if deadline.is_some() {
                break;
            }
            continue;
        };
        if r.outgoing {
            outgoing += 1;
        } else {
            incoming += 1;
        }
        if r.truncated {
            truncated += 1;
        }
        let time = SystemTime::now().duration_since(UNIX_EPOCH).map_err(err)?;
        let orig = u32::try_from(r.original_len).map_err(err)?;
        for word in [
            u32::try_from(time.as_secs()).map_err(err)?,
            time.subsec_micros(),
            r.len as u32,
            orig,
        ] {
            out.write_all(&word.to_le_bytes()).map_err(err)?;
        }
        out.write_all(&buf[..r.len]).map_err(err)?;
        if !acked
            && buf.get(12..14) == Some(&[0x88, 0xb5])
            && r.len >= 27
            && &buf[14..27] == b"WIRELAB-READY"
        {
            fs::write(ack, "ack\n").map_err(err)?;
            acked = true;
        }
    }
    let stats = sock.stats();
    out.flush().map_err(err)?;
    let delta = counter(iface)?
        .checked_sub(rx0)
        .ok_or("interface counter reset")?;
    let drops = stats.as_ref().map_or(-1, |s| i64::from(s.drops));
    let mut v = json!({"iface":iface,"pcap":Path::new(pcap).file_name().and_then(|x|x.to_str()),"marker_acked":acked,"frames_in":incoming,"frames_out":outgoing,"kernel_tp_packets":stats.as_ref().map_or(-1,|s|i64::from(s.packets)),"drops":drops,"truncated_frames":truncated,"snaplen":65535,"iface_rx_delta":delta,"rx_counter_mismatch":delta!=incoming});
    v["valid"] = json!(capture_valid(&v));
    write_json(meta, &v)?;
    Ok(0)
}
fn marker(a: &BTreeMap<String, String>) -> Result<i32, String> {
    let s = RawSocket::open(get(a, "iface")?).map_err(err)?;
    let mut f = Vec::new();
    f.extend(mac(get(a, "dst")?)?);
    f.extend(mac(get(a, "src")?)?);
    f.extend([0x88, 0xb5]);
    f.extend(b"WIRELAB-READY");
    f.resize(60, 0);
    for _ in 0..3 {
        if s.send(&f).map_err(err)? != f.len() {
            return Err("short marker send".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(0)
}
fn responder(a: &BTreeMap<String, String>) -> Result<i32, String> {
    lab_io::install_signal_handlers().map_err(err)?;
    let ports = get(a, "ports")?;
    let mut listeners = Vec::new();
    for p in ports.split(',').filter(|s| !s.is_empty()) {
        let p = p.parse::<u16>().map_err(err)?;
        if p == 0 {
            return Err("port zero".into());
        }
        listeners.push(lab_io::listen(std::net::Ipv4Addr::UNSPECIFIED, p, 128).map_err(err)?);
    }
    fs::write(get(a, "ready")?, format!("listening {ports}\n")).map_err(err)?;
    while !lab_io::stop_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(listeners);
    Ok(0)
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
    let exe = std::env::current_exe().map_err(err)?;
    let mut harness = json!({"rmasscan-lab":sha(&exe)?});
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/wire-lab.sh");
    if script.exists() {
        harness["wire-lab.sh"] = json!(sha(script)?);
    }
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
/// Remove personal paths and run-specific namespace names from published JSON.
pub fn scrub(v: &mut Value) {
    match v {
        Value::String(s) => {
            for prefix in ["/Users/", "/home/"] {
                let mut from = 0;
                while let Some(i) = s[from..].find(prefix) {
                    let start = from + i;
                    let after = start + prefix.len();
                    let end = s[after..]
                        .find(|c: char| c == '/' || c.is_whitespace() || c == '\"' || c == '\'')
                        .map_or(s.len(), |n| after + n);
                    s.replace_range(start..end, "$HOME");
                    from = start + 5;
                }
            }
            *s = s.replace("/root/", "$HOME/");
            for prefix in ["wl-scan-", "wl-peer-"] {
                let mut from = 0;
                while let Some(i) = s[from..].find(prefix) {
                    let start = from + i + prefix.len();
                    let end = s[start..]
                        .find(|c: char| !c.is_ascii_digit() && c != '-')
                        .map_or(s.len(), |n| start + n);
                    if end > start {
                        s.replace_range(start..end, "RUNID");
                        from = start + 5;
                    } else {
                        from = start;
                    }
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(scrub),
        Value::Object(m) => m.values_mut().for_each(scrub),
        _ => {}
    }
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
    for (k, opt) in [("scanner", "ns-a"), ("peer", "ns-b")] {
        let ns = get(a, opt)?;
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
        check_isolation_snapshot(&links, &routes, &forwarding)?;
        let endpoint = links
            .as_array()
            .and_then(|ls| ls.iter().find(|x| x["ifname"] != "lo"))
            .ok_or("veth missing")?;
        let iface = endpoint["ifname"]
            .as_str()
            .ok_or("interface name missing")?;
        if iface.contains('/') {
            return Err("invalid namespace interface".into());
        }
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
        let unreachable = Command::new("ip")
            .args(["netns", "exec", ns, "ip", "route", "get", "8.8.8.8"])
            .output()
            .map_err(err)?;
        if unreachable.status.success() {
            return Err("lab has route to external IP".into());
        }
        v[format!("{k}_route_get_8_8_8_8")] =
            json!(String::from_utf8_lossy(&unreachable.stderr).trim());
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
    write_json(get(a, "out")?, &v)?;
    Ok(0)
}

pub fn check_isolation_snapshot(
    links: &Value,
    routes: &Value,
    forwarding: &str,
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
    if routes.len() > 1
        || routes
            .iter()
            .any(|r| r["dst"] == "default" || !r["gateway"].is_null())
    {
        return Err("unexpected route or gateway in lab".into());
    }
    if forwarding.trim() != "0" {
        return Err("namespace forwarding enabled or unknown".into());
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result<i32, String> {
    let (cmd, rest) = args.split_first().ok_or("capture subcommand required")?;
    let a = opts(rest)?;
    match cmd.as_str() {
        "record" => record(&a),
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
}
