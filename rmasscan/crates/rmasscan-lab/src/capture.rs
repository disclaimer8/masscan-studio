//! Sealed Linux capture support and portable evidence manifests.
use crate::link;
use rmasscan_net::lab_io;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, process::Command, time::Duration};

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
fn responder(a: &BTreeMap<String, String>) -> Result<i32, String> {
    lab_io::install_signal_handlers().map_err(err)?;
    let ports = get(a, "ports")?;
    let mut listeners = Vec::new();
    for p in ports.split(',').filter(|s| !s.is_empty()) {
        let p = p.parse::<u16>().map_err(err)?;
        if p == 0 {
            return Err("port zero".into());
        }
        listeners
            .push(std::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, p)).map_err(err)?);
    }
    fs::write(get(a, "ready")?, format!("listening {ports}\n")).map_err(err)?;
    while !lab_io::stop_requested() {
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(listeners);
    Ok(0)
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
fn scrub_str(s: &str) -> String {
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
}
