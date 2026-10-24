//! Offline verifier for complete Windows wire evidence, including historical schema 1.
use crate::pcap::{self, Frames};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
const PASS: &str = "PASS";
const FAIL: &str = "FAIL";
const INVALID: &str = "INVALID";
const NOT_RUN: &str = "NOT RUN";
const PEER: &str = "198.18.0.2";
const PAUSE: &str = "c03_multi_ports";
const SCAN: &str = "11111111111111111111111111111111";
const A1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const A2: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
fn n(v: &Value) -> i128 {
    v.as_u64().map(i128::from).unwrap_or(-1)
}
// Report arithmetic uses a wider domain than the counters; unknown counters
// are never accepted by a numeric bound merely because they are absent.
fn received_with_duplicates(j: &Value) -> Option<u128> {
    Some(u128::from(j["received"].as_u64()?) + u128::from(j["duplicates"].as_u64()?))
}
fn integer_note(value: i128) -> Value {
    serde_json::Number::from_i128(value)
        .map(Value::Number)
        .unwrap_or_else(|| json!(value.to_string()))
}
fn f(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}
fn array(v: &Value) -> &[Value] {
    v.as_array().map(Vec::as_slice).unwrap_or(&[])
}
fn truth(v: &Value) -> bool {
    !v.is_null()
        && v != false
        && v != 0
        && v != ""
        && v.as_array().is_none_or(|x| !x.is_empty())
        && v.as_object().is_none_or(|x| !x.is_empty())
}
fn read_json(p: impl AsRef<Path>) -> Option<Value> {
    serde_json::from_slice(&fs::read(p).ok()?).ok()
}
fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{b:02x}")).collect()
}
fn ports(spec: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for tok in spec.split(',') {
        let mut p = tok.split('-');
        if let Some(lo) = p.next().and_then(|s| s.parse::<u16>().ok()) {
            let hi = p.next().and_then(|s| s.parse().ok()).unwrap_or(lo);
            out.extend(lo..=hi);
        }
    }
    out
}
fn open_ports() -> Vec<u16> {
    [vec![80, 443], (8000..8008).collect()].concat()
}
pub fn case_by_name(name: &str) -> Option<Value> {
    let (port, sp, count, rate, wait) = match name {
        "c01_one_addr_port_synack" => ("80", "40000", 1, 100, 3),
        "c02_one_addr_port_rst" => ("81", "40000", 1, 100, 3),
        "c03_multi_ports" => ("8000-8015", "40000", 16, 100, 3),
        "c04_exclude" => ("80,81,443,82", "40000", 4, 100, 3),
        "c05_srcport_single" => ("80,81,443,82", "50123", 4, 100, 3),
        "c06_srcport_range" => ("80,81,443,82", "50000-50015", 4, 100, 3),
        "x01_foreign_replies" => ("80,81,443,8099", "40000", 4, 100, 3),
        "pb_stop_silent" | "pb_stop_load" => ("8100-8119", "40000", 20, 1, 10),
        "pb_stop_drain" | "pb_stop_fullqueue" => ("80,81", "40000", 2, 1, 10),
        "pb_overflow_queue" => ("80,81,82,83,84,85", "40000", 6, 1, 10),
        "pb_linkloss" => ("8200-8399", "40000", 200, 20, 3),
        "pb_rxloss" => ("8000-8015", "40000", 16, 100, 3),
        "pb_perm_scan" => ("80", "40000", 1, 100, 3),
        _ => return None,
    };
    Some(
        json!({"name":name,"ports":port,"source_port":sp,"syn":count,"rate":rate,"wait":wait,"seed":1,"targets":if name=="c04_exclude"{"198.18.0.0/30"}else{PEER},"exclude":if name=="c04_exclude"{json!("198.18.0.0-198.18.0.1,198.18.0.3")}else{Value::Null}}),
    )
}
fn functional_cases() -> Vec<Value> {
    [
        "c01_one_addr_port_synack",
        "c02_one_addr_port_rst",
        PAUSE,
        "c04_exclude",
        "c05_srcport_single",
        "c06_srcport_range",
        "x01_foreign_replies",
    ]
    .iter()
    .filter_map(|x| case_by_name(x))
    .collect()
}
fn replies(case: &Value, silent: bool) -> Vec<String> {
    let mut a: Vec<_> = ports(s(&case["ports"]))
        .into_iter()
        .filter(|p| silent || (*p != 8099 && !(8100..8120).contains(p)))
        .map(|p| {
            format!(
                "{PEER}:{p}:{}",
                if open_ports().contains(&p) {
                    "open"
                } else {
                    "closed"
                }
            )
        })
        .collect();
    a.sort();
    a
}
pub fn cases_psv() -> String {
    functional_cases()
        .iter()
        .map(|c| {
            let r = replies(c, true);
            let o = r.iter().filter(|x| x.ends_with(":open")).count();
            format!(
                "{}|{}|{}|{}|{} -p{} --source-port {}{}\n",
                s(&c["name"]),
                n(&c["syn"]),
                o,
                r.len() - o,
                s(&c["targets"]),
                s(&c["ports"]),
                s(&c["source_port"]),
                if c["exclude"].is_null() {
                    String::new()
                } else {
                    format!(" --exclude {}", s(&c["exclude"]))
                }
            )
        })
        .collect()
}
pub fn planned(man: &Value) -> Vec<Value> {
    let mut out = Vec::new();
    if man["plan"] == "failure" {
        for sc in ["silent", "drain", "fullqueue", "load"] {
            out.push(json!({"tag":format!("stop_{sc}"),"kind":"stop","scenario":sc}));
        }
        for k in ["overflow_queue", "linkloss"] {
            out.push(json!({"tag":k,"kind":k}));
        }
        for v in [
            "wrong_ports",
            "wrong_seed",
            "corrupt_next_index",
            "corrupt_checksum",
            "truncated",
            "empty",
            "future_format",
            "future_engine",
        ] {
            out.push(json!({"tag":format!("ckpt_{v}"),"kind":"ckpt_refuse","variant":v}));
        }
        for v in ["scan", "inventory"] {
            out.push(
                json!({"tag":format!("perm_restricted_{v}"),"kind":"perm_restricted","variant":v}),
            );
        }
        out.push(json!({"tag":"perm_elevated_control","kind":"case","case":"c01_one_addr_port_synack","repeat":1}));
        out.push(json!({"tag":"rxloss","kind":"rxloss"}));
    } else {
        for c in functional_cases() {
            for r in 1..=2 {
                out.push(json!({"tag":format!("{}.run{r}",s(&c["name"])),"kind":if s(&c["name"]).starts_with('x'){"foreign"}else{"case"},"case":c["name"],"repeat":r}));
            }
        }
        for n in [0, 1, 8, 15] {
            for kind in ["pause", "resume"] {
                out.push(json!({"tag":format!("{kind}_N{n}"),"kind":kind,"n":n}));
            }
        }
        for k in ["complete_nopause", "refuse_completed"] {
            out.push(json!({"tag":k,"kind":k}));
        }
    }
    out
}
fn kind_case(it: &Value) -> Option<Value> {
    let name = match s(&it["kind"]) {
        "case" | "foreign" => s(&it["case"]),
        "stop" => match s(&it["scenario"]) {
            "silent" => "pb_stop_silent",
            "drain" => "pb_stop_drain",
            "fullqueue" => "pb_stop_fullqueue",
            _ => "pb_stop_load",
        },
        "overflow_queue" => "pb_overflow_queue",
        "linkloss" => "pb_linkloss",
        "rxloss" => "pb_rxloss",
        "perm_restricted" if it["variant"] == "inventory" => return None,
        "perm_restricted" => "pb_perm_scan",
        _ => PAUSE,
    };
    let mut c = case_by_name(name)?;
    if it["kind"] == "ckpt_refuse" {
        if it["variant"] == "wrong_ports" {
            c["ports"] = json!("8000-8014");
        }
        if it["variant"] == "wrong_seed" {
            c["seed"] = json!(2);
        }
    }
    Some(c)
}
fn arg_map(it: &Value, man: &Value, side: bool) -> BTreeMap<String, Value> {
    let mut a = BTreeMap::new();
    let c = if side {
        case_by_name(PAUSE)
    } else {
        kind_case(it)
    };
    if let Some(c) = c {
        for (k, v) in [
            ("iface", man["binding"]["iface"].clone()),
            ("src-ip", man["binding"]["src_ip"].clone()),
            (
                "src-mac",
                json!(s(&man["binding"]["src_mac"]).to_lowercase()),
            ),
            (
                "router-mac",
                json!(s(&man["binding"]["router_mac"]).to_lowercase()),
            ),
            ("targets", c["targets"].clone()),
            ("ports", c["ports"].clone()),
            ("source-port", c["source_port"].clone()),
            ("seed", json!(n(&c["seed"]).to_string())),
            ("rate", json!(n(&c["rate"]).to_string())),
            ("wait", json!(n(&c["wait"]).to_string())),
        ] {
            a.insert(format!("--{k}"), v);
        }
        if !c["exclude"].is_null() {
            a.insert("--exclude".into(), c["exclude"].clone());
        }
    }
    let mut add = |k: &str, v: Value| {
        a.insert(k.into(), v);
    };
    if side {
        for (k, v) in [
            ("--scan-id", SCAN),
            ("--attempt-id", A1),
            ("--checkpoint-out", "<any>"),
        ] {
            add(k, json!(v));
        }
        add(
            "--forge-checkpoint-next-index",
            json!(if it["kind"] == "refuse_completed" {
                "16"
            } else {
                "8"
            }),
        );
        return a;
    }
    match s(&it["kind"]) {
        "pause" | "complete_nopause" => {
            add("--scan-id", json!(SCAN));
            add("--attempt-id", json!(A1));
            add(
                "--pause-after",
                json!(if it["kind"] == "pause" {
                    n(&it["n"]).to_string()
                } else {
                    "16".into()
                }),
            );
            add("--checkpoint-out", json!("<any>"));
        }
        "resume" | "refuse_completed" | "ckpt_refuse" => {
            add("--scan-id", json!(SCAN));
            add("--attempt-id", json!(A2));
            add("--resume-checkpoint", json!("<any>"));
        }
        "stop" => {
            add("--observe-ms", json!("1500"));
            match s(&it["scenario"]) {
                "drain" => add("--stop-in-drain", json!(true)),
                "fullqueue" => {
                    add("--result-capacity", json!("2"));
                    add("--no-consume", json!(true));
                    add("--stop-after-ms", json!("4500"));
                }
                _ => add("--stop-after-ms", json!("2500")),
            }
        }
        "overflow_queue" => {
            add("--result-capacity", json!("1"));
            add("--no-consume", json!(true));
            add("--observe-ms", json!("1500"));
        }
        "linkloss" | "rxloss" => {
            add("--checkpoint-out", json!("<any>"));
            add("--observe-ms", json!("500"));
            if it["kind"] == "rxloss" {
                add("--rx-stall-ms", json!("6000"));
            }
        }
        "perm_restricted" if it["variant"] == "inventory" => add("--inventory", json!(true)),
        _ => {}
    }
    a
}
pub fn expected_args(
    it: &Value,
    man: &Value,
    paths: &BTreeMap<String, String>,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for (k, v) in arg_map(it, man, it["forge"] == true) {
        out.push(k.clone());
        if v == true {
            continue;
        }
        out.push(if v == "<any>" {
            paths
                .get(&k)
                .ok_or_else(|| format!("path required for {k}"))?
                .clone()
        } else {
            s(&v).to_owned()
        });
    }
    Ok(out)
}
#[derive(Default)]
struct Run {
    tag: String,
    checks: Vec<Value>,
    notes: BTreeMap<String, Value>,
    argv_ok: bool,
}
impl Run {
    fn new(tag: &str) -> Self {
        Self {
            tag: tag.into(),
            ..Self::default()
        }
    }
    fn add(&mut self, name: &str, result: &str, detail: impl ToString, beh: bool) {
        self.checks
            .push(json!({"name":name,"result":result,"detail":detail.to_string(),"behaviour":beh}));
    }
    fn check(&mut self, name: &str, ok: bool, detail: impl ToString, bad: &str, beh: bool) -> bool {
        self.add(name, if ok { PASS } else { bad }, detail, beh);
        ok
    }
    fn inv(&mut self, name: &str, ok: bool, detail: impl ToString) {
        self.check(name, ok, detail, INVALID, false);
    }
    fn beh(&mut self, name: &str, ok: bool, detail: impl ToString) {
        self.check(name, ok, detail, FAIL, true);
    }
    fn proven(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|c| c["result"] == INVALID || c["result"] == NOT_RUN)
    }
    fn cap(&mut self, name: &str, ok: bool, detail: impl ToString) {
        let p = self.proven();
        self.check(name, ok, detail, if p { FAIL } else { INVALID }, p);
    }
    fn behaviour_fail(&self) -> bool {
        self.argv_ok
            && self
                .checks
                .iter()
                .any(|c| c["behaviour"] == true && c["result"] == FAIL)
    }
    fn verdict(&self) -> &str {
        for v in [NOT_RUN, INVALID, FAIL, PASS] {
            if self.checks.iter().any(|c| {
                if c["result"] == FAIL && !self.argv_ok {
                    v == INVALID
                } else {
                    c["result"] == v
                }
            }) {
                return v;
            }
        }
        NOT_RUN
    }
    fn summary(&self) -> Value {
        json!({"tag":self.tag,"checks":self.checks,"notes":self.notes,"verdict":self.verdict(),"behaviour_fail":self.behaviour_fail()})
    }
}
fn parse_args(v: &Value) -> Result<BTreeMap<String, Value>, String> {
    let av = v["argv"].as_array().ok_or("argv not array")?;
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < av.len() {
        let k = av[i].as_str().ok_or("non-string argv")?;
        if !k.starts_with("--") || out.contains_key(k) {
            return Err("unexpected positional or duplicate argument".into());
        }
        let value = if i + 1 < av.len() && !s(&av[i + 1]).starts_with("--") {
            i += 1;
            av[i].clone()
        } else {
            json!(true)
        };
        out.insert(k.into(), value);
        i += 1;
    }
    Ok(out)
}
fn verify_argv(r: &mut Run, it: &Value, man: &Value, d: &Path) {
    let mut ok = true;
    for (side, name) in [(false, "argv.json"), (true, "forge-argv.json")] {
        if side && it["kind"] != "refuse_completed" && it["kind"] != "ckpt_refuse" {
            continue;
        }
        let Some(av) = read_json(d.join(name)) else {
            r.add(name, NOT_RUN, "missing or invalid JSON", false);
            ok = false;
            continue;
        };
        let want = arg_map(it, man, side);
        let good = parse_args(&av).is_ok_and(|got| {
            got.len() == want.len()
                && want.iter().all(|(k, v)| {
                    got.get(k).is_some_and(|g| {
                        g == v || (v == "<any>" && g.as_str().is_some_and(|s| !s.is_empty()))
                    })
                })
        });
        ok = r.check(
            &format!("{name} matches run kind definition"),
            good,
            av.to_string(),
            INVALID,
            false,
        ) && ok;
    }
    r.argv_ok = ok;
}
#[derive(Clone)]
struct Binding {
    src: String,
    sm: String,
    pm: String,
}
impl Binding {
    fn new(m: &Value) -> Self {
        Self {
            src: s(&m["src_ip"]).into(),
            sm: s(&m["src_mac"]).to_lowercase(),
            pm: s(&m["router_mac"]).to_lowercase(),
        }
    }
}
struct Tcp {
    sm: String,
    dm: String,
    src: String,
    dst: String,
    sp: u16,
    dp: u16,
    flags: u8,
    id: u16,
}
fn tcp(b: &[u8]) -> Option<Tcp> {
    if b.len() < 54 || b[12..14] != [8, 0] || b[23] != 6 || b[14] >> 4 != 4 {
        return None;
    }
    let h = (b[14] & 15) as usize * 4;
    let o = 14 + h;
    if h < 20 || b.len() < o + 20 {
        return None;
    }
    let mac = |o| {
        b[o..o + 6]
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let ip = |o| {
        b[o..o + 4]
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".")
    };
    Some(Tcp {
        sm: mac(6),
        dm: mac(0),
        src: ip(26),
        dst: ip(30),
        sp: u16::from_be_bytes([b[o], b[o + 1]]),
        dp: u16::from_be_bytes([b[o + 2], b[o + 3]]),
        flags: b[o + 13] & 63,
        id: u16::from_be_bytes([b[18], b[19]]),
    })
}
fn sports(c: &Value) -> (u16, u16) {
    let p = ports(s(&c["source_port"]));
    (*p.first().unwrap_or(&1), *p.last().unwrap_or(&65535))
}
fn syns(fr: &Frames, b: &Binding, sp: (u16, u16)) -> Frames {
    fr.iter()
        .filter(|(_, f)| {
            pcap::is_syn(f)
                && tcp(f).is_some_and(|i| {
                    i.sm == b.sm
                        && i.dm == b.pm
                        && i.src == b.src
                        && i.dst == PEER
                        && (sp.0..=sp.1).contains(&i.sp)
                })
        })
        .cloned()
        .collect()
}
fn wire_replies(fr: &Frames, b: &Binding, sp: Option<(u16, u16)>) -> Vec<String> {
    fr.iter()
        .filter_map(|(_, f)| tcp(f))
        .filter(|i| {
            i.sm == b.pm
                && i.dm == b.sm
                && i.dst == b.src
                && i.id != 0xf0e1
                && sp.is_none_or(|sp| (sp.0..=sp.1).contains(&i.dp))
        })
        .filter_map(|i| {
            if i.flags & 0x12 == 0x12 {
                Some(format!("{}:{}:open", i.src, i.sp))
            } else if i.flags & 4 != 0 {
                Some(format!("{}:{}:closed", i.src, i.sp))
            } else {
                None
            }
        })
        .collect()
}
fn unique(x: Vec<String>) -> Vec<String> {
    x.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}
fn load_pcap(r: &mut Run, p: &Path) -> Option<(Frames, Vec<u8>)> {
    let name = p.file_name().unwrap_or_default().to_string_lossy();
    let Ok(data) = fs::read(p) else {
        r.add(&format!("{name} present"), NOT_RUN, "missing", false);
        return None;
    };
    match pcap::read_pcap_records(&data) {
        Ok((_, fr)) => {
            r.add(&format!("{name} complete pcap"), PASS, fr.len(), false);
            Some((fr, data))
        }
        Err(e) => {
            r.add(&format!("{name} complete pcap"), INVALID, e, false);
            None
        }
    }
}
fn ether(f: &[u8], typ: [u8; 2]) -> bool {
    f.get(12..14) == Some(typ.as_slice())
}
fn capture_command(c: &Value, who: &str, b: &Binding, netns: &str) -> bool {
    let all: Vec<_> = array(&c["cmd"]).iter().filter_map(Value::as_str).collect();
    // The only accepted prefix is an optional `sudo -n`. The peer capture must run inside
    // the manifest namespace; the eno1 capture must run in the host namespace.
    let mut rest = all.as_slice();
    if let ["sudo", "-n", tail @ ..] = rest {
        rest = tail;
    }
    let rest = if who == "peer" {
        match rest {
            ["ip", "netns", "exec", ns, tail @ ..] if !netns.is_empty() && *ns == netns => tail,
            _ => return false,
        }
    } else {
        rest
    };
    let ["tcpdump", av @ ..] = rest else {
        return false;
    };
    let iface = if who == "peer" { "lab0" } else { "eno1" };
    let mut i = 0;
    let mut found = false;
    let mut tail = Vec::new();
    while i < av.len() {
        match av[i] {
            "-i" => {
                if i + 1 >= av.len() || av[i + 1] != iface || found {
                    return false;
                }
                found = true;
                i += 2;
            }
            "-w" | "-B" | "-s" | "-Z" => {
                if i + 1 >= av.len() {
                    return false;
                }
                i += 2;
            }
            "-n" | "-nn" | "-U" | "--immediate-mode" | "-p" => i += 1,
            x if x.starts_with('-') => return false,
            _ => {
                tail.extend_from_slice(&av[i..]);
                break;
            }
        }
    }
    if !found {
        return false;
    }
    let filter = s(&c["filter"]);
    let actual = tail.join(" ");
    let actual = actual.trim_matches('\'').trim_matches('"');
    if who == "peer" {
        actual.is_empty() && (filter.is_empty() || filter == "(none: every frame on lab0)")
    } else {
        let want = format!(
            "net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host {} or ether host {} or ether proto 0x88b5",
            b.sm, b.pm
        );
        (filter == want || filter == format!("{want} or ether proto 0x88b6")) && actual == filter
    }
}
struct Ctx {
    d: PathBuf,
    rj: Value,
    meta: Value,
    peer: Option<(Frames, Vec<u8>)>,
    bind: Binding,
}
fn capture(r: &mut Run, man: &Value, ctx: &Ctx, cap: &Value, eno: &Option<(Frames, Vec<u8>)>) {
    let b = &ctx.bind;
    for (who, p) in [("peer", &ctx.peer), ("eno1", eno)] {
        let c = &cap[who];
        r.inv(
            &format!("{who} capture interface and filter are exact"),
            capture_command(c, who, b, s(&man["stand"]["netns"])),
            c["cmd"].to_string(),
        );
        if let Some((fr, data)) = p {
            let rec = &c["pcap"];
            r.inv(
                &format!("{who} pcap hash, size and count"),
                rec["sha256"] == sha(data)
                    && n(&rec["size"]) == data.len() as i128
                    && n(&rec["frames"]) == fr.len() as i128,
                rec.to_string(),
            );
            let st = &c["tcpdump"];
            let measured = ["captured", "received", "dropped_kernel"]
                .iter()
                .all(|k| st[k].as_u64().is_some())
                && (st["dropped_if"].as_u64().is_some()
                    || (st["dropped_if"].is_null()
                        && c["interface_drop_delta"].as_u64().is_some()));
            let interface_clean = (st["dropped_if"].as_u64() == Some(0)
                || (st["dropped_if"].is_null() && c["interface_drop_delta"].as_u64() == Some(0)))
                && c.get("interface_drop_delta")
                    .is_none_or(|delta| delta.as_u64() == Some(0));
            r.inv(
                &format!("{who} tcpdump statistics measured"),
                measured,
                st.to_string(),
            );
            r.inv(
                &format!("{who} capture no drops and all frames accounted"),
                measured
                    && st["dropped_kernel"] == 0
                    && interface_clean
                    && n(&st["captured"]) == fr.len() as i128
                    && st["captured"] == st["received"],
                st.to_string(),
            );
            r.inv(
                &format!("{who} listening before guest"),
                c["listening"] == true,
                "",
            );
        }
    }
    if let Some((fr, _)) = &ctx.peer {
        let cn = &cap["peer"]["counters"];
        let ints = [
            "rx_before",
            "tx_before",
            "rx_ready",
            "tx_ready",
            "rx_end",
            "tx_end",
        ]
        .iter()
        .all(|k| cn[k].as_u64().is_some());
        let lo = n(&cn["rx_end"]) - n(&cn["rx_ready"]) + n(&cn["tx_end"]) - n(&cn["tx_ready"]);
        let hi = n(&cn["rx_end"]) - n(&cn["rx_before"]) + n(&cn["tx_end"]) - n(&cn["tx_before"]);
        r.inv(
            "peer interface counter window",
            ints && ["rx", "tx"].iter().all(|prefix| {
                let before = n(&cn[format!("{prefix}_before")]);
                let ready = n(&cn[format!("{prefix}_ready")]);
                let end = n(&cn[format!("{prefix}_end")]);
                before <= ready && ready <= end
            }) && lo >= 0
                && hi >= lo
                && (lo..=hi).contains(&(fr.len() as i128)),
            cn.to_string(),
        );
        r.inv(
            "readiness marker captured",
            fr.iter().any(|(_, f)| ether(f, [0x88, 0xb5])),
            "",
        );
        let schema = cap["capture_schema"].as_u64().unwrap_or(1);
        r.inv(
            "capture schema not older than manifest",
            schema >= man["capture_schema"].as_u64().unwrap_or(1),
            schema,
        );
        if schema >= 2 {
            let ends: Vec<_> = fr
                .iter()
                .filter(|(_, f)| {
                    ether(f, [0x88, 0xb5]) && f.get(14..25) == Some(b"WIRELAB-END".as_slice())
                })
                .map(|(t, _)| *t)
                .collect();
            let end = ends.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            r.inv(
                "end marker and flushed capture tail",
                !ends.is_empty() && !fr.iter().any(|(t, f)| !ether(f, [0x88, 0xb5]) && *t > end),
                "",
            );
            r.inv(
                "immediate capture mode",
                ["peer", "eno1"].iter().all(|k| {
                    array(&cap[k]["cmd"])
                        .iter()
                        .any(|v| v == "--immediate-mode")
                }),
                "",
            );
        } else {
            r.add(
                "historical schema 1: no end-marker requirement",
                PASS,
                "tail protection absent",
                false,
            );
        }
        r.inv(
            "capture reached quiescence",
            cap["quiet"]["reached"] == true && f(&cap["quiet"]["quiet_s"]) >= 1.,
            cap["quiet"].to_string(),
        );
        let ts: Vec<_> = [
            "capture_started_utc",
            "guest_started_utc",
            "guest_finished_utc",
            "capture_stopped_utc",
        ]
        .iter()
        .map(|k| f(&ctx.meta[k]))
        .collect();
        r.inv(
            "capture encloses guest in UTC",
            ts.iter().all(|x| x.is_finite()) && ts.windows(2).all(|w| w[0] <= w[1]),
            format!("{ts:?}"),
        );
    }
    if let Some((fr, _)) = eno {
        r.check(
            "eno1 saw zero lab packets",
            fr.is_empty(),
            fr.len(),
            FAIL,
            false,
        );
    }
    for name in ["status-pre", "status-post", "guest-verify", "listeners"] {
        let Some(v) = read_json(ctx.d.join(format!("{name}.json"))) else {
            r.add(name, NOT_RUN, "missing or invalid JSON", false);
            continue;
        };
        let ok = match name {
            "status-pre" | "status-post" => {
                v["raw_run_allowed"] == true && !truth(&v["isolation_violations"])
            }
            "guest-verify" => v["ok"] == true,
            _ => {
                let mut op: Vec<_> = array(&v["open"]).iter().filter_map(Value::as_u64).collect();
                op.sort();
                let mut want: Vec<_> = open_ports().iter().map(|n| *n as u64).collect();
                want.sort();
                let silent = if man["listeners"]["silent"].is_array() {
                    man["listeners"]["silent"].clone()
                } else {
                    json!([8099])
                };
                op == want
                    && v["ready"] == true
                    && v["silent"] == silent
                    && array(&v["silent"]).contains(&json!(8099))
                    && v["silent_proven"] == true
            }
        };
        r.inv(&format!("{name} valid before/after run"), ok, v.to_string());
    }
    // From capture schema 3 the invocation nonce chain is mandatory: a run without it has no
    // binding between the gate and this scanner invocation. Schema 1/2 archives predate the
    // contract and keep an exemption that the verdict states.
    let chain_schema = cap["capture_schema"]
        .as_u64()
        .unwrap_or(1)
        .max(man["capture_schema"].as_u64().unwrap_or(1));
    let nonce = ctx.meta.get("invocation_nonce");
    if chain_schema >= 3 {
        r.inv(
            "invocation nonce recorded (capture schema 3 requires the chain)",
            nonce.and_then(Value::as_str).is_some_and(|s| !s.is_empty()),
            nonce.map_or("missing".into(), Value::to_string),
        );
        r.inv(
            "guest Verify exit code recorded and zero",
            ctx.meta.get("guest_verify_exit").and_then(Value::as_i64) == Some(0),
            ctx.meta
                .get("guest_verify_exit")
                .map_or("missing".into(), Value::to_string),
        );
        for name in ["guest-verify-stdout.txt", "guest-verify-stderr.txt"] {
            r.inv(
                &format!("{name} recorded"),
                ctx.d.join(name).is_file(),
                name,
            );
        }
        let pre = read_json(ctx.d.join("status-pre.json"));
        let bound = pre.as_ref().map(|v| v["guest_verify_nonce"].clone());
        r.inv(
            "status-pre carries this invocation's guest Verify nonce",
            matches!((nonce.and_then(Value::as_str), bound.as_ref().and_then(Value::as_str)), (Some(a), Some(b)) if !a.is_empty() && a == b),
            bound.map_or("status-pre missing".into(), |v| v.to_string()),
        );
    } else if nonce.is_none() {
        r.add(
            &format!("historical schema {chain_schema}: invocation nonce chain not required"),
            PASS,
            "directory predates capture schema 3, which makes the chain mandatory",
            false,
        );
    }
    if let Some(id) = nonce {
        let gv = read_json(ctx.d.join("guest-verify.json"));
        r.inv(
            "guest Verify belongs to this invocation",
            id.as_str().is_some_and(|s| !s.is_empty())
                && gv.as_ref().is_some_and(|v| v["verification_nonce"] == *id),
            id.to_string(),
        );
        match read_json(ctx.d.join("run-artifacts.json")) {
            None => r.add(
                "current invocation artifact hashes present",
                if chain_schema >= 3 { INVALID } else { NOT_RUN },
                "run-artifacts.json missing",
                false,
            ),
            Some(proof) => {
                r.inv(
                    "artifact hashes belong to this invocation",
                    proof["invocation_nonce"] == *id,
                    proof["invocation_nonce"].to_string(),
                );
                let files = proof["files"].as_object();
                r.inv(
                    "invocation proof covers result, runner, arguments and preflight",
                    files.is_some_and(|files| {
                        [
                            "run.json",
                            "guest-runner.json",
                            "argv.json",
                            "guest-verify.json",
                        ]
                        .iter()
                        .all(|k| files.contains_key(*k))
                    }),
                    "",
                );
                if let Some(files) = files {
                    for (name, expected) in files {
                        let path = Path::new(name);
                        let contained = !name.is_empty()
                            && path.components().count() == 1
                            && matches!(
                                path.components().next(),
                                Some(std::path::Component::Normal(_))
                            );
                        let actual = contained.then(|| fs::read(ctx.d.join(path)).ok()).flatten();
                        r.inv(
                            &format!("current invocation hash of {name}"),
                            actual
                                .as_ref()
                                .is_some_and(|bytes| expected == &json!(sha(bytes))),
                            expected.to_string(),
                        );
                    }
                }
            }
        }
    }
    if let Some(rc) = ctx.meta.get("guest_ssh_rc") {
        r.inv(
            "guest runner transport completed successfully",
            rc == 0,
            rc.to_string(),
        );
    }
    if let Some(id) = ctx.meta.get("run_id") {
        for name in ["run.json", "guest-verify.json"] {
            let v = if name == "run.json" {
                Some(ctx.rj.clone())
            } else {
                read_json(ctx.d.join(name))
            };
            r.inv(
                &format!("{name} belongs to current run"),
                truth(id) && v.as_ref().is_some_and(|v| v["run_id"] == *id),
                id.to_string(),
            );
        }
    }
}
fn job(r: &mut Run, j: &Value, c: &Value, man: &Value) {
    let mut want = json!({"iface":man["binding"]["iface"],"src_ip":man["binding"]["src_ip"],"src_mac":s(&man["binding"]["src_mac"]).to_lowercase(),"router_mac":s(&man["binding"]["router_mac"]).to_lowercase(),"retries":0,"shard":"1/1","blackrock_rounds":14});
    for k in [
        "source_port",
        "targets",
        "exclude",
        "ports",
        "seed",
        "rate",
        "wait",
    ] {
        want[k] = c[k].clone();
    }
    let ok = want
        .as_object()
        .unwrap()
        .iter()
        .all(|(k, v)| j["job"][k] == *v);
    r.beh(
        "job echo matches requested case and binding",
        ok,
        j["job"].to_string(),
    );
}
fn health(j: &Value) -> bool {
    j["rx_health"]["kernel_drops"].as_u64() == Some(0)
        && j["net"]["kernel_drops"].as_u64() == Some(0)
}
fn clean(j: &Value) -> bool {
    ["tx_uncertain", "tx_errors", "rx_errors"]
        .iter()
        .all(|k| j["net"][k].as_u64() == Some(0))
}
fn frozen(j: &Value) -> bool {
    j["net"]["tx_sent"].as_u64().is_some()
        && ["tx_sent_at_join", "tx_sent_after_observe", "sent"]
            .iter()
            .all(|k| j[k] == j["net"]["tx_sent"])
}
fn fixture(
    r: &mut Run,
    root: &Path,
    fx: &Value,
    c: &Value,
    b: &Binding,
) -> Option<(Frames, Vec<u8>)> {
    let ent = &fx["fixtures"][format!("{}.run1", s(&c["name"]))];
    if ent.is_null() {
        r.add("oracle fixture listed", NOT_RUN, "no entry", false);
        return None;
    }
    let file = Path::new(s(&ent["file"]));
    if file.is_absolute()
        || file
            .components()
            .any(|x| matches!(x, std::path::Component::ParentDir))
    {
        r.add(
            "fixture path contained",
            INVALID,
            "path escapes evidence root",
            false,
        );
        return None;
    }
    let p = load_pcap(r, &root.join(file))?;
    r.inv(
        "oracle fixture hash",
        ent["sha256"] == sha(&p.1),
        ent.to_string(),
    );
    let all = p.0.iter().filter(|(_, f)| pcap::is_syn(f)).count();
    r.inv(
        "every fixture SYN carries exact binding",
        all > 0 && syns(&p.0, b, sports(c)).len() == all,
        all,
    );
    Some(p)
}
fn fixture_binding(r: &mut Run, fx: &Value, b: &Binding) {
    let bb = &fx["binding"];
    r.inv(
        "oracle fixture binding identical without normalization",
        s(&bb["src_ip"]) == b.src
            && s(&bb["src_mac"]).to_lowercase() == b.sm
            && s(&bb["router_mac"]).to_lowercase() == b.pm
            && (bb["seed"] == 1 || bb["seed"] == "1")
            && (bb["rate"] == 100 || bb["rate"] == "100"),
        bb.to_string(),
    );
    r.inv(
        "oracle hash, pinned revision, clean tree and all fixtures valid",
        truth(&fx["oracle"]["sha256"])
            && truth(&fx["oracle"]["git_commit"])
            && fx["oracle"]["git_tree_clean"] == true
            && fx["all_valid"] == true,
        fx["oracle"].to_string(),
    );
}
fn continuous(r: &mut Run, root: &Path, man: &Value, fx: &Value, ctx: &Ctx, c: &Value) {
    let j = &ctx.rj;
    let count = n(&c["syn"]);
    let exp = replies(c, false);
    job(r, j, c, man);
    r.beh(
        "guest exit code zero",
        ctx.meta["guest_exit"] == 0,
        ctx.meta["guest_exit"].to_string(),
    );
    r.beh(
        "outcome Completed",
        j["status"] == "ok" && j["reason"] == "Completed",
        j["reason"].to_string(),
    );
    r.beh(
        "sent, next index, range and expected total equal expected probes",
        ["sent", "next_index", "range", "expected_total"]
            .iter()
            .all(|k| n(&j[k]) == count),
        count,
    );
    r.beh(
        "RX drops are measured zero",
        health(j),
        j["rx_health"].to_string(),
    );
    r.beh(
        "net TX count consistent and no errors",
        j["net"]["tx_sent"] == j["sent"] && clean(j),
        j["net"].to_string(),
    );
    r.beh(
        "results equal listener truth with no duplicates",
        j["replies"] == json!(exp)
            && n(&j["reply_total"]) == exp.len() as i128
            && j["reply_unique"] == j["reply_total"],
        j["replies"].to_string(),
    );
    if let Some((fr, data)) = &ctx.peer {
        if let Some((ff, fb)) = fixture(r, root, fx, c, &ctx.bind) {
            let (code, msg) = pcap::compare_bytes(&fb, &[data], None, &[]);
            r.add(
                "SYN bytes and order equal C oracle",
                [PASS, FAIL, INVALID][code as usize],
                msg,
                false,
            );
            r.check(
                "no SYN other than scanner",
                fr.iter().filter(|(_, f)| pcap::is_syn(f)).count() == count as usize
                    && syns(fr, &ctx.bind, sports(c)).len() == count as usize,
                count,
                FAIL,
                false,
            );
            r.check(
                "C oracle wire replies equal listener truth",
                unique(wire_replies(&ff, &ctx.bind, None)) == replies(c, true),
                "",
                FAIL,
                false,
            );
        }
        let wire = wire_replies(fr, &ctx.bind, Some(sports(c)));
        r.check(
            "peer wire replies equal results",
            unique(wire.clone()) == exp
                && received_with_duplicates(j).is_some_and(|count| count <= wire.len() as u128),
            wire.len(),
            FAIL,
            false,
        );
    }
}
fn strays(fr: &Frames, b: &Binding, sp: (u16, u16)) -> usize {
    let sy = syns(fr, b, sp);
    let (Some(first), Some(last)) = (sy.first(), sy.last()) else {
        return 0;
    };
    fr.iter()
        .filter(|(t, f)| {
            if f.len() < 14 || *t < first.0 || *t > last.0 + 3. || ether(f, [0x88, 0xb5]) {
                return false;
            }
            let mac = |o| {
                f[o..o + 6]
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            };
            if !(mac(0) == b.sm || f[0] & 1 != 0) || mac(6) == b.sm {
                return false;
            }
            if let Some(i) = tcp(f)
                && (i.id == 0xf0e1
                    || i.sm == b.pm
                        && i.dst == b.src
                        && (sp.0..=sp.1).contains(&i.dp)
                        && (i.flags & 0x12 == 0x12 || i.flags & 4 != 0))
            {
                return false;
            }
            true
        })
        .count()
}
fn foreign(r: &mut Run, ctx: &Ctx, c: &Value) {
    let j = &ctx.rj;
    let exp = replies(c, false);
    r.beh(
        "no foreign reply became a result",
        j["replies"] == json!(exp),
        j["replies"].to_string(),
    );
    let Some(inj) = read_json(ctx.d.join("injector.json")) else {
        r.add("injector.json present", NOT_RUN, "missing", false);
        return;
    };
    let ns = ctx
        .peer
        .as_ref()
        .map_or(0, |(fr, _)| strays(fr, &ctx.bind, sports(c)));
    let sent = n(&inj["sent_total"]);
    let discarded = n(&j["discarded"]);
    r.beh(
        "discarded at least injected plus observed strays",
        sent >= 0 && discarded >= sent + ns as i128,
        format!("{discarded} >= {sent} + {ns}"),
    );
    if let Some((fr, _)) = &ctx.peer {
        let ff: Vec<_> = fr
            .iter()
            .filter(|(_, f)| tcp(f).is_some_and(|i| i.id == 0xf0e1))
            .collect();
        r.inv(
            "all foreign injection kinds reached the wire",
            sent > 0
                && ff.len() as i128 == sent
                && [
                    "other_ip",
                    "unscanned_port",
                    "wrong_cookie",
                    "wrong_dst_port",
                ]
                .iter()
                .all(|k| n(&inj["kinds"][k]) > 0),
            inj.to_string(),
        );
        let sy = syns(fr, &ctx.bind, sports(c));
        if let (Some(first), Some(last)) = (sy.first(), sy.last()) {
            r.inv(
                "foreign frames inside receive window",
                ff.iter().any(|(t, _)| *t >= first.0 && *t <= last.0 + 3.),
                ff.len(),
            );
        }
        r.notes.insert("strays_in_rx_window".into(), json!(ns));
        r.notes.insert("injected".into(), json!(sent));
        r.cap(
            "no unexplained discards",
            discarded <= sent + ns as i128,
            format!("{discarded} <= {sent} + {ns}"),
        );
        let genuine = wire_replies(fr, &ctx.bind, Some(sports(c))).len();
        r.check(
            "duplicates are genuine peer retransmits only",
            received_with_duplicates(j).is_some_and(|count| count <= genuine as u128),
            genuine,
            FAIL,
            false,
        );
    }
}
fn checkpoint(r: &mut Run, ctx: &Ctx, it: &Value) {
    let p = ctx.d.join("checkpoint.bin");
    let Ok(bytes) = fs::read(&p) else {
        r.add("checkpoint.bin present", NOT_RUN, "missing", false);
        return;
    };
    let j = &ctx.rj;
    let valid = bytes.len() == 120
        && bytes.get(..8) == Some(b"RMSCNCKP".as_slice())
        && bytes.get(8..12) == Some(1u32.to_be_bytes().as_slice())
        && bytes.get(12..16) == Some(1u32.to_be_bytes().as_slice())
        && Sha256::digest(&bytes[..88]).as_slice() == &bytes[88..];
    r.beh(
        "exported checkpoint format and checksum valid",
        valid,
        format!("{} bytes", bytes.len()),
    );
    if !valid {
        return;
    }
    let ni = u64::from_be_bytes(bytes[80..88].try_into().unwrap());
    let av = read_json(ctx.d.join("argv.json"))
        .and_then(|v| parse_args(&v).ok())
        .unwrap_or_default();
    r.beh(
        "checkpoint bytes match summary, job digest and requested identity",
        hex(&bytes) == s(&j["checkpoint_hex"])
            && hex(&bytes[16..32]) == s(&j["scan_id"])
            && hex(&bytes[32..48]) == s(&j["attempt_id"])
            && hex(&bytes[48..80]) == s(&j["job"]["job_digest"])
            && ni == it["n"].as_u64().unwrap_or(u64::MAX)
            && j["checkpoint_next_index"] == json!(ni)
            && av.get("--scan-id") == Some(&j["scan_id"])
            && av.get("--attempt-id") == Some(&j["attempt_id"]),
        ni,
    );
}
fn workers(r: &mut Run, j: &Value) {
    let w = &j["workers"];
    let res = &j["resources"];
    let ids = w["tx_tid"].as_u64().is_some() && w["rx_tid"].as_u64().is_some();
    r.beh(
        "TX and RX OS thread identities measured",
        ids,
        w.to_string(),
    );
    r.beh(
        "TX and RX workers gone after join",
        ids && w["tx_alive_after_join"] == false && w["rx_alive_after_join"] == false,
        w.to_string(),
    );
    let (a, b, c) = (
        n(&res["fds_before_open"]),
        n(&res["fds_open"]),
        n(&res["fds_after_join"]),
    );
    r.beh(
        "adapter handles open during scan and closed after join",
        a >= 0 && b > a && c >= 0 && c <= a + 2,
        res.to_string(),
    );
}
fn align(r: &mut Run, ctx: &Ctx, c: &Value, uncertain: bool) -> Option<f64> {
    let (fr, _) = ctx.peer.as_ref()?;
    let sy = syns(fr, &ctx.bind, sports(c));
    let j = &ctx.rj;
    let tx = n(&j["net"]["tx_sent"]);
    let unc = n(&j["net"]["tx_uncertain"]);
    r.cap(
        "wire SYN count equals confirmed TX (plus allowed uncertainty)",
        sy.len() as i128 == tx
            || uncertain && tx >= 0 && unc >= 0 && (tx..=tx + unc).contains(&(sy.len() as i128)),
        format!("wire={} tx={tx} uncertain={unc}", sy.len()),
    );
    let Some(first) = sy.first() else {
        r.add("clock alignment", INVALID, "no scanner SYN", false);
        return None;
    };
    let guest_first = f(&j["wall"]["t0_utc_ms"]) / 1000. + f(&j["timing"]["first_send_s"]);
    let end = f(&j["wall"]["outcome_utc_ms"]) / 1000.;
    if !guest_first.is_finite() || !end.is_finite() {
        r.add(
            "wall clock fields present",
            INVALID,
            j["wall"].to_string(),
            false,
        );
        return None;
    }
    let offset = first.0 - guest_first;
    let outcome = end + offset;
    let after = sy.iter().filter(|(t, _)| *t > outcome + 0.02).count();
    r.notes
        .insert("clock_offset_ms".into(), json!(offset * 1000.));
    r.notes.insert(
        "alignment".into(),
        json!("peer first SYN minus guest confirmed send wall clock"),
    );
    r.notes.insert("outcome_peer_ts".into(), json!(outcome));
    r.notes.insert("syn_after_outcome".into(), json!(after));
    r.notes.insert(
        "last_syn_to_outcome_ms".into(),
        json!((outcome - sy.last().unwrap().0) * 1000.),
    );
    r.cap(
        "no SYN after terminal outcome (20 ms margin)",
        after == 0,
        after,
    );
    Some(outcome)
}
fn flood(r: &mut Run, ctx: &Ctx, c: &Value, outcome: Option<f64>, overlap: bool) {
    let Some(fl) = read_json(ctx.d.join("flood.json")) else {
        r.add("flood.json present", NOT_RUN, "missing", false);
        return;
    };
    if let Some((fr, _)) = &ctx.peer {
        let count = fr.iter().filter(|(_, f)| ether(f, [0x88, 0xb6])).count();
        r.inv(
            "every flooded frame on peer wire",
            n(&fl["sent"]) > 0 && n(&fl["sent"]) == count as i128 && fl["errors"] == 0,
            format!("wire={count} flood={fl}"),
        );
        if overlap {
            let sy = syns(fr, &ctx.bind, sports(c));
            if let (Some(first), Some(end)) = (sy.first(), outcome) {
                r.inv(
                    "flood overlaps scan and terminal outcome",
                    f(&fl["t_first"]) < first.0 && f(&fl["t_last"]) > end,
                    fl.to_string(),
                );
            }
        }
    }
    r.notes.insert("flood".into(), fl);
}
fn stop(r: &mut Run, ctx: &Ctx, it: &Value, c: &Value, man: &Value) {
    let j = &ctx.rj;
    let tm = &j["timing"];
    job(r, j, c, man);
    r.beh(
        "Stop exits zero, Stopped, no failure detail",
        ctx.meta["guest_exit"] == 0
            && j["status"] == "ok"
            && j["reason"] == "Stopped"
            && j["fail_detail"] == "",
        j["reason"].to_string(),
    );
    r.beh(
        "Stop to outcome and join under 1000 ms measured",
        tm["stop_requested"] == true
            && (0. ..1000.).contains(&f(&tm["stop_to_outcome_ms"]))
            && (0. ..1000.).contains(&f(&tm["join_ms"])),
        tm.to_string(),
    );
    r.beh(
        "Stop has no checkpoint",
        j["checkpoint"] == false && j["checkpoint_hex"].is_null(),
        "",
    );
    r.beh(
        "Stop RX measured zero and no TX/RX errors",
        health(j) && clean(j),
        j["net"].to_string(),
    );
    r.beh(
        "TX frozen through at least one second observation",
        frozen(j) && n(&j["observe_ms"]) >= 1000,
        j["observe_ms"].to_string(),
    );
    let exp = replies(c, false);
    match s(&it["scenario"]) {
        "silent" | "load" => r.beh(
            "Stop mid-TX with empty receive path",
            n(&j["sent"]) > 0 && n(&j["sent"]) < n(&j["range"]) && j["reply_total"] == 0,
            j["sent"].to_string(),
        ),
        "drain" => r.beh(
            "Stop during drain skips ten second wait",
            j["sent"] == c["syn"]
                && j["range"] == c["syn"]
                && f(&tm["total_s"]) < 6.
                && j["replies"] == json!(exp),
            tm.to_string(),
        ),
        _ => r.beh(
            "full result queue kept both genuine replies",
            j["replies"] == json!(exp) && j["reply_total"] == 2 && j["sent"] == c["syn"],
            j["replies"].to_string(),
        ),
    }
    workers(r, j);
    if it["scenario"] == "load" {
        r.beh(
            "RX load reached capture handle",
            n(&j["net"]["rx_packets"]) >= 1000,
            j["net"].to_string(),
        );
    }
    let end = align(r, ctx, c, false);
    if it["scenario"] == "load" && ctx.peer.is_some() {
        flood(r, ctx, c, end, true);
    }
}
fn overflow(r: &mut Run, ctx: &Ctx, c: &Value, man: &Value) {
    let j = &ctx.rj;
    job(r, j, c, man);
    r.beh(
        "queue overflow fails ConsumerTooSlow, partial scan, no checkpoint",
        ctx.meta["guest_exit"] == 3
            && j["reason"] == "Failed"
            && s(&j["fail_detail"]).contains("ConsumerTooSlow")
            && j["checkpoint"] == false
            && j["checkpoint_hex"].is_null()
            && n(&j["sent"]) > 0
            && n(&j["sent"]) < n(&j["range"]),
        j["fail_detail"].to_string(),
    );
    r.beh(
        "TX frozen after queue failure without TX error",
        frozen(j) && j["net"]["tx_errors"] == 0,
        j["net"].to_string(),
    );
    let exp = replies(c, false);
    r.beh(
        "kept queue results genuine",
        array(&j["replies"])
            .iter()
            .all(|v| exp.iter().any(|x| v == x)),
        j["replies"].to_string(),
    );
    workers(r, j);
    align(r, ctx, c, false);
}
fn linkloss(r: &mut Run, ctx: &Ctx, c: &Value, man: &Value) {
    let j = &ctx.rj;
    job(r, j, c, man);
    r.beh(
        "NIC disconnect fails TxUncertain, partial scan, no checkpoint",
        ctx.meta["guest_exit"] == 3
            && j["reason"] == "Failed"
            && s(&j["fail_detail"]).contains("TxUncertain")
            && j["checkpoint"] == false
            && j["checkpoint_hex"].is_null()
            && n(&j["sent"]) > 0
            && n(&j["sent"]) < n(&j["range"])
            && n(&j["net"]["tx_uncertain"]) >= 1,
        j["fail_detail"].to_string(),
    );
    r.beh(
        "uncertain TX not retried or counted, confirmed TX frozen",
        frozen(j),
        j["net"].to_string(),
    );
    r.beh(
        "no checkpoint file on guest",
        ctx.meta["checkpoint_file_exists"] == false,
        "",
    );
    workers(r, j);
    let le = read_json(ctx.d.join("linkloss.json"));
    let end = align(r, ctx, c, true);
    if let Some(ll) = le {
        let down = array(&ll["events"])
            .iter()
            .find(|v| v["set_link"] == "down");
        let up = array(&ll["events"]).iter().find(|v| v["set_link"] == "up");
        r.inv(
            "lab link down after first SYN then restored with successful QMP",
            ll["first_syn_seen"] == true
                && down.zip(up).is_some_and(|(d, u)| {
                    f(&d["t"]) < f(&u["t"])
                        && d["reply"].get("return").is_some()
                        && u["reply"].get("return").is_some()
                }),
            ll.to_string(),
        );
        if let (Some(d), Some(e)) = (down, end) {
            let lag = e - f(&d["t"]);
            r.notes
                .insert("down_to_outcome_ms".into(), json!(lag * 1000.));
            r.inv(
                "failure promptly follows disconnect",
                (0. ..3.).contains(&lag),
                lag,
            );
            if let Some(u) = up {
                r.inv("link restored after outcome", f(&u["t"]) > e, "");
            }
        }
    } else {
        r.add("linkloss.json present", NOT_RUN, "missing", false);
    }
}
fn rxloss(r: &mut Run, ctx: &Ctx, c: &Value, man: &Value) {
    let j = &ctx.rj;
    job(r, j, c, man);
    let Some(drops) = j["rx_health"]["kernel_drops"].as_u64().filter(|x| *x > 0) else {
        r.add(
            "RX overflow reproduced with measured drops",
            NOT_RUN,
            format!("NOT REPRODUCED: {}", j["rx_health"]),
            false,
        );
        return;
    };
    let detail = s(&j["fail_detail"]);
    let parsed = detail
        .split_once("RxLoss")
        .and_then(|(_, s)| {
            s.split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
        })
        .and_then(|s| s.parse::<u64>().ok());
    r.beh(
        "RX loss fails with exactly measured drop count",
        ctx.meta["guest_exit"] == 3
            && j["reason"] == "Failed"
            && parsed == Some(drops)
            && j["net"]["kernel_drops"] == json!(drops),
        detail,
    );
    r.beh(
        "RX loss has no checkpoint summary, hex or file",
        j["checkpoint"] == false
            && j["checkpoint_hex"].is_null()
            && ctx.meta["checkpoint_file_exists"] == false,
        "",
    );
    let exp = replies(c, false);
    r.beh(
        "accepted results retained and genuine",
        array(&j["replies"])
            .iter()
            .all(|v| exp.iter().any(|x| v == x))
            && n(&j["reply_total"]) == array(&j["replies"]).len() as i128,
        j["replies"].to_string(),
    );
    r.beh(
        "TX frozen after RX failure",
        frozen(j),
        j["net"].to_string(),
    );
    workers(r, j);
    let nic = read_json(ctx.d.join("nic.json"));
    let fl = read_json(ctx.d.join("flood.json"));
    let mut ind = json!({"kernel_drops_n":drops,"rx_read_by_handle":j["net"]["rx_packets"]});
    if let (Some(nic), Some(fl)) = (nic, fl) {
        let sum = |v: &Value| -> Option<u64> {
            let st = v["stats"].as_object()?;
            [
                "ReceivedUnicastPackets",
                "ReceivedMulticastPackets",
                "ReceivedBroadcastPackets",
            ]
            .iter()
            .try_fold(0u64, |a, k| {
                a.checked_add(st.get(*k).and_then(Value::as_u64)?)
            })
        };
        if let (Some(a), Some(b)) = (sum(&nic["after"]), sum(&nic["before"])) {
            let delta = a as i128 - b as i128;
            let read = j["net"]["rx_packets"].as_u64();
            ind["nic_rx_delta"] = integer_note(delta);
            ind["peer_flood_sent"] = fl["sent"].clone();
            ind["nic_minus_read"] =
                read.map_or(Value::Null, |read| integer_note(delta - i128::from(read)));
            r.beh(
                "drops plus handle reads cannot exceed NIC packets",
                read.is_some_and(|read| i128::from(drops) + i128::from(read) <= delta),
                delta,
            );
            r.beh(
                "drops cannot exceed peer flood sent",
                fl["sent"].as_u64().is_some_and(|x| drops <= x),
                fl["sent"].to_string(),
            );
        } else {
            r.add(
                "independent NIC counters readable",
                NOT_RUN,
                nic.to_string(),
                false,
            );
        }
    } else {
        r.add(
            "independent NIC and flood inputs present",
            NOT_RUN,
            "missing",
            false,
        );
    }
    r.notes.insert("independent_count".into(), ind);
    r.notes.insert("independent_count_note".into(),json!("kernel_drops counts this Npcap handle buffer only; unread queued frames are not drops. NIC count is an independent upper bound."));
    let end = align(r, ctx, c, false);
    if ctx.peer.is_some() {
        flood(r, ctx, c, end, false);
    }
}
/// The refusal must have been tested with the file it claims: checkpoint-used.bin is the
/// declared mutation of checkpoint-forged.bin, otherwise the case proved something else.
fn refusal_provenance(r: &mut Run, ctx: &Ctx, variant: &str) {
    match (
        fs::read(ctx.d.join("checkpoint-forged.bin")),
        fs::read(ctx.d.join("checkpoint-used.bin")),
    ) {
        (Ok(forged), Ok(used)) => {
            let want = crate::windows_suite::mutate_checkpoint(variant, &forged);
            r.beh(
                "checkpoint-used.bin is the declared mutation of checkpoint-forged.bin",
                want.as_ref().is_ok_and(|w| *w == used),
                format!(
                    "{variant}: forged {} bytes, used {} bytes",
                    forged.len(),
                    used.len()
                ),
            );
        }
        _ => r.add(
            "checkpoint-forged.bin and checkpoint-used.bin recorded",
            NOT_RUN,
            "missing",
            false,
        ),
    }
}
fn refusal(r: &mut Run, ctx: &Ctx, it: &Value, c: &Value, man: &Value) {
    let j = &ctx.rj;
    job(r, j, c, man);
    let want = match s(&it["variant"]) {
        "wrong_ports" | "wrong_seed" => "JobMismatch",
        "corrupt_next_index" | "corrupt_checksum" => "BadChecksum",
        "truncated" | "empty" => "Malformed",
        "future_format" => "UnsupportedFormat",
        "future_engine" => "EngineVersionMismatch",
        _ => "AlreadyCompleted",
    };
    if it["kind"] == "ckpt_refuse" {
        refusal_provenance(r, ctx, s(&it["variant"]));
    }
    r.beh(
        "checkpoint refused before adapter opens with expected reason",
        ctx.meta["guest_exit"] == 4
            && j["status"] == "error"
            && (it["kind"] == "refuse_completed" || j["stage"] == "resume-preflight")
            && s(&j["error"]).starts_with(want)
            && j["opened_adapter"] == false
            && j["tx_sent"] == 0,
        j["error"].to_string(),
    );
    if let Some((fr, _)) = &ctx.peer {
        r.cap(
            "no scanner SYN reached wire",
            syns(fr, &ctx.bind, sports(c)).is_empty(),
            "",
        );
    }
}
fn permission(r: &mut Run, ctx: &Ctx, it: &Value, man: &Value) {
    let j = &ctx.rj;
    let rc = n(&ctx.meta["guest_exit"]);
    r.notes.insert("token_flags_reported_by_the_process".into(),json!({"elevated":j["identity"]["elevated"],"restricted_token":j["identity"]["restricted_token"]}));
    r.inv(
        "restricted token launched with runas trustlevel",
        s(&ctx.meta["restricted_via"]).contains("runas /trustlevel:0x20000"),
        ctx.meta["restricted_via"].to_string(),
    );
    if it["variant"] == "inventory" {
        r.beh(
            "admin-only Npcap hides non-loopback adapters and provides hint",
            rc == 5
                && j["mode"] == "inventory"
                && j["opened_adapter"] == false
                && j["tx_sent"] == 0
                && array(&j["devices"]).iter().all(|v| v["loopback"] == true)
                && s(&j["access_hint"]).contains("Administrators-only"),
            j["devices"].to_string(),
        );
    } else {
        job(r, j, &case_by_name("pb_perm_scan").unwrap(), man);
        let e = s(&j["error"]).split('(').next().unwrap_or("");
        r.beh(
            "restricted scan refuses before opening adapter or sending",
            ((rc == 2 && e == "InterfaceMismatch")
                || (rc == 5 && (e == "PermissionDenied" || e == "DriverUnavailable")))
                && j["status"] == "error"
                && j["opened_adapter"] == false
                && j["tx_sent"] == 0,
            j["error"].to_string(),
        );
    }
    if let Some((fr, _)) = &ctx.peer {
        r.cap(
            "no scanner SYN under restricted token",
            syns(fr, &ctx.bind, (1, 65535)).is_empty(),
            "",
        );
    }
}
fn verify_item(
    root: &Path,
    man: &Value,
    fx: &Value,
    it: &Value,
    rel: Option<&Path>,
) -> (Run, Option<Ctx>) {
    let mut r = Run::new(s(&it["tag"]));
    let d = rel
        .map(|p| root.join(p))
        .unwrap_or_else(|| root.join("runs").join(s(&it["tag"])));
    if !d.is_dir() {
        r.add("run directory present", NOT_RUN, "missing", false);
        return (r, None);
    }
    let rj = read_json(d.join("run.json"));
    let meta = read_json(d.join("meta.json"));
    let cap = read_json(d.join("capture.json"));
    for (name, v) in [
        ("run.json", &rj),
        ("meta.json", &meta),
        ("capture.json", &cap),
    ] {
        if v.is_none() {
            r.add(name, NOT_RUN, "missing or invalid JSON", false);
        }
    }
    let peer = load_pcap(&mut r, &d.join("peer.pcap"));
    let eno = load_pcap(&mut r, &d.join("eno1.pcap"));
    let (Some(rj), Some(meta), Some(cap)) = (rj, meta, cap) else {
        return (r, None);
    };
    let ctx = Ctx {
        d,
        rj,
        meta,
        peer,
        bind: Binding::new(&man["binding"]),
    };
    let j = &ctx.rj;
    r.inv(
        "source commit matches manifest",
        truth(&man["code_commit"]) && j["identity"]["source_commit"] == man["code_commit"],
        j["identity"].to_string(),
    );
    r.inv(
        "binary sha256 matches manifest",
        truth(&man["exe"]["sha256"]) && j["identity"]["binary_sha256"] == man["exe"]["sha256"],
        "",
    );
    r.inv(
        "guest hashed same executable before run",
        ctx.meta["exe_sha256"] == man["exe"]["sha256"],
        "",
    );
    r.inv(
        "process is Windows",
        j["identity"]["os"]["family"] == "windows",
        "",
    );
    capture(&mut r, man, &ctx, &cap, &eno);
    verify_argv(&mut r, it, man, &ctx.d);
    fixture_binding(&mut r, fx, &ctx.bind);
    let wanted = arg_map(it, man, false);
    for (k, field) in [("--scan-id", "scan_id"), ("--attempt-id", "attempt_id")] {
        if let Some(v) = wanted.get(k) {
            if j.get(field).is_some() {
                r.beh(
                    &format!("{field} matches requested argv"),
                    j[field] == *v,
                    j[field].to_string(),
                );
            } else if ["pause", "resume", "complete_nopause"].contains(&s(&it["kind"])) {
                r.beh(&format!("{field} echoed"), false, "missing");
            }
        }
    }
    let c = kind_case(it).unwrap_or(Value::Null);
    match s(&it["kind"]) {
        "case" | "foreign" => {
            continuous(&mut r, root, man, fx, &ctx, &c);
            if it["kind"] == "foreign" {
                foreign(&mut r, &ctx, &c);
            }
        }
        "stop" => stop(&mut r, &ctx, it, &c, man),
        "overflow_queue" => overflow(&mut r, &ctx, &c, man),
        "linkloss" => linkloss(&mut r, &ctx, &c, man),
        "rxloss" => rxloss(&mut r, &ctx, &c, man),
        "ckpt_refuse" | "refuse_completed" => refusal(&mut r, &ctx, it, &c, man),
        "perm_restricted" => permission(&mut r, &ctx, it, man),
        "pause" => {
            job(&mut r, j, &c, man);
            let ni = n(&it["n"]);
            r.beh(
                "pause exits zero, Paused, exact progress and checkpoint summary",
                ctx.meta["guest_exit"] == 0
                    && j["reason"] == "Paused"
                    && n(&j["sent"]) == ni
                    && n(&j["next_index"]) == ni
                    && j["checkpoint"] == true
                    && n(&j["checkpoint_next_index"]) == ni,
                j["reason"].to_string(),
            );
            r.beh(
                "pause health measured zero, exact TX and clean net",
                health(j) && clean(j) && n(&j["net"]["tx_sent"]) == ni,
                j["net"].to_string(),
            );
            checkpoint(&mut r, &ctx, it);
        }
        "resume" => {
            job(&mut r, j, &c, man);
            r.beh(
                "resume completes remaining progress",
                ctx.meta["guest_exit"] == 0
                    && j["reason"] == "Completed"
                    && n(&j["sent"]) == 16 - n(&it["n"])
                    && j["start_index"] == it["n"]
                    && j["next_index"] == 16,
                j["reason"].to_string(),
            );
            r.beh(
                "resume RX measured zero and clean net",
                health(j) && clean(j),
                j["net"].to_string(),
            );
        }
        "complete_nopause" => {
            job(&mut r, j, &c, man);
            r.beh(
                "pause at end completes with no checkpoint",
                ctx.meta["guest_exit"] == 0
                    && j["reason"] == "Completed"
                    && j["checkpoint"] == false
                    && j["sent"] == 16,
                j["reason"].to_string(),
            );
            r.beh(
                "completed RX measured zero",
                health(j),
                j["rx_health"].to_string(),
            );
        }
        _ => r.add("known run kind", INVALID, it.to_string(), false),
    }
    (r, Some(ctx))
}
fn groups(
    root: &Path,
    man: &Value,
    fx: &Value,
    rs: &BTreeMap<String, Run>,
    cs: &BTreeMap<String, Ctx>,
) -> Vec<Value> {
    let mut out = Vec::new();
    let c = case_by_name(PAUSE).unwrap();
    for ni in [0, 1, 8, 15] {
        let mut r = Run::new(&format!("group_pause_resume_N{ni}"));
        let a = format!("pause_N{ni}");
        let b = format!("resume_N{ni}");
        let (Some(ca), Some(cb), Some(cc)) =
            (cs.get(&a), cs.get(&b), cs.get("c03_multi_ports.run1"))
        else {
            r.add(
                "both legs and continuous run usable",
                NOT_RUN,
                "missing",
                false,
            );
            out.push(r.summary());
            continue;
        };
        let (Some(pa), Some(pb), Some(pc)) = (&ca.peer, &cb.peer, &cc.peer) else {
            r.add(
                "both legs and continuous captures usable",
                NOT_RUN,
                "missing or invalid",
                false,
            );
            out.push(r.summary());
            continue;
        };
        let bad: Vec<_> = [&a, &b]
            .into_iter()
            .filter_map(|t| rs.get(t))
            .filter(|r| r.verdict() != PASS)
            .collect();
        if !bad.is_empty() {
            let v = if bad.iter().any(|r| r.verdict() == NOT_RUN) {
                NOT_RUN
            } else if bad.iter().any(|r| r.verdict() == INVALID) {
                INVALID
            } else {
                FAIL
            };
            r.argv_ok = true;
            r.add("both legs pass individually", v, "bad leg", false);
            out.push(r.summary());
            continue;
        }
        r.argv_ok = true;
        let (ra, rb) = (&ca.rj, &cb.rj);
        r.check(
            "scan identity constant, attempt fresh, resume origin recorded",
            ra["scan_id"] == rb["scan_id"]
                && ra["attempt_id"] != rb["attempt_id"]
                && rb["resumed_from_attempt"] == ra["attempt_id"]
                && ra["resumed_from_attempt"].is_null(),
            "",
            FAIL,
            false,
        );
        let legs = [pa.1.as_slice(), pb.1.as_slice()];
        if let Some((_, data)) = fixture(&mut r, root, fx, &c, &ca.bind) {
            let (code, msg) = pcap::compare_bytes(&data, &legs, None, &[]);
            r.add(
                "pause plus resume equals C oracle bytes and order",
                [PASS, FAIL, INVALID][code as usize],
                msg,
                false,
            );
        }
        let (code, msg) = pcap::compare_bytes(&pc.1, &legs, None, &[]);
        r.add(
            "pause plus resume equals continuous Rust bytes and order",
            [PASS, FAIL, INVALID][code as usize],
            msg,
            false,
        );
        r.check(
            "no probe lost or added at resume seam",
            syns(&pa.0, &ca.bind, sports(&c)).len() == ni
                && syns(&pb.0, &cb.bind, sports(&c)).len() == 16 - ni,
            "",
            FAIL,
            false,
        );
        let mut union: Vec<_> = array(&ra["replies"])
            .iter()
            .chain(array(&rb["replies"]))
            .map(|v| s(v).to_string())
            .collect();
        union.sort();
        r.check(
            "reply union equals listener truth without duplicates",
            union == replies(&c, false) && unique(union.clone()).len() == union.len(),
            format!("{union:?}"),
            FAIL,
            false,
        );
        let _ = man;
        out.push(r.summary());
    }
    out
}
fn finish(mut result: Value) -> Value {
    let vs: Vec<_> = array(&result["runs"])
        .iter()
        .chain(array(&result["groups"]))
        .collect();
    let disc = array(&result["discarded"]);
    let totals = |a: &[&Value]| -> Value {
        let mut o = serde_json::Map::new();
        for v in [NOT_RUN, INVALID, FAIL, PASS] {
            o.insert(
                v.into(),
                json!(a.iter().filter(|r| r["verdict"] == v).count()),
            );
        }
        Value::Object(o)
    };
    let ts = totals(&vs);
    let ds = totals(&disc.iter().collect::<Vec<_>>());
    let mut overall = if !vs.is_empty() && vs.iter().all(|r| r["verdict"] == PASS) {
        PASS
    } else if vs.iter().any(|r| r["verdict"] == NOT_RUN) {
        NOT_RUN
    } else if vs.iter().any(|r| r["verdict"] == INVALID) {
        INVALID
    } else {
        FAIL
    };
    let beh: Vec<_> = vs
        .iter()
        .copied()
        .chain(disc)
        .filter(|r| r["behaviour_fail"] == true)
        .map(|r| r["tag"].clone())
        .collect();
    if !beh.is_empty() || disc.iter().any(|r| r["verdict"] == FAIL) {
        overall = FAIL;
    } else if overall == PASS && disc.iter().any(|r| r["verdict"] == PASS) {
        overall = INVALID;
    }
    result["totals"] = ts;
    result["discarded_totals"] = ds;
    result["overall"] = json!(overall);
    result["behaviour_fail"] = json!(beh);
    result
}
/// The `provenance` block of a verdict: the build recorded at run time, this verifier's own build, and
/// warnings (never refusals) for a dirty tree or a build from another commit than the one under test.
fn provenance_report(man: &Value) -> Value {
    let verifier = crate::provenance::collect(Path::new("."));
    let orch = man["orchestrator"].clone();
    let mut warnings = Vec::new();
    if orch.is_null() {
        warnings
            .push("orchestrator build not recorded (capture_schema below 3: exempt)".to_owned());
    } else {
        if orch["git_dirty"] == true {
            warnings.push(
                "orchestrator was built from uncommitted changes to tracked files".to_owned(),
            );
        }
        if orch["git_commit"].is_string() && orch["git_commit"] != man["code_commit"] {
            warnings.push(format!(
                "orchestrator commit {} differs from the commit under test {}",
                orch["git_commit"], man["code_commit"]
            ));
        }
        match orch["build_commit"].as_str() {
            Some("unknown") => warnings.push(
                "orchestrator build commit is unknown (RMASSCAN_LAB_BUILD_COMMIT was not set at build time); the binary sha256 is the only build identity"
                    .to_owned(),
            ),
            Some(b) if b != man["code_commit"].as_str().unwrap_or("") => warnings.push(format!(
                "orchestrator binary was built from commit {b}, which differs from the commit under test {}",
                man["code_commit"]
            )),
            _ => {}
        }
    }
    if verifier["git_dirty"] == true {
        warnings.push("verifier was built from uncommitted changes to tracked files".to_owned());
    }
    json!({"orchestrator":orch,"verifier":verifier,"warnings":warnings})
}
pub fn verify_dir(root: &Path) -> Value {
    let mut result = json!({"schema":1,"dir":root.file_name().unwrap_or_default().to_string_lossy(),"runs":[],"groups":[],"discarded":[]});
    let Some(man) = read_json(root.join("manifest.json")) else {
        let mut r = Run::new("manifest");
        r.add("manifest present and valid JSON", NOT_RUN, "missing", false);
        result["runs"] = json!([r.summary()]);
        return finish(result);
    };
    let fx = read_json(root.join("fixtures/manifest.json"));
    let mut r = Run::new("manifest");
    for k in ["code_commit", "exe", "binding"] {
        r.check(
            &format!("manifest.{k} present"),
            truth(&man[k]),
            "",
            NOT_RUN,
            false,
        );
    }
    r.check(
        "manifest executable sha256 present",
        truth(&man["exe"]["sha256"]),
        "",
        NOT_RUN,
        false,
    );
    // Which build of this tool produced the evidence (schema >= 3: mandatory; older evidence is exempt).
    result["provenance"] = provenance_report(&man);
    if man["capture_schema"].as_u64().unwrap_or(1) >= 3 {
        let why = crate::provenance::problem(&man["orchestrator"]);
        r.check(
            "orchestrator build recorded (commit, dirty flag, binary sha256)",
            why.is_none(),
            why.unwrap_or_default(),
            INVALID,
            false,
        );
    }
    r.check(
        "fixtures manifest present",
        fx.is_some(),
        "",
        NOT_RUN,
        false,
    );
    let mut runs = vec![r.summary()];
    if r.verdict() != PASS {
        result["runs"] = json!(runs);
        return finish(result);
    }
    let fx = fx.unwrap();
    let mut rs = BTreeMap::new();
    let mut cs = BTreeMap::new();
    for it in planned(&man) {
        let (r, c) = verify_item(root, &man, &fx, &it, None);
        runs.push(r.summary());
        if let Some(c) = c {
            cs.insert(s(&it["tag"]).into(), c);
        }
        rs.insert(s(&it["tag"]).into(), r);
    }
    if man["plan"] != "failure" {
        result["groups"] = json!(groups(root, &man, &fx, &rs, &cs));
    }
    result["runs"] = json!(runs);
    let mut discarded = Vec::new();
    if let Ok(entries) = fs::read_dir(root.join("runs_discarded")) {
        let mut paths: Vec<_> = entries
            .filter_map(Result::ok)
            .filter(|e| e.path().is_dir())
            .collect();
        paths.sort_by_key(|e| e.file_name());
        for e in paths {
            let name = e.file_name().to_string_lossy().to_string();
            let tag = name.rsplit_once('.').map_or(name.as_str(), |(a, _)| a);
            let mut r = if let Some(mut it) = planned(&man).into_iter().find(|it| it["tag"] == tag)
            {
                it["tag"] = json!(name);
                verify_item(
                    root,
                    &man,
                    &fx,
                    &it,
                    Some(&Path::new("runs_discarded").join(&name)),
                )
                .0
            } else {
                let mut r = Run::new(&name);
                r.argv_ok = true;
                r.add("discarded run belongs to planned tag", FAIL, tag, false);
                r
            };
            r.tag = name;
            discarded.push(r.summary());
        }
    }
    result["discarded"] = json!(discarded);
    finish(result)
}
pub fn run_status(root: &Path, tag: &str) -> (String, bool) {
    let Some(man) = read_json(root.join("manifest.json")) else {
        return (NOT_RUN.into(), false);
    };
    let Some(it) = planned(&man).into_iter().find(|it| it["tag"] == tag) else {
        return (NOT_RUN.into(), false);
    };
    let fx = read_json(root.join("fixtures/manifest.json")).unwrap_or(Value::Null);
    let (r, _) = verify_item(root, &man, &fx, &it, None);
    (r.verdict().into(), r.behaviour_fail())
}
pub fn run(args: &[String]) -> Result<i32, String> {
    if args.iter().any(|x| x == "--cases-psv") {
        print!("{}", cases_psv());
        return Ok(0);
    }
    let mut dir = None;
    let mut out = None;
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("value required for {k}"))?;
        match k.as_str() {
            "--dir" => dir = Some(v),
            "--out" => out = Some(v),
            _ => return Err(format!("unknown argument {k}")),
        }
    }
    let root = Path::new(dir.ok_or("--dir required")?);
    let res = verify_dir(root);
    if let Some(out) = out {
        fs::write(
            out,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&res).map_err(|e| e.to_string())?
            ),
        )
        .map_err(|e| e.to_string())?;
    }
    for r in array(&res["runs"])
        .iter()
        .chain(array(&res["groups"]))
        .chain(array(&res["discarded"]))
    {
        let bad: Vec<_> = array(&r["checks"])
            .iter()
            .filter(|c| c["result"] != PASS)
            .take(3)
            .map(|c| format!("{}: {}", s(&c["result"]), s(&c["name"])))
            .collect();
        println!(
            "{:<8} {} {}",
            s(&r["verdict"]),
            s(&r["tag"]),
            bad.join("; ")
        );
    }
    let p = &res["provenance"];
    let short = |v: &Value| s(v).chars().take(12).collect::<String>();
    println!(
        "provenance: orchestrator built from {} (checkout head {}) dirty={} binary sha256 {} (authoritative); verifier built from {} (checkout head {}) dirty={} binary sha256 {}",
        short(&p["orchestrator"]["build_commit"]),
        short(&p["orchestrator"]["git_commit"]),
        p["orchestrator"]["git_dirty"],
        short(&p["orchestrator"]["binary_sha256"]),
        short(&p["verifier"]["build_commit"]),
        short(&p["verifier"]["git_commit"]),
        p["verifier"]["git_dirty"],
        short(&p["verifier"]["binary_sha256"]),
    );
    for w in array(&p["warnings"]) {
        println!("provenance warning: {}", s(w));
    }
    println!("overall: {} {}", s(&res["overall"]), res["totals"]);
    Ok(match s(&res["overall"]) {
        PASS => 0,
        FAIL => 1,
        _ => 2,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn historical() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional",
        )
    }
    #[test]
    fn historical_functional_is_pass() {
        let v = verify_dir(&historical());
        assert_eq!(
            v["overall"],
            PASS,
            "{}",
            serde_json::to_string_pretty(&v).unwrap()
        );
        assert_eq!(v["totals"][PASS], 29);
    }
    #[test]
    fn committed_r1_smoke_replays_as_documented() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../../docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional-r1-smoke",
        );
        let v = verify_dir(&dir);
        assert_eq!(v["overall"], NOT_RUN);
        assert_eq!(
            (
                v["totals"][PASS].as_u64(),
                v["totals"][INVALID].as_u64(),
                v["totals"][NOT_RUN].as_u64()
            ),
            (Some(1), Some(1), Some(27))
        );
    }
    #[test]
    fn plans_have_full_spec() {
        assert_eq!(planned(&json!({})).len(), 24);
        assert_eq!(planned(&json!({"plan":"failure"})).len(), 18);
    }
    #[test]
    fn missing_never_pass() {
        assert_eq!(
            verify_dir(Path::new("/definitely-missing-evidence"))["overall"],
            NOT_RUN
        );
    }
    #[test]
    fn wrong_interface_and_filter_rejected() {
        let root = historical();
        let man = read_json(root.join("manifest.json")).unwrap();
        let b = Binding::new(&man["binding"]);
        let cap = read_json(root.join("runs/pause_N8/capture.json")).unwrap();
        assert!(capture_command(&cap["peer"], "peer", &b, "wvp-n2"));
        assert!(capture_command(&cap["eno1"], "eno1", &b, "wvp-n2"));
        let mut p = cap["peer"].clone();
        p["cmd"][6] = json!("eno1");
        assert!(!capture_command(&p, "peer", &b, "wvp-n2"));
        let mut p = cap["eno1"].clone();
        p["filter"] = json!("tcp port 1");
        assert!(!capture_command(&p, "eno1", &b, "wvp-n2"));
    }
    #[test]
    fn duplicate_arguments_rejected() {
        assert!(parse_args(&json!({"argv":["--rate","1","--rate","100"]})).is_err());
    }
}
#[cfg(test)]
#[path = "verify_fixture.rs"]
pub(crate) mod fixture;
#[cfg(test)]
#[path = "verify_tests.rs"]
mod regression_tests;
