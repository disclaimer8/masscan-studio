//! Strict classic pcap parsing and byte-exact ordered SYN comparison.
use serde_json::Value;
use std::fs;
pub type Frames = Vec<(f64, Vec<u8>)>;
pub fn read_pcap_records(data: &[u8]) -> Result<(u32, Frames), String> {
    if data.len() < 24 {
        return Err("pcap global header truncated".into());
    }
    let (le, nano) = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("bad pcap magic".into()),
    };
    let u32at = |o: usize| {
        let a: [u8; 4] = data[o..o + 4].try_into().expect("bounds checked");
        if le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        }
    };
    let lt = u32at(20);
    if lt != 1 {
        return Err(format!(
            "unsupported pcap link type {lt}; Ethernet required"
        ));
    }
    let mut frames = Vec::new();
    let mut off = 24;
    while off < data.len() {
        if data.len() - off < 16 {
            return Err(format!("pcap record header truncated at {off}"));
        }
        let sec = u32at(off);
        let frac = u32at(off + 4);
        let cap = u32at(off + 8) as usize;
        let orig = u32at(off + 12) as usize;
        off += 16;
        if cap != orig {
            return Err("snapped pcap frame".into());
        }
        if cap > data.len() - off {
            return Err("pcap record body truncated".into());
        }
        if frac >= if nano { 1_000_000_000 } else { 1_000_000 } {
            return Err("invalid pcap timestamp fraction".into());
        }
        frames.push((
            sec as f64 + frac as f64 / if nano { 1e9 } else { 1e6 },
            data[off..off + cap].to_vec(),
        ));
        off += cap;
    }
    Ok((lt, frames))
}
pub fn is_syn(f: &[u8]) -> bool {
    if f.len() < 54
        || f[12..14] != [8, 0]
        || f[14] >> 4 != 4
        || f[23] != 6
        || u16::from_be_bytes([f[20], f[21]]) & 0x1fff != 0
    {
        return false;
    }
    let ihl = (f[14] & 15) as usize * 4;
    ihl >= 20 && f.len() >= 14 + ihl + 14 && f[14 + ihl + 13] & 0x3f == 2
}
pub fn meta_problem(m: &Value) -> Option<String> {
    for k in [
        "drops",
        "kernel_drops",
        "truncated_frames",
        "truncated",
        "rx_counter_mismatch",
    ] {
        let Some(v) = m.get(k) else {
            continue;
        };
        let measured_clean = if matches!(k, "truncated" | "rx_counter_mismatch") {
            v == false || v.as_u64() == Some(0)
        } else {
            v.as_u64() == Some(0)
        };
        if !measured_clean {
            return Some(format!("capture reports {k}={v}"));
        }
    }
    if m["valid"] == false {
        Some("capture meta marked invalid".into())
    } else {
        None
    }
}
pub fn compare_streams(exp: &[Vec<u8>], act: &[Vec<u8>]) -> (i32, String) {
    for (i, (a, b)) in exp.iter().zip(act).enumerate() {
        if a != b {
            return (
                1,
                format!(
                    "SYN #{i} differs (length {} vs {}, first differing byte {:?})",
                    a.len(),
                    b.len(),
                    a.iter().zip(b).position(|(x, y)| x != y)
                ),
            );
        }
    }
    if exp.len() != act.len() {
        (
            1,
            format!(
                "SYN count differs: expected {}, actual {}",
                exp.len(),
                act.len()
            ),
        )
    } else {
        (
            0,
            format!("{} SYN frames identical and in order", exp.len()),
        )
    }
}
pub fn compare_bytes(
    exp: &[u8],
    acts: &[&[u8]],
    em: Option<&Value>,
    am: &[Value],
) -> (i32, String) {
    for m in em.into_iter().chain(am) {
        if let Some(e) = meta_problem(m) {
            return (2, e);
        }
    }
    let ef = match read_pcap_records(exp) {
        Ok((_, f)) => f,
        Err(e) => return (2, format!("expected pcap: {e}")),
    };
    let es: Vec<_> = ef
        .into_iter()
        .filter(|(_, f)| is_syn(f))
        .map(|(_, f)| f)
        .collect();
    if es.is_empty() {
        return (2, "expected pcap contains no SYN frames".into());
    }
    let mut as_ = Vec::new();
    for (i, a) in acts.iter().enumerate() {
        match read_pcap_records(a) {
            Ok((_, f)) => as_.extend(f.into_iter().filter(|(_, f)| is_syn(f)).map(|(_, f)| f)),
            Err(e) => return (2, format!("actual[{i}] pcap: {e}")),
        }
    }
    compare_streams(&es, &as_)
}
pub fn steady_state_rate(ts: &[f64]) -> Option<f64> {
    let k = (ts.len() / 10).max(1);
    if ts.len() < k + 2 {
        return None;
    }
    let dt = ts[ts.len() - 1] - ts[k];
    (dt > 0.).then(|| (ts.len() - 1 - k) as f64 / dt)
}
pub fn run(args: &[String]) -> Result<i32, String> {
    if args.iter().any(|x| x == "--self-test") {
        return self_test();
    }
    let mut exp = None;
    let mut acts = Vec::new();
    let mut em = None;
    let mut am = Vec::new();
    let mut it = args.iter();
    while let Some(k) = it.next() {
        let v = it.next().ok_or_else(|| format!("missing value for {k}"))?;
        match k.as_str() {
            "--expected" => exp = Some(v),
            "--actual" => acts.push(v),
            "--expected-meta" => em = Some(v),
            "--actual-meta" => am.push(v),
            _ => return Err(format!("unknown argument {k}")),
        }
    }
    let exp = exp.ok_or("--expected required")?;
    if acts.is_empty() {
        return Err("--actual required".into());
    }
    if !am.is_empty() && am.len() != acts.len() {
        return Err("one --actual-meta per --actual required".into());
    }
    let load = |p: &String| fs::read(p).map_err(|e| format!("{p}: {e}"));
    let json = |p: &String| -> Result<Value, String> {
        serde_json::from_slice(&load(p)?).map_err(|e| e.to_string())
    };
    let e = load(exp)?;
    let aa = acts.into_iter().map(load).collect::<Result<Vec<_>, _>>()?;
    let mm = am.into_iter().map(json).collect::<Result<Vec<_>, _>>()?;
    let ee = em.map(json).transpose()?;
    let (code, msg) = compare_bytes(
        &e,
        &aa.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        ee.as_ref(),
        &mm,
    );
    println!("{}: {msg}", ["PASS", "FAIL", "INVALID"][code as usize]);
    Ok(code)
}
fn sample_packet(port: u16) -> Vec<u8> {
    let mut p = vec![0; 54];
    p[12] = 8;
    p[14] = 0x45;
    p[23] = 6;
    p[47] = 2;
    p[36..38].copy_from_slice(&port.to_be_bytes());
    p
}
pub fn encode(frames: &Frames) -> Vec<u8> {
    let mut b = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    b.extend([0; 8]);
    b.extend(65535u32.to_le_bytes());
    b.extend(1u32.to_le_bytes());
    for (t, p) in frames {
        b.extend((*t as u32).to_le_bytes());
        b.extend(((t.fract() * 1e6) as u32).to_le_bytes());
        b.extend((p.len() as u32).to_le_bytes());
        b.extend((p.len() as u32).to_le_bytes());
        b.extend(p);
    }
    b
}
fn self_test() -> Result<i32, String> {
    let a = sample_packet(80);
    let b = sample_packet(443);
    let good = encode(&vec![(1., a.clone()), (2., b.clone())]);
    let leg1 = encode(&vec![(1., a)]);
    let leg2 = encode(&vec![(2., b)]);
    for (code, want) in [
        (compare_bytes(&good, &[&good], None, &[]).0, 0),
        (compare_bytes(&good, &[&leg1, &leg2], None, &[]).0, 0),
        (compare_bytes(&good, &[&leg2, &leg1], None, &[]).0, 1),
        (
            compare_bytes(&good, &[&good[..good.len() - 1]], None, &[]).0,
            2,
        ),
        (
            compare_bytes(&good, &[&good], None, &[serde_json::json!({"drops":1})]).0,
            2,
        ),
    ] {
        if code != want {
            return Err(format!("self-test expected {want}, got {code}"));
        }
    }
    println!("PASS: pcap comparator self-test");
    Ok(0)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognizes_syn() {
        assert!(is_syn(&sample_packet(80)));
    }
    #[test]
    fn parses_classic_capture() {
        assert_eq!(
            read_pcap_records(&encode(&vec![(1., sample_packet(80))]))
                .unwrap()
                .1
                .len(),
            1
        );
    }
    #[test]
    fn rejects_truncation() {
        let mut b = encode(&vec![(1., sample_packet(80))]);
        b.pop();
        assert!(read_pcap_records(&b).is_err());
    }
    #[test]
    fn comparator_regressions() {
        assert_eq!(self_test().unwrap(), 0);
    }
    #[test]
    fn rate_excludes_startup() {
        assert!(
            (steady_state_rate(&(0..1000).map(|i| i as f64 / 1000.).collect::<Vec<_>>()).unwrap()
                - 1000.)
                .abs()
                < 1.
        );
        assert!(steady_state_rate(&[0., 1.]).is_none());
    }
}
#[cfg(test)]
mod acceptance_tests {
    use super::*;
    use serde_json::json;
    fn bytes(packets: Vec<Vec<u8>>) -> Vec<u8> {
        encode(
            &packets
                .into_iter()
                .enumerate()
                .map(|(i, p)| (i as f64, p))
                .collect(),
        )
    }
    #[test]
    fn every_original_packet_comparator_rejection_class() {
        let a = sample_packet(80);
        let b = sample_packet(81);
        let c = sample_packet(443);
        let d = sample_packet(22);
        let base = vec![a.clone(), b.clone(), c.clone(), d.clone()];
        let good = bytes(base.clone());
        let mut arp = vec![0; 42];
        arp[12] = 8;
        arp[13] = 6;
        let mut rst = a.clone();
        rst[47] = 4;
        let ignored = bytes(vec![
            arp.clone(),
            a.clone(),
            rst,
            b.clone(),
            c.clone(),
            arp,
            d.clone(),
        ]);
        assert_eq!(compare_bytes(&good, &[&ignored], None, &[]).0, 0);
        for packets in [
            vec![b.clone(), a.clone(), c.clone(), d.clone()],
            vec![a.clone(), b.clone(), d.clone()],
            vec![a.clone(), b.clone(), b.clone(), c.clone(), d.clone()],
            [base.clone(), vec![a.clone()]].concat(),
        ] {
            assert_eq!(compare_bytes(&good, &[&bytes(packets)], None, &[]).0, 1);
        }
        for offset in [0, 26, 38, 41, 50] {
            let mut m = base.clone();
            m[2][offset] ^= 1;
            assert_eq!(compare_bytes(&good, &[&bytes(m)], None, &[]).0, 1);
        }
        for length in [10, 24 + 16 + 54 + 5, good.len() - 7] {
            assert_eq!(compare_bytes(&good, &[&good[..length]], None, &[]).0, 2);
        }
        assert_eq!(
            compare_bytes(&good[..good.len() - 1], &[&good], None, &[]).0,
            2
        );
        assert_eq!(compare_bytes(&good, &[&[0; 64]], None, &[]).0, 2);
        assert_eq!(compare_bytes(&bytes(vec![]), &[&good], None, &[]).0, 2);
        let mut snapped = good.clone();
        snapped[36..40].copy_from_slice(&53u32.to_le_bytes());
        assert_eq!(compare_bytes(&good, &[&snapped], None, &[]).0, 2);
        let empty = bytes(vec![]);
        let ab = bytes(vec![a.clone(), b.clone()]);
        let cd = bytes(vec![c.clone(), d.clone()]);
        assert_eq!(compare_bytes(&good, &[&empty, &good], None, &[]).0, 0);
        assert_eq!(compare_bytes(&good, &[&ab, &cd], None, &[]).0, 0);
        for legs in [
            vec![ab.clone(), bytes(vec![c.clone()])],
            vec![bytes(vec![a.clone(), b.clone(), c.clone()]), cd.clone()],
            vec![ab.clone(), bytes(vec![d.clone()])],
            vec![cd.clone(), ab.clone()],
        ] {
            assert_eq!(
                compare_bytes(
                    &good,
                    &legs.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    None,
                    &[]
                )
                .0,
                1
            );
        }
        assert_eq!(
            compare_bytes(&good, &[&ab, &cd], None, &[json!({}), json!({"drops":1})]).0,
            2
        );
        assert_eq!(
            compare_bytes(&good, &[&ab, &cd[..cd.len() - 1]], None, &[]).0,
            2
        );
    }
    #[test]
    fn both_endiannesses_and_timestamp_units() {
        let packet = sample_packet(80);
        let little = bytes(vec![packet]);
        let mut big = little.clone();
        for (start, end) in [
            (0, 4),
            (4, 6),
            (6, 8),
            (8, 12),
            (12, 16),
            (16, 20),
            (20, 24),
            (24, 28),
            (28, 32),
            (32, 36),
            (36, 40),
        ] {
            big[start..end].reverse();
        }
        assert_eq!(compare_bytes(&little, &[&big], None, &[]).0, 0);
        let mut nano = little.clone();
        nano[..4].copy_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]);
        nano[28..32].copy_from_slice(&123_456_789u32.to_le_bytes());
        assert!((read_pcap_records(&nano).unwrap().1[0].0 - 0.123456789).abs() < 1e-12);
        assert_eq!(compare_bytes(&little, &[&nano], None, &[]).0, 0);
        let mut bad = little.clone();
        bad[20..24].copy_from_slice(&113u32.to_le_bytes());
        assert!(read_pcap_records(&bad).is_err());
    }
    #[test]
    fn unknown_negative_or_noninteger_capture_counters_are_invalid() {
        for key in ["drops", "kernel_drops", "truncated_frames"] {
            for value in [
                Value::Null,
                json!(-1),
                json!(1),
                json!("0"),
                json!(false),
                json!(0.5),
            ] {
                let mut meta = json!({});
                meta[key] = value;
                assert!(meta_problem(&meta).is_some(), "{meta}");
            }
        }
        for meta in [
            json!({"truncated":true}),
            json!({"rx_counter_mismatch":true}),
            json!({"valid":false}),
        ] {
            assert!(meta_problem(&meta).is_some());
        }
        assert!(
            meta_problem(
                &json!({"drops":0,"kernel_drops":0,"truncated_frames":0,"truncated":false})
            )
            .is_none()
        );
    }
    #[test]
    fn reply_flags_fragments_and_short_packets_not_syn() {
        for flags in [0x12, 0x14, 4, 1, 0x18] {
            let mut p = sample_packet(80);
            p[47] = flags;
            assert!(!is_syn(&p));
        }
        for len in 0..54 {
            assert!(!is_syn(&sample_packet(80)[..len]));
        }
        let mut p = sample_packet(80);
        p[21] = 1;
        assert!(!is_syn(&p));
        p[21] = 0;
        p[14] = 0x44;
        assert!(!is_syn(&p));
    }
}
