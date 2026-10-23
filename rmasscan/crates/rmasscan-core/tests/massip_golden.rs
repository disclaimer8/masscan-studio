//! Oracle-проверка MassIp + BlackRock по golden `-sL` фикстурам (AGPL-3.0,
//! порт masscan © Robert David Graham, massip.c + main-listscan.c:15,29-62,
//! main.c:1655-1670).
//!
//! Для каждого IPv4 `-sL` кейса без shard/resume/retries!=0: excludes, optimize,
//! затем строка i = `pick(shuffle(i))`. Усечённые кейсы сверяются по первым
//! 2000 строкам, `line_count` и sha256 всего потока (SHA-256 ниже, test-only).

use std::net::Ipv4Addr;

use rmasscan_core::blackrock::BlackRock;
use rmasscan_core::massip::MassIp;
use rmasscan_core::targets::{add_target_string, parse_ports};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    file: Option<String>,
    mode: Option<String>,
    args: Option<Vec<String>>,
    line_count: Option<u64>,
    sha256: Option<String>,
    truncated: Option<bool>,
}

struct Spec {
    targets: String,
    ports: String,
    excludes: Vec<String>,
    seed: u64,
    rounds: u32,
}

/// `Err(reason)` когда кейс вне области теста.
fn spec_for(args: &[String]) -> Result<Spec, String> {
    let (mut targets, mut ports) = (None, None);
    let mut excludes = Vec::new();
    let (mut seed, mut rounds) = (None, 14u32); // main.c:1595
    let mut it = args.iter().skip(1); // -sL
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("missing {name} value"));
        match a.as_str() {
            "--seed" => seed = Some(val("seed")?.parse::<u64>().map_err(|e| e.to_string())?),
            "--blackrock-rounds" => {
                rounds = val("rounds")?
                    .parse()
                    .map_err(|_| "bad rounds".to_string())?
            }
            "--exclude" => excludes.push(val("exclude")?),
            "--retries" => {
                if val("retries")? != "0" {
                    return Err("retries != 0".into());
                }
            }
            o if o.starts_with("--") => return Err(format!("unsupported option {o}")),
            p if p.starts_with("-p") => {
                if ports.replace(p[2..].to_string()).is_some() {
                    return Err("multiple -p".into());
                }
            }
            t => {
                if targets.replace(t.to_string()).is_some() {
                    return Err("multiple targets".into());
                }
            }
        }
    }
    let targets = targets.ok_or("no target")?;
    if targets.contains(':') || excludes.iter().any(|e| e.contains(':')) {
        return Err("IPv6 out of scope in v1".into());
    }
    Ok(Spec {
        targets,
        ports: ports.ok_or("no -p")?,
        excludes,
        seed: seed.ok_or("no --seed")?,
        rounds,
    })
}

// ---- минимальный SHA-256 (FIPS 180-4), только для тестов ----
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    h: [u32; 8],
    buf: Vec<u8>,
    len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: Vec::with_capacity(64),
            len: 0,
        }
    }

    fn block(&mut self, b: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = self.h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for (h, x) in self.h.iter_mut().zip(v) {
            *h = h.wrapping_add(x);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len += data.len() as u64;
        while !data.is_empty() {
            let n = (64 - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..n]);
            data = &data[n..];
            if self.buf.len() == 64 {
                let b = std::mem::take(&mut self.buf);
                self.block(&b);
                self.buf = b;
                self.buf.clear();
            }
        }
    }

    fn finish(mut self) -> String {
        let bits = self.len * 8;
        self.update(&[0x80]);
        while self.buf.len() != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        self.h.iter().map(|x| format!("{x:08x}")).collect()
    }
}

#[test]
fn sha256_known_vectors() {
    let mut s = Sha256::new();
    s.update(b"abc");
    assert_eq!(
        s.finish(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        Sha256::new().finish(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

fn build(spec: &Spec) -> MassIp {
    let mut t = MassIp::new();
    add_target_string(&mut t.ipv4, &spec.targets).unwrap();
    parse_ports(&mut t.ports, &spec.ports).unwrap();
    let mut ex = MassIp::new();
    for e in &spec.excludes {
        add_target_string(&mut ex.ipv4, e).unwrap();
    }
    t.apply_excludes(&mut ex); // main.c:1655
    t.optimize(); // main.c:1670
    t
}

#[test]
fn listscan_matches_oracle_for_multi_port_multi_range_exclude() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden");
    let manifest: Manifest =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/manifest.json")).unwrap())
            .unwrap();
    let mut checked = Vec::new();
    for case in manifest
        .cases
        .iter()
        .filter(|c| c.mode.as_deref() == Some("-sL"))
    {
        let file = case.file.as_deref().expect("file");
        let spec = match spec_for(case.args.as_deref().expect("args")) {
            Ok(s) => s,
            Err(why) => {
                println!("SKIP {file}: {why}");
                continue;
            }
        };
        let t = build(&spec);
        let range = t.range();
        let line_count = case.line_count.expect("line_count");
        assert_eq!(range, line_count, "{file}: range vs line_count");
        let br = BlackRock::new(range, spec.seed, spec.rounds);
        let single_port = t.count_ports() == 1;
        let truncated = case.truncated.unwrap_or(false);
        let expected = std::fs::read_to_string(format!("{dir}/{file}")).unwrap();
        let mut exp = expected.lines();
        let mut sha = Sha256::new();
        for i in 0..range {
            let (ip, port) = t.pick(br.shuffle(i));
            let ip = Ipv4Addr::from(ip);
            let line = if single_port {
                ip.to_string()
            } else {
                format!("{ip}:{port}")
            };
            if let Some(e) = exp.next() {
                assert_eq!(line, e, "{file} line {}", i + 1);
            } else {
                assert!(truncated, "{file}: fixture shorter than range");
            }
            if truncated {
                sha.update(line.as_bytes());
                sha.update(b"\n");
            }
        }
        if truncated {
            assert_eq!(expected.lines().count(), 2000, "{file}: head length");
            assert_eq!(
                Some(sha.finish()),
                case.sha256,
                "{file}: sha256 of full stream"
            );
        } else {
            assert!(exp.next().is_none(), "{file}: fixture longer than range");
        }
        checked.push(file.to_string());
    }
    println!("CHECKED {checked:?}");
    for must in [
        "slash24_p80-443_seed1",
        "multirange_ports_seed7",
        "exclude_list_seed3",
        "slash8_excl_slash9",
        "slash22_p0-1023",
        "slash30_allports",
    ] {
        assert!(
            checked.iter().any(|f| f.contains(must)),
            "{must} not verified"
        );
    }
}
