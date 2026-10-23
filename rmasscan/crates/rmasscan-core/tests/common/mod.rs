//! Общая поддержка golden-тестов (AGPL-3.0, masscan © Robert David Graham):
//! манифест, путь к фикстурам, SHA-256 (только для тестов) и разбор
//! аргументов `-sL` (main-listscan.c:15-65, main.c:1595).
#![allow(dead_code)]

use serde::Deserialize;

/// Каталог golden-фикстур; не зависит от cwd.
pub const GOLDEN_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden");

#[derive(Deserialize)]
pub struct Manifest {
    pub cases: Vec<Case>,
    pub offline_gen_pps: Option<f64>,
    pub offline_gen_bench: Option<GenBench>,
}

#[derive(Deserialize)]
pub struct GenBench {
    pub cpu_model: Option<String>,
}

#[derive(Deserialize)]
pub struct Case {
    pub file: Option<String>,
    pub mode: Option<String>,
    pub args: Option<Vec<String>>,
    pub line_count: Option<u64>,
    pub sha256: Option<String>,
    pub truncated: Option<bool>,
}

pub fn load_manifest() -> Manifest {
    let text = std::fs::read_to_string(format!("{GOLDEN_DIR}/manifest.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// Параметры `-sL` кейса (то, что `main_listscan` берёт из Masscan).
pub struct ListSpec {
    pub targets: String,
    pub ports: String,
    pub excludes: Vec<String>,
    pub seed: u64,
    pub rounds: u32,
    /// `shard.one`, `shard.of` (по умолчанию 1/1).
    pub shard_one: u32,
    pub shard_of: u32,
    pub resume_index: u64,
    /// `resume.count`, `None` = не задан (C: 0 = без ограничения).
    pub resume_count: Option<u64>,
    pub retries: u32,
    /// `max_rate` (double); по умолчанию 100 (main.c:1599), задаётся `--rate`.
    pub max_rate: f64,
}

/// `Err(reason)` когда кейс вне области v1 (неизвестные опции).
/// IPv6 определяется вызывающим по `targets`.
pub fn parse_listscan_args(args: &[String]) -> Result<ListSpec, String> {
    let (mut targets, mut ports) = (None, None);
    let mut excludes = Vec::new();
    let (mut seed, mut rounds) = (None, 14u32); // main.c:1595
    let (mut shard_one, mut shard_of) = (1u32, 1u32);
    let (mut resume_index, mut resume_count) = (0u64, None);
    let (mut retries, mut max_rate) = (0u32, 100.0f64); // main.c:1599
    let mut it = args.iter().skip(1); // -sL
    while let Some(a) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("missing {name} value"));
        let num = |s: String| s.parse::<u64>().map_err(|e| format!("{s}: {e}"));
        match a.as_str() {
            "--seed" => seed = Some(num(val("seed")?)?),
            "--blackrock-rounds" => rounds = num(val("rounds")?)? as u32,
            "--exclude" => excludes.push(val("exclude")?),
            "--retries" => retries = num(val("retries")?)? as u32,
            "--rate" => {
                let v = val("rate")?;
                max_rate = v.parse::<f64>().map_err(|e| format!("{v}: {e}"))?;
            }
            "--shard" => {
                let v = val("shard")?;
                let (o, f) = v.split_once('/').ok_or("bad shard")?;
                (shard_one, shard_of) = (num(o.into())? as u32, num(f.into())? as u32);
                if shard_one == 0 || shard_one > shard_of {
                    return Err("bad shard".into());
                }
            }
            "--resume-index" => resume_index = num(val("resume-index")?)?,
            "--resume-count" => resume_count = Some(num(val("resume-count")?)?),
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
    Ok(ListSpec {
        targets: targets.ok_or("no target")?,
        ports: ports.ok_or("no -p")?,
        excludes,
        seed: seed.ok_or("no --seed")?,
        rounds,
        shard_one,
        shard_of,
        resume_index,
        resume_count,
        retries,
        max_rate,
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

pub struct Sha256 {
    h: [u32; 8],
    buf: Vec<u8>,
    len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
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

    pub fn update(&mut self, mut data: &[u8]) {
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

    pub fn finish(mut self) -> String {
        let bits = self.len * 8;
        self.update(&[0x80]);
        while self.buf.len() != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        self.h.iter().map(|x| format!("{x:08x}")).collect()
    }
}
