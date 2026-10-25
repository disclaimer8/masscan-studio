//! A small in-memory gzip reader (RFC 1952 over RFC 1951), std only. The safety walk reads captures the lab
//! compressed (`*.pcap.gz`) without extracting them to disk and without a new dependency. Any malformed input is an
//! error, never a partial result: the caller fails closed.

/// Largest output accepted (above the largest archived capture, 9.6 MB). The declared ISIZE is checked against it
/// before anything is allocated, and the output never grows past the declared size.
const MAX_OUT: usize = 256 << 20;

struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
    bit: u32,
    n: u32,
}
impl Bits<'_> {
    fn need(&mut self, k: u32) -> Result<u32, String> {
        while self.n < k {
            let b = *self
                .d
                .get(self.pos)
                .ok_or("unexpected end of deflate data")?;
            self.pos += 1;
            self.bit |= u32::from(b) << self.n;
            self.n += 8;
        }
        let v = self.bit & ((1u64 << k) - 1) as u32;
        self.bit = if k == 32 { 0 } else { self.bit >> k };
        self.n -= k;
        Ok(v)
    }
}

struct Huff {
    count: [u16; 16],
    symbol: Vec<u16>,
}
impl Huff {
    fn new(lengths: &[u8]) -> Result<Huff, String> {
        let mut count = [0u16; 16];
        for l in lengths {
            count[usize::from(*l)] += 1;
        }
        let mut left: i32 = 1;
        for c in &count[1..] {
            left = (left << 1) - i32::from(*c);
            if left < 0 {
                return Err("over-subscribed Huffman code".into());
            }
        }
        let mut offs = [0u16; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + count[i];
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (s, l) in lengths.iter().enumerate() {
            if *l != 0 {
                symbol[usize::from(offs[usize::from(*l)])] = s as u16;
                offs[usize::from(*l)] += 1;
            }
        }
        Ok(Huff { count, symbol })
    }
    fn decode(&self, b: &mut Bits) -> Result<u16, String> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.need(1)? as i32;
            let c = i32::from(self.count[len]);
            if code - c < first {
                return self
                    .symbol
                    .get((index + (code - first)) as usize)
                    .copied()
                    .ok_or_else(|| "bad Huffman symbol".to_owned());
            }
            index += c;
            first += c;
            first <<= 1;
            code <<= 1;
        }
        Err("invalid Huffman code".into())
    }
}

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fn codes(
    b: &mut Bits,
    out: &mut Vec<u8>,
    lit: &Huff,
    dist: &Huff,
    limit: usize,
) -> Result<(), String> {
    loop {
        let sym = usize::from(lit.decode(b)?);
        match sym {
            0..=255 => {
                if out.len() >= limit {
                    return Err("output larger than the declared size".into());
                }
                out.push(sym as u8)
            }
            256 => return Ok(()),
            257..=285 => {
                let i = sym - 257;
                let len = usize::from(LBASE[i]) + b.need(u32::from(LEXT[i]))? as usize;
                let ds = usize::from(dist.decode(b)?);
                if ds >= 30 {
                    return Err("bad distance symbol".into());
                }
                let d = usize::from(DBASE[ds]) + b.need(u32::from(DEXT[ds]))? as usize;
                if d > out.len() {
                    return Err("distance too far back".into());
                }
                if out.len() + len > limit {
                    return Err("output larger than the declared size".into());
                }
                for _ in 0..len {
                    out.push(out[out.len() - d]);
                }
            }
            _ => return Err("bad length symbol".into()),
        }
    }
}

fn inflate(d: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    let mut b = Bits {
        d,
        pos: 0,
        bit: 0,
        n: 0,
    };
    let mut out = Vec::new();
    loop {
        let last = b.need(1)?;
        match b.need(2)? {
            0 => {
                b.bit = 0;
                b.n = 0;
                let h = d.get(b.pos..b.pos + 4).ok_or("truncated stored block")?;
                let len = usize::from(u16::from_le_bytes([h[0], h[1]]));
                if u16::from_le_bytes([h[2], h[3]]) != !u16::from_le_bytes([h[0], h[1]]) {
                    return Err("stored block length check failed".into());
                }
                b.pos += 4;
                if out.len() + len > limit {
                    return Err("output larger than the declared size".into());
                }
                out.extend_from_slice(d.get(b.pos..b.pos + len).ok_or("truncated stored block")?);
                b.pos += len;
            }
            1 => {
                let mut l = [8u8; 288];
                l[144..256].fill(9);
                l[256..280].fill(7);
                codes(
                    &mut b,
                    &mut out,
                    &Huff::new(&l)?,
                    &Huff::new(&[5u8; 30])?,
                    limit,
                )?;
            }
            2 => {
                let (nlen, ndist, ncode) = (
                    b.need(5)? as usize + 257,
                    b.need(5)? as usize + 1,
                    b.need(4)? as usize + 4,
                );
                if nlen > 286 || ndist > 30 {
                    return Err("too many length or distance codes".into());
                }
                const ORDER: [usize; 19] = [
                    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
                ];
                let mut cl = [0u8; 19];
                for o in ORDER.iter().take(ncode) {
                    cl[*o] = b.need(3)? as u8;
                }
                let ch = Huff::new(&cl)?;
                let mut ls = vec![0u8; nlen + ndist];
                let mut i = 0;
                while i < nlen + ndist {
                    let s = ch.decode(&mut b)?;
                    if s < 16 {
                        ls[i] = s as u8;
                        i += 1;
                        continue;
                    }
                    let (v, rep) = match s {
                        16 => (
                            *ls.get(i.wrapping_sub(1))
                                .ok_or("repeat with no previous length")?,
                            3 + b.need(2)?,
                        ),
                        17 => (0, 3 + b.need(3)?),
                        _ => (0, 11 + b.need(7)?),
                    };
                    if i + rep as usize > nlen + ndist {
                        return Err("too many code lengths".into());
                    }
                    for _ in 0..rep {
                        ls[i] = v;
                        i += 1;
                    }
                }
                codes(
                    &mut b,
                    &mut out,
                    &Huff::new(&ls[..nlen])?,
                    &Huff::new(&ls[nlen..])?,
                    limit,
                )?;
            }
            _ => return Err("reserved deflate block type".into()),
        }
        if last == 1 {
            return Ok((out, b.pos));
        }
    }
}

/// Decompress one gzip member (trailing bytes after its trailer are an error).
pub fn gunzip(d: &[u8]) -> Result<Vec<u8>, String> {
    if d.len() < 18 || d[0] != 0x1f || d[1] != 0x8b || d[2] != 8 {
        return Err("not a gzip member".into());
    }
    let flg = d[3];
    let mut p = 10;
    if flg & 4 != 0 {
        let x = usize::from(u16::from_le_bytes([
            *d.get(p).ok_or("short header")?,
            *d.get(p + 1).ok_or("short header")?,
        ]));
        p += 2 + x;
    }
    for bit in [8u8, 16] {
        if flg & bit != 0 {
            while *d.get(p).ok_or("unterminated header string")? != 0 {
                p += 1;
            }
            p += 1;
        }
    }
    if flg & 2 != 0 {
        p += 2;
    }
    let body = d.get(p..).ok_or("short header")?;
    // ISIZE (the last four bytes) is the declared size: refuse an absurd one before allocating anything, and never
    // let the output grow past it.
    let declared = u32::from_le_bytes([
        d[d.len() - 4],
        d[d.len() - 3],
        d[d.len() - 2],
        d[d.len() - 1],
    ]) as usize;
    if declared > MAX_OUT {
        return Err(format!(
            "declared size {declared} exceeds the {MAX_OUT} byte limit"
        ));
    }
    let (out, used) = inflate(body, declared)?;
    let tr = body.get(used..used + 8).ok_or("missing gzip trailer")?;
    if body.len() != used + 8 {
        return Err("bytes after the gzip trailer".into());
    }
    let (crc, isize) = (
        u32::from_le_bytes([tr[0], tr[1], tr[2], tr[3]]),
        u32::from_le_bytes([tr[4], tr[5], tr[6], tr[7]]),
    );
    if isize != out.len() as u32 {
        return Err("gzip size mismatch".into());
    }
    if crc32(&out) != crc {
        return Err("gzip CRC mismatch".into());
    }
    Ok(out)
}

pub(crate) fn crc32(d: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for b in d {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xedb8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn lcg(n: usize, mask: u8) -> Vec<u8> {
        let mut x = 12345u32;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                ((x >> 24) as u8) & mask
            })
            .collect()
    }

    /// The deterministic plaintext of a vector. The `.gz` files under `testdata/gz/` were made once on the Mac from
    /// exactly these bytes with `gzip -<level> -n` (see `dump_plaintexts`), so no test needs an external tool.
    fn plain(kind: &str) -> Vec<u8> {
        match kind {
            "empty" => Vec::new(),
            "hello" => b"hello".to_vec(),
            "text" => {
                let mut v = Vec::new();
                for i in 0..400u32 {
                    v.extend_from_slice(&(i.wrapping_mul(2654435761) >> (i % 7)).to_le_bytes());
                    v.extend_from_slice(b"198.18.0.2 RST ACK 0xf0e1 ");
                }
                v
            }
            "random" => lcg(3000, 0xff),
            "multi" => lcg(70000, 7),
            _ => panic!("unknown vector {kind}"),
        }
    }

    macro_rules! gz {
        ($name:literal) => {
            include_bytes!(concat!("../testdata/gz/", $name, ".gz")).as_slice()
        };
    }

    /// (vector, plaintext kind, sha256 of the plaintext, what the deflate stream is made of)
    fn vectors() -> Vec<(&'static str, &'static str, &'static str, &'static [u8])> {
        vec![
            (
                "empty.l6",
                "empty",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                gz!("empty.l6"),
            ),
            (
                "hello.l6",
                "hello",
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
                gz!("hello.l6"),
            ),
            ("text.l1", "text", TEXT_SHA, gz!("text.l1")),
            ("text.l6", "text", TEXT_SHA, gz!("text.l6")),
            ("text.l9", "text", TEXT_SHA, gz!("text.l9")),
            ("random.l1", "random", RANDOM_SHA, gz!("random.l1")),
            ("random.l6", "random", RANDOM_SHA, gz!("random.l6")),
            ("multi.l1", "multi", MULTI_SHA, gz!("multi.l1")),
            ("multi.l6", "multi", MULTI_SHA, gz!("multi.l6")),
            ("multi.l9", "multi", MULTI_SHA, gz!("multi.l9")),
        ]
    }
    const TEXT_SHA: &str = "b042cff1ed566fcdff798c7e32acc33847057fbb82ab50ef40d34327aadcf696";
    const RANDOM_SHA: &str = "75fe167f7710a81ef249b6bbf40d8291dc1a4913ab72a74ec56187b542b6ef82";
    const MULTI_SHA: &str = "2e984bedc7104d654f130f9498324f08e196887bcce8d27dca379c51c43605a0";

    fn sha(d: &[u8]) -> String {
        Sha256::digest(d)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// The first deflate block type of a gzip member written without optional header fields (`gzip -n`).
    fn first_block_type(z: &[u8]) -> u8 {
        (z[10] >> 1) & 3
    }

    #[test]
    fn reads_the_gzip_vectors_stored_fixed_dynamic_and_multi_block() {
        let mut kinds = std::collections::BTreeSet::new();
        for (name, kind, want_sha, z) in vectors() {
            let out = gunzip(z).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(sha(&out), want_sha, "{name}: sha256");
            assert_eq!(out, plain(kind), "{name}: plaintext");
            kinds.insert(first_block_type(z));
        }
        // Stored (0), fixed (1) and dynamic (2) deflate blocks are all exercised by real gzip output.
        assert_eq!(kinds.into_iter().collect::<Vec<_>>(), vec![0, 1, 2]);
    }

    #[test]
    fn a_vector_with_more_than_one_deflate_block_is_read() {
        // 70000 symbols cannot fit one gzip block (32768 symbols per block): the stream continues past a non-final block.
        let z = gz!("multi.l6");
        assert_eq!(
            inflate(&z[10..z.len()], 70000).map(|(o, _)| o.len()),
            Ok(70000)
        );
        let first_final = z[10] & 1;
        assert_eq!(first_final, 0, "the first block must not be the last one");
    }

    #[test]
    fn damaged_input_is_an_error_never_a_partial_result() {
        let z = gz!("text.l6").to_vec();
        assert!(gunzip(&z[..z.len() - 3]).is_err(), "truncated");
        let mut bad = z.clone();
        let last = bad.len() - 6;
        bad[last] ^= 1;
        assert!(gunzip(&bad).is_err(), "CRC");
        let mut size = z.clone();
        let n = size.len() - 1;
        size[n] ^= 1;
        assert!(gunzip(&size).is_err(), "size");
        let mut more = z.clone();
        more.push(0);
        assert!(gunzip(&more).is_err(), "trailing byte");
        let mut mid = z.clone();
        let m = mid.len() / 2;
        mid[m] ^= 0x55;
        assert!(
            gunzip(&mid).is_err(),
            "a flipped bit inside the deflate data"
        );
        let mut magic = z.clone();
        magic[0] = 0;
        assert!(gunzip(&magic).is_err());
        assert!(gunzip(b"not gzip at all, really not gzip").is_err());
    }

    /// A small input must not make the reader allocate: a declared size beyond the cap is refused up front, and a
    /// stream that expands past its own declared size stops there.
    #[test]
    fn a_small_input_claiming_or_expanding_to_a_huge_size_is_an_error_without_a_big_allocation() {
        // 1. ISIZE claims 4 GiB - 1: refused before inflating.
        let mut z = gz!("hello.l6").to_vec();
        let n = z.len();
        z[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        let e = gunzip(&z).unwrap_err();
        assert!(e.contains("exceeds"), "{e}");
        // 2. The multi-block vector expands to 70000 bytes but claims 10: the output stops at the claim.
        let mut z = gz!("multi.l6").to_vec();
        let n = z.len();
        z[n - 4..].copy_from_slice(&10u32.to_le_bytes());
        let e = gunzip(&z).unwrap_err();
        assert!(e.contains("declared size"), "{e}");
        // 3. A tiny hand-made stream: a fixed block with a 258-byte match repeated, claiming 1000 bytes, whose
        // symbols would expand to far more; it stops at the claim.
        let mut bits = Vec::<u8>::new();
        let mut acc = 0u64;
        let mut cnt = 0u32;
        let mut put = |v: u64, k: u32, bits: &mut Vec<u8>| {
            acc |= v << cnt;
            cnt += k;
            while cnt >= 8 {
                bits.push(acc as u8);
                acc >>= 8;
                cnt -= 8;
            }
        };
        let rev = |code: u32, len: u32| {
            (0..len).fold(0u64, |a, i| {
                a | (u64::from((code >> i) & 1) << (len - 1 - i))
            })
        };
        put(1, 1, &mut bits); // final
        put(1, 2, &mut bits); // fixed
        put(rev(0x30 + u32::from(b'a'), 8), 8, &mut bits); // literal 'a'
        for _ in 0..4000 {
            put(rev(0xc0 + 285 - 280, 8), 8, &mut bits); // length 258
            put(rev(0, 5), 5, &mut bits); // distance 1
        }
        put(0, 7, &mut bits); // end of block
        put(0, 7, &mut bits);
        let mut z = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
        z.extend_from_slice(&bits);
        z.extend_from_slice(&0u32.to_le_bytes());
        z.extend_from_slice(&1000u32.to_le_bytes());
        let e = gunzip(&z).unwrap_err();
        assert!(e.contains("declared size"), "{e}");
    }

    /// Cross-check against the system gzip on Unix, in addition to the embedded vectors.
    #[cfg(unix)]
    #[test]
    fn matches_the_system_gzip_when_there_is_one() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let Ok(mut g) = Command::new("gzip")
            .args(["-c", "-6"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        else {
            return;
        };
        let data = plain("multi");
        let mut stdin = g.stdin.take().unwrap();
        let d = data.clone();
        let w = std::thread::spawn(move || stdin.write_all(&d).unwrap());
        let o = g.wait_with_output().unwrap();
        w.join().unwrap();
        assert_eq!(gunzip(&o.stdout).unwrap(), data);
    }

    /// Writes the plaintexts the `.gz` vectors were made from: `RMASSCAN_GZ_DUMP=<dir> cargo test -- --ignored
    /// dump_plaintexts`, then `gzip -n -1 / -6 / -9 -c` each file into `testdata/gz/<kind>.l<level>.gz`.
    #[test]
    #[ignore = "regenerates the vector inputs"]
    fn dump_plaintexts() {
        let dir = std::env::var("RMASSCAN_GZ_DUMP").expect("RMASSCAN_GZ_DUMP");
        for kind in ["empty", "hello", "text", "random", "multi"] {
            std::fs::write(format!("{dir}/{kind}"), plain(kind)).unwrap();
            println!("{kind} {}", sha(&plain(kind)));
        }
    }
}
