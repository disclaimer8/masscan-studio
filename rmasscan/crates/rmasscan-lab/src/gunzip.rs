//! A small in-memory gzip reader (RFC 1952 over RFC 1951), std only. The safety walk reads captures the lab
//! compressed (`*.pcap.gz`) without extracting them to disk and without a new dependency. Any malformed input is an
//! error, never a partial result: the caller fails closed.

const MAX_OUT: usize = 1 << 30;

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

fn codes(b: &mut Bits, out: &mut Vec<u8>, lit: &Huff, dist: &Huff) -> Result<(), String> {
    loop {
        let sym = usize::from(lit.decode(b)?);
        match sym {
            0..=255 => out.push(sym as u8),
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
                for _ in 0..len {
                    out.push(out[out.len() - d]);
                }
            }
            _ => return Err("bad length symbol".into()),
        }
        if out.len() > MAX_OUT {
            return Err("output too large".into());
        }
    }
}

fn inflate(d: &[u8]) -> Result<(Vec<u8>, usize), String> {
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
                out.extend_from_slice(d.get(b.pos..b.pos + len).ok_or("truncated stored block")?);
                b.pos += len;
            }
            1 => {
                let mut l = [8u8; 288];
                l[144..256].fill(9);
                l[256..280].fill(7);
                codes(&mut b, &mut out, &Huff::new(&l)?, &Huff::new(&[5u8; 30])?)?;
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
                )?;
            }
            _ => return Err("reserved deflate block type".into()),
        }
        if out.len() > MAX_OUT {
            return Err("output too large".into());
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
    let (out, used) = inflate(body)?;
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

fn crc32(d: &[u8]) -> u32 {
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
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn gzip(data: &[u8], level: &str) -> Vec<u8> {
        let mut g = Command::new("/usr/bin/gzip")
            .args(["-c", level])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = g.stdin.take().unwrap();
        let data = data.to_vec();
        let w = std::thread::spawn(move || stdin.write_all(&data).unwrap());
        let o = g.wait_with_output().unwrap();
        w.join().unwrap();
        assert!(o.status.success());
        o.stdout
    }

    #[test]
    fn reads_what_gzip_writes_at_every_level() {
        let mut data = Vec::new();
        for i in 0..20000u32 {
            data.extend_from_slice(&(i.wrapping_mul(2654435761) >> (i % 7)).to_le_bytes());
            data.extend_from_slice(b"198.18.0.2 RST ACK 0xf0e1 ");
        }
        for level in ["-1", "-6", "-9"] {
            assert_eq!(gunzip(&gzip(&data, level)).unwrap(), data, "{level}");
        }
        assert_eq!(gunzip(&gzip(b"", "-6")).unwrap(), b"");
        let rnd: Vec<u8> = (0..70000u32)
            .map(|i| (i.wrapping_mul(2246822519) >> 13) as u8)
            .collect();
        assert_eq!(gunzip(&gzip(&rnd, "-6")).unwrap(), rnd);
    }

    #[test]
    fn damaged_input_is_an_error_never_a_partial_result() {
        let z = gzip(&vec![7u8; 5000], "-6");
        assert!(gunzip(&z[..z.len() - 3]).is_err());
        let mut bad = z.clone();
        let last = bad.len() - 6;
        bad[last] ^= 1;
        assert!(gunzip(&bad).is_err(), "CRC");
        let mut more = z.clone();
        more.push(0);
        assert!(gunzip(&more).is_err());
        assert!(gunzip(b"not gzip at all, really not gzip").is_err());
    }
}
