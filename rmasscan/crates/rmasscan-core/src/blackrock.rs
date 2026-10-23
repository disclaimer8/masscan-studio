//! BlackRock: перестановка Фейстеля, задающая порядок целей (AGPL-3.0).
//! Порт `src/crypto-blackrock.c` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Любое расхождение с C меняет порядок всех целей, поэтому арифметика
//! `uint64_t` повторена дословно, а переполнения выражены через `wrapping_*`.

/// S-box, crypto-blackrock.c:68.
pub const SBOX: [u8; 256] = [
    0x91, 0x58, 0xb3, 0x31, 0x6c, 0x33, 0xda, 0x88, 0x57, 0xdd, 0x8c, 0xf2, 0x29, 0x5a, 0x08, 0x9f,
    0x49, 0x34, 0xce, 0x99, 0x9e, 0xbf, 0x0f, 0x81, 0xd4, 0x2f, 0x92, 0x3f, 0x95, 0xf5, 0x23, 0x00,
    0x0d, 0x3e, 0xa8, 0x90, 0x98, 0xdd, 0x20, 0x00, 0x03, 0x69, 0x0a, 0xca, 0xba, 0x12, 0x08, 0x41,
    0x6e, 0xb9, 0x86, 0xe4, 0x50, 0xf0, 0x84, 0xe2, 0xb3, 0xb3, 0xc8, 0xb5, 0xb2, 0x2d, 0x18, 0x70,
    0x0a, 0xd7, 0x92, 0x90, 0x9e, 0x1e, 0x0c, 0x1f, 0x08, 0xe8, 0x06, 0xfd, 0x85, 0x2f, 0xaa, 0x5d,
    0xcf, 0xf9, 0xe3, 0x55, 0xb9, 0xfe, 0xa6, 0x7f, 0x44, 0x3b, 0x4a, 0x4f, 0xc9, 0x2f, 0xd2, 0xd3,
    0x8e, 0xdc, 0xae, 0xba, 0x4f, 0x02, 0xb4, 0x76, 0xba, 0x64, 0x2d, 0x07, 0x9e, 0x08, 0xec, 0xbd,
    0x52, 0x29, 0x07, 0xbb, 0x9f, 0xb5, 0x58, 0x6f, 0x07, 0x55, 0xb0, 0x34, 0x74, 0x9f, 0x05, 0xb2,
    0xdf, 0xa9, 0xc6, 0x2a, 0xa3, 0x5d, 0xff, 0x10, 0x40, 0xb3, 0xb7, 0xb4, 0x63, 0x6e, 0xf4, 0x3e,
    0xee, 0xf6, 0x49, 0x52, 0xe3, 0x11, 0xb3, 0xf1, 0xfb, 0x60, 0x48, 0xa1, 0xa4, 0x19, 0x7a, 0x2e,
    0x90, 0x28, 0x90, 0x8d, 0x5e, 0x8c, 0x8c, 0xc4, 0xf2, 0x4a, 0xf6, 0xb2, 0x19, 0x83, 0xea, 0xed,
    0x6d, 0xba, 0xfe, 0xd8, 0xb6, 0xa3, 0x5a, 0xb4, 0x48, 0xfa, 0xbe, 0x5c, 0x69, 0xac, 0x3c, 0x8f,
    0x63, 0xaf, 0xa4, 0x42, 0x25, 0x50, 0xab, 0x65, 0x80, 0x65, 0xb9, 0xfb, 0xc7, 0xf2, 0x2d, 0x5c,
    0xe3, 0x4c, 0xa4, 0xa6, 0x8e, 0x07, 0x9c, 0xeb, 0x41, 0x93, 0x65, 0x44, 0x4a, 0x86, 0xc1, 0xf6,
    0x2c, 0x97, 0xfd, 0xf4, 0x6c, 0xdc, 0xe1, 0xe0, 0x28, 0xd9, 0x89, 0x7b, 0x09, 0xe2, 0xa0, 0x38,
    0x74, 0x4a, 0xa6, 0x5e, 0xd2, 0xe2, 0x4d, 0xf3, 0xf4, 0xc6, 0xbc, 0xa2, 0x51, 0x58, 0xe8, 0xae,
];

/// Ошибки конструктора.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlackRockError {
    /// `range == 0`: в C `a = b = 0` и деление на ноль (crypto-blackrock.c:117).
    #[error("blackrock range must be non-zero")]
    EmptyRange,
    /// `seed >> (64 - r)` в C определён только для `r < 64`.
    #[error("blackrock rounds must be < 64")]
    TooManyRounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlackRock {
    a: u64,
    b: u64,
    rounds: u32,
    seed: u64,
    range: u64,
}

impl BlackRock {
    /// `blackrock_init`, crypto-blackrock.c:108. Вызывающий обязан не
    /// допускать пустой range; здесь он отклоняется ошибкой.
    pub fn try_new(range: u64, seed: u64, rounds: u32) -> Result<BlackRock, BlackRockError> {
        if range == 0 {
            return Err(BlackRockError::EmptyRange);
        }
        if rounds >= 64 {
            return Err(BlackRockError::TooManyRounds);
        }
        // C: `sqrt(range * 1.0)`; u64 -> f64 округляется так же, как в C
        // (round-to-nearest-even), sqrt корректно округлён в IEEE-754.
        let root = (range as f64).sqrt();
        // Таблица малых range, :116-148.
        let (a, mut b) = match range {
            1 => (1, 1),
            2 => (1, 2),
            3 => (2, 2),
            4..=6 => (2, 3),
            7 | 8 => (3, 3),
            // `(uint64_t)(root - 2)`; для range >= 9 root >= 3, значит >= 1.
            _ => ((root - 2.0) as u64, (root + 3.0) as u64),
        };
        // :150
        while a.wrapping_mul(b) <= range {
            b = b.wrapping_add(1);
        }
        Ok(BlackRock {
            a,
            b,
            rounds,
            seed,
            range,
        })
    }

    /// То же, что [`BlackRock::try_new`], но паникует на `range == 0` или
    /// `rounds >= 64`.
    pub fn new(range: u64, seed: u64, rounds: u32) -> BlackRock {
        match Self::try_new(range, seed, rounds) {
            Ok(br) => br,
            Err(e) => panic!("BlackRock::new: {e}"),
        }
    }

    /// `blackrock_shuffle`, :268 (cycle-walking).
    pub fn shuffle(&self, m: u64) -> u64 {
        let mut c = encrypt(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = encrypt(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }

    /// `blackrock_unshuffle`, :282.
    pub fn unshuffle(&self, m: u64) -> u64 {
        let mut c = unencrypt(self.rounds, self.a, self.b, m, self.seed);
        while c >= self.range {
            c = unencrypt(self.rounds, self.a, self.b, c, self.seed);
        }
        c
    }
}

/// `READ`, crypto-blackrock.c:164.
fn read(r: u64, big_r: u64, seed: u64) -> u64 {
    // :171. r in 1..64, так что оба сдвига < 64.
    let big_r = big_r ^ (seed.wrapping_shl(r as u32) ^ seed.wrapping_shr((64 - r) as u32));
    let byte = |n: u32| -> usize { ((((big_r >> (n * 8)) ^ seed ^ r) & 0xFF) as u8) as usize };
    // В C `sbox[..]<<24UL` имеет тип int (сдвиг берёт тип левого операнда);
    // gcc даёт знаковое значение, которое затем расширяется и маскируется
    // `& 0x0ffffFFFF`, т.е. результат равен вычислению в u32/u64 с маской.
    let s = |n: u32| -> u32 { SBOX[byte(n)] as u32 };
    let r0 = (s(0) as u64) | ((s(1) as u64) << 8);
    // `16UL`/`24UL`: сдвиг в unsigned long (64 бита), без знаковых эффектов.
    let r1 = (((s(2) as u64) << 16) | ((s(3) as u64) << 24)) & 0xffff_ffff;
    let r2 = (s(4) as u64) | ((s(5) as u64) << 8);
    let r3 = (((s(6) as u64) << 16) | ((s(7) as u64) << 24)) & 0xffff_ffff;
    // :181. `r2<<23UL ^ r3<<33UL`: старшие биты отбрасываются, как в C.
    r0 ^ r1 ^ r2.wrapping_shl(23) ^ r3.wrapping_shl(33)
}

/// `ENCRYPT`, crypto-blackrock.c:192.
fn encrypt(r: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let mut l = m % a;
    let mut rr = m / a;
    for j in 1..=r {
        let t = l.wrapping_add(read(j as u64, rr, seed));
        let tmp = if j & 1 != 0 { t % a } else { t % b };
        l = rr;
        rr = tmp;
    }
    if r & 1 != 0 {
        a.wrapping_mul(l).wrapping_add(rr)
    } else {
        a.wrapping_mul(rr).wrapping_add(l)
    }
}

/// `UNENCRYPT`, crypto-blackrock.c:220.
fn unencrypt(r: u32, a: u64, b: u64, m: u64, seed: u64) -> u64 {
    let (mut l, mut rr);
    if r & 1 != 0 {
        rr = m % a;
        l = m / a;
    } else {
        l = m % a;
        rr = m / a;
    }
    for j in (1..=r).rev() {
        let modulus = if j & 1 != 0 { a } else { b };
        let mut tmp = read(j as u64, l, seed);
        if tmp > rr {
            tmp -= rr;
            tmp = modulus - (tmp % modulus);
            if tmp == modulus {
                tmp = 0;
            }
        } else {
            tmp = (rr - tmp) % modulus;
        }
        rr = l;
        l = tmp;
    }
    a.wrapping_mul(rr).wrapping_add(l)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffle_unshuffle_round_trip() {
        let br = BlackRock::new(1000, 0, 4);
        for i in 0..10u64 {
            assert_eq!(br.unshuffle(br.shuffle(i)), i);
        }
    }

    #[test]
    fn shuffle_is_a_permutation() {
        // blackrock_verify, crypto-blackrock.c:298
        for seed in [1u64, 2, 42] {
            for &range in &[6056u64, 6074, 6094] {
                let br = BlackRock::new(range, seed, 4);
                let mut seen = vec![0u8; range as usize];
                for i in 0..range {
                    seen[br.shuffle(i) as usize] += 1;
                }
                assert!(seen.iter().all(|&c| c == 1));
            }
        }
    }

    #[test]
    fn tiny_ranges_are_permutations_and_round_trip() {
        // таблица :116-148 покрывает 1..=8; дальше идёт формула
        for range in 1..=40u64 {
            for rounds in [1u32, 3, 4, 14] {
                let br = BlackRock::new(range, 7, rounds);
                let mut seen = vec![0u8; range as usize];
                for i in 0..range {
                    let x = br.shuffle(i);
                    assert!(x < range);
                    seen[x as usize] += 1;
                    assert_eq!(br.unshuffle(x), i, "range {range} rounds {rounds}");
                }
                assert!(
                    seen.iter().all(|&c| c == 1),
                    "range {range} rounds {rounds}"
                );
            }
        }
    }

    #[test]
    fn range_one_maps_zero_to_zero() {
        assert_eq!(BlackRock::new(1, 1, 4).shuffle(0), 0);
    }

    #[test]
    fn zero_range_is_rejected() {
        assert_eq!(BlackRock::try_new(0, 1, 4), Err(BlackRockError::EmptyRange));
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn new_panics_on_zero_range() {
        let _ = BlackRock::new(0, 1, 4);
    }

    #[test]
    fn rounds_64_or_more_is_rejected() {
        assert_eq!(
            BlackRock::try_new(10, 1, 64),
            Err(BlackRockError::TooManyRounds)
        );
    }

    #[test]
    fn no_overflow_panic_on_large_range_and_rounds14() {
        let br = BlackRock::new(1_000_003, 0xdead_beef_cafe, 14);
        let x = br.shuffle(123_456);
        assert!(x < 1_000_003);
        assert_eq!(br.unshuffle(x), 123_456);
    }

    #[test]
    fn huge_range_and_seed_do_not_panic() {
        let br = BlackRock::new(1u64 << 48, u64::MAX, 63);
        let x = br.shuffle(u64::MAX >> 17);
        assert!(x < (1u64 << 48));
    }
}
