//! Фильтр RST на FIN без соединения: `rstfilter_is_filter` (`src/misc-rstfilter.c:61-133`, справка A7), порт
//! masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0.
//!
//! 16384 корзины по 4 бита (`rstfilter_create(entropy, 16384)`, `src/main.c:553`), ключ SipHash `{seed, seed}`.
//! Корзина соединения на 15 фильтрует, иначе растёт на 1; каждый вызов уменьшает одну псевдослучайную корзину, поэтому
//! насыщенная пара изредка снова получает RST. Отличие от C (класс в, справка E1.11): у IPv4 пятое слово входа C не
//! заполняет (`:67-82`) и хэширует мусор стека, здесь оно 0.

use rmasscan_core::cookie::siphash24;
use rmasscan_core::stack::{ConnAddrs, ConnKey};

/// Число корзин (`src/main.c:553`), степень двойки.
const BUCKETS: usize = 16384;

/// `struct ResetFilter` (`src/misc-rstfilter.c:6-13`). Корзины заводятся на первом вызове: таблица без FIN без
/// соединения памяти под фильтр не держит.
#[derive(Clone, Debug)]
pub(crate) struct RstFilter {
    seed: u64,
    /// `unsigned counter`: номер вызова во втором хэше.
    counter: u32,
    /// Две корзины на байт: чётная в старшем полубайте, нечётная в младшем (`:103-114`).
    buckets: Vec<u8>,
}

impl RstFilter {
    pub(crate) fn new(seed: u64) -> RstFilter {
        RstFilter {
            seed,
            counter: 0,
            buckets: Vec::new(),
        }
    }

    /// `rstfilter_is_filter(rf, ip_me, port_me, ip_them, port_them)` (`src/main.c:1033`): `true` значит RST не
    /// слать.
    pub(crate) fn is_filtered(&mut self, k: &ConnKey) -> bool {
        if self.buckets.is_empty() {
            self.buckets = vec![0; BUCKETS / 2];
        }
        let mut input = match k.addrs {
            // `:77-82`; `input[4]` нулём (E1.11).
            ConnAddrs::V4 { local, remote } => [
                u64::from(local),
                u64::from(k.local_port),
                u64::from(remote),
                u64::from(k.remote_port),
                0,
            ],
            // `:83-89`: `hi` это старшие 64 бита адреса; слово портов в `unsigned`.
            ConnAddrs::V6 { local, remote } => [
                high(local),
                low(local),
                high(remote),
                low(remote),
                u64::from((u32::from(k.local_port) << 16) | u32::from(k.remote_port)),
            ],
        };
        let hash = self.hash(&input);
        let filtered = match self.bucket(hash) {
            Some((byte, shift)) => {
                let nibble = (*byte >> shift) & 0x0F;
                if nibble == 0x0F {
                    true
                } else {
                    *byte = byte.wrapping_add(1 << shift);
                    false
                }
            }
            None => false,
        };
        // Опустошить случайную корзину (`:116-130`): `input[0] = (unsigned)hash`, `input[1] = counter++`.
        input[0] = u64::from(hash as u32);
        input[1] = u64::from(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let hash = self.hash(&input);
        if let Some((byte, shift)) = self.bucket(hash)
            && (*byte >> shift) & 0x0F != 0
        {
            *byte = byte.wrapping_sub(1 << shift);
        }
        filtered
    }

    /// Байты корзин (0 до первого вызова).
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        self.buckets.len()
    }

    /// `siphash24(input, sizeof(input), key)`: 40 байт, слова в порядке байтов хоста (все цели LE).
    fn hash(&self, input: &[u64; 5]) -> u64 {
        let mut bytes = [0u8; 40];
        for (dst, word) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(input) {
            dst.copy_from_slice(&word.to_le_bytes());
        }
        siphash24(&bytes, self.seed, self.seed)
    }

    /// Байт корзины `hash & (BUCKETS - 1)` и сдвиг её полубайта.
    fn bucket(&mut self, hash: u64) -> Option<(&mut u8, u8)> {
        let index = usize::try_from(hash & (BUCKETS as u64 - 1)).unwrap_or(0);
        let shift = if index & 1 == 1 { 0 } else { 4 };
        self.buckets.get_mut(index / 2).map(|b| (b, shift))
    }
}

/// `ipv6address.hi`.
fn high(a: u128) -> u64 {
    (a >> 64) as u64
}

/// `ipv6address.lo`.
fn low(a: u128) -> u64 {
    a as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(remote: u32, remote_port: u16) -> ConnKey {
        ConnKey {
            addrs: ConnAddrs::V4 {
                local: 0xc0a8_0001,
                remote,
            },
            local_port: 61000,
            remote_port,
        }
    }

    /// FNV-1a 64 по байтам итогов 0/1, как у оракула.
    fn fnv(h: u64, b: u8) -> u64 {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    }

    fn run(f: &mut RstFilter, keys: &[ConnKey], calls: usize) -> (u32, u64) {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        let mut passes = 0u32;
        for n in 0..calls {
            let r = f.is_filtered(&keys[n % keys.len()]);
            passes += u32::from(!r);
            h = fnv(h, u8::from(r));
        }
        (passes, h)
    }

    /// Векторы оракула вне репозитория: `src/misc-rstfilter.c` и `src/crypto-siphash24.c` C с `input[5] = {0}` (E1.11)
    /// и драйвер на те же ключи. Одна пара: 15 RST, потом фильтр; 300 пар IPv4 и 300 пар IPv6 по кругу, 20 000 вызовов:
    /// число пропусков и FNV-1a последовательности итогов (опустошение случайных корзин вносит в неё ~300 пропусков).
    #[test]
    fn rstfilter_matches_c_vectors() {
        let mut f = RstFilter::new(0x1122_3344_5566_7788);
        let key = ConnKey {
            addrs: ConnAddrs::V4 {
                local: 0x0a00_0001,
                remote: 0x0a00_0002,
            },
            local_port: 40000,
            remote_port: 80,
        };
        let got: String = (0..20)
            .map(|_| if f.is_filtered(&key) { '1' } else { '0' })
            .collect();
        assert_eq!(got, "00000000000000011111");

        let keys: Vec<ConnKey> = (0..300u32)
            .map(|i| v4(0x0a00_0000 + i, 80 + u16::try_from(i % 7).expect("port")))
            .collect();
        let mut f = RstFilter::new(0x0123_4567_89ab_cdef);
        assert_eq!(run(&mut f, &keys, 20_000), (4808, 0x4ca7_85e4_342b_db13));

        let keys: Vec<ConnKey> = (0..300u32)
            .map(|i| ConnKey {
                addrs: ConnAddrs::V6 {
                    local: (0x2001_0db8_0000_0000u128 << 64) | 1,
                    remote: (0x2001_0db8_0001_0000u128 << 64) | (u128::from(i) * 0x1_0001),
                },
                local_port: 61000,
                remote_port: 443 + u16::try_from(i % 5).expect("port"),
            })
            .collect();
        let mut f = RstFilter::new(0xfedc_ba98_7654_3210);
        assert_eq!(run(&mut f, &keys, 20_000), (4825, 0xc318_35d8_0c8d_1b9c));
    }

    #[test]
    fn buckets_allocated_on_first_use() {
        let mut f = RstFilter::new(7);
        assert!(f.buckets.is_empty());
        assert!(!f.is_filtered(&v4(1, 2)));
        assert_eq!(f.buckets.len(), BUCKETS / 2);
        assert_eq!(f.counter, 1);
    }
}
