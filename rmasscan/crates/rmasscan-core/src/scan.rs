//! Генератор порядка целей: индексы `-sL` и поток индексов transmit (AGPL-3.0).
//! Порт `src/main-listscan.c` и арифметики индексов `transmit_thread`
//! (`src/main.c:203-448`) из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Все `uint64_t`-операции C, где возможно переполнение, выражены через
//! `wrapping_*`; `unsigned` (32 бита) в C остаётся `u32`.

use std::net::Ipv4Addr;

use crate::blackrock::{BlackRock, BlackRockError};
use crate::massip::{MassIp, RangeOverflow};

/// `--shard one/of` (masscan.h `shard.one`, `shard.of`; по умолчанию 1/1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shard {
    pub one: u32,
    pub of: u32,
}

impl Default for Shard {
    fn default() -> Self {
        Shard { one: 1, of: 1 }
    }
}

/// Ошибки `list_scan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// `range == 0`: в C деление на ноль в `blackrock_init` (crypto-blackrock.c:117).
    #[error("nothing to scan: the target range is empty")]
    EmptyRange,
    /// Диапазон не помещается в 63 бита (main.c:1698-1704).
    #[error(transparent)]
    RangeOverflow(#[from] RangeOverflow),
    /// `shard.of == 0`: шаг 0, в C бесконечный цикл (main-listscan.c:14,65).
    #[error("shard divisor must be non-zero")]
    ZeroShard,
    #[error(transparent)]
    BlackRock(#[from] BlackRockError),
}

/// Строка `-sL` (main-listscan.c:53-62, только IPv4): при ровно одном порте
/// печатается один IP, иначе `ip:port`.
pub fn format_list_line(ip: u32, port: u32, single_port: bool) -> String {
    let ip = Ipv4Addr::from(ip);
    if single_port {
        ip.to_string()
    } else {
        format!("{ip}:{port}")
    }
}

/// Итератор индексов `-sL`: `for (i=start; i<end; i += increment)`.
struct ListIndices {
    i: u64,
    end: u64,
    increment: u64,
}

impl Iterator for ListIndices {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.i >= self.end {
            return None;
        }
        let cur = self.i;
        self.i = self.i.wrapping_add(self.increment); // main-listscan.c:65
        Some(cur)
    }
}

/// Пред-shuffle индексы `i` для `-sL` (main-listscan.c:29-35,42,65).
///
/// Паникует при `shard.of == 0` (в C бесконечный цикл); [`list_scan`]
/// проверяет это заранее и возвращает ошибку.
pub fn list_scan_indices(
    range: u64,
    shard: Shard,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: u64,
) -> impl Iterator<Item = u64> {
    assert!(shard.of != 0, "shard.of must be non-zero");
    // :29 `resume.index + (shard.one-1)`: `shard.one-1` — unsigned (32 бита).
    let start = resume_index.wrapping_add(u64::from(shard.one.wrapping_sub(1)));
    let mut end = range; // :30
    // :31 `resume.count` равный 0 означает "без ограничения".
    if let Some(count) = resume_count.filter(|&c| c != 0) {
        let limit = start.wrapping_add(count);
        if end > limit {
            end = limit; // :32
        }
    }
    // :35 `end += (uint64_t)(retries * max_rate)` — max_rate, не range.
    end = end.wrapping_add(u64::from(retries).wrapping_mul(max_rate));
    ListIndices {
        i: start,
        end,
        increment: u64::from(shard.of), // :14
    }
}

/// Итератор transmit (main.c:269-334, :421-428).
struct TransmitIndices {
    i: u64,
    end: u64,
    range: u64,
    rate: u64,
    retries: u32,
    /// `unsigned r` (main.c:211).
    r: u32,
    increment: u64,
}

impl Iterator for TransmitIndices {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        if self.i >= self.end {
            return None; // main.c:269 `i < end`
        }
        // main.c:322 `xXx = (i + (r--) * rate)`: r — unsigned, повышается до u64.
        let (prod, o1) = u64::from(self.r).overflowing_mul(self.rate);
        let (mut x, o2) = self.i.overflowing_add(prod);
        self.r = self.r.wrapping_sub(1);
        // main.c:323-333: понижение по модулю range.
        if self.rate > self.range {
            x %= self.range;
        } else if !(o1 || o2) {
            x %= self.range; // то же, что цикл вычитания, когда сумма не переполнилась
        } else {
            while x >= self.range {
                x -= self.range;
            }
        }
        // main.c:424-427
        if self.r == 0 {
            self.i = self.i.wrapping_add(self.increment);
            self.r = self.retries.wrapping_add(1);
        }
        Some(x)
    }
}

/// Пред-shuffle значения `xXx` transmit-потока (main.c:203-448).
///
/// `nic_count` и `nic_index` в C — `unsigned`; здесь берутся как `u32`
/// (усечение), арифметика `shard.of * nic_count` и `(shard.one-1) * nic_count`
/// идёт в 32 битах с переполнением, как в C (:219, :266). Паникует, если
/// шаг (`shard.of * nic_count`) равен нулю: в C это бесконечный цикл.
#[allow(clippy::too_many_arguments)]
pub fn transmit_index_stream(
    range: u64,
    shard: Shard,
    nic_count: u64,
    nic_index: u64,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: u64,
) -> impl Iterator<Item = u64> {
    let nic_count = nic_count as u32;
    let nic_index = nic_index as u32;
    // :219 `unsigned increment = shard.of * nic_count`
    let increment = shard.of.wrapping_mul(nic_count);
    assert!(increment != 0, "shard.of * nic_count must be non-zero");
    // :266 `resume.index + (shard.one-1) * nic_count + nic_index`;
    // произведение — unsigned (32 бита), сумма с u64 — в u64.
    let start = resume_index
        .wrapping_add(u64::from(shard.one.wrapping_sub(1).wrapping_mul(nic_count)))
        .wrapping_add(u64::from(nic_index));
    let mut end = range; // :267
    if let Some(count) = resume_count.filter(|&c| c != 0) {
        let limit = start.wrapping_add(count);
        if end > limit {
            end = limit; // :269-270
        }
    }
    // :273 `end += retries * range` (в отличие от -sL, где max_rate)
    end = end.wrapping_add(u64::from(retries).wrapping_mul(range));
    TransmitIndices {
        i: start,
        end,
        range,
        rate: max_rate, // :208 `(uint64_t)max_rate`
        retries,
        r: retries.wrapping_add(1), // :209 `(unsigned)retries + 1`
        increment: u64::from(increment),
    }
}

/// `main_listscan` (main-listscan.c:8-67), IPv4. `massip` должен быть
/// оптимизирован. Для каждого индекса вызывает `emit(ip, port)`.
/// Форматирование строки: [`format_list_line`] (одиночный порт:
/// `massip.count_ports() == 1`).
#[allow(clippy::too_many_arguments)]
pub fn list_scan<F: FnMut(u32, u32)>(
    massip: &MassIp,
    seed: u64,
    rounds: u32,
    shard: Shard,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: u64,
    mut emit: F,
) -> Result<(), ScanError> {
    let range = massip.try_range()?; // main.c:1698-1704
    if range == 0 {
        return Err(ScanError::EmptyRange); // до BlackRock (crypto-blackrock.c:117)
    }
    if shard.of == 0 {
        return Err(ScanError::ZeroShard);
    }
    let blackrock = BlackRock::try_new(range, seed, rounds)?; // :24
    for i in list_scan_indices(range, shard, resume_index, resume_count, retries, max_rate) {
        let x = blackrock.shuffle(i); // :42
        let (ip, port) = massip.pick(x); // :44
        emit(ip, port);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::{add_target_string, parse_ports};

    const ONE: Shard = Shard { one: 1, of: 1 };

    #[test]
    fn transmit_stream_retries0_offsets_by_rate() {
        let got: Vec<u64> = transmit_index_stream(10, ONE, 1, 0, 0, None, 0, 3).collect();
        assert_eq!(got, vec![3, 4, 5, 6, 7, 8, 9, 0, 1, 2]);
    }

    #[test]
    fn transmit_stream_retries2_three_offsets_per_index() {
        let got: Vec<u64> = transmit_index_stream(10, ONE, 1, 0, 0, None, 2, 1).collect();
        assert_eq!(&got[0..3], &[3u64, 2, 1]);
        assert_eq!(&got[3..6], &[4u64, 3, 2]);
        assert_eq!(&got[87..90], &[2u64, 1, 0]);
        assert_eq!(got.len(), 90);
    }

    #[test]
    fn transmit_rate_above_range_uses_modulo() {
        // rate 25 > range 10: (i + 25) % 10
        let got: Vec<u64> = transmit_index_stream(10, ONE, 1, 0, 0, None, 0, 25).collect();
        assert_eq!(got, vec![5, 6, 7, 8, 9, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn transmit_start_with_nic_shard_and_resume() {
        // start = 5 + (2-1)*3 + 1 = 9; increment = 3*3 = 9; i = 9, 18 (< end 20)
        let mk = |count| {
            transmit_index_stream(20, Shard { one: 2, of: 3 }, 3, 1, 5, count, 0, 0)
                .collect::<Vec<u64>>()
        };
        assert_eq!(mk(Some(15)), vec![9, 18]); // 9+15 > 20: no clamp
        assert_eq!(mk(Some(4)), vec![9]); // end clamped to 9+4 = 13
        assert_eq!(mk(None), vec![9, 18]);
    }

    #[test]
    fn transmit_empty_range_yields_nothing() {
        assert_eq!(
            transmit_index_stream(0, ONE, 1, 0, 0, None, 3, 7).count(),
            0
        );
    }

    #[test]
    fn list_scan_indices_retries_use_max_rate_not_range() {
        let n = list_scan_indices(10, ONE, 0, None, 2, 5).count();
        assert_eq!(n, 10 + 2 * 5);
    }

    #[test]
    fn shard_2_of_3_steps_by_three() {
        let got: Vec<u64> =
            list_scan_indices(9, Shard { one: 2, of: 3 }, 0, None, 0, 100).collect();
        assert_eq!(got, vec![1, 4, 7]);
    }

    #[test]
    fn list_scan_resume_count_clamps_end() {
        let got: Vec<u64> = list_scan_indices(256, ONE, 100, Some(50), 0, 100).collect();
        assert_eq!(got, (100..150).collect::<Vec<_>>());
        // count 0 = без ограничения (main-listscan.c:31)
        assert_eq!(list_scan_indices(8, ONE, 2, Some(0), 0, 1).count(), 6);
    }

    #[test]
    fn format_line_single_vs_multi_port() {
        assert_eq!(format_list_line(0x0a000001, 80, true), "10.0.0.1");
        assert_eq!(format_list_line(0x0a000001, 80, false), "10.0.0.1:80");
    }

    fn massip(targets: &str, ports: &str) -> MassIp {
        let mut t = MassIp::new();
        add_target_string(t.ipv4_mut(), targets).unwrap();
        parse_ports(t.ports_mut(), ports).unwrap();
        t.optimize();
        t
    }

    #[test]
    fn list_scan_empty_range_is_error_before_blackrock() {
        let mut t = MassIp::new();
        t.optimize();
        let r = list_scan(&t, 1, 14, ONE, 0, None, 0, 100, |_, _| panic!("no emit"));
        assert_eq!(r, Err(ScanError::EmptyRange));
    }

    #[test]
    fn list_scan_rejects_zero_shard_and_bad_rounds() {
        let t = massip("10.0.0.0/30", "80");
        let z = Shard { one: 1, of: 0 };
        assert_eq!(
            list_scan(&t, 1, 14, z, 0, None, 0, 100, |_, _| ()),
            Err(ScanError::ZeroShard)
        );
        assert_eq!(
            list_scan(&t, 1, 64, ONE, 0, None, 0, 100, |_, _| ()),
            Err(ScanError::BlackRock(BlackRockError::TooManyRounds))
        );
    }

    #[test]
    fn list_scan_emits_every_target_once() {
        let t = massip("10.0.0.0/30", "80,443");
        let mut seen = Vec::new();
        list_scan(&t, 1, 14, ONE, 0, None, 0, 100, |ip, p| seen.push((ip, p))).unwrap();
        seen.sort();
        assert_eq!(seen.len(), 8);
        seen.dedup();
        assert_eq!(seen.len(), 8);
    }
}
