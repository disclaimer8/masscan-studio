//! Генератор порядка целей: индексы `-sL` и поток индексов transmit (AGPL-3.0).
//! Порт `src/main-listscan.c` и арифметики индексов `transmit_thread`
//! (`src/main.c:203-448`) из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Все `uint64_t`-операции C, где возможно переполнение, выражены через
//! `wrapping_*`; `unsigned` (32 бита) в C остаётся `u32`. `max_rate` в C —
//! `double` (masscan.h:178); приведения к `uint64_t` сделаны там же, где в C.
//! Rust `as` из `f64` в `u64` насыщается, где в C неопределённое поведение
//! (значения >= 2^64 или NaN); для реальных скоростей результаты совпадают.

use std::net::Ipv4Addr;
use std::ops::ControlFlow;

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

/// Ошибки `list_scan` и `transmit_scan`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// `range == 0`: в C бесконечный цикл в `blackrock_init` (crypto-blackrock.c:117-120, :151-152).
    #[error("nothing to scan: the target range is empty")]
    EmptyRange,
    /// Диапазон не помещается в 63 бита (main.c:1698-1704).
    #[error(transparent)]
    RangeOverflow(#[from] RangeOverflow),
    /// Нулевой шаг (`shard.of == 0`, либо `shard.of * nic_count == 0` в u32):
    /// в C бесконечный цикл (main-listscan.c:14,65; main.c:223,422).
    #[error("shard divisor must be non-zero")]
    ZeroShard,
    #[error(transparent)]
    BlackRock(#[from] BlackRockError),
    /// `-sL` с `retries > 0`: индекс `index >= range` не выходит из cycle-walk
    /// BlackRock (в C бесконечный цикл, crypto-blackrock.c:268-276).
    #[error(
        "-sL with retries would never terminate: index {index} does not shuffle into the \
         target range (use --retries 0, or a different --rate/--seed/--blackrock-rounds)"
    )]
    NonTerminating { index: u64 },
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

/// Пред-shuffle индексы `i` для `-sL` (main-listscan.c:31-35,42,65).
///
/// Паникует при `shard.of == 0` (в C бесконечный цикл); [`list_scan`]
/// проверяет это заранее и возвращает ошибку.
///
/// Осторожно: это сырой итератор. При `retries > 0` ручной `BlackRock::shuffle`
/// по его индексам может зациклиться, как и в C (main-listscan.c:35 ->
/// crypto-blackrock.c:268-276); [`list_scan`] этого не допускает
/// ([`ScanError::NonTerminating`]), [`BlackRock::shuffle_bounded`] даёт `None`.
/// Путь transmit безопасен: xXx сначала приводится по модулю range.
pub fn list_scan_indices(
    range: u64,
    shard: Shard,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: f64,
) -> impl Iterator<Item = u64> {
    let (i, end, increment) =
        list_bounds(range, shard, resume_index, resume_count, retries, max_rate);
    ListIndices { i, end, increment }
}

fn list_bounds(
    range: u64,
    shard: Shard,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: f64,
) -> (u64, u64, u64) {
    assert!(shard.of != 0, "shard.of must be non-zero");
    // :31 `resume.index + (shard.one-1)`: `shard.one-1` — unsigned (32 бита).
    let start = resume_index.wrapping_add(u64::from(shard.one.wrapping_sub(1)));
    let mut end = range; // :32
    // :33-34 `resume.count` равный 0 означает "без ограничения".
    if let Some(count) = resume_count.filter(|&c| c != 0) {
        let limit = start.wrapping_add(count);
        if end > limit {
            end = limit;
        }
    }
    // :35 `end += (uint64_t)(retries * max_rate)`: умножение в double
    // (unsigned * double), затем усечение; max_rate, не range.
    end = end.wrapping_add((f64::from(retries) * max_rate) as u64);
    (start, end, u64::from(shard.of)) // :14
}

/// Итератор transmit (main.c:280-333, :421-424).
struct TransmitIndices {
    i: u64,
    end: u64,
    range: u64,
    rate: u64,
    retries: u32,
    /// `unsigned r` (main.c:213).
    r: u32,
    increment: u64,
}

impl Iterator for TransmitIndices {
    type Item = (u64, u64);
    fn next(&mut self) -> Option<(u64, u64)> {
        if self.i >= self.end {
            return None; // main.c:280 `i < end`
        }
        let cur = self.i;
        // main.c:328 `xXx = (i + (r--) * rate)`: r — unsigned, повышается до u64.
        let mut x = self
            .i
            .wrapping_add(u64::from(self.r).wrapping_mul(self.rate));
        self.r = self.r.wrapping_sub(1);
        // main.c:329-333: ветка `%` и цикл вычитания дают одно и то же —
        // остаток от деления значения x (уже свёрнутого по 2^64) на range
        // (range > 0, иначе цикл не входит: end == 0). Поэтому один `%`.
        x %= self.range;
        // main.c:421-424
        if self.r == 0 {
            self.i = self.i.wrapping_add(self.increment);
            self.r = self.retries.wrapping_add(1);
        }
        Some((cur, x))
    }
}

/// Пред-shuffle поток transmit (main.c:203-448): пары `(i, xXx)`, где `i` —
/// текущий индекс цикла (нужен для SYN-cookie источника, main.c:379), а `xXx` —
/// `(i + r*rate) mod range` до `blackrock_shuffle`.
///
/// `nic_count`/`nic_index` — `unsigned` в C; произведения `shard.of * nic_count`
/// и `(shard.one-1) * nic_count` идут в 32 битах с переполнением (:223, :269).
/// Паникует, если шаг равен нулю: в C это бесконечный цикл.
#[allow(clippy::too_many_arguments)]
pub fn transmit_index_stream(
    range: u64,
    shard: Shard,
    nic_count: u32,
    nic_index: u32,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: f64,
) -> impl Iterator<Item = (u64, u64)> {
    // :223 `unsigned increment = shard.of * nic_count`
    let increment = shard.of.wrapping_mul(nic_count);
    assert!(increment != 0, "shard.of * nic_count must be non-zero");
    // :269 `resume.index + (shard.one-1) * nic_count + nic_index`;
    // произведение — unsigned (32 бита), сумма с u64 — в u64.
    let start = resume_index
        .wrapping_add(u64::from(shard.one.wrapping_sub(1).wrapping_mul(nic_count)))
        .wrapping_add(u64::from(nic_index));
    let mut end = range; // :270
    if let Some(count) = resume_count.filter(|&c| c != 0) {
        let limit = start.wrapping_add(count);
        if end > limit {
            end = limit; // :271-272
        }
    }
    // :273 `end += retries * range` (в отличие от -sL, где max_rate)
    end = end.wrapping_add(u64::from(retries).wrapping_mul(range));
    TransmitIndices {
        i: start,
        end,
        range,
        rate: max_rate as u64, // :212 `(uint64_t)masscan->max_rate`
        retries,
        r: retries.wrapping_add(1), // :213 `(unsigned)retries + 1`
        increment: u64::from(increment),
    }
}

/// `main_listscan` (main-listscan.c:6-72), IPv4. `massip` должен быть
/// оптимизирован. Для каждого индекса вызывает `emit(ip, port)`.
/// Форматирование строки: [`format_list_line`] (одиночный порт:
/// `massip.count_ports() == 1`).
///
/// При `retries > 0` в C `-sL` может зациклиться в cycle-walk BlackRock
/// (main-listscan.c:35 -> crypto-blackrock.c:268-276). Здесь это проверяется до
/// первого вывода: функция возвращает [`ScanError::NonTerminating`]. Путь
/// transmit безопасен: xXx сначала приводится по модулю range.
#[allow(clippy::too_many_arguments)]
pub fn list_scan<F: FnMut(u32, u32)>(
    massip: &MassIp,
    seed: u64,
    rounds: u32,
    shard: Shard,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: f64,
    mut emit: F,
) -> Result<(), ScanError> {
    let range = massip.try_range()?; // main.c:1698-1704
    if range == 0 {
        return Err(ScanError::EmptyRange); // до BlackRock (crypto-blackrock.c:117)
    }
    if shard.of == 0 {
        return Err(ScanError::ZeroShard);
    }
    let blackrock = BlackRock::try_new(range, seed, rounds)?; // :29
    // Индексы `>= range` бывают только из-за `retries * max_rate` (:35). Их
    // cycle-walk может не завершиться; проверяем ДО первого вывода.
    let (start, end, inc) =
        list_bounds(range, shard, resume_index, resume_count, retries, max_rate);
    if end > range {
        let mut i = start;
        if i < range {
            // первый индекс шага не меньше `range`
            i = i.saturating_add((range - i).div_ceil(inc).saturating_mul(inc));
        }
        while i < end {
            if blackrock.shuffle_bounded(i).is_none() {
                return Err(ScanError::NonTerminating { index: i });
            }
            i = i.wrapping_add(inc);
            if i < inc {
                break;
            }
        }
    }
    for i in list_scan_indices(range, shard, resume_index, resume_count, retries, max_rate) {
        let x = blackrock.shuffle(i); // :42
        let (ip, port) = massip.pick(x); // :44
        emit(ip, port);
    }
    Ok(())
}

/// Индексная часть `transmit_thread` (main.c:203-448), IPv4, без отправки.
/// `emit(i, repeats, xXx, ip, port)` вызывается на каждую отправку:
/// - `i` — индекс цикла, `repeats` — счётчик `--infinite` (всегда 0: `--infinite`
///   вне области v1); вместе они дают `(unsigned)(i+repeats)` для источника
///   SYN-cookie (main.c:379-384);
/// - `xXx` — результат `blackrock_shuffle` (main.c:334; `range_ipv6 == 0`, поэтому
///   вычитание на :369 тождественно), нужен для `(unsigned)xXx` в :381;
/// - `(ip, port)` — `massip.pick(xXx)` (:371-372).
#[allow(clippy::too_many_arguments)]
pub fn transmit_scan<F: FnMut(u64, u64, u64, u32, u32)>(
    massip: &MassIp,
    seed: u64,
    rounds: u32,
    shard: Shard,
    nic_count: u32,
    nic_index: u32,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: f64,
    mut emit: F,
) -> Result<(), ScanError> {
    transmit_scan_flow(
        massip,
        seed,
        rounds,
        shard,
        nic_count,
        nic_index,
        resume_index,
        resume_count,
        retries,
        max_rate,
        |i, repeats, xxx, ip, port| {
            emit(i, repeats, xxx, ip, port);
            ControlFlow::<()>::Continue(())
        },
    )
    .map(|_| ())
}

/// [`transmit_scan`] с досрочной остановкой: как только `emit` вернул
/// `ControlFlow::Break(b)`, обход прекращается немедленно (без прохода до
/// конца диапазона) и возвращается `Ok(Break(b))`. Порядок и значения те же.
#[allow(clippy::too_many_arguments)]
pub fn transmit_scan_flow<B, F: FnMut(u64, u64, u64, u32, u32) -> ControlFlow<B>>(
    massip: &MassIp,
    seed: u64,
    rounds: u32,
    shard: Shard,
    nic_count: u32,
    nic_index: u32,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
    max_rate: f64,
    mut emit: F,
) -> Result<ControlFlow<B>, ScanError> {
    let range = massip.try_range()?;
    if range == 0 {
        return Err(ScanError::EmptyRange);
    }
    if shard.of.wrapping_mul(nic_count) == 0 {
        return Err(ScanError::ZeroShard);
    }
    let blackrock = BlackRock::try_new(range, seed, rounds)?; // main.c:261
    let repeats = 0u64; // main.c:226
    for (i, x) in transmit_index_stream(
        range,
        shard,
        nic_count,
        nic_index,
        resume_index,
        resume_count,
        retries,
        max_rate,
    ) {
        let xxx = blackrock.shuffle(x); // main.c:334
        let (ip, port) = massip.pick(xxx);
        if let ControlFlow::Break(b) = emit(i, repeats, xxx, ip, port) {
            return Ok(ControlFlow::Break(b));
        }
    }
    Ok(ControlFlow::Continue(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::{add_target_string, parse_ports};

    const ONE: Shard = Shard { one: 1, of: 1 };

    fn xs(it: impl Iterator<Item = (u64, u64)>) -> Vec<u64> {
        it.map(|(_, x)| x).collect()
    }

    #[test]
    fn transmit_stream_retries0_offsets_by_rate() {
        let got = xs(transmit_index_stream(10, ONE, 1, 0, 0, None, 0, 3.0));
        assert_eq!(got, vec![3, 4, 5, 6, 7, 8, 9, 0, 1, 2]);
    }

    #[test]
    fn transmit_stream_retries2_three_offsets_per_index() {
        let all: Vec<(u64, u64)> = transmit_index_stream(10, ONE, 1, 0, 0, None, 2, 1.0).collect();
        let got: Vec<u64> = all.iter().map(|p| p.1).collect();
        assert_eq!(&got[0..3], &[3u64, 2, 1]);
        assert_eq!(&got[3..6], &[4u64, 3, 2]);
        assert_eq!(&got[87..90], &[2u64, 1, 0]);
        assert_eq!(got.len(), 90);
        // i is the loop index: constant across the r group, then advances.
        assert_eq!(
            all.iter().map(|p| p.0).take(7).collect::<Vec<_>>(),
            vec![0, 0, 0, 1, 1, 1, 2]
        );
        assert_eq!(all[89].0, 29);
    }

    #[test]
    fn transmit_rate_above_range_uses_modulo() {
        let got = xs(transmit_index_stream(10, ONE, 1, 0, 0, None, 0, 25.0));
        assert_eq!(got, vec![5, 6, 7, 8, 9, 0, 1, 2, 3, 4]);
    }

    #[test]
    fn transmit_fractional_rate_truncates() {
        // main.c:212 `(uint64_t)max_rate`: 3.9 -> 3
        let got = xs(transmit_index_stream(10, ONE, 1, 0, 0, None, 0, 3.9));
        assert_eq!(got[0], 3);
    }

    #[test]
    fn transmit_start_with_nic_shard_and_resume() {
        // start = 5 + (2-1)*3 + 1 = 9; increment = 3*3 = 9; i = 9, 18 (< end 20)
        let mk = |count| {
            xs(transmit_index_stream(
                20,
                Shard { one: 2, of: 3 },
                3,
                1,
                5,
                count,
                0,
                0.0,
            ))
        };
        assert_eq!(mk(Some(15)), vec![9, 18]); // 9+15 > 20: no clamp
        assert_eq!(mk(Some(4)), vec![9]); // end clamped to 9+4 = 13
        assert_eq!(mk(None), vec![9, 18]);
    }

    #[test]
    fn transmit_end_wraps_when_retries_times_range_overflows() {
        // range = 2^62, retries 4: retries*range = 2^64 wraps to 0 (main.c:273),
        // so end = start+3 = 3 stays; 3 positions x 5 sends.
        let range = 1u64 << 62;
        let all: Vec<(u64, u64)> =
            transmit_index_stream(range, ONE, 1, 0, 0, Some(3), 4, 1.0).collect();
        assert_eq!(all.len(), 15);
        assert_eq!(
            all.iter().take(6).map(|p| p.1).collect::<Vec<_>>(),
            vec![5, 4, 3, 2, 1, 6]
        );
        assert_eq!(all[14], (2, 3));
    }

    #[test]
    fn transmit_empty_range_yields_nothing() {
        assert_eq!(
            transmit_index_stream(0, ONE, 1, 0, 0, None, 3, 7.0).count(),
            0
        );
    }

    #[test]
    fn list_scan_indices_retries_use_max_rate_not_range() {
        let n = list_scan_indices(10, ONE, 0, None, 2, 5.0).count();
        assert_eq!(n, 10 + 2 * 5);
    }

    #[test]
    fn list_scan_fractional_rate_matches_c_double_cast() {
        // Counts measured with the real C binary (-sL 10.0.0.0/24 -p80 --seed 1).
        let n = |retries, rate| list_scan_indices(256, ONE, 0, None, retries, rate).count();
        assert_eq!(n(2, 100.5), 457);
        assert_eq!(n(3, 0.5), 257);
        assert_eq!(n(2, 1000.999), 2257);
    }

    #[test]
    fn list_scan_resume_index_past_range_with_retries() {
        // C-verified: start 256 >= range, end = 256 + 1*10 -> 10 indices.
        assert_eq!(list_scan_indices(256, ONE, 256, None, 1, 10.0).count(), 10);
    }

    #[test]
    fn shard_2_of_3_steps_by_three() {
        let got: Vec<u64> =
            list_scan_indices(9, Shard { one: 2, of: 3 }, 0, None, 0, 100.0).collect();
        assert_eq!(got, vec![1, 4, 7]);
    }

    #[test]
    fn list_scan_resume_count_clamps_end() {
        let got: Vec<u64> = list_scan_indices(256, ONE, 100, Some(50), 0, 100.0).collect();
        assert_eq!(got, (100..150).collect::<Vec<_>>());
        // count 0 = без ограничения (main-listscan.c:33)
        assert_eq!(list_scan_indices(8, ONE, 2, Some(0), 0, 1.0).count(), 6);
    }

    #[test]
    fn format_line_single_vs_multi_port() {
        assert_eq!(format_list_line(0x0a000001, 80, true), "10.0.0.1");
        assert_eq!(format_list_line(0x0a000001, 80, false), "10.0.0.1:80");
        // ipv4address_selftest vector, massip-addr.c:313-317.
        assert_eq!(format_list_line(0x01FF00A3, 80, true), "1.255.0.163");
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
        let r = list_scan(&t, 1, 14, ONE, 0, None, 0, 100.0, |_, _| panic!("no emit"));
        assert_eq!(r, Err(ScanError::EmptyRange));
    }

    #[test]
    fn list_scan_rejects_zero_shard_and_bad_rounds() {
        let t = massip("10.0.0.0/30", "80");
        let z = Shard { one: 1, of: 0 };
        assert_eq!(
            list_scan(&t, 1, 14, z, 0, None, 0, 100.0, |_, _| ()),
            Err(ScanError::ZeroShard)
        );
        assert_eq!(
            list_scan(&t, 1, 64, ONE, 0, None, 0, 100.0, |_, _| ()),
            Err(ScanError::BlackRock(BlackRockError::TooManyRounds))
        );
    }

    #[test]
    fn list_scan_with_retries_that_cannot_terminate_errors_before_any_emit() {
        // Range 4, retries 1, rate 100: extra indices 4..104 contain one whose
        // cycle-walk never returns below range (C hangs; the CLI used to hang).
        let t = massip("10.0.0.0/30", "80");
        let r = list_scan(&t, 1, 14, ONE, 0, None, 1, 100.0, |_, _| panic!("no emit"));
        assert!(
            matches!(r, Err(ScanError::NonTerminating { index }) if index >= 4),
            "{r:?}"
        );
        // rounds 0 is the identity: any index >= range is stuck.
        let r = list_scan(&t, 1, 0, ONE, 0, None, 1, 100.0, |_, _| panic!("no emit"));
        assert!(matches!(r, Err(ScanError::NonTerminating { .. })), "{r:?}");
    }

    #[test]
    fn list_scan_retries_golden_cases_still_terminate() {
        // listscan/slash24_p80_seed1_retries2*.txt: 456 and 2256 lines.
        let t = massip("10.0.0.0/24", "80");
        for (rate, lines) in [(100.0, 456usize), (1000.0, 2256)] {
            let mut n = 0;
            list_scan(&t, 1, 14, ONE, 0, None, 2, rate, |_, _| n += 1).unwrap();
            assert_eq!(n, lines);
        }
    }

    #[test]
    fn list_scan_emits_every_target_once() {
        let t = massip("10.0.0.0/30", "80,443");
        let mut seen = Vec::new();
        list_scan(&t, 1, 14, ONE, 0, None, 0, 100.0, |ip, p| {
            seen.push((ip, p))
        })
        .unwrap();
        seen.sort();
        assert_eq!(seen.len(), 8);
        seen.dedup();
        assert_eq!(seen.len(), 8);
    }

    #[test]
    fn transmit_scan_validates_and_matches_list_scan_order() {
        let t = massip("10.0.0.0/30", "80,443");
        let mut e = MassIp::new();
        e.optimize();
        assert_eq!(
            transmit_scan(&e, 1, 14, ONE, 1, 0, 0, None, 0, 100.0, |_, _, _, _, _| ()),
            Err(ScanError::EmptyRange)
        );
        let z = Shard { one: 1, of: 0 };
        assert_eq!(
            transmit_scan(&t, 1, 14, z, 1, 0, 0, None, 0, 100.0, |_, _, _, _, _| ()),
            Err(ScanError::ZeroShard)
        );
        assert_eq!(
            transmit_scan(&t, 1, 14, ONE, 0, 0, 0, None, 0, 100.0, |_, _, _, _, _| ()),
            Err(ScanError::ZeroShard)
        );
        // retries 0, rate 0: xXx == i, so the order equals -sL.
        let (mut a, mut b) = (Vec::new(), Vec::new());
        list_scan(&t, 1, 14, ONE, 0, None, 0, 0.0, |ip, p| a.push((ip, p))).unwrap();
        transmit_scan(&t, 1, 14, ONE, 1, 0, 0, None, 0, 0.0, |i, rep, _, ip, p| {
            assert_eq!((rep, i), (0, b.len() as u64));
            b.push((ip, p));
        })
        .unwrap();
        assert_eq!(a, b);
    }
}
