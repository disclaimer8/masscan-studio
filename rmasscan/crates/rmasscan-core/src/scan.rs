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
use crate::massip::{MassIp, RangeOverflow, TargetIp};
use crate::ranges6::format_ipv6_c;

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
    /// IPv4-вариант API (`list_scan`, `transmit_scan`, `transmit_scan_flow`) вызван
    /// с IPv6-целями: молча пропустить их нельзя (`list_scan_v46`,
    /// `transmit_scan_flow_v46`).
    #[error("the targets include IPv6 addresses; this IPv4-only entry point cannot scan them")]
    Ipv6Targets,
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

/// Строка `-sL` (main-listscan.c:53-62) для IPv4 и IPv6: один порт даёт только
/// адрес (:54-56), иначе `ip:port` для IPv4 и `[ip]:port` для IPv6 (:58-60).
/// Адрес IPv6 печатает `ipv6address_fmt` ([`format_ipv6_c`]).
pub fn format_list_line_v46(target: TargetIp, port: u32, single_port: bool) -> String {
    match target {
        TargetIp::V4(ip) => format_list_line(ip, port, single_port),
        TargetIp::V6(ip) if single_port => format_ipv6_c(ip),
        TargetIp::V6(ip) => format!("[{}]:{port}", format_ipv6_c(ip)),
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

/// Границы цикла transmit для одного потока: `(start, end, increment)`
/// (main.c:223, :269-273). `increment == 0` означает `shard.of * nic_count == 0`
/// (в C бесконечный цикл).
pub fn transmit_bounds(
    range: u64,
    shard: Shard,
    nic_count: u32,
    nic_index: u32,
    resume_index: u64,
    resume_count: Option<u64>,
    retries: u32,
) -> (u64, u64, u64) {
    // :223 `unsigned increment = shard.of * nic_count`
    let increment = shard.of.wrapping_mul(nic_count);
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
    (start, end, u64::from(increment))
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
    let (start, end, increment) = transmit_bounds(
        range,
        shard,
        nic_count,
        nic_index,
        resume_index,
        resume_count,
        retries,
    );
    assert!(increment != 0, "shard.of * nic_count must be non-zero");
    TransmitIndices {
        i: start,
        end,
        range,
        rate: max_rate as u64, // :212 `(uint64_t)masscan->max_rate`
        retries,
        r: retries.wrapping_add(1), // :213 `(unsigned)retries + 1`
        increment,
    }
}

/// `main_listscan` (main-listscan.c:6-72), только IPv4. `massip` должен быть
/// оптимизирован. Для каждого индекса вызывает `emit(ip, port)`.
/// Форматирование строки: [`format_list_line`] (одиночный порт:
/// `massip.count_ports() == 1`). С IPv6-целями отказывает
/// [`ScanError::Ipv6Targets`] до первого вывода: смесь печатает
/// [`list_scan_v46`].
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
    if massip.has_ipv6_targets() {
        return Err(ScanError::Ipv6Targets);
    }
    list_scan_v46(
        massip,
        seed,
        rounds,
        shard,
        resume_index,
        resume_count,
        retries,
        max_rate,
        |target, port| match target {
            TargetIp::V4(ip) => emit(ip, port),
            // IPv6-цели отклонены выше (`Ipv6Targets`); молчаливый пропуск потерял бы половину листинга.
            TargetIp::V6(_) => unreachable!("IPv6 targets are refused before the listing starts"),
        },
    )
}

/// [`list_scan`] для IPv4 и IPv6. Порядок индексов `massip_pick` (massip.c:27-43,
/// main-listscan.c:44): IPv4 на `0..count_ipv4 * ports`, IPv6 выше; без
/// IPv6-целей результат побайтно совпадает с [`list_scan`]. Строка:
/// [`format_list_line_v46`].
#[allow(clippy::too_many_arguments)]
pub fn list_scan_v46<F: FnMut(TargetIp, u32)>(
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
        let (target, port) = massip.pick_list(x); // :44
        emit(target, port);
    }
    Ok(())
}

/// Индексная часть `transmit_thread` (main.c:203-448), только IPv4, без отправки.
/// С IPv6-целями отказывает [`ScanError::Ipv6Targets`]: см. [`transmit_scan_flow_v46`].
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
/// С IPv6-целями отказывает [`ScanError::Ipv6Targets`] до первой отправки.
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
    if massip.has_ipv6_targets() {
        return Err(ScanError::Ipv6Targets);
    }
    transmit_scan_flow_v46(
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
        |i, repeats, xxx, target, port| match target {
            TargetIp::V4(ip) => emit(i, repeats, xxx, ip, port),
            // IPv6-цели отклонены выше (`Ipv6Targets`); молчаливый пропуск потерял бы половину скана.
            TargetIp::V6(_) => unreachable!("IPv6 targets are refused before the flow starts"),
        },
    )
}

/// [`transmit_scan_flow`] для IPv4 и IPv6 (main.c:251-373). Индексы
/// `xxx < range_ipv6 = count_ipv6 * ports` дают IPv6 (`range6list_pick(xxx %
/// count_ipv6)`, порт `xxx / count_ipv6`), остальные IPv4 с вычетом
/// `range_ipv6` (:342-343, :369-372; [`MassIp::pick_transmit`]). Это обратный
/// порядок `-sL` ([`list_scan_v46`]): у C `massip_pick` и `transmit_thread`
/// нумеруют по-разному.
///
/// `emit(i, repeats, xXx, target, port)`: `xXx` как в C на момент SYN-cookie, то
/// есть у IPv4 после вычитания `range_ipv6` (:369, до :381), у IPv6 как после
/// shuffle. Без IPv6-целей `range_ipv6 == 0` и всё побайтно как раньше.
#[allow(clippy::too_many_arguments)]
pub fn transmit_scan_flow_v46<B, F: FnMut(u64, u64, u64, TargetIp, u32) -> ControlFlow<B>>(
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
        let (target, port, xxx) = massip.pick_transmit(xxx);
        if let ControlFlow::Break(b) = emit(i, repeats, xxx, target, port) {
            return Ok(ControlFlow::Break(b));
        }
    }
    Ok(ControlFlow::Continue(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::{add_target_string, parse_ports};

    /// main.c:269-273: `start`, `end`, шаг на пару (shard 2/3, 2 NIC).
    #[test]
    fn transmit_bounds_follow_c_start_end_increment() {
        let shard = Shard { one: 2, of: 3 };
        assert_eq!(transmit_bounds(10, shard, 2, 0, 0, None, 0), (2, 10, 6));
        assert_eq!(transmit_bounds(10, shard, 2, 1, 0, None, 0), (3, 10, 6));
        // resume.count усекает end, затем + retries * range.
        assert_eq!(transmit_bounds(10, shard, 2, 1, 4, Some(3), 2), (7, 30, 6));
        assert_eq!(transmit_bounds(10, shard, 2, 1, 4, Some(0), 2), (7, 30, 6));
    }

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

    fn mixed(targets: &str, ports: &str) -> MassIp {
        let mut t = MassIp::new();
        t.add_target_string(targets).unwrap();
        parse_ports(t.ports_mut(), ports).unwrap();
        t.optimize();
        t
    }

    fn v6(low: u128) -> TargetIp {
        TargetIp::V6((0x2001_0db8u128 << 96) | low)
    }

    /// main.c:251-260, :336-373: `count_ipv6 = 2, count_ipv4 = 3, ports = 2`.
    /// `range_ipv6 = 4`: shuffled indices `0..4` are IPv6, `4..10` IPv4 with 4
    /// subtracted. Expected values are recomputed here from the raw lists and the
    /// formulas of main.c:342-343 and :371-372, not through `MassIp::pick_transmit`.
    #[test]
    fn mixed_v4_v6_transmit_puts_v6_in_low_indices_and_v4_after() {
        let t = mixed("2001:db8::10-2001:db8::11,192.0.2.1-192.0.2.3", "80,443");
        assert_eq!(
            (t.count_ipv6s(), t.count_ipv4s(), t.count_ports()),
            (2, 3, 2)
        );
        assert_eq!((t.range(), t.range_ipv6()), (10, 4));
        let br = BlackRock::try_new(10, 7, 14).unwrap();
        let (mut raw, mut got) = (Vec::new(), Vec::new());
        // rate 0: xXx == i
        let _ = transmit_scan_flow_v46(
            &t,
            7,
            14,
            ONE,
            1,
            0,
            0,
            None,
            0,
            0.0,
            |i, rep, xxx, tg, port| {
                assert_eq!((i, rep), (got.len() as u64, 0));
                raw.push(br.shuffle(i));
                got.push((xxx, tg, port));
                ControlFlow::<()>::Continue(())
            },
        )
        .unwrap();
        let ports = [80u32, 443];
        let v6s = [0x10u128, 0x11];
        let v4s = [0xc000_0201u32, 0xc000_0202, 0xc000_0203];
        for (r, (xxx, tg, port)) in raw.iter().zip(&got) {
            if *r < 4 {
                // main.c:342-343, :357 (cookie xXx unchanged for IPv6)
                assert_eq!(*xxx, *r);
                assert_eq!(*tg, v6(v6s[(*r % 2) as usize]), "raw {r}");
                assert_eq!(*port, ports[(*r / 2) as usize]);
            } else {
                // main.c:369-372: xXx -= range_ipv6 before the pick and the cookie
                let x = *r - 4;
                assert_eq!(*xxx, x);
                assert_eq!(*tg, TargetIp::V4(v4s[(x % 3) as usize]), "raw {r}");
                assert_eq!(*port, ports[(x / 3) as usize]);
            }
        }
        // the shuffle is a permutation, so exactly 4 IPv6 and 6 IPv4 targets appear,
        // each (target, port) pair once
        let mut raw_sorted = raw.clone();
        raw_sorted.sort_unstable();
        assert_eq!(raw_sorted, (0..10).collect::<Vec<u64>>());
        assert_eq!(
            got.iter()
                .filter(|g| matches!(g.1, TargetIp::V6(_)))
                .count(),
            4
        );
        let mut pairs: Vec<_> = got.iter().map(|g| format!("{:?}{}", g.1, g.2)).collect();
        pairs.sort();
        pairs.dedup();
        assert_eq!(pairs.len(), 10);
    }

    /// The IPv4-only entry points never skip IPv6 targets silently.
    #[test]
    fn ipv4_only_entry_points_refuse_ipv6_targets() {
        let t = mixed("2001:db8::10,192.0.2.1", "80");
        assert_eq!(
            list_scan(&t, 1, 14, ONE, 0, None, 0, 0.0, |_, _| panic!("emitted")),
            Err(ScanError::Ipv6Targets)
        );
        assert_eq!(
            transmit_scan(&t, 1, 14, ONE, 1, 0, 0, None, 0, 0.0, |_, _, _, _, _| {
                panic!("emitted")
            }),
            Err(ScanError::Ipv6Targets)
        );
    }

    fn list_lines(t: &MassIp, seed: u64) -> Vec<String> {
        let single = t.count_ports() == 1;
        let mut out = Vec::new();
        list_scan_v46(t, seed, 14, ONE, 0, None, 0, 0.0, |tg, p| {
            out.push(format_list_line_v46(tg, p, single));
        })
        .unwrap();
        out
    }

    /// Output of the C binary 8e6b3b0 (`~/masscan/bin/masscan -sL --seed 42
    /// 2001:db8::/126 192.0.2.0/30 -p80,443`), main-listscan.c:53-62: IPv4 as
    /// `ip:port`, IPv6 as `[ip]:port`, in the `massip_pick` order (massip.c:30-41).
    #[test]
    fn list_scan_mixed_two_ports_matches_c_binary() {
        let t = mixed("2001:db8::/126,192.0.2.0/30", "80,443");
        let want = [
            "[2001:db8::1]:443",
            "[2001:db8::2]:80",
            "192.0.2.2:80",
            "[2001:db8::3]:80",
            "192.0.2.1:80",
            "[2001:db8::1]:80",
            "[2001:db8::]:443",
            "192.0.2.3:443",
            "192.0.2.0:443",
            "[2001:db8::2]:443",
            "192.0.2.2:443",
            "[2001:db8::3]:443",
            "192.0.2.3:80",
            "192.0.2.1:443",
            "[2001:db8::]:80",
            "192.0.2.0:80",
        ];
        assert_eq!(list_lines(&t, 42), want);
    }

    /// C binary, same targets with `-p80` (one port: address only, :54-56).
    #[test]
    fn list_scan_mixed_single_port_matches_c_binary() {
        let t = mixed("2001:db8::/126,192.0.2.0/30", "80");
        let want = [
            "192.0.2.0",
            "192.0.2.3",
            "192.0.2.2",
            "2001:db8::",
            "2001:db8::3",
            "192.0.2.1",
            "2001:db8::1",
            "2001:db8::2",
        ];
        assert_eq!(list_lines(&t, 42), want);
    }

    /// C binary: `-sL --seed 42 --range 2001:db8::/66 -p80 | head -4` (a 2^62 range:
    /// the first lines are pulled through the index iterator, not a full scan).
    #[test]
    fn list_scan_ipv6_slash_66_first_lines_match_c_binary() {
        let t = mixed("2001:db8::/66", "80");
        let range = t.try_range().unwrap();
        assert_eq!(range, 1 << 62);
        let br = BlackRock::try_new(range, 42, 14).unwrap();
        let got: Vec<String> = list_scan_indices(range, ONE, 0, None, 0, 0.0)
            .take(4)
            .map(|i| {
                let (tg, p) = t.pick_list(br.shuffle(i));
                format_list_line_v46(tg, p, true)
            })
            .collect();
        assert_eq!(
            got,
            [
                "2001:db8::2820:3055:ec41:2e9f",
                "2001:db8::83c:59d4:24fe:3acf",
                "2001:db8::f80:7f3a:4bfd:1dfd",
                "2001:db8::34f:31cd:7127:1efe",
            ]
        );
    }

    /// Without IPv6 targets the v46 entry points emit exactly what the IPv4 ones do.
    #[test]
    fn v46_entry_points_equal_ipv4_ones_on_pure_ipv4() {
        let t = mixed("198.18.0.0/28", "80,443");
        let (mut a, mut b) = (Vec::new(), Vec::new());
        list_scan(&t, 42, 14, ONE, 0, None, 0, 100.0, |ip, p| a.push((ip, p))).unwrap();
        list_scan_v46(&t, 42, 14, ONE, 0, None, 0, 100.0, |tg, p| b.push((tg, p))).unwrap();
        assert_eq!(
            a.iter()
                .map(|&(ip, p)| (TargetIp::V4(ip), p))
                .collect::<Vec<_>>(),
            b
        );
        let (mut c, mut d) = (Vec::new(), Vec::new());
        transmit_scan(
            &t,
            42,
            14,
            ONE,
            1,
            0,
            0,
            None,
            0,
            100.0,
            |i, r, x, ip, p| {
                c.push((i, r, x, TargetIp::V4(ip), p));
            },
        )
        .unwrap();
        let _ = transmit_scan_flow_v46(
            &t,
            42,
            14,
            ONE,
            1,
            0,
            0,
            None,
            0,
            100.0,
            |i, r, x, tg, p| {
                d.push((i, r, x, tg, p));
                ControlFlow::<()>::Continue(())
            },
        )
        .unwrap();
        assert_eq!(c, d);
    }

    /// An IPv6-only plan: `range_ipv6 == range`, no IPv4 pick is reached.
    #[test]
    fn ipv6_only_transmit_uses_the_whole_range_for_ipv6() {
        let t = mixed("2001:db8::10-2001:db8::13", "80,443");
        let mut n = 0;
        let _ =
            transmit_scan_flow_v46(&t, 3, 14, ONE, 1, 0, 0, None, 0, 0.0, |_, _, xxx, tg, _| {
                assert!(xxx < 8 && matches!(tg, TargetIp::V6(_)));
                n += 1;
                ControlFlow::<()>::Continue(())
            })
            .unwrap();
        assert_eq!(n, 8);
    }
}
