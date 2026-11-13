//! Списки диапазонов IPv6-адресов, разбор целей и форматирование (AGPL-3.0).
//! Порт `src/massip-rangesv6.c`, IPv6-ветвей `src/massip-parse.c` и
//! `ipv6address_fmt` из `src/massip-addr.c` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Адрес хранится как `u128` (в C это пара `hi`/`lo` по 64 бита; арифметика
//! `PLUS_ONE`/`MINUS_ONE`/`_int128_*` совпадает с `wrapping_*` над `u128`).
//! Модуль ничего не передаёт в сеть.

use crate::targets::{ParseError, is_c_space};

/// Адрес IPv6 в сетевом порядке байт (массив `tmp[16]` из `ipv6address_fmt`,
/// massip-addr.c:84-92).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6AddrBytes(pub [u8; 16]);

impl Ipv6AddrBytes {
    pub fn from_u128(a: u128) -> Self {
        Self(a.to_be_bytes())
    }

    pub fn to_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }
}

impl From<u128> for Ipv6AddrBytes {
    fn from(a: u128) -> Self {
        Self::from_u128(a)
    }
}

/// Инклюзивный диапазон `[begin, end]` (massip-rangesv6.h `struct Range6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Range {
    pub begin: u128,
    pub end: u128,
}

/// massip-rangesv6.c:219-242 `range6_is_overlap` (смежные диапазоны
/// считаются пересекающимися). `PLUS_ONE(end)` защищён проверкой `== FFFF`.
fn is_overlap(lhs: Ipv6Range, rhs: Ipv6Range) -> bool {
    if lhs.begin < rhs.begin && (lhs.end == u128::MAX || lhs.end.wrapping_add(1) >= rhs.begin) {
        return true;
    }
    if lhs.begin >= rhs.begin && lhs.end <= rhs.end {
        return true;
    }
    if rhs.begin < lhs.begin && (rhs.end == u128::MAX || rhs.end.wrapping_add(1) >= lhs.begin) {
        return true;
    }
    if rhs.begin >= lhs.begin && rhs.end <= lhs.end {
        return true;
    }
    false
}

/// Список диапазонов IPv6 (massip-rangesv6.h `struct Range6List`).
#[derive(Debug, Clone)]
pub struct Range6List {
    list: Vec<Ipv6Range>,
    /// Префиксные суммы размеров (`size_t picker[]`, нижние 64 бита суммы,
    /// :554-582 `picker[i] = (size_t)total.lo`); строится `optimize`.
    picker: Option<Vec<u64>>,
    is_sorted: bool,
}

impl Default for Range6List {
    fn default() -> Self {
        Self::new()
    }
}

impl Range6List {
    pub fn new() -> Self {
        // Пустой список отсортирован (massip-rangesv6.c:327-329).
        Self {
            list: Vec::new(),
            picker: None,
            is_sorted: true,
        }
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn get(&self, index: usize) -> Ipv6Range {
        self.list[index]
    }

    pub fn as_slice(&self) -> &[Ipv6Range] {
        &self.list
    }

    /// massip-rangesv6.c:309-346 `range6list_add_range`: если диапазон
    /// пересекает последний в списке, он сливается с ним, иначе
    /// добавляется в конец; список после этого считается неотсортированным
    /// (кроме первого элемента). Отличие от C: устаревший `picker` сбрасывается.
    pub fn add(&mut self, begin: u128, end: u128) {
        let range = Ipv6Range { begin, end };
        self.picker = None;
        let Some(last) = self.list.last_mut() else {
            self.list.push(range);
            self.is_sorted = true;
            return;
        };
        if is_overlap(*last, range) {
            // :250-257 `range6_combine`
            if range.begin <= last.begin {
                last.begin = range.begin;
            }
            if last.end <= range.end {
                last.end = range.end;
            }
        } else {
            self.list.push(range);
        }
        self.is_sorted = false;
    }

    /// massip-rangesv6.c:274-324 `range6list_sort`: сортировка по `begin` и
    /// слияние перекрытий повторным `add`.
    pub fn sort_and_merge(&mut self) {
        if self.list.is_empty() {
            self.is_sorted = true;
            return;
        }
        if self.is_sorted {
            return;
        }
        self.list.sort_by_key(|r| r.begin);
        let old = std::mem::take(&mut self.list);
        for r in old {
            self.add(r.begin, r.end);
        }
        self.picker = None;
        self.is_sorted = true;
    }

    /// massip-rangesv6.c:197-207 `range6list_is_contains` (линейный поиск).
    pub fn is_contains(&self, ip: u128) -> bool {
        self.list.iter().any(|r| r.begin <= ip && ip <= r.end)
    }

    /// massip-rangesv6.c:490-507 `range6list_count`. Полное пространство
    /// (`::/0`) даёт `u128::MAX`, а не 2^128: C возвращает значение
    /// «переполнения» (`end - begin == ~0`, :499-500) без прибавления
    /// единицы. Сумма оборачивается, как в C.
    pub fn count_u128(&self) -> u128 {
        let mut result: u128 = 0;
        for r in &self.list {
            let x = r.end.wrapping_sub(r.begin);
            if x == u128::MAX {
                return x;
            }
            result = result.wrapping_add(x.wrapping_add(1));
        }
        result
    }

    /// massip-rangesv6.c:554-582 `range6list_optimize`: сортировка и
    /// префиксные суммы для `pick`. Пустой список не трогается.
    pub fn optimize(&mut self) {
        if self.list.is_empty() {
            return;
        }
        self.sort_and_merge();
        let mut total: u128 = 0;
        let picker = self
            .list
            .iter()
            .map(|r| {
                let p = total as u64;
                total = total.wrapping_add(r.end.wrapping_sub(r.begin).wrapping_add(1));
                p
            })
            .collect();
        self.picker = Some(picker);
    }

    /// massip-rangesv6.c:513-543 `range6list_pick`: бинарный поиск по
    /// префиксным суммам. `index` обязан быть меньше числа адресов (C этого
    /// не проверяет и вернул бы адрес за последним диапазоном); список должен
    /// быть оптимизирован и непуст (в C иначе `exit(1)`, здесь паника).
    pub fn pick(&self, index: u64) -> u128 {
        let picker = self
            .picker
            .as_ref()
            .expect("ipv6 picker is null: call optimize before pick");
        let maxmax = self.list.len();
        let (mut min, mut max) = (0usize, maxmax);
        let mid = loop {
            let mid = min + (max - min) / 2;
            if index < picker[mid] {
                max = mid;
                continue;
            }
            if mid + 1 == maxmax || index < picker[mid + 1] {
                break mid;
            }
            min = mid + 1;
        };
        self.list[mid]
            .begin
            .wrapping_add(u128::from(index - picker[mid]))
    }

    /// massip-rangesv6.c:380-485 `range6list_remove_range`. Совпадает с C
    /// для всех входов, на которых C завершается. ОТЛИЧИЕ: C зацикливается
    /// навсегда, когда исключаемый диапазон начинается с `::` внутри цели,
    /// начинающейся с `::` (`MINUS_ONE(0)` = все единицы воссоздаёт цель), или
    /// заканчивается на `ffff:...:ffff` внутри цели (`PLUS_ONE(MAX)` = 0
    /// воссоздаёт `[0, MAX]`); проверено запуском C. Здесь в этих двух
    /// случаях пустая половина не создаётся.
    fn remove_range(&mut self, begin: u128, end: u128) {
        let x = Ipv6Range { begin, end };
        self.picker = None;
        let mut i = 0usize;
        while i < self.list.len() {
            let cur = self.list[i];
            if !is_overlap(cur, x) {
                i += 1;
                continue;
            }
            // Исключение целиком накрывает диапазон: удалить (:395-401).
            if begin <= cur.begin && cur.end <= end {
                self.list.remove(i);
                continue;
            }
            // Исключение делит диапазон: усечь нижнюю часть, добавить верхнюю
            // (:405-420). C затем повторно просматривает тот же индекс.
            if cur.begin <= begin && end <= cur.end {
                // Порядок как в C (:411-416): сначала усечение, потом добавление,
                // иначе новый диапазон слился бы с самой целью.
                if begin == 0 {
                    self.list.remove(i);
                } else {
                    self.list[i].end = begin - 1;
                }
                if end != u128::MAX {
                    self.add(end.wrapping_add(1), cur.end);
                }
                continue;
            }
            // Пересечение снизу (:423-425) и сверху (:428-430); второе
            // условие читает уже обновлённый `begin` цели.
            if cur.begin <= end && end <= cur.end {
                self.list[i].begin = end.wrapping_add(1);
            }
            let cur = self.list[i];
            if cur.begin <= begin && begin <= cur.end {
                self.list[i].end = begin.wrapping_sub(1);
            }
            i += 1;
        }
    }

    /// massip-rangesv6.c:447-472 `range6list_exclude`: удаляет каждый
    /// диапазон `excludes` из списка (без предварительной сортировки);
    /// возвращает суммарный размер исключений.
    pub fn apply_excludes(&mut self, excludes: &Range6List) -> u128 {
        let mut count: u128 = 0;
        for r in &excludes.list {
            count = count.wrapping_add(r.end.wrapping_sub(r.begin).wrapping_add(1));
            self.remove_range(r.begin, r.end);
        }
        self.picker = None;
        count
    }
}

/// massip-addr.c:33-109 `ipv6address_fmt`: слова по 16 бит в hex без ведущих
/// нулей; сжимается ПЕРВАЯ серия нулевых слов (не самая длинная, в отличие от
/// `Ipv6Addr::Display`), одиночный нулевой слово тоже сжимается в `::`.
pub fn format_ipv6_c(addr: u128) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let ip = Ipv6AddrBytes::from_u128(addr).0;
    let mut out = String::with_capacity(39);
    let mut is_ellision = false;
    let mut i = 0usize;
    // `for (i = 0; i < 16; i += 2)`, :36-77
    while i < 16 {
        let n = (u32::from(ip[i]) << 8) | u32::from(ip[i + 1]);
        if n == 0 && !is_ellision {
            is_ellision = true;
            while i < 13 && ip[i + 2] == 0 && ip[i + 3] == 0 {
                i += 2;
            }
            out.push(':');
            // Нулевой адрес целиком: вывод "::" (:58-62).
            while i == 14 && ip[i] == 0 && ip[i + 1] == 0 {
                i = 16;
                out.push(':');
            }
            i += 2;
            continue;
        }
        if i != 0 {
            out.push(':');
        }
        if n >> 12 != 0 {
            out.push(char::from(HEX[((n >> 12) & 0xF) as usize]));
        }
        if n >> 8 != 0 {
            out.push(char::from(HEX[((n >> 8) & 0xF) as usize]));
        }
        if n >> 4 != 0 {
            out.push(char::from(HEX[((n >> 4) & 0xF) as usize]));
        }
        out.push(char::from(HEX[(n & 0xF) as usize]));
        i += 2;
    }
    out
}

/// massip-parse.c:240-265 `_ipv6_apply_cidr` (`prefix` в 0..=128).
fn apply_cidr6(begin: u128, prefix: u32) -> Ipv6Range {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let begin = begin & mask;
    Ipv6Range {
        begin,
        end: begin | !mask,
    }
}

/// massip-parse.c:150-165 `_switch_to_ipv6`: десятичные цифры, накопленные
/// как число, перечитываются как hex-цифры (`2001` из «2001:» → 0x2001).
fn switch_to_hex(num: u32) -> u32 {
    ((num / 1000) % 10) * 16 * 16 * 16
        + ((num / 100) % 10) * 16 * 16
        + ((num / 10) % 10) * 16
        + (num % 10)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Start,
    Comment,
    Number0,
    Begin,
    Colon,
    Cidr,
    CidrNum,
    End,
}

/// Состояние `struct massip_parser` (massip-parse.c:19-39), только для IPv6.
struct P6 {
    tmp: u32,
    digit_count: u32,
    words: [u16; 8],
    index: usize,
    ellision: usize,
    is_bracket: bool,
    is_second: bool,
    begin: u128,
    end: u128,
}

impl P6 {
    /// :72-82 `_init_next_address`.
    fn init_next(&mut self, is_second: bool) {
        self.tmp = 0;
        self.ellision = 8;
        self.index = 0;
        self.is_bracket = false;
        self.digit_count = 0;
        self.is_second = is_second;
    }

    /// :86-143 `_parser_finish_ipv6`; `false` при ошибке.
    fn finish(&mut self) -> bool {
        let (index, ellision) = (self.index, self.ellision);
        // Нужно 8 слов или сжатие (:93-95).
        if index < 8 && ellision >= 8 {
            return false;
        }
        // Раскрытие `::` (:97-109): memmove хвоста к концу, нули в середину.
        let n = index - ellision;
        self.words.copy_within(ellision..index, 8 - n);
        for w in &mut self.words[ellision..ellision + (8 - index)] {
            *w = 0;
        }
        let mut a: u128 = 0;
        for w in self.words {
            a = (a << 16) | u128::from(w);
        }
        if self.is_second {
            self.end = a;
        } else {
            self.begin = a;
            self.end = a;
        }
        self.init_next(true);
        true
    }
}

/// massip-parse.c:274-763 `_parser_next` (только IPv6-состояния) поверх
/// massip-parse.c:1051-1103 `massip_parse_range`: разбирает один адрес или
/// диапазон IPv6, начиная с `*offset`. В конце строки автомату подаётся
/// виртуальный `\n` (:1082). `*offset` сдвигается за разделитель.
///
/// Принимает всё, что принимает C, включая его особенности (`:1:2:3:4:5:6:7`,
/// `::` вместо нуля слов, `a-b-c`, `a-b/N`, незакрытую `[`; см. тесты).
/// Отличия от C, оба намеренные: (1) обратный диапазон (`::2-::1`) отвергается
/// `ReversedRange`: C его принимает (massip-parse.c:419-431 не сравнивает
/// концы), а позже падает на счёте; для IPv4 действует то же решение
/// проекта; (2) девять слов (`1:2:3:4:5:6:7:8:`), где C пишет за пределы
/// `tmp[8]` (неопределённое поведение, на практике SIGSEGV), отвергаются.
pub(crate) fn parse_ipv6_range_at(buf: &[u8], offset: &mut usize) -> Result<Ipv6Range, ParseError> {
    let bad = ParseError::BadIpv6;
    let mut p = P6 {
        tmp: 0,
        digit_count: 0,
        words: [0; 8],
        index: 0,
        ellision: 8,
        is_bracket: false,
        is_second: false,
        begin: 0,
        end: 0,
    };
    let mut st = St::Start;
    let mut i = *offset;
    let hex_val = |c: u8| -> Option<u32> { (c as char).to_digit(16) };

    loop {
        // Виртуальный `\n` в позиции `buf.len()` (:1082); после него поток
        // кончился, и автомат, не нашедший адрес, даёт Bad_Address.
        let c = match i.cmp(&buf.len()) {
            std::cmp::Ordering::Less => buf[i],
            std::cmp::Ordering::Equal => b'\n',
            std::cmp::Ordering::Greater => return Err(bad),
        };
        i += 1;
        let consumed = i.min(buf.len());

        match st {
            // :301-352 LINE_START / ADDR_START
            St::Start => {
                p.init_next(false);
                match c {
                    b' ' | b'\t' | b'\r' | b'\n' => {}
                    b'#' | b';' | b'/' | b'-' => st = St::Comment,
                    b'0'..=b'9' => {
                        p.tmp = u32::from(c - b'0');
                        p.digit_count = 1;
                        st = St::Number0;
                    }
                    b'a'..=b'f' | b'A'..=b'F' => {
                        p.tmp = hex_val(c).unwrap_or(0);
                        p.digit_count = 1;
                        st = St::Begin;
                    }
                    b':' => {
                        p.words[p.index] = 0;
                        p.index += 1;
                        st = St::Colon;
                    }
                    b'[' => {
                        p.is_bracket = true;
                        st = St::Begin;
                    }
                    _ => return Err(bad),
                }
            }
            // :478-488 COMMENT
            St::Comment => {
                if c == b'\n' {
                    st = St::Start;
                }
            }
            // :642-700 NUMBER0 (десятичное начало, возможно IPv6)
            St::Number0 => match c {
                b'0'..=b'9' => {
                    p.digit_count += 1;
                    p.tmp = p.tmp * 10 + u32::from(c - b'0');
                    if p.tmp > 255 || p.digit_count > 3 {
                        p.tmp = switch_to_hex(p.tmp);
                        st = St::Begin;
                    }
                }
                b'a'..=b'f' | b'A'..=b'F' | b':' => {
                    p.tmp = switch_to_hex(p.tmp);
                    st = St::Begin;
                    i -= 1; // перечитать символ (:669, :745)
                }
                _ => return Err(bad),
            },
            // :386-398 IPV6_CIDR
            St::Cidr => {
                p.digit_count = 0;
                p.tmp = 0;
                match c {
                    b'0'..=b'9' => {
                        p.tmp = u32::from(c - b'0');
                        p.digit_count = 1;
                        st = St::CidrNum;
                    }
                    _ => return Err(bad),
                }
            }
            St::Colon | St::Begin => {
                if st == St::Colon {
                    // :400-415 IPV6_COLON
                    p.digit_count = 0;
                    p.tmp = 0;
                    if c == b':' {
                        if p.ellision < 8 {
                            return Err(bad);
                        }
                        p.ellision = p.index;
                        continue;
                    }
                    st = St::Begin;
                }
                // :418-482 IPV6_BEGIN / IPV6_NEXT
                match c {
                    b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => {
                        if p.digit_count >= 4 {
                            return Err(bad);
                        }
                        p.tmp = p.tmp * 16 + hex_val(c).unwrap_or(0);
                        p.digit_count += 1;
                    }
                    b':' => {
                        if p.index >= 8 {
                            return Err(bad);
                        }
                        p.words[p.index] = p.tmp as u16;
                        p.index += 1;
                        st = St::Colon;
                    }
                    b']' => {
                        if !p.is_bracket {
                            return Err(bad);
                        }
                        st = St::End;
                    }
                    b'[' => {
                        if p.is_bracket {
                            return Err(bad);
                        }
                        p.is_bracket = true;
                    }
                    b'/' | b' ' | b'\t' | b'\r' | b'\n' | b',' | b'-' => {
                        // push back (:471-475)
                        i -= 1;
                        st = St::End;
                    }
                    _ => return Err(bad),
                }
            }
            // :491-532 IPV6_END
            St::End => {
                // Последнее слово (:494). C пишет tmp[8] при index == 8 (UB).
                if p.index >= 8 {
                    return Err(bad);
                }
                p.words[p.index] = p.tmp as u16;
                p.index += 1;
                if !p.finish() {
                    return Err(bad);
                }
                match c {
                    b'/' => st = St::Cidr,
                    b'-' => st = St::Begin,
                    b'\n' | b' ' | b'\t' | b'\r' | b',' => {
                        if p.begin > p.end {
                            return Err(ParseError::ReversedRange);
                        }
                        *offset = consumed;
                        return Ok(Ipv6Range {
                            begin: p.begin,
                            end: p.end,
                        });
                    }
                    _ => return Err(bad),
                }
            }
            // :536-585 IPV6_CIDR_NUM
            St::CidrNum => match c {
                b'0'..=b'9' => {
                    if p.digit_count == 4 {
                        return Err(bad);
                    }
                    p.digit_count += 1;
                    p.tmp = p.tmp * 10 + u32::from(c - b'0');
                    if p.tmp > 128 {
                        return Err(bad);
                    }
                }
                b':' | b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                    let r = apply_cidr6(p.begin, p.tmp);
                    *offset = consumed;
                    return Ok(r);
                }
                _ => return Err(bad),
            },
        }
    }
}

/// Один IPv6-адрес, диапазон `a-b` или блок `a/N` (в скобках или без);
/// как `massip_parse_range` для одной цели. Хвост после цели, кроме
/// пробелов и запятых, отвергается.
pub fn parse_ipv6_target(spec: &str) -> Result<Ipv6Range, ParseError> {
    let buf = spec.as_bytes();
    let mut off = 0;
    let r = parse_ipv6_range_at(buf, &mut off)?;
    while off < buf.len() && (is_c_space(buf[off]) || buf[off] == b',') {
        off += 1;
    }
    if off < buf.len() {
        return Err(ParseError::BadIpv6);
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::ParseError;
    use std::net::Ipv6Addr;

    fn v(s: &str) -> u128 {
        u128::from(s.parse::<Ipv6Addr>().unwrap())
    }

    fn r(b: &str, e: &str) -> Ipv6Range {
        Ipv6Range {
            begin: v(b),
            end: v(e),
        }
    }

    fn list(ranges: &[(u128, u128)]) -> Range6List {
        let mut l = Range6List::new();
        for &(b, e) in ranges {
            l.add(b, e);
        }
        l
    }

    /// Review Focus 1. Oracle: `masscan --range <addr> -sL -p80` prints the
    /// address through `ipv6address_fmt` (massip-addr.c:33-109).
    #[test]
    fn ipv6_parse_unbracketed_and_c_fmt_first_zero() {
        let a = parse_ipv6_target("2a03:9060:0:400:0:0:0:2").unwrap();
        assert_eq!(a.begin, a.end);
        assert_eq!(a.begin, v("2a03:9060:0:400::2"));
        // C compresses the FIRST zero run (here the single word at index 2),
        // not the longest one (massip-addr.c:50-66); std prints "2a03:9060:0:400::2".
        assert_eq!(format_ipv6_c(a.begin), "2a03:9060::400:0:0:0:2");
        assert_ne!(format_ipv6_c(a.begin), Ipv6Addr::from(a.begin).to_string());

        // Unbracketed a-f starts parse (massip-parse.c:312-325; the CLI
        // positional check at main-conf.c:3594 is a separate, CLI-level rule).
        assert_eq!(
            parse_ipv6_target("fe80::1").unwrap(),
            r("fe80::1", "fe80::1")
        );
        assert_eq!(
            parse_ipv6_target("FE80::A").unwrap(),
            r("fe80::a", "fe80::a")
        );
        assert_eq!(
            parse_ipv6_target("fd00::/126").unwrap(),
            r("fd00::", "fd00::3")
        );
        assert_eq!(
            parse_ipv6_target("[2001:db8::1]-[2001:db8::5]").unwrap(),
            r("2001:db8::1", "2001:db8::5")
        );
        // Rejected: reversed range (see ReversedRange note on `parse_ipv6_range_at`),
        // double ellision (massip-parse.c:366-372).
        assert_eq!(parse_ipv6_target("::2-::1"), Err(ParseError::ReversedRange));
        assert_eq!(parse_ipv6_target("1::2::3"), Err(ParseError::BadIpv6));
    }

    /// Every row is the output of the C binary: `masscan --range <in> -p80 -sL`.
    #[test]
    fn c_fmt_matches_c_binary_table() {
        let rows: &[(&str, &str)] = &[
            ("2a03:9060:0:400:0:0:0:2", "2a03:9060::400:0:0:0:2"),
            ("2001:db8:0:0:0:0:0:1", "2001:db8::1"),
            ("1:0:0:0:0:0:0:0", "1::"),
            ("0:0:0:0:0:0:0:0", "::"),
            ("::1", "::1"),
            ("0:0:0:0:0:0:1:0", "::1:0"),
            ("1:0:2:0:0:0:3:0", "1::2:0:0:0:3:0"),
            ("0:1:0:0:2:0:0:0", "::1:0:0:2:0:0:0"),
            ("0:0:1:0:0:0:0:0", "::1:0:0:0:0:0"),
            ("1:0:0:2:0:0:0:0", "1::2:0:0:0:0"),
            ("1:2:3:4:5:6:7:0", "1:2:3:4:5:6:7::"),
            ("1:0:2:3:4:5:6:7", "1::2:3:4:5:6:7"),
            ("0:2:3:4:5:6:7:8", "::2:3:4:5:6:7:8"),
            ("1:2:3:4:5:6:0:0", "1:2:3:4:5:6::"),
            ("1:2:3:4:5:6:0:8", "1:2:3:4:5:6::8"),
            ("FE80::A", "fe80::a"),
            (
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
            ("1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"),
            ("0001::", "1::"),
            ("a:b::", "a:b::"),
        ];
        for (input, want) in rows {
            let a = parse_ipv6_target(input).unwrap();
            assert_eq!(a.begin, a.end, "{input}");
            assert_eq!(format_ipv6_c(a.begin), *want, "{input}");
        }
    }

    /// Quirks of the C state machine that C accepts and an RFC parser would
    /// not; every row verified with the C binary (-sL listing).
    #[test]
    fn parse_matches_c_state_machine_quirks() {
        let ok: &[(&str, u128, u128)] = &[
            // ':' at the start pushes a zero word (massip-parse.c:333-336).
            (":1:2:3:4:5:6:7", v("0:1:2:3:4:5:6:7"), v("0:1:2:3:4:5:6:7")),
            // '::' may stand for zero words (finish_ipv6 :95-110).
            (
                "1::2:3:4:5:6:7:8",
                v("1:2:3:4:5:6:7:8"),
                v("1:2:3:4:5:6:7:8"),
            ),
            // Trailing ':' before '/' (IPV6_END pushes the empty word).
            ("::1:/120", v("::1:0"), v("::1:ff")),
            // CIDR after a range re-masks begin and overwrites end (:454-461).
            ("::1-::3/126", v("::"), v("::3")),
            // A third address replaces the end again (IPV6_END '-' :435).
            ("::1-::3-::5", v("::1"), v("::5")),
            // Four digits of prefix are allowed: "0004" is /4 (:520-535).
            ("::1/0004", 0, (1u128 << 124) - 1),
            // Unclosed '[' is accepted (no bracket check at IPV6_END).
            ("[::1", v("::1"), v("::1")),
            ("[::1]/128", v("::1"), v("::1")),
            ("[::1]-::3", v("::1"), v("::3")),
            ("::1-[::3]", v("::1"), v("::3")),
            // Decimal start digits are re-read as hex (_switch_to_ipv6 :150-165).
            ("2001:db8::1", v("2001:db8::1"), v("2001:db8::1")),
            ("9999::1", v("9999::1"), v("9999::1")),
            ("256::1", v("256::1"), v("256::1")),
            ("0001::", v("1::"), v("1::")),
            ("::/0", 0, u128::MAX),
            ("ffff::/128", v("ffff::"), v("ffff::")),
        ];
        for (input, b, e) in ok {
            assert_eq!(
                parse_ipv6_target(input),
                Ok(Ipv6Range { begin: *b, end: *e }),
                "{input}"
            );
        }
        // Rejected by the C binary ("ERROR: bad IP address/range").
        for bad in [
            "1::2::3",
            ":::",
            "::1/129",
            "::1/",
            "::1/12a",
            "abcde::",
            "12345::",
            "99999::1",
            "00001::",
            "1:2:3:4:5:6:7",
            "fe80::1%eth0",
            "::ffff:1.2.3.4",
            "1.2.3.4-::1",
            "::1-1.2.3.4",
            "::1/64-::3",
            "[::1/128]",
            "[[::1]]",
            "::1]",
            "::g",
            ":1-:3",
            "::1-",
            "::1/-1",
            "::1/ 64",
            "10.0.0.1",
            "",
        ] {
            assert!(parse_ipv6_target(bad).is_err(), "{bad:?}");
        }
        // C reads past tmp[8] (undefined behaviour, observed SIGSEGV with the
        // C binary) for nine words; we reject.
        assert!(parse_ipv6_target("1:2:3:4:5:6:7:8:").is_err());
        assert!(parse_ipv6_target("1:2:3:4:5:6:7:8:9").is_err());
    }

    #[test]
    fn parse_at_handles_separators_and_comments() {
        let buf = b"  # note\n::1 , fe80::/126,::5-::6\t[::9]";
        let mut off = 0;
        let mut got = Vec::new();
        while off < buf.len() {
            got.push(parse_ipv6_range_at(buf, &mut off).unwrap());
            while off < buf.len() && (crate::targets::is_c_space(buf[off]) || buf[off] == b',') {
                off += 1;
            }
        }
        assert_eq!(
            got,
            [
                r("::1", "::1"),
                r("fe80::", "fe80::3"),
                r("::5", "::6"),
                r("::9", "::9")
            ]
        );
        // The ':' terminator after /N is consumed and the next token starts
        // after it (massip-parse.c:520-535).
        let mut off = 0;
        assert_eq!(
            parse_ipv6_range_at(b"::/126:::5", &mut off).unwrap(),
            r("::", "::3")
        );
        assert_eq!(off, 7);
    }

    #[test]
    fn addr_bytes_roundtrip() {
        let a = v("2a03:9060:0:400::2");
        let b = Ipv6AddrBytes::from_u128(a);
        assert_eq!(b.0[0], 0x2a);
        assert_eq!(b.0[15], 2);
        assert_eq!(b.to_u128(), a);
    }

    /// Review Focus 1: `::/0` neither panics nor wraps to zero.
    #[test]
    fn ipv6_full_space_and_63bit_limit() {
        let full = parse_ipv6_target("::/0").unwrap();
        assert_eq!((full.begin, full.end), (0, u128::MAX));
        let mut l = Range6List::new();
        l.add(full.begin, full.end);
        l.optimize();
        // massip-rangesv6.c:497-499: 2^128 is not representable, C returns the
        // all-ones "overflow" value (it equals 2^128 - 1, one short).
        assert_eq!(l.count_u128(), u128::MAX);
        // pick still works over the whole space (picker holds lo-64 sums).
        assert_eq!(l.pick(0), 0);
        assert_eq!(l.pick(u64::MAX), u128::from(u64::MAX));
        assert!(l.is_contains(u128::MAX));

        // A /66 is the largest block that fits the 63-bit scan range (the C
        // hint text of main.c:1698-1704); counting it does not overflow u128.
        let mut l = Range6List::new();
        let b = parse_ipv6_target("2001:db8::/66").unwrap();
        l.add(b.begin, b.end);
        assert_eq!(l.count_u128(), 1u128 << 62);

        // Exclude carves the middle out and keeps both sides.
        let mut t = Range6List::new();
        t.add(0, u128::MAX);
        let mut x = Range6List::new();
        x.add(100, 199);
        assert_eq!(t.apply_excludes(&x), 100);
        t.optimize();
        assert_eq!(
            t.as_slice(),
            &[
                Ipv6Range { begin: 0, end: 99 },
                Ipv6Range {
                    begin: 200,
                    end: u128::MAX
                }
            ]
        );
        assert_eq!(t.count_u128(), u128::MAX - 99); // (100 + (MAX-200+1)) = MAX-99
        assert_eq!(t.pick(99), 99);
        assert_eq!(t.pick(100), 200);
    }

    #[test]
    fn add_merges_adjacent_and_overlapping_after_optimize() {
        let mut l = list(&[(10, 20), (30, 40), (21, 29), (100, 110), (5, 12)]);
        l.optimize();
        assert_eq!(
            l.as_slice(),
            &[
                Ipv6Range { begin: 5, end: 40 },
                Ipv6Range {
                    begin: 100,
                    end: 110
                }
            ]
        );
        // Adjacent ranges at the top of the space do not wrap
        // (massip-rangesv6.c:225-226 guards PLUS_ONE with `== FFFF`).
        let mut l = list(&[(u128::MAX - 1, u128::MAX), (0, 3)]);
        l.optimize();
        assert_eq!(l.len(), 2);
    }

    /// massip-rangesv6.c:408-485 `range6list_remove_range` cases.
    #[test]
    fn exclude_cases_match_c() {
        let ex = |t: &[(u128, u128)], x: &[(u128, u128)]| {
            let mut t = list(t);
            let x = list(x);
            t.apply_excludes(&x);
            t.optimize();
            t.as_slice()
                .iter()
                .map(|r| (r.begin, r.end))
                .collect::<Vec<_>>()
        };
        // wholly covered
        assert_eq!(ex(&[(10, 20)], &[(5, 25)]), vec![]);
        assert_eq!(ex(&[(10, 20)], &[(10, 20)]), vec![]);
        // bisect
        assert_eq!(ex(&[(10, 20)], &[(14, 15)]), vec![(10, 13), (16, 20)]);
        // lower / upper side
        assert_eq!(ex(&[(10, 20)], &[(5, 12)]), vec![(13, 20)]);
        assert_eq!(ex(&[(10, 20)], &[(18, 30)]), vec![(10, 17)]);
        // exclude starting at the range start / ending at the range end
        assert_eq!(ex(&[(10, 20)], &[(10, 14)]), vec![(15, 20)]);
        assert_eq!(ex(&[(10, 20)], &[(16, 20)]), vec![(10, 15)]);
        // adjacent, no real overlap: untouched
        assert_eq!(ex(&[(10, 20)], &[(21, 30)]), vec![(10, 20)]);
        assert_eq!(ex(&[(10, 20)], &[(1, 9)]), vec![(10, 20)]);
        // several ranges, several excludes, unsorted excludes
        assert_eq!(
            ex(&[(0, 9), (20, 29), (40, 49)], &[(45, 60), (5, 22)]),
            vec![(0, 4), (23, 29), (40, 44)]
        );
        // single address carved from a block (masscan ::/124 --exclude ::5)
        assert_eq!(ex(&[(0, 15)], &[(5, 5)]), vec![(0, 4), (6, 15)]);
    }

    /// DIVERGENCE FROM C. The C binary never returns for these inputs
    /// (verified: `masscan --range ::/124 --exclude ::/126 -sL` and
    /// `--range ffff:...:fff0/124 --exclude ffff:...:fff8-ffff:...:ffff` run
    /// until killed). massip-rangesv6.c:436-448: the bisect branch computes
    /// MINUS_ONE(begin) = all-ones for begin == 0 and PLUS_ONE(end) = 0 for
    /// end == all-ones, which re-creates the range it just cut, forever.
    /// We return the arithmetically correct result instead.
    #[test]
    fn exclude_at_both_ends_of_the_space_terminates_unlike_c() {
        let ex = |t: &[(u128, u128)], x: &[(u128, u128)]| {
            let mut t = list(t);
            t.apply_excludes(&list(x));
            t.optimize();
            t.as_slice()
                .iter()
                .map(|r| (r.begin, r.end))
                .collect::<Vec<_>>()
        };
        assert_eq!(ex(&[(0, 15)], &[(0, 3)]), vec![(4, 15)]);
        assert_eq!(ex(&[(0, 10)], &[(0, 5)]), vec![(6, 10)]);
        assert_eq!(
            ex(&[(0, 255)], &[(0, 5), (100, 110)]),
            vec![(6, 99), (111, 255)]
        );
        let m = u128::MAX;
        assert_eq!(ex(&[(m - 15, m)], &[(m - 7, m)]), vec![(m - 15, m - 8)]);
        assert_eq!(ex(&[(1, m)], &[(3, m)]), vec![(1, 2)]);
        assert_eq!(ex(&[(0, m)], &[(0, 5)]), vec![(6, m)]);
        assert_eq!(ex(&[(0, m)], &[(m - 5, m)]), vec![(0, m - 6)]);
        assert_eq!(ex(&[(0, m)], &[(0, m)]), vec![]);
    }

    /// Oracle: `masscan --range <t> --exclude <x> -p80 -sL`, sorted, matches
    /// the set our excludes leave (small blocks, C does not hang here).
    #[test]
    fn exclude_matches_c_binary_listings() {
        let case = |t: &str, x: &str| {
            let mut tl = Range6List::new();
            let tr = parse_ipv6_target(t).unwrap();
            tl.add(tr.begin, tr.end);
            let mut xl = Range6List::new();
            let xr = parse_ipv6_target(x).unwrap();
            xl.add(xr.begin, xr.end);
            tl.apply_excludes(&xl);
            tl.optimize();
            tl.as_slice()
                .iter()
                .map(|r| (r.begin, r.end))
                .collect::<Vec<_>>()
        };
        // C listed ::14 .. ::1f
        assert_eq!(case("::10/124", "::10/126"), vec![(0x14, 0x1f)]);
        assert_eq!(case("::10/124", "::12/126"), vec![(0x14, 0x1f)]);
        // C listed every address of ::/124 except ::5
        assert_eq!(case("::/124", "::5"), vec![(0, 4), (6, 15)]);
        // C listed 1:: .. 1::4 and 1::8 .. 1::f
        assert_eq!(
            case("1::/124", "1::5-1::7"),
            vec![(v("1::"), v("1::4")), (v("1::8"), v("1::f"))]
        );
    }

    /// massip-rangesv6.c:490-507 and masscan's own selftest massip.c:127-145
    /// ("2607:f8b0:4002:801::2004/124,1111::1" minus "...2004/126,1111::/16").
    #[test]
    fn c_massip_selftest_count_is_twelve() {
        let mut t = Range6List::new();
        for s in ["2607:f8b0:4002:801::2004/124", "1111::1"] {
            let r = parse_ipv6_target(s).unwrap();
            t.add(r.begin, r.end);
        }
        let mut x = Range6List::new();
        for s in ["2607:f8b0:4002:801::2004/126", "1111::/16"] {
            let r = parse_ipv6_target(s).unwrap();
            x.add(r.begin, r.end);
        }
        t.apply_excludes(&x);
        t.optimize();
        assert_eq!(t.count_u128(), 12);
    }

    fn r_rand(seed: &mut u32) -> u32 {
        *seed = seed.wrapping_mul(214_013).wrapping_add(2_531_011);
        (*seed >> 16) & 0x7fff
    }

    /// massip-rangesv6.c:608-640 `regress_pick2` loop 3..100: picking every
    /// index reproduces the sorted list.
    #[test]
    fn pick_reproduces_sorted_list() {
        for i in 3..100u32 {
            let mut seed = i;
            let mut targets = Range6List::new();
            let (mut begin, mut end) = (0u128, 0u128);
            let n = r_rand(&mut seed) % 5 + 1;
            for _ in 0..n {
                begin += u128::from(r_rand(&mut seed) % 10);
                end = begin + u128::from(r_rand(&mut seed) % 10);
                targets.add(begin, end);
            }
            targets.optimize();
            let count = targets.count_u128();
            assert!(count >> 64 == 0);
            let mut dup = Range6List::new();
            for j in 0..count as u64 {
                let a = targets.pick(j);
                dup.add(a, a);
            }
            assert_eq!(targets.as_slice(), dup.as_slice(), "seed {i}");
            let _ = end;
        }
    }

    #[test]
    #[should_panic(expected = "picker")]
    fn pick_before_optimize_panics() {
        let l = list(&[(1, 2)]);
        l.pick(0);
    }

    /// 128-bit arithmetic carries across the 64-bit halves
    /// (`_int128_add64` / `PLUS_ONE`, massip-rangesv6.c:50-58,150-165).
    #[test]
    fn count_and_pick_cross_the_64_bit_boundary() {
        let lo = (1u128 << 64) - 3;
        let mut l = list(&[(lo, lo + 9)]);
        l.optimize();
        assert_eq!(l.count_u128(), 10);
        assert_eq!(l.pick(2), lo + 2);
        assert_eq!(l.pick(3), 1u128 << 64);
        let mut x = list(&[(1u128 << 64, (1u128 << 64) + 1)]);
        x.optimize();
        l.apply_excludes(&x);
        l.optimize();
        assert_eq!(l.count_u128(), 8);
    }

    #[test]
    fn is_contains_is_inclusive() {
        let l = list(&[(10, 20), (40, 50)]);
        assert!(l.is_contains(10) && l.is_contains(20) && l.is_contains(45));
        assert!(!l.is_contains(9) && !l.is_contains(21) && !l.is_contains(51));
    }
    /// Randomised: the result of `apply_excludes` is the set difference, for
    /// unsorted multi-range inputs including both ends of the space. The C
    /// binary was checked against the same set arithmetic on 300 random cases
    /// where it terminates (every case away from `::` and the top address).
    #[test]
    fn exclude_equals_set_difference_on_random_inputs() {
        use std::collections::BTreeSet;
        let mut seed = 12345u32;
        for case in 0..2000u32 {
            let near_top = case % 4 == 1;
            let near_zero = case % 4 == 2;
            let base: u128 = if near_top {
                u128::MAX - 63
            } else if near_zero {
                0
            } else {
                v("2001:db8::")
            };
            let make = |n: u32, seed: &mut u32| -> Vec<(u128, u128)> {
                (0..n)
                    .map(|_| {
                        let b = u128::from(r_rand(seed) % 60);
                        let l = u128::from(r_rand(seed) % 12);
                        (base + b, (base + b).saturating_add(l))
                    })
                    .collect()
            };
            let nt = r_rand(&mut seed) % 4 + 1;
            let nx = r_rand(&mut seed) % 4 + 1;
            let ts = make(nt, &mut seed);
            let xs = make(nx, &mut seed);
            let mut want = BTreeSet::new();
            for &(b, e) in &ts {
                for a in b..=e {
                    want.insert(a);
                }
            }
            for &(b, e) in &xs {
                for a in b..=e {
                    want.remove(&a);
                }
            }
            let mut t = list(&ts);
            t.apply_excludes(&list(&xs));
            t.optimize();
            let mut got = BTreeSet::new();
            for r in t.as_slice() {
                assert!(
                    r.begin <= r.end,
                    "case {case}: invalid range left: {ts:?} - {xs:?}"
                );
                for a in r.begin..=r.end {
                    got.insert(a);
                }
            }
            assert_eq!(got, want, "case {case}: {ts:?} - {xs:?}");
            // merged and sorted: no two ranges touch
            for w in t.as_slice().windows(2) {
                assert!(
                    w[0].end.checked_add(1).is_none_or(|n| n < w[1].begin),
                    "case {case}"
                );
            }
        }
    }
}
