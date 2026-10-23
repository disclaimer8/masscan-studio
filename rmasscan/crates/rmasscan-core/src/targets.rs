//! Разбор целей и портов командной строки (AGPL-3.0).
//! Порт частей `src/massip.c`, `src/massip-parse.c`, `src/massip-rangesv4.c`
//! и `src/massip-port.h` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).

use crate::ranges::{Range, RangeList};

/// Ошибка разбора цели или порта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("bad IPv4 address or range")]
    BadIpv4,
    #[error("bad port or port range")]
    BadPort,
    #[error("IPv6 targets are not supported")]
    Ipv6NotSupported,
    #[error("only TCP ports are supported (T: prefix or none)")]
    UnsupportedProtoPrefix,
    #[error("range end comes before range start")]
    ReversedRange,
}

pub const TEMPL_TCP: u32 = 0;
pub const TEMPL_TCP_LAST: u32 = 65535;
pub const TEMPL_UDP: u32 = 65536;
pub const TEMPL_UDP_LAST: u32 = 65536 + 65535;
pub const TEMPL_SCTP: u32 = 65536 * 2;
pub const TEMPL_SCTP_LAST: u32 = 65536 * 2 + 65535;
pub const TEMPL_ICMP_ECHO: u32 = 65536 * 3;
pub const TEMPL_ICMP_TIMESTAMP: u32 = 65536 * 3 + 1;
pub const TEMPL_ARP: u32 = 65536 * 3 + 2;
pub const TEMPL_OPROTO_FIRST: u32 = 65536 * 3 + 256;
pub const TEMPL_OPROTO_LAST: u32 = 65536 * 3 + 256 + 255;
pub const TEMPL_VULN_CHECK: u32 = 65536 * 4;

/// C `isspace` в локали "C" (включая \v и \f).
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// massip-rangesv4.c:470 `parse_ipv4`: четыре октета, ведущие нули
/// пропускаются, не более 3 значащих цифр. Возвращает адрес и смещение.
fn parse_ipv4(line: &[u8], mut offset: usize) -> Option<(u32, usize)> {
    let max = line.len();
    let mut result: u32 = 0;
    for i in 0..4 {
        if offset >= max || !line[offset].is_ascii_digit() {
            return None;
        }
        while offset < max && line[offset] == b'0' {
            offset += 1;
        }
        let mut x: u32 = 0;
        let mut digits = 0;
        while offset < max && line[offset].is_ascii_digit() {
            x = x * 10 + u32::from(line[offset] - b'0');
            offset += 1;
            digits += 1;
            if digits > 3 {
                return None;
            }
        }
        if x > 255 {
            return None;
        }
        result = result.wrapping_mul(256).wrapping_add(x);
        if i == 3 {
            break;
        }
        if offset >= max || line[offset] != b'.' {
            return None;
        }
        offset += 1;
    }
    Some((result, offset))
}

/// massip-rangesv4.c:533 `range_parse_ipv4`: `a.b.c.d`, `a.b.c.d/N` или
/// `a.b.c.d-e.f.g.h`. Эта функция в C не стоит на пути `--range`/`--exclude`
/// (там `massip_parse_range`); она нужна для `router-ip`, `redis` и файлов.
///
/// Отличия от C: невалидный ввод даёт `Err` вместо «badrange»
/// `{0xFFFFFFFF, 0}`, а мусор после адреса (C его молча игнорирует при
/// `offset == NULL`) тоже отвергается.
pub fn range_parse_ipv4(line: &str) -> Result<Range, ParseError> {
    let line = line.as_bytes();
    let max = line.len();
    let mut offset = 0;
    while offset < max && is_c_space(line[offset]) {
        offset += 1;
    }
    let (begin, off) = parse_ipv4(line, offset).ok_or(ParseError::BadIpv4)?;
    offset = off;
    let mut result = Range { begin, end: begin };
    while offset < max && is_c_space(line[offset]) {
        offset += 1;
    }
    if offset < max && line[offset] == b'/' {
        offset += 1;
        if offset >= max || !line[offset].is_ascii_digit() {
            return Err(ParseError::BadIpv4);
        }
        while offset < max && line[offset] == b'0' {
            offset += 1;
        }
        let mut prefix: u64 = 0;
        let mut digits = 0;
        while offset < max && line[offset].is_ascii_digit() {
            prefix = prefix * 10 + u64::from(line[offset] - b'0');
            offset += 1;
            digits += 1;
            if digits > 2 {
                return Err(ParseError::BadIpv4);
            }
        }
        if prefix > 32 {
            return Err(ParseError::BadIpv4);
        }
        result = apply_cidr(begin, prefix as u32);
    } else if offset < max && line[offset] == b'-' {
        let (ip, off) = parse_ipv4(line, offset + 1).ok_or(ParseError::BadIpv4)?;
        offset = off;
        // C (massip-rangesv4.c:596) тоже отвергает обратный диапазон.
        if ip < begin {
            return Err(ParseError::ReversedRange);
        }
        result.end = ip;
    }
    while offset < max && is_c_space(line[offset]) {
        offset += 1;
    }
    if offset < max {
        return Err(ParseError::BadIpv4);
    }
    Ok(result)
}

/// massip-parse.c:`_ipv4_apply_cidr`: `0xFFFFFFFF00000000 >> bits`.
fn apply_cidr(begin: u32, bits: u32) -> Range {
    let mask = (0xFFFF_FFFF_0000_0000u64 >> bits) as u32;
    let begin = begin & mask;
    Range {
        begin,
        end: begin | !mask,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum St {
    Start,
    Comment,
    /// Первый адрес, k-й октет (NUMBER0..3).
    First(u8),
    /// Второй адрес диапазона (SECOND0..3).
    Second(u8),
    CidrNum,
    Uni1,
    Uni2,
}

/// IPv6-ветки C-автомата (massip-parse.c `IPV6_*`) не портируются: токен с
/// двоеточием считаем IPv6, остальное считаем мусором.
fn not_ipv4(buf: &[u8], tok_start: usize) -> ParseError {
    let tok = buf[tok_start..]
        .iter()
        .take_while(|&&c| !is_c_space(c) && c != b',');
    if tok.clone().any(|&c| c == b':') {
        ParseError::Ipv6NotSupported
    } else {
        ParseError::BadIpv4
    }
}

/// massip-parse.c:1051 `massip_parse_range` поверх автомата `_parser_next`
/// (:`_parser_next`, только IPv4-состояния). Разбирает один адрес/диапазон,
/// начиная с `*offset`; в конце строки автомату подаётся виртуальный `\n`
/// (как в :1082). Возвращает диапазон и сдвигает `*offset` за разделитель.
fn parse_range_at(buf: &[u8], offset: &mut usize) -> Result<Range, ParseError> {
    let mut i = *offset;
    let mut st = St::Start;
    let mut tmp: u32 = 0;
    let mut digits: u32 = 0;
    let mut addr: u32 = 0;
    let mut begin: u32 = 0;
    let mut tok_start = i;
    let mut fed_newline = false;

    loop {
        let mut c = if i < buf.len() {
            i += 1;
            buf[i - 1]
        } else if !fed_newline {
            fed_newline = true;
            b'\n'
        } else {
            // Автомат всё ещё «работает» после виртуального \n: Bad_Address.
            return Err(ParseError::BadIpv4);
        };
        let consumed = if fed_newline { buf.len() } else { i };

        if st == St::Uni2 {
            // :`UNIDASH2`: U+2010..U+2015 ведут себя как '-' в NUMBER3.
            if !(0x90..=0x95).contains(&c) {
                return Err(ParseError::BadIpv4);
            }
            c = b'-';
            st = St::First(3);
        }

        match st {
            St::Start => match c {
                b' ' | b'\t' | b'\r' | b'\n' => {}
                b'#' | b';' | b'/' | b'-' => st = St::Comment,
                b'0'..=b'9' => {
                    tok_start = i - 1;
                    tmp = u32::from(c - b'0');
                    digits = 1;
                    st = St::First(0);
                }
                b'a'..=b'f' | b'A'..=b'F' | b':' | b'[' => {
                    return Err(not_ipv4(buf, i - 1));
                }
                _ => return Err(ParseError::BadIpv4),
            },
            St::Comment => {
                if c == b'\n' {
                    st = St::Start;
                }
            }
            St::Uni1 => {
                if c == 0x80 {
                    st = St::Uni2;
                } else {
                    return Err(ParseError::BadIpv4);
                }
            }
            St::Uni2 => unreachable!(),
            St::First(k) | St::Second(k) => {
                let first = matches!(st, St::First(_));
                let sep = |c: u8| matches!(c, b',' | b' ' | b'\t' | b'\r' | b'\n' | b':');
                match c {
                    b'.' => {
                        addr = (addr << 8) | tmp;
                        tmp = 0;
                        digits = 0;
                        if k == 3 {
                            return Err(ParseError::BadIpv4);
                        }
                        st = if first {
                            St::First(k + 1)
                        } else {
                            St::Second(k + 1)
                        };
                    }
                    b'0'..=b'9' => {
                        digits += 1;
                        tmp = tmp * 10 + u32::from(c - b'0');
                        if tmp > 255 || digits > 3 {
                            // :`NUMBER0` → IPv6, иначе ошибка.
                            return Err(if first && k == 0 {
                                not_ipv4(buf, tok_start)
                            } else {
                                ParseError::BadIpv4
                            });
                        }
                    }
                    b'a'..=b'f' | b'A'..=b'F' => {
                        return Err(if first && k == 0 {
                            not_ipv4(buf, tok_start)
                        } else {
                            ParseError::BadIpv4
                        });
                    }
                    0xe2 => {
                        if first && k == 3 {
                            st = St::Uni1;
                        } else {
                            return Err(ParseError::BadIpv4);
                        }
                    }
                    b'-' | 0x96 => {
                        if first && k == 3 {
                            begin = (addr << 8) | tmp;
                            tmp = 0;
                            digits = 0;
                            addr = 0;
                            st = St::Second(0);
                        } else {
                            return Err(ParseError::BadIpv4);
                        }
                    }
                    b'/' => {
                        if first && k == 3 {
                            begin = (addr << 8) | tmp;
                            tmp = 0;
                            digits = 0;
                            addr = 0;
                            st = St::CidrNum;
                        } else {
                            return Err(ParseError::BadIpv4);
                        }
                    }
                    b':' if first && k == 0 => return Err(not_ipv4(buf, tok_start)),
                    c if sep(c) => {
                        if k != 3 {
                            return Err(ParseError::BadIpv4);
                        }
                        let value = (addr << 8) | tmp;
                        let range = if first {
                            Range {
                                begin: value,
                                end: value,
                            }
                        } else {
                            Range { begin, end: value }
                        };
                        // C принимает обратный диапазон (massip-parse.c:719-731
                        // не проверяет begin <= end), но он ломает `pick`
                        // (немонотонный picker), поэтому отвергаем (ruling).
                        if range.end < range.begin {
                            return Err(ParseError::ReversedRange);
                        }
                        *offset = consumed;
                        return Ok(range);
                    }
                    _ => return Err(ParseError::BadIpv4),
                }
            }
            St::CidrNum => match c {
                b'0'..=b'9' => {
                    if digits == 3 {
                        return Err(ParseError::BadIpv4);
                    }
                    digits += 1;
                    tmp = tmp * 10 + u32::from(c - b'0');
                    if tmp > 32 {
                        return Err(ParseError::BadIpv4);
                    }
                }
                // Как в C, "a.b.c.d/" без цифр даёт /0 (digit_count == 0 не
                // проверяется, massip-parse.c:IPV4_CIDR_NUM).
                b':' | b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                    *offset = consumed;
                    return Ok(apply_cidr(begin, tmp));
                }
                _ => return Err(ParseError::BadIpv4),
            },
        }
    }
}

/// massip.c:72 `massip_add_target_string`: диапазоны через запятую и/или
/// пробелы. На пути `--range`/`--exclude` в main-conf.c:2736/2752 стоит
/// именно эта функция (через `massip_parse_range`), не `range_parse_ipv4`.
/// IPv6 даёт `Ipv6NotSupported`. При ошибке `targets` не меняется (C
/// добавляет уже разобранные диапазоны до ошибки; здесь всё или ничего).
pub fn add_target_string(targets: &mut RangeList, s: &str) -> Result<(), ParseError> {
    let buf = s.as_bytes();
    let mut offset = 0;
    let mut found = Vec::new();
    while offset < buf.len() {
        found.push(parse_range_at(buf, &mut offset)?);
        while offset < buf.len() && (is_c_space(buf[offset]) || buf[offset] == b',') {
            offset += 1;
        }
    }
    for r in found {
        targets.add_range(r.begin, r.end);
    }
    Ok(())
}

/// C `strtoul(p, &p, 0)` для строки, начинающейся с цифры: `0x` — hex,
/// ведущий `0` — восьмеричное, иначе десятичное. Переполнение даёт
/// `u64::MAX` (в C затем `(unsigned)`-усечение, которое мы не повторяем).
fn strtoul0(s: &[u8], pos: &mut usize) -> u64 {
    let (radix, mut i) = if s[*pos] == b'0'
        && s.get(*pos + 1).is_some_and(|c| *c == b'x' || *c == b'X')
        && s.get(*pos + 2).is_some_and(u8::is_ascii_hexdigit)
    {
        (16, *pos + 2)
    } else if s[*pos] == b'0' {
        (8, *pos)
    } else {
        (10, *pos)
    };
    let mut v: u64 = 0;
    while let Some(d) = s.get(i).and_then(|c| (*c as char).to_digit(radix)) {
        v = v
            .saturating_mul(u64::from(radix))
            .saturating_add(u64::from(d));
        i += 1;
    }
    *pos = i;
    v
}

/// massip-rangesv4.c:993 `rangelist_parse_ports` (через `massip_add_port_string`,
/// main-conf.c:2675). Формы: `80`, `1000-2000`, `-1024` (порты 1..=1024,
/// как в C: `port = 1`), `80-` (до 65535), список через запятую, `T:`-префикс.
/// `U:`/`S:`/`O:`/`I:` дают `UnsupportedProtoPrefix`.
///
/// Отличия от C: там мусор на месте порта (`abc`, `80,,90`, `08`, `T:`)
/// молча обрывает разбор без ошибки, здесь это `BadPort`; значения больше
/// 0xFFFF отвергаются без `(unsigned)`-усечения. `#` по-прежнему начинает
/// комментарий. При ошибке `ports` не меняется. Обратный диапазон
/// (`end < begin`) — ошибка, как в C (:1067).
pub fn parse_ports(ports: &mut RangeList, s: &str) -> Result<(), ParseError> {
    let b = s.as_bytes();
    let mut p = 0;
    let mut found: Vec<(u32, u32)> = Vec::new();

    while p < b.len() {
        while p < b.len() && is_c_space(b[p]) {
            p += 1;
        }
        if p >= b.len() || b[p] == b'#' {
            break;
        }

        // :1016 — префикс протокола. Для TCP смещение 0, оно же по умолчанию.
        if b[p].is_ascii_alphabetic() && b.get(p + 1) == Some(&b':') {
            match b[p] {
                b'T' | b't' => {}
                b'U' | b'u' | b'S' | b's' | b'O' | b'o' | b'I' | b'i' => {
                    return Err(ParseError::UnsupportedProtoPrefix);
                }
                _ => return Err(ParseError::BadPort),
            }
            p += 2;
        }

        // :1044 начало диапазона; `-N` значит с порта 1.
        let port: u64 = match b.get(p) {
            Some(b'-') => 1,
            Some(c) if c.is_ascii_digit() => strtoul0(b, &mut p),
            _ => return Err(ParseError::BadPort),
        };

        // :1056 конец диапазона; `N-` значит до 65535.
        let end: u64 = if b.get(p) == Some(&b'-') {
            p += 1;
            if b.get(p).is_some_and(u8::is_ascii_digit) {
                strtoul0(b, &mut p)
            } else {
                0xFFFF
            }
        } else {
            port
        };

        // :1067 проверка границ.
        if port > 0xFFFF || end > 0xFFFF {
            return Err(ParseError::BadPort);
        }
        if end < port {
            return Err(ParseError::ReversedRange);
        }
        found.push((port as u32 + TEMPL_TCP, end as u32 + TEMPL_TCP));

        while p < b.len() && is_c_space(b[p]) {
            p += 1;
        }
        if p >= b.len() {
            break;
        }
        // C (:1090) просто выходит, если дальше не запятая; `#` там — комментарий.
        if b[p] == b'#' {
            break;
        }
        if b[p] != b',' {
            return Err(ParseError::BadPort);
        }
        p += 1;
    }

    for (begin, end) in found {
        ports.add_range(begin, end);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_single_cidr_dash() {
        assert_eq!(
            range_parse_ipv4("192.168.1.3").unwrap(),
            Range {
                begin: 0xc0a8_0103,
                end: 0xc0a8_0103
            }
        );
        assert_eq!(
            range_parse_ipv4("10.0.1.2/16").unwrap(),
            Range {
                begin: 0x0a00_0000,
                end: 0x0a00_ffff
            }
        );
        assert_eq!(
            range_parse_ipv4("10.0.0.20-10.0.0.30").unwrap(),
            Range {
                begin: 0x0a00_0000 + 20,
                end: 0x0a00_0000 + 30
            }
        );
        assert_eq!(
            range_parse_ipv4("0.0.0.0/0").unwrap(),
            Range {
                begin: 0,
                end: 0xffff_ffff
            }
        );
    }

    #[test]
    fn parse_ipv4_rejects_bad_octets() {
        for bad in ["75.748.86.91", "23.75.345.200", "192.1083.0.1", "0.0.0./0"] {
            assert!(range_parse_ipv4(bad).is_err(), "{bad}");
        }
        // Автомат `massip_parse_range` (путь --range) строже по октетам, но
        // принимает "0.0.0./0" как /0 (проверено на C-харнессе), поэтому
        // тот случай здесь не проверяется.
        for bad in ["75.748.86.91", "23.75.345.200", "192.1083.0.1"] {
            let mut l = RangeList::new();
            assert!(add_target_string(&mut l, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reversed_ranges_rejected() {
        // C принимает обратный диапазон (massip-parse.c:719-731), мы нет.
        assert_eq!(
            range_parse_ipv4("10.0.0.5-10.0.0.3"),
            Err(ParseError::ReversedRange)
        );
        let mut l = RangeList::new();
        assert_eq!(
            add_target_string(&mut l, "10.0.0.5-10.0.0.3"),
            Err(ParseError::ReversedRange)
        );
        assert!(l.is_empty());
        assert!(parse_ports(&mut l, "2000-1000").is_err());
    }

    #[test]
    fn add_target_string_selftest_cases() {
        // massip-parse.c:1121-1123
        for s in [
            "0.0.1.0/24,0.0.3.0-0.0.4.0",
            "0.0.1.0-0.0.1.255,0.0.3.0-0.0.4.0",
            "0.0.1.0/24 0.0.3.0-0.0.4.0",
        ] {
            let mut l = RangeList::new();
            add_target_string(&mut l, s).unwrap();
            assert_eq!(l.len(), 2, "{s}");
            assert_eq!(
                l.get(0),
                Range {
                    begin: 0x100,
                    end: 0x1ff
                }
            );
            assert_eq!(
                l.get(1),
                Range {
                    begin: 0x300,
                    end: 0x400
                }
            );
        }
    }

    #[test]
    fn add_target_string_ipv6_and_edges() {
        let mut l = RangeList::new();
        for v6 in [
            "1::1",
            "::1",
            "2607:f8b0:4002:801::2004/124",
            "1111::/16",
            "[::1]",
        ] {
            assert_eq!(
                add_target_string(&mut l, v6),
                Err(ParseError::Ipv6NotSupported),
                "{v6}"
            );
        }
        assert!(l.is_empty());
        // Пустая строка: C ничего не делает и возвращает 0.
        add_target_string(&mut l, "").unwrap();
        // Только пробелы / ведущая запятая: ошибка (виртуальный \n, :1082).
        assert!(add_target_string(&mut l, "  ").is_err());
        assert!(add_target_string(&mut l, ",1.2.3.4").is_err());
        // Хвостовая запятая/пробел и ведущий пробел допустимы.
        add_target_string(&mut l, " 1.2.3.4, ").unwrap();
        add_target_string(&mut l, "5.6.7.8,,9.9.9.9").unwrap();
        assert_eq!(l.len(), 3);
    }

    #[test]
    fn add_target_string_quirks_of_c() {
        let one = |s: &str| {
            let mut l = RangeList::new();
            add_target_string(&mut l, s).map(|()| l.as_slice().to_vec())
        };
        // ведущие нули десятичные (:`NUMBER*`), 4 цифры уже ошибка
        assert_eq!(
            one("010.001.0.1").unwrap(),
            vec![Range {
                begin: 0x0a01_0001,
                end: 0x0a01_0001
            }]
        );
        assert!(one("0001.0.0.1").is_err());
        // /32 и /0
        assert_eq!(
            one("1.2.3.4/32").unwrap(),
            vec![Range {
                begin: 0x0102_0304,
                end: 0x0102_0304
            }]
        );
        assert_eq!(
            one("1.2.3.4/0").unwrap(),
            vec![Range {
                begin: 0,
                end: u32::MAX
            }]
        );
        assert!(one("1.2.3.4/33").is_err());
        // Недописанные адреса C принимает с нулями (проверено на харнессе).
        assert_eq!(
            one("1.2.3.").unwrap(),
            vec![Range {
                begin: 0x0102_0300,
                end: 0x0102_0300
            }]
        );
        assert_eq!(
            one("0.0.0./0").unwrap(),
            vec![Range {
                begin: 0,
                end: u32::MAX
            }]
        );
        // "a.b.c.d/" без цифр — это /0, как в C.
        assert_eq!(
            one("1.2.3.4/").unwrap(),
            vec![Range {
                begin: 0,
                end: u32::MAX
            }]
        );
        // Unicode-дефис U+2013
        assert_eq!(
            one("1.1.1.1\u{2013}1.1.1.3").unwrap(),
            vec![Range {
                begin: 0x0101_0101,
                end: 0x0101_0103
            }]
        );
    }

    #[test]
    fn parse_ports_tcp_and_rejects_other_protos() {
        let mut p = RangeList::new();
        parse_ports(&mut p, "80,1000-2000,1234,4444").unwrap();
        p.sort_and_merge();
        assert_eq!(p.len(), 3);
        assert_eq!(p.get(0), Range { begin: 80, end: 80 });
        assert_eq!(
            p.get(1),
            Range {
                begin: 1000,
                end: 2000
            }
        );
        // Review Focus №5: не-TCP префиксы отклоняются
        assert_eq!(
            parse_ports(&mut RangeList::new(), "U:53"),
            Err(ParseError::UnsupportedProtoPrefix)
        );
        assert!(parse_ports(&mut RangeList::new(), "70000").is_err());
    }

    #[test]
    fn parse_ports_forms() {
        let one = |s: &str| {
            let mut l = RangeList::new();
            parse_ports(&mut l, s).map(|()| l.as_slice().to_vec())
        };
        // nmap-стиль: `-N` начинается с 1 (:1044), `N-` кончается 65535
        assert_eq!(
            one("-1024").unwrap(),
            vec![Range {
                begin: 1,
                end: 1024
            }]
        );
        assert_eq!(
            one("80-").unwrap(),
            vec![Range {
                begin: 80,
                end: 65535
            }]
        );
        assert_eq!(
            one("-").unwrap(),
            vec![Range {
                begin: 1,
                end: 65535
            }]
        );
        assert_eq!(one("T:80").unwrap(), vec![Range { begin: 80, end: 80 }]);
        assert_eq!(one("t:80,443").unwrap().len(), 2);
        assert_eq!(one("0-10").unwrap(), vec![Range { begin: 0, end: 10 }]);
        assert_eq!(
            one("65535").unwrap(),
            vec![Range {
                begin: 65535,
                end: 65535
            }]
        );
        assert_eq!(
            one(" 80 , 81 ").unwrap(),
            vec![Range { begin: 80, end: 81 }]
        );
        assert_eq!(one("80,").unwrap(), vec![Range { begin: 80, end: 80 }]);
        assert_eq!(
            one("80 # comment").unwrap(),
            vec![Range { begin: 80, end: 80 }]
        );
        assert_eq!(one("").unwrap(), vec![]);
        // strtoul base 0
        assert_eq!(one("0x50").unwrap(), vec![Range { begin: 80, end: 80 }]);
        assert_eq!(one("010").unwrap(), vec![Range { begin: 8, end: 8 }]);
        // ошибки
        for bad in [
            "65536",
            "99999999999999999999",
            "abc",
            "80,,81",
            "80x",
            "X:80",
            "T:",
            "80,U:53",
            "S:1",
            "O:1",
            "I:1",
            "8a",
        ] {
            assert!(one(bad).is_err(), "{bad}");
        }
        // при ошибке список не меняется
        let mut l = RangeList::new();
        assert!(parse_ports(&mut l, "80,U:53").is_err());
        assert!(l.is_empty());
    }

    #[test]
    fn proto_offsets() {
        assert_eq!(TEMPL_UDP, 65536);
        assert_eq!(TEMPL_SCTP, 131072);
        assert_eq!(TEMPL_ICMP_ECHO, 196608);
        assert_eq!(TEMPL_OPROTO_FIRST, 196608 + 256);
    }
}
