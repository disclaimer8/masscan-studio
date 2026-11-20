//! Разбор целей и портов командной строки (AGPL-3.0).
//! Порт частей `src/massip.c`, `src/massip-parse.c`, `src/massip-rangesv4.c`
//! и `src/massip-port.h` из masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).

use crate::ranges::{Range, RangeList};
use crate::ranges6::{Range6List, parse_ipv6_range_at};

/// Ошибка разбора цели или порта.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("bad IPv4 address or range")]
    BadIpv4,
    #[error("bad port or port range")]
    BadPort,
    #[error("IPv6 targets are not supported")]
    Ipv6NotSupported,
    #[error("range end comes before range start")]
    ReversedRange,
    #[error("bad IPv6 address or range")]
    BadIpv6,
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
pub(crate) fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `s` без ведущих пробелов C ([`is_c_space`]).
fn skip_c_space(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| is_c_space(c)).count();
    &s[n..]
}

/// `s` без ведущих разделителей списка целей: пробелов C и запятых.
fn skip_target_separators(s: &[u8]) -> &[u8] {
    let n = s
        .iter()
        .take_while(|&&c| is_c_space(c) || c == b',')
        .count();
    &s[n..]
}

/// `s` без ведущих нулей.
fn skip_zeros(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| c == b'0').count();
    &s[n..]
}

/// massip-rangesv4.c:470 `parse_ipv4`: четыре октета, ведущие нули
/// пропускаются, не более 3 значащих цифр. Возвращает адрес и остаток строки.
fn parse_ipv4(line: &[u8]) -> Option<(u32, &[u8])> {
    let mut rest = line;
    let mut result: u32 = 0;
    for i in 0..4 {
        if !rest.first().is_some_and(u8::is_ascii_digit) {
            return None;
        }
        rest = skip_zeros(rest);
        let mut x: u32 = 0;
        let mut digits = 0;
        while let [c @ b'0'..=b'9', tail @ ..] = rest {
            x = x * 10 + u32::from(c - b'0');
            rest = tail;
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
        rest = rest.strip_prefix(b".")?;
    }
    Some((result, rest))
}

/// massip-rangesv4.c:533 `range_parse_ipv4`: `a.b.c.d`, `a.b.c.d/N` или
/// `a.b.c.d-e.f.g.h`. Эта функция в C не стоит на пути `--range`/`--exclude`
/// (там `massip_parse_range`); она нужна для `router-ip`, `redis` и файлов.
///
/// Отличия от C: невалидный ввод даёт `Err` вместо «badrange»
/// `{0xFFFFFFFF, 0}`, а мусор после адреса (C его молча игнорирует при
/// `offset == NULL`) тоже отвергается.
pub fn range_parse_ipv4(line: &str) -> Result<Range, ParseError> {
    let (begin, rest) = parse_ipv4(skip_c_space(line.as_bytes())).ok_or(ParseError::BadIpv4)?;
    let mut result = Range { begin, end: begin };
    let mut rest = skip_c_space(rest);
    if let Some(tail) = rest.strip_prefix(b"/") {
        if !tail.first().is_some_and(u8::is_ascii_digit) {
            return Err(ParseError::BadIpv4);
        }
        rest = skip_zeros(tail);
        let mut prefix: u64 = 0;
        let mut digits = 0;
        while let [c @ b'0'..=b'9', tail @ ..] = rest {
            prefix = prefix * 10 + u64::from(c - b'0');
            rest = tail;
            digits += 1;
            if digits > 2 {
                return Err(ParseError::BadIpv4);
            }
        }
        if prefix > 32 {
            return Err(ParseError::BadIpv4);
        }
        result = apply_cidr(begin, prefix as u32);
    } else if let Some(tail) = rest.strip_prefix(b"-") {
        let (ip, tail) = parse_ipv4(tail).ok_or(ParseError::BadIpv4)?;
        rest = tail;
        // C (massip-rangesv4.c:621-627) тоже отвергает обратный диапазон.
        if ip < begin {
            return Err(ParseError::ReversedRange);
        }
        result.end = ip;
    }
    if !skip_c_space(rest).is_empty() {
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
/// (:`_parser_next`, только IPv4-состояния). Разбирает один адрес/диапазон
/// с начала `buf`; в конце строки автомату подаётся виртуальный `\n`
/// (как в :1082). Возвращает диапазон и остаток `buf` за разделителем.
fn parse_range_at(buf: &[u8]) -> Result<(Range, &[u8]), ParseError> {
    let mut rest = buf;
    let mut st = St::Start;
    let mut tmp: u32 = 0;
    let mut digits: u32 = 0;
    let mut addr: u32 = 0;
    let mut begin: u32 = 0;
    let mut tok_start = 0;
    let mut fed_newline = false;

    loop {
        // Смещение байта `c` в `buf`, взятое до того, как `c` снят с `rest`.
        let at = buf.len() - rest.len();
        let mut c = if let Some((&c, tail)) = rest.split_first() {
            rest = tail;
            c
        } else if !fed_newline {
            fed_newline = true;
            b'\n'
        } else {
            // Автомат всё ещё «работает» после виртуального \n: Bad_Address.
            return Err(ParseError::BadIpv4);
        };

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
                    tok_start = at;
                    tmp = u32::from(c - b'0');
                    digits = 1;
                    st = St::First(0);
                }
                b'a'..=b'f' | b'A'..=b'F' | b':' | b'[' => {
                    return Err(not_ipv4(buf, at));
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
                        // Пустой октет ("1..2.3" C читает как 1.0.2.3, "x-.1.2.3"
                        // аналогично) — опечатка, отвергаем (ruling), как и
                        // хвостовую точку; C: massip-parse.c:608-620 не смотрит digit_count.
                        if digits == 0 {
                            return Err(ParseError::BadIpv4);
                        }
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
                        if first && k == 3 && digits > 0 {
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
                        if first && k == 3 && digits > 0 {
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
                        // C принимает "1.2.3." как 1.2.3.0 (massip-parse.c:658-703:
                        // NUMBER3 без проверки digit_count); malformed, отвергаем (ruling).
                        if k != 3 || digits == 0 {
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
                        return Ok((range, rest));
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
                // C принимает "a.b.c.d/" без цифр как /0, т.е. всё пространство IPv4
                // (massip-parse.c:538 IPV4_CIDR_NUM не проверяет digit_count).
                // Это опечатка, а не намерение: отвергаем (ruling).
                b':' | b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                    if digits == 0 {
                        return Err(ParseError::BadIpv4);
                    }
                    return Ok((apply_cidr(begin, tmp), rest));
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
    let mut rest = s.as_bytes();
    let mut found = Vec::new();
    while !rest.is_empty() {
        let (r, tail) = parse_range_at(rest)?;
        found.push(r);
        rest = skip_target_separators(tail);
    }
    for r in found {
        targets.add_range(r.begin, r.end);
    }
    Ok(())
}

/// massip.c:72-100 `massip_add_target_string` с обеими ветками: IPv4-диапазоны
/// идут в `ipv4`, IPv6 (`Ipv6_Address`, :89 `range6list_add_range`) в `ipv6`.
/// Строка, разбираемая как IPv4, ведёт себя ровно как [`add_target_string`]
/// (включая ошибки); токен, который C-автомат переводит в IPv6
/// (`_switch_to_ipv6`, massip-parse.c:150), разбирает `parse_ipv6_range_at`.
/// При ошибке не меняется ни один из списков (всё или ничего).
pub fn add_target_string_v46(
    ipv4: &mut RangeList,
    ipv6: &mut Range6List,
    s: &str,
) -> Result<(), ParseError> {
    let buf = s.as_bytes();
    let mut rest = buf;
    let mut found4 = Vec::new();
    let mut found6 = Vec::new();
    while !rest.is_empty() {
        match parse_range_at(rest) {
            Ok((r, tail)) => {
                found4.push(r);
                rest = tail;
            }
            Err(ParseError::Ipv6NotSupported) => {
                // IPv6 разбирается заново с начала этого вызова `parse_range_at`.
                let mut offset = buf.len() - rest.len();
                found6.push(parse_ipv6_range_at(buf, &mut offset)?);
                rest = &buf[offset..];
            }
            Err(e) => return Err(e),
        }
        rest = skip_target_separators(rest);
    }
    for r in found4 {
        ipv4.add_range(r.begin, r.end);
    }
    for r in found6 {
        ipv6.add(r.begin, r.end);
    }
    Ok(())
}

/// C `strtoul(p, &p, 0)` для строки, начинающейся с цифры: `0x` — hex,
/// ведущий `0` — восьмеричное, иначе десятичное. Переполнение даёт
/// `u64::MAX` (в C затем `(unsigned)`-усечение, которое мы не повторяем).
/// Возвращает значение и остаток `s` за числом.
pub(crate) fn strtoul0(s: &[u8]) -> (u64, &[u8]) {
    let (radix, mut rest) = match s {
        [b'0', b'x' | b'X', h, ..] if h.is_ascii_hexdigit() => (16, &s[2..]),
        [b'0', ..] => (8, s),
        _ => (10, s),
    };
    let mut v: u64 = 0;
    while let [c, tail @ ..] = rest
        && let Some(d) = (*c as char).to_digit(radix)
    {
        v = v
            .saturating_mul(u64::from(radix))
            .saturating_add(u64::from(d));
        rest = tail;
    }
    (v, rest)
}

/// Протокол, закодированный в индексе порта (`massip-port.h:11-25`), и его
/// порт. Общий для приёма и передачи тип ядра; выходной слой CLI строит свой
/// `Proto` поверх него.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortProto {
    Tcp,
    Udp,
    Sctp,
    /// `I:0` (`Templ_ICMP_echo`).
    IcmpEcho,
    /// `I:n`, `n` кроме 0 и ARP: `Templ_ICMP_timestamp` = 1 и далее. Живой
    /// скан такие индексы отклоняет (Р1).
    IcmpOther(u8),
    /// `Templ_ARP` = 65536*3+2, то есть `I:2` (massip-port.h:18-20).
    Arp,
    /// `O:n`, сырой IP-протокол `n` (`Templ_Oproto_first + n`).
    Oproto(u8),
}

impl PortProto {
    /// Разбирает индекс порта на протокол и 16-битный порт. Порт осмыслен
    /// для TCP/UDP/SCTP, для остальных он 0. Индексы выше `Templ_Oproto_last`
    /// (`I:512..`, парсер принимает их, как C) не моделируются: они
    /// сворачиваются в `IcmpOther(255)`, а живой слой их отклоняет.
    pub fn from_raw(raw: u32) -> (PortProto, u16) {
        let low = (raw & 0xFFFF) as u16;
        match raw {
            r if r < TEMPL_UDP => (PortProto::Tcp, low),
            r if r < TEMPL_SCTP => (PortProto::Udp, low),
            r if r < TEMPL_ICMP_ECHO => (PortProto::Sctp, low),
            TEMPL_ICMP_ECHO => (PortProto::IcmpEcho, 0),
            TEMPL_ARP => (PortProto::Arp, 0),
            r if r < TEMPL_OPROTO_FIRST => (PortProto::IcmpOther((r - TEMPL_ICMP_ECHO) as u8), 0),
            r if r <= TEMPL_OPROTO_LAST => (PortProto::Oproto((r - TEMPL_OPROTO_FIRST) as u8), 0),
            _ => (PortProto::IcmpOther(u8::MAX), 0),
        }
    }
}

/// Что [`tokenize_ports`] делает с не-портом: на месте порта (мусор, пустой элемент) и после диапазона (не запятая).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PortListEnd {
    /// `--nmap-payloads`: как C (massip-rangesv4.c:1048-1050, :1084-1085), разбор молча останавливается, остаток
    /// строки разбирает вызывающий. У `O:` до 255 ограничено только начало диапазона, как в C (:1068).
    StopAtNonPort,
    /// `-p`: не-порт это `BadPort` (спека §4.1); у `O:` до 255 ограничены оба конца (Р2).
    Error,
}

/// massip-rangesv4.c:993 `rangelist_parse_ports`: один разборщик списка портов для `-p` ([`parse_ports_with`],
/// режим [`PortListEnd::Error`]) и `--nmap-payloads` ([`PortListEnd::StopAtNonPort`]), без префикса по умолчанию.
/// Возвращает пары с префиксными сдвигами и длину разобранной части `s`: место остановки или комментария `#`, иначе
/// вся строка. Формы, префиксы и проверки описаны у [`parse_ports_with`].
///
/// Отличия от C: значения больше 0xFFFF отвергаются без `(unsigned)`-усечения (оба режима, [`strtoul0`]); мусор на
/// месте порта и после диапазона C молча обрывает разбор, режим `Error` возвращает `BadPort`.
pub(crate) fn tokenize_ports(
    s: &[u8],
    end: PortListEnd,
) -> Result<(Vec<(u32, u32)>, usize), ParseError> {
    tokenize_ports_with(s, TEMPL_TCP, end)
}

/// [`tokenize_ports`] со сдвигом `default_offset` до первого явного префикса.
fn tokenize_ports_with(
    s: &[u8],
    default_offset: u32,
    end: PortListEnd,
) -> Result<(Vec<(u32, u32)>, usize), ParseError> {
    let stop = end == PortListEnd::StopAtNonPort;
    let mut rest = s;
    // :1005 `proto_offset` липкий: действует до следующего префикса.
    let mut offset = default_offset;
    let mut found: Vec<(u32, u32)> = Vec::new();

    loop {
        rest = skip_c_space(rest);
        if matches!(rest.first(), None | Some(b'#')) {
            break;
        }

        // :1016 — префикс протокола; неизвестная буква в C ошибка (:1034).
        if let [c @ (b'A'..=b'Z' | b'a'..=b'z'), b':', tail @ ..] = rest {
            offset = match c.to_ascii_uppercase() {
                b'T' => TEMPL_TCP,
                b'U' => TEMPL_UDP,
                b'S' => TEMPL_SCTP,
                b'O' => TEMPL_OPROTO_FIRST,
                b'I' => TEMPL_ICMP_ECHO,
                _ => return Err(ParseError::BadPort),
            };
            rest = tail;
        }
        let is_oproto = offset == TEMPL_OPROTO_FIRST;

        // :1044 начало диапазона; `-N` значит с порта 1.
        let port: u64 = match rest.first() {
            Some(b'-') => 1,
            Some(c) if c.is_ascii_digit() => {
                let (v, tail) = strtoul0(rest);
                rest = tail;
                v
            }
            // C (massip-rangesv4.c:1048-1050) молча обрывает разбор: "80 443",
            // "80,,81", "80;443", "08" дают {80}/{80}/{80}/{0}, ",80" и "T: 80"
            // — пусто. Для `-p` спека §4.1: ошибка, а не тихая потеря (ruling).
            _ if stop => break,
            _ => return Err(ParseError::BadPort),
        };

        // :1056 конец диапазона; `N-` значит до 65535 (у `O:` до 255).
        let last: u64 = if let Some(tail) = rest.strip_prefix(b"-") {
            rest = tail;
            if rest.first().is_some_and(u8::is_ascii_digit) {
                let (v, tail) = strtoul0(rest);
                rest = tail;
                v
            } else if is_oproto {
                0xFF
            } else {
                0xFFFF
            }
        } else {
            port
        };

        // :1067 проверка границ; у `O:` начало до 255 (:1068), у `-p` и конец (Р2).
        let port_limit = if is_oproto { 0xFF } else { 0xFFFF };
        let last_limit = if is_oproto && !stop { 0xFF } else { 0xFFFF };
        if port > port_limit || last > last_limit {
            return Err(ParseError::BadPort);
        }
        if last < port {
            return Err(ParseError::ReversedRange);
        }
        found.push((port as u32 + offset, last as u32 + offset));

        rest = skip_c_space(rest);
        match rest {
            [b',', tail @ ..] => rest = tail,
            // C (:1084-1085) просто выходит, если дальше не запятая; `#` там — комментарий.
            [] | [b'#', ..] => break,
            // Здесь C (:1084-1085) тоже просто выходит и теряет остаток
            // ("80- 90" -> 80-65535, "80 - 90" -> {80}, "80-90-100" -> 80-90); `-p`
            // возвращает ошибку (ruling).
            _ if stop => break,
            _ => return Err(ParseError::BadPort),
        }
    }
    Ok((found, s.len() - rest.len()))
}

/// massip-rangesv4.c:993 `rangelist_parse_ports` (через `massip_add_port_string`,
/// main-conf.c:2675). Формы: `80`, `1000-2000`, `-1024` (порты 1..=1024,
/// как в C: `port = 1`), `80-` (до 65535), список через запятую и липкие
/// префиксы `T:`/`U:`/`S:`/`I:`/`O:` любого регистра (:1016-1040): сдвиги
/// 0, 65536, 131072, 196608 и 196864 (`massip-port.h`). `default_offset` это
/// сдвиг до первого явного префикса (`-sU -p53`, main-conf.c:2670-2674).
///
/// Границы типа (спека Р2): TCP/UDP/SCTP до 65535, `O:` до 255 (в C :1068
/// ограничивает `O:` только по началу диапазона), для `I:` как в C до 65535:
/// `I:303` это тот же индекс, что `O:47`, и `--echo` печатает его именно так.
///
/// Отличия от C: там мусор на месте порта (`abc`, `80,,90`, `08`, `T:`)
/// молча обрывает разбор без ошибки, здесь это `BadPort`; значения больше
/// 0xFFFF отвергаются без `(unsigned)`-усечения. `#` по-прежнему начинает
/// комментарий. При ошибке `ports` не меняется. Обратный диапазон
/// (`end < begin`) — ошибка, как в C (:1067).
pub fn parse_ports_with(
    ports: &mut RangeList,
    s: &str,
    default_offset: u32,
) -> Result<(), ParseError> {
    let (found, _) = tokenize_ports_with(s.as_bytes(), default_offset, PortListEnd::Error)?;
    for (begin, end) in found {
        ports.add_range(begin, end);
    }
    Ok(())
}

/// `parse_ports_with` без префикса по умолчанию: порты TCP.
pub fn parse_ports(ports: &mut RangeList, s: &str) -> Result<(), ParseError> {
    parse_ports_with(ports, s, TEMPL_TCP)
}

/// main-conf.c:896 `config_top_ports`: первые `max` портов встроенных
/// таблиц ([`crate::top_ports`]) для включённых типов скана, затем сортировка.
/// Размер таблицы ограничивает `max` сверху (:1045, :1053).
pub fn add_top_ports(ports: &mut RangeList, max: u32, tcp: bool, udp: bool) {
    let max = max as usize;
    if tcp {
        for &p in crate::top_ports::TOP_TCP_PORTS.iter().take(max) {
            ports.add_range(TEMPL_TCP + u32::from(p), TEMPL_TCP + u32::from(p));
        }
    }
    if udp {
        for &p in crate::top_ports::TOP_UDP_PORTS.iter().take(max) {
            ports.add_range(TEMPL_UDP + u32::from(p), TEMPL_UDP + u32::from(p));
        }
    }
    ports.sort_and_merge();
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
        // massip-rangesv4.c:1250-1285
        for bad in ["75.748.86.91", "23.75.345.200", "192.1083.0.1", "0.0.0./0"] {
            assert!(range_parse_ipv4(bad).is_err(), "{bad}");
        }
        // Путь --range (автомат massip_parse_range). Селфтесты C:
        // massip-rangesv4.c:1250-1285; "0.0.0./0" C-автомат принимает как /0,
        // мы отвергаем (ruling).
        for bad in ["75.748.86.91", "23.75.345.200", "192.1083.0.1", "0.0.0./0"] {
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
        // C принимает эти формы (проверено на харнессе), мы отвергаем (ruling).
        for bad in [
            "1.2.3.",
            "0.0.0./0",
            "1.2.3.4/",
            "1.2.3.4/,5.6.7.8",
            "1.2.3.-1.2.3.4",
            "1.2.3.4-1.2.3.",
        ] {
            assert_eq!(one(bad), Err(ParseError::BadIpv4), "{bad}");
        }
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
    fn parse_ports_tcp_plain_lists() {
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
        // massip-rangesv4.c:1378-1381
        assert_eq!(
            p.get(2),
            Range {
                begin: 4444,
                end: 4444
            }
        );
        // U: больше не отклоняется (Р2), см. sticky_port_prefixes_and_oproto_live_refusal
        assert!(parse_ports(&mut RangeList::new(), "U:53").is_ok());
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
            "8a",
            "U:",
            "I:-x",
        ] {
            assert!(one(bad).is_err(), "{bad}");
        }
        // при ошибке список не меняется, даже если до неё были валидные префиксные порты
        let mut l = RangeList::new();
        assert!(parse_ports(&mut l, "80,U:53,O:256").is_err());
        assert!(l.is_empty());
    }

    #[test]
    fn port_garbage_rejected_where_c_truncates() {
        // C: {80}, {80}, 80-65535, {0}. Мы: ошибка (спека §4.1).
        for bad in ["80 443", "80,,81", "80- 90", "08"] {
            assert_eq!(
                parse_ports(&mut RangeList::new(), bad),
                Err(ParseError::BadPort),
                "{bad}"
            );
        }
    }

    #[test]
    fn malformed_octets_rejected() {
        for bad in [
            "1..2.3",
            "1.2..3",
            "1.1.1.1-.1.2.3",
            "1.1.1.1-1..2.3",
            ".1.2.3",
        ] {
            let mut l = RangeList::new();
            assert!(add_target_string(&mut l, bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn target_separators_and_host_bits() {
        for s in [
            "1.1.1.1\t2.2.2.2",
            "1.1.1.1\n2.2.2.2",
            "1.1.1.1\r2.2.2.2",
            "1.1.1.1\r\n2.2.2.2",
        ] {
            let mut l = RangeList::new();
            add_target_string(&mut l, s).unwrap();
            assert_eq!(l.len(), 2, "{s:?}");
        }
        let mut l = RangeList::new();
        add_target_string(&mut l, "10.0.1.2/16").unwrap();
        assert_eq!(
            l.as_slice(),
            &[Range {
                begin: 0x0a00_0000,
                end: 0x0a00_ffff
            }]
        );
    }

    #[test]
    fn proto_offsets() {
        assert_eq!(TEMPL_UDP, 65536);
        assert_eq!(TEMPL_SCTP, 131072);
        assert_eq!(TEMPL_ICMP_ECHO, 196608);
        assert_eq!(TEMPL_OPROTO_FIRST, 196608 + 256);
    }

    fn raw(s: &str) -> Vec<(u32, u32)> {
        let mut l = RangeList::new();
        parse_ports(&mut l, s).unwrap();
        l.as_slice().iter().map(|r| (r.begin, r.end)).collect()
    }

    #[test]
    fn sticky_port_prefixes_and_oproto_live_refusal() {
        // massip-rangesv4.c:1016-1040: префикс липкий до следующего префикса,
        // регистр не важен; сдвиги из massip-port.h:11-25.
        assert_eq!(
            raw("U:53,161,T:80-81,s:2905,I:0,o:47"),
            [
                (65589, 65589),
                (65697, 65697),
                (80, 81),
                (133_977, 133_977),
                (196_608, 196_608),
                (196_911, 196_911),
            ]
        );
        // липкость не сбрасывается запятой и пробелами
        assert_eq!(raw("U:1 , 2"), [(65537, 65538)]);
        // `U:-` и `U:80-` берут верхнюю границу 65535 (:1056-1061), `O:5-` до 255
        assert_eq!(raw("U:-"), [(65537, 65536 + 65535)]);
        assert_eq!(raw("S:65535"), [(131_072 + 65535, 131_072 + 65535)]);
        assert_eq!(raw("O:5-"), [(196_864 + 5, 196_864 + 255)]);
        assert_eq!(raw("O:255"), [(196_864 + 255, 196_864 + 255)]);
        // Р2: границы типа отклоняются (в C :1068 O:300 проходил)
        for bad in [
            "O:256",
            "O:5-256",
            "O:300",
            "U:65536",
            "T:65536",
            "S:65536",
            "U:1-65536",
            "I:65536",
            "k:80",
        ] {
            assert!(
                parse_ports(&mut RangeList::new(), bad).is_err(),
                "{bad} must be rejected"
            );
        }
        // при ошибке список не меняется
        let mut l = RangeList::new();
        assert!(parse_ports(&mut l, "U:53,O:256").is_err());
        assert!(l.is_empty());
    }

    #[test]
    fn parse_ports_with_default_prefix() {
        // main-conf.c:2670-2674: `-sU -p53` даёт U:53, явный `T:` сбрасывает
        let mut l = RangeList::new();
        parse_ports_with(&mut l, "53,T:80", TEMPL_UDP).unwrap();
        assert_eq!(
            l.as_slice().iter().map(|r| r.begin).collect::<Vec<_>>(),
            [65589, 80]
        );
    }

    #[test]
    fn port_proto_from_raw_splits_index() {
        use PortProto::*;
        assert_eq!(PortProto::from_raw(80), (Tcp, 80));
        assert_eq!(PortProto::from_raw(65535), (Tcp, 65535));
        assert_eq!(PortProto::from_raw(TEMPL_UDP), (Udp, 0));
        assert_eq!(PortProto::from_raw(TEMPL_UDP + 53), (Udp, 53));
        assert_eq!(PortProto::from_raw(TEMPL_UDP_LAST), (Udp, 65535));
        assert_eq!(PortProto::from_raw(TEMPL_SCTP + 2905), (Sctp, 2905));
        assert_eq!(PortProto::from_raw(TEMPL_SCTP_LAST), (Sctp, 65535));
        assert_eq!(PortProto::from_raw(TEMPL_ICMP_ECHO), (IcmpEcho, 0));
        assert_eq!(PortProto::from_raw(TEMPL_ICMP_TIMESTAMP), (IcmpOther(1), 0));
        assert_eq!(PortProto::from_raw(TEMPL_ARP), (Arp, 0));
        assert_eq!(PortProto::from_raw(TEMPL_ICMP_ECHO + 3), (IcmpOther(3), 0));
        assert_eq!(
            PortProto::from_raw(TEMPL_ICMP_ECHO + 255),
            (IcmpOther(255), 0)
        );
        assert_eq!(PortProto::from_raw(TEMPL_OPROTO_FIRST), (Oproto(0), 0));
        assert_eq!(
            PortProto::from_raw(TEMPL_OPROTO_FIRST + 47),
            (Oproto(47), 0)
        );
        assert_eq!(PortProto::from_raw(TEMPL_OPROTO_LAST), (Oproto(255), 0));
    }

    #[test]
    fn top_ports_follow_the_c_tables() {
        use crate::top_ports::{TOP_TCP_PORTS, TOP_UDP_PORTS};
        // main-conf.c:934-1037 и :899-932: размеры и первые значения
        assert_eq!(TOP_TCP_PORTS.len(), 1008);
        assert_eq!(TOP_UDP_PORTS.len(), 31);
        assert_eq!(&TOP_TCP_PORTS[..5], [80, 443, 8080, 21, 990]);
        assert_eq!(&TOP_UDP_PORTS[..5], [161, 135, 500, 137, 138]);
        let list = |n, tcp, udp| {
            let mut l = RangeList::new();
            add_top_ports(&mut l, n, tcp, udp);
            l.as_slice()
                .iter()
                .map(|r| (r.begin, r.end))
                .collect::<Vec<_>>()
        };
        // main-conf.c:1043-1058: только TCP, только UDP, оба; список отсортирован
        assert_eq!(
            list(5, true, false),
            [(21, 21), (80, 80), (443, 443), (990, 990), (8080, 8080)]
        );
        assert_eq!(
            list(5, false, true),
            [
                (65536 + 135, 65536 + 135),
                (65536 + 137, 65536 + 138),
                (65536 + 161, 65536 + 161),
                (65536 + 500, 65536 + 500),
            ]
        );
        let both = list(5, true, true);
        assert_eq!(both.len(), 5 + 4);
        assert_eq!(both[0], (21, 21));
        assert_eq!(both[8], (65536 + 500, 65536 + 500));
        // N больше таблицы режется по длине таблицы (:1045, :1053)
        let mut all = RangeList::new();
        add_top_ports(&mut all, 100_000, false, true);
        assert_eq!(all.count(), 31);
        // N = 0 ничего не добавляет
        assert!(list(0, true, true).is_empty());
    }
    /// massip.c:72-100 `massip_add_target_string` with the IPv6 branch
    /// (`range6list_add_range`, :89).
    #[test]
    fn add_target_string_v46_splits_families() {
        use crate::ranges6::{Ipv6Range, Range6List};
        let mut v4 = RangeList::new();
        let mut v6 = Range6List::new();
        add_target_string_v46(
            &mut v4,
            &mut v6,
            "10.0.0.1,fd00::/126 [::1]-[::3]\t192.168.0.0/30",
        )
        .unwrap();
        assert_eq!(v4.len(), 2);
        assert_eq!(
            v4.get(0),
            Range {
                begin: 0x0a00_0001,
                end: 0x0a00_0001
            }
        );
        assert_eq!(
            v4.get(1),
            Range {
                begin: 0xc0a8_0000,
                end: 0xc0a8_0003
            }
        );
        let fd = 0xfd00u128 << 112;
        assert_eq!(
            v6.as_slice(),
            &[
                Ipv6Range {
                    begin: fd,
                    end: fd + 3
                },
                Ipv6Range { begin: 1, end: 3 }
            ]
        );
    }

    /// Mixed-family string with a bad token: all or nothing, in both lists,
    /// like `add_target_string` (the C code keeps the part parsed before the
    /// error, we do not).
    #[test]
    fn add_target_string_v46_is_atomic() {
        use crate::ranges6::Range6List;
        let mut v4 = RangeList::new();
        let mut v6 = Range6List::new();
        for bad in [
            "10.0.0.1,::1,zz",
            "::1,1.2.3.4-::1",
            "1::2::3",
            "::2-::1",
            "10.0.0.1,::1/129",
        ] {
            assert!(
                add_target_string_v46(&mut v4, &mut v6, bad).is_err(),
                "{bad}"
            );
            assert!(v4.is_empty() && v6.is_empty(), "{bad}");
        }
        assert_eq!(
            add_target_string_v46(&mut v4, &mut v6, "::2-::1"),
            Err(ParseError::ReversedRange)
        );
        assert_eq!(
            add_target_string_v46(&mut v4, &mut v6, "1::2::3"),
            Err(ParseError::BadIpv6)
        );
    }

    /// IPv4-only strings behave exactly as `add_target_string`, including its
    /// error values (IPv4 behaviour is frozen).
    #[test]
    fn add_target_string_v46_matches_v4_on_v4_input() {
        use crate::ranges6::Range6List;
        for s in [
            "1.2.3.4",
            "10.0.0.0/8,192.168.1.1-192.168.1.9",
            " 1.2.3.4, ",
            "",
            "  ",
            ",1.2.3.4",
            "1.2.3.4-1.2.3.3",
            "1.2.3",
            "256.1.1.1",
            "1.2.3.4:80",
            "#c\n5.6.7.8",
        ] {
            let mut a = RangeList::new();
            let mut b = RangeList::new();
            let mut v6 = Range6List::new();
            let ra = add_target_string(&mut a, s);
            let rb = add_target_string_v46(&mut b, &mut v6, s);
            assert_eq!(ra, rb, "{s:?}");
            assert_eq!(a.as_slice(), b.as_slice(), "{s:?}");
            assert!(v6.is_empty(), "{s:?}");
        }
    }

    use proptest::prelude::*;

    /// Пробелы C вокруг запятой (в том числе `\v` и `\f`).
    const PORT_GAPS: [&str; 7] = ["", " ", "\t", "\x0b", "\x0c", "\r", "\n"];

    /// Число в записи `strtoul(.., 0)`: десятичной, восьмеричной с ведущим `0` или шестнадцатеричной с `0x`/`0X`.
    fn c_number(v: u32, radix: u8) -> String {
        match radix {
            0 => format!("{v}"),
            1 => format!("0{v:o}"),
            2 => format!("0x{v:x}"),
            _ => format!("0X{v:X}"),
        }
    }

    /// Строка только из портов и ожидаемые пары: липкие префиксы `T:`/`U:`/`S:`/`I:`/`O:` любого регистра, формы
    /// `a`, `a-b`, `-b`, `a-` и `-`, числа в любой записи `strtoul0`, пробелы C вокруг запятых и по краям, иногда
    /// хвостовая запятая. Значения в границах типа (у `O:` до 255), диапазоны не обратные.
    fn port_only_list() -> impl Strategy<Value = (String, Vec<(u32, u32)>)> {
        const PREFIXES: [&str; 10] = ["T:", "t:", "U:", "u:", "S:", "s:", "I:", "i:", "O:", "o:"];
        let item = (
            proptest::option::weighted(0.4, proptest::sample::select(&PREFIXES[..])),
            0u32..=0xFFFF,
            0u32..=0xFFFF,
            0u8..5,
            0u8..4,
            0u8..4,
            proptest::sample::select(&PORT_GAPS[..]),
            proptest::sample::select(&PORT_GAPS[..]),
        );
        (
            proptest::collection::vec(item, 1..8),
            proptest::sample::select(&PORT_GAPS[..]),
            any::<bool>(),
        )
            .prop_map(|(items, edge, trailing_comma)| {
                let mut s = String::from(edge);
                let mut want = Vec::new();
                let mut offset = TEMPL_TCP;
                for (k, (prefix, a, b, form, ra, rb, before, after)) in
                    items.into_iter().enumerate()
                {
                    if k > 0 {
                        s.push_str(before);
                        s.push(',');
                        s.push_str(after);
                    }
                    if let Some(p) = prefix {
                        s.push_str(p);
                        offset = match p.as_bytes()[0].to_ascii_uppercase() {
                            b'T' => TEMPL_TCP,
                            b'U' => TEMPL_UDP,
                            b'S' => TEMPL_SCTP,
                            b'I' => TEMPL_ICMP_ECHO,
                            _ => TEMPL_OPROTO_FIRST,
                        };
                    }
                    let max = if offset == TEMPL_OPROTO_FIRST {
                        0xFF
                    } else {
                        0xFFFF
                    };
                    let (a, b) = (a % (max + 1), b % (max + 1));
                    let (lo, hi) = (a.min(b), a.max(b));
                    let (begin, end) = match form {
                        0 => {
                            s.push_str(&c_number(lo, ra));
                            (lo, lo)
                        }
                        1 => {
                            s.push_str(&format!("{}-{}", c_number(lo, ra), c_number(hi, rb)));
                            (lo, hi)
                        }
                        2 => {
                            let hi = hi.max(1);
                            s.push_str(&format!("-{}", c_number(hi, rb)));
                            (1, hi)
                        }
                        3 => {
                            s.push_str(&format!("{}-", c_number(lo, ra)));
                            (lo, max)
                        }
                        _ => {
                            s.push('-');
                            (1, max)
                        }
                    };
                    want.push((begin + offset, end + offset));
                }
                if trailing_comma {
                    s.push(',');
                }
                s.push_str(edge);
                (s, want)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 5000,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// На строке только из портов оба режима разборщика дают одни и те же пары, читают строку целиком и
        /// совпадают с ожидаемыми парами генератора.
        #[test]
        fn tokenize_ports_modes_agree_on_ports((s, want) in port_only_list()) {
            let stop = tokenize_ports(s.as_bytes(), PortListEnd::StopAtNonPort);
            let error = tokenize_ports(s.as_bytes(), PortListEnd::Error);
            prop_assert_eq!(&stop, &error, "{:?}", s);
            prop_assert_eq!(stop, Ok((want, s.len())), "{:?}", s);
        }
    }

    /// Оба документированных отличия от C (см. [`parse_ports_with`]) в обоих режимах разборщика.
    #[test]
    fn tokenize_ports_keeps_both_c_differences() {
        use PortListEnd::{Error, StopAtNonPort};
        // 1. Мусор на месте порта или после диапазона: C молча обрывает разбор, `StopAtNonPort` тоже (пары и длина
        //    разобранного как у C), `Error` отказывает.
        type Stop = (&'static str, &'static [(u32, u32)], usize);
        let garbage: [Stop; 8] = [
            ("80 443", &[(80, 80)], 3),
            ("80,,81", &[(80, 80)], 3),
            ("80;443", &[(80, 80)], 2),
            ("08", &[(0, 0)], 1),
            (",80", &[], 0),
            ("T: 80", &[], 2),
            ("80- 90", &[(80, 65535)], 4),
            ("80-90-100", &[(80, 90)], 5),
        ];
        for (s, pairs, used) in garbage {
            assert_eq!(
                tokenize_ports(s.as_bytes(), StopAtNonPort),
                Ok((pairs.to_vec(), used)),
                "{s:?}"
            );
            assert_eq!(
                tokenize_ports(s.as_bytes(), Error),
                Err(ParseError::BadPort),
                "{s:?}"
            );
        }
        // 2. Больше 0xFFFF без `(unsigned)`-усечения: C принимает эти строки как 80, 80-80, U:0 и 80.
        for s in ["4294967376", "80-4294967376", "U:4294967296", "0x100000050"] {
            assert!(
                tokenize_ports(s.as_bytes(), StopAtNonPort).is_err(),
                "{s:?}"
            );
            assert_eq!(
                tokenize_ports(s.as_bytes(), Error),
                Err(ParseError::BadPort),
                "{s:?}"
            );
        }
    }

    /// Копия базы (`a275ea9e`) дословно, кроме видимости `pub(super)`: `parse_ipv4`, `range_parse_ipv4`, `not_ipv4`,
    /// `parse_range_at`, `add_target_string`, `add_target_string_v46`, `strtoul0` и `parse_ports_with` с курсором
    /// `usize` (targets.rs:44-592) и `parse_ports_prefix` из payloads.rs:1040-1094. `St`, `apply_cidr` и
    /// `parse_ipv6_range_at` общие: задача их не меняет. Эталон `*_match_old_*`.
    mod old {
        use super::super::*;

        pub(super) fn parse_ipv4(line: &[u8], mut offset: usize) -> Option<(u32, usize)> {
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

        pub(super) fn range_parse_ipv4(line: &str) -> Result<Range, ParseError> {
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
                // C (massip-rangesv4.c:621-627) тоже отвергает обратный диапазон.
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

        pub(super) fn not_ipv4(buf: &[u8], tok_start: usize) -> ParseError {
            let tok = buf[tok_start..]
                .iter()
                .take_while(|&&c| !is_c_space(c) && c != b',');
            if tok.clone().any(|&c| c == b':') {
                ParseError::Ipv6NotSupported
            } else {
                ParseError::BadIpv4
            }
        }

        pub(super) fn parse_range_at(buf: &[u8], offset: &mut usize) -> Result<Range, ParseError> {
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
                                // Пустой октет ("1..2.3" C читает как 1.0.2.3, "x-.1.2.3"
                                // аналогично) — опечатка, отвергаем (ruling), как и
                                // хвостовую точку; C: massip-parse.c:608-620 не смотрит digit_count.
                                if digits == 0 {
                                    return Err(ParseError::BadIpv4);
                                }
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
                                if first && k == 3 && digits > 0 {
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
                                if first && k == 3 && digits > 0 {
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
                                // C принимает "1.2.3." как 1.2.3.0 (massip-parse.c:658-703:
                                // NUMBER3 без проверки digit_count); malformed, отвергаем (ruling).
                                if k != 3 || digits == 0 {
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
                        // C принимает "a.b.c.d/" без цифр как /0, т.е. всё пространство IPv4
                        // (massip-parse.c:538 IPV4_CIDR_NUM не проверяет digit_count).
                        // Это опечатка, а не намерение: отвергаем (ruling).
                        b':' | b',' | b' ' | b'\t' | b'\r' | b'\n' => {
                            if digits == 0 {
                                return Err(ParseError::BadIpv4);
                            }
                            *offset = consumed;
                            return Ok(apply_cidr(begin, tmp));
                        }
                        _ => return Err(ParseError::BadIpv4),
                    },
                }
            }
        }

        pub(super) fn add_target_string(
            targets: &mut RangeList,
            s: &str,
        ) -> Result<(), ParseError> {
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

        pub(super) fn add_target_string_v46(
            ipv4: &mut RangeList,
            ipv6: &mut Range6List,
            s: &str,
        ) -> Result<(), ParseError> {
            let buf = s.as_bytes();
            let mut offset = 0;
            let mut found4 = Vec::new();
            let mut found6 = Vec::new();
            while offset < buf.len() {
                match parse_range_at(buf, &mut offset) {
                    Ok(r) => found4.push(r),
                    Err(ParseError::Ipv6NotSupported) => {
                        found6.push(parse_ipv6_range_at(buf, &mut offset)?)
                    }
                    Err(e) => return Err(e),
                }
                while offset < buf.len() && (is_c_space(buf[offset]) || buf[offset] == b',') {
                    offset += 1;
                }
            }
            for r in found4 {
                ipv4.add_range(r.begin, r.end);
            }
            for r in found6 {
                ipv6.add(r.begin, r.end);
            }
            Ok(())
        }

        pub(super) fn strtoul0(s: &[u8], pos: &mut usize) -> u64 {
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

        pub(super) fn parse_ports_with(
            ports: &mut RangeList,
            s: &str,
            default_offset: u32,
        ) -> Result<(), ParseError> {
            let b = s.as_bytes();
            let mut p = 0;
            // :1005 `proto_offset` липкий: действует до следующего префикса.
            let mut offset = default_offset;
            let mut found: Vec<(u32, u32)> = Vec::new();

            while p < b.len() {
                while p < b.len() && is_c_space(b[p]) {
                    p += 1;
                }
                if p >= b.len() || b[p] == b'#' {
                    break;
                }

                // :1016 — префикс протокола; неизвестная буква в C ошибка (:1034).
                if b[p].is_ascii_alphabetic() && b.get(p + 1) == Some(&b':') {
                    offset = match b[p] {
                        b'T' | b't' => TEMPL_TCP,
                        b'U' | b'u' => TEMPL_UDP,
                        b'S' | b's' => TEMPL_SCTP,
                        b'O' | b'o' => TEMPL_OPROTO_FIRST,
                        b'I' | b'i' => TEMPL_ICMP_ECHO,
                        _ => return Err(ParseError::BadPort),
                    };
                    p += 2;
                }
                let is_oproto = offset == TEMPL_OPROTO_FIRST;

                // :1044 начало диапазона; `-N` значит с порта 1.
                let port: u64 = match b.get(p) {
                    Some(b'-') => 1,
                    Some(c) if c.is_ascii_digit() => strtoul0(b, &mut p),
                    // C (massip-rangesv4.c:1048-1050) молча обрывает разбор: "80 443",
                    // "80,,81", "80;443", "08" дают {80}/{80}/{80}/{0}, ",80" и "T: 80"
                    // — пусто. Спека §4.1: ошибка, а не тихая потеря (ruling).
                    _ => return Err(ParseError::BadPort),
                };

                // :1056 конец диапазона; `N-` значит до 65535 (у `O:` до 255).
                let end: u64 = if b.get(p) == Some(&b'-') {
                    p += 1;
                    if b.get(p).is_some_and(u8::is_ascii_digit) {
                        strtoul0(b, &mut p)
                    } else if is_oproto {
                        0xFF
                    } else {
                        0xFFFF
                    }
                } else {
                    port
                };

                // :1067 проверка границ; у `O:` верхняя граница 255 (Р2).
                let limit = if is_oproto { 0xFF } else { 0xFFFF };
                if port > limit || end > limit {
                    return Err(ParseError::BadPort);
                }
                if end < port {
                    return Err(ParseError::ReversedRange);
                }
                found.push((port as u32 + offset, end as u32 + offset));

                while p < b.len() && is_c_space(b[p]) {
                    p += 1;
                }
                if p >= b.len() {
                    break;
                }
                // C (:1084-1085) просто выходит, если дальше не запятая; `#` там — комментарий.
                if b[p] == b'#' {
                    break;
                }
                // Здесь C (:1084-1085) тоже просто выходит и теряет остаток
                // ("80- 90" -> 80-65535, "80 - 90" -> {80}, "80-90-100" -> 80-90); мы
                // возвращаем ошибку (ruling).
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

        pub(super) fn parse_ports_prefix(s: &[u8]) -> Result<(Vec<(u32, u32)>, usize), ()> {
            use crate::targets::{
                TEMPL_ICMP_ECHO, TEMPL_OPROTO_FIRST, TEMPL_SCTP, TEMPL_TCP, TEMPL_UDP,
            };
            let mut p = 0;
            let mut offset = TEMPL_TCP;
            let mut out = Vec::new();
            while p < s.len() {
                while p < s.len() && is_c_space(s[p]) {
                    p += 1;
                }
                if p >= s.len() || s[p] == b'#' {
                    break;
                }
                if s[p].is_ascii_alphabetic() && s.get(p + 1) == Some(&b':') {
                    offset = match s[p] {
                        b'T' | b't' => TEMPL_TCP,
                        b'U' | b'u' => TEMPL_UDP,
                        b'S' | b's' => TEMPL_SCTP,
                        b'O' | b'o' => TEMPL_OPROTO_FIRST,
                        b'I' | b'i' => TEMPL_ICMP_ECHO,
                        _ => return Err(()),
                    };
                    p += 2;
                }
                let port = match s.get(p) {
                    Some(b'-') => 1,
                    Some(c) if c.is_ascii_digit() => strtoul0(s, &mut p),
                    _ => break,
                };
                let is_oproto = offset == TEMPL_OPROTO_FIRST;
                let end = if s.get(p) == Some(&b'-') {
                    p += 1;
                    if s.get(p).is_some_and(u8::is_ascii_digit) {
                        strtoul0(s, &mut p)
                    } else if is_oproto {
                        0xFF
                    } else {
                        0xFFFF
                    }
                } else {
                    port
                };
                if (port > 0xFF && is_oproto) || port > 0xFFFF || end > 0xFFFF || end < port {
                    return Err(());
                }
                out.push((port as u32 + offset, end as u32 + offset));
                while p < s.len() && is_c_space(s[p]) {
                    p += 1;
                }
                if s.get(p) != Some(&b',') {
                    break;
                }
                p += 1;
            }
            Ok((out, p))
        }
    }

    /// Токены почти правильных строк целей и портов: цифры (с ведущими нулями, hex, переполнением `u32` и `u64`),
    /// адреса, CIDR, `-`, `,`, `/`, `.`, все пробелы C, префиксы портов, комментарии, признаки IPv6, байты
    /// юникодного дефиса U+2013 и его обрывки.
    const NEAR_VALID: [&[u8]; 66] = [
        b"0",
        b"1",
        b"7",
        b"00",
        b"08",
        b"010",
        b"80",
        b"255",
        b"256",
        b"999",
        b"0001",
        b"65535",
        b"65536",
        b"0x50",
        b"0X1f",
        b"0x",
        b"0xg",
        b"4294967376",
        b"99999999999999999999",
        b"18446744073709551616",
        b"1.2.3.4",
        b"10.0.0.0",
        b"0.0.0.0",
        b"255.255.255.255",
        b"1.2.3",
        b"/",
        b"/0",
        b"/8",
        b"/24",
        b"/32",
        b"/33",
        b"/007",
        b"-",
        b",",
        b".",
        b" ",
        b"\t",
        b"\n",
        b"\r",
        b"\x0b",
        b"\x0c",
        b"U:",
        b"T:",
        b"S:",
        b"O:",
        b"I:",
        b"u:",
        b"o:",
        b"k:",
        b"#",
        b";",
        b":",
        b"::",
        b"::1",
        b"[",
        b"]",
        b"a",
        b"f",
        b"x",
        b"g",
        b"\xe2\x80\x93",
        b"\xe2\x80",
        b"\xe2",
        b"\x96",
        b"\x80",
        b"\xff",
    ];

    /// Склейка 0–11 токенов [`NEAR_VALID`] с хвостовым мусорным байтом.
    fn token_soup() -> impl Strategy<Value = Vec<u8>> {
        (
            proptest::collection::vec(proptest::sample::select(&NEAR_VALID[..]), 0..12),
            proptest::option::of(any::<u8>()),
        )
            .prop_map(|(tokens, junk)| {
                let mut s = tokens.concat();
                s.extend(junk);
                s
            })
    }

    /// С вероятностью 1/3 вставляет в `s` токен [`NEAR_VALID`] или случайный байт в случайном месте.
    fn with_insertion(s: impl Strategy<Value = Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
        let insert = prop_oneof![
            proptest::sample::select(&NEAR_VALID[..]).prop_map(<[u8]>::to_vec),
            any::<u8>().prop_map(|b| vec![b]),
        ];
        (
            s,
            proptest::option::weighted(0.33, (any::<proptest::sample::Index>(), insert)),
        )
            .prop_map(|(mut s, insert)| {
                if let Some((at, bytes)) = insert {
                    let at = at.index(s.len() + 1);
                    s.splice(at..at, bytes);
                }
                s
            })
    }

    /// Адрес `v` текстом. `forms` по октету: 0–59 десятичное число, 60 три цифры с ведущими нулями, 61 четыре цифры
    /// (`0` и три цифры), 62 `256`, 63 пустой октет; 64 и больше у четвёртого октета отбрасывают его (`1.2.3`), у
    /// третьего добавляют пятый октет (`1.2.3.4.5`).
    fn ipv4_text(v: u32, forms: [u8; 4]) -> Vec<u8> {
        let mut parts = Vec::new();
        for (k, &f) in forms.iter().enumerate() {
            let o = (v >> (24 - 8 * k)) & 0xFF;
            match f {
                0..=59 => parts.push(format!("{o}")),
                60 => parts.push(format!("{o:03}")),
                61 => parts.push(format!("0{o:03}")),
                62 => parts.push("256".to_string()),
                63 => parts.push(String::new()),
                _ if k == 3 => {}
                _ if k == 2 => parts.extend([format!("{o}"), "5".to_string()]),
                _ => parts.push(format!("{o}")),
            }
        }
        parts.join(".").into_bytes()
    }

    /// Список целей, близкий к правильному: адреса (иногда с испорченным октетом, см. [`ipv4_text`]), `/N`,
    /// диапазоны через `-`, U+2013, `\x96` и U+2017 (не дефис), в трёх случаях из четырёх по возрастанию; токены
    /// IPv6, разделители C и комментарии между элементами.
    fn target_list() -> impl Strategy<Value = Vec<u8>> {
        const V6: [&str; 7] = [
            "::1",
            "fd00::/126",
            "[::1]",
            "2001:db8::1-2001:db8::3",
            "::2-::1",
            "1::2::3",
            "a:",
        ];
        const SEPARATORS: [&str; 10] = [",", " ", "\t", ", ", "\n", ",,", " ,", "#c\n", "\x0b", ""];
        const DASHES: [&[u8]; 4] = [b"-", b"\xe2\x80\x93", b"\x96", b"\xe2\x80\x97"];
        let forms = || {
            prop_oneof![
                12 => Just([0u8; 4]),
                1 => any::<[u8; 4]>().prop_map(|f| f.map(|b| b % 66)),
            ]
        };
        let addr = (any::<u32>(), forms()).prop_map(|(v, f)| ipv4_text(v, f));
        let cidr = prop_oneof![
            8 => (0u32..=32).prop_map(|n| format!("/{n}").into_bytes()),
            1 => proptest::sample::select(&["/", "/33", "/007", "/100"][..])
                .prop_map(|c| c.as_bytes().to_vec()),
        ];
        let range = (
            any::<u32>(),
            any::<u32>(),
            proptest::bool::weighted(0.25),
            forms(),
            forms(),
            prop_oneof![6 => Just(DASHES[0]), 1 => proptest::sample::select(&DASHES[..])],
        )
            .prop_map(|(a, b, reversed, fa, fb, dash)| {
                let (a, b) = if reversed {
                    (a.max(b), a.min(b))
                } else {
                    (a.min(b), a.max(b))
                };
                [ipv4_text(a, fa), dash.to_vec(), ipv4_text(b, fb)].concat()
            });
        let item = prop_oneof![
            4 => addr.clone(),
            2 => (addr, cidr).prop_map(|(a, c)| [a, c].concat()),
            3 => range,
            1 => proptest::sample::select(&V6[..]).prop_map(|t| t.as_bytes().to_vec()),
        ];
        let separator = prop_oneof![
            10 => proptest::sample::select(&SEPARATORS[..6]),
            1 => proptest::sample::select(&SEPARATORS[..]),
        ];
        proptest::collection::vec((item, separator), 1..5).prop_map(|items| {
            let mut s = Vec::new();
            for (k, (item, sep)) in items.into_iter().enumerate() {
                if k > 0 {
                    s.extend_from_slice(sep.as_bytes());
                }
                s.extend(item);
            }
            s
        })
    }

    /// Входы дифференциала целей: случайные байты, [`token_soup`] и [`target_list`] со вставкой мусора.
    fn target_input() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => proptest::collection::vec(any::<u8>(), 0..40),
            1 => token_soup(),
            3 => with_insertion(target_list()),
        ]
    }

    /// Входы дифференциала портов: случайные байты, [`token_soup`] и [`port_only_list`] со вставкой мусора.
    fn port_input() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            1 => proptest::collection::vec(any::<u8>(), 0..40),
            1 => token_soup(),
            3 => with_insertion(port_only_list().prop_map(|(s, _)| s.into_bytes())),
        ]
    }

    /// Сдвиги до первого префикса для `parse_ports_with`: все префиксы и не префикс.
    const DEFAULT_OFFSETS: [u32; 6] = [
        TEMPL_TCP,
        TEMPL_UDP,
        TEMPL_SCTP,
        TEMPL_ICMP_ECHO,
        TEMPL_OPROTO_FIRST,
        7,
    ];

    /// Разборщики целей на срезах против копий базы на каждом суффиксе `s`: значение, остаток (как смещение
    /// `s.len() - rest.len()`) и ошибка; при ошибке `parse_range_at` позиция остаётся в начале суффикса, с которой
    /// `add_target_string_v46` разбирает IPv6. Строковые функции целиком: результат и списки.
    fn targets_match_old(s: &[u8]) {
        for o in 0..=s.len() {
            let tail = &s[o..];
            let new = parse_ipv4(tail).map(|(v, rest)| (v, s.len() - rest.len()));
            assert_eq!(new, old::parse_ipv4(s, o), "parse_ipv4 {s:02x?} at {o}");

            let mut off = o;
            let want = old::parse_range_at(s, &mut off).map(|r| (r, off));
            let got = parse_range_at(tail).map(|(r, rest)| (r, s.len() - rest.len()));
            assert_eq!(got, want, "parse_range_at {s:02x?} at {o}");
            assert_eq!(off, got.map_or(o, |(_, at)| at), "position {s:02x?} at {o}");

            if tail.first().is_some_and(u8::is_ascii_digit) {
                let mut pos = o;
                let want = old::strtoul0(s, &mut pos);
                let (v, rest) = strtoul0(tail);
                assert_eq!(
                    (v, s.len() - rest.len()),
                    (want, pos),
                    "strtoul0 {s:02x?} at {o}"
                );
            }

            let t = String::from_utf8_lossy(tail);
            assert_eq!(range_parse_ipv4(&t), old::range_parse_ipv4(&t), "{t:?}");
            let (mut a, mut b) = (RangeList::new(), RangeList::new());
            assert_eq!(
                add_target_string(&mut a, &t),
                old::add_target_string(&mut b, &t),
                "{t:?}"
            );
            assert_eq!(a.as_slice(), b.as_slice(), "{t:?}");
            let (mut a4, mut b4) = (RangeList::new(), RangeList::new());
            let (mut a6, mut b6) = (Range6List::new(), Range6List::new());
            assert_eq!(
                add_target_string_v46(&mut a4, &mut a6, &t),
                old::add_target_string_v46(&mut b4, &mut b6, &t),
                "{t:?}"
            );
            assert_eq!(a4.as_slice(), b4.as_slice(), "{t:?}");
            assert_eq!(a6.as_slice(), b6.as_slice(), "{t:?}");
        }
    }

    /// Разборщик портов против копий базы на каждом суффиксе `s`: `StopAtNonPort` против `parse_ports_prefix` (пары,
    /// длина разобранного, отказ), `Error` против `-p` базы (пары в порядке добавления и ошибка), `parse_ports_with`
    /// при каждом сдвиге из [`DEFAULT_OFFSETS`].
    fn ports_match_old(s: &[u8]) {
        for o in 0..=s.len() {
            let tail = &s[o..];
            assert_eq!(
                tokenize_ports(tail, PortListEnd::StopAtNonPort).map_err(|_| ()),
                old::parse_ports_prefix(tail),
                "StopAtNonPort {tail:02x?}"
            );

            let t = String::from_utf8_lossy(tail);
            let mut want = RangeList::new();
            let old_p = old::parse_ports_with(&mut want, &t, TEMPL_TCP);
            match tokenize_ports(t.as_bytes(), PortListEnd::Error) {
                Ok((pairs, used)) => {
                    assert_eq!(old_p, Ok(()), "{t:?}");
                    let mut got = RangeList::new();
                    for (b, e) in pairs {
                        got.add_range(b, e);
                    }
                    assert_eq!(got.as_slice(), want.as_slice(), "{t:?}");
                    assert!(
                        used == t.len() || t.as_bytes()[used] == b'#',
                        "Error stops at end or '#': {t:?} at {used}"
                    );
                }
                Err(e) => assert_eq!(old_p, Err(e), "{t:?}"),
            }
            for d in DEFAULT_OFFSETS {
                let (mut a, mut b) = (RangeList::new(), RangeList::new());
                assert_eq!(
                    parse_ports_with(&mut a, &t, d),
                    old::parse_ports_with(&mut b, &t, d),
                    "{t:?} default {d}"
                );
                assert_eq!(a.as_slice(), b.as_slice(), "{t:?} default {d}");
            }
        }
    }

    /// Случаев на каждый дифференциал; каждый случай проверяет все суффиксы входа.
    const OLD_PARSER_CASES: u32 = 20_000;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: OLD_PARSER_CASES,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        /// Разборщики целей на срезах равны копиям базы на случайных байтах и почти правильных строках.
        #[test]
        fn target_parsers_match_old(s in target_input()) {
            targets_match_old(&s);
        }

        /// Один разборщик портов в обоих режимах равен двум разборщикам базы на тех же входах.
        #[test]
        fn port_parsers_match_old(s in port_input()) {
            ports_match_old(&s);
        }
    }

    /// Все строки длиной до 4 над алфавитами из 16 байт (69 905 строк на алфавит): короткие сочетания
    /// разделителей, префиксов, точек и цифр, которые случайный генератор может обойти.
    #[test]
    fn short_strings_match_old_exhaustively() {
        const TARGET_BYTES: &[u8; 16] = b"012.-/:, \x0ba#\n\xe2\x80\x93";
        const PORT_BYTES: &[u8; 16] = b"0189x-, \x0b#U:Ok5\t";
        for (alphabet, check) in [
            (TARGET_BYTES, targets_match_old as fn(&[u8])),
            (PORT_BYTES, ports_match_old),
        ] {
            let mut n = 0;
            for len in 0..=4u32 {
                for code in 0..16usize.pow(len) {
                    let s: Vec<u8> = (0..len)
                        .map(|k| alphabet[code / 16usize.pow(k) % 16])
                        .collect();
                    check(&s);
                    n += 1;
                }
            }
            assert_eq!(n, 69_905);
        }
    }
}
