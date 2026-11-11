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

/// C `strtoul(p, &p, 0)` для строки, начинающейся с цифры: `0x` — hex,
/// ведущий `0` — восьмеричное, иначе десятичное. Переполнение даёт
/// `u64::MAX` (в C затем `(unsigned)`-усечение, которое мы не повторяем).
pub(crate) fn strtoul0(s: &[u8], pos: &mut usize) -> u64 {
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
}
