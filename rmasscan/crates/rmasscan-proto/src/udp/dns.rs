//! DNS, порт 53 (`src/proto-dns.c`), и разбор DNS, общий с NBNS (`proto_dns_parse`, `dns_name_skip`).
//!
//! Смещения считаются от начала датаграммы, у C от начала кадра (`proto_dns_parse(dns, px, app_offset, ...)`,
//! `src/proto-dns.c:371`). Отличия от C (README эталонов, Р2):
//! - указатель сжатия адресует сообщение DNS, у C кадр (`src/proto-dns.c:69`): у C проверка имени зависит от байтов
//!   канального и IP-заголовков (класс а: чтение за пределами датаграммы, класс в: канал, семейство, VLAN и адреса).
//!   В Ethernet + IPv6 и с тегом 802.1Q обычный `c0 0c` у C всегда ошибка, и сжатый ответ даёт только сырой баннер;
//!   в Ethernet + IPv4 проходит случайно (`super` и README эталонов);
//! - TXT читается против длины датаграммы, у C против длины кадра (`src/proto-dns.c:420-434`): хвост кадра за
//!   IP-датаграммой (FCS) у C попадает в текст;
//! - датаграмма короче 12 байт не совпадает с cookie: у C `id` не инициализирован (`src/proto-dns.c:205-206`);
//! - меньше двух записей: сырой баннер; у C `rr_offset[1]` не инициализирован (`src/proto-dns.c:419`);
//! - `dns_extract_name` (`src/proto-dns.c:140-170, 317-318`) не переносится: результат не читается, а у ответа без
//!   записей C читает неинициализированный `rr_offset[0]` (ASan: чтение за буфером, эталон `dns-header-only`).

use super::{Status, UdpContext, be16, byte};
use crate::app::app_id;

/// Ёмкость `rr_offset[]` (`src/proto-dns-parse.h:40`).
const MAX_RRS: usize = 1024;

/// Разобранный заголовок и смещения записей (`struct DNS_Incoming`, `src/proto-dns-parse.h:8-42`): только поля,
/// которые читают `handle_dns` и `handle_nbtstat`.
pub(super) struct DnsIncoming {
    pub id: u16,
    pub qr: bool,
    /// RCODE с расширенными битами EDNS0 (`src/proto-dns.c:302`), может быть больше 15.
    pub rcode: u32,
    pub qdcount: u16,
    pub ancount: u16,
    /// Смещения записей от начала датаграммы, не больше [`MAX_RRS`] (`rr_offset[]`, `rr_count`).
    pub rr_offset: Vec<usize>,
}

/// `dns_name_skip_validate` (`src/proto-dns.c:34-90`). Указатель сжатия здесь смещение в датаграмме (у C в кадре).
/// Конечен: каждый оборот либо растит `name_length` (предел 255), либо счётчик подряд идущих указателей (предел 4).
fn dns_name_skip_validate(
    px: &[u8],
    mut offset: usize,
    length: usize,
    mut name_length: usize,
) -> usize {
    let error = length.saturating_add(1);
    let result = offset.saturating_add(2);
    let mut recursion = 0u32;
    loop {
        if name_length >= 255 || offset >= length {
            return error;
        }
        let Some(len) = byte(px, offset) else {
            return error;
        };
        if len & 0xC0 != 0 {
            if len & 0xC0 != 0xC0 || offset.saturating_add(1) >= length {
                return error;
            }
            let Some(low) = byte(px, offset + 1) else {
                return error;
            };
            offset = usize::from(len & 0x3F) << 8 | usize::from(low);
            recursion += 1;
            if recursion > 4 {
                return error;
            }
        } else {
            recursion = 0;
            if len == 0 {
                return result;
            }
            name_length += usize::from(len) + 1;
            offset += usize::from(len) + 1;
        }
    }
}

/// `dns_name_skip` (`src/proto-dns.c:97-135`): смещение после имени или `max + 1`.
pub(super) fn dns_name_skip(px: &[u8], mut offset: usize, max: usize) -> usize {
    let error = max.saturating_add(1);
    let mut name_length = 0usize;
    loop {
        if name_length >= 255 || offset >= max {
            return error;
        }
        let Some(b) = byte(px, offset) else {
            return error;
        };
        match b >> 6 {
            0 if b == 0 => return offset + 1,
            0 => {
                name_length += usize::from(b) + 1;
                offset += usize::from(b) + 1;
            }
            3 => return dns_name_skip_validate(px, offset, max, name_length),
            // 0x40 (метка EDNS0, RFC 2671) и 0x80: имя неверно.
            _ => return error,
        }
    }
}

/// Пропуск одной записи после имени: `offset += n`, затем RDLENGTH по `offset - 2` (`src/proto-dns.c:282-289`).
/// `None`, если разбор у C здесь останавливается.
fn skip_rr_body(px: &[u8], offset: usize, max: usize) -> Option<usize> {
    let offset = offset.saturating_add(10);
    if offset > max {
        return None;
    }
    let rdlength = usize::from(be16(px, offset - 2)?);
    let offset = offset + rdlength;
    (offset <= max).then_some(offset)
}

/// `proto_dns_parse` (`src/proto-dns.c:175-322`) над датаграммой. `None` при длине меньше 12: у C поля остаются
/// неинициализированными (`src/proto-dns.c:205-206`), здесь это «нет заголовка».
pub(super) fn proto_dns_parse(px: &[u8]) -> Option<DnsIncoming> {
    let max = px.len();
    if max < 12 {
        return None;
    }
    let mut dns = DnsIncoming {
        id: be16(px, 0)?,
        qr: byte(px, 2)? >> 7 & 1 == 1,
        rcode: u32::from(byte(px, 3)? & 0xF),
        qdcount: be16(px, 4)?,
        ancount: be16(px, 6)?,
        rr_offset: Vec::new(),
    };
    let nscount = be16(px, 8)?;
    let arcount = be16(px, 10)?;
    let mut offset = 12usize;
    // Вопросы: имя, тип, класс 1/255/3 (src/proto-dns.c:238-253).
    for _ in 0..dns.qdcount {
        if dns.rr_offset.len() >= MAX_RRS {
            return Some(dns);
        }
        dns.rr_offset.push(offset);
        offset = dns_name_skip(px, offset, max).saturating_add(4);
        if offset > max {
            return Some(dns);
        }
        let Some(xclass) = be16(px, offset - 2) else {
            return Some(dns);
        };
        if !matches!(xclass, 1 | 255 | 3) {
            return Some(dns);
        }
    }
    // Ответы и полномочия (src/proto-dns.c:277-290).
    for _ in 0..u32::from(dns.ancount) + u32::from(nscount) {
        if dns.rr_offset.len() >= MAX_RRS {
            return Some(dns);
        }
        dns.rr_offset.push(offset);
        match skip_rr_body(px, dns_name_skip(px, offset, max), max) {
            Some(next) => offset = next,
            None => return Some(dns),
        }
    }
    // Дополнительные: OPT EDNS0 (src/proto-dns.c:291-315).
    for _ in 0..arcount {
        if dns.rr_offset.len() >= MAX_RRS {
            return Some(dns);
        }
        dns.rr_offset.push(offset);
        if offset.saturating_add(11) <= max && px.get(offset..offset + 3) == Some(&[0, 0, 0x29][..])
        {
            let (Some(payload_size), Some(ext)) = (be16(px, offset + 3), byte(px, offset + 5))
            else {
                return Some(dns);
            };
            if payload_size < 512 {
                return Some(dns);
            }
            dns.rcode |= u32::from(ext) << 4;
        }
        match skip_rr_body(px, dns_name_skip(px, offset, max), max) {
            Some(next) => offset = next,
            None => return Some(dns),
        }
    }
    Some(dns)
}

/// Строки RCODE 1-9 (`src/proto-dns.c:388-399`).
fn rcode_reason(rcode: u32) -> Option<&'static str> {
    Some(match rcode {
        1 => "1:FORMERR",
        2 => "2:SERVFAIL",
        3 => "3:NXDOMAIN",
        4 => "4:NOTIMP",
        5 => "5:REFUSED",
        6 => "6:YXDOMAIN",
        7 => "7:XRRSET",
        8 => "8:NOTAUTH",
        9 => "9:NOTZONE",
        _ => return None,
    })
}

/// `handle_dns` (`src/proto-dns.c:353-449`).
pub(super) fn handle_dns(cx: &UdpContext, px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    let length = px.len();
    // src/proto-dns.c:369-374: несовпадение (и заголовок короче 12 байт) отбрасывает ответ.
    let Some(dns) = proto_dns_parse(px) else {
        return Status::Handled;
    };
    if u32::from(dns.id) != cx.cookie & 0xFFFF {
        return Status::Handled;
    }
    if !dns.qr {
        return Status::Fallback;
    }
    if let Some(reason) = rcode_reason(dns.rcode) {
        out.push((app_id::DNS_VERSIONBIND, reason.as_bytes().to_vec()));
        return Status::Fallback;
    }
    // src/proto-dns.c:419: rr_offset[1] (вторая запись, обычно первый ответ); без неё у C мусор.
    let Some(&rr) = dns.rr_offset.get(1) else {
        return Status::Fallback;
    };
    let offset = dns_name_skip(px, rr, length);
    if offset.saturating_add(10) >= length {
        return Status::Fallback;
    }
    let (Some(rtype), Some(xclass), Some(rrlen), Some(txtlen)) = (
        be16(px, offset),
        be16(px, offset + 2),
        be16(px, offset + 8),
        byte(px, offset + 10),
    ) else {
        return Status::Fallback;
    };
    let offset = offset + 11;
    // src/proto-dns.c:432-434: длина строки не дальше конца датаграммы.
    let txtlen = usize::from(txtlen).min(length - offset);
    if rrlen == 0 || txtlen > usize::from(rrlen) - 1 {
        return Status::Fallback;
    }
    if rtype != 0x10 || xclass != 3 {
        return Status::Fallback;
    }
    let Some(text) = px.get(offset..offset + txtlen) else {
        return Status::Fallback;
    };
    out.push((app_id::DNS_VERSIONBIND, text.to_vec()));
    Status::Handled
}

#[cfg(test)]
mod tests {
    use super::super::handle_udp;
    use super::*;
    use crate::app::app_id;

    const COOKIE: u32 = 0x5EED_1234;

    /// Ответ на зонд version.bind TXT CHAOS (`src/templ-payloads.c:76-86`) с флагами `flags` и TXT `rdata`.
    fn chaos(flags: u16, rdata: &[u8]) -> Vec<u8> {
        let mut v = vec![0x12, 0x34];
        v.extend(flags.to_be_bytes());
        v.extend([0, 1, 0, 1, 0, 0, 0, 0]);
        v.extend(b"\x07version\x04bind\x00\x00\x10\x00\x03");
        v.extend([0xC0, 0x0C, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0]);
        v.extend(u16::try_from(rdata.len()).expect("rdlength").to_be_bytes());
        v.extend(rdata);
        v
    }

    fn cx(rawudp: bool) -> UdpContext {
        UdpContext {
            port_them: 53,
            cookie: COOKIE,
            rawudp,
        }
    }

    /// Строки RCODE 1-9 и сырой баннер; RCODE 0 и 10-15 идут в разбор TXT (`src/proto-dns.c:388-409`).
    #[test]
    fn dns_rcode_strings() {
        let names = [
            "1:FORMERR",
            "2:SERVFAIL",
            "3:NXDOMAIN",
            "4:NOTIMP",
            "5:REFUSED",
            "6:YXDOMAIN",
            "7:XRRSET",
            "8:NOTAUTH",
            "9:NOTZONE",
        ];
        for rcode in 0u16..16 {
            let px = chaos(0x8400 | rcode, b"\x079.18.24");
            let got = handle_udp(&cx(false), &px);
            let want = match names.get(usize::from(rcode).wrapping_sub(1)) {
                Some(s) => vec![
                    (app_id::DNS_VERSIONBIND, s.as_bytes().to_vec()),
                    (app_id::NONE, px.clone()),
                ],
                None => vec![(app_id::DNS_VERSIONBIND, b"9.18.24".to_vec())],
            };
            assert_eq!(got, want, "rcode {rcode}");
        }
    }

    /// Только первая строка TXT, без проверки имени ответа (`src/proto-dns.c:419-447`).
    #[test]
    fn dns_chaos_txt_first_string_only() {
        let px = chaos(0x8400, b"\x03abc\x03def");
        assert_eq!(
            handle_udp(&cx(false), &px),
            vec![(app_id::DNS_VERSIONBIND, b"abc".to_vec())]
        );
        assert_eq!(
            handle_udp(&cx(true), &px),
            vec![
                (app_id::DNS_VERSIONBIND, b"abc".to_vec()),
                (app_id::NONE, px.clone())
            ]
        );
    }

    /// Датаграмма короче заголовка: у C `id` не инициализирован (`src/proto-dns.c:205-206`); у нас это несовпадение
    /// cookie (Р2): ничего, с `--rawudp` только сырой баннер.
    #[test]
    fn dns_short_payload_is_mismatch() {
        let px = chaos(0x8400, b"\x079.18.24");
        for n in 0..12 {
            assert_eq!(handle_udp(&cx(false), &px[..n]), vec![], "len {n}");
            assert_eq!(
                handle_udp(&cx(true), &px[..n]),
                vec![(app_id::NONE, px[..n].to_vec())],
                "len {n}"
            );
        }
        assert_eq!(
            handle_udp(&cx(false), &px[..12]),
            vec![(app_id::NONE, px[..12].to_vec())]
        );
    }

    /// Неверный cookie: ничего (`src/proto-dns.c:373-374`); сравниваются младшие 16 бит.
    #[test]
    fn dns_cookie_low_16_bits() {
        let px = chaos(0x8400, b"\x079.18.24");
        let wrong = UdpContext {
            cookie: COOKIE + 1,
            ..cx(false)
        };
        assert_eq!(handle_udp(&wrong, &px), vec![]);
        let high = UdpContext {
            cookie: 0xA5A5_1234,
            ..cx(false)
        };
        assert_eq!(
            handle_udp(&high, &px),
            vec![(app_id::DNS_VERSIONBIND, b"9.18.24".to_vec())]
        );
    }

    /// Указатель сжатия считается от начала сообщения DNS (у C от начала кадра, отличие из README): `c0 00`
    /// указывает на id `12 34`, метка длины 0x12 выходит за конец, имя неверно, сырой баннер.
    #[test]
    fn dns_pointer_is_message_relative() {
        let mut px = chaos(0x8400, b"\x079.18.24");
        px[30] = 0xC0;
        px[31] = 0x00;
        assert_eq!(
            handle_udp(&cx(false), &px),
            vec![(app_id::NONE, px.clone())]
        );
    }
}
