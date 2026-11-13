//! NetBIOS name service, порт 137 (`src/proto-netbios.c`): ответ NBSTAT на зонд `*` (`src/templ-payloads.c:109-118`).
//! Разбор DNS общий с портом 53 ([`super::dns`]), отличия от C те же: смещения от начала датаграммы, длина
//! датаграммы вместо длины кадра (`src/proto-netbios.c:145-166`), неинициализированные `id` и `rr_offset[qdcount]`
//! (`src/proto-netbios.c:127-144`) дают несовпадение и сырой баннер.

use super::dns::{dns_name_skip, proto_dns_parse};
use super::{Status, UdpContext, be16, byte};
use crate::app::app_id;

/// Буфер баннера `handle_nbtstat_rr` (`src/proto-netbios.c:65`): дальше `append_char` молча не пишет.
const BANNER_MAX: usize = 65_536;

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// `append_char` (`src/proto-netbios.c:18-23`).
fn append_char(banner: &mut Vec<u8>, c: u8) {
    if banner.len() < BANNER_MAX {
        banner.push(c);
    }
}

fn append_hex(banner: &mut Vec<u8>, c: u8) {
    append_char(banner, HEX[usize::from(c >> 4)]);
    append_char(banner, HEX[usize::from(c & 0xF)]);
}

/// `append_name` (`src/proto-netbios.c:28-55`): 15 байт имени, затем суффикс `<XX>` и перевод строки. Пробел и NUL
/// печатаются пробелом, `isalnum || ispunct` (C-локаль: 0x21-0x7E) как есть, прочее `<XX>` прописными.
fn append_name(banner: &mut Vec<u8>, name: &[u8; 16]) {
    let (chars, suffix) = name.split_at(15);
    for &c in chars {
        match c {
            0x00 | 0x20 => append_char(banner, b' '),
            0x21..=0x7E => append_char(banner, c),
            _ => {
                append_char(banner, b'<');
                append_hex(banner, c);
                append_char(banner, b'>');
            }
        }
    }
    append_char(banner, b'<');
    append_hex(banner, suffix.first().copied().unwrap_or(0));
    append_char(banner, b'>');
    append_char(banner, b'\n');
}

/// `handle_nbtstat_rr` (`src/proto-netbios.c:60-104`): `px` начинается с числа имён. Записи по 18 байт, пока
/// помещаются; затем MAC, где C шесть раз печатает ПЕРВЫЙ байт (`unsigned char c = px[offset];`, `src/proto-netbios.c:87`,
/// C1.11): функциональный баг, детерминирован, воспроизводится (Р1).
fn handle_nbtstat_rr(px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) {
    let length = px.len();
    let Some(mut name_count) = byte(px, 0) else {
        return;
    };
    let mut offset = 1usize;
    let mut banner = Vec::new();
    while offset + 18 <= length && name_count != 0 {
        let Some(name) = px
            .get(offset..offset + 16)
            .and_then(|n| <&[u8; 16]>::try_from(n).ok())
        else {
            break;
        };
        append_name(&mut banner, name);
        offset += 18;
        name_count -= 1;
    }
    for i in 0..6 {
        if offset + i < length {
            let c = byte(px, offset).unwrap_or(0);
            append_hex(&mut banner, c);
            if i < 5 {
                append_char(&mut banner, b'-');
            }
        }
    }
    out.push((app_id::NBTSTAT, banner));
}

/// `handle_nbtstat` (`src/proto-netbios.c:110-169`).
pub(super) fn handle_nbtstat(cx: &UdpContext, px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    let length = px.len();
    let Some(dns) = proto_dns_parse(px) else {
        return Status::Handled;
    };
    if u32::from(dns.id) != cx.cookie & 0xFFFF {
        return Status::Handled;
    }
    if !dns.qr || dns.rcode != 0 || dns.qdcount > 1 || dns.ancount < 1 || dns.rr_offset.is_empty() {
        return Status::Fallback;
    }
    // src/proto-netbios.c:144: rr_offset[qdcount]; если разбор не дошёл до ответа, у C там мусор.
    let Some(&rr) = dns.rr_offset.get(usize::from(dns.qdcount)) else {
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
    if rrlen == 0 || u16::from(txtlen) > rrlen - 1 {
        return Status::Fallback;
    }
    if rtype != 0x21 || xclass != 1 {
        return Status::Fallback;
    }
    handle_nbtstat_rr(px.get(offset + 10..).unwrap_or_default(), out);
    Status::Fallback
}

#[cfg(test)]
mod tests {
    use super::super::handle_udp;
    use super::*;
    use crate::app::app_id;

    fn entry(name: &[u8], suffix: u8) -> Vec<u8> {
        let mut v = name.to_vec();
        v.resize(15, b' ');
        v.push(suffix);
        v.extend([0x04, 0x00]);
        v
    }

    /// Ответ NBSTAT без вопроса: имя ответа `A`, `rdata` как есть.
    fn reply(rdata: &[u8]) -> Vec<u8> {
        let mut v = vec![
            0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 1, b'A', 0, 0x00, 0x21, 0x00, 0x01, 0,
            0, 0, 0,
        ];
        v.extend(u16::try_from(rdata.len()).expect("rdlength").to_be_bytes());
        v.extend(rdata);
        v
    }

    /// MAC печатает первый байт шесть раз (`src/proto-netbios.c:87`, C1.11): воспроизводится, как у C (Р1).
    #[test]
    fn nbtstat_mac_repeats_first_byte() {
        let mut rdata = vec![2];
        rdata.extend(entry(b"HOST1", 0x00));
        rdata.extend(entry(b"WORKGROUP", 0x00));
        rdata.extend([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let px = reply(&rdata);
        let cx = UdpContext {
            port_them: 137,
            cookie: 0x5EED_1234,
            rawudp: false,
        };
        assert_eq!(
            handle_udp(&cx, &px),
            vec![
                (
                    app_id::NBTSTAT,
                    b"HOST1          <00>\nWORKGROUP      <00>\n52-52-52-52-52-52".to_vec()
                ),
                (app_id::NONE, px.clone())
            ]
        );
        // Три байта после имён: три пары, у третьей дефис остаётся (i < 5).
        let px = reply(&[0, 0x52, 0x54, 0x00]);
        assert_eq!(
            handle_udp(&cx, &px),
            vec![
                (app_id::NBTSTAT, b"52-52-52-".to_vec()),
                (app_id::NONE, px.clone())
            ]
        );
        // Неверный cookie: ничего (src/proto-netbios.c:129-130).
        let wrong = UdpContext {
            cookie: 0x5EED_1235,
            ..cx
        };
        assert_eq!(handle_udp(&wrong, &px), vec![]);
    }

    /// Символы имени: пробел и NUL как пробел, isalnum || ispunct (C-локаль) как есть, остальное `<XX>`.
    #[test]
    fn nbtstat_name_bytes() {
        let cx = UdpContext {
            port_them: 137,
            cookie: 0x5EED_1234,
            rawudp: false,
        };
        for b in 0u8..=255 {
            let mut rdata = vec![1];
            rdata.extend(entry(&[b], 0x1D));
            let px = reply(&rdata);
            let first = match b {
                0x00 | 0x20 => " ".to_string(),
                0x21..=0x7E => char::from(b).to_string(),
                _ => format!("<{b:02X}>"),
            };
            let want = format!("{first}              <1D>\n");
            assert_eq!(
                handle_udp(&cx, &px),
                vec![
                    (app_id::NBTSTAT, want.into_bytes()),
                    (app_id::NONE, px.clone())
                ],
                "byte {b:#x}"
            );
        }
    }
}
