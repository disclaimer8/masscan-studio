//! CoAP, порт 5683 (`src/proto-coap.c`). Cookie мягкий: чужой message id даёт ` IP-MISMATCH` (`src/proto-coap.c:
//! 564-571`). Все детерминированные ошибки C повторены (Р1, справка B6, C1.14): токен собирается из байтов заголовка
//! `px[0..TKL]`, а не `px[4..]`, и печатается десятичным после `0x` (`src/proto-coap.c:345-349, 364`); в разборе
//! ссылок `offset == ';'` сравнивает смещение, а не байт (`src/proto-coap.c:239`); без Content-Format печатается
//! ` text-plain` (`content_format` по умолчанию 0, `src/proto-coap.c:396, 504-505`); длина опции 15 берётся как
//! есть; значение Content-Format длиннее 4 байт теряет старшие байты (`unsigned`, `src/proto-coap.c:483-485`).

use super::{Status, UdpContext, default_udp_parse};
use crate::app::app_id;

/// `response_code` (`src/proto-coap.c:59-95`).
fn response_code(code: u8) -> &'static str {
    match (code >> 5, code & 0x1F) {
        (2, 0) => "Okay",
        (2, 1) => "Created",
        (2, 2) => "Deleted",
        (2, 3) => "Valid",
        (2, 4) => "Changed",
        (2, 5) => "Content",
        (4, 0) => "Bad Request",
        (4, 1) => "Unauthorized",
        (4, 2) => "Bad Option",
        (4, 3) => "Forbidden",
        (4, 4) => "Not Found",
        (4, 5) => "Method Not Allowed",
        (4, 6) => "Not Acceptable",
        (4, 12) => "Precondition Failed",
        (4, 13) => "Request Too Large",
        (4, 15) => "Unsupported Content-Format",
        (5, 0) => "Internal Server Error",
        (5, 1) => "Not Implemented",
        (5, 2) => "Bad Gateway",
        (5, 3) => "Service Unavailable",
        (5, 4) => "Gateway Timeout",
        (5, 5) => "Proxying Not Supported",
        (2, _) => "Okay",
        (4, _) => "Error",
        _ => "PARSE_ERR",
    }
}

/// `isspace` в локали C (masscan не вызывает `setlocale`).
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// `is_attr_char` (`src/proto-coap.c:106-116`), `isalnum` в локали C.
fn is_attr_char(c: u8) -> bool {
    matches!(
        c,
        b'!' | b'#' | b'$' | b'&' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
    ) || c.is_ascii_alphanumeric()
}

/// Состояния `parse_links` (`src/proto-coap.c:126-138`). `PARM_BEGIN` у C недостижимо: в него никто не переходит.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Begin,
    Value,
    End,
    ParmNameBegin,
    ParmName,
    ParmValueBegin,
    ParmValue,
    ParmQuoted,
    ParmQuotedEscape,
    Invalid,
}

/// `parse_links` (`src/proto-coap.c:120-284`): `(начало, длина)` каждой `<ссылки>` без угловых скобок. Параметры C
/// разбирает, но в баннер они не попадают.
fn parse_links(px: &[u8], mut offset: usize) -> Vec<(usize, usize)> {
    let mut links: Vec<(usize, usize)> = Vec::new();
    let mut state = Link::Begin;
    while let Some(&c) = px.get(offset) {
        state = match state {
            Link::Invalid => break,
            Link::Begin if is_space(c) => Link::Begin,
            Link::Begin if c != b'<' => Link::Invalid,
            Link::Begin => {
                links.push((offset + 1, 0));
                Link::Value
            }
            Link::Value if c == b'>' => Link::End,
            Link::Value => {
                if let Some(last) = links.last_mut() {
                    last.1 += 1;
                }
                Link::Value
            }
            Link::End if is_space(c) => Link::End,
            Link::End if c == b',' => Link::Begin,
            Link::End if c == b';' => Link::ParmNameBegin,
            Link::End => Link::Invalid,
            Link::ParmNameBegin if is_space(c) => Link::ParmNameBegin,
            Link::ParmNameBegin if !is_attr_char(c) => Link::Invalid,
            Link::ParmNameBegin => Link::ParmName,
            Link::ParmName if is_space(c) => Link::ParmName,
            Link::ParmName if c == b'=' => Link::ParmValueBegin,
            Link::ParmName if !is_attr_char(c) => Link::Invalid,
            Link::ParmName => Link::ParmName,
            Link::ParmValueBegin if is_space(c) => Link::ParmValueBegin,
            Link::ParmValueBegin if c == b'"' => Link::ParmQuoted,
            // src/proto-coap.c:239: `offset == ';'`, то есть смещение 59 в датаграмме, а не байт `;`.
            Link::ParmValueBegin if offset == usize::from(b';') => Link::ParmNameBegin,
            Link::ParmValueBegin if c == b',' => Link::Begin,
            Link::ParmValueBegin => Link::ParmValue,
            Link::ParmValue if is_space(c) => Link::ParmValue,
            Link::ParmValue if c == b';' => Link::ParmNameBegin,
            Link::ParmValue if c == b',' => Link::Begin,
            Link::ParmValue => Link::ParmValue,
            Link::ParmQuoted if c == b'\\' => Link::ParmQuotedEscape,
            Link::ParmQuoted if c == b'"' => Link::ParmValue,
            Link::ParmQuoted => Link::ParmQuoted,
            Link::ParmQuotedEscape => Link::ParmQuoted,
        };
        offset += 1;
    }
    links
}

/// Номер опции «ошибка разбора» (`optnum = 0xFFFFFFFF`, `src/proto-coap.c:417`).
const BAD_OPTION: u32 = u32::MAX;

/// `coap_parse` (`src/proto-coap.c:288-531`): годен ли ответ и message id (`px[2..4]`, читается до проверок, если
/// есть 4 байта).
fn coap_parse(px: &[u8], banner: &mut Vec<u8>) -> (bool, u32) {
    let length = px.len();
    let (Some(&b0), Some(&code), Some(&id_hi), Some(&id_lo)) =
        (px.first(), px.get(1), px.get(2), px.get(3))
    else {
        return (false, 0);
    };
    let message_id = u32::from(id_hi) << 8 | u32::from(id_lo);
    let version = b0 >> 6 & 3;
    let kind = b0 >> 4 & 3;
    let token_length = usize::from(b0 & 0x0F);
    // src/proto-coap.c:327-343: только v1, только ACK, токен до 8 байт и помещается.
    if version != 1 || kind != 2 || token_length > 8 || 4 + token_length > length {
        return (false, message_id);
    }
    // src/proto-coap.c:345-349: токен из px[0..TKL] (заголовок), как у C.
    let token = px
        .get(..token_length)
        .unwrap_or(&[])
        .iter()
        .fold(0u64, |t, &b| t << 8 | u64::from(b));
    banner.extend_from_slice(
        format!("rsp={}.{}({})", code >> 5, code & 0x1F, response_code(code)).as_bytes(),
    );
    if token != 0 {
        // src/proto-coap.c:364: "0x%llu".
        banner.extend_from_slice(format!(" token=0x{token}").as_bytes());
    }

    // src/proto-coap.c:394-502
    let mut offset = 4 + token_length;
    let mut optnum: u32 = 0;
    let mut content_format: u32 = 0;
    while let Some(&opt) = px.get(offset) {
        offset += 1;
        if opt == 0xFF {
            break;
        }
        let mut optlen = u32::from(opt & 0x0F);
        let delta = opt >> 4;
        match delta {
            13 => match px.get(offset) {
                Some(&d) => {
                    optnum = optnum.wrapping_add(u32::from(d) + 13);
                    offset += 1;
                }
                None => {
                    banner.extend_from_slice(b" PARSE_ERR");
                    optnum = BAD_OPTION;
                }
            },
            14 => match (px.get(offset), px.get(offset + 1)) {
                (Some(&hi), Some(&lo)) => {
                    optnum = optnum.wrapping_add((u32::from(hi) << 8 | u32::from(lo)) + 269);
                    offset += 2;
                }
                _ => {
                    banner.extend_from_slice(b" PARSE_ERR");
                    optnum = BAD_OPTION;
                }
            },
            15 => {
                // 0xFF уже вышел из цикла: длина здесь всегда не 15.
                if optlen != 15 {
                    banner.extend_from_slice(b" PARSE_ERR");
                }
                optnum = BAD_OPTION;
            }
            _ => optnum = optnum.wrapping_add(u32::from(delta)),
        }
        match optlen {
            13 => match px.get(offset) {
                Some(&l) => {
                    optlen = u32::from(l) + 13;
                    offset += 1;
                }
                None => {
                    banner.extend_from_slice(b" PARSE_ERR");
                    optnum = BAD_OPTION;
                }
            },
            14 => match (px.get(offset), px.get(offset + 1)) {
                (Some(&hi), Some(&lo)) => {
                    optlen = (u32::from(hi) << 8 | u32::from(lo)) + 269;
                    offset += 2;
                }
                _ => {
                    banner.extend_from_slice(b" PARSE_ERR");
                    optnum = BAD_OPTION;
                }
            },
            _ => {}
        }
        // optlen не больше 65 535 + 269: в usize помещается.
        let value = usize::try_from(optlen)
            .ok()
            .and_then(|n| px.get(offset..offset.checked_add(n)?));
        if value.is_none() {
            banner.extend_from_slice(b" PARSE_ERR");
            optnum = BAD_OPTION;
        }
        let name: &[u8] = match optnum {
            BAD_OPTION => b"",
            1 => b" /If-Match/",
            3 => b" /Uri-Host/",
            4 => b" /Etag",
            5 => b" /If-None-Match/",
            7 => b" /Uri-Port/",
            8 => b" /Location-Path/",
            11 => b" /Uri-Path/",
            12 => {
                content_format = value
                    .unwrap_or(&[])
                    .iter()
                    .fold(0u32, |f, &b| f << 8 | u32::from(b));
                b" /Content-Format/"
            }
            14 => b" /Max-Age/",
            15 => b" /Uri-Query/",
            17 => b" /Accept/",
            20 => b" /Location-Query/",
            35 => b" /Proxy-Uri/",
            39 => b" /Proxy-Scheme/",
            60 => b" /Size1/",
            _ => b" /(Unknown)/",
        };
        banner.extend_from_slice(name);
        if optnum == BAD_OPTION {
            break;
        }
        offset += value.map_or(0, <[u8]>::len);
    }

    // src/proto-coap.c:504-525
    match content_format {
        0 => banner.extend_from_slice(b" text-plain"),
        40 => {
            banner.extend_from_slice(b" application/link-format");
            for (start, len) in parse_links(px, offset) {
                banner.push(b' ');
                banner.extend_from_slice(px.get(start..start + len).unwrap_or(&[]));
            }
        }
        41 => banner.extend_from_slice(b" application/xml"),
        42 => banner.extend_from_slice(b" application/octet-stream"),
        47 => banner.extend_from_slice(b" application/exi"),
        50 => banner.extend_from_slice(b" application/json"),
        _ => banner.extend_from_slice(b" (unknown-content-type)"),
    }
    (true, message_id)
}

/// `coap_handle_response` (`src/proto-coap.c:535-589`): годный ответ даёт баннер `coap` и сырой, негодный
/// `default_udp_parse` (первые 64 байта) и сырой.
pub(super) fn coap_handle_response(
    cx: &UdpContext,
    px: &[u8],
    out: &mut Vec<(u16, Vec<u8>)>,
) -> Status {
    let mut text = Vec::new();
    let (valid, message_id) = coap_parse(px, &mut text);
    if cx.cookie & 0xFFFF != message_id {
        text.extend_from_slice(b" IP-MISMATCH");
    }
    if valid {
        out.push((app_id::COAP, text));
        Status::Fallback
    } else {
        default_udp_parse(px, out)
    }
}

#[cfg(test)]
mod tests {
    use crate::app::app_id;
    use crate::udp::{UdpContext, handle_udp};

    const COOKIE: u32 = 0x5EED_1234;

    fn coap(cookie: u32, px: &[u8]) -> Vec<(u16, Vec<u8>)> {
        handle_udp(
            &UdpContext {
                port_them: 5683,
                cookie,
                rawudp: false,
            },
            px,
        )
    }

    fn text(px: &[u8]) -> Vec<u8> {
        let got = coap(COOKIE, px);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].0, app_id::COAP);
        assert_eq!(got[1], (app_id::NONE, px.to_vec()));
        got[0].1.clone()
    }

    /// B6, C1.14: токен собирается из `px[0..TKL]`, то есть из заголовка, и печатается десятичным после `0x`
    /// (`src/proto-coap.c:345-349, 364`). Настоящий токен (`AA BB CC DD`) не виден, опции начинаются после него.
    #[test]
    fn coap_token_bug_reproduced() {
        let px = [0x64, 0x45, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD];
        // 0x64451234 = 1682248244
        assert_eq!(text(&px), b"rsp=2.5(Content) token=0x1682248244 text-plain");
        // TKL 1: токен = первый байт 0x61 = 97.
        assert_eq!(
            text(&[0x61, 0x45, 0x12, 0x34, 0x00]),
            b"rsp=2.5(Content) token=0x97 text-plain"
        );
        // TKL 8: восемь первых байт, u64.
        let px = [0x68, 0x45, 0x12, 0x34, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            text(&px),
            format!(
                "rsp=2.5(Content) token=0x{} text-plain",
                u64::from_be_bytes([0x68, 0x45, 0x12, 0x34, 1, 2, 3, 4])
            )
            .as_bytes()
        );
    }

    /// Негодный ответ (`coap_parse` false): `default_udp_parse` и сырой, ` IP-MISMATCH` пропадает вместе с текстом
    /// (`src/proto-coap.c:585-588`).
    #[test]
    fn coap_invalid_goes_def64_then_raw() {
        let long: Vec<u8> = [&[0x20u8, 0x45, 0x12, 0x34][..], &[b'x'; 100]].concat();
        for px in [
            vec![0x60, 0x45, 0x12],                // короче 4 байт
            vec![0x20, 0x45, 0x12, 0x34],          // версия 0
            vec![0x40, 0x45, 0x12, 0x34],          // CON, не ACK
            vec![0x70, 0x45, 0x12, 0x34],          // RST
            vec![0x69, 0x45, 0x12, 0x34, 0, 0, 0], // TKL 9
            vec![0x64, 0x45, 0x12, 0x34, 0, 0, 0], // TKL 4 не помещается
            long,
        ] {
            let def64 = px.get(..64).unwrap_or(&px).to_vec();
            assert_eq!(
                coap(COOKIE, &px),
                vec![(app_id::NONE, def64.clone()), (app_id::NONE, px.clone())],
                "{px:02x?}"
            );
            assert_eq!(coap(0, &px)[0], (app_id::NONE, def64));
        }
    }

    /// Мягкий cookie: младшие 16 бит против message id.
    #[test]
    fn coap_soft_cookie_ip_mismatch() {
        let px = [0x60, 0x45, 0x12, 0x35];
        assert_eq!(text(&px), b"rsp=2.5(Content) text-plain IP-MISMATCH");
        assert_eq!(
            coap(0xABCD_1235, &px)[0].1,
            b"rsp=2.5(Content) text-plain".to_vec()
        );
    }

    /// Опции: имена, расширенные дельта и длина, ошибки разбора (`src/proto-coap.c:397-502`).
    #[test]
    fn coap_options() {
        let hdr = [0x60, 0x45, 0x12, 0x34];
        let with = |opts: &[u8]| text(&[&hdr[..], opts].concat());
        // Uri-Path (11, длина 1), затем Content-Format (дельта 1, длина 1, 50), затем Size1 (дельта 13 + 35 = 48).
        assert_eq!(
            with(&[0xB1, b'a', 0x11, 50, 0xD0, 35]),
            b"rsp=2.5(Content) /Uri-Path/ /Content-Format/ /Size1/ application/json"
        );
        // Дельта 14: 269 + 0 = 269, неизвестная; затем длина 13 + 0 = 13 байт не помещается.
        assert_eq!(
            with(&[0xE0, 0, 0, 0x0D, 0]),
            b"rsp=2.5(Content) /(Unknown)/ PARSE_ERR text-plain"
        );
        // Дельта 15: всегда PARSE_ERR; с длиной 13 без байта ещё два раза.
        assert_eq!(
            with(&[0xFD]),
            b"rsp=2.5(Content) PARSE_ERR PARSE_ERR PARSE_ERR text-plain"
        );
        // Дельта 13 без байта.
        assert_eq!(with(&[0xD0]), b"rsp=2.5(Content) PARSE_ERR text-plain");
        // Длина 15 берётся как есть.
        assert_eq!(
            with(&[0x1F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF]),
            b"rsp=2.5(Content) /If-Match/ text-plain"
        );
        // Content-Format из 5 байт: старший теряется (unsigned), 01 00 00 00 28 = 40.
        assert_eq!(
            with(&[0xC5, 1, 0, 0, 0, 0x28, 0xFF, b'<', b'a', b'>']),
            b"rsp=2.5(Content) /Content-Format/ application/link-format a"
        );
        // Без опций код 0.00: класс 0, PARSE_ERR в скобках.
        assert_eq!(
            text(&[0x60, 0x00, 0x12, 0x34]),
            b"rsp=0.0(PARSE_ERR) text-plain"
        );
        assert_eq!(
            text(&[0x60, 0x9F, 0x12, 0x34]),
            b"rsp=4.31(Error) text-plain"
        );
    }

    /// Ссылки link-format: только `<...>`, параметры не печатаются, и ошибка `offset == ';'`
    /// (`src/proto-coap.c:239`): значение параметра на смещении 59 переводит разбор в имя параметра, и следующая
    /// ссылка теряется.
    #[test]
    fn coap_links_and_offset_59() {
        let reply = |payload: &[u8]| -> Vec<u8> {
            [&[0x60, 0x45, 0x12, 0x34, 0xC1, 40, 0xFF][..], payload].concat()
        };
        assert_eq!(
            text(&reply(b"</a>;ct=40,</b/c>;if=\"x\\\"y\", <d>")),
            b"rsp=2.5(Content) /Content-Format/ application/link-format /a /b/c d"
        );
        // Полезная нагрузка с 7-го байта: `</a>;x` + `x` * k + `=1,</b>`, значение `1` на смещении 14 + k.
        let value_at = |at: usize| -> Vec<u8> {
            let payload = [&b"</a>;x"[..], &vec![b'x'; at - 14], b"=1,</b>"].concat();
            let px = reply(&payload);
            assert_eq!(px[at], b'1');
            px
        };
        assert_eq!(
            text(&value_at(59)),
            b"rsp=2.5(Content) /Content-Format/ application/link-format /a"
        );
        assert_eq!(
            text(&value_at(58)),
            b"rsp=2.5(Content) /Content-Format/ application/link-format /a /b"
        );
    }
}
