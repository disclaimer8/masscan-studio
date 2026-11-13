//! NTP, порт 123 (`src/proto-ntp.c`). Cookie нет: `ntp_set_cookie` ничего не пишет (`src/proto-ntp.c:21-28`),
//! проверка закомментирована (`src/proto-ntp.c:264-267`).

use super::{Status, byte};
use crate::app::app_id;

/// Коды запросов режима 7 (`request_codes`, `src/proto-ntp.c:34-73`).
fn request_code(code: u8) -> Option<&'static str> {
    Some(match code {
        0 => "PEER_LIST",
        1 => "PEER_LIST_SUM",
        2 => "PEER_INFO",
        3 => "PEER_STATS",
        4 => "SYS_INFO",
        5 => "SYS_STATS",
        6 => "IO_STATS",
        7 => "MEM_STATS",
        8 => "LOOP_INFO",
        9 => "TIMER_STATS",
        10 => "CONFIG",
        11 => "UNCONFIG",
        12 => "SET_SYS_FLAG",
        13 => "CLR_SYS_FLAG",
        16 => "GET_RESTRICT",
        17 => "RESADDFLAGS",
        18 => "RESSUBFLAGS",
        19 => "UNRESTRICT",
        20 => "MON_GETLIST",
        21 => "RESET_STATS",
        22 => "RESET_PEER",
        23 => "REREAD_KEYS",
        26 => "TRUSTKEY",
        27 => "UNTRUSTKEY",
        28 => "AUTHINFO",
        29 => "TRAPS",
        30 => "ADD_TRAP",
        31 => "CLR_TRAP",
        32 => "REQUEST_KEY",
        33 => "CONTROL_KEY",
        34 => "GET_CTLSTATS",
        36 => "GET_CLOCKINFO",
        37 => "SET_CLKFUDGE",
        38 => "GET_KERNEL",
        39 => "GET_CLKBUGINFO",
        42 => "MON_GETLIST_1",
        43 => "HOSTNAME_ASSOCID",
        _ => return None,
    })
}

/// Коды ошибок (`error_codes`, `src/proto-ntp.c:75-83`); прочие `Bogus Error Code` (`src/proto-ntp.c:123-124`).
fn error_code(code: u8) -> &'static str {
    match code {
        0 => "No Error",
        1 => "Incompatible Implementation Number",
        2 => "Unimplemented Request Code",
        3 => "Format Error",
        4 => "No Data Available",
        7 => "Authentication Failure",
        _ => "Bogus Error Code",
    }
}

/// `ntp_modlist_parse` (`src/proto-ntp.c:100-153`). Перед текстом ошибки и `response-too-big` разделителя нет
/// (C1.12), как у C.
fn ntp_modlist_parse(px: &[u8], banner: &mut Vec<u8>) {
    let length = px.len();
    let (Some(b0), Some(b4), Some(b5), Some(b6), Some(b7)) = (
        byte(px, 0),
        byte(px, 4),
        byte(px, 5),
        byte(px, 6),
        byte(px, 7),
    ) else {
        return;
    };
    if 4 + 4 >= length {
        return;
    }
    let errcode = b4 >> 4 & 0xF;
    let record_count = u32::from(b4 & 0xF) << 8 | u32::from(b5);
    let record_size = u32::from(b6 & 0xF) << 8 | u32::from(b7);
    if errcode != 0 {
        banner.extend_from_slice(b"Response was NTP Error Code ");
        banner.extend_from_slice(errcode.to_string().as_bytes());
        banner.extend_from_slice(b" - \"");
        banner.extend_from_slice(error_code(errcode).as_bytes());
        banner.extend_from_slice(b"\"");
        return;
    }
    // Не больше 0xFFF * 0xFFF: в u32 помещается, как в `unsigned` C.
    let size = record_count * record_size;
    if 4 + u64::from(size) > u64::try_from(length).unwrap_or(u64::MAX) || size > 500 {
        banner.extend_from_slice(b"response-too-big");
        return;
    }
    let more = if b0 >> 6 & 1 == 1 { "true" } else { "false" };
    banner.extend_from_slice(format!(" response-size={size}-bytes more={more}").as_bytes());
}

/// `ntp_priv` (`src/proto-ntp.c:157-187`): реализация `px[2]`, код запроса `px[3]`.
fn ntp_priv(px: &[u8], banner: &mut Vec<u8>) {
    let (Some(implementation), Some(code)) = (byte(px, 2), byte(px, 3)) else {
        return;
    };
    match implementation {
        0 => return banner.extend_from_slice(b"UNIV"),
        2 => return banner.extend_from_slice(b"XNTPD-OLD"),
        3 => banner.extend_from_slice(b"XNTPD"),
        _ => return,
    }
    if let Some(name) = request_code(code) {
        banner.push(b' ');
        banner.extend_from_slice(name.as_bytes());
    }
    if code == 42 {
        ntp_modlist_parse(px, banner);
    }
}

/// `ntp_v2_parse` (`src/proto-ntp.c:191-222`): ответ (бит 7), версия 2, режим 7.
fn ntp_v2_parse(px: &[u8], banner: &mut Vec<u8>) {
    let Some(b0) = byte(px, 0) else {
        return;
    };
    if px.len() < 4 || b0 >> 7 != 1 || b0 >> 3 & 7 != 2 {
        return;
    }
    if b0 & 7 == 7 {
        ntp_priv(px, banner);
    }
}

/// `ntp_handle_response` (`src/proto-ntp.c:228-282`): версия 2 даёт баннер `ntp` (может быть пустым) и сырой.
pub(super) fn ntp_handle_response(px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    let Some(b0) = byte(px, 0) else {
        return Status::Fallback;
    };
    if px.len() < 4 || b0 >> 3 & 7 != 2 {
        return Status::Fallback;
    }
    let mut banner = Vec::new();
    ntp_v2_parse(px, &mut banner);
    out.push((app_id::NTP, banner));
    Status::Fallback
}

#[cfg(test)]
mod tests {
    use super::super::{UdpContext, handle_udp};
    use crate::app::app_id;

    fn ntp(px: &[u8]) -> Vec<(u16, Vec<u8>)> {
        handle_udp(
            &UdpContext {
                port_them: 123,
                cookie: 0,
                rawudp: false,
            },
            px,
        )
    }

    fn monlist(b0: u8, err_count: [u8; 2], size: u16, data: usize) -> Vec<u8> {
        let mut v = vec![b0, 0x00, 0x03, 0x2A, err_count[0], err_count[1]];
        v.extend(size.to_be_bytes());
        v.extend(std::iter::repeat_n(0u8, data));
        v
    }

    /// Обе строки примера справки B2; перед `Response` разделителя нет (`src/proto-ntp.c:126`, C1.12).
    #[test]
    fn ntp_v2_mode7_monlist_texts() {
        let ok = monlist(0x97, [0x00, 0x06], 72, 432);
        assert_eq!(
            ntp(&ok),
            vec![
                (
                    app_id::NTP,
                    b"XNTPD MON_GETLIST_1 response-size=432-bytes more=false".to_vec()
                ),
                (app_id::NONE, ok.clone())
            ]
        );
        let err = monlist(0x97, [0x40, 0x00], 0, 4);
        assert_eq!(
            ntp(&err),
            vec![
                (
                    app_id::NTP,
                    b"XNTPD MON_GETLIST_1Response was NTP Error Code 4 - \"No Data Available\""
                        .to_vec()
                ),
                (app_id::NONE, err.clone())
            ]
        );
        // 8 байт: offset + 4 >= length, разбора списка нет (src/proto-ntp.c:113-114).
        assert_eq!(
            ntp(&err[..8]),
            vec![
                (app_id::NTP, b"XNTPD MON_GETLIST_1".to_vec()),
                (app_id::NONE, err[..8].to_vec())
            ]
        );
    }

    /// Версия не 2 или меньше 4 байт: только сырой; версия 2 без разбора: пустой баннер ntp (`src/proto-ntp.c:243-281`).
    #[test]
    fn ntp_version_gate() {
        assert_eq!(ntp(&[0x97, 0, 3]), vec![(app_id::NONE, vec![0x97, 0, 3])]);
        assert_eq!(
            ntp(&[0x24, 0, 3, 0x2A]),
            vec![(app_id::NONE, vec![0x24, 0, 3, 0x2A])]
        );
        assert_eq!(
            ntp(&[0x17, 0, 3, 0x2A]),
            vec![
                (app_id::NTP, vec![]),
                (app_id::NONE, vec![0x17, 0, 3, 0x2A])
            ]
        );
        assert_eq!(
            ntp(&[0x97, 0, 0, 0x2A]),
            vec![
                (app_id::NTP, b"UNIV".to_vec()),
                (app_id::NONE, vec![0x97, 0, 0, 0x2A])
            ]
        );
    }
}
