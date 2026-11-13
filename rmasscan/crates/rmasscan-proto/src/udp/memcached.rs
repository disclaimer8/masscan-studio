//! memcached по UDP, порт 11211 (`memcached_udp_parse`, `src/proto-memcached.c:298-392`). Текст разбирает
//! [`crate::memcached_text`], общий с TCP. Cookie мягкий: при несовпадении request id текст получает ` IP-MISMATCH`,
//! баннер всё равно пишется (жёсткая проверка у C закомментирована, `src/proto-memcached.c:354-355`).

use super::{Status, UdpContext, be16, default_udp_parse};
use crate::app::app_id;
use crate::memcached_text::MemcachedText;

/// `memcached_udp_parse`. Возврат 0 во всех ветках: сырой баннер идёт следом (у C на 11211 он читает за концом
/// датаграммы, `src/proto-udp.c:97-101`; у нас сама датаграмма, Р2).
pub(super) fn memcached_udp_parse(
    cx: &UdpContext,
    px: &[u8],
    out: &mut Vec<(u16, Vec<u8>)>,
) -> Status {
    // src/proto-memcached.c:317-318: заголовок кадра 8 байт.
    let (Some(request_id), Some(sequence), Some(total), Some(reserved), Some(body)) = (
        be16(px, 0),
        be16(px, 2),
        be16(px, 4),
        be16(px, 6),
        px.get(8..),
    ) else {
        return Status::Fallback;
    };
    // src/proto-memcached.c:334-344, 390-391
    if sequence > 100 || total > 100 || reserved != 0 {
        return default_udp_parse(px, out);
    }
    let mut text = Vec::new();
    MemcachedText::new().parse(body, &mut text);
    // src/proto-memcached.c:373-374
    if cx.cookie & 0xFFFF != u32::from(request_id) {
        text.extend_from_slice(b" IP-MISMATCH");
    }
    out.push((app_id::MEMCACHED, text));
    Status::Fallback
}

#[cfg(test)]
mod tests {
    use crate::app::app_id;
    use crate::udp::{UdpContext, handle_udp};

    const COOKIE: u32 = 0x5EED_1234;

    fn mc(cookie: u32, px: &[u8]) -> Vec<(u16, Vec<u8>)> {
        handle_udp(
            &UdpContext {
                port_them: 11211,
                cookie,
                rawudp: false,
            },
            px,
        )
    }

    /// Заголовок кадра: request id, sequence 0, всего 1 датаграмма, reserved 0 (`src/proto-memcached.c:321-327`).
    fn frame(request_id: u16, body: &[u8]) -> Vec<u8> {
        [&request_id.to_be_bytes()[..], &[0, 0, 0, 1, 0, 0], body].concat()
    }

    const STATS: &[u8] =
        b"STAT pid 1234\r\nSTAT uptime 12345\r\nSTAT time 1700000000\r\nSTAT version 1.6.21\r\n\
                           STAT libevent 2.1.12-stable\r\nSTAT pointer_size 64\r\nEND\r\n";

    /// Пример справки B5: из `stats` остаются uptime, time и version, с пробелом в конце, затем сырой баннер.
    #[test]
    fn memcached_stats_keeps_uptime_time_version() {
        let px = frame(0x1234, STATS);
        assert_eq!(
            mc(COOKIE, &px),
            vec![
                (
                    app_id::MEMCACHED,
                    b"uptime=12345 time=1700000000 version=1.6.21 ".to_vec()
                ),
                (app_id::NONE, px.clone())
            ]
        );
    }

    /// Мягкий cookie (`src/proto-memcached.c:373-374`, справка B10): чужой request id даёт ` IP-MISMATCH` в конце
    /// текста, баннер остаётся; пустой текст тоже пишется.
    #[test]
    fn memcached_soft_cookie_ip_mismatch() {
        let px = frame(0x1235, STATS);
        assert_eq!(
            mc(COOKIE, &px),
            vec![
                (
                    app_id::MEMCACHED,
                    b"uptime=12345 time=1700000000 version=1.6.21  IP-MISMATCH".to_vec()
                ),
                (app_id::NONE, px.clone())
            ]
        );
        // Совпадают только младшие 16 бит cookie.
        assert_eq!(
            mc(0xFFFF_1234, &frame(0x1234, STATS))[0].1,
            b"uptime=12345 time=1700000000 version=1.6.21 "
        );
        let empty = frame(0x1234, b"");
        assert_eq!(
            mc(COOKIE, &empty),
            vec![(app_id::MEMCACHED, vec![]), (app_id::NONE, empty.clone())]
        );
        assert_eq!(
            mc(0, &empty)[0],
            (app_id::MEMCACHED, b" IP-MISMATCH".to_vec())
        );
    }

    /// Ранние выходы: меньше 8 байт только сырой; sequence или число датаграмм больше 100, reserved не 0:
    /// `default_udp_parse` (первые 64 байта) и сырой.
    #[test]
    fn memcached_header_checks() {
        let short = frame(0x1234, b"")[..7].to_vec();
        assert_eq!(mc(COOKIE, &short), vec![(app_id::NONE, short.clone())]);
        let mut px = frame(0x1234, STATS);
        px[3] = 101;
        assert_eq!(
            mc(COOKIE, &px),
            vec![
                (app_id::NONE, px[..64].to_vec()),
                (app_id::NONE, px.clone())
            ]
        );
        px[3] = 100;
        assert_eq!(mc(COOKIE, &px)[0].0, app_id::MEMCACHED);
        px[5] = 101;
        assert_eq!(mc(COOKIE, &px)[0], (app_id::NONE, px[..64].to_vec()));
        px[5] = 1;
        px[7] = 1;
        assert_eq!(mc(COOKIE, &px)[0], (app_id::NONE, px[..64].to_vec()));
    }
}
