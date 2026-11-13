//! memcached по UDP, порт 11211 (справка B5): заголовок кадра 8 байт и текст ответа на `stats`.

use super::{COOKIE, Case, Mode, WRONG_COOKIE, be16, cat};

/// Заголовок кадра (`src/proto-memcached.c:321-327`): request id, номер датаграммы, их число, reserved.
fn frame(id: u16, sequence: u16, total: u16, reserved: u16, body: &[u8]) -> Vec<u8> {
    cat(&[
        &be16(id),
        &be16(sequence),
        &be16(total),
        &be16(reserved),
        body,
    ])
}

/// Ответ с request id из cookie и одной датаграммой.
fn reply(body: &[u8]) -> Vec<u8> {
    frame((COOKIE & 0xFFFF) as u16, 0, 1, 0, body)
}

/// Начало ответа memcached 1.6 на `stats`: после `libevent` (имени нет в таблице C) разбор стоит.
const STATS: &[u8] = b"STAT pid 1234\r\nSTAT uptime 12345\r\nSTAT time 1700000000\r\nSTAT version 1.6.21\r\n\
STAT libevent 2.1.12-stable\r\nSTAT pointer_size 64\r\nSTAT rusage_user 0.123456\r\nSTAT curr_connections 2\r\nEND\r\n";

/// Короткое тело для проверок заголовка: в кадрах C печатает сырой баннер за датаграммой побайтно, и длина тела
/// умножает объём эталонов.
const SHORT: &[u8] = b"STAT uptime 5\r\n";

pub fn cases() -> Vec<Case> {
    let with = |name, cookie, rawudp, mode, payload, about| Case {
        name,
        port: 11211,
        cookie,
        rawudp,
        mode,
        payload,
        about,
    };
    let id = (COOKIE & 0xFFFF) as u16;
    vec![
        with(
            "memcached-stats",
            COOKIE,
            false,
            Mode::Prefixes,
            reply(STATS),
            "ответ на stats: uptime, time, version и пробел, сырой (src/proto-memcached.c:361-388); все обрезки, \
             включая короче 8 байт (только сырой) и пустое тело (пустой баннер)",
        ),
        with(
            "memcached-stats-wrong-cookie",
            WRONG_COOKIE,
            false,
            Mode::Whole,
            reply(STATS),
            "чужой request id: мягкий cookie, текст и ` IP-MISMATCH` (src/proto-memcached.c:373-374)",
        ),
        with(
            "memcached-stats-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            reply(STATS),
            "--rawudp: сырой один раз (status 0)",
        ),
        with(
            "memcached-sequence-100",
            COOKIE,
            false,
            Mode::Whole,
            frame(id, 100, 1, 0, SHORT),
            "номер датаграммы 100: ещё разбирается (src/proto-memcached.c:335)",
        ),
        with(
            "memcached-sequence-101",
            COOKIE,
            false,
            Mode::Whole,
            frame(id, 101, 1, 0, SHORT),
            "номер датаграммы 101: default_udp_parse и сырой (src/proto-memcached.c:335-336, 390-391)",
        ),
        with(
            "memcached-total-0",
            COOKIE,
            false,
            Mode::Whole,
            frame(id, 0, 0, 0, SHORT),
            "число датаграмм 0: разбирается",
        ),
        with(
            "memcached-total-101",
            COOKIE,
            false,
            Mode::Whole,
            frame(id, 0, 101, 0, SHORT),
            "число датаграмм 101: default_udp_parse (src/proto-memcached.c:339-340)",
        ),
        with(
            "memcached-reserved-1",
            COOKIE,
            false,
            Mode::Whole,
            frame(id, 0, 1, 1, SHORT),
            "reserved 1: default_udp_parse (src/proto-memcached.c:343-344)",
        ),
        with(
            "memcached-reserved-256",
            COOKIE,
            false,
            Mode::Whole,
            frame(id, 0, 1, 256, SHORT),
            "reserved 0x0100 (старший байт): default_udp_parse",
        ),
        with(
            "memcached-case-insensitive",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"stat UPTIME 5\r\nStAt TiMe 6\r\nSTAT Version 1.6\r\n"),
            "smack без учёта регистра, имя в баннере из таблицы C (src/proto-memcached.c:195, 235)",
        ),
        with(
            "memcached-stat-newline-skips-line",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"STAT\nSTAT uptime 1\r\nSTAT time 2\r\n"),
            "`STAT\\n`: состояние 2 съедает следующую строку (src/proto-memcached.c:143-144, 162-167)",
        ),
        with(
            "memcached-response-skips-line",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"ERROR\nSTAT uptime 1\r\nCLIENT_ERROR bad\r\nSTAT time 2\r\n"),
            "любой другой ответ уходит в состояние 2: после `ERROR\\n` пропадает следующая строка",
        ),
        with(
            "memcached-blank-lines",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"\r\nSTAT uptime 1\r\n\nSTAT time 2\r\nSTAT version 3\r\n"),
            "пустые строки: шаблон \"\" плюс разделитель; после `\\n` следующая строка пропадает",
        ),
        with(
            "memcached-unknown-stat-stops",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"STAT uptime 1\r\nSTAT libevent 2.1\r\nSTAT time 2\r\n"),
            "имя не из таблицы: smack без совпадения съедает остаток (src/smack1.c:1075-1100)",
        ),
        with(
            "memcached-unknown-line-stops",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"VERSION 1.6.21\r\nSTAT uptime 1\r\n"),
            "строка не с ответа из таблицы: ничего",
        ),
        with(
            "memcached-end-stops",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"STAT uptime 1\r\nEND\r\nSTAT time 2\r\n"),
            "после END всё игнорируется (src/proto-memcached.c:148-159)",
        ),
        with(
            "memcached-value-forms",
            COOKIE,
            false,
            Mode::Whole,
            reply(b"STAT uptime\r\nSTAT time \nSTAT version \x0b\x0c 1.6 beta\r\r\n"),
            "имя без значения: `=` без пробела; пробелы isspace перед значением, CR внутри выпадает",
        ),
        with(
            "memcached-after-stat-sweep",
            COOKIE,
            false,
            Mode::Sweep(8 + 4),
            reply(b"STAT uptime 5\nSTAT time 6\n"),
            "байт после STAT: только ` \\t\\r\\n` (у `\\n` строка пропадает)",
        ),
        with(
            "memcached-name-end-sweep",
            COOKIE,
            false,
            Mode::Sweep(8 + 11),
            reply(b"STAT uptime 5\nSTAT time 6\n"),
            "байт после имени: только ` \\t\\r\\n` кончают имя",
        ),
        with(
            "memcached-value-first-byte-sweep",
            COOKIE,
            false,
            Mode::Sweep(8 + 13),
            reply(b"STAT version X1\nSTAT time 6\n"),
            "первый байт значения: isspace (локаль C) пропускается, `\\n` кончает строку, прочие в значении",
        ),
        with(
            "memcached-long-value",
            COOKIE,
            false,
            Mode::Whole,
            reply(&cat(&[b"STAT version ", &[b'v'; 1400], b"\r\n"])),
            "значение 1400 байт целиком",
        ),
    ]
}
