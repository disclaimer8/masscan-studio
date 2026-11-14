//! CoAP, порт 5683 (справка B6): ACK на зонд `GET /.well-known/core`, message id из cookie.

use super::{COOKIE, Case, Mode, WRONG_COOKIE, cat};

/// Заголовок: версия 1, тип 2 (ACK), TKL; код; message id (`src/proto-coap.c:319-324`).
fn header(tkl: u8, code: u8, id: u16) -> Vec<u8> {
    cat(&[&[0x60 | tkl, code], &id.to_be_bytes()])
}

const ID: u16 = (COOKIE & 0xFFFF) as u16;
/// 2.05 Content.
const CONTENT: u8 = 0x45;
/// Опция Content-Format (дельта 12, длина 1) и значение 40 (link-format), затем маркер полезной нагрузки.
const LINK_FORMAT: [u8; 3] = [0xC1, 40, 0xFF];

fn link_reply(links: &[u8]) -> Vec<u8> {
    cat(&[&header(0, CONTENT, ID), &LINK_FORMAT, links])
}

/// Вектор selftest C (`src/proto-coap.c:695-702`): message id 0x01CE.
const SELFTEST: &[u8] =
    b"\x60\x45\x01\xce\xc1\x28\xff</register>,</ndm/dis>,</ndm/ci>,</mirror>,</uhp>,\
</ndm/logout>,</ndm/login>,</info>";

pub fn cases() -> Vec<Case> {
    let with = |name, cookie, rawudp, mode, payload, about| Case {
        name,
        port: 5683,
        cookie,
        rawudp,
        mode,
        payload,
        about,
    };
    // Ответ на зонд: токен 2 байта (C печатает вместо него байты заголовка), Content-Format 40 и ссылки.
    let core = cat(&[
        &header(2, CONTENT, ID),
        &[0xAB, 0xCD],
        &LINK_FORMAT,
        b"</.well-known/core>;ct=40,</sensors/temp>;if=\"sensor\",</sensors/light>;rt=\"light-lux\";if=\"sensor\",\
          </firmware/v2.1>;rt=\"firmware\";sz=262144",
    ]);
    // Значение параметра ссылки на смещении `at` датаграммы: `</a>;x`, заполнитель, `=1,</b>`.
    let param_value_at =
        |at: usize| link_reply(&cat(&[b"</a>;x", &vec![b'x'; at - 14], b"=1,</b>"]));
    let option_names = cat(&[
        &header(0, CONTENT, ID),
        &[0x11, b'x'], // 1 If-Match
        &[0x20],       // 3 Uri-Host
        &[0x10],       // 4 Etag
        &[0x10],       // 5 If-None-Match
        &[0x10],       // 6 неизвестная
        &[0x10],       // 7 Uri-Port
        &[0x10],       // 8 Location-Path
        &[0x30],       // 11 Uri-Path
        &[0x11, 50],   // 12 Content-Format = 50
        &[0x20],       // 14 Max-Age
        &[0x10],       // 15 Uri-Query
        &[0x20],       // 17 Accept
        &[0x30],       // 20 Location-Query
        &[0xD0, 2],    // 20 + 13 + 2 = 35 Proxy-Uri
        &[0x40],       // 39 Proxy-Scheme
        &[0xD0, 8],    // 39 + 13 + 8 = 60 Size1
        &[0xE0, 0, 0], // 60 + 269 = 329 неизвестная
        &[0xFF],
        b"{}",
    ]);
    let ext = cat(&[
        &header(0, CONTENT, ID),
        &[0xEE, 0x00, 0x05, 0x00, 0x10],
        &[b'v'; 269 + 16],
        &[0xDD, 0x02, 0x03],
        &[b'w'; 13 + 3],
        &[0xFF],
        b"text",
    ]);
    vec![
        with(
            "coap-link-format",
            COOKIE,
            false,
            Mode::Prefixes,
            core.clone(),
            "ACK 2.05 с токеном и link-format: coap и сырой (src/proto-coap.c:575-584); токен из байтов заголовка, \
             `0x<десятичное>` (C1.14); все обрезки (короче 4 байт, токен не помещается: def64 и сырой)",
        ),
        with(
            "coap-link-format-wrong-cookie",
            WRONG_COOKIE,
            false,
            Mode::Whole,
            core.clone(),
            "чужой message id: мягкий cookie, ` IP-MISMATCH` (src/proto-coap.c:570-571)",
        ),
        with(
            "coap-link-format-rawudp",
            COOKIE,
            true,
            Mode::Whole,
            core,
            "--rawudp: сырой один раз (status 0)",
        ),
        with(
            "coap-selftest",
            0x5EED_01CE,
            false,
            Mode::Whole,
            SELFTEST.to_vec(),
            "вектор selftest C (src/proto-coap.c:695-702), message id 462",
        ),
        with(
            "coap-byte0-sweep",
            COOKIE,
            false,
            Mode::Sweep(0),
            cat(&[
                &header(0, CONTENT, ID),
                &[0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xFF],
                b"<x>",
            ]),
            "версия, тип и TKL 0..15: годен только v1 ACK с TKL <= 8, токен из px[0..TKL] (src/proto-coap.c:327-349)",
        ),
        with(
            "coap-code-sweep",
            COOKIE,
            false,
            Mode::Sweep(1),
            header(0, CONTENT, ID),
            "все коды ответа: строки response_code и запасные по классу (src/proto-coap.c:59-95)",
        ),
        with(
            "coap-option-byte-sweep",
            COOKIE,
            false,
            Mode::Sweep(4),
            cat(&[
                &header(0, CONTENT, ID),
                &[
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                ],
                &[0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13],
            ]),
            "байт опции: все дельты и длины, расширения 13 и 14, PARSE_ERR (src/proto-coap.c:397-502)",
        ),
        with(
            "coap-option-names",
            COOKIE,
            false,
            Mode::Whole,
            option_names,
            "имена опций 1..60 и неизвестные (src/proto-coap.c:469-496)",
        ),
        with(
            "coap-option-extended",
            COOKIE,
            false,
            Mode::Whole,
            ext,
            "дельта и длина 14 (+269) и 13 (+13) со значениями",
        ),
        with(
            "coap-content-format-sweep",
            COOKIE,
            false,
            Mode::Sweep(5),
            link_reply(b"</a>;ct=0,</b>"),
            "значение Content-Format 0..255: text-plain, link-format со ссылками, xml, octet-stream, exi, json, \
             прочие (src/proto-coap.c:504-525)",
        ),
        with(
            "coap-content-format-5-bytes",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[
                &header(0, CONTENT, ID),
                &[0xC5, 1, 0, 0, 0, 40, 0xFF],
                b"</a>,</b>",
            ]),
            "Content-Format из 5 байт: старший теряется (unsigned), остаётся 40",
        ),
        with(
            "coap-no-content-format",
            COOKIE,
            false,
            Mode::Whole,
            cat(&[&header(0, CONTENT, ID), &[0xB1, b'a', 0xFF], b"hello"]),
            "без Content-Format: ` text-plain` (content_format по умолчанию 0)",
        ),
        with(
            "coap-empty-ack",
            COOKIE,
            false,
            Mode::Whole,
            header(0, 0, ID),
            "пустой ACK 0.00: класс 0, `PARSE_ERR` в скобках",
        ),
        with(
            "coap-link-param-at-59",
            COOKIE,
            false,
            Mode::Whole,
            param_value_at(59),
            "`offset == ';'` (src/proto-coap.c:239): значение параметра на смещении 59 уводит в имя, ссылка </b> теряется",
        ),
        with(
            "coap-link-param-at-58",
            COOKIE,
            false,
            Mode::Whole,
            param_value_at(58),
            "то же на смещении 58: обе ссылки",
        ),
        with(
            "coap-link-quoted",
            COOKIE,
            false,
            Mode::Whole,
            link_reply(br#"</sensors/temp>;if="se\"\;\,\<\>\\nsor",</success>"#),
            "кавычки и экранирование в параметре (первый selftest parse_links, src/proto-coap.c:653-660)",
        ),
        with(
            "coap-link-invalid",
            COOKIE,
            false,
            Mode::Whole,
            link_reply(b"  <a> , <b>x,<c>"),
            "пробелы допустимы, мусор после `>` останавливает разбор ссылок",
        ),
    ]
}
