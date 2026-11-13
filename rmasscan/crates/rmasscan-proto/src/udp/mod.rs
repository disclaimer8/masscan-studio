//! UDP-ответы, из которых C делает баннеры: `handle_udp` (`src/proto-udp.c:54-132`) и парсеры портов 53, 123, 137,
//! 161, 500, 5683, 11211 и ZeroAccess 16464/16465/16470/16471 (`src/proto-dns.c`, `src/proto-ntp.c`,
//! `src/proto-netbios.c`, `src/proto-snmp.c`, `src/proto-isakmp.c`, `src/proto-coap.c`, `src/proto-memcached.c`,
//! `src/proto-zeroaccess.c`). Остальные порты идут веткой `default`.
//!
//! Все парсеры работают с полезной нагрузкой датаграммы (у C `px + parsed->app_offset`, `parsed->app_length`).
//! Четыре парсера C получают весь кадр и абсолютные смещения; здесь смещения считаются от начала датаграммы.
//!
//! **Правило для всех парсеров: читается только датаграмма, и ничего не выводится из байтов, которые не пришли.** Там,
//! где C читает за её концом, он читает память захвата (дополнение кадра, FCS, остаток буфера), и его вывод там не
//! функция ответа (Р1 классы а и в). У нас такое чтение ведёт себя так, как C ведёт себя у собственной границы чтения
//! в том же месте: длина TXT и NBSTAT по датаграмме вместо кадра, `e_next_*` ISAKMP за концом датаграммы даёт одни
//! единицы без сдвига (как за `max`), сырой баннер это сама датаграмма, байты, которых нет, ни с чем не совпадают.
//!
//! Отличия от C (Р1 классы а, б и в, Р2, Р5), каждое с эталоном в `tests/golden/udp-banners`:
//! - сырой баннер на 11211 и портах без парсера: у C чтение за концом датаграммы (`src/proto-udp.c:97-101, 108-112,
//!   129`), у нас сама датаграмма;
//! - указатель сжатия DNS/NBNS у C адресует кадр (`src/proto-dns.c:69`, `px` это кадр), у нас сообщение DNS. Проверка
//!   имени у C читает байты канального и IP-заголовков, и результат зависит от канала, семейства, VLAN и адресов, а
//!   не от ответа (Р1 классы а и в). Обычный `c0 0c` попадает на байт 12 кадра: в Ethernet + IPv4 это 0x08, имя
//!   проходит случайно, и C совпадает с нами; в Ethernet + IPv6 (0x86) и с тегом 802.1Q (0x81) это ошибка
//!   (`src/proto-dns.c:61-62`), без канального заголовка там адрес источника IPv4. Тогда **везде, где мы печатаем
//!   dns-ver или nbtstat для ответа со сжатым именем ответа, C печатает только сырой баннер**. Ответ с RCODE 1-9 C
//!   печатает до проверки имени, тут C совпадает с нами. Два случая идут иначе: ответ с OPT EDNS0 теряет расширенный
//!   RCODE (C печатает строку базового RCODE и сырой, мы текст TXT: `dns-edns-ext-rcode-nxdomain`), а указатель в
//!   байты заголовков (`dns-pointer-to-id`, `dns-pointer-chain-5`, `dns-pointer-loop`) у C проходит проверку и даёт
//!   dns-ver там, где у нас сырой баннер. Измерено оракулом в кадрах `eth`, `eth6`, `vlan`, `rawip` (README эталонов,
//!   виды `NameRejectedInFrame`, `ExtRcodeLost`, `NameAcceptedInFrame` в `FRAME_DIFFS` в `tests/udp_golden.rs`);
//! - TXT и NBSTAT C читает против длины кадра (`src/proto-dns.c:420-434`, `src/proto-netbios.c:145-166`), у нас против
//!   длины датаграммы. Дополнение Ethernet до 60 байт на результат не влияет (запись начинается не раньше байта 54
//!   кадра, и `offset + 10 >= length` срабатывает раньше), а хвост за IP-датаграммой (FCS, если захват его
//!   оставляет) C читает в текст dns-ver и в MAC NBSTAT;
//! - неинициализированные `id` и `rr_offset[]` у C (`src/proto-dns.c:205-206, 419`, `src/proto-netbios.c:144`): у нас
//!   короткая датаграмма не совпадает с cookie, а отсутствующая запись даёт сырой баннер;
//! - `dns_extract_name` (`src/proto-dns.c:318`) не переносится: её результат никто не читает, а у C она читает
//!   неинициализированный `rr_offset[0]` ответа без записей (ASan: чтение за буфером);
//! - `asn1_integer` у C читает байт тега без проверки границы (`src/proto-snmp.c:151`, на 1 байт за датаграммой); вывод
//!   от этого байта не зависит;
//! - ISAKMP: конец вложенной нагрузки C берёт из её поля длины и читает за датаграммой (`src/proto-isakmp.c:49`,
//!   `:246`); у нас конец не дальше датаграммы (правило выше), разделы, где это меняет вывод, закреплены в
//!   `PAST_DATAGRAM` в `tests/udp_golden.rs`. Цикл по нагрузкам, предложениям, преобразованиям или атрибутам, шаг
//!   которого не сдвинул смещение, у C вечный (`src/proto-isakmp.c:68-70, 146, 191, 372`), у нас этот шаг последний
//!   (`C_HANGS`). Текст ISAKMP растёт квадратично от длины датаграммы; он обрезается ровно на 65 536 байтах (Р5), и
//!   разбор на этом кончается (`isakmp.rs`);
//! - ZeroAccess: датаграмму длиннее 2048 байт C проверяет CRC по стеку за буфером (`src/proto-zeroaccess.c:176, 208`),
//!   у нас она не ZeroAccess; `banout` без `max_length` (`src/proto-zeroaccess.c:183-185`) у нас обычный баннер
//!   (`zeroaccess.rs`);
//! - memcached: в состоянии «до конца строки» C читает `px[length]` (`src/proto-memcached.c:165`), вывод от него не
//!   зависит, у нас не читается (`memcached_text.rs`).

mod coap;
mod dns;
mod isakmp;
mod memcached;
mod netbios;
mod ntp;
mod snmp;
mod zeroaccess;

use crate::app::app_id;

/// Один UDP-ответ глазами парсеров C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpContext {
    /// Порт источника ответа: парсер выбирается только по нему (`src/proto-udp.c:76`).
    pub port_them: u16,
    /// `(unsigned)syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy)` (`src/proto-dns.c:369`,
    /// справка B10): его вычисляет приём, маску протокола (`& 0xFFFF`, `& 0x7FFFFFFF`) накладывает парсер.
    pub cookie: u32,
    /// `--rawudp` (`out->is_banner_rawudp`, `src/proto-udp.c:120`).
    pub rawudp: bool,
}

/// Что парсер вернул в `status` (`src/proto-udp.c:61`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    /// 0: следом сырой баннер.
    Fallback,
    /// 1: разобрано или отброшено по cookie; сырой баннер только с `--rawudp`.
    Handled,
}

/// Баннеры одного ответа в порядке C (справка B0): `(номер приложения, байты)`. Запись статуса `open udp` сюда не
/// входит, её пишет движок (`src/proto-udp.c:63-73`).
pub fn handle_udp(cx: &UdpContext, payload: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    // src/proto-udp.c:76-113
    let status = match cx.port_them {
        53 => dns::handle_dns(cx, payload, &mut out),
        123 => ntp::ntp_handle_response(payload, &mut out),
        137 => netbios::handle_nbtstat(cx, payload, &mut out),
        161 => snmp::handle_snmp(cx, payload, &mut out),
        500 => isakmp::isakmp_parse(cx, payload, &mut out),
        5683 => coap::coap_handle_response(cx, payload, &mut out),
        11211 => memcached::memcached_udp_parse(cx, payload, &mut out),
        16464 | 16465 | 16470 | 16471 => zeroaccess::handle_zeroaccess(payload, &mut out),
        _ => default_udp_parse(payload, &mut out),
    };
    // src/proto-udp.c:120-131: вся датаграмма (у C на 11211 и в default чтение за её концом, Р2).
    if status == Status::Fallback || cx.rawudp {
        out.push((app_id::NONE, payload.to_vec()));
    }
    out
}

/// [`handle_udp`] по полям [`UdpContext`]: форма `rmasscan_engine::UdpBannerParser`, которую движок получает в
/// `BannerOptions::udp_parser` (от этого крейта он не зависит). Одна на CLI и тесты движка.
pub fn udp_banner_parser(
    port_them: u16,
    cookie: u32,
    rawudp: bool,
    payload: &[u8],
) -> Vec<(u16, Vec<u8>)> {
    handle_udp(
        &UdpContext {
            port_them,
            cookie,
            rawudp,
        },
        payload,
    )
}

/// `default_udp_parse` (`src/proto-udp.c:27-50`): первые 64 байта как `unknown`, возврат 0.
fn default_udp_parse(px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    out.push((app_id::NONE, px.get(..64).unwrap_or(px).to_vec()));
    Status::Fallback
}

/// Байт по смещению или `None` за концом.
fn byte(px: &[u8], at: usize) -> Option<u8> {
    px.get(at).copied()
}

/// Big-endian u16 по смещению или `None`, если не помещается.
fn be16(px: &[u8], at: usize) -> Option<u16> {
    Some(u16::from(byte(px, at)?) << 8 | u16::from(byte(px, at.checked_add(1)?)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app_name;
    use crate::banner::MAX_BANNER_BYTES;

    const COOKIE: u32 = 0x5EED_1234;

    fn cx(port_them: u16, rawudp: bool) -> UdpContext {
        UdpContext {
            port_them,
            cookie: COOKIE,
            rawudp,
        }
    }

    /// Номера и имена приложений UDP-баннеров (`src/masscan-app.h:8-49`): они пишутся в `-oB`.
    #[test]
    fn udp_app_ids_are_pinned() {
        for (id, want, name) in [
            (app_id::NONE, 0, "unknown"),
            (app_id::DNS_VERSIONBIND, 6, "dns-ver"),
            (app_id::SNMP, 7, "snmp"),
            (app_id::NBTSTAT, 8, "nbtstat"),
            (app_id::ZEROACCESS, 14, "zeroaccess"),
            (app_id::NTP, 19, "ntp"),
            (app_id::MEMCACHED, 25, "memcached"),
            (app_id::COAP, 28, "coap"),
            (app_id::ISAKMP, 35, "isakmp"),
        ] {
            assert_eq!(id, want, "{name}");
            assert_eq!(app_name(id), name);
        }
    }

    #[test]
    fn default_port_gives_def64_and_raw() {
        let px: Vec<u8> = (0..100u8).collect();
        let got = handle_udp(&cx(9999, false), &px);
        assert_eq!(got, vec![(0, px[..64].to_vec()), (0, px.clone())]);
        // --rawudp ничего не добавляет: status уже 0.
        assert_eq!(handle_udp(&cx(9999, true), &px), got);
        assert_eq!(
            handle_udp(&cx(0, false), &[]),
            vec![(0, vec![]), (0, vec![])]
        );
    }

    /// Детерминированный xorshift64*: тест не зависит от внешних крейтов и воспроизводим.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).expect("n")).expect("index")
        }
        fn byte(&mut self) -> u8 {
            self.next().to_le_bytes()[0]
        }
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Правдоподобные ответы для мутаций и cookie, с которым каждый проходит проверку: вектор selftest SNMP
    /// (`src/proto-snmp.c:630-644`), ответ CHAOS TXT, NBSTAT, MON_GETLIST_1, `sample1` ISAKMP
    /// (`src/proto-isakmp.c:464-471`), ACK CoAP 2.05 с link-format и `stats` memcached.
    fn seeds() -> Vec<(u16, u32, Vec<u8>)> {
        vec![
            (
                161,
                0x26,
                hex("3039020100 04067075626c6963 a22c 020126 020100 020100 3021 301f 06092b0601800201010200
                     06122b06010401 8f5101010182295d011b020201"),
            ),
            (
                53,
                COOKIE,
                hex("1234 8400 0001 0001 0000 0000 0776657273696f6e 0462696e64 00 0010 0003
                     c00c 0010 0003 00000000 0008 07 392e31382e3234"),
            ),
            (
                137,
                COOKIE,
                hex("1234 8400 0000 0001 0000 0000 0141 00 0021 0001 00000000 0019
                     01 484f53543120202020202020202020 20 0400 525400123456"),
            ),
            (123, COOKIE, hex("97 00 03 2a 00 01 00 08 0102030405060708")),
            (
                500,
                0xC118_84DA,
                hex("00000000c11884da be3dc68eeaf2daac 01100200 00000000 00000050 00000034 00000001
                     00000001 00000028 01010001 00000020 01010000 80010005 80020002 80040002 80030001
                     800b0001 800c0001"),
            ),
            (
                5683,
                COOKIE,
                [
                    &[0x62, 0x45, 0x12, 0x34, 0xAB, 0xCD, 0xC1, 40, 0xFF][..],
                    b"</.well-known/core>;ct=40,</sensors/temp>;if=\"sensor\",</light>;rt=\"light-lux\"",
                ]
                .concat(),
            ),
            (
                11211,
                COOKIE,
                [
                    &[0x12, 0x34, 0, 0, 0, 1, 0, 0][..],
                    b"STAT pid 1234\r\nSTAT uptime 12345\r\nSTAT time 1700000000\r\nSTAT version 1.6.21\r\nEND\r\n",
                ]
                .concat(),
            ),
        ]
    }

    /// Одна-четыре мутации: замена байта, обрезка, вставка, хвост.
    fn mutate(rng: &mut Rng, px: &mut Vec<u8>) {
        for _ in 0..=rng.below(4) {
            match rng.below(4) {
                0 if !px.is_empty() => {
                    let i = rng.below(px.len());
                    px[i] = rng.byte();
                }
                1 => px.truncate(rng.below(px.len() + 1)),
                2 => {
                    let i = rng.below(px.len() + 1);
                    px.insert(i, rng.byte());
                }
                _ => {
                    let n = rng.below(64);
                    px.extend((0..n).map(|_| rng.byte()));
                }
            }
        }
    }

    /// Р1 класс б и задача: случайные датаграммы 0..2000 байт на каждом порту и мутации правдоподобных ответов не
    /// роняют ни один парсер, а сырой баннер всегда равен датаграмме.
    #[test]
    fn udp_parsers_never_panic() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let ports = [
            53u16, 123, 137, 161, 7, 500, 5683, 11211, 16464, 16465, 16470, 16471,
        ];
        for &port in &ports {
            for _ in 0..3000 {
                let len = rng.below(2001);
                let px: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                for rawudp in [false, true] {
                    let c = UdpContext {
                        port_them: port,
                        cookie: u32::try_from(rng.next() >> 32).expect("u32"),
                        rawudp,
                    };
                    check_invariants(&c, &px);
                }
            }
        }
        let rounds = 20_000u32;
        for (port, cookie, seed) in seeds() {
            // Досягаемость: сколько мутаций дошло до баннера парсера (не только сырого).
            let mut reached = 0u32;
            for _ in 0..rounds {
                let mut px = seed.clone();
                mutate(&mut rng, &mut px);
                let c = UdpContext {
                    port_them: port,
                    cookie,
                    rawudp: rng.below(2) == 1,
                };
                if check_invariants(&c, &px) {
                    reached += 1;
                }
            }
            // Мутации не превращаются в один шум: заметная доля доходит до текста парсера.
            assert!(
                reached * 5 > rounds,
                "port {port}: only {reached} of {rounds} mutations reached the parser text"
            );
        }
        // ZeroAccess: любая мутация шифротекста ломает CRC, поэтому мутируется открытый текст `retL` и шифруется
        // заново с верной CRC.
        let plain = [
            &[0u8; 4][..],
            b"Lter",
            b"mass",
            &3u32.to_le_bytes(),
            &[192, 0, 2, 10, 0, 0, 0, 1],
            &[198, 51, 100, 20, 0, 0, 0, 2],
            &[203, 0, 113, 30, 0, 0, 0, 3],
        ]
        .concat();
        let mut reached = 0u32;
        for _ in 0..rounds {
            let mut px = plain.clone();
            mutate(&mut rng, &mut px);
            let c = UdpContext {
                port_them: 16464,
                cookie: 0,
                rawudp: rng.below(2) == 1,
            };
            if check_invariants(&c, &zeroaccess::seal(&px)) {
                reached += 1;
            }
        }
        assert!(
            reached * 5 > rounds,
            "zeroaccess: only {reached} of {rounds} mutations reached the parser text"
        );
    }

    /// Проверяет инварианты ответа и говорит, дошёл ли он до текста парсера.
    fn check_invariants(c: &UdpContext, px: &[u8]) -> bool {
        let got = handle_udp(c, px);
        // Сырой баннер, если есть, последний и равен датаграмме; кроме него не больше двух баннеров.
        assert!(got.len() <= 3, "{got:?}");
        if c.rawudp {
            assert_eq!(got.last(), Some(&(app_id::NONE, px.to_vec())));
        }
        for (app, bytes) in &got {
            assert!(
                [
                    app_id::NONE,
                    app_id::DNS_VERSIONBIND,
                    app_id::SNMP,
                    app_id::NBTSTAT,
                    app_id::NTP,
                    app_id::ISAKMP,
                    app_id::COAP,
                    app_id::MEMCACHED,
                    app_id::ZEROACCESS,
                ]
                .contains(app),
                "app {app}"
            );
            // Любая запись не длиннее предела Р5.
            assert!(bytes.len() <= MAX_BANNER_BYTES, "{}", bytes.len());
            // Текст всех парсеров, кроме ISAKMP, линеен по датаграмме: самое длинное на байт входа это имя опции
            // CoAP (17 байт ` /Content-Format/` на однобайтовую опцию с дельтой 0). Текст ISAKMP растёт квадратично
            // (`isakmp.rs`) и ограничен только пределом Р5.
            assert!(
                *app == app_id::ISAKMP || bytes.len() <= 20 * px.len() + 64,
                "{} > {}",
                bytes.len(),
                px.len()
            );
        }
        got.iter().any(|(app, _)| *app != app_id::NONE)
    }
}
