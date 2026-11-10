//! Нагрузки UDP-зондов (AGPL-3.0): 28 встроенных записей masscan, мутации cookie и загрузчики `--nmap-payloads` и
//! `--pcap-payloads`. Порт `src/templ-payloads.c` (таблица `hard_coded_udp_payloads` :66-472, `payloads_udp_lookup`,
//! `payloads_datagram_add`, `payloads_read_pcap`), `src/templ-nmap-payloads.c` и `set_cookie`-функций `proto-dns.c:334`,
//! `proto-ntp.c:22`, `proto-snmp.c:403`, `proto-isakmp.c:446`, `proto-coap.c:594`, `proto-memcached.c:397`, masscan ©
//! Robert David Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Встроенные 28 нагрузок это собственный код masscan (AGPL-3.0), перенесённый дословно. Ничего из `nmap-payloads` Nmap
//! (лицензия NPSL) в порт не входит: файл пользователя читается только в рантайме по его просьбе.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::targets::{is_c_space, strtoul0};

/// `length == 0xFFFFFFFF` в таблице C значит "длина строки" (templ-payloads.c:571).
const LEN_STRLEN: u32 = 0xFFFF_FFFF;
/// `zeroaccess_getL_length` (proto-zeroaccess.h:15).
const ZEROACCESS_LEN: u32 = 16;
/// `zeroaccess_getL` (proto-zeroaccess.c:23): "getL" с id `mass`, уже с CRC и зашифрованный.
const ZEROACCESS_GETL: [u8; 16] = [
    0x46, 0x5d, 0x49, 0x9e, 0x28, 0x94, 0x8d, 0xab, 0xc9, 0xc0, 0xd1, 0x99, 0xe0, 0xf2, 0xc2, 0x5e,
];

/// Верхняя граница нагрузки: буфер кадра в C 2048 байт (`main.c` `px[2048]`, `template_set_target_ipv4` обрезает
/// `r_length` до `sizeof_px`), минус 42 байта заголовков. C молча режет длиннее, порт отказывает при загрузке.
pub const MAX_PAYLOAD_LEN: usize = 2048 - 42;
/// `unsigned char buf[1500]` разбора `nmap-payloads` (templ-nmap-payloads.c:216): `append_byte` молча отбрасывает лишнее.
const NMAP_STRING_MAX: usize = 1500;

/// Мутатор cookie (`SET_COOKIE`, templ-payloads.h): вписывает младшие биты `seqno` в нагрузку, чтобы ответ можно было
/// связать с зондом. В C `seqno` это `unsigned` (`udp_payload_fixup`, templ-pkt.c:618), в `uint64_t` он попадает
/// с нулевой старшей половиной.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CookieMutator {
    /// `dns_set_cookie` (DNS 53, портмаппер 111, NBNS 137, NFS 2049): первые два байта.
    Dns,
    /// `ntp_set_cookie`: ничего не делает.
    Ntp,
    /// `snmp_set_cookie` (161): request-id PDU.
    Snmp,
    /// `isakmp_set_cookie` (500): восемь байт `init_cookie`.
    Isakmp,
    /// `coap_udp_set_cookie` (5683): message id, байты 2 и 3.
    Coap,
    /// `memcached_udp_set_cookie` (11211): request id, байты 0 и 1.
    Memcached,
}

impl CookieMutator {
    /// Применяет мутацию к нагрузке на месте. Длина берётся из среза, как `length` в C.
    pub fn apply(self, px: &mut [u8], seqno: u32) {
        match self {
            // proto-dns.c:334: `length > 2`.
            CookieMutator::Dns if px.len() > 2 => {
                px[0] = (seqno >> 8) as u8;
                px[1] = seqno as u8;
            }
            CookieMutator::Dns | CookieMutator::Ntp => {}
            CookieMutator::Snmp => snmp_set_cookie(px, seqno),
            // proto-isakmp.c:446: `seqno >> (56 - 8*i)`; `seqno` 32-битный, поэтому первые 4 байта нулевые.
            CookieMutator::Isakmp if px.len() >= 8 => {
                for (i, b) in px.iter_mut().take(8).enumerate() {
                    *b = (u64::from(seqno) >> (56 - 8 * i)) as u8;
                }
            }
            CookieMutator::Isakmp => {}
            // proto-coap.c:594: `length < 4` выходит.
            CookieMutator::Coap if px.len() >= 4 => {
                px[2] = (seqno >> 8) as u8;
                px[3] = seqno as u8;
            }
            CookieMutator::Coap => {}
            // proto-memcached.c:397: `length < 2` выходит.
            CookieMutator::Memcached if px.len() >= 2 => {
                px[0] = (seqno >> 8) as u8;
                px[1] = seqno as u8;
            }
            CookieMutator::Memcached => {}
        }
    }
}

// --- ASN.1 для SNMP (proto-snmp.c:105-185). C читает `px[offset]` без проверки границ; здесь за границей 0. ---

fn at(px: &[u8], i: u64) -> u8 {
    usize::try_from(i)
        .ok()
        .and_then(|i| px.get(i))
        .copied()
        .unwrap_or(0)
}

/// proto-snmp.c:180 `asn1_tag`.
fn asn1_tag(px: &[u8], length: u64, offset: &mut u64) -> u32 {
    if *offset >= length {
        return 0;
    }
    let t = u32::from(at(px, *offset));
    *offset += 1;
    t
}

/// proto-snmp.c:106 `asn1_length`.
fn asn1_length(px: &[u8], length: u64, offset: &mut u64) -> u64 {
    let first = u64::from(at(px, *offset));
    if *offset >= length || (first & 0x80 != 0 && *offset + (first & 0x7F) >= length) {
        *offset = length;
        return 0xFFFF_FFFF;
    }
    let mut result = first;
    *offset += 1;
    if result & 0x80 != 0 {
        let mut length_of_length = result & 0x7F;
        if length_of_length == 0 {
            *offset = length;
            return 0xFFFF_FFFF;
        }
        result = 0;
        while length_of_length != 0 {
            result = result * 256 + u64::from(at(px, *offset));
            *offset += 1;
            if result > 0x10000 {
                *offset = length;
                return 0xFFFF_FFFF;
            }
            length_of_length -= 1;
        }
    }
    result
}

/// proto-snmp.c:146 `asn1_integer`.
fn asn1_integer(px: &[u8], length: u64, offset: &mut u64) -> u64 {
    let tag = at(px, *offset);
    *offset += 1;
    if tag != 0x02 {
        *offset = length;
        return 0xFFFF_FFFF;
    }
    let int_length = asn1_length(px, length, offset);
    if int_length == 0xFFFF_FFFF || *offset + int_length > length || int_length > 20 {
        *offset = length;
        return 0xFFFF_FFFF;
    }
    let mut result = 0u64;
    for _ in 0..int_length {
        result = result
            .wrapping_mul(256)
            .wrapping_add(u64::from(at(px, *offset)));
        *offset += 1;
    }
    result
}

/// proto-snmp.c:403 `snmp_set_cookie`: идёт по BER до request-id PDU и пишет туда `seqno` (старший бит чистится, чтобы
/// INTEGER остался положительным).
fn snmp_set_cookie(px: &mut [u8], seqno: u32) {
    let mut length = px.len() as u64;
    let mut offset = 0u64;
    if asn1_tag(px, length, &mut offset) != 0x30 {
        return;
    }
    let outer = asn1_length(px, length, &mut offset);
    if length > outer + offset {
        length = outer + offset;
    }
    if asn1_integer(px, length, &mut offset) != 0 {
        return; // версия 0
    }
    if asn1_tag(px, length, &mut offset) != 0x04 {
        return; // community
    }
    let community_len = asn1_length(px, length, &mut offset);
    offset += community_len;
    let tag = asn1_tag(px, length, &mut offset);
    if !(0xA0..=0xA5).contains(&tag) {
        return;
    }
    let outer = asn1_length(px, length, &mut offset);
    if length > outer + offset {
        length = outer + offset;
    }
    asn1_tag(px, length, &mut offset); // тег request-id
    let len = asn1_length(px, length, &mut offset);
    let be = seqno.to_be_bytes();
    let bytes: &[u8] = match len {
        1 => &[be[3] & 0x7F],
        2 => &[be[2] & 0x7F, be[3]],
        3 => &[be[1] & 0x7F, be[2], be[3]],
        4 => &[be[0] & 0x7F, be[1], be[2], be[3]],
        5 => &[0, be[0], be[1], be[2], be[3]],
        _ => return,
    };
    for (k, b) in bytes.iter().enumerate() {
        if let Some(slot) = usize::try_from(offset + k as u64)
            .ok()
            .and_then(|i| px.get_mut(i))
        {
            *slot = *b;
        }
    }
}

/// Запись таблицы C (`struct PayloadUDP_Default`, templ-payloads.c:38): `buf` склеена из строковых литералов исходника.
struct Builtin {
    port: u16,
    /// Не используется ни в C (`source_port = 0x1000` по умолчанию в `udp_payload_fixup` и дальше не читается), ни здесь.
    source_port: u32,
    /// Автор C задаёт длину отдельно от строки: `masscan-test 0x00000000` на порту 7 уходит длиной 12.
    length: u32,
    set_cookie: Option<CookieMutator>,
    buf: &'static [&'static [u8]],
}

/// `hard_coded_udp_payloads` (templ-payloads.c:66-472) в порядке исходника.
const BUILTIN: &[Builtin] = &[
    // ECHO: отражает всё, что получил
    Builtin {
        port: 7,
        source_port: 65536,
        length: 12,
        set_cookie: None,
        buf: &[b"masscan-test 0x00000000"],
    },
    // QOTD, цитата дня (усилитель)
    Builtin {
        port: 17,
        source_port: 65536,
        length: 12,
        set_cookie: None,
        buf: &[b"masscan-test"],
    },
    // chargen (усилитель)
    Builtin {
        port: 19,
        source_port: 65536,
        length: 12,
        set_cookie: None,
        buf: &[b"masscan-test"],
    },
    // DNS, запрос version.bind TXT CHAOS (cookie в txid)
    Builtin {
        port: 53,
        source_port: 65536,
        length: 0x1f,
        set_cookie: Some(CookieMutator::Dns),
        buf: &[
            b"P\xb6",
            b"\x01 ",
            b"\x00\x01",
            b"\x00\x00\x00\x00\x00\x00",
            b"\x07",
            b"version",
            b"\x04",
            b"bind",
            b"\x00",
            b"\x00\x10",
            b"\x00\x03",
        ],
    },
    // TFTP, чтение файла
    Builtin {
        port: 69,
        source_port: 65536,
        length: 24,
        set_cookie: None,
        buf: &[b"\x00\x01", b"masscan-test", b"\x00", b"netascii", b"\x00"],
    },
    // portmapper, ONC RPC NULL (cookie в первых двух байтах xid)
    Builtin {
        port: 111,
        source_port: 65536,
        length: 40,
        set_cookie: Some(CookieMutator::Dns),
        buf: &[
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x02",
            b"\x00\x01\x86\xa0",
            b"\x00\x00\x00\x02",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // NTP
    Builtin {
        port: 123,
        source_port: 65536,
        length: 48,
        set_cookie: Some(CookieMutator::Ntp),
        buf: &[
            b"\x17\x00\x03*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // NetBIOS Name Service NBSTAT
    Builtin {
        port: 137,
        source_port: 65536,
        length: 50,
        set_cookie: Some(CookieMutator::Dns),
        buf: &[
            b"\xab\x12",
            b"\x00\x00",
            b"\x00\x01\x00\x00\x00\x00\x00\x00",
            b" ",
            b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            b"\x00",
            b"\x00!",
            b"\x00\x01",
        ],
    },
    // NetBIOS-SMB BROWSER
    Builtin {
        port: 138,
        source_port: 65536,
        length: 174,
        set_cookie: None,
        buf: &[
            b"\x11",
            b"\n",
            b"\xc1\x00",
            b"\n\x01\x01\xd5",
            b"\x00\x8a",
            b"\x00\xa0",
            b"\x00\x00",
            b" ",
            b"ENEBFDFDEDEBEOCNFEEFFDFECACACAAA",
            b"\x00",
            b" ",
            b"FHEPFCELEHFCEPFFFACACACACACACABN",
            b"\x00",
            b"\xffSMB%\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x11\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8\x03\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x06\x00V\x00\x03\x00\x01\x00\x01",
            b"\x00\x02\x00\x17\x00\\MAILSLOT\\B",
            b"ROWSE\x00",
            b"\x09\x04\x01\x00\x00\x00",
        ],
    },
    // SNMP GET sysName/sysDesc, community public (cookie в request-id)
    Builtin {
        port: 161,
        source_port: 65536,
        length: 59,
        set_cookie: Some(CookieMutator::Snmp),
        buf: &[
            b"0",
            b"9",
            b"\x02\x01\x00",
            b"\x04\x06",
            b"public",
            b"\xa0",
            b",",
            b"\x02\x04\x00\x00\x00\x00",
            b"\x02\x01\x00",
            b"\x02\x01\x00",
            b"0\x1e",
            b"0\r",
            b"\x06\x09+\x06\x01\x80\x02\x01\x01\x01\x00",
            b"\x05\x00",
            b"0\r",
            b"\x06\x09+\x06\x01\x80\x02\x01\x01\x05\x00",
            b"\x05\x00",
        ],
    },
    // DTLS ClientHello
    Builtin {
        port: 443,
        source_port: 65536,
        length: 115,
        set_cookie: None,
        buf: &[
            b"\x16",
            b"\xfe\xff",
            b"\x00\x00",
            b"\x00\x00\x00\x00\x00\x07",
            b"\x00f",
            b"\x01",
            b"\x00\x00Z",
            b"\x00\x00",
            b"\x00\x00\x00",
            b"\x00\x00Z",
            b"\xfe\xfd",
            b"\x1d\xb1\xe3R.\x89\x94\xb7\x153/0\xff\xff\xcfv",
            b"'w\xab\x04\xe4\x86o!\x18\x0e\xf8\xddp\xcc\xab\x9e",
            b"\x00",
            b"\x00",
            b"\x00\x04",
            b"\xc00",
            b"\x00\xff",
            b"\x01",
            b"\x00",
            b"\x00,",
            b"\x00\x0b\x00\x04\x03\x00\x01\x02",
            b"\x00\n\x00\x0c\x00\n\x00\x1d\x00\x17\x00\x1e\x00\x19\x00\x18",
            b"\x00#\x00\x00",
            b"\x00\x16\x00\x00",
            b"\x00\x17\x00\x00",
            b"\x00\r\x00\x04\x00\x02\x05\x01",
        ],
    },
    // RIP, запрос таблицы
    Builtin {
        port: 520,
        source_port: 65536,
        length: 24,
        set_cookie: None,
        buf: &[
            b"\x01",
            b"\x01",
            b"\x00\x00",
            b"\x00\x02",
            b"\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x10",
        ],
    },
    // RADIUS access-request
    Builtin {
        port: 1645,
        source_port: 65536,
        length: 20,
        set_cookie: None,
        buf: &[
            b"\x01",
            b"\x00",
            b"\x00\x14",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // RADIUS access-request
    Builtin {
        port: 1812,
        source_port: 65536,
        length: 20,
        set_cookie: None,
        buf: &[
            b"\x01",
            b"\x00",
            b"\x00\x14",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // RADIUS (opcode 4)
    Builtin {
        port: 1646,
        source_port: 65536,
        length: 20,
        set_cookie: None,
        buf: &[
            b"\x04",
            b"\x00",
            b"\x00\x14",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // RADIUS (opcode 4)
    Builtin {
        port: 1813,
        source_port: 65536,
        length: 20,
        set_cookie: None,
        buf: &[
            b"\x04",
            b"\x00",
            b"\x00\x14",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // L2TP
    Builtin {
        port: 1701,
        source_port: 65536,
        length: 60,
        set_cookie: None,
        buf: &[
            b"\xc8\x02",
            b"\x00<",
            b"\x00\x00",
            b"\x00\x00",
            b"\x00\x00",
            b"\x00\x00",
            b"\x80\x08\x00\x00\x00\x00\x00\x01",
            b"\x80\x08\x00\x00\x00\x02\x01\x00",
            b"\x80\x0e\x00\x00\x00\x07",
            b"masscan1",
            b"\x80\n\x00\x00\x00\x03\x00\x00\x00\x03",
            b"\x80\x08\x00\x00\x00\x09\x00\x00",
        ],
    },
    // UPnP SSDP M-SEARCH
    Builtin {
        port: 1900,
        source_port: 65536,
        length: LEN_STRLEN,
        set_cookie: None,
        buf: &[
            b"M-SEARCH * HTTP/1.1\r\n",
            b"HOST: 239.255.255.250:1900\r\n",
            b"MAN: \"ssdp:discover\"\r\n",
            b"MX: 1\r\n",
            b"ST: ssdp:all\r\n",
            b"USER-AGENT: unix/1.0 UPnP/1.1 masscan/1.x\r\n",
        ],
    },
    // NFS, ONC RPC NULL (cookie, как у DNS: первые два байта)
    Builtin {
        port: 2049,
        source_port: 65536,
        length: 40,
        set_cookie: Some(CookieMutator::Dns),
        buf: &[
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x02",
            b"\x00\x01\x86\xa3",
            b"\x00\x00\x00\x02",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
    },
    // SIP OPTIONS
    Builtin {
        port: 5060,
        source_port: 65536,
        length: LEN_STRLEN,
        set_cookie: None,
        buf: &[
            b"OPTIONS sip:carol@chicago.com SIP/2.0\r\n",
            b"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bKhjhs8ass877\r\n",
            b"Max-Forwards: 70\r\n",
            b"To: <sip:carol@chicago.com>\r\n",
            b"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n",
            b"Call-ID: a84b4c76e66710\r\n",
            b"CSeq: 63104 OPTIONS\r\n",
            b"Contact: <sip:alice@pc33.atlanta.com>\r\n",
            b"Accept: application/sdp\r\n",
            b"Content-Length: 0\r\n",
        ],
    },
    // CoAP GET /.well-known/core (cookie в message id)
    Builtin {
        port: 5683,
        source_port: 65536,
        length: 21,
        set_cookie: Some(CookieMutator::Coap),
        buf: &[
            b"@",
            b"\x01",
            b"\x01\xce",
            b"\xbb",
            b".well-known",
            b"\x04",
            b"core",
        ],
    },
    // memcached "stats" (cookie в request id)
    Builtin {
        port: 11211,
        source_port: 65536,
        length: 15,
        set_cookie: Some(CookieMutator::Memcached),
        buf: &[b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"],
    },
    // ZeroAccess getL
    Builtin {
        port: 16464,
        source_port: 65536,
        length: ZEROACCESS_LEN,
        set_cookie: None,
        buf: &[&ZEROACCESS_GETL],
    },
    // ZeroAccess getL
    Builtin {
        port: 16465,
        source_port: 65536,
        length: ZEROACCESS_LEN,
        set_cookie: None,
        buf: &[&ZEROACCESS_GETL],
    },
    // ZeroAccess getL
    Builtin {
        port: 16470,
        source_port: 65536,
        length: ZEROACCESS_LEN,
        set_cookie: None,
        buf: &[&ZEROACCESS_GETL],
    },
    // ZeroAccess getL
    Builtin {
        port: 16471,
        source_port: 65536,
        length: ZEROACCESS_LEN,
        set_cookie: None,
        buf: &[&ZEROACCESS_GETL],
    },
    // Quake 3 getstatus
    Builtin {
        port: 27960,
        source_port: 65536,
        length: LEN_STRLEN,
        set_cookie: None,
        buf: &[b"\xff\xff\xff\xffgetstatus\x10"],
    },
    // ISAKMP (cookie в init_cookie)
    Builtin {
        port: 500,
        source_port: 500,
        length: 352,
        set_cookie: Some(CookieMutator::Isakmp),
        buf: &[
            b"\x00\x11\"3DUfw",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            b"\x01",
            b"\x10",
            b"\x02",
            b"\x00",
            b"\x00\x00\x00\x00",
            b"\x00\x00\x01`",
            b"\x00",
            b"\x00",
            b"\x01D",
            b"\x00\x00\x00\x01",
            b"\x00\x00\x00\x01",
            b"\x00",
            b"\x00",
            b"\x018",
            b"\x01",
            b"\x01",
            b"\x00",
            b"\r",
            b"",
            b"\x03",
            b"\x00",
            b"\x00 ",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02",
            b"\x80\x0b\x00\x01\x80\x0c\x00\x01",
            b"\x03",
            b"\x00",
            b"\x00 ",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x01\x80\x02\x00\x01\x80\x03\x00\x01\x80\x04\x00\x02",
            b"\x80\x0b\x00\x01\x80\x0c\x00\x01",
            b"\x03",
            b"\x00",
            b"\x00 ",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x07\x80\x02\x00\x04\x80\x03\x00\x01\x80\x04\x00\x0e",
            b"\x80\x0b\x00\x01\x80\x0c\x00\x01",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x02",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x03",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x04",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\x00\x08",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdd",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfa\xdf",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xe9",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xeb",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xed",
            b"\x03",
            b"\x00",
            b"\x00\x14",
            b"\x00",
            b"\x01",
            b"\x00\x00",
            b"\x80\x01\x00\x05\x80\x02\x00\x02\x80\x03\xfd\xef",
            b"\x00",
            b"\x00",
            b"\x00\x08",
            b"\x00",
            b"\x01",
            b"\x00\x00",
        ],
    },
];

/// Одна нагрузка порта (`struct PayloadUDP_Item`, templ-payloads.c:26).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadEntry {
    /// Байты до `set_cookie`.
    pub payload: Arc<[u8]>,
    /// См. [`Builtin::source_port`]: хранится, но нигде не читается.
    pub source_port: u32,
    /// У встроенных записей по таблице, у записей из файлов всегда `None` (`payloads_datagram_add_nocookie`,
    /// templ-payloads.c:407, и `payloads_read_pcap` :504 передают 0): файл заменяет и нагрузку, и мутацию.
    pub set_cookie: Option<CookieMutator>,
}

impl PayloadEntry {
    /// Нагрузка зонда с вписанным cookie (`udp_payload_fixup`, templ-pkt.c:618).
    pub fn with_cookie(&self, seqno: u32) -> Vec<u8> {
        let mut data = self.payload.to_vec();
        if let Some(m) = self.set_cookie {
            m.apply(&mut data, seqno);
        }
        data
    }
}

/// Ошибки загрузки внешних файлов нагрузок.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    /// `templ-nmap-payloads.c:241-282`: C печатает строку в stderr и молча бросает остаток файла; порт отказывает.
    #[error("line {line}: {msg}")]
    Syntax { line: usize, msg: &'static str },
    #[error("capture file: {0}")]
    Pcap(&'static str),
    #[error(
        "payload of {len} bytes for port {port} is longer than the {MAX_PAYLOAD_LEN} bytes a probe can carry"
    )]
    TooLong { port: u32, len: usize },
}

/// Таблица нагрузок UDP по портам назначения (`struct PayloadsUDP`, отсортирована по порту).
#[derive(Clone, Debug)]
pub struct PayloadTable {
    map: BTreeMap<u32, PayloadEntry>,
}

impl Default for PayloadTable {
    fn default() -> Self {
        PayloadTable::builtin()
    }
}

impl PayloadTable {
    /// Пустая таблица (все порты шлют 0-байтовую нагрузку).
    pub fn empty() -> Self {
        PayloadTable {
            map: BTreeMap::new(),
        }
    }

    /// 28 встроенных нагрузок (`payloads_udp_create`, templ-payloads.c:668).
    pub fn builtin() -> Self {
        let mut t = PayloadTable::empty();
        for b in BUILTIN {
            // Литерал C заканчивается нулём: длина 0x1f у DNS (порт 53) считает его (30 байт строки и NUL).
            let mut full: Vec<u8> = b.buf.concat();
            full.push(0);
            let length = if b.length == LEN_STRLEN {
                full.iter().position(|&c| c == 0).unwrap_or(full.len()) // strlen, templ-payloads.c:571
            } else {
                b.length as usize
            };
            // Длина в таблице не бывает больше литерала с нулём (ASan на настоящем C это подтверждает).
            let payload: Arc<[u8]> = Arc::from(&full[..length.min(full.len())]);
            t.map.insert(
                u32::from(b.port),
                PayloadEntry {
                    payload,
                    source_port: b.source_port,
                    set_cookie: b.set_cookie,
                },
            );
        }
        t
    }

    /// `payloads_udp_lookup` (templ-payloads.c:519): нагрузка порта или `None` (тогда шлётся 0 байт, templ-pkt.c:630).
    pub fn get(&self, port: u16) -> Option<&PayloadEntry> {
        self.map.get(&u32::from(port))
    }

    /// Число записей.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Порты таблицы по возрастанию.
    pub fn ports(&self) -> impl Iterator<Item = u32> + '_ {
        self.map.keys().copied()
    }

    /// `payloads_datagram_add` (templ-payloads.c:333): по записи на каждый порт диапазонов, одинаковый порт заменяет
    /// прежнюю запись. Порты вне 16 бит (`U:53` в файле, смещение `Templ_UDP`) никогда не совпадут с поиском, как в C.
    fn add(
        &mut self,
        data: &[u8],
        ranges: &[(u32, u32)],
        source_port: u32,
    ) -> Result<usize, PayloadError> {
        if data.len() > MAX_PAYLOAD_LEN {
            let port = ranges.first().map_or(0, |r| r.0);
            return Err(PayloadError::TooLong {
                port,
                len: data.len(),
            });
        }
        let payload: Arc<[u8]> = Arc::from(data);
        let mut n = 0;
        for &(begin, end) in ranges {
            for port in begin..=end {
                self.map.insert(
                    port,
                    PayloadEntry {
                        payload: payload.clone(),
                        source_port,
                        set_cookie: None,
                    },
                );
                n += 1;
            }
        }
        Ok(n)
    }

    /// `--nmap-payloads` (`read_nmap_payloads`, templ-nmap-payloads.c:215). Возвращает число записанных портов.
    /// Синтаксическая ошибка отказывает целиком: C печатает её в stderr и продолжает скан с тем, что успел прочитать.
    pub fn load_nmap_payloads(&mut self, text: &str) -> Result<usize, PayloadError> {
        self.load_nmap_payloads_bytes(text.as_bytes())
    }

    /// [`PayloadTable::load_nmap_payloads`] для сырых байт файла (C читает файл как есть, без разбора UTF-8).
    pub fn load_nmap_payloads_bytes(&mut self, text: &[u8]) -> Result<usize, PayloadError> {
        let mut lines = NmapLines {
            it: text.split((|b: &u8| *b == b'\n') as fn(&u8) -> bool),
            number: 0,
            cur: Vec::new(),
        };
        let mut added = 0;
        loop {
            let mut buf: Vec<u8> = Vec::new();
            let mut source_port = 0x10000u32;
            // [udp]
            if !lines.next_line() {
                break;
            }
            if !lines.cur.starts_with(b"udp") {
                return Err(lines.syntax("expected \"udp\""));
            }
            lines.cur.drain(..3);
            trim(&mut lines.cur);
            // [ports]
            if !lines.next_line() {
                break;
            }
            let (ranges, rest_at) =
                parse_ports_prefix(&lines.cur).map_err(|_| lines.syntax("expected ports"))?;
            lines.cur.drain(..rest_at);
            trim(&mut lines.cur);
            // [C string]
            loop {
                trim(&mut lines.cur);
                if !lines.next_line() || lines.cur[0] != b'"' {
                    break;
                }
                let rest_at = parse_c_string(&mut buf, &lines.cur);
                lines.cur.drain(..rest_at);
                trim(&mut lines.cur);
            }
            // [source]
            if lines.cur.starts_with(b"source") {
                lines.cur.drain(..6);
                trim(&mut lines.cur);
                if !lines.cur.first().is_some_and(u8::is_ascii_digit) {
                    return Err(lines.syntax("expected source port"));
                }
                let mut pos = 0;
                source_port = strtoul0(&lines.cur, &mut pos) as u32;
                lines.cur.clear();
            }
            if !buf.is_empty() {
                added += self.add(&buf, &ranges, source_port)?;
            }
        }
        Ok(added)
    }

    /// `--pcap-payloads` (`payloads_read_pcap`, templ-payloads.c:437): из каждого пакета UDP берётся нагрузка и порт
    /// назначения. Пакет без нагрузки тоже заменяет запись (в C `payloads_datagram_add` вызывается без проверки длины).
    /// Возвращает число записанных портов.
    ///
    /// Отличия от C: неизвестный порядок байт заголовка и повреждённый кадр это ошибка (C печатает предупреждение и
    /// читает мусор или перепрыгивает через повреждение); обрезанный хвост файла это конец данных, как в C;
    /// разбираются Ethernet с VLAN-тегами, IPv4 без фрагментов и IPv6 с прямым UDP (остальные кадры пропускаются).
    pub fn load_pcap_payloads(&mut self, data: &[u8]) -> Result<usize, PayloadError> {
        let head = data.get(..24).ok_or(PayloadError::Pcap("file too short"))?;
        let big = match head[..4] {
            [0xa1, 0xb2, 0xc3, 0xd4] => true,
            [0xd4, 0xc3, 0xb2, 0xa1] => false,
            _ => return Err(PayloadError::Pcap("unknown byte order")),
        };
        let rd32 = |b: &[u8]| {
            let a = [b[0], b[1], b[2], b[3]];
            if big {
                u32::from_be_bytes(a)
            } else {
                u32::from_le_bytes(a)
            }
        };
        // rawsock-pcapfile.c:597-611: 0 читается как Ethernet; WiFi и Prism проходят, но разбираются как Ethernet.
        match rd32(&head[20..24]) {
            0 | 1 | 0x7f | 0x69 | 119 => {}
            _ => return Err(PayloadError::Pcap("unsupported link type")),
        }
        let mut added = 0;
        let mut pos = 24usize;
        while let Some(h) = data.get(pos..pos + 16) {
            let (secs, usecs) = (rd32(&h[0..4]), rd32(&h[4..8]));
            let (caplen, origlen) = (rd32(&h[8..12]) as usize, rd32(&h[12..16]) as usize);
            pos += 16;
            if secs == 0 && usecs == 0 && origlen == 0 && caplen == 0 {
                continue; // :322
            }
            // :328-335
            if caplen > 65536 || origlen < caplen || !(8..=160_000).contains(&origlen) {
                return Err(PayloadError::Pcap("corrupt frame header"));
            }
            let Some(frame) = data.get(pos..pos + caplen) else {
                break; // обрезанный хвост
            };
            pos += caplen;
            if let Some((port, payload)) = udp_payload(frame) {
                added += self.add(payload, &[(u32::from(port), u32::from(port))], 0x10000)?;
            }
        }
        Ok(added)
    }
}

// --- разбор `nmap-payloads` (templ-nmap-payloads.c) ---

struct NmapLines<'a> {
    it: std::slice::Split<'a, u8, fn(&u8) -> bool>,
    number: usize,
    cur: Vec<u8>,
}

fn trim(line: &mut Vec<u8>) {
    while line.last().is_some_and(|&c| is_c_space(c)) {
        line.pop();
    }
    let n = line.iter().take_while(|&&c| is_c_space(c)).count();
    line.drain(..n);
}

impl NmapLines<'_> {
    /// `get_next_line` (:44): строка в `cur` остаётся, пока её не разобрали; пустые и комментарии (`#`, `/`, `;`)
    /// пропускаются. `false` в конце файла.
    fn next_line(&mut self) -> bool {
        if !self.cur.is_empty() {
            return true;
        }
        for raw in self.it.by_ref() {
            self.number += 1;
            self.cur = raw.to_vec();
            trim(&mut self.cur);
            if matches!(self.cur.first(), Some(b'#' | b'/' | b';')) || self.cur.is_empty() {
                self.cur.clear();
                continue;
            }
            return true;
        }
        self.cur.clear();
        false
    }

    fn syntax(&self, msg: &'static str) -> PayloadError {
        PayloadError::Syntax {
            line: self.number,
            msg,
        }
    }
}

/// `rangelist_parse_ports` (massip-rangesv4.c:993) с остановкой на первом не-порте: возвращает диапазоны (с
/// префиксным сдвигом, как в C) и смещение остатка строки. Ошибка: неизвестный префикс или порт вне диапазона.
fn parse_ports_prefix(s: &[u8]) -> Result<(Vec<(u32, u32)>, usize), ()> {
    use crate::targets::{TEMPL_ICMP_ECHO, TEMPL_OPROTO_FIRST, TEMPL_SCTP, TEMPL_TCP, TEMPL_UDP};
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

/// `parse_c_string` (templ-nmap-payloads.c:100): разбирает строку в кавычках, дописывает байты в `buf` (не больше 1500)
/// и возвращает смещение за закрывающей кавычкой. Цифры 8 и 9 после `\` дают нулевой байт и сами остаются в строке,
/// как в C.
fn parse_c_string(buf: &mut Vec<u8>, line: &[u8]) -> usize {
    let push = |buf: &mut Vec<u8>, c: u8| {
        if buf.len() < NMAP_STRING_MAX {
            buf.push(c);
        }
    };
    let hexval = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    if line.first() != Some(&b'"') {
        return 0;
    }
    let mut o = 1;
    while o < line.len() && line[o] != b'"' {
        if line[o] != b'\\' {
            push(buf, line[o]);
            o += 1;
            continue;
        }
        o += 1;
        let c = line.get(o).copied().unwrap_or(0);
        match c {
            b'0'..=b'9' => {
                let mut val = 0u32;
                for _ in 0..3 {
                    if line.get(o).is_some_and(|c| (b'0'..=b'7').contains(c)) {
                        val = val * 8 + u32::from(hexval(line[o]));
                        o += 1;
                    }
                }
                push(buf, val as u8);
                continue;
            }
            b'x' => {
                o += 1;
                let mut val = 0u32;
                for _ in 0..2 {
                    if line.get(o).is_some_and(u8::is_ascii_hexdigit) {
                        val = val * 16 + u32::from(hexval(line[o]));
                        o += 1;
                    }
                }
                push(buf, val as u8);
                continue;
            }
            b'a' => push(buf, 7),
            b'b' => push(buf, 8),
            b'f' => push(buf, 12),
            b'n' => push(buf, b'\n'),
            b'r' => push(buf, b'\r'),
            b't' => push(buf, b'\t'),
            b'v' => push(buf, 11),
            other => push(buf, other),
        }
        o += 1;
    }
    if line.get(o) == Some(&b'"') {
        o += 1;
    }
    o.min(line.len())
}

// --- разбор кадра для `--pcap-payloads` (proto-preprocess.c:55-212, подмножество) ---

fn rd16(b: &[u8], i: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
    ])))
}

/// Порт назначения и нагрузка UDP-пакета Ethernet-кадра; `None` для всего остального и для искажённых кадров
/// (`preprocess_frame` возвращает 0 или не `FOUND_UDP`).
fn udp_payload(frame: &[u8]) -> Option<(u16, &[u8])> {
    let mut off = 14;
    let mut ethertype = rd16(frame, 12)?;
    if ethertype < 2000 {
        return None; // LLC не разбираем
    }
    // 802.1Q (proto-preprocess.c:331).
    while ethertype == 0x8100 || ethertype == 0x88a8 {
        ethertype = rd16(frame, off + 2)?;
        off += 4;
    }
    let (udp_at, end) = match ethertype {
        0x0800 => {
            let ip = frame.get(off..)?;
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                return None;
            }
            let header = usize::from(ip[0] & 0x0F) * 4;
            let total = rd16(ip, 2)?;
            if header < 20 || ip.len() < header || total < header || ip.len() < total {
                return None;
            }
            // фрагмент: смещение или MF (:106-108)
            if rd16(ip, 6)? & 0x3FFF != 0 || ip[6] & 0x20 != 0 || ip[9] != 17 {
                return None;
            }
            (off + header, off + total)
        }
        0x86dd => {
            let ip = frame.get(off..)?;
            if ip.len() < 40 || ip[0] >> 4 != 6 || ip[6] != 17 {
                return None;
            }
            let payload = rd16(ip, 4)?;
            if ip.len() < 40 + payload {
                return None;
            }
            (off + 40, off + 40 + payload)
        }
        _ => return None,
    };
    if end < udp_at + 8 {
        return None;
    }
    let port = u16::try_from(rd16(frame, udp_at + 2)?).ok()?;
    Some((port, frame.get(udp_at + 8..end)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp_c_vectors::{C_FORCED, C_FRAMES, C_RAW};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    const PORTS_28: [u16; 28] = [
        7, 17, 19, 53, 69, 111, 123, 137, 138, 161, 443, 500, 520, 1645, 1646, 1701, 1812, 1813,
        1900, 2049, 5060, 5683, 11211, 16464, 16465, 16470, 16471, 27960,
    ];

    /// Какой мутатор C ставит каждому порту (templ-payloads.c:66-472).
    fn expected_mutator(port: u16) -> Option<CookieMutator> {
        Some(match port {
            53 | 111 | 137 | 2049 => CookieMutator::Dns,
            123 => CookieMutator::Ntp,
            161 => CookieMutator::Snmp,
            500 => CookieMutator::Isakmp,
            5683 => CookieMutator::Coap,
            11211 => CookieMutator::Memcached,
            _ => return None,
        })
    }

    #[test]
    fn builtin_28_udp_payloads_match_c_bytes_and_cookies() {
        let t = PayloadTable::builtin();
        assert_eq!(t.len(), 28);
        assert_eq!(t.ports().collect::<Vec<_>>(), PORTS_28.map(u32::from));

        // Нагрузки до мутации: `payloads_udp_lookup` настоящего C, байт в байт, включая длину из таблицы (порт 7 это
        // 12 байт от 23-байтной строки, порт 1900 длина по `strlen`).
        assert_eq!(C_RAW.len(), 28);
        for &(port, source_port, hex) in C_RAW {
            let e = t.get(port).unwrap_or_else(|| panic!("port {port}"));
            assert_eq!(&e.payload[..], &unhex(hex)[..], "payload of {port}");
            assert_eq!(e.source_port, source_port, "source_port of {port}");
            assert_eq!(e.set_cookie, expected_mutator(port), "mutator of {port}");
        }

        // Нагрузки в кадрах C при реальном cookie (seqno = cookie зонда) и при произвольных seqno, включая границы.
        for &(port, seqno, hex) in C_FRAMES {
            let frame = unhex(hex);
            match t.get(port) {
                Some(e) => assert_eq!(e.with_cookie(seqno), frame[42..], "port {port} cookie"),
                None => assert_eq!(frame.len(), 42, "port {port} has no payload"),
            }
        }
        assert_eq!(C_FORCED.len(), 40);
        for &(port, seqno, hex) in C_FORCED {
            let frame = unhex(hex);
            let e = t.get(port).unwrap();
            assert_eq!(
                e.with_cookie(seqno),
                frame[42..],
                "port {port} seqno {seqno:#x}"
            );
        }
    }

    #[test]
    fn cookie_mutations_land_on_the_exact_bytes() {
        let t = PayloadTable::builtin();
        let seq = 0xa1b2_c3d4u32;
        let at = |port: u16| t.get(port).unwrap().with_cookie(seq);
        let raw = |port: u16| t.get(port).unwrap().payload.to_vec();
        // DNS 53, портмаппер 111, NBNS 137, NFS 2049: первые два байта (`dns_set_cookie`).
        for port in [53, 111, 137, 2049] {
            let (a, r) = (at(port), raw(port));
            assert_eq!(a[..2], [0xc3, 0xd4], "{port}");
            assert_eq!(a[2..], r[2..], "{port}");
        }
        // NTP 123: без изменений.
        assert_eq!(at(123), raw(123));
        // SNMP 161: request-id PDU (4 байта, старший бит чистится), остальное нетронуто.
        let (a, r) = (at(161), raw(161));
        assert_eq!(a[17..21], [0x21, 0xb2, 0xc3, 0xd4]);
        assert_eq!(a[..17], r[..17]);
        assert_eq!(a[21..], r[21..]);
        // ISAKMP 500: init_cookie 8 байт, старшие 4 нулевые (`seqno` это `unsigned`).
        let (a, r) = (at(500), raw(500));
        assert_eq!(a[..8], [0, 0, 0, 0, 0xa1, 0xb2, 0xc3, 0xd4]);
        assert_eq!(a[8..], r[8..]);
        // CoAP 5683: message id, байты 2 и 3.
        let (a, r) = (at(5683), raw(5683));
        assert_eq!(a[2..4], [0xc3, 0xd4]);
        assert_eq!([&a[..2], &a[4..]].concat(), [&r[..2], &r[4..]].concat());
        // memcached 11211: request id, байты 0 и 1.
        let (a, r) = (at(11211), raw(11211));
        assert_eq!(a[..2], [0xc3, 0xd4]);
        assert_eq!(a[2..], r[2..]);
        // Порты без мутатора не меняются.
        for port in [7u16, 69, 138, 443, 1900, 5060, 16464, 27960] {
            assert_eq!(at(port), raw(port), "{port}");
        }
    }

    #[test]
    fn snmp_cookie_handles_every_request_id_width_and_refuses_garbage() {
        // BER: SEQUENCE { INTEGER 0, OCTET STRING "p", GET { INTEGER(len) .. } }; ширина id 1..=5 (proto-snmp.c:442-474).
        let pdu = |idlen: usize| {
            let mut v = vec![
                0x30,
                0,
                0x02,
                0x01,
                0x00,
                0x04,
                0x01,
                b'p',
                0xa0,
                0,
                0x02,
                idlen as u8,
            ];
            v.extend(std::iter::repeat_n(0u8, idlen));
            v[9] = (2 + idlen) as u8;
            v[1] = (v.len() - 2) as u8;
            v
        };
        let seq = 0xfeed_beefu32;
        let want: [&[u8]; 5] = [
            &[0x6f],
            &[0x3e, 0xef],
            &[0x6d, 0xbe, 0xef],
            &[0x7e, 0xed, 0xbe, 0xef],
            &[0x00, 0xfe, 0xed, 0xbe, 0xef],
        ];
        for (i, w) in want.iter().enumerate() {
            let mut p = pdu(i + 1);
            CookieMutator::Snmp.apply(&mut p, seq);
            assert_eq!(&p[12..], *w, "width {}", i + 1);
        }
        // Не SNMP, версия не 0, пустой id, обрезанное сообщение: ничего не пишется и ничего не падает.
        for bad in [
            vec![0x31, 0x01, 0x00],
            vec![0x30, 0x03, 0x02, 0x01, 0x01],
            pdu(0),
            pdu(5)[..9].to_vec(),
            vec![],
        ] {
            let mut p = bad.clone();
            CookieMutator::Snmp.apply(&mut p, seq);
            assert_eq!(p, bad);
        }
        // Мутаторы на коротких данных (порог длины из C).
        for (m, n) in [
            (CookieMutator::Dns, 2),
            (CookieMutator::Coap, 3),
            (CookieMutator::Memcached, 1),
            (CookieMutator::Isakmp, 7),
        ] {
            let mut p = vec![0u8; n];
            m.apply(&mut p, seq);
            assert_eq!(p, vec![0u8; n], "{m:?}");
        }
    }

    // Синтаксис `nmap-payloads`: короткая рукописная проверка, не строки из файла Nmap.
    const NMAP_FIXTURE: &str = "\
# comment
; another comment
/ and another

udp 53,5353
\"\\x00\\x01\\x02\" \"abc\\n\"
\"\\101\\x42C\"
source 40000

udp 9999
\"hello\" \"\\\"quoted\\\"\"
udp 7-8 \"x\"
";

    #[test]
    fn nmap_and_pcap_payload_parsers_override_table() {
        // --nmap-payloads: заменяет встроенную запись порта 53 (и её мутацию), добавляет новые порты.
        let mut t = PayloadTable::builtin();
        assert_eq!(t.get(53).unwrap().set_cookie, Some(CookieMutator::Dns));
        let n = t.load_nmap_payloads(NMAP_FIXTURE).unwrap();
        assert_eq!(n, 5); // 53, 5353, 9999, 7, 8
        let e53 = t.get(53).unwrap();
        assert_eq!(&e53.payload[..], b"\x00\x01\x02abc\nABC");
        assert_eq!(e53.set_cookie, None);
        assert_eq!(e53.source_port, 40000);
        assert_eq!(t.get(5353).unwrap().payload, e53.payload);
        let e9999 = t.get(9999).unwrap();
        assert_eq!(&e9999.payload[..], b"hello\"quoted\"");
        assert_eq!(e9999.source_port, 0x10000);
        assert_eq!(&t.get(7).unwrap().payload[..], b"x"); // заменил "masscan-test"
        assert_eq!(&t.get(8).unwrap().payload[..], b"x");
        assert_eq!(t.len(), 28 + 3);
        // Остальные встроенные записи на месте.
        assert_eq!(t.get(161).unwrap().set_cookie, Some(CookieMutator::Snmp));

        // --pcap-payloads: синтетический pcap, оба порядка байт; берутся только UDP без фрагментации.
        let frames = vec![
            eth_ipv4_udp(&[], 161, b"snmp-from-pcap", 0),
            eth_ipv4_udp(&[], 4444, b"", 0),
            eth_ipv4_udp(&[0x81, 0x00, 0x00, 0x05], 4445, b"vlan", 0),
            eth_ipv4_udp(&[], 4446, b"fragment", 0x2000),
            eth_ipv4_tcp(80),
            eth_ipv6_udp(5555, b"v6"),
        ];
        for big in [false, true] {
            let mut t = PayloadTable::builtin();
            assert_eq!(
                t.load_pcap_payloads(&pcap_file(big, 1, &frames)).unwrap(),
                4
            );
            let e = t.get(161).unwrap();
            assert_eq!(&e.payload[..], b"snmp-from-pcap");
            assert_eq!(e.set_cookie, None, "pcap replaces the cookie mutation too");
            assert_eq!(e.source_port, 0x10000);
            assert_eq!(&t.get(4444).unwrap().payload[..], b"");
            assert_eq!(&t.get(4445).unwrap().payload[..], b"vlan");
            assert!(t.get(4446).is_none(), "fragments are skipped");
            assert!(t.get(80).is_none(), "TCP is skipped");
            assert_eq!(&t.get(5555).unwrap().payload[..], b"v6");
            // Файл `--nmap-payloads` читается после pcap (main-conf.c:3163-3183) и побеждает.
            t.load_nmap_payloads("udp 161\n\"nmap-wins\"\n").unwrap();
            assert_eq!(&t.get(161).unwrap().payload[..], b"nmap-wins");
        }
        // Усечённый хвост это конец данных, не ошибка.
        let mut file = pcap_file(false, 1, &frames[..1]);
        file.extend_from_slice(&[1, 2, 3, 4, 5]);
        assert_eq!(PayloadTable::empty().load_pcap_payloads(&file), Ok(1));
    }

    #[test]
    fn payload_loaders_reject_bad_input_without_panicking() {
        let bad = |s: &str| PayloadTable::empty().load_nmap_payloads(s).unwrap_err();
        assert_eq!(
            bad("tcp 80\n\"x\"\n"),
            PayloadError::Syntax {
                line: 1,
                msg: "expected \"udp\""
            }
        );
        assert_eq!(
            bad("# c\nudp 99999\n\"x\"\n"),
            PayloadError::Syntax {
                line: 2,
                msg: "expected ports"
            }
        );
        assert_eq!(
            bad("udp 1\n\"x\"\nsource abc\n"),
            PayloadError::Syntax {
                line: 3,
                msg: "expected source port"
            }
        );
        assert!(matches!(
            bad("udp 1\n\"x\"\nbogus\n"),
            PayloadError::Syntax { line: 3, .. }
        ));
        // Записи без строки и пустой файл это не ошибка.
        let mut t = PayloadTable::empty();
        assert_eq!(t.load_nmap_payloads(""), Ok(0));
        assert_eq!(t.load_nmap_payloads("udp 53\n"), Ok(0));
        assert!(t.is_empty());
        // Нагрузка длиннее 1500 байт усекается как в C (`buf[1500]`).
        let long = format!("udp 9\n\"{}\"\n", "a".repeat(1600));
        t.load_nmap_payloads(&long).unwrap();
        assert_eq!(t.get(9).unwrap().payload.len(), 1500);
        // pcap: короткий файл, чужой порядок байт, неизвестный тип канала, повреждённый кадр.
        let e = |d: &[u8]| PayloadTable::empty().load_pcap_payloads(d).unwrap_err();
        assert_eq!(e(&[0; 10]), PayloadError::Pcap("file too short"));
        assert_eq!(e(&[0; 24]), PayloadError::Pcap("unknown byte order"));
        assert_eq!(
            e(&pcap_file(false, 113, &[])),
            PayloadError::Pcap("unsupported link type")
        );
        let mut corrupt = pcap_file(false, 1, &[]);
        corrupt.extend_from_slice(&[1, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 4, 0, 0, 0]);
        assert_eq!(e(&corrupt), PayloadError::Pcap("corrupt frame header"));
        // Мусорные кадры пропускаются без паники.
        let junk: Vec<Vec<u8>> = vec![vec![0xff; 8], vec![0x08; 20], vec![0; 14 + 20]];
        assert_eq!(
            PayloadTable::empty().load_pcap_payloads(&pcap_file(false, 1, &junk)),
            Ok(0)
        );
    }

    fn pcap_file(big: bool, linktype: u32, frames: &[Vec<u8>]) -> Vec<u8> {
        let w32 = |v: u32| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let w16 = |v: u16| {
            if big {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        };
        let mut f = Vec::new();
        // magic читается big-endian по байтам: `a1b2c3d4` значит big-endian файл (rawsock-pcapfile.c:578)
        f.extend_from_slice(&if big {
            [0xa1, 0xb2, 0xc3, 0xd4]
        } else {
            [0xd4, 0xc3, 0xb2, 0xa1]
        });
        f.extend_from_slice(&w16(2));
        f.extend_from_slice(&w16(4));
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&w32(65535));
        f.extend_from_slice(&w32(linktype));
        for fr in frames {
            f.extend_from_slice(&w32(1));
            f.extend_from_slice(&w32(2));
            f.extend_from_slice(&w32(fr.len() as u32));
            f.extend_from_slice(&w32(fr.len() as u32));
            f.extend_from_slice(fr);
        }
        f
    }

    /// Ethernet (+ необязательные теги `vlan` между MAC и IPv4), IPv4 (адреса документации), UDP.
    fn eth_ipv4_udp(vlan: &[u8], dport: u16, payload: &[u8], frag: u16) -> Vec<u8> {
        let mut f = vec![
            0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        if vlan.is_empty() {
            f.extend_from_slice(&[0x08, 0x00]);
        } else {
            f.extend_from_slice(&[0x81, 0x00]);
            f.extend_from_slice(&[vlan[2], vlan[3], 0x08, 0x00]);
        }
        let total = (20 + 8 + payload.len()) as u16;
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(&frag.to_be_bytes());
        f.extend_from_slice(&[64, 17, 0, 0, 198, 18, 0, 1, 198, 18, 0, 2]);
        f.extend_from_slice(&[0x30, 0x39]);
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }

    fn eth_ipv4_tcp(dport: u16) -> Vec<u8> {
        let mut f = eth_ipv4_udp(&[], dport, &[0; 12], 0);
        f[23] = 6;
        f
    }

    fn eth_ipv6_udp(dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![
            0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0, 0x11, 0x22, 0x33, 0x44, 0x55,
        ];
        f.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[17, 64]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        f.extend_from_slice(&[0x30, 0x39]);
        f.extend_from_slice(&dport.to_be_bytes());
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(payload);
        f
    }
}
