//! Ожидаемые байты выведены независимо от реализации:
//! * NS: собран вручную по RFC 4861 §4.3/§7.2.2, сумма посчитана `checksum_ipv6` из C (`util-checksum.c:118-153`)
//!   скретч-программой (`/scratchpad/t4c/ns.c`, masscan 8e6b3b0), не нашим кодом;
//! * NA: вывод настоящего `stack_ndpv6_incoming_request` (`stack-ndpv6.c:95-182`), собранного из исходников C
//!   (`/scratchpad/t4c/h.c`, подставные `stack_get_packetbuffer`/`stack_transmit_packetbuffer`);
//! * сумма в тестах разбора считается отдельной простой реализацией (`independent_checksum`).

use super::*;

const MY_MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const ME: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0001;
const TARGET: u128 = 0xfd00_0000_0000_0000_0000_0000_0a0b_0c0d;
const ROUTER_MAC: [u8; 6] = [0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0x01];

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// RFC 1071 по псевдозаголовку RFC 8200 §8.1, поле суммы в `icmp` считается нулём.
fn independent_checksum(src: &[u8], dst: &[u8], icmp: &[u8]) -> u16 {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(src);
    bytes.extend_from_slice(dst);
    bytes.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 58]);
    let mut body = icmp.to_vec();
    body[2] = 0;
    body[3] = 0;
    bytes.extend_from_slice(&body);
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    let mut sum: u32 = 0;
    for w in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([w[0], w[1]]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn fix_checksum(frame: &mut [u8]) {
    let x = independent_checksum(&frame[22..38], &frame[38..54], &frame[54..]);
    frame[56..58].copy_from_slice(&x.to_be_bytes());
}

/// NS, собранный C-скретчем `ns.c`: 33:33:ff:0b:0c:0d <- 02:11:22:33:44:55, fd00::1 -> ff02::1:ff0b:0c0d.
const NS_C: &str = "3333ff0b0c0d 021122334455 86dd 60000000 0020 3a ff \
    fd000000000000000000000000000001 ff0200000000000000000001ff0b0c0d \
    8700 f4d2 00000000 fd00000000000000000000000a0b0c0d 0101 021122334455";

#[test]
fn ndp_solicitation_86_bytes_and_advertisement_parse() {
    // NS: все 86 байт.
    let ns = encode_neighbor_solicitation(MY_MAC, ME, TARGET);
    assert_eq!(ns.len(), 86);
    assert_eq!(ns.to_vec(), hex(NS_C));
    // Поля по отдельности (RFC 4861 §7.2.2): группа solicited-node, hop limit 255, опция 1.
    assert_eq!(&ns[0..6], &[0x33, 0x33, 0xff, 0x0b, 0x0c, 0x0d]);
    assert_eq!(
        &ns[38..54],
        &hex("ff02 0000 0000 0000 0000 0001 ff0b 0c0d")[..]
    );
    assert_eq!(ns[21], 255);
    assert_eq!(&ns[18..20], &[0, 32]);
    assert_eq!(&ns[78..86], &hex("0101 021122334455")[..]);
    // Сумма RFC 4443 независимой реализацией.
    assert_eq!(
        u16::from_be_bytes([ns[56], ns[57]]),
        independent_checksum(&ns[22..38], &ns[38..54], &ns[54..])
    );
    assert_eq!(
        solicited_node_address(TARGET),
        0xff02_0000_0000_0000_0000_0001_ff0b_0c0d
    );
    assert_eq!(
        solicited_node_mac(TARGET),
        [0x33, 0x33, 0xff, 0x0b, 0x0c, 0x0d]
    );

    // NA роутера на наш NS: unicast на нас, hop limit 255, опция 2.
    let router_mac = ROUTER_MAC;
    let na = encode_neighbor_advertisement(router_mac, TARGET, MY_MAC, ME);
    let p = decode_neighbor_advertisement(&na).unwrap();
    assert_eq!(p.target, TARGET);
    assert_eq!(p.target_lla, router_mac);
    assert_eq!(p.dst_ip, ME);
    assert_eq!(p.flags, 0x60);
    let mut pending = PendingNdp::new(MY_MAC, ME, TARGET);
    assert_eq!(pending.request_frame(), ns);
    assert_eq!(pending.offer(&na), Some(router_mac));
    assert_eq!(pending.resolved(), Some(router_mac));

    // RFC 4861 §7.1.2: hop limit != 255 игнорируется (а сумма при этом верна).
    let mut low = na;
    low[21] = 254;
    fix_checksum(&mut low);
    assert_eq!(
        decode_neighbor_advertisement(&low),
        Err(NdpError::HopLimit(254))
    );
    assert_eq!(PendingNdp::new(MY_MAC, ME, TARGET).offer(&low), None);
    // code != 0.
    let mut code = na;
    code[55] = 1;
    fix_checksum(&mut code);
    assert_eq!(decode_neighbor_advertisement(&code), Err(NdpError::Code(1)));
    // Битая сумма.
    let mut bad = na;
    bad[57] ^= 1;
    assert_eq!(decode_neighbor_advertisement(&bad), Err(NdpError::Checksum));
    // Не NA (тип 135).
    assert_eq!(
        decode_neighbor_advertisement(&ns),
        Err(NdpError::WrongType(135))
    );
}

#[test]
fn advertisement_for_another_target_or_host_is_ignored() {
    let mut pending = PendingNdp::new(MY_MAC, ME, TARGET);
    let other = TARGET + 1;
    assert_eq!(
        pending.offer(&encode_neighbor_advertisement(
            ROUTER_MAC, other, MY_MAC, ME
        )),
        None
    );
    // Адресован другому IPv6 / другому MAC.
    assert_eq!(
        pending.offer(&encode_neighbor_advertisement(
            ROUTER_MAC,
            TARGET,
            MY_MAC,
            ME + 1
        )),
        None
    );
    assert_eq!(
        pending.offer(&encode_neighbor_advertisement(
            ROUTER_MAC,
            TARGET,
            [2, 2, 2, 2, 2, 2],
            ME
        )),
        None
    );
    // Multicast и нулевой MAC в опции.
    assert_eq!(
        pending.offer(&encode_neighbor_advertisement(
            [0x33, 0x33, 0, 0, 0, 1],
            TARGET,
            MY_MAC,
            ME
        )),
        None
    );
    assert_eq!(
        pending.offer(&encode_neighbor_advertisement([0; 6], TARGET, MY_MAC, ME)),
        None
    );
    // Мусор и обрезки.
    assert_eq!(pending.offer(&[0u8; 5]), None);
    let na = encode_neighbor_advertisement(ROUTER_MAC, TARGET, MY_MAC, ME);
    assert_eq!(pending.offer(&na[..60]), None);
    assert_eq!(pending.resolved(), None);
}

#[test]
fn advertisement_option_and_flag_rules() {
    let na = encode_neighbor_advertisement(ROUTER_MAC, TARGET, MY_MAC, ME);
    // Без опции 2: нечем разрешать (кадр короче на 8 байт, payload 24).
    let mut short = na[..78].to_vec();
    short[18..20].copy_from_slice(&24u16.to_be_bytes());
    fix_checksum(&mut short);
    assert_eq!(
        decode_neighbor_advertisement(&short),
        Err(NdpError::NoTargetLla)
    );
    // Опция длиной 0 отбрасывает пакет (RFC 4861 §7.1.2).
    let mut zero = na;
    zero[79] = 0;
    fix_checksum(&mut zero);
    assert_eq!(
        decode_neighbor_advertisement(&zero),
        Err(NdpError::BadOption)
    );
    // Опция 1 вместо 2: нет Target LLA.
    let mut slla = na;
    slla[78] = 1;
    fix_checksum(&mut slla);
    assert_eq!(
        decode_neighbor_advertisement(&slla),
        Err(NdpError::NoTargetLla)
    );
    // Multicast-получатель с флагом Solicited это нарушение §7.1.2.
    let all_nodes = 0xff02_0000_0000_0000_0000_0000_0000_0001u128;
    let mcast = encode_neighbor_advertisement(ROUTER_MAC, TARGET, MY_MAC, all_nodes);
    assert_eq!(
        decode_neighbor_advertisement(&mcast),
        Err(NdpError::SolicitedToMulticast)
    );
    // Расширение между IPv6 и ICMPv6 не допускается.
    let mut ext = na;
    ext[20] = 0;
    assert_eq!(
        decode_neighbor_advertisement(&ext),
        Err(NdpError::NotIcmpv6(0))
    );
    // payload_length больше кадра.
    let mut beyond = na;
    beyond[19] = 0x40;
    assert!(matches!(
        decode_neighbor_advertisement(&beyond),
        Err(NdpError::PayloadBeyondFrame { .. })
    ));
    // Ethernet-трейлер за payload_length не мешает.
    let mut padded = na.to_vec();
    padded.extend_from_slice(&[0; 6]);
    assert!(decode_neighbor_advertisement(&padded).is_ok());
}

/// NS роутера для нас, как в `/scratchpad/t4c/h.c`: 0a:bb:cc:dd:ee:01 fe80::abcd -> ff02::1:ff00:2, цель fd00::2.
fn router_ns(with_option: bool) -> Vec<u8> {
    let mut f = hex("3333ff000002 0abbccddee01 86dd 60000000 0020 3a ff \
         fe80000000000000000000000000abcd ff0200000000000000000001ff000002 \
         8700 0000 00000000 fd000000000000000000000000000002 0101 0abbccddee01");
    if !with_option {
        f.truncate(78);
        f[18..20].copy_from_slice(&24u16.to_be_bytes());
    }
    fix_checksum(&mut f);
    f
}

const MY_IP2: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0002;

/// Вывод `stack_ndpv6_incoming_request` C на `router_ns(true)` (8e6b3b0, h.c, ветка `ns_with_opt_opcode_set`).
const NA_C: &str = "0abbccddee01 021122334455 86dd 60000000 0020 3a ff \
    fd000000000000000000000000000002 fe80000000000000000000000000abcd \
    8800 08b6 60000000 fd000000000000000000000000000002 0201 021122334455";

#[test]
fn incoming_ns_answer_equals_c_bytes() {
    let ns = router_ns(true);
    let na = answer_neighbor_solicitation(&ns, MY_MAC, MY_IP2).unwrap();
    assert_eq!(na.to_vec(), hex(NA_C));
    assert_eq!(na.len(), 86);
    assert_eq!(&na[18..20], &[0, 32]);
    // Ответ сам является валидным NA.
    let p = decode_neighbor_advertisement(&na).unwrap();
    assert_eq!((p.target, p.target_lla, p.flags), (MY_IP2, MY_MAC, 0x60));
}

/// C (:145) копирует запрос и не переписывает `payload_length`: на NS без опции (payload 24) он шлёт 86 байт с
/// длиной 0x0018. Вывод C на этом входе взят из h.c (`ns_no_opt_opcode_set`); порт обязан отличаться ровно
/// двумя байтами длины.
#[test]
fn incoming_ns_without_option_gets_payload_length_32_unlike_c() {
    let ns = router_ns(false);
    assert_eq!(ns.len(), 78);
    let na = answer_neighbor_solicitation(&ns, MY_MAC, MY_IP2).unwrap();
    let c_bytes = hex(&NA_C.replace("60000000 0020", "60000000 0018"));
    assert_eq!(&c_bytes[18..20], &[0, 24]);
    let mut want = c_bytes;
    want[18..20].copy_from_slice(&[0, 32]);
    assert_eq!(na.to_vec(), want);
    assert_eq!(na.len(), 86);
}

#[test]
fn incoming_ns_that_must_not_be_answered() {
    let ok = router_ns(true);
    assert!(answer_neighbor_solicitation(&ok, MY_MAC, MY_IP2).is_some());
    // Не наш адрес (stack-ndpv6.c:128-130).
    assert!(answer_neighbor_solicitation(&ok, MY_MAC, MY_IP2 + 1).is_none());
    // hop limit != 255, code != 0, битая сумма (RFC 4861 §7.1.1).
    let mut f = ok.clone();
    f[21] = 64;
    fix_checksum(&mut f);
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    let mut f = ok.clone();
    f[55] = 1;
    fix_checksum(&mut f);
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    let mut f = ok.clone();
    f[56] ^= 0xff;
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    // DAD: источник `::` (C ответил бы на `::`).
    let mut f = ok.clone();
    f[22..38].fill(0);
    fix_checksum(&mut f);
    assert_eq!(
        decode_neighbor_solicitation(&f),
        Err(NdpError::UnspecifiedSource)
    );
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    // Адресат не наш адрес и не наш solicited-node (C принял бы любой ff02::/16).
    let mut f = ok.clone();
    f[38..54].copy_from_slice(&0xff02_0000_0000_0000_0000_0000_0000_0001u128.to_be_bytes());
    fix_checksum(&mut f);
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    // Unicast NS на наш адрес (main.c:859) принимается.
    let mut f = ok.clone();
    f[38..54].copy_from_slice(&MY_IP2.to_be_bytes());
    fix_checksum(&mut f);
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_some());
    // Цель multicast.
    let mut f = ok.clone();
    f[62] = 0xff;
    fix_checksum(&mut f);
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    // NA, обрезок, мусор.
    let na = encode_neighbor_advertisement(ROUTER_MAC, MY_IP2, MY_MAC, ME);
    assert!(answer_neighbor_solicitation(&na, MY_MAC, MY_IP2).is_none());
    assert!(answer_neighbor_solicitation(&ok[..60], MY_MAC, MY_IP2).is_none());
    assert!(answer_neighbor_solicitation(&[], MY_MAC, MY_IP2).is_none());
}

/// Ответ никогда не отражается на multicast: источник IPv6 multicast или Ethernet-источник multicast/broadcast
/// молча отбрасываются (в C `memcpy` ответа кладёт их в адресата, :149-150).
#[test]
fn ns_with_multicast_source_is_never_reflected() {
    let ok = router_ns(true);
    assert!(answer_neighbor_solicitation(&ok, MY_MAC, MY_IP2).is_some());
    let mut f = ok.clone();
    f[22..38].copy_from_slice(&0xff02_0000_0000_0000_0000_0000_0000_0001u128.to_be_bytes());
    fix_checksum(&mut f);
    assert!(answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none());
    for mac in [
        [0x33, 0x33, 0, 0, 0, 1],
        [0xff; 6],
        [0x01, 0, 0x5e, 0, 0, 1],
    ] {
        let mut f = ok.clone();
        f[6..12].copy_from_slice(&mac);
        assert!(
            answer_neighbor_solicitation(&f, MY_MAC, MY_IP2).is_none(),
            "{mac:02x?}"
        );
    }
}
