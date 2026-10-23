//! Контрольные суммы RFC 1071 (AGPL-3.0). Порт `src/util-checksum.c` и
//! `ip_header_checksum` из `src/templ-pkt.c:184`, masscan © Robert David
//! Graham (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! `util-checksum.c` распространяется под MIT (util-checksum.c:6):
//! Author: Robert David Graham, Copyright: 2020, License: The MIT License (MIT).

/// Байт или 0 за границей буфера (C читает за границей без проверки).
fn byte(buf: &[u8], i: usize) -> u32 {
    u32::from(buf.get(i).copied().unwrap_or(0))
}

/// Слово big-endian `buf[i]<<8 | buf[i+1]`.
fn be16(buf: &[u8], i: usize) -> u32 {
    byte(buf, i) << 8 | byte(buf, i + 1)
}

/// `_checksum_calculate`, util-checksum.c:23. Сумма 16-битных слов; нечётный
/// хвост дополняется нулевым байтом справа. `unsigned` в C -> `wrapping_add`.
fn checksum_calculate(buf: &[u8]) -> u32 {
    let mut sum = 0u32;
    let (pairs, rest) = buf.as_chunks::<2>();
    for c in pairs {
        sum = sum.wrapping_add(u32::from(c[0]) << 8 | u32::from(c[1]));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    sum
}

/// Частичная сумма IP-заголовка без инверсии, templ-pkt.c:184.
///
/// `max` - смещение конца пакета; сумма берётся не дальше `offset + ihl*4`.
/// C читает `px[i+1]` без проверки границ; здесь отсутствующий байт - 0.
pub fn ip_header_checksum(px: &[u8], offset_ip: usize, max: usize) -> u16 {
    let header_length = ((byte(px, offset_ip) & 0xF) * 4) as usize;
    let max = max.min(offset_ip + header_length);
    let mut xsum = 0u32;
    let mut i = offset_ip;
    while i < max {
        xsum = xsum.wrapping_add(be16(px, i));
        i += 2;
    }
    // Три свёртки, как в C (:200-202).
    for _ in 0..3 {
        xsum = (xsum & 0xFFFF) + (xsum >> 16);
    }
    xsum as u16
}

/// Три свёртки `u64` без инверсии, как templ-pkt.c:200-202, :266-268 и
/// :1015-1017. C суммирует `checksum_tcp + ip_me + ip_them + port_me +
/// port_them + seqno` в `uint64_t` (templ-pkt.c:1009-1018, до ~3*2^32), поэтому
/// свёртка через `u32` дала бы другой результат.
pub fn fold(sum: u64) -> u16 {
    let mut x = sum;
    for _ in 0..3 {
        x = (x >> 16) + (x & 0xFFFF);
    }
    x as u16
}

/// Частичная сумма TCP-сегмента с псевдозаголовком, без инверсии,
/// templ-pkt.c:243-271 (`tcp_ipv4_checksum`). Берутся адреса из IP-заголовка
/// (`offset_ip+12..20`) и слова `offset_tcp..offset_app` (для нечётной длины
/// C читает байт сразу за концом; здесь за границей буфера - 0).
pub fn tcp_ipv4_partial(px: &[u8], offset_ip: usize, offset_tcp: usize, offset_app: usize) -> u16 {
    let mut xsum = 6u32;
    xsum = xsum.wrapping_add(offset_app.wrapping_sub(offset_tcp) as u32);
    for k in [12, 14, 16, 18] {
        xsum = xsum.wrapping_add(be16(px, offset_ip + k));
    }
    let mut i = offset_tcp;
    while i < offset_app {
        xsum = xsum.wrapping_add(be16(px, i));
        i += 2;
    }
    fold(u64::from(xsum))
}

/// Складывает и инвертирует, util-checksum.c:62.
pub fn fold_and_invert(sum: u32) -> u16 {
    let sum = (sum >> 16) + (sum & 0xFFFF);
    let sum = (sum >> 16) + (sum & 0xFFFF);
    (!sum & 0xFFFF) as u16
}

/// util-checksum.c:74. Псевдозаголовок плюс полезная нагрузка; текущее поле
/// checksum вычитается по `ip_proto`. Для протоколов 0 и 2 псевдозаголовка нет
/// (сумма пересчитывается без него); для 1 он остаётся, как в C.
/// Неизвестный протокол: C возвращает `0xFFFFFFFF`, здесь `0xFFFF`. Эта ветка
/// недостижима (нет C-вызывающих кроме selftest, util-checksum.c:249), а `0xFFFF`
/// неотличимо от настоящего результата.
/// C читает поля checksum без проверки длины; за границей буфера - 0.
pub fn checksum_ipv4(ip_src: u32, ip_dst: u32, ip_proto: u8, payload: &[u8]) -> u16 {
    let mut sum = (ip_src >> 16) & 0xFFFF;
    sum = sum.wrapping_add(ip_src & 0xFFFF);
    sum = sum.wrapping_add((ip_dst >> 16) & 0xFFFF);
    sum = sum.wrapping_add(ip_dst & 0xFFFF);
    sum = sum.wrapping_add(u32::from(ip_proto));
    sum = sum.wrapping_add(payload.len() as u32);
    sum = sum.wrapping_add(checksum_calculate(payload));

    match ip_proto {
        0 => {
            sum = checksum_calculate(payload);
            sum = sum.wrapping_sub(be16(payload, 10));
        }
        1 => sum = sum.wrapping_sub(be16(payload, 2)),
        2 => {
            sum = checksum_calculate(payload);
            sum = sum.wrapping_sub(be16(payload, 2));
        }
        6 => sum = sum.wrapping_sub(be16(payload, 16)),
        17 => sum = sum.wrapping_sub(be16(payload, 6)),
        _ => return 0xFFFF,
    }
    fold_and_invert(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // util-checksum.c:160-190 (ipv4packets[]).
    const IGMP: &str = "1164ee9b00000000";
    const UDP: &str =
        "dc1301bb00296042 5bd6163ab1783d5d dd0e5a0535749291 574caac18576c00f 8d9e19a5cca28165 be";
    const TCP: &str = "7e7069951fb977c6ee097b72501803fd84b20000170303003a6c04e30e25798e1c98dd2c8d413953fbd0d53e14f8dfb9b847e043ab0924587c6aab91af24c05cc6af5645eda3de06a2d1790a21fe9c2e6e8119";

    #[test]
    fn checksum_ipv4_reference_vectors() {
        let igmp = hex(IGMP);
        assert_eq!(igmp.len(), 8);
        assert_eq!(checksum_ipv4(0x0a14_1e01, 0xe000_0001, 2, &igmp), 0xee9b);
        let udp = hex(UDP);
        assert_eq!(udp.len(), 41);
        assert_eq!(checksum_ipv4(0x0a14_1ec9, 0xadc2_900a, 17, &udp), 0x6042);
        let tcp = hex(TCP);
        assert_eq!(tcp.len(), 83);
        assert_eq!(checksum_ipv4(0x0a14_1ec9, 0xa2fe_c14a, 6, &tcp), 0x84b2);
    }

    #[test]
    fn unknown_protocol_returns_all_ones() {
        // C returns 0xFFFFFFFF (util-checksum.c:112); truncated to u16.
        assert_eq!(checksum_ipv4(1, 2, 99, &[0u8; 24]), 0xFFFF);
    }

    #[test]
    fn fold_and_invert_double_fold() {
        // 0x1FFFF -> 0x10000 -> 0x0001 -> !1
        assert_eq!(fold_and_invert(0x1FFFF), 0xFFFE);
        assert_eq!(fold_and_invert(0), 0xFFFF);
    }

    #[test]
    fn ip_header_checksum_known_header() {
        // Classic example header, checksum field 0xb861; sum of all words
        // folds to 0xFFFF for a valid header.
        let h = hex("4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7");
        assert_eq!(ip_header_checksum(&h, 0, h.len()), 0xFFFF);
        // With the checksum zeroed, partial sum is the complement of 0xb861.
        let mut z = h.clone();
        z[10] = 0;
        z[11] = 0;
        assert_eq!(ip_header_checksum(&z, 0, z.len()), !0xb861u16);
    }

    #[test]
    fn ip_header_checksum_respects_ihl_and_offset() {
        let mut p = vec![0xAAu8, 0xBB];
        p.extend(hex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7"));
        p.extend([0xFF; 8]); // payload beyond IHL must be ignored
        let max = p.len();
        assert_eq!(ip_header_checksum(&p, 2, max), !0xb861u16);
    }

    #[test]
    fn fold_u64_overflowing_incremental_sum() {
        // C-значение (harness h2.c): sum = 0x1234ABCD + 0xC0A80101 + 0xFFFFFFFE
        // + 80 + 0xFFFFF + 0xFFFFFFFF = 12128660762 -> 32777.
        let sum = 0x1234_ABCDu64 + 0xC0A8_0101 + 0xFFFF_FFFE + 80 + 0xF_FFFF + 0xFFFF_FFFF;
        assert_eq!(sum, 12_128_660_762);
        assert_eq!(fold(sum), 32777);
        // Свёртка через u32 дала бы другое значение.
        assert_ne!(fold(u64::from(sum as u32)), 32777);
    }

    fn tcp_buf() -> Vec<u8> {
        let mut v: Vec<u8> = (0..60u32).map(|i| (i * 7 + 3) as u8).collect();
        v[0] = 0x45;
        v
    }

    #[test]
    fn tcp_ipv4_partial_matches_c() {
        let p = tcp_buf();
        assert_eq!(tcp_ipv4_partial(&p, 0, 20, 40), 50240);
        assert_eq!(tcp_ipv4_partial(&p, 0, 34, 54), 38161);
    }

    #[test]
    fn ip_header_checksum_truncated_and_odd_max() {
        let h = hex("4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7");
        assert_eq!(ip_header_checksum(&h, 0, 20), 18334);
        // max < offset+IHL*4 (C harness values).
        assert_eq!(ip_header_checksum(&h, 0, 12), 50564);
        // odd max: last word still reads px[max]
        assert_eq!(ip_header_checksum(&h, 0, 13), 34349);
    }
}
