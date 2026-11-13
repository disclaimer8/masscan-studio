//! SNMP, порт 161 (`src/proto-snmp.c`): разбор BER-ответа SNMPv1 и текст `OID:значение` по связкам.
//!
//! Отличие от C одно, без видимого следствия: `asn1_integer` у C читает байт тега без проверки границы
//! (`src/proto-snmp.c:151`), на конце датаграммы это чтение на 1 байт за ней (ASan, эталоны `snmp-selftest`,
//! `snmp-reqid-21-bytes`). Результат от прочитанного байта не зависит: при `offset >= length` и тег 2, и любой другой
//! дают ошибку и `offset = length`; здесь байт не читается.

use std::sync::OnceLock;

use super::{Status, UdpContext, byte};
use crate::app::app_id;

/// Ошибка BER у C (`0xFFFFffff`, `src/proto-snmp.c:115`).
const ASN1_ERROR: u64 = 0xFFFF_FFFF;

/// Таблица `mib[]` (`src/proto-snmp.c:73-95`), в том же порядке: порядок решает ничью `mib2`/`sys`.
const MIB: [(&str, &str); 17] = [
    ("43.1006.51.341332", "selftest"),
    ("43", "iso.org"),
    ("43.6", "dod"),
    ("43.6.1", "inet"),
    ("43.6.1.2", "mgmt"),
    ("43.6.1.2.1", "mib2"),
    ("43.6.1.2.1.", "sys"),
    ("43.6.1.2.1.1.1", "sysDescr"),
    ("43.6.1.2.1.1.2", "sysObjectID"),
    ("43.6.1.2.1.1.3", "sysUpTime"),
    ("43.6.1.2.1.1.4", "sysContact"),
    ("43.6.1.2.1.1.5", "sysName"),
    ("43.6.1.2.1.1.6", "sysLocation"),
    ("43.6.1.2.1.1.7", "sysServices"),
    ("43.6.1.4", "priv"),
    ("43.6.1.4.1", "enterprise"),
    ("43.6.1.4.1.2001", "okidata"),
];

/// `convert_oid` (`src/proto-snmp.c:499-531`): десятичные числа через точку в base-128. Таблица только
/// десятичная, поэтому `strtoul(..., 0)` здесь просто десятичный разбор; хвостовая точка ничего не добавляет.
fn convert_oid(src: &str) -> Vec<u8> {
    let mut dst = Vec::new();
    for part in src.split('.').filter(|p| !p.is_empty()) {
        let Ok(id) = part.parse::<u32>() else {
            break;
        };
        // id_prefix_count (src/proto-snmp.c:483-494)
        let count = match id {
            0x1000_0000.. => 4,
            0x20_0000.. => 3,
            0x4000.. => 2,
            0x80.. => 1,
            _ => 0,
        };
        for i in (1..=count).rev() {
            dst.push(((id >> (7 * i)) & 0x7F) as u8 | 0x80);
        }
        dst.push((id & 0x7F) as u8);
    }
    dst
}

/// Шаблоны MIB в байтах, по порядку `mib[]`.
fn patterns() -> &'static [Vec<u8>] {
    static P: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    P.get_or_init(|| MIB.iter().map(|(oid, _)| convert_oid(oid)).collect())
}

/// Поиск имени `snmp_banner_oid` (`src/proto-snmp.c:220-232`) без автомата Aho-Corasick. У C это smack с
/// `SMACK_ANCHOR_BEGIN | SMACK_SNMP_HACK` (`src/proto-snmp.c:610-615`): все шаблоны привязаны к началу, после
/// первого несовпадения автомат навсегда в базовом состоянии (переходы туда из любого состояния, `src/smack1.c:886-892`),
/// а в каждом состоянии, из которого шаблон идёт дальше, байт 0x80 ведёт в то же состояние (`src/smack1.c:824-827`).
/// Совпадение сообщается после каждого байта, оставившего автомат в состоянии совпадения, и последнее сообщённое
/// побеждает: самый длинный префикс, а смещение имени сдвигается и петлёй 0x80. У `mib2` и `sys` одно состояние,
/// `m_ids = [mib2, sys]`; `smack_search_next` отдаёт их с конца по одному за вызов (`src/smack1.c:1471-1484`), а цикл
/// вызывающего кончается, когда смещение дошло до конца OID: на последнем байте побеждает `sys`, иначе `mib2`.
/// Возвращает (индекс в `mib[]`, смещение после совпадения).
fn mib_match(oid: &[u8]) -> Option<(usize, usize)> {
    let pats = patterns();
    // Текущее состояние: префикс шаблонов без пропущенных 0x80.
    let mut prefix: Vec<u8> = Vec::new();
    let mut found = None;
    for (i, &b) in oid.iter().enumerate() {
        let has_children = pats
            .iter()
            .any(|p| p.len() > prefix.len() && p.starts_with(&prefix));
        if !(b == 0x80 && has_children) {
            prefix.push(b);
            if !pats.iter().any(|p| p.starts_with(&prefix)) {
                break;
            }
        }
        let ids: Vec<usize> = (0..pats.len())
            .filter(|&k| pats.get(k).is_some_and(|p| *p == prefix))
            .collect();
        let pick = if i + 1 < oid.len() {
            ids.first()
        } else {
            ids.last()
        };
        if let Some(&id) = pick {
            found = Some((id, i + 1));
        }
    }
    found
}

/// `next_id` (`src/proto-snmp.c:189-202`): цифра base-128. `uint64_t <<= 7` теряет старшие биты: так же здесь
/// (`<<` в Rust не проверяет потерю битов значения).
fn next_id(oid: &[u8], offset: &mut usize) -> u64 {
    let mut result = 0u64;
    while let Some(b) = byte(oid, *offset).filter(|b| b & 0x80 != 0) {
        result = result << 7 | u64::from(b & 0x7F);
        *offset += 1;
    }
    if let Some(b) = byte(oid, *offset) {
        result = result << 7 | u64::from(b & 0x7F);
        *offset += 1;
    }
    result
}

/// `snmp_banner_oid` (`src/proto-snmp.c:206-251`): имя MIB и остаток `.N`; последний нулевой `.0` отбрасывается.
fn snmp_banner_oid(oid: &[u8], banner: &mut Vec<u8>) {
    let mut i = 0;
    if let Some((id, offset)) = mib_match(oid) {
        if let Some((_, name)) = MIB.get(id) {
            banner.extend_from_slice(name.as_bytes());
        }
        i = offset;
    }
    while i < oid.len() {
        let x = next_id(oid, &mut i);
        if x == 0 && i >= oid.len() {
            break;
        }
        banner.extend_from_slice(format!(".{x}").as_bytes());
    }
}

/// `snmp_banner` (`src/proto-snmp.c:255-292`): перевод строки перед каждой связкой, кроме первой
/// (`banout_newline` пишет только в непустой баннер, `src/proto-banout.c:149-158`).
fn snmp_banner(oid: &[u8], var_tag: u8, var: &[u8], banner: &mut Vec<u8>) {
    if !banner.is_empty() {
        banner.push(b'\n');
    }
    snmp_banner_oid(oid, banner);
    banner.push(b':');
    match var_tag {
        // INTEGER: беззнаково, младшие 64 бита (src/proto-snmp.c:272-280).
        2 => {
            let v = var.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
            banner.extend_from_slice(v.to_string().as_bytes());
        }
        6 => snmp_banner_oid(var, banner),
        // OCTET STRING, IpAddress, Counter32, TimeTicks и прочее: сырые байты (C1.13).
        _ => banner.extend_from_slice(var),
    }
}

/// Курсор BER: `px`, текущая (сужаемая) длина и смещение, как `length`/`offset` в `snmp_parse` (оба `uint64_t`).
struct Ber<'a> {
    px: &'a [u8],
    length: u64,
    offset: u64,
}

impl Ber<'_> {
    fn at(&self, offset: u64) -> Option<u8> {
        usize::try_from(offset).ok().and_then(|o| byte(self.px, o))
    }

    /// `asn1_tag` (`src/proto-snmp.c:179-185`): 0 за концом.
    fn tag(&mut self) -> u8 {
        if self.offset >= self.length {
            return 0;
        }
        let t = self.at(self.offset).unwrap_or(0);
        self.offset += 1;
        t
    }

    fn fail(&mut self) -> u64 {
        self.offset = self.length;
        ASN1_ERROR
    }

    /// `asn1_length` (`src/proto-snmp.c:105-139`): короткая и длинная форма; длина длины 0 или значение больше
    /// 0x10000 это ошибка.
    fn len(&mut self) -> u64 {
        let Some(first) = (self.offset < self.length)
            .then(|| self.at(self.offset))
            .flatten()
        else {
            return self.fail();
        };
        if first & 0x80 != 0 && self.offset + u64::from(first & 0x7F) >= self.length {
            return self.fail();
        }
        self.offset += 1;
        if first & 0x80 == 0 {
            return u64::from(first);
        }
        let mut length_of_length = first & 0x7F;
        if length_of_length == 0 {
            return self.fail();
        }
        let mut result = 0u64;
        while length_of_length != 0 {
            let Some(b) = self.at(self.offset) else {
                return self.fail();
            };
            result = result * 256 + u64::from(b);
            self.offset += 1;
            if result > 0x10000 {
                return self.fail();
            }
            length_of_length -= 1;
        }
        result
    }

    /// `asn1_integer` (`src/proto-snmp.c:145-175`): до 20 байт, беззнаково, младшие 64 бита. C читает байт тега без
    /// проверки границы (`src/proto-snmp.c:151`); за концом любой байт ведёт к ошибке, поэтому здесь сразу ошибка.
    fn integer(&mut self) -> u64 {
        if self.offset >= self.length || self.at(self.offset) != Some(0x02) {
            return self.fail();
        }
        self.offset += 1;
        let int_length = self.len();
        if int_length == ASN1_ERROR || self.offset + int_length > self.length || int_length > 20 {
            return self.fail();
        }
        let mut result = 0u64;
        for _ in 0..int_length {
            let Some(b) = self.at(self.offset) else {
                return self.fail();
            };
            result = result << 8 | u64::from(b);
            self.offset += 1;
        }
        result
    }

    /// `if (length > outer_length + offset) length = outer_length + offset;`
    fn clamp(&mut self, outer_length: u64) {
        let end = outer_length.saturating_add(self.offset);
        if self.length > end {
            self.length = end;
        }
    }

    fn slice(&self, start: u64, len: u64) -> &[u8] {
        let (Ok(start), Ok(len)) = (usize::try_from(start), usize::try_from(len)) else {
            return &[];
        };
        self.px
            .get(start..start.saturating_add(len))
            .unwrap_or_default()
    }
}

/// `snmp_parse` (`src/proto-snmp.c:301-398`): текст баннера и request-id (`(unsigned)`; 0, если разбор до него не
/// дошёл).
fn snmp_parse(px: &[u8]) -> (Vec<u8>, u32) {
    let mut banner = Vec::new();
    let mut ber = Ber {
        px,
        length: u64::try_from(px.len()).unwrap_or(u64::MAX),
        offset: 0,
    };
    if ber.tag() != 0x30 {
        return (banner, 0);
    }
    let outer = ber.len();
    ber.clamp(outer);
    // SNMPv1 only (C1.13).
    if ber.integer() != 0 {
        return (banner, 0);
    }
    if ber.tag() != 0x04 {
        return (banner, 0);
    }
    let community_length = ber.len();
    ber.offset = ber.offset.saturating_add(community_length);
    let pdu_tag = ber.tag();
    if !(0xA0..=0xA5).contains(&pdu_tag) {
        return (banner, 0);
    }
    let outer = ber.len();
    ber.clamp(outer);
    // (unsigned)snmp->request_id: младшие 32 бита (src/proto-snmp.c:343).
    let request_id = (ber.integer() & 0xFFFF_FFFF) as u32;
    let _error_status = ber.integer();
    let _error_index = ber.integer();
    if ber.tag() != 0x30 {
        return (banner, request_id);
    }
    let outer = ber.len();
    ber.clamp(outer);
    // Каждый оборот съедает хотя бы байт 0x30.
    while ber.offset < ber.length {
        if ber.at(ber.offset) != Some(0x30) {
            break;
        }
        ber.offset += 1;
        let varbind_length = ber.len();
        if varbind_length == ASN1_ERROR {
            break;
        }
        if ber.offset.saturating_add(varbind_length) > ber.length {
            return (banner, request_id);
        }
        if ber.tag() != 6 {
            return (banner, request_id);
        }
        let oid_length = ber.len();
        let oid_start = ber.offset;
        ber.offset = ber.offset.saturating_add(oid_length);
        if ber.offset > ber.length {
            return (banner, request_id);
        }
        let var_tag = ber.tag();
        let var_length = ber.len();
        let var_start = ber.offset;
        ber.offset = ber.offset.saturating_add(var_length);
        if ber.offset > ber.length {
            return (banner, request_id);
        }
        if var_tag == 5 {
            continue;
        }
        snmp_banner(
            ber.slice(oid_start, oid_length),
            var_tag,
            ber.slice(var_start, var_length),
            &mut banner,
        );
    }
    (banner, request_id)
}

/// `handle_snmp` (`src/proto-snmp.c:536-584`): request-id сверяется с `cookie & 0x7FFFFFFF`; при совпадении баннер
/// `snmp` (может быть пустым) и сырой.
pub(super) fn handle_snmp(cx: &UdpContext, px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    let (banner, request_id) = snmp_parse(px);
    if cx.cookie & 0x7FFF_FFFF != request_id {
        return Status::Handled;
    }
    out.push((app_id::SNMP, banner));
    Status::Fallback
}

#[cfg(test)]
mod tests {
    use super::super::handle_udp;
    use super::*;
    use crate::app::app_id;

    /// Вектор `snmp_selftest_banner` (`src/proto-snmp.c:630-644`).
    const SELFTEST: [u8; 59] = [
        0x30, 0x39, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0xA2, 0x2C,
        0x02, 0x01, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x21, 0x30, 0x1F, 0x06, 0x09,
        0x2B, 0x06, 0x01, 0x80, 0x02, 0x01, 0x01, 0x02, 0x00, 0x06, 0x12, 0x2B, 0x06, 0x01, 0x04,
        0x01, 0x8F, 0x51, 0x01, 0x01, 0x01, 0x82, 0x29, 0x5D, 0x01, 0x1B, 0x02, 0x02, 0x01,
    ];

    fn snmp(cookie: u32, px: &[u8]) -> Vec<(u16, Vec<u8>)> {
        handle_udp(
            &UdpContext {
                port_them: 161,
                cookie,
                rawudp: false,
            },
            px,
        )
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, u8::try_from(value.len()).expect("short form")];
        v.extend(value);
        v
    }

    /// GetResponse SNMP версии `version` с request-id 0x5EED1234 и одной связкой `oid` = OCTET STRING `value`.
    fn response(version: u8, oid: &[u8], value: &[u8]) -> Vec<u8> {
        let vb = tlv(0x30, &[tlv(6, oid), tlv(4, value)].concat());
        let pdu = tlv(
            0xA2,
            &[
                tlv(2, &[0x5E, 0xED, 0x12, 0x34]),
                tlv(2, &[0]),
                tlv(2, &[0]),
                tlv(0x30, &vb),
            ]
            .concat(),
        );
        tlv(0x30, &[tlv(2, &[version]), tlv(4, b"public"), pdu].concat())
    }

    /// Вектор selftest C: `sysObjectID:okidata.1.1.1.297.93.1.27.2.2.1` (`src/proto-snmp.c:657-665`).
    #[test]
    fn snmp_selftest_vector() {
        assert_eq!(
            snmp(0x26, &SELFTEST),
            vec![
                (
                    app_id::SNMP,
                    b"sysObjectID:okidata.1.1.1.297.93.1.27.2.2.1".to_vec()
                ),
                (app_id::NONE, SELFTEST.to_vec())
            ]
        );
        assert_eq!(snmp(0x27, &SELFTEST), vec![]);
        // Старший бит cookie маскируется (src/proto-snmp.c:568).
        assert_eq!(snmp(0x8000_0026, &SELFTEST).len(), 2);
    }

    /// SNMPv2c (версия 1): `snmp_parse` выходит до request-id, он остаётся 0 и не совпадает с cookie: ничего
    /// (C1.13). При cookie & 0x7FFFFFFF = 0 совпадает: пустой баннер snmp и сырой.
    #[test]
    fn snmp_v2c_gives_no_banner() {
        let px = response(1, &[0x2B, 6, 1, 2, 1, 1, 5, 0], b"router1");
        assert_eq!(snmp(0x5EED_1234, &px), vec![]);
        assert_eq!(
            snmp(0x8000_0000, &px),
            vec![(app_id::SNMP, vec![]), (app_id::NONE, px.clone())]
        );
        let v1 = response(0, &[0x2B, 6, 1, 2, 1, 1, 5, 0], b"router1");
        assert_eq!(
            snmp(0x5EED_1234, &v1),
            vec![
                (app_id::SNMP, b"sysName:router1".to_vec()),
                (app_id::NONE, v1.clone())
            ]
        );
    }

    /// Sub-id из 21 байта base-128: C сдвигает `uint64_t` с потерей старших бит (`src/proto-snmp.c:193-200`),
    /// здесь так же, без паники переполнения: все единицы дают `u64::MAX`.
    #[test]
    fn snmp_huge_subid_does_not_overflow() {
        let mut oid = vec![0x2B, 6, 1, 4, 1];
        oid.extend([0xFF; 20]);
        oid.push(0x7F);
        let px = response(0, &oid, b"x");
        assert_eq!(
            snmp(0x5EED_1234, &px),
            vec![
                (app_id::SNMP, b"enterprise.18446744073709551615:x".to_vec()),
                (app_id::NONE, px.clone())
            ]
        );
        // 0x81 0x80 ... 0x00: 1 << 133 по модулю 2^64 = 0, но значение не последнее, поэтому печатается.
        let mut oid = vec![0x2B, 0x81];
        oid.extend([0x80; 18]);
        oid.extend([0x00, 0x05]);
        let px = response(0, &oid, b"y");
        assert_eq!(
            snmp(0x5EED_1234, &px)[0],
            (app_id::SNMP, b"iso.org.0.5:y".to_vec())
        );
    }

    /// `convert_oid` даёт те же байты, что второй selftest C (`xx[]`, `src/proto-snmp.c:677-711`), и поиск по ним
    /// находит `selftest`.
    #[test]
    fn snmp_mib_patterns_match_c_selftest() {
        let xx = [43u8, 0x80 | 7, 110, 51, 0x80 | 20, 0x80 | 106, 84];
        assert_eq!(convert_oid("43.1006.51.341332"), xx);
        assert_eq!(
            convert_oid("43.6.1.4.1.2001"),
            [0x2B, 6, 1, 4, 1, 0x8F, 0x51]
        );
        assert_eq!(convert_oid("43.6.1.2.1."), convert_oid("43.6.1.2.1"));
        assert_eq!(convert_oid("268435456"), [0x81, 0x80, 0x80, 0x80, 0x00]);
        assert_eq!(mib_match(&xx), Some((0, xx.len())));
        assert_eq!(MIB[0].1, "selftest");
    }

    /// Ничья `mib2`/`sys` (одинаковые байты после `convert_oid`): на конце OID побеждает `sys`, дальше `mib2`
    /// (порядок `m_ids` в `smack_search_next`, `src/smack1.c:1471-1484`).
    #[test]
    fn snmp_mib2_sys_tie() {
        let name = |oid: &[u8]| {
            let px = response(0, oid, b"v");
            snmp(0x5EED_1234, &px).remove(0).1
        };
        assert_eq!(name(&[0x2B, 6, 1, 2, 1]), b"sys:v");
        assert_eq!(name(&[0x2B, 6, 1, 2, 1, 2]), b"mib2.2:v");
        assert_eq!(name(&[0x2B, 6, 1, 2, 1, 1, 1, 0]), b"sysDescr:v");
        assert_eq!(name(&[0x2B, 6, 1, 0x80, 2, 1, 1, 5, 0]), b"sysName:v");
    }
}
