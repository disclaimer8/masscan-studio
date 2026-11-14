//! ZeroAccess, порты 16464, 16465, 16470 и 16471 (`handle_zeroaccess`, `src/proto-zeroaccess.c:170-259`). Cookie нет.
//! Ответ `retL` расшифровывается XOR с ключом `ftp2`, который после каждого 4-байтового слова сдвигается
//! циклически на бит влево (`zadecrypt`, `src/proto-zeroaccess.c:111-129`); CRC-32 пакета с обнулённым полем CRC
//! равна сохранённой (little-endian), байты 4-7 `Lter`, число адресов не больше 256 и помещается. Баннер
//! `ZeroAccess:` и `a.b.c.d ` на каждый адрес, затем сырой (возврат 0).
//!
//! Отличия от C (Р1 класс а, Р2), каждое с эталоном:
//! - C расшифровывает в стековый буфер 2048 байт, а CRC считает по всей длине датаграммы (`src/proto-zeroaccess.c:
//!   176, 208`): у датаграммы длиннее 2048 байт CRC идёт по памяти стека за буфером и на практике не совпадает. У нас
//!   такая датаграмма не ZeroAccess (сырой баннер);
//! - `banout` C заполняет руками без `max_length` (`src/proto-zeroaccess.c:183-185`, C1.17): дописывание зависит от
//!   мусора стека (с нулём C зацикливается в `banout_expand`, с большим значением пишет за `banner[200]`). У нас
//!   баннер собирается как у любого другого парсера;
//! - у длины не кратной 4 последнее слово `zadecrypt` читает до трёх байт за датаграммой; на вывод это не влияет
//!   (CRC и адреса берут только первые `len` байт), у нас не читается;
//! - сохранённую CRC C собирает как `buf[3]<<24` в `int` (`src/proto-zeroaccess.c:206`, UB по UBSan при старшем бите);
//!   у нас это `u32` little-endian, то же значение, что gcc даёт на деле.

use super::Status;
use crate::app::app_id;

/// Таблица CRC-32 (`crc32_table`, `src/proto-zeroaccess.c:31-84`): обычный отражённый многочлен 0xEDB88320.
const CRC32_TABLE: [u32; 256] = crc32_table();

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// `crc_calc` (`src/proto-zeroaccess.c:90-103`).
fn crc_calc(px: &[u8]) -> u32 {
    !px.iter().fold(!0u32, |crc, &b| {
        CRC32_TABLE[usize::from((crc as u8) ^ b)] ^ (crc >> 8)
    })
}

/// `zadecrypt` (`src/proto-zeroaccess.c:111-129`); XOR, поэтому и шифрует.
fn zadecrypt(src: &[u8]) -> Vec<u8> {
    let mut key = u32::from_be_bytes(*b"ftp2");
    let mut dst = Vec::with_capacity(src.len());
    for word in src.chunks(4) {
        for (&b, k) in word.iter().zip(key.to_le_bytes()) {
            dst.push(b ^ k);
        }
        key = key.rotate_left(1);
    }
    dst
}

/// Буфер расшифровки C (`unsigned char buf[2048]`, `src/proto-zeroaccess.c:176`).
const BUF: usize = 2048;

/// Little-endian u32 по смещению (`buf[0] | buf[1]<<8 | ...`, `src/proto-zeroaccess.c:206, 222`).
fn le32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

/// `handle_zeroaccess`.
pub(super) fn handle_zeroaccess(px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    // Короче 16 байт C отбрасывает после CRC (src/proto-zeroaccess.c:214), длиннее 2048 читает за буфером (Р2).
    if px.len() < 16 || px.len() > BUF {
        return Status::Fallback;
    }
    let mut buf = zadecrypt(px);
    let (Some(old_crc), Some(ip_count)) = (le32(&buf, 0), le32(&buf, 12)) else {
        return Status::Fallback;
    };
    let is_retl = buf.get(4..8) == Some(b"Lter".as_slice());
    if let Some(head) = buf.get_mut(..4) {
        head.fill(0);
    }
    // src/proto-zeroaccess.c:201-226
    if old_crc != crc_calc(&buf) || !is_retl || ip_count > 256 {
        return Status::Fallback;
    }
    let Some(entries) = usize::try_from(ip_count)
        .ok()
        .and_then(|n| buf.get(16..16 + n * 8))
    else {
        return Status::Fallback;
    };
    let mut text = b"ZeroAccess:".to_vec();
    for entry in entries.chunks(8) {
        if let [a, b, c, d, ..] = entry {
            text.extend_from_slice(format!("{a}.{b}.{c}.{d} ").as_bytes());
        }
    }
    out.push((app_id::ZEROACCESS, text));
    Status::Fallback
}

/// Шифрует открытый текст `retL` с правильной CRC: для тестов и генератора эталонов.
#[cfg(test)]
pub(super) fn seal(plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    if let Some(head) = buf.get_mut(..4) {
        head.fill(0);
    }
    let crc = crc_calc(&buf);
    if let Some(head) = buf.get_mut(..4) {
        head.copy_from_slice(&crc.to_le_bytes());
    }
    zadecrypt(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp::{UdpContext, handle_udp};

    fn za(px: &[u8]) -> Vec<(u16, Vec<u8>)> {
        handle_udp(
            &UdpContext {
                port_them: 16464,
                cookie: 0,
                rawudp: false,
            },
            px,
        )
    }

    /// Открытый текст `retL`: CRC (заполнит [`seal`]), `Lter`, 4 байта, число адресов LE, записи по 8 байт.
    fn retl(tag: &[u8; 4], count: u32, addrs: &[[u8; 4]]) -> Vec<u8> {
        let mut v = [&[0u8; 4][..], tag, b"mass", &count.to_le_bytes()].concat();
        for a in addrs {
            v.extend_from_slice(a);
            v.extend_from_slice(&[0x5E, 0xED, 0x00, 0x01]);
        }
        v
    }

    /// Таблица и CRC как у C: значения из `crc32_table` и стандартная проверка "123456789".
    #[test]
    fn zeroaccess_crc_table_matches_c() {
        assert_eq!(CRC32_TABLE[1], 0x7707_3096);
        assert_eq!(CRC32_TABLE[128], 0xEDB8_8320);
        assert_eq!(CRC32_TABLE[255], 0x2D02_EF8D);
        assert_eq!(crc_calc(b"123456789"), 0xCBF4_3926);
        // selftest C (src/proto-zeroaccess.c:263-302): зонд getL расшифровывается с верной CRC.
        let sample = [
            0xda, 0xbe, 0x6e, 0xce, 0x28, 0x94, 0x8d, 0xab, 0xc9, 0xc0, 0xd1, 0x99, 0xec, 0xd6,
            0xa9, 0x3c,
        ];
        let mut buf = zadecrypt(&sample);
        let old = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        buf[..4].fill(0);
        assert_eq!(old, crc_calc(&buf));
        assert_eq!(&buf[4..8], b"Lteg");
        assert_eq!(seal(&buf), sample);
    }

    /// CRC и `Lter` (`src/proto-zeroaccess.c:201-215`), предел числа адресов и выход за пакет (`:223-226`).
    #[test]
    fn zeroaccess_crc_and_lter() {
        let addrs = [[192, 0, 2, 10], [198, 51, 100, 20], [203, 0, 113, 30]];
        let px = seal(&retl(b"Lter", 3, &addrs));
        assert_eq!(
            za(&px),
            vec![
                (
                    app_id::ZEROACCESS,
                    b"ZeroAccess:192.0.2.10 198.51.100.20 203.0.113.30 ".to_vec()
                ),
                (app_id::NONE, px.clone())
            ]
        );
        for port in [16465, 16470, 16471] {
            let cx = UdpContext {
                port_them: port,
                cookie: 0,
                rawudp: false,
            };
            assert_eq!(handle_udp(&cx, &px), za(&px));
        }
        // Любой испорченный байт ломает CRC.
        for i in 0..px.len() {
            let mut bad = px.clone();
            bad[i] ^= 0x40;
            assert_eq!(za(&bad), vec![(app_id::NONE, bad.clone())], "byte {i}");
        }
        let raw_only = |plain: &[u8]| {
            let px = seal(plain);
            assert_eq!(za(&px), vec![(app_id::NONE, px.clone())]);
        };
        raw_only(&retl(b"Lteg", 3, &addrs));
        raw_only(&retl(b"Lter", 4, &addrs));
        raw_only(&retl(b"Lter", 257, &[[1, 2, 3, 4]; 257]));
        raw_only(&retl(b"Lter", 0, &[])[..15]);
        // Ноль адресов и длина не кратная 4.
        let px = seal(&[retl(b"Lter", 0, &[]), vec![1, 2]].concat());
        assert_eq!(za(&px)[0], (app_id::ZEROACCESS, b"ZeroAccess:".to_vec()));
        // 256 адресов не помещаются в 2048 байт C: сырой (Р2); 254 помещаются.
        raw_only(&retl(b"Lter", 256, &[[1, 2, 3, 4]; 256]));
        let px = seal(&retl(b"Lter", 254, &[[255, 255, 255, 255]; 254]));
        assert_eq!(px.len(), 2048);
        assert_eq!(za(&px)[0].1.len(), 11 + 254 * 16);
    }
}
