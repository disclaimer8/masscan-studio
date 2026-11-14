//! ZeroAccess, порты 16464/16465/16470/16471 (справка B8): ответы `retL`, зашифрованные как у бота. CRC здесь
//! побитовая (не таблица парсера), чтобы генератор не повторял код, который проверяет.

use super::{Case, Mode, cat};

/// CRC-32 (отражённый многочлен 0xEDB88320), побитно.
fn crc32(px: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in px {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// XOR с ключом `ftp2`, ключ после каждого слова циклически на бит влево (`zadecrypt`,
/// `src/proto-zeroaccess.c:111-129`).
fn xor(px: &[u8]) -> Vec<u8> {
    let mut key = u32::from_be_bytes(*b"ftp2");
    let mut out = Vec::new();
    for word in px.chunks(4) {
        out.extend(word.iter().zip(key.to_le_bytes()).map(|(b, k)| b ^ k));
        key = key.rotate_left(1);
    }
    out
}

/// Открытый текст с CRC (поле CRC при подсчёте нулевое, хранится little-endian) и шифрование.
fn seal(plain: &[u8]) -> Vec<u8> {
    let mut buf = plain.to_vec();
    buf[..4].fill(0);
    let crc = crc32(&buf);
    buf[..4].copy_from_slice(&crc.to_le_bytes());
    xor(&buf)
}

/// Открытый текст `retL`: CRC, тег, 4 байта, число адресов LE, записи по 8 байт (адрес и 4 байта).
fn retl(tag: &[u8; 4], count: u32, addrs: &[[u8; 4]]) -> Vec<u8> {
    let mut v = cat(&[&[0; 4], tag, b"mass", &count.to_le_bytes()]);
    for (i, a) in addrs.iter().enumerate() {
        v.extend_from_slice(a);
        v.extend_from_slice(&u32::try_from(i).expect("index").to_be_bytes());
    }
    v
}

const THREE: [[u8; 4]; 3] = [[192, 0, 2, 10], [198, 51, 100, 20], [203, 0, 113, 30]];

/// Зонд getL (`zeroaccess_getL`, `src/proto-zeroaccess.c:23-26`).
const GETL: [u8; 16] = [
    0x46, 0x5d, 0x49, 0x9e, 0x28, 0x94, 0x8d, 0xab, 0xc9, 0xc0, 0xd1, 0x99, 0xe0, 0xf2, 0xc2, 0x5e,
];
/// Вектор selftest (`sample`, `src/proto-zeroaccess.c:263-268`): getL для xrand 0x7f570a0f.
const SELFTEST: [u8; 16] = [
    0xda, 0xbe, 0x6e, 0xce, 0x28, 0x94, 0x8d, 0xab, 0xc9, 0xc0, 0xd1, 0x99, 0xec, 0xd6, 0xa9, 0x3c,
];

pub fn cases() -> Vec<Case> {
    let with = |name, port, rawudp, mode, payload, about| Case {
        name,
        port,
        cookie: 0,
        rawudp,
        mode,
        payload,
        about,
    };
    let three = seal(&retl(b"Lter", 3, &THREE));
    // Самые длинные адреса RFC 5737 (`198.51.100.2NN `, 15 символов).
    let long = |n: u8| -> Vec<u8> {
        let addrs: Vec<[u8; 4]> = (0..n).map(|i| [198, 51, 100, 200 + i]).collect();
        seal(&retl(b"Lter", u32::from(n), &addrs))
    };
    let many = |n: usize| -> Vec<u8> {
        let addrs: Vec<[u8; 4]> = (0..n)
            .map(|i| [203, 0, 113, u8::try_from(i % 256).expect("octet")])
            .collect();
        seal(&retl(b"Lter", u32::try_from(n).expect("count"), &addrs))
    };
    vec![
        with(
            "zeroaccess-retl",
            16464,
            false,
            Mode::Prefixes,
            three.clone(),
            "retL с тремя адресами: zeroaccess и сырой (src/proto-zeroaccess.c:217-258); все обрезки (CRC не сходится)",
        ),
        with(
            "zeroaccess-retl-16465",
            16465,
            false,
            Mode::Whole,
            three.clone(),
            "порт 16465 (src/proto-udp.c:102-107)",
        ),
        with(
            "zeroaccess-retl-16470",
            16470,
            false,
            Mode::Whole,
            three.clone(),
            "порт 16470",
        ),
        with(
            "zeroaccess-retl-16471",
            16471,
            false,
            Mode::Whole,
            three.clone(),
            "порт 16471",
        ),
        with(
            "zeroaccess-retl-rawudp",
            16464,
            true,
            Mode::Whole,
            three.clone(),
            "--rawudp: сырой один раз (status 0)",
        ),
        with(
            "zeroaccess-crc-sweep",
            16464,
            false,
            Mode::Sweep(0),
            three,
            "первый байт CRC 0..255: проходит только верный (src/proto-zeroaccess.c:201-211)",
        ),
        with(
            "zeroaccess-getl-probe",
            16464,
            false,
            Mode::Whole,
            GETL.to_vec(),
            "зонд getL: CRC верна, тег не Lter, сырой (src/proto-zeroaccess.c:214-215)",
        ),
        with(
            "zeroaccess-selftest",
            16464,
            false,
            Mode::Whole,
            SELFTEST.to_vec(),
            "вектор selftest C: getL, сырой",
        ),
        with(
            "zeroaccess-count-257",
            16464,
            false,
            Mode::Whole,
            seal(&retl(b"Lter", 257, &THREE)),
            "число адресов 257: больше 256, сырой (src/proto-zeroaccess.c:223-224)",
        ),
        with(
            "zeroaccess-count-past-end",
            16464,
            false,
            Mode::Whole,
            seal(&retl(b"Lter", 4, &THREE)),
            "4 адреса в пакете на 3: выход за пакет, сырой (src/proto-zeroaccess.c:225-226)",
        ),
        with(
            "zeroaccess-no-addresses",
            16464,
            false,
            Mode::Whole,
            seal(&retl(b"Lter", 0, &[])),
            "ноль адресов: `ZeroAccess:`",
        ),
        with(
            "zeroaccess-unaligned",
            16464,
            false,
            Mode::Whole,
            seal(&cat(&[&retl(b"Lter", 1, &THREE[..1]), &[1, 2, 3]])),
            "длина 27, не кратна 4: последнее слово zadecrypt у C читает за датаграммой, на вывод не влияет",
        ),
        with(
            "zeroaccess-12-addresses",
            16464,
            false,
            Mode::Whole,
            long(12),
            "12 длинных адресов: баннер 191 байт, внутри banner[200] даже без max_length (C1.17)",
        ),
        with(
            "zeroaccess-13-addresses",
            16464,
            false,
            Mode::Whole,
            long(13),
            "13 длинных адресов: баннер 206 байт; banout без max_length у C пишет за banner[200] \
             (src/proto-zeroaccess.c:183-185, C1.17)",
        ),
        with(
            "zeroaccess-over-2048",
            16464,
            false,
            Mode::Whole,
            many(255),
            "255 адресов, 2056 байт: C считает CRC по стеку за buf[2048] (src/proto-zeroaccess.c:176, 208), \
             не совпадает; у нас не ZeroAccess, сырой",
        ),
    ]
}
