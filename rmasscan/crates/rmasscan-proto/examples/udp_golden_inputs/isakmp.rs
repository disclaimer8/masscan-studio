//! ISAKMP, порт 500 (справка B7): векторы selftest C и собранные ответы. Cookie инициатора у C это 32-битный cookie
//! с четырьмя нулевыми байтами впереди (`src/proto-isakmp.c:401-413`).

use super::{COOKIE, Case, Mode, cat};

/// `sample1` (`src/proto-isakmp.c:464-471`): cookie инициатора 0x00000000C11884DA.
const SAMPLE1: &[u8] = b"\x00\x00\x00\x00\xc1\x18\
\x84\xda\xbe\x3d\xc6\x8e\xea\xf2\xda\xac\x01\x10\x02\x00\x00\x00\
\x00\x00\x00\x00\x00\x50\x00\x00\x00\x34\x00\x00\x00\x01\x00\x00\
\x00\x01\x00\x00\x00\x28\x01\x01\x00\x01\x00\x00\x00\x20\x01\x01\
\x00\x00\x80\x01\x00\x05\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\
\x00\x01\x80\x0b\x00\x01\x80\x0c\x00\x01";
const SAMPLE1_COOKIE: u32 = 0xC118_84DA;

/// `sample2` (`src/proto-isakmp.c:473-481`).
const SAMPLE2: &[u8] = b"\xe4\x7a\x59\x1f\xd0\x57\
\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec\x01\x10\x02\x00\x00\x00\
\x00\x00\x00\x00\x00\x6c\x0d\x00\x00\x3c\x00\x00\x00\x01\x00\x00\
\x00\x01\x00\x00\x00\x30\x01\x01\x00\x01\x00\x00\x00\x28\x01\x01\
\x00\x00\x80\x01\x00\x07\x80\x0e\x00\x80\x80\x02\x00\x02\x80\x04\
\x00\x02\x80\x03\x00\x01\x80\x0b\x00\x01\x00\x0c\x00\x04\x00\x01\
\x51\x80\x00\x00\x00\x14\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\
\x28\xf2\x0e\x95\x45\x2f";

/// `sample3` (`src/proto-isakmp.c:483-502`).
const SAMPLE3: &[u8] = b"\xe4\x7a\x59\x1f\xd0\x57\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec\
\x04\x10\x02\x00\x00\x00\x00\x00\x00\x00\x01\x30\x0a\x00\x00\x84\
\x6d\x02\x6d\x56\x16\xc4\x5b\xe0\x5e\x5b\x89\x84\x11\xe9\xf9\x5d\
\x19\x5c\xea\x00\x9a\xd2\x2c\x62\xbe\xf0\x6c\x57\x1b\x7c\xfb\xc4\
\x79\x2f\x45\x56\x4e\xc7\x10\xac\x58\x4a\xa1\x8d\x20\xcb\xc8\xf5\
\xf8\x91\x06\x66\xb8\x9e\x4e\xe2\xf9\x5a\xbc\x02\x30\xe2\xcb\xa1\
\xb8\x8a\xc4\xbb\xa7\xfc\xc8\x18\xa9\x86\xc0\x1a\x4c\xa8\x65\xa5\
\xeb\x82\x88\x4d\xbe\xc8\x5b\xfd\x7d\x1a\x30\x3b\x09\x89\x4d\xcf\
\x2e\x37\x85\xfd\x79\xdb\xa2\x25\x37\x7c\xf8\xcc\xa0\x09\xce\xff\
\xbb\x6a\xa3\x8b\x64\x8c\x4b\x05\x40\x4f\x1c\xfa\xac\x36\x1a\xff\
\x0d\x00\x00\x18\x15\xb6\x88\x42\x1e\xd5\xc3\xdd\x92\xd3\xb8\x6e\
\x47\xa7\x6f\x0d\x39\xcc\x09\xe0\x0d\x00\x00\x14\x12\xf5\xf2\x8c\
\x45\x71\x68\xa9\x70\x2d\x9f\xe2\x74\xcc\x01\x00\x0d\x00\x00\x14\
\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00\
\x0d\x00\x00\x14\x55\xcc\x29\xed\x90\x2a\xb8\xec\x53\xb1\xdf\x86\
\x7c\x61\x09\x29\x14\x00\x00\x0c\x09\x00\x26\x89\xdf\xd6\xb7\x12\
\x14\x00\x00\x18\xfe\xbf\x46\x2f\x1c\xd7\x58\x05\xa7\xba\xa2\x87\
\x47\xe7\x69\xd6\x74\xf8\x56\x00\x00\x00\x00\x18\x15\x74\xd6\x4c\
\x01\x65\xba\xd1\x6a\x02\x3f\x03\x8d\x45\xa0\x74\x98\xd8\xd0\x51";

/// `sample4` (`src/proto-isakmp.c:504-509`): флаг шифрования.
const SAMPLE4: &[u8] = b"\xe4\x7a\x59\x1f\xd0\x57\x58\x7f\xa0\x0b\x8e\xf0\x90\x2b\xb8\xec\
\x05\x10\x02\x01\x00\x00\x00\x00\x00\x00\x00\x4c\xb0\x32\xaa\xa6\
\x2a\x70\x71\x8e\xf2\xf0\x99\xcd\xd8\xbf\x6e\xb9\x04\x42\xed\x9d\
\x72\x6d\xaa\x6b\x6d\xad\x62\x40\x26\xf5\xfb\xb1\x73\xd9\xf7\x75\
\x71\xc2\x32\xa5\x6a\xcf\xe1\x2c\x74\x03\xe9\x53";

/// Cookie `sample2`..`sample4` после обнуления старших четырёх байт cookie инициатора.
const SAMPLE_COOKIE: u32 = 0xD057_587F;

/// Вектор с обнулёнными старшими 32 битами cookie инициатора: иначе он не совпадёт ни с каким 32-битным cookie.
fn low_cookie(sample: &[u8]) -> Vec<u8> {
    cat(&[&[0, 0, 0, 0], sample.get(4..).unwrap_or(&[])])
}

/// Заголовок ISAKMP (28 байт) с cookie [`COOKIE`]; длина сообщения пишется [`message`].
fn header(next: u8) -> Vec<u8> {
    cat(&[
        &[0, 0, 0, 0],
        &COOKIE.to_be_bytes(),
        &[0x11; 8],
        &[next, 0x10, 2, 0],
        &[0; 4],
        &[0; 4],
    ])
}

/// Заголовок и нагрузки с верной длиной сообщения.
fn message(next: u8, body: &[&[u8]]) -> Vec<u8> {
    let mut px = cat(&[&header(next), &cat(body)]);
    let len = u32::try_from(px.len()).expect("length").to_be_bytes();
    px[24..28].copy_from_slice(&len);
    px
}

/// Заголовок нагрузки: следующая, reserved, длина вместе с заголовком.
fn payload(next: u8, len: u16) -> Vec<u8> {
    cat(&[&[next, 0], &len.to_be_bytes()])
}

const RFC_39947_NAT: [u8; 16] = [
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f,
];
const CISCO_UNITY: [u8; 16] = [
    0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc, 0x01, 0x00,
];
const RFC3706_DPD: [u8; 16] = [
    0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01, 0x00,
];
const XAUTH: [u8; 8] = [0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12];

pub fn cases() -> Vec<Case> {
    let with = |name, cookie, rawudp, mode, payload, about| Case {
        name,
        port: 500,
        cookie,
        rawudp,
        mode,
        payload,
        about,
    };
    let attributes: Vec<u8> = cat(&[
        &[0x80, 1, 0, 5],
        &[0x80, 1, 0, 7],
        &[0x80, 1, 0, 9],
        &[0x80, 2, 0, 2],
        &[0x80, 2, 0, 1],
        &[0x80, 3, 0, 1],
        &[0x80, 3, 0, 5],
        &[0x80, 3, 0xFD, 0xE9],
        &[0x80, 4, 0, 2],
        &[0x80, 11, 0, 1],
        &[0x80, 12, 0x0E, 0x10],
        &[0x80, 14, 1, 0],
        &[0x80, 0x22, 0xAB, 0xCD],
        &[0x00, 1, 0, 5],
        &[0x80, 1, 0, 5],
    ]);
    let transform = cat(&[&payload(0, 8 + 60), &[1, 1, 0, 0], &attributes]);
    let proposal = cat(&[&payload(0, 8 + 68), &[7, 3, 0, 1], &transform]);
    // SA длиной 100 в датаграмме 36 байт, поле длины сообщения 1000: max верхнего уровня = датаграмма.
    let mut past_end = cat(&[&header(1), &payload(0, 100), &[0, 0, 0, 1]]);
    past_end[24..28].copy_from_slice(&1000u32.to_be_bytes());
    vec![
        with(
            "isakmp-sample1",
            SAMPLE1_COOKIE,
            false,
            Mode::Prefixes,
            SAMPLE1.to_vec(),
            "selftest sample1 (src/proto-isakmp.c:554-556): SA, предложение, IKE 3DES SHA PSK; только isakmp \
             (return 1); все обрезки: короче 16 байт сырой, нагрузки длиннее датаграммы",
        ),
        with(
            "isakmp-sample2",
            SAMPLE_COOKIE,
            false,
            Mode::Prefixes,
            low_cookie(SAMPLE2),
            "selftest sample2 (старшие байты cookie обнулены): AES key=128bits, атрибут TLV, vendor RFC-39947-NAT; \
             все обрезки",
        ),
        with(
            "isakmp-sample3",
            SAMPLE_COOKIE,
            false,
            Mode::Prefixes,
            low_cookie(SAMPLE3),
            "selftest sample3: KEY-XCHG, NONCE, vendor id CISCO-UNITY, RFC3706-DPD, неизвестный, XAUTH, NAT-D; все \
             обрезки",
        ),
        with(
            "isakmp-sample4",
            SAMPLE_COOKIE,
            false,
            Mode::Whole,
            low_cookie(SAMPLE4),
            "selftest sample4: флаг шифрования, ENCRYPTED и конец (src/proto-isakmp.c:319-322)",
        ),
        with(
            "isakmp-sample1-wrong-cookie",
            SAMPLE1_COOKIE + 1,
            false,
            Mode::Whole,
            SAMPLE1.to_vec(),
            "чужой cookie: только сырой (src/proto-isakmp.c:413-420)",
        ),
        with(
            "isakmp-sample1-rawudp",
            SAMPLE1_COOKIE,
            true,
            Mode::Whole,
            SAMPLE1.to_vec(),
            "--rawudp: isakmp и сырой",
        ),
        with(
            "isakmp-sample2-cookie-high-bits",
            SAMPLE_COOKIE,
            false,
            Mode::Whole,
            SAMPLE2.to_vec(),
            "cookie инициатора со старшими битами: с 32-битным cookie не совпадает никогда, сырой",
        ),
        with(
            "isakmp-next-payload-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(16),
            SAMPLE1.to_vec(),
            "тип первой нагрузки 0..255: имена [n], vendor id без имени, `[%u]` от 32 (src/proto-isakmp.c:339-342)",
        ),
        with(
            "isakmp-version-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(17),
            SAMPLE1.to_vec(),
            "версия: старшая и младшая тетрада",
        ),
        with(
            "isakmp-exchange-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(18),
            SAMPLE1.to_vec(),
            "тип обмена: id-prot для 2, иначе число",
        ),
        with(
            "isakmp-flags-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(19),
            SAMPLE1.to_vec(),
            "флаги: нечётные дают ENCRYPTED и конец",
        ),
        with(
            "isakmp-length-sweep",
            SAMPLE_COOKIE,
            false,
            Mode::Sweep(27),
            low_cookie(SAMPLE2),
            "длина сообщения 0..255 (младший байт): max = min(длина датаграммы, поле) (src/proto-isakmp.c:306-308)",
        ),
        with(
            "isakmp-situation-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(39),
            SAMPLE1.to_vec(),
            "биты situation SA: IDENTITY, SECRECY, INTEGRITY",
        ),
        with(
            "isakmp-protocol-id-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(45),
            SAMPLE1.to_vec(),
            "протокол предложения: id=ISAKMP для 1, иначе id=N",
        ),
        with(
            "isakmp-transform-id-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(53),
            SAMPLE1.to_vec(),
            "id преобразования: IKE с атрибутами для 1, иначе trans=N",
        ),
        with(
            "isakmp-attribute-type-sweep",
            SAMPLE1_COOKIE,
            false,
            Mode::Sweep(57),
            SAMPLE1.to_vec(),
            "тип первого атрибута 0..255 со значением 5: все ветки (src/proto-isakmp.c:73-122)",
        ),
        with(
            "isakmp-attributes",
            COOKIE,
            false,
            Mode::Whole,
            message(
                1,
                &[
                    &payload(0, 12 + 76),
                    &[0, 0, 0, 1],
                    &[0, 0, 0, 7],
                    &proposal,
                ],
            ),
            "атрибуты: шифр 5/7/прочий, хэш, PSK для 1 и 5, auth, группа и время молча, ключ, прочие, TLV \
             останавливает",
        ),
        with(
            "isakmp-vendor-ids",
            COOKIE,
            false,
            Mode::Whole,
            message(
                13,
                &[
                    &payload(13, 20),
                    &RFC_39947_NAT,
                    &payload(13, 20),
                    &CISCO_UNITY,
                    &payload(13, 20),
                    &RFC3706_DPD,
                    &payload(13, 12),
                    &XAUTH,
                    &payload(13, 20),
                    &[0x5A; 16],
                    &payload(13, 19),
                    &CISCO_UNITY[..15],
                    &payload(0, 13),
                    &cat(&[&XAUTH, &[0]]),
                ],
            ),
            "vendor id: четыре известных, неизвестный, известный неполной длины и длиннее (src/proto-isakmp.c:243-250)",
        ),
        with(
            "isakmp-doi",
            COOKIE,
            false,
            Mode::Whole,
            message(
                1,
                &[
                    &payload(1, 12),
                    &[0, 0, 0, 0],
                    &[0, 0, 0, 0],
                    &payload(1, 12),
                    &[0, 0, 0, 2],
                    &[0, 0, 0, 0],
                    &payload(0, 12 + 12),
                    &[0, 0, 0, 1],
                    &[0, 0, 0, 6],
                    &payload(0, 12),
                    &[2, 3, 0, 1],
                    &payload(0, 4),
                    &[],
                ],
            ),
            "DOI generic, 2 и ipsec; предложение с протоколом 3 и пустым преобразованием",
        ),
        with(
            "isakmp-payload-past-datagram",
            COOKIE,
            false,
            Mode::Whole,
            past_end,
            "SA длиннее датаграммы: C читает за её концом (src/proto-isakmp.c:49), у нас там нули",
        ),
        with(
            "isakmp-zero-length-payload",
            COOKIE,
            false,
            Mode::Whole,
            message(4, &[&payload(10, 0), &[0xAB, 0xCD]]),
            "нагрузка длиной 0 со следующей 10: у C вечный цикл (src/proto-isakmp.c:372-373, Р2)",
        ),
        with(
            "isakmp-zero-length-last",
            COOKIE,
            false,
            Mode::Whole,
            message(4, &[&payload(0, 0)]),
            "нагрузка длиной 0 без следующей: у C конец",
        ),
        with(
            "isakmp-zero-length-proposal",
            COOKIE,
            false,
            Mode::Whole,
            message(
                1,
                &[
                    &payload(0, 20),
                    &[0, 0, 0, 1],
                    &[0, 0, 0, 1],
                    &payload(2, 0),
                    &[1, 1, 0, 0],
                ],
            ),
            "предложение длиной 0 со следующим 2: у C вечный цикл (src/proto-isakmp.c:191, Р2)",
        ),
        with(
            "isakmp-zero-length-transform",
            COOKIE,
            false,
            Mode::Whole,
            message(
                1,
                &[
                    &payload(0, 24),
                    &[0, 0, 0, 1],
                    &[0, 0, 0, 0],
                    &payload(0, 12),
                    &[1, 1, 0, 1],
                    &payload(3, 0),
                ],
            ),
            "преобразование длиной 0 со следующим 3: у C вечный цикл (src/proto-isakmp.c:146, Р2)",
        ),
        with(
            "isakmp-odd-attribute-tail",
            COOKIE,
            false,
            Mode::Whole,
            message(
                1,
                &[
                    &payload(0, 33),
                    &[0, 0, 0, 1],
                    &[0, 0, 0, 0],
                    &payload(0, 21),
                    &[1, 1, 0, 1],
                    &payload(0, 13),
                    &[1, 1, 0, 0],
                    &[0x80, 1, 0, 7],
                    &[0x80],
                ],
            ),
            "от атрибутов остался один байт: e_next_short16 не двигает смещение, у C вечный цикл \
             (src/proto-isakmp.c:68-70, Р2)",
        ),
    ]
}
