//! ISAKMP, порт 500 (`src/proto-isakmp.c`). Cookie жёсткий: 8 байт cookie инициатора, прочитанные big-endian,
//! равны 32-битному `(unsigned)syn_cookie` (зонд пишет его с четырьмя нулевыми байтами впереди), иначе только сырой
//! баннер (`src/proto-isakmp.c:401-420`). Совпало: текст `isakmp` без сырого (`return 1`).
//!
//! Чтение идёт через `e_next_*` (`src/util-extract.c`): за концом буфера (`offset + n > max`) значение из одних
//! единиц, смещение не двигается; это детерминированно и повторено. Отличия от C (Р1, Р2, Р5), каждое с эталоном:
//! - конец вложенной нагрузки C берёт из её поля длины (`_get_payload`, `src/proto-isakmp.c:48-50`), и он может лежать
//!   за концом датаграммы; `e_next_*` проверяет только его, а vendor id сравнивается `memcmp` по всей длине
//!   (`src/proto-isakmp.c:230, 246`). Так C читает память захвата за датаграммой, и его вывод там не функция ответа
//!   (Р1 классы а и в). У нас, по общему правилу UDP-парсеров (`udp/mod.rs`), конец любой нагрузки не дальше конца
//!   датаграммы: чтение за ним ведёт себя как у `e_next_*` за `max` (одни единицы, смещение не двигается).
//!   Длина vendor id остаётся длиной C из поля длины (где C ничего не читает за датаграммой, вывод тот же), а
//!   неполученные байты не совпадают ни с чем. Где правило меняет вывод, ожидание rmasscan закреплено в
//!   `PAST_DATAGRAM` в `tests/udp_golden/past_datagram.rs`, а вывод C (с нулями за датаграммой) остаётся в эталоне свидетельством;
//! - нагрузка, предложение или преобразование длиной 0 с ненулевым «следующим» зацикливает C навсегда
//!   (`src/proto-isakmp.c:146, 191, 372`), как и атрибут преобразования, от которого остался один байт до `max`
//!   (`e_next_short16` не двигает смещение, `src/proto-isakmp.c:68-70`): C печатает одно и то же бесконечно и не
//!   возвращается (Р1 класс б, Р2). У нас шаг цикла, не сдвинувший смещение, выполняется один раз и завершает цикл
//!   (`C_HANGS` в `tests/udp_golden.rs`);
//! - текст растёт квадратично от длины датаграммы: `max` вложенной нагрузки не ограничен родителем
//!   (`src/proto-isakmp.c:48-50`), и каждое преобразование длиной 0xFFFF заново читает остаток датаграммы как
//!   атрибуты (1480 байт дают у C ~240 КБ текста). Р5 ограничивает запись баннера 65 536 байтами, поэтому текст
//!   обрезается ровно на [`MAX_BANNER_BYTES`] и разбор на этом останавливается: каждый цикл выходит, как только
//!   место кончилось; вывод тот же, что у C с Р5;
//! - `e_next_long64` сдвигает знаковый `int` на 24 (`src/util-extract.c:58, 60`, UB по UBSan на cookie со старшим
//!   битом); значение C отбрасывает, у нас cookie только пропускаются.

use super::{Status, UdpContext};
use crate::app::app_id;
use crate::banner::MAX_BANNER_BYTES;

/// `struct ebuf_t` (`src/util-extract.h:5-9`). `max` никогда не дальше конца датаграммы.
#[derive(Clone, Copy)]
struct Ebuf<'a> {
    buf: &'a [u8],
    offset: usize,
    max: usize,
}

impl Ebuf<'_> {
    /// Следующие `n` байт big-endian или одни единицы без сдвига (`src/util-extract.c:4-46`).
    fn next(&mut self, n: usize) -> u32 {
        let end = self.offset.saturating_add(n);
        let bytes = match self.buf.get(self.offset..end) {
            Some(bytes) if end <= self.max => bytes,
            _ => {
                return if n == 4 { u32::MAX } else { (1 << (8 * n)) - 1 };
            }
        };
        self.offset = end;
        bytes.iter().fold(0u32, |v, &b| v << 8 | u32::from(b))
    }

    /// `e_next_byte`.
    fn byte(&mut self) -> u32 {
        self.next(1)
    }

    /// `e_next_short16(.., EBUF_BE)`.
    fn short16(&mut self) -> u32 {
        self.next(2)
    }

    /// `e_next_int32(.., EBUF_BE)`.
    fn int32(&mut self) -> u32 {
        self.next(4)
    }

    /// `e_next_long64`: значение не нужно, только сдвиг (`src/util-extract.c:54-55`).
    fn skip64(&mut self) {
        if self.offset.saturating_add(8) <= self.max {
            self.offset += 8;
        }
    }
}

/// Текст баннера: не длиннее `cap` (Р5) и счётчик шагов циклов (для тестов на объём работы).
struct Writer {
    text: Vec<u8>,
    cap: usize,
    steps: u64,
}

impl Writer {
    /// Дописывает, сколько помещается до `cap`, остальное отбрасывает.
    fn push(&mut self, s: &[u8]) {
        let room = self.cap.saturating_sub(self.text.len());
        self.text.extend_from_slice(s.get(..room).unwrap_or(s));
    }

    /// Место кончилось: дальше разбор не идёт.
    fn full(&self) -> bool {
        self.text.len() >= self.cap
    }

    /// Шаг цикла: продолжать, если место есть.
    fn step(&mut self) -> bool {
        self.steps += 1;
        !self.full()
    }
}

/// `payload_t` (`src/proto-isakmp.c:33-38`).
struct Payload<'a> {
    next: u32,
    length: usize,
    ebuf: Ebuf<'a>,
}

/// `_get_payload` (`src/proto-isakmp.c:40-52`): заголовок 4 байта; длина от 4 задаёт конец содержимого (у нас не
/// дальше конца датаграммы), меньшая оставляет `max` родителя.
fn get_payload<'a>(ebuf: &Ebuf<'a>) -> Payload<'a> {
    let mut sub = *ebuf;
    let next = sub.byte();
    sub.byte();
    let length = usize::try_from(sub.short16()).unwrap_or(usize::MAX);
    if length >= 4 {
        sub.max = sub.offset.saturating_add(length - 4).min(sub.buf.len());
    }
    Payload {
        next,
        length,
        ebuf: sub,
    }
}

/// `_parse_transform` (`src/proto-isakmp.c:54-132`).
fn parse_transform(w: &mut Writer, mut ebuf: Ebuf<'_>) {
    ebuf.byte(); // номер преобразования
    let transform_id = ebuf.byte();
    if transform_id != 1 {
        w.push(format!("trans={transform_id} ").as_bytes());
        return;
    }
    w.push(b"trans=IKE ");
    ebuf.short16(); // reserved
    while ebuf.offset < ebuf.max && w.step() {
        let before = ebuf.offset;
        let x = ebuf.short16();
        let val = ebuf.short16();
        if x & 0x8000 == 0 {
            return;
        }
        let s = match (x & 0x7FFF, val) {
            (1, 5) => "3DES-CBC ".to_string(),
            (1, 7) => "AES-CBC ".to_string(),
            (1, _) => format!("encrypt=0x{val:x} "),
            (2, 2) => "SHA ".to_string(),
            (2, _) => format!("hash=0x{val:x} "),
            // src/proto-isakmp.c:99-104: 1 и 5 оба PSK.
            (3, 1 | 5) => "PSK ".to_string(),
            (3, _) => format!("auth=0x{val:x} "),
            (4 | 11 | 12, _) => String::new(),
            (14, _) => format!("key={val}bits "),
            (t, _) => format!("val=0x{t:04x}{val:04x} "),
        };
        w.push(s.as_bytes());
        // Один байт до max: e_next_short16 не двигает смещение, C повторяет этот шаг вечно (Р2).
        if ebuf.offset == before {
            return;
        }
    }
}

/// `_parse_transforms` и `_parse_proposals` (`src/proto-isakmp.c:134-152, 179-197`): цикл по нагрузкам до
/// нулевого «следующего». Нулевая длина у C зацикливается (Р2), здесь завершает цикл.
fn parse_chain(w: &mut Writer, mut ebuf: Ebuf<'_>, each: fn(&mut Writer, Ebuf<'_>)) {
    while ebuf.offset.saturating_add(4) <= ebuf.max && w.step() {
        let payload = get_payload(&ebuf);
        each(w, payload.ebuf);
        ebuf.offset = ebuf.offset.saturating_add(payload.length);
        if payload.next == 0 || payload.length == 0 {
            break;
        }
    }
}

/// `_parse_proposal` (`src/proto-isakmp.c:154-177`). SPI не пропускается: преобразования читаются сразу за
/// четырьмя байтами заголовка предложения, как у C.
fn parse_proposal(w: &mut Writer, mut ebuf: Ebuf<'_>) {
    w.push(format!("{} ", ebuf.byte()).as_bytes());
    match ebuf.byte() {
        1 => w.push(b"id=ISAKMP "),
        id => w.push(format!("id={id} ").as_bytes()),
    }
    ebuf.byte(); // размер SPI
    ebuf.byte(); // число преобразований
    parse_chain(w, ebuf, parse_transform);
}

/// `_payload_security_association` (`src/proto-isakmp.c:199-225`).
fn payload_security_association(w: &mut Writer, mut ebuf: Ebuf<'_>) {
    let doi = ebuf.int32();
    let bitmap = ebuf.int32();
    match doi {
        0 => w.push(b"DOI=generic "),
        1 => {
            w.push(b"DOI=ipsec ");
            for (bit, name) in [(1, "IDENTITY "), (2, "SECRECY "), (4, "INTEGRITY ")] {
                if bitmap & bit != 0 {
                    w.push(name.as_bytes());
                }
            }
            parse_chain(w, ebuf, parse_proposal);
        }
        _ => w.push(format!("DOI={doi} ").as_bytes()),
    }
}

/// Vendor id (`src/proto-isakmp.c:235-240`).
const VENDORS: [(&[u8], &str); 4] = [
    (
        &[
            0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95,
            0x45, 0x2f,
        ],
        "RFC-39947-NAT",
    ),
    (
        &[
            0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc,
            0x01, 0x00,
        ],
        "CISCO-UNITY",
    ),
    (
        &[
            0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57,
            0x01, 0x00,
        ],
        "RFC3706-DPD",
    ),
    (&[0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12], "XAUTH"),
];

/// `_payload_vendor_id` (`src/proto-isakmp.c:227-252`): длина содержимого, как у C, из поля длины (`max - offset` до
/// ограничения датаграммой), и байты целиком равны одному из известных. Байты, которых в датаграмме нет, не совпадают
/// ни с чем (у C там `memcmp` за датаграммой).
fn payload_vendor_id(w: &mut Writer, ebuf: Ebuf<'_>, length: usize) {
    let Some(content) = ebuf
        .offset
        .checked_add(length)
        .and_then(|end| ebuf.buf.get(ebuf.offset..end))
    else {
        return;
    };
    if let Some((_, name)) = VENDORS.iter().find(|(vendor, _)| *vendor == content) {
        w.push(format!("{{{name}}} ").as_bytes());
    }
}

/// Имена нагрузок (`payload_names`, `src/proto-isakmp.c:265-274`); 13 (vendor id) без имени.
fn payload_name(next: u32) -> String {
    match next {
        1 => "[SEC-ASSOC]".to_string(),
        4 => "[KEY-XCHG]".to_string(),
        10 => "[NONCE]".to_string(),
        13 => String::new(),
        20 => "[NAT-D]".to_string(),
        n => format!("[{n}]"),
    }
}

/// `_parse_response` (`src/proto-isakmp.c:255-376`) с текстом не длиннее `cap`; второе значение: шаги циклов.
fn parse_response_capped(px: &[u8], cap: usize) -> (Vec<u8>, u64) {
    let mut w = Writer {
        text: Vec::new(),
        cap,
        steps: 0,
    };
    let mut ebuf = Ebuf {
        buf: px,
        offset: 0,
        max: px.len(),
    };
    ebuf.skip64();
    ebuf.skip64();
    let mut next_payload = ebuf.byte();
    let version = ebuf.byte();
    let exchange_type = ebuf.byte();
    let flags = ebuf.byte();
    ebuf.int32(); // message id
    let my_length = usize::try_from(ebuf.int32()).unwrap_or(usize::MAX);
    if ebuf.max >= my_length {
        ebuf.max = my_length;
    }
    w.push(format!("v{}.{} ", version >> 4 & 0xF, version & 0xF).as_bytes());
    match exchange_type {
        2 => w.push(b"xchg=id-prot "),
        x => w.push(format!("xchg={x} ").as_bytes()),
    }
    if flags & 1 != 0 {
        w.push(b"ENCRYPTED ");
        return (w.text, w.steps);
    }
    while next_payload != 0 && ebuf.offset.saturating_add(4) <= ebuf.max && w.step() {
        let payload = get_payload(&ebuf);
        w.push(payload_name(next_payload).as_bytes());
        w.push(b" ");
        match next_payload {
            1 => payload_security_association(&mut w, payload.ebuf),
            13 => {
                // Длина содержимого C: из поля длины; меньше 4 оставляет max родителя (src/proto-isakmp.c:48-50, 230).
                let length = match payload.length.checked_sub(4) {
                    Some(length) => length,
                    None => payload.ebuf.max.saturating_sub(payload.ebuf.offset),
                };
                payload_vendor_id(&mut w, payload.ebuf, length);
            }
            _ => {}
        }
        ebuf.offset = ebuf.offset.saturating_add(payload.length);
        next_payload = payload.next;
        // Нулевая длина: C разбирает ту же нагрузку снова и снова (Р2).
        if payload.length == 0 {
            break;
        }
    }
    (w.text, w.steps)
}

/// `_parse_response` с пределом Р5.
fn parse_response(px: &[u8]) -> Vec<u8> {
    parse_response_capped(px, MAX_BANNER_BYTES).0
}

/// `isakmp_parse` (`src/proto-isakmp.c:378-443`).
pub(super) fn isakmp_parse(cx: &UdpContext, px: &[u8], out: &mut Vec<(u16, Vec<u8>)>) -> Status {
    // src/proto-isakmp.c:393-394
    if px.len() < 16 {
        return Status::Fallback;
    }
    // src/proto-isakmp.c:401-413: 8 байт big-endian против 32-битного cookie.
    let resp_cookie = px.iter().take(8).fold(0u64, |v, &b| v << 8 | u64::from(b));
    if resp_cookie != u64::from(cx.cookie) {
        return Status::Fallback;
    }
    out.push((app_id::ISAKMP, parse_response(px)));
    Status::Handled
}

#[cfg(test)]
mod tests {
    use super::parse_response;
    use crate::app::app_id;
    use crate::udp::{UdpContext, handle_udp};

    fn isakmp(cookie: u32, rawudp: bool, px: &[u8]) -> Vec<(u16, Vec<u8>)> {
        handle_udp(
            &UdpContext {
                port_them: 500,
                cookie,
                rawudp,
            },
            px,
        )
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Векторы selftest C (`sample1`..`sample4`, `src/proto-isakmp.c:464-509`).
    fn samples() -> [Vec<u8>; 4] {
        [
            hex("00000000c11884da be3dc68eeaf2daac 01100200 00000000 00000050 00000034 00000001 00000001
                 00000028 01010001 00000020 01010000 80010005 80020002 80040002 80030001 800b0001 800c0001"),
            hex("e47a591fd057587f a00b8ef0902bb8ec 01100200 00000000 0000006c 0d00003c 00000001 00000001
                 00000030 01010001 00000028 01010000 80010007 800e0080 80020002 80040002 80030001 800b0001
                 000c0004 00015180 00000014 4a131c81 07035845 5c5728f2 0e95452f"),
            hex("e47a591fd057587f a00b8ef0902bb8ec 04100200 00000000 00000130 0a000084 6d026d56 16c45be0
                 5e5b898411e9f95d 195cea009ad22c62 bef06c571b7cfbc4 792f45564ec710ac 584aa18d20cbc8f5
                 f8910666b89e4ee2 f95abc0230e2cba1 b88ac4bba7fcc818 a986c01a4ca865a5 eb82884dbec85bfd
                 7d1a303b09894dcf 2e3785fd79dba225 377cf8cca009ceff bb6aa38b648c4b05 404f1cfaac361aff
                 0d000018 15b68842 1ed5c3dd 92d3b86e 47a76f0d 39cc09e0 0d000014 12f5f28c 4571 68a9 702d9fe2
                 74cc0100 0d000014 afcad713 68a1f1c9 6b8696fc 77570100 0d000014 55cc29ed 902ab8ec 53b1df86
                 7c610929 1400000c 09002689 dfd6b712 14000018 febf462f 1cd75805 a7baa287 47e769d6 74f85600
                 00000018 1574d64c 0165bad1 6a023f03 8d45a074 98d8d051"),
            hex("e47a591fd057587f a00b8ef0902bb8ec 05100201 00000000 0000004c b032aaa6 2a70718e f2f099cd
                 d8bf6eb9 0442ed9d 726daa6b 6dad6240 26f5fbb1 73d9f775 71c232a5 6acfe12c 7403e953"),
        ]
    }

    /// Строки selftest C (`src/proto-isakmp.c:554-568`) как префиксы текста (`_test_sample` сравнивает префикс,
    /// `src/proto-isakmp.c:533`).
    #[test]
    fn isakmp_selftest_prefixes() {
        let want = [
            "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE 3DES-CBC SHA PSK",
            "v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE AES-CBC key=128bits SHA PSK  {RFC-39947-NAT}",
            "v1.0 xchg=id-prot [KEY-XCHG] [NONCE]  {CISCO-UNITY}  {RFC3706-DPD}   {XAUTH} [NAT-D] [NAT-D]",
            "v1.0 xchg=id-prot ENCRYPTED",
        ];
        let samples = samples();
        assert_eq!(samples[0].len(), 80);
        assert_eq!(samples[1].len(), 108);
        assert_eq!(samples[2].len(), 304);
        assert_eq!(samples[3].len(), 76);
        for (px, want) in samples.iter().zip(want) {
            let got = parse_response(px);
            assert!(
                got.starts_with(want.as_bytes()),
                "{:?} does not start with {want:?}",
                String::from_utf8_lossy(&got)
            );
        }
        // Целиком: префикс плюс завершающий пробел.
        assert_eq!(
            parse_response(&samples[0]),
            [want[0].as_bytes(), b" "].concat()
        );
    }

    /// Cookie: 8 байт big-endian против 32-битного cookie; совпало: только `isakmp`, иначе только сырой.
    #[test]
    fn isakmp_cookie_and_raw() {
        let px = samples()[0].clone();
        let text = parse_response(&px);
        assert_eq!(
            isakmp(0xC118_84DA, false, &px),
            vec![(app_id::ISAKMP, text.clone())]
        );
        assert_eq!(
            isakmp(0xC118_84DA, true, &px),
            vec![(app_id::ISAKMP, text), (app_id::NONE, px.clone())]
        );
        assert_eq!(
            isakmp(0xC118_84DB, false, &px),
            vec![(app_id::NONE, px.clone())]
        );
        // Старшие 32 бита cookie инициатора не нули: не совпадает никогда.
        let s2 = samples()[1].clone();
        assert_eq!(
            isakmp(0xD057_587F, false, &s2),
            vec![(app_id::NONE, s2.clone())]
        );
        // Короче 16 байт: сырой.
        assert_eq!(
            isakmp(0xC118_84DA, false, &px[..15]),
            vec![(app_id::NONE, px[..15].to_vec())]
        );
        // Ровно 16 байт: заголовок не читается (e_next_* за max), одни единицы.
        assert_eq!(
            isakmp(0xC118_84DA, false, &px[..16]),
            vec![(app_id::ISAKMP, b"v15.15 xchg=255 ENCRYPTED ".to_vec())]
        );
    }

    /// Заголовок ISAKMP (28 байт) с cookie 0x5EED1234, первой нагрузкой `next` и длиной сообщения `len`.
    fn header(next: u8, len: u32) -> Vec<u8> {
        [
            &[0, 0, 0, 0, 0x5E, 0xED, 0x12, 0x34][..],
            &[0x11; 8],
            &[next, 0x10, 2, 0],
            &[0; 4],
            &len.to_be_bytes(),
        ]
        .concat()
    }

    fn with_length(mut px: Vec<u8>) -> Vec<u8> {
        let n = u32::try_from(px.len()).expect("len").to_be_bytes();
        px[24..28].copy_from_slice(&n);
        px
    }

    /// Р2: нагрузка длиной 0 с ненулевым «следующим» у C разбирается вечно (`src/proto-isakmp.c:372-373`), как и
    /// предложение и преобразование длиной 0 (`:146`, `:191`) и атрибут, от которого остался один байт (`:68-70`).
    /// У нас каждый такой цикл делает один шаг и заканчивается.
    #[test]
    fn isakmp_zero_length_payload_terminates() {
        let isakmp_text = |px: &[u8]| -> Vec<u8> {
            let got = isakmp(0x5EED_1234, false, px);
            assert_eq!(got.len(), 1, "{got:?}");
            got[0].1.clone()
        };
        // Верхний уровень: нагрузка 4 (KEY-XCHG) длиной 0, следующая 10.
        let px = with_length([header(4, 0), vec![10, 0, 0, 0, 0xAB, 0xCD]].concat());
        assert_eq!(isakmp_text(&px), b"v1.0 xchg=id-prot [KEY-XCHG] ");
        // Длина 0 и следующая 0: у C тоже конец.
        let px = with_length([header(4, 0), vec![0, 0, 0, 0]].concat());
        assert_eq!(isakmp_text(&px), b"v1.0 xchg=id-prot [KEY-XCHG] ");
        // SA с предложением длиной 0 и следующим 2 (преобразований нет: они начались бы на max).
        let sa = [
            vec![0, 0, 0, 20],
            vec![0, 0, 0, 1],
            vec![0, 0, 0, 1],
            vec![2, 0, 0, 0],
            vec![1, 1, 0, 0],
        ]
        .concat();
        let px = with_length([header(1, 0), sa].concat());
        assert_eq!(
            isakmp_text(&px),
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP "
        );
        // Предложение с преобразованием длиной 0 и следующим 3: тело преобразования на max, оба байта 255.
        let sa = [
            vec![0, 0, 0, 24],
            vec![0, 0, 0, 1],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 12],
            vec![1, 1, 0, 1],
            vec![3, 0, 0, 0],
        ]
        .concat();
        let px = with_length([header(1, 0), sa].concat());
        assert_eq!(
            isakmp_text(&px),
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec 1 id=ISAKMP trans=255 "
        );
        // Преобразование IKE, атрибуты: 80 01 00 07, затем один байт до max.
        let sa = [
            vec![0, 0, 0, 33],
            vec![0, 0, 0, 1],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 21],
            vec![1, 1, 0, 1],
            vec![0, 0, 0, 13],
            vec![1, 1, 0, 0],
            vec![0x80, 1, 0, 7],
            vec![0x80],
        ]
        .concat();
        let px = with_length([header(1, 0), sa].concat());
        assert_eq!(
            isakmp_text(&px),
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec 1 id=ISAKMP trans=IKE AES-CBC val=0x7fffffff "
        );
    }

    /// Нагрузка длиннее датаграммы: C читает за её концом память захвата (Р1 классы а и в). У нас конец нагрузки не
    /// дальше конца датаграммы, и чтение за ним даёт одни единицы без сдвига, как `e_next_*` за `max`.
    #[test]
    fn isakmp_reads_bounded_by_the_datagram() {
        let text = |px: &[u8]| isakmp(0x5EED_1234, false, px).remove(0).1;
        // SA длиной 100 в датаграмме 36 байт: DOI=1 получен, bitmap нет (все биты), предложений нет. C с нулями
        // за датаграммой печатает `DOI=ipsec 0 id=0 trans=0 `.
        let px = [header(1, 1000), vec![0, 0, 0, 100], vec![0, 0, 0, 1]].concat();
        assert_eq!(
            text(&px),
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY SECRECY INTEGRITY "
        );
        // Vendor id длиной 16, получено 15 байт CISCO-UNITY: не совпадает (C с нулями совпал бы: последний байт 0).
        let cisco: [u8; 16] = [
            0x12, 0xf5, 0xf2, 0x8c, 0x45, 0x71, 0x68, 0xa9, 0x70, 0x2d, 0x9f, 0xe2, 0x74, 0xcc,
            0x01, 0x00,
        ];
        let px = [header(13, 1000), vec![0, 0, 0, 20], cisco[..15].to_vec()].concat();
        assert_eq!(text(&px), b"v1.0 xchg=id-prot  ");
        // Получено целиком: совпадает.
        let px = [header(13, 1000), vec![0, 0, 0, 20], cisco.to_vec()].concat();
        assert_eq!(text(&px), b"v1.0 xchg=id-prot  {CISCO-UNITY} ");
        // Поле длины говорит 26 байт содержимого, получено 16 байт CISCO-UNITY: длина C 26, сравнения нет, как у C
        // (там ничего не читается за датаграммой).
        let px = [header(13, 1000), vec![0, 0, 0, 30], cisco.to_vec()].concat();
        assert_eq!(text(&px), b"v1.0 xchg=id-prot  ");
        // sample1 без последнего байта: значение последнего атрибута не получено (одни единицы, тип 12 молча),
        // затем от атрибутов остался один байт: шаг печатает `val=0x7fffffff ` и не двигается, цикл кончается. C
        // читает недостающий байт за датаграммой и печатает текст без этого шага.
        let s1 = samples()[0].clone();
        assert_eq!(
            isakmp(0xC118_84DA, false, &s1[..79]).remove(0).1,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP trans=IKE 3DES-CBC SHA PSK \
              val=0x7fffffff "
        );
    }

    /// Вечный цикл C с другого входа: от атрибутов осталось 3 байта, тип прочитан, значение нет (смещение
    /// сдвинулось на 2), затем остаётся один байт (`src/proto-isakmp.c:68-70`).
    #[test]
    fn isakmp_three_attribute_bytes_left_terminates() {
        let sa = [
            vec![0, 0, 0, 35],
            vec![0, 0, 0, 1],
            vec![0, 0, 0, 0],
            vec![0, 0, 0, 23],
            vec![1, 1, 0, 1],
            vec![0, 0, 0, 15],
            vec![1, 1, 0, 0],
            vec![0x80, 1, 0, 7],
            vec![0x80, 14, 0],
        ]
        .concat();
        let px = with_length([header(1, 0), sa].concat());
        assert_eq!(px.len(), 63);
        assert_eq!(
            isakmp(0x5EED_1234, false, &px),
            vec![(
                app_id::ISAKMP,
                b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec 1 id=ISAKMP trans=IKE AES-CBC key=65535bits \
                  val=0x7fffffff "
                    .to_vec()
            )]
        );
    }

    /// Построение рецензента: SA с `n` предложениями по 16 байт, в каждом преобразование длиной 0xFFFF, которое
    /// читает остаток датаграммы как атрибуты (по 4 атрибута с текстом на каждое следующее предложение).
    fn amplifier(n: usize) -> Vec<u8> {
        let mut proposals = Vec::new();
        for _ in 0..n {
            proposals.extend_from_slice(&[
                0x82, 0, 0, 16, 0x87, 1, 0, 1, 0x80, 0, 0xFF, 0xFF, 0x80, 1, 0, 0,
            ]);
        }
        let sa_len = u16::try_from(12 + proposals.len()).expect("SA length");
        let sa = [
            &[0, 0][..],
            &sa_len.to_be_bytes(),
            &[0, 0, 0, 1],
            &[0, 0, 0, 0],
            &proposals,
        ]
        .concat();
        with_length([header(1, 0), sa].concat())
    }

    /// Текст растёт квадратично (`max` вложенной нагрузки не ограничен родителем, `src/proto-isakmp.c:48-50`), поэтому
    /// он обрезается ровно на 65 536 байтах (Р5), и разбор на этом кончается: число шагов циклов ограничено.
    #[test]
    fn isakmp_text_is_capped_at_max_banner_bytes() {
        use super::{MAX_BANNER_BYTES, parse_response_capped};
        let px = amplifier(90);
        assert_eq!(px.len(), 1480);
        let (uncapped, _) = parse_response_capped(&px, usize::MAX);
        let (capped, steps) = parse_response_capped(&px, MAX_BANNER_BYTES);
        assert!(uncapped.len() > 200_000, "{}", uncapped.len());
        assert_eq!(capped.len(), MAX_BANNER_BYTES);
        assert_eq!(capped, uncapped[..MAX_BANNER_BYTES]);
        assert!(steps < 10_000, "{steps} steps");
        assert_eq!(
            isakmp(0x5EED_1234, false, &px),
            vec![(app_id::ISAKMP, capped)]
        );
        // ~64 КБ: у C порядка 480 МБ текста; у нас 65 536 байт за ограниченное число шагов.
        let px = amplifier(4000);
        assert_eq!(px.len(), 64_040);
        let (capped, steps) = parse_response_capped(&px, MAX_BANNER_BYTES);
        assert_eq!(capped.len(), MAX_BANNER_BYTES);
        assert!(steps < 10_000, "{steps} steps");
    }

    /// Атрибуты преобразования IKE (`src/proto-isakmp.c:73-122`) и прочие ветки.
    #[test]
    fn isakmp_attributes_and_names() {
        let attrs: Vec<u8> = [
            [0x80, 1, 0, 5],
            [0x80, 1, 0, 9],
            [0x80, 2, 0, 2],
            [0x80, 2, 0, 1],
            [0x80, 3, 0, 1],
            [0x80, 3, 0, 5],
            [0x80, 3, 0xFD, 0xE9],
            [0x80, 4, 0, 2],
            [0x80, 11, 0, 1],
            [0x80, 12, 0x0E, 0x10],
            [0x80, 14, 1, 0],
            [0x80, 0x22, 0xAB, 0xCD],
            [0x00, 1, 0, 5],
            [0x80, 1, 0, 5],
        ]
        .concat();
        let transform = [vec![0, 0, 0, 8 + 56], vec![1, 1, 0, 0], attrs].concat();
        let proposal = [vec![0, 0, 0, 8 + 64], vec![7, 3, 0, 1], transform].concat();
        let sa = [
            vec![0, 0, 0, 12 + 72],
            vec![0, 0, 0, 1],
            vec![0, 0, 0, 7],
            proposal,
        ]
        .concat();
        let px = with_length([header(1, 0), sa].concat());
        assert_eq!(
            isakmp(0x5EED_1234, false, &px)[0].1,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY SECRECY INTEGRITY 7 id=3 trans=IKE \
              3DES-CBC encrypt=0x9 SHA hash=0x1 PSK PSK auth=0xfde9 key=256bits val=0x0022abcd "
        );
        // DOI 0 и прочие, имена нагрузок 20, 2, 33, 255.
        let px = with_length(
            [
                header(1, 0),
                vec![20, 0, 0, 8],
                vec![0, 0, 0, 0],
                vec![2, 0, 0, 4],
                vec![33, 0, 0, 4],
                vec![255, 0, 0, 4],
                vec![0, 0, 0, 4],
            ]
            .concat(),
        );
        assert_eq!(
            isakmp(0x5EED_1234, false, &px)[0].1,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=generic [NAT-D] [2] [33] [255] "
        );
    }
}
