//! Паритет UDP-парсеров баннеров с C (AGPL-3.0). Каждый кейс `tests/golden/udp-banners` это датаграмма ответа и
//! вывод C-оракула `udp-oracle`: настоящий `handle_udp` masscan © Robert David Graham (HEAD 8e6b3b0) с заглушками
//! вывода (README эталонов). Эталон C (`cases/<кейс>.out`) снят с датаграммой в роли кадра (`app_offset` 0),
//! `-ftrivial-auto-var-init=pattern` и нулями за датаграммой: так C адресует датаграмму, а не кадр, и не видит мусора
//! стека, как решено для rmasscan (Р1, Р2). rmasscan обязан напечатать его байт в байт, кроме разделов, закреплённых
//! руками: где C не вернулся (`hang`, [`C_HANGS`]) и где C читает память захвата за концом датаграммы
//! ([`PAST_DATAGRAM`], вид отличия проверяется по выводу C с нулями и с 0xEE). Вывод того же C с байтами 0xEE за
//! датаграммой (`cases/<кейс>.ee.out`) и в настоящих кадрах (`cases/<кейс>.<кадр>.out`; кадры [`FRAMES`]), только
//! если он другой, сверяется с эталоном по правилам названных отличий: чтение за датаграммой бывает только у ISAKMP,
//! сырой баннер за концом датаграммы (11211 и порты без парсера) совпадает длиной, а остальные отличия перечислены в
//! [`FRAME_DIFFS`] с видом отличия, и вид проверяется в каждом разделе.
//!
//! Датаграммы строит `examples/udp_golden_inputs.rs`; закоммиченные `cases/*.bin` обязаны с ним совпадать.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use rmasscan_proto::{UdpContext, app_id, handle_udp};

#[path = "../examples/udp_golden_inputs.rs"]
#[allow(dead_code)]
mod udp_golden_inputs;

use udp_golden_inputs::{Case, cases};

const DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/udp-banners"
);
const ORACLE_GIT_HEAD: &str = "8e6b3b0c07a81e8ea61d557c06134a21a6881614";

/// Кадры, в которых снят вывод C (`udp_oracle.c`): Ethernet + IPv4, Ethernet + IPv6, Ethernet + 802.1Q + IPv4,
/// IPv4 без канального заголовка.
const FRAMES: [&str; 4] = ["eth", "eth6", "vlan", "rawip"];

/// Вид отличия вывода C в кадре от ожидания. Причина у всех одна: C разрешает указатель сжатия DNS/NBNS как смещение в
/// кадре (`src/proto-dns.c:69`, `px` это кадр), поэтому проверка имени читает байты канального и IP-заголовков. Обычный
/// `c0 0c` попадает на байт 12 кадра: в Ethernet + IPv4 это 0x08 (EtherType), «метка» длины 8 кончается на нулевом
/// младшем байте смещения фрагмента, и имя проходит случайно; в Ethernet + IPv6 там 0x86, в 802.1Q 0x81 (оба
/// `& 0xC0 == 0x80`, ошибка, `src/proto-dns.c:61-62`), без канального заголовка там адрес источника IPv4. У нас
/// указатель адресует сообщение DNS (Р1 классы а и в: результат C зависит от канала, семейства, VLAN и адресов, а не
/// от ответа).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameDiff {
    /// Имя отвергнуто в кадре: у C только сырой баннер, у нас текст парсера (dns-ver или nbtstat) и, если он есть,
    /// тот же сырой.
    NameRejectedInFrame,
    /// Имя принято в кадре через байты заголовков: у C dns-ver, у нас имя неверно и сырой баннер.
    NameAcceptedInFrame,
    /// Имя ответа отвергнуто в кадре раньше OPT EDNS0, расширенный RCODE не прочитан: у C строка базового RCODE и
    /// сырой, у нас (RCODE 3 | ext << 4 = 19, строки нет) текст TXT.
    ExtRcodeLost,
}

use FrameDiff::{ExtRcodeLost, NameAcceptedInFrame, NameRejectedInFrame};

/// Пары (кейс, кадры), где вывод C в кадре отличается не только сырым баннером за концом датаграммы, и вид отличия.
/// Каждый раздел, где кадр отличается, обязан быть этого вида; каждая пара обязана отличаться хотя бы в одном.
const FRAME_DIFFS: &[(&str, &[&str], FrameDiff)] = &[
    (
        "dns-chaos-txt",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-chaos-txt-rawudp",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-chaos-txt-cookie-high-bits",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-flags-hi-sweep",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-flags-lo-sweep",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-txt-two-strings",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-txt-empty-string",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-txt-rdlength-past-end",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-txt-len-clamped",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-edns-ext-rcode",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-edns-ext-rcode-nxdomain",
        &["eth6", "vlan", "rawip"],
        ExtRcodeLost,
    ),
    (
        "dns-many-answers",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    ("dns-pointer-chain-4", &["rawip"], NameRejectedInFrame),
    (
        "nbns-nbstat-with-question",
        &["eth6", "vlan", "rawip"],
        NameRejectedInFrame,
    ),
    (
        "dns-pointer-to-id",
        &["eth", "eth6", "vlan"],
        NameAcceptedInFrame,
    ),
    (
        "dns-pointer-chain-5",
        &["eth", "eth6", "vlan"],
        NameAcceptedInFrame,
    ),
    ("dns-pointer-loop", &["eth6", "vlan"], NameAcceptedInFrame),
];

fn frame_diff(case: &str, frame: &str) -> Option<FrameDiff> {
    FRAME_DIFFS
        .iter()
        .find(|(c, frames, _)| *c == case && frames.contains(&frame))
        .map(|(_, _, kind)| *kind)
}

/// Раздел отличается так, как сказано в `kind`.
fn diff_is(
    kind: FrameDiff,
    payload: &[(u16, Vec<u8>)],
    frame: &[(u16, Vec<u8>)],
    datagram: &[u8],
) -> bool {
    let raw = (app_id::NONE, datagram.to_vec());
    let parser = |b: Option<&(u16, Vec<u8>)>| matches!(b, Some((app, _)) if *app == app_id::DNS_VERSIONBIND || *app == app_id::NBTSTAT);
    match kind {
        NameRejectedInFrame => {
            frame == [raw.clone()]
                && parser(payload.first())
                && (payload.len() == 1 || payload.get(1..) == Some(&[raw][..]))
        }
        NameAcceptedInFrame => {
            payload == [raw]
                && frame.len() == 1
                && matches!(frame.first(), Some((app, _)) if *app == app_id::DNS_VERSIONBIND)
        }
        ExtRcodeLost => {
            let rcode_string = |b: &[u8]| matches!(b, [b'1'..=b'9', b':', ..]);
            matches!(payload, [(app, _)] if *app == app_id::DNS_VERSIONBIND)
                && matches!(frame, [(app, text), r] if *app == app_id::DNS_VERSIONBIND && rcode_string(text) && *r == raw)
        }
    }
}

/// Сырой баннер за концом датаграммы (`src/proto-udp.c:97-101, 108-112, 129`): всё равно, кроме содержимого
/// последнего сырого баннера той же длины.
fn raw_past_datagram(port: u16, payload: &[(u16, Vec<u8>)], frame: &[(u16, Vec<u8>)]) -> bool {
    overreads(port)
        && payload.len() == frame.len()
        && payload
            .split_last()
            .zip(frame.split_last())
            .is_some_and(|((p, p_rest), (f, f_rest))| {
                p_rest == f_rest
                    && p.0 == app_id::NONE
                    && f.0 == app_id::NONE
                    && p.1.len() == f.1.len()
            })
}

/// Ожидаемые байты баннера в файле оракула.
#[derive(Debug)]
enum Bytes {
    /// `=datagram`: первые LEN байт датаграммы раздела.
    Datagram,
    Literal(Vec<u8>),
}

/// Чем кончился вызов `handle_udp` у оракула (каждый раздел идёт в отдельном процессе).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// Вернулся: строки статуса и баннеров.
    Returned,
    /// Не вернулся за 2 с (`hang`): вечный цикл C.
    Hang,
    /// Упал по сигналу (`crash signal=N`).
    Crash(i32),
}

#[derive(Debug)]
struct Section {
    label: String,
    outcome: Outcome,
    banners: Vec<(u16, usize, Bytes)>,
}

struct Out {
    header: String,
    sections: Vec<Section>,
}

fn parse_bytes(s: &str) -> Bytes {
    if s == "-" {
        return Bytes::Literal(Vec::new());
    }
    if s == "=datagram" {
        return Bytes::Datagram;
    }
    let inner = s
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or_else(|| panic!("bad bytes field {s:?}"));
    let raw = inner.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\\' {
            assert_eq!(raw.get(i + 1), Some(&b'x'), "bad escape in {s:?}");
            let hex = std::str::from_utf8(&raw[i + 2..i + 4]).expect("hex");
            out.push(u8::from_str_radix(hex, 16).expect("hex"));
            i += 4;
        } else {
            out.push(raw[i]);
            i += 1;
        }
    }
    Bytes::Literal(out)
}

fn parse_out(text: &str, what: &str) -> Out {
    let mut lines = text.lines();
    let header = lines
        .next()
        .unwrap_or_else(|| panic!("{what}: empty"))
        .to_string();
    let mut sections: Vec<Section> = Vec::new();
    for line in lines {
        if let Some(label) = line.strip_prefix("section ") {
            sections.push(Section {
                label: label.to_string(),
                outcome: Outcome::Returned,
                banners: Vec::new(),
            });
        } else if line == "hang" || line.starts_with("crash signal=") {
            let outcome = match line.strip_prefix("crash signal=") {
                Some(n) => Outcome::Crash(n.parse().expect("signal")),
                None => Outcome::Hang,
            };
            sections
                .last_mut()
                .unwrap_or_else(|| panic!("{what}: {line} before section"))
                .outcome = outcome;
        } else if line == "status open count=1" {
            // handle_udp всегда пишет одну запись статуса (src/proto-udp.c:63-73); её пишет движок, не парсер.
        } else if let Some(rest) = line.strip_prefix("banner ") {
            let mut it = rest.splitn(3, ' ');
            let app: u16 = it.next().and_then(|v| v.parse().ok()).expect("app");
            let len: usize = it.next().and_then(|v| v.parse().ok()).expect("len");
            let bytes = parse_bytes(it.next().expect("bytes"));
            if let Bytes::Literal(b) = &bytes {
                assert_eq!(b.len(), len, "{what}: {line}");
            }
            sections
                .last_mut()
                .unwrap_or_else(|| panic!("{what}: banner before section"))
                .banners
                .push((app, len, bytes));
        } else {
            panic!("{what}: unexpected line {line:?}");
        }
    }
    Out { header, sections }
}

fn resolve(banners: &[(u16, usize, Bytes)], datagram: &[u8]) -> Vec<(u16, Vec<u8>)> {
    banners
        .iter()
        .map(|(app, len, b)| {
            let bytes = match b {
                Bytes::Datagram => datagram[..*len].to_vec(),
                Bytes::Literal(v) => v.clone(),
            };
            (*app, bytes)
        })
        .collect()
}

fn show(banners: &[(u16, Vec<u8>)]) -> String {
    banners
        .iter()
        .map(|(app, b)| format!("({app}, {:?})", String::from_utf8_lossy(b)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn header_for(c: &Case, framing: &str) -> String {
    format!(
        "udp-oracle port={} cookie=0x{:08x} rawudp={} mode={} sections={} framing={framing}",
        c.port,
        c.cookie,
        u8::from(c.rawudp),
        c.mode.arg(),
        c.sections().len()
    )
}

/// Порты, на которых C берёт сырой баннер за концом датаграммы (`src/proto-udp.c:97-101, 108-112`).
fn overreads(port: u16) -> bool {
    !matches!(
        port,
        53 | 123 | 137 | 161 | 500 | 5683 | 16464 | 16465 | 16470 | 16471
    )
}

/// Число разделов всех кейсов: ловит пропавший кейс или раздел.
const SECTIONS_TOTAL: usize = 9_248;

/// Раздел, где C не возвращается (`hang` у оракула), и вывод rmasscan там.
struct CHang {
    case: &'static str,
    label: &'static str,
    banners: &'static [(u16, &'static [u8])],
}

/// Вечные циклы ISAKMP (`src/proto-isakmp.c:68-70, 146, 191, 372`; Р1 класс б, Р2). У нас шаг цикла, не
/// сдвинувший смещение, последний.
const C_HANGS: &[CHang] = &[
    // Нагрузка KEY-XCHG длиной 0, следующая NONCE: C печатает `[NONCE] ` без конца.
    CHang {
        case: "isakmp-zero-length-payload",
        label: "len=34",
        banners: &[(app_id::ISAKMP, b"v1.0 xchg=id-prot [KEY-XCHG] ")],
    },
    // Предложение длиной 0, следующее 2: C печатает `1 id=ISAKMP ` без конца.
    CHang {
        case: "isakmp-zero-length-proposal",
        label: "len=48",
        banners: &[(
            app_id::ISAKMP,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec IDENTITY 1 id=ISAKMP ",
        )],
    },
    // Преобразование длиной 0 на конце предложения, следующее 3: C печатает `trans=255 ` без конца.
    CHang {
        case: "isakmp-zero-length-transform",
        label: "len=52",
        banners: &[(
            app_id::ISAKMP,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec 1 id=ISAKMP trans=255 ",
        )],
    },
    // Один байт атрибутов до max: C печатает `val=0x7fffffff ` без конца.
    CHang {
        case: "isakmp-odd-attribute-tail",
        label: "len=61",
        banners: &[(
            app_id::ISAKMP,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec 1 id=ISAKMP trans=IKE AES-CBC val=0x7fffffff ",
        )],
    },
    // Три байта атрибутов: тип 14 прочитан, значение нет (сдвиг на 2), затем один байт: C печатает
    // `val=0x7fffffff ` без конца.
    CHang {
        case: "isakmp-attribute-tail-3",
        label: "len=63",
        banners: &[(
            app_id::ISAKMP,
            b"v1.0 xchg=id-prot [SEC-ASSOC] DOI=ipsec 1 id=ISAKMP trans=IKE AES-CBC key=65535bits \
              val=0x7fffffff ",
        )],
    },
];

/// Вид отличия rmasscan от C там, где C читает память захвата за концом датаграммы (ISAKMP: конец вложенной
/// нагрузки из её поля длины, `src/proto-isakmp.c:48-50, 246`; у нас конец не дальше датаграммы, чтение за ним даёт
/// одни единицы без сдвига, как `e_next_*` за `max`). Первый токен (через пробел), где текст rmasscan и текст C с
/// нулями за датаграммой (`.out`) расходятся, определяет вид.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PastKind {
    /// Токен C там зависит от байтов за датаграммой: с нулями и с 0xEE (`.ee.out`) он разный. У rmasscan на его
    /// месте значение несостоявшегося чтения или конец разбора.
    CReadsPastDatagram,
    /// Вывод C от байтов за датаграммой не зависит (с нулями и с 0xEE одинаков), но последнее чтение атрибута C
    /// делает через её конец. У rmasscan это чтение не состоялось, смещение не сдвинулось, и последний шаг цикла
    /// атрибутов на оставшемся байте печатает `val=0x7fffffff ` (как C, если бы его `max` кончался на датаграмме):
    /// текст rmasscan = текст C + `val=0x7fffffff `.
    FailedReadStep,
}

/// Раздел, где C читает за датаграммой, вид отличия и текст `isakmp` rmasscan, закреплённый руками.
struct PastDatagram {
    case: &'static str,
    label: &'static str,
    kind: PastKind,
    text: &'static str,
}

#[path = "udp_golden/past_datagram.rs"]
mod past_datagram;

use past_datagram::PAST_DATAGRAM;

/// Отличие раздела вида `kind`: `rust` (вывод rmasscan) против `c0` (C с нулями за датаграммой) и `cee` (C с 0xEE).
fn past_kind_holds(kind: PastKind, rust: &[u8], c0: &[u8], cee: &[u8]) -> bool {
    let tokens =
        |b: &[u8]| -> Vec<Vec<u8>> { b.split(|&c| c == b' ').map(<[u8]>::to_vec).collect() };
    let (r, z, e) = (tokens(rust), tokens(c0), tokens(cee));
    let Some(t) = (0..=r.len().max(z.len())).find(|&i| r.get(i) != z.get(i)) else {
        return false;
    };
    match kind {
        PastKind::CReadsPastDatagram => c0 != cee && z.get(t) != e.get(t),
        PastKind::FailedReadStep => c0 == cee && rust == [c0, b"val=0x7fffffff "].concat(),
    }
}

/// Запись раздела: исход и баннеры.
fn record(section: &Section, datagram: &[u8]) -> (Outcome, Vec<(u16, Vec<u8>)>) {
    (section.outcome, resolve(&section.banners, datagram))
}

/// Вывод C в `payload` с байтами 0xEE за датаграммой (`cases/<кейс>.ee.out`, только если он другой): метки
/// разделов, где вывод C зависит от памяти за датаграммой, и сам вывод. Так читает только ISAKMP: длина вложенной
/// нагрузки задаёт её конец (`src/proto-isakmp.c:49`), `e_next_*` проверяет только его (Р1 классы а и в).
fn past_datagram(dir: &Path, c: &Case, out: &Out) -> Option<(BTreeSet<String>, Out)> {
    let path = dir.join(format!("cases/{}.ee.out", c.name));
    if !path.exists() {
        return None;
    }
    let text = String::from_utf8(read(&path)).expect("utf-8");
    let ee = parse_out(&text, c.name);
    assert_eq!(ee.header, header_for(c, "payload"), "{}", c.name);
    assert_eq!(ee.sections.len(), out.sections.len(), "{}", c.name);
    let mut labels = BTreeSet::new();
    for ((want, ee_section), (_, datagram)) in
        out.sections.iter().zip(&ee.sections).zip(c.sections())
    {
        assert_eq!(want.label, ee_section.label, "{}", c.name);
        if record(want, &datagram) != record(ee_section, &datagram) {
            labels.insert(want.label.clone());
        }
    }
    assert!(
        !labels.is_empty(),
        "{}: .ee.out equals .out, remove it",
        c.name
    );
    assert_eq!(
        c.port, 500,
        "{}: only ISAKMP reads past the datagram",
        c.name
    );
    Some((labels, ee))
}

#[test]
fn udp_golden_matches_c() {
    let dir = Path::new(DIR);
    let manifest = String::from_utf8(read(&dir.join("manifest.json"))).expect("utf-8");
    assert!(
        manifest.contains(&format!("\"masscan_git_head\": \"{ORACLE_GIT_HEAD}\"")),
        "oracle pin"
    );
    let all = cases();
    let mut names = BTreeSet::new();
    let mut failures = Vec::new();
    let mut sections_checked = 0usize;
    let mut hangs_seen = BTreeSet::new();
    let mut past_seen = BTreeSet::new();
    for c in &all {
        assert!(names.insert(c.name), "duplicate case {}", c.name);
        assert!(
            manifest.contains(&format!("\"name\": \"{}\"", c.name)),
            "{} not in manifest.json",
            c.name
        );
        assert_eq!(
            read(&dir.join(format!("cases/{}.bin", c.name))),
            c.payload,
            "{}.bin drifted from the generator",
            c.name
        );
        let text =
            String::from_utf8(read(&dir.join(format!("cases/{}.out", c.name)))).expect("utf-8");
        let out = parse_out(&text, c.name);
        assert_eq!(out.header, header_for(c, "payload"), "{}", c.name);
        let sections = c.sections();
        assert_eq!(out.sections.len(), sections.len(), "{}", c.name);
        let cx = UdpContext {
            port_them: c.port,
            cookie: c.cookie,
            rawudp: c.rawudp,
        };
        let past = past_datagram(dir, c, &out);
        for (i, ((label, datagram), want)) in sections.iter().zip(&out.sections).enumerate() {
            assert_eq!(&want.label, label, "{}", c.name);
            let got = handle_udp(&cx, datagram);
            sections_checked += 1;
            if let Some(p) = PAST_DATAGRAM
                .iter()
                .find(|p| p.case == c.name && p.label == label)
            {
                past_seen.insert((c.name, label.clone()));
                let c0 = record(want, datagram);
                let cee = past
                    .as_ref()
                    .and_then(|(_, ee)| ee.sections.get(i))
                    .map_or_else(|| c0.clone(), |s| record(s, datagram));
                let isakmp = |r: &(Outcome, Vec<(u16, Vec<u8>)>)| match r {
                    (Outcome::Returned, b) => match b.as_slice() {
                        [(app_id::ISAKMP, text)] => Some(text.clone()),
                        _ => None,
                    },
                    _ => None,
                };
                let pinned = p.text.as_bytes();
                // Закреплённый текст: это вывод rmasscan, он не равен выводу C с нулями, и отличие объявленного вида.
                let ok = match (isakmp(&c0), isakmp(&cee)) {
                    (Some(z), Some(e)) => {
                        got == [(app_id::ISAKMP, pinned.to_vec())]
                            && z != pinned
                            && past_kind_holds(p.kind, pinned, &z, &e)
                    }
                    _ => false,
                };
                if !ok {
                    failures.push(format!(
                        "{} [{label}]: PAST_DATAGRAM {:?}\n  C (00): {}\n  C (ee): {}\n  pinned: {}\n  Rust:   {}",
                        c.name,
                        p.kind,
                        show(&c0.1),
                        show(&cee.1),
                        p.text,
                        show(&got)
                    ));
                }
                continue;
            }
            let want = match want.outcome {
                Outcome::Returned => resolve(&want.banners, datagram),
                Outcome::Hang => {
                    let Some(hang) = C_HANGS
                        .iter()
                        .find(|h| h.case == c.name && h.label == label)
                    else {
                        failures.push(format!(
                            "{} [{label}]: C hangs, C_HANGS has no entry",
                            c.name
                        ));
                        continue;
                    };
                    hangs_seen.insert((c.name, label.clone()));
                    hang.banners
                        .iter()
                        .map(|(app, b)| (*app, b.to_vec()))
                        .collect()
                }
                Outcome::Crash(signal) => {
                    failures.push(format!("{} [{label}]: C crashed (signal {signal})", c.name));
                    continue;
                }
            };
            if got != want {
                failures.push(format!(
                    "{} [{label}]\n  C:    {}\n  Rust: {}",
                    c.name,
                    show(&want),
                    show(&got)
                ));
            }
        }
        for frame in FRAMES {
            check_frame(dir, c, &out, past.as_ref(), frame, &mut failures);
        }
    }
    // Каждый файл каталога принадлежит кейсу генератора.
    for entry in fs::read_dir(dir.join("cases")).expect("cases dir") {
        let file = entry
            .expect("entry")
            .file_name()
            .into_string()
            .expect("utf-8 name");
        let stem = FRAMES
            .iter()
            .chain(&["ee"])
            .find_map(|f| file.strip_suffix(&format!(".{f}.out")))
            .or_else(|| file.strip_suffix(".out"))
            .or_else(|| file.strip_suffix(".bin"))
            .unwrap_or_else(|| panic!("unexpected file cases/{file}"));
        assert!(
            names.contains(stem),
            "cases/{file} has no case in the generator"
        );
    }
    for (name, frames, _) in FRAME_DIFFS {
        assert!(
            names.contains(name),
            "FRAME_DIFFS lists unknown case {name}"
        );
        assert!(
            frames.iter().all(|f| FRAMES.contains(f)),
            "FRAME_DIFFS: {name}"
        );
    }
    for h in C_HANGS {
        assert!(
            hangs_seen.contains(&(h.case, h.label.to_string())),
            "C_HANGS: {} [{}] is not a hang in the goldens",
            h.case,
            h.label
        );
    }
    for p in PAST_DATAGRAM {
        assert!(
            past_seen.contains(&(p.case, p.label.to_string())),
            "PAST_DATAGRAM: {} [{}] is not a section of the goldens",
            p.case,
            p.label
        );
    }
    assert!(
        failures.is_empty(),
        "{} of {sections_checked} sections differ from C:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert_eq!(sections_checked, SECTIONS_TOTAL, "sections of all cases");
}

/// Вывод C в кадре `frame`: файла нет, если он равен ожиданию; иначе каждый отличающийся раздел это сырой баннер за
/// концом датаграммы, чтение за датаграммой (раздел из `.ee.out`, и кадр совпадает с ним: за кадром тот же 0xEE)
/// или вид отличия из [`FRAME_DIFFS`].
fn check_frame(
    dir: &Path,
    c: &Case,
    out: &Out,
    past: Option<&(BTreeSet<String>, Out)>,
    frame: &str,
    failures: &mut Vec<String>,
) {
    let path = dir.join(format!("cases/{}.{frame}.out", c.name));
    let kind = frame_diff(c.name, frame);
    if !path.exists() {
        assert!(
            kind.is_none(),
            "{}: listed in FRAME_DIFFS for {frame} but has no .{frame}.out",
            c.name
        );
        return;
    }
    let text = String::from_utf8(read(&path)).expect("utf-8");
    let got_frame = parse_out(&text, c.name);
    assert_eq!(got_frame.header, header_for(c, frame), "{}", c.name);
    assert_eq!(got_frame.sections.len(), out.sections.len(), "{}", c.name);
    let (mut differs, mut of_kind) = (0, 0);
    for (i, ((section, (_, datagram)), f)) in out
        .sections
        .iter()
        .zip(c.sections())
        .zip(&got_frame.sections)
        .enumerate()
    {
        assert_eq!(section.label, f.label, "{}", c.name);
        let want = record(section, &datagram);
        let got = record(f, &datagram);
        if want == got {
            continue;
        }
        differs += 1;
        if want.0 == Outcome::Returned
            && got.0 == Outcome::Returned
            && raw_past_datagram(c.port, &want.1, &got.1)
        {
            continue;
        }
        if let Some((labels, ee)) = past
            && labels.contains(&section.label)
            && ee.sections.get(i).map(|s| record(s, &datagram)) == Some(got.clone())
        {
            continue;
        }
        match kind {
            Some(k) if want.0 == got.0 && diff_is(k, &want.1, &got.1, &datagram) => of_kind += 1,
            _ => failures.push(format!(
                "{} [{}]: C in the {frame} frame differs, expected kind {kind:?}\n  payload: {:?} {}\n  {frame}: {:?} {}",
                c.name,
                section.label,
                want.0,
                show(&want.1),
                got.0,
                show(&got.1)
            )),
        }
    }
    assert!(
        differs > 0,
        "{}: .{frame}.out equals .out, remove it",
        c.name
    );
    assert!(
        kind.is_none() || of_kind > 0,
        "{}: listed in FRAME_DIFFS for {frame}, but no section differs that way",
        c.name
    );
}

/// Мутации эталонных датаграмм (байт, обрезка, вставка) не роняют `handle_udp` ни на одном порту.
#[test]
fn udp_golden_mutations_never_panic() {
    let mut state: u64 = 0xD1B5_4A32_D192_ED03;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for c in cases() {
        for _ in 0..200 {
            let mut px = c.payload.clone();
            let r = next();
            let at = usize::try_from(r % (px.len() as u64 + 1)).expect("index");
            match (r >> 32) % 3 {
                0 if at < px.len() => px[at] = (r >> 40) as u8,
                1 => px.truncate(at),
                _ => px.insert(at, (r >> 40) as u8),
            }
            for port in [c.port, 53, 123, 137, 161, 500, 5683, 11211, 16464] {
                let cx = UdpContext {
                    port_them: port,
                    cookie: c.cookie,
                    rawudp: r & 1 == 1,
                };
                let got = handle_udp(&cx, &px);
                if cx.rawudp {
                    assert_eq!(got.last(), Some(&(app_id::NONE, px.clone())));
                }
            }
        }
    }
}
