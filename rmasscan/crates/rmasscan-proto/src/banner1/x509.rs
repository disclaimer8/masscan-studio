//! Разбор X.509: имена CN и SAN листа в запись `ssl` (справка 4c §C по `src/proto-x509.c`).
//!
//! Rust-нативный инкрементный обход DER позиционным путём C (не транскрипция его ~130 состояний): явный стек
//! кадров «поле + остаток длины», типизированные поля сертификата, проверяемый разбор длины. Наблюдаемое
//! поведение сверено с C эталонами (`tests/golden/x509`): какие имена пишутся на любом входе, включая битый
//! DER, и где разбор останавливается. Учёт байтов тот же, что у C: перед каждым байтом кадры с нулевым
//! остатком снимаются со стека, каждый потреблённый байт уменьшает остаток верхнего кадра
//! (`src/proto-x509.c:558-581`), поэтому результат не зависит от нарезки потока на сегменты (Р13).
//!
//! Пределы `ASN1_push` (`:304-330`): длина поля не больше остатка родителя (ASN1-CHILD-OVERFLOW, `:345-351`),
//! глубина стека 9 кадров включая внешний кадр длины сертификата, длина свыше 16 бит. Отказ push у C липкий
//! только между вызовами `x509_decode`: внутри одного вызова локальное состояние идёт дальше без кадра,
//! поэтому результат C на битом входе зависит от нарезки на вызовы; эталон Р13 — C на целом потоке, и здесь
//! отказ push просто не кладёт кадр и разбор продолжается. Отказ самого первого push (длина сертификата в
//! `init` свыше 16 бит) оставляет стек пустым, и сертификат не разбирается вовсе. Формы длины за пределами
//! двух байт повторяются как у C: аккумулятор u16 и счётчик байтов длины u8 оба с обёрткой (справка §C3, §F E1.2).

use crate::app::app_id;

use super::session::ParseCx;

/// Глубина стека C: `remainings[9]` (`src/proto-x509.h:20-24`), включая кадр длины сертификата из
/// `x509_decode_init`.
const MAX_DEPTH: usize = 9;

/// Поле сертификата по позиционному пути C (перечень состояний `src/proto-x509.c:439-476` и таблица
/// `kludge_next` `:485-526`, сведённые в поля). `Padding` — байты до конца кадра без разбора
/// (ASN1-CHILD-UNDERFLOW); `Error` — жёсткая ошибка тега: остаток текущего кадра пропускается (`ASN1_skip`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    OuterSeq,
    TbsSeq,
    VersionWrap,
    VersionInt,
    Serial,
    SigAlgSeq,
    SigOid,
    IssuerSeq,
    IssuerSet,
    IssuerRdnSeq,
    IssuerOid,
    IssuerValue,
    ValiditySeq,
    ValidTime,
    ValidTime2,
    SubjectSeq,
    SubjectSet,
    SubjectRdnSeq,
    SubjectOid,
    SubjectValue,
    PubKeySeq,
    ExtensionsWrap,
    ExtensionsSeq,
    ExtensionSeq,
    ExtOid,
    ExtValue,
    ExtInnerSeq,
    GeneralName,
    DnsName,
    OuterAlgSeq,
    OuterAlgOid,
    Encrypted,
    Padding,
    Error,
}

/// Что делать с байтами значения поля после его длины.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// Контейнер: первое вложенное поле.
    Child(Field),
    /// Байты без разбора, по одному (PADDING и мёртвыеContents C: версия, серийник, времена, значение issuer).
    Plain,
    /// Пропуск остатка поля целиком (`ASN1_skip`: публичный ключ, подпись, ERROR).
    Skip,
    /// Значение OID: матчер C; `subject` — OID имени субъекта, где совпадение CN дописывает `", "`.
    Oid { subject: bool },
    /// Значение имени субъекта или dNSName: пишется в `ssl`, пока тип `Subject_Common`.
    Name,
}

/// Проверка тега поля: жёсткая (несоответствие — ERROR) или мягкая (разбор идёт дальше к длине).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tag {
    Hard(u8),
    Soft,
    /// Тег разбирается отдельной логикой поля (ExtValue, GeneralName, Padding, Error).
    Special,
}

impl Field {
    fn tag(self) -> Tag {
        match self {
            Field::VersionWrap => Tag::Hard(0xa0),
            Field::VersionInt | Field::Serial => Tag::Hard(0x02),
            Field::SigOid
            | Field::IssuerOid
            | Field::SubjectOid
            | Field::ExtOid
            | Field::OuterAlgOid => Tag::Hard(0x06),
            Field::ExtensionsWrap => Tag::Hard(0xa3),
            Field::Encrypted => Tag::Hard(0x03),
            Field::IssuerSet
            | Field::SubjectSet
            | Field::IssuerValue
            | Field::SubjectValue
            | Field::ValidTime
            | Field::ValidTime2 => Tag::Soft,
            Field::ExtValue | Field::GeneralName | Field::Padding | Field::Error => Tag::Special,
            _ => Tag::Hard(0x30),
        }
    }

    /// Поле-«брат» после этого поля: `kludge_next` от состояния длины (`src/proto-x509.c:485-526`), по умолчанию
    /// PADDING. Для DnsName брат — следующий GeneralName.
    fn brother(self) -> Field {
        match self {
            Field::TbsSeq => Field::OuterAlgSeq,
            Field::VersionWrap => Field::Serial,
            Field::Serial => Field::SigAlgSeq,
            Field::SigAlgSeq => Field::IssuerSeq,
            Field::IssuerSeq => Field::ValiditySeq,
            Field::IssuerSet => Field::IssuerSet,
            Field::IssuerOid => Field::IssuerValue,
            Field::ValiditySeq => Field::SubjectSeq,
            Field::ValidTime => Field::ValidTime2,
            Field::SubjectSeq => Field::PubKeySeq,
            Field::SubjectSet => Field::SubjectSet,
            Field::SubjectOid => Field::SubjectValue,
            Field::PubKeySeq => Field::ExtensionsWrap,
            Field::ExtensionSeq => Field::ExtensionSeq,
            Field::ExtOid => Field::ExtValue,
            Field::DnsName => Field::GeneralName,
            Field::OuterAlgSeq => Field::Encrypted,
            _ => Field::Padding,
        }
    }

    /// Что идёт после длины поля.
    fn body(self) -> Body {
        match self {
            Field::OuterSeq => Body::Child(Field::TbsSeq),
            Field::TbsSeq => Body::Child(Field::VersionWrap),
            Field::VersionWrap => Body::Child(Field::VersionInt),
            Field::SigAlgSeq => Body::Child(Field::SigOid),
            Field::IssuerSeq => Body::Child(Field::IssuerSet),
            Field::IssuerSet => Body::Child(Field::IssuerRdnSeq),
            Field::IssuerRdnSeq => Body::Child(Field::IssuerOid),
            Field::ValiditySeq => Body::Child(Field::ValidTime),
            Field::SubjectSeq => Body::Child(Field::SubjectSet),
            Field::SubjectSet => Body::Child(Field::SubjectRdnSeq),
            Field::SubjectRdnSeq => Body::Child(Field::SubjectOid),
            Field::ExtensionsWrap => Body::Child(Field::ExtensionsSeq),
            Field::ExtensionsSeq => Body::Child(Field::ExtensionSeq),
            Field::ExtensionSeq => Body::Child(Field::ExtOid),
            Field::ExtValue => Body::Child(Field::ExtInnerSeq),
            Field::ExtInnerSeq => Body::Child(Field::GeneralName),
            Field::OuterAlgSeq => Body::Child(Field::OuterAlgOid),
            Field::SigOid | Field::IssuerOid | Field::ExtOid | Field::OuterAlgOid => {
                Body::Oid { subject: false }
            }
            Field::SubjectOid => Body::Oid { subject: true },
            Field::SubjectValue | Field::DnsName => Body::Name,
            Field::PubKeySeq | Field::Encrypted | Field::Error => Body::Skip,
            _ => Body::Plain,
        }
    }
}

/// Кадр стека: остаток длины поля и поле-брат после него (`stack.remainings[]`/`stack.states[]`).
#[derive(Clone, Copy, Debug)]
struct Frame {
    remaining: u32,
    next: Field,
}

/// Матчер OID по наблюдаемому поведению smack-таблицы `mib[]` (справка §C4): байты значения с отброшенными
/// `0x80` (SMACK_SNMP_HACK) сравниваются с двумя шаблонами, дающими вывод; прочие шаблоны таблицы важны только
/// тем, что их совпадение сбрасывает тип в невыводящий, что сводится к правилу в [`OidMatch::finish`].
#[derive(Clone, Copy, Debug, Default)]
struct OidMatch {
    /// Сколько первых байтов значения уже совпало с каждым шаблоном (255 — шаблон мёртв).
    cn: u8,
    san: u8,
    /// Был ли хоть один не-`0x80` байт; первый такой байт.
    first: Option<u8>,
    /// Шаблон CN или SAN завершился на границе дуги внутри этого OID.
    common: bool,
}

const OID_CN: [u8; 3] = [0x55, 0x04, 0x03];
const OID_SAN: [u8; 3] = [0x55, 0x1d, 0x11];

impl OidMatch {
    fn reset(&mut self) {
        *self = OidMatch::default();
    }

    /// Один байт значения OID. Возвращает `true`, если на этом байте завершился шаблон CN или SAN
    /// и байт — конец дуги (без старшего бита), как отчёт smack на границе дуги (`src/proto-x509.c:687-746`).
    fn byte(&mut self, b: u8) -> bool {
        if self.first.is_none() && b != 0x80 {
            self.first = Some(b);
        }
        if b == 0x80 {
            return false;
        }
        let mut done = false;
        for (pos, pat) in [(&mut self.cn, OID_CN), (&mut self.san, OID_SAN)] {
            if *pos != u8::MAX {
                if pat.get(usize::from(*pos)) == Some(&b) {
                    *pos += 1;
                    if usize::from(*pos) == pat.len() {
                        done = true;
                        self.common = true;
                    }
                } else {
                    *pos = u8::MAX;
                }
            }
        }
        done && b & 0x80 == 0
    }
}

/// Шаг внутри поля: тег, первый байт длины, остальные байты длины, значение.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Tag(Field),
    LenFirst(Field),
    LenRest(Field),
    Body(Field),
}

/// Разбор сертификата: `x509_decode_init` + `x509_decode` (`src/proto-x509.c:544-1060,1378-1383`).
#[derive(Debug)]
pub(crate) struct X509 {
    stack: [Frame; MAX_DEPTH],
    depth: usize,
    step: Step,
    /// Накопление длинной формы длины, как `u.tag` у C (u16 значение, u8 счётчик — обе с обёрткой).
    len_value: u16,
    len_left: u8,
    /// Номер сертификата в цепочке с единицы: `x509.count` (u8 у C, ставится вызывающим после init).
    count: u8,
    /// `subject.type == Subject_Common`.
    subject_common: bool,
    oid: OidMatch,
}

impl Default for X509 {
    fn default() -> Self {
        X509 {
            stack: [Frame {
                remaining: 0,
                next: Field::Error,
            }; MAX_DEPTH],
            depth: 0,
            step: Step::Tag(Field::OuterSeq),
            len_value: 0,
            len_left: 0,
            count: 0,
            subject_common: false,
            oid: OidMatch::default(),
        }
    }
}

impl X509 {
    /// `x509_decode_init(&x, cert_remaining)`, затем `x.count = count` вызывающего
    /// (`src/proto-ssl.c:432-437`): внешний кадр — длина сертификата из TLS.
    pub(crate) fn init(&mut self, cert_len: usize, count: u32) {
        *self = X509::default();
        self.count = count as u8;
        self.push(Field::Error, cert_len);
    }

    /// `ASN1_push` (`src/proto-x509.c:304-374`): длина свыше 16 бит, глубина 9 или ребёнок длиннее родителя —
    /// кадр не кладётся, а разбор целого потока у C продолжается без него (шапка модуля); длина ребёнка при
    /// успехе вычитается из остатка родителя.
    fn push(&mut self, next: Field, remaining: usize) {
        if remaining > usize::from(u16::MAX) || self.depth >= MAX_DEPTH {
            return;
        }
        if self.depth > 0 {
            let parent = &mut self.stack[self.depth - 1];
            if remaining as u32 > parent.remaining {
                return;
            }
            parent.remaining -= remaining as u32;
        }
        self.stack[self.depth] = Frame {
            remaining: remaining as u32,
            next,
        };
        self.depth += 1;
    }

    fn top(&mut self) -> Option<&mut Frame> {
        self.depth.checked_sub(1).map(move |i| &mut self.stack[i])
    }

    /// Один фрагмент DER (`x509_decode`): имена дописываются в запись `ssl` через `cx`.
    pub(crate) fn feed(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut i = 0usize;
        while i < px.len() {
            // Снятие drained кадров перед байтом, как у C (`:567-571`).
            while self.depth > 0 && self.stack[self.depth - 1].remaining == 0 {
                self.depth -= 1;
                self.step = Step::Tag(self.stack[self.depth].next);
                if self.stack[self.depth].next == Field::Error && self.depth == 0 {
                    return;
                }
            }
            let Some(top) = self.top() else { return };
            if top.remaining == 0 {
                return;
            }
            top.remaining -= 1;
            let b = px[i];
            match self.step {
                Step::Tag(field) => self.step = self.on_tag(cx, field, b),
                Step::LenFirst(field) => {
                    if b & 0x80 != 0 {
                        self.len_left = b & 0x7f;
                        self.len_value = 0;
                        self.step = Step::LenRest(field);
                    } else {
                        self.push(field.brother(), usize::from(b));
                        self.step = self.after_len(field);
                    }
                }
                Step::LenRest(field) => {
                    self.len_value = (self.len_value << 8) | u16::from(b);
                    self.len_left = self.len_left.wrapping_sub(1);
                    if self.len_left == 0 {
                        let len = usize::from(self.len_value);
                        self.push(field.brother(), len);
                        self.step = self.after_len(field);
                    }
                }
                Step::Body(field) => {
                    i += self.on_body(cx, field, b, &px[i..]);
                }
            }
            i += 1;
        }
    }

    fn after_len(&mut self, field: Field) -> Step {
        match field.body() {
            Body::Child(child) => Step::Tag(child),
            Body::Oid { .. } => {
                self.oid.reset();
                Step::Body(field)
            }
            _ => Step::Body(field),
        }
    }

    fn on_tag(&mut self, cx: &mut ParseCx<'_>, field: Field, b: u8) -> Step {
        match field {
            Field::IssuerSet | Field::SubjectSet => {
                self.subject_common = false;
                Step::LenFirst(field)
            }
            Field::ExtValue => {
                if b == 0x04 {
                    Step::LenFirst(field)
                } else {
                    Step::Body(Field::Padding)
                }
            }
            Field::GeneralName => {
                if self.subject_common && b == 0x82 {
                    cx.append(app_id::SSL3, b", ");
                    Step::LenFirst(Field::DnsName)
                } else {
                    Step::Body(Field::Padding)
                }
            }
            Field::Padding => Step::Body(Field::Padding),
            Field::Error => Step::Body(Field::Error),
            _ => match field.tag() {
                Tag::Hard(want) if b != want => Step::Body(Field::Error),
                _ => Step::LenFirst(field),
            },
        }
    }

    /// Байт значения поля; возвращает, сколько *дополнительных* байт съел пропуск (`ASN1_skip`).
    fn on_body(&mut self, cx: &mut ParseCx<'_>, field: Field, b: u8, rest: &[u8]) -> usize {
        match field.body() {
            Body::Skip => self.skip(rest),
            Body::Oid { subject } => {
                if self.oid.byte(b) {
                    if subject {
                        if self.count <= 1 {
                            cx.append(app_id::SSL3, b", ");
                            self.subject_common = true;
                        } else {
                            self.subject_common = false;
                        }
                    } else {
                        self.subject_common = true;
                    }
                } else if b & 0x80 == 0 && !self.oid.common {
                    // Граница дуги без совпадения CN/SAN: совпадение любого другого шаблона таблицы
                    // сбрасывает тип; шаблоны начинаются с дуг 42/43/85 (справка §C4).
                    if matches!(self.oid.first, Some(0x2a | 0x2b | 0x55)) {
                        self.subject_common = false;
                    }
                }
                0
            }
            Body::Name => {
                if self.subject_common {
                    cx.append(app_id::SSL3, &[b]);
                }
                0
            }
            Body::Child(_) | Body::Plain => 0,
        }
    }

    /// `ASN1_skip` (`src/proto-x509.c:404-427`): пропуск остатка верхнего кадра в пределах фрагмента. Текущий
    /// байт уже уменьшил остаток в `feed`; `rest` начинается с него.
    fn skip(&mut self, rest: &[u8]) -> usize {
        let Some(top) = self.top() else { return 0 };
        let avail = rest.len().saturating_sub(1);
        let n = avail.min(top.remaining as usize);
        top.remaining -= n as u32;
        n
    }
}
