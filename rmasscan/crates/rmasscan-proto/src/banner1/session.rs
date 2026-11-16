//! Сессия баннера одного соединения: `banner1_parse` (`src/proto-banner1.c:113-325`, справка B1) над `tcb->banout`
//! и `tcb->banner1_state`, и неизменяемая конфигурация скана, которая выдаёт сессии таблице ([`BannerConfig`]
//! вместо глобальных `banner1` и `payloads.tcp[]` C).
//!
//! Правила неразрезанного потока (Р13, справка E2): байты до совпадения лежат в записи HEUR; на совпадении запись
//! вынимается (E1.3), и парсер получает их, а затем весь текущий сегмент, так что он видит поток с первого байта, а
//! записи `unknown` из байтов до совпадения нет (E2.1; у C по сегментам она остаётся). Первое совпадение решает:
//! отвергнутый SSL3 (hello TLS не слан, B1.2) делает остаток потока `unknown` (E2.2; у C следующий сегмент ещё может
//! совпасть с `{"` или IAC). Классификатор смотрит только первые 65 536 байт потока ([`CLASSIFY_WINDOW`], Р5), поэтому
//! байты до совпадения всегда целиком в записи HEUR и при неограниченном бюджете результат не зависит от нарезки.
//!
//! Бюджет таблицы режет записи только с конца ([`Banout::append`]); запись HEUR, которой бюджет отказал хоть в байте,
//! в парсер не повторяется, и поток остаётся `unknown` (её начало), а не идёт в парсер с дырой.

use std::fmt;
use std::sync::Arc;

use rmasscan_core::banner::MAX_BANNER_BYTES;

use crate::app::app_id;
use crate::tcp::app::{ByteBudget, Session, SessionAction, Sessions};

use super::banout::{Banout, Base64Stream};
use super::classify::{Classifier, PATTERNS, SearchState};
use super::ftp::Ftp;
use super::hello::{HelloTable, TcpBannerSettings};
use super::http::Http;
use super::imap4::Imap4;
use super::memcached::Memcached;
use super::minecraft::Minecraft;
use super::pop3::Pop3;
use super::rdp::Rdp;
use super::smtp::Smtp;
use super::ssh::Ssh;
use super::telnet::Telnet;
use super::tls::TlsFlags;
use super::vnc::Vnc;

/// Парсер, который выбрал классификатор (ветки `switch (tcb_state->app_proto)`, `src/proto-banner1.c:187-316`), в
/// границах 4b: SMB, TLS и всё после STARTTLS это [`AppProto::Unported`] (справка B6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppProto {
    Ftp,
    Smtp,
    Pop3,
    Imap4,
    Ssh,
    Http,
    /// Версия RFB из `extra` шаблона (`tcb_state->sub.vnc.version`, `:153-155`).
    Vnc(u8),
    Memcached,
    Telnet,
    Rdp,
    Minecraft,
    /// Ещё не перенесённый протокол: каждый байт в `unknown` (app 1).
    Unported,
}

/// Разбор байтов сервера одним парсером приложения: возобновляемый автомат, результат не зависит от нарезки (Р13).
pub(crate) trait Parser: Send {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]);
    /// Последние отложенные байты перед `banner_flush` (`src/stack-tcp-core.c:810-828`); у HTTP незавершённый
    /// заголовок ждёт здесь ради порядка C на неразрезанном потоке (`src/proto-http.c:678-681`, E2.3).
    fn flush(&mut self, _cx: &mut ParseCx<'_>) {}
    /// Состояние автомата для структурных тестов «никогда не паникует» (`terminal_tests`): какие состояния прошёл
    /// поток. Парсеры без такого теста дают 0.
    #[cfg(test)]
    fn probe(&self) -> u32 {
        0
    }
}

/// `isprint` локали C (masscan `setlocale` не зовёт): 0x20-0x7E; NUL в это не входит. Общий для FTP, SMTP и следующих
/// текстовых парсеров.
pub(super) fn c_isprint(c: u8) -> bool {
    matches!(c, 0x20..=0x7e)
}

/// Что видит парсер: буферы баннеров и бюджет таблицы, действия (`tcpapi_send` и `tcpapi_close` по порядку),
/// `--capture html`. Порта нет: ни один парсер 4b его не читает (FTP, SMTP и POP3 только сохраняют и возвращают
/// `pstate->port` вокруг `memset` передачи STARTTLS, `src/proto-ftp.c:96-100`; порт решает классификатор).
/// `starttls` ставит передача STARTTLS (у C `app_proto = PROTO_SSL3`, `src/proto-ftp.c:93-104`, `src/proto-smtp.c:139-150`, `src/proto-pop3.c:122-133`): со следующего
/// сегмента поток идёт в `unknown`; остаток своего сегмента парсер решает сам, текстовые парсеры отдают его в `unknown`
/// ([`ParseCx::hand_off_starttls`]).
pub(crate) struct ParseCx<'a> {
    pub(crate) banout: &'a mut Banout,
    pub(crate) budget: &'a mut ByteBudget,
    pub(crate) acts: &'a mut Vec<SessionAction>,
    /// `pstate->base64`: один кодер на соединение (захват сертификатов и heartbleed делят его, справка 4c §B4).
    pub(crate) base64: &'a mut Base64Stream,
    pub(crate) capture_html: bool,
    /// Флаги TLS скана (`Banner1.is_capture_*`/`is_heartbleed`/…), значение на сессию.
    pub(crate) tls_flags: TlsFlags,
    pub(crate) starttls: bool,
}

impl ParseCx<'_> {
    /// `banout_append(banout, app, px, length)`. Запись режется только с конца: после первого байта, в котором
    /// отказали предел Р5 или бюджет, в неё больше ничего не пишется ([`Banout::append`]).
    pub(crate) fn append(&mut self, app: u16, px: &[u8]) {
        self.banout.append(self.budget, app, px);
    }

    /// `banout_init_base64(&pstate->base64)`.
    // Потребитель — парсер TLS (задача 4 подэтапа 4c).
    #[allow(dead_code)]
    pub(crate) fn init_base64(&mut self) {
        self.base64.reset();
    }

    /// `banout_append_base64(banout, app, px, length, &pstate->base64)`.
    #[allow(dead_code)]
    pub(crate) fn append_base64(&mut self, app: u16, px: &[u8]) {
        self.banout.append_base64(self.budget, self.base64, app, px);
    }

    /// `banout_finalize_base64(banout, app, &pstate->base64)`.
    #[allow(dead_code)]
    pub(crate) fn finalize_base64(&mut self, app: u16) {
        self.banout.finalize_base64(self.budget, self.base64, app);
    }

    /// `banout_end(banout, app)`.
    #[allow(dead_code)]
    pub(crate) fn end_banner(&mut self, app: u16) {
        self.banout.end(app);
    }

    /// `banout_is_contains(banout, app, needle)`.
    pub(crate) fn banner_contains(&self, app: u16, needle: &[u8]) -> bool {
        self.banout.contains(app, needle)
    }

    /// `tcpapi_send(socket, bytes, length, 0)` парсера.
    pub(crate) fn send(&mut self, bytes: &[u8]) {
        self.acts.push(SessionAction::Send(bytes.to_vec()));
    }

    /// `tcpapi_send(socket, bytes, length, TCP__static)` неизменного блоба процесса: в очередь встаёт общий буфер, не
    /// копия (у C указатель на статическую память, `src/stack-tcp-core.c:1381-1385`).
    pub(crate) fn send_shared(&mut self, buf: &Arc<[u8]>) {
        self.acts.push(SessionAction::SendShared(Arc::clone(buf)));
    }

    /// `tcpapi_send(socket, bytes, length, TCP__copy)` (`src/proto-tcp-telnet.c:248`).
    pub(crate) fn send_copy(&mut self, bytes: &[u8]) {
        self.acts.push(SessionAction::SendCopy(bytes.to_vec()));
    }

    /// `tcpapi_close(socket)` парсера; C зовёт его и повторно (IMAP4 закрывает дважды), каждый вызов записан.
    pub(crate) fn close(&mut self) {
        self.acts.push(SessionAction::Close);
    }

    /// Согласие сервера на STARTTLS (FTP 234, SMTP 220, POP3 `+OK`). У C `memset` состояния потока, `app_proto =
    /// PROTO_SSL3`, `is_sent_sslhello = 1` и `tcpapi_send(banner_ssl.hello)` (`src/proto-ftp.c:93-104`,
    /// `src/proto-smtp.c:139-150`, `src/proto-pop3.c:122-133`). В 4b hello TLS не шлётся (справка B6): номер C
    /// становится SSL3 ([`Banner1Session::run`]), а каждый байт после строки согласия, `rest` этого сегмента и все
    /// следующие сегменты, это одна запись `unknown`. У C цикл парсера на этом не кончается (`state = 0`, затем
    /// `break` из `switch`): `rest` идёт тем же текстовым парсером с состояния 0, как новое приветствие (с повтором
    /// `AUTH TLS`, `EHLO` или `CAPA`), а следующий сегмент уже в TLS, так что у C итог тут зависит от нарезки
    /// (эталоны `*-tail`); правило 4b от неё не зависит.
    pub(crate) fn hand_off_starttls(&mut self, rest: &[u8]) {
        self.starttls = true;
        if !rest.is_empty() {
            self.append(app_id::HEUR, rest);
        }
    }
}

/// Заглушка ещё не перенесённого протокола.
struct Unported;

impl Parser for Unported {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        cx.append(app_id::HEUR, px);
    }
}

/// Парсер приложения: одиннадцать перенесённых, SSL3 и SMB это [`Unported`] (справка B6).
pub(crate) fn parser_for(p: AppProto) -> Box<dyn Parser> {
    match p {
        AppProto::Ftp => Box::<Ftp>::default(),
        AppProto::Smtp => Box::<Smtp>::default(),
        AppProto::Pop3 => Box::<Pop3>::default(),
        AppProto::Imap4 => Box::<Imap4>::default(),
        AppProto::Http => Box::<Http>::default(),
        AppProto::Ssh => Box::<Ssh>::default(),
        AppProto::Telnet => Box::<Telnet>::default(),
        AppProto::Vnc(version) => Box::new(Vnc::new(version)),
        AppProto::Rdp => Box::<Rdp>::default(),
        AppProto::Memcached => Box::<Memcached>::default(),
        AppProto::Minecraft => Box::<Minecraft>::default(),
        AppProto::Unported => Box::new(Unported),
    }
}

/// Неизменяемая часть скана, одна на все сессии (у C это глобальные `banner1` и `payloads.tcp[]`): hello по порту с
/// запросом HTTP, `--capture html`, выбор парсера и собранный классификатор. Сессия держит на неё `Arc`, а не копии
/// полей.
struct Scan {
    hellos: HelloTable,
    capture_html: bool,
    /// Флаги TLS; настоящие настройки придут в задаче 5, до неё — умолчания C (захват сертификатов включён).
    tls_flags: TlsFlags,
    parsers: fn(AppProto) -> Box<dyn Parser>,
    classifier: &'static Classifier,
}

impl fmt::Debug for Scan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scan")
            .field("hellos", &self.hellos)
            .field("capture_html", &self.capture_html)
            .finish_non_exhaustive()
    }
}

/// Неизменяемая конфигурация скана из [`TcpBannerSettings`]: раздаёт сессии таблицам соединений.
#[derive(Debug)]
pub(crate) struct BannerConfig {
    scan: Arc<Scan>,
}

impl BannerConfig {
    pub(crate) fn new(s: &TcpBannerSettings) -> BannerConfig {
        BannerConfig::with_parsers(s, parser_for)
    }

    /// Конфигурация с выбором парсера `parsers` (вне тестов всегда [`parser_for`]). Автомат классификатора
    /// собирается здесь, до скана, как `smack_compile` в `banner1_create` из `tcpcon_create_table`
    /// (`src/proto-banner1.c:509-517`, `src/stack-tcp-core.c:714`), а не на первом сегменте приёма; он один на
    /// процесс.
    fn with_parsers(
        s: &TcpBannerSettings,
        parsers: fn(AppProto) -> Box<dyn Parser>,
    ) -> BannerConfig {
        BannerConfig {
            scan: Arc::new(Scan {
                hellos: HelloTable::new(s),
                capture_html: s.capture_html,
                tls_flags: TlsFlags::default(),
                parsers,
                classifier: Classifier::banner1(),
            }),
        }
    }

    /// Новая сессия порта `port` (`tcpcon_create_tcb`, `src/stack-tcp-core.c:1043-1049`).
    pub(crate) fn session(&self, port: u16) -> Banner1Session {
        Banner1Session {
            scan: Arc::clone(&self.scan),
            port,
            app_proto: None,
            stage: Stage::Classify { state: 0, seen: 0 },
            banout: Banout::default(),
            base64: Base64Stream::default(),
        }
    }

    /// Сессия, которая сразу разбирает поток парсером приложения `app` (номер C) без классификатора; у VNC версия 0,
    /// как у обнулённого `tcb_state` без шаблона.
    pub(crate) fn forced(&self, port: u16, app: u16) -> Banner1Session {
        let mut s = self.session(port);
        s.app_proto = Some(app);
        s.stage = Stage::Parse((self.scan.parsers)(app_proto_for(app, 0)));
        s
    }
}

/// Номер приложения C (`patterns[x].id` после поправки порта) в парсер 4b: ветки `switch (tcb_state->app_proto)`
/// (`src/proto-banner1.c:187-316`); SSL3 (TLS, 4c), SMB (4d) и прочие номера без ветки это [`AppProto::Unported`].
fn app_proto_for(app: u16, extra: u8) -> AppProto {
    match app {
        app_id::FTP => AppProto::Ftp,
        app_id::SMTP => AppProto::Smtp,
        app_id::POP3 => AppProto::Pop3,
        app_id::IMAP4 => AppProto::Imap4,
        app_id::SSH1 | app_id::SSH2 => AppProto::Ssh,
        app_id::HTTP => AppProto::Http,
        app_id::VNC_RFB => AppProto::Vnc(extra),
        app_id::MEMCACHED => AppProto::Memcached,
        app_id::TELNET => AppProto::Telnet,
        app_id::RDP => AppProto::Rdp,
        app_id::MC => AppProto::Minecraft,
        _ => AppProto::Unported,
    }
}

impl Sessions for BannerConfig {
    fn new_session(&self, remote_port: u16) -> Box<dyn Session> {
        Box::new(self.session(remote_port))
    }
}

/// Окно классификатора: первые 65 536 байт потока (Р5, как предел записи HEUR, в которой они ждут). Шаблон, который
/// впервые совпал бы дальше, не ищется, и поток остаётся `unknown` (у C предела нет, и он классифицирует и разбирает
/// позже, `src/proto-banner1.c:127-184`). Так байты до совпадения всегда целиком в записи HEUR, и результат один и
/// тот же целиком, по байту и в любой нарезке.
const CLASSIFY_WINDOW: usize = MAX_BANNER_BYTES;

/// Где поток: классификатор (состояние smack и сколько байт потока он уже видел), `unknown` до конца или парсер
/// приложения.
enum Stage {
    Classify {
        state: SearchState,
        seen: usize,
    },
    /// Классификатор больше не ищет, каждый байт в HEUR: отвергнутый SSL3 (E2.2), окно без совпадения
    /// ([`CLASSIFY_WINDOW`]) или совпадение при неполной записи HEUR (её не повторить в парсер).
    Unknown,
    Parse(Box<dyn Parser>),
}

/// Сессия баннера одного соединения (`tcb->stream`, `tcb->banner1_state`, `tcb->banout`): общая часть скана, порт и
/// своё состояние.
pub(crate) struct Banner1Session {
    scan: Arc<Scan>,
    port: u16,
    /// `tcb_state->app_proto`; `None` это PROTO_NONE.
    app_proto: Option<u16>,
    stage: Stage,
    banout: Banout,
    /// `tcb_state->base64`.
    base64: Base64Stream,
}

/// `is_sent_sslhello` (`src/proto-banner1.h:249`): его ставит только отправка TLS hello (`banner_set_sslhello`,
/// `src/stack-tcp-app.c:157-163`), а его в 4b нет, поэтому совпадение SSL3 всегда отвергается (справка B1.2, B6).
const SSL_HELLO_SENT: bool = false;

impl Banner1Session {
    pub(crate) fn app_proto(&self) -> Option<u16> {
        self.app_proto
    }

    /// [`Parser::probe`] выбранного парсера; `None`, пока классификатор ищет или поток `unknown`.
    #[cfg(test)]
    pub(crate) fn probe(&self) -> Option<u32> {
        match &self.stage {
            Stage::Parse(p) => Some(p.probe()),
            _ => None,
        }
    }

    /// Один вызов парсера. Передача STARTTLS (`cx.starttls`) делает номер C SSL3, а парсер заглушкой: дальше
    /// `unknown`.
    fn run(
        &mut self,
        parser: &mut Box<dyn Parser>,
        budget: &mut ByteBudget,
        acts: &mut Vec<SessionAction>,
        px: &[u8],
    ) {
        let mut cx = ParseCx {
            banout: &mut self.banout,
            budget,
            acts,
            base64: &mut self.base64,
            capture_html: self.scan.capture_html,
            tls_flags: self.scan.tls_flags,
            starttls: false,
        };
        parser.parse(&mut cx, px);
        if cx.starttls {
            self.app_proto = Some(app_id::SSL3);
            *parser = Box::new(Unported);
        }
    }

    /// Совпадение шаблона `id` (`src/proto-banner1.c:136-182`): поправки порта и версии, номер C, парсер; запись
    /// HEUR вынимается и повторяется в парсер, затем весь текущий сегмент. Неполная запись HEUR (бюджет отказал ей в
    /// байте) в парсер не идёт: он увидел бы поток с дырой, и поток остаётся `unknown`, номер C тот, что выбрал
    /// классификатор.
    fn classified(
        &mut self,
        id: usize,
        px: &[u8],
        budget: &mut ByteBudget,
        acts: &mut Vec<SessionAction>,
    ) {
        let Some(pat) = PATTERNS.get(id) else {
            self.banout.append(budget, app_id::HEUR, px);
            return;
        };
        // `:147-157`: `"220 "` (`extra == 1`) на 25 и 587 это SMTP.
        let app = if pat.app == app_id::FTP && pat.extra == 1 && matches!(self.port, 25 | 587) {
            app_id::SMTP
        } else {
            pat.app
        };
        self.app_proto = Some(app);
        if self.banout.lossy(app_id::HEUR) {
            // Стадия остаётся `Unknown` (её поставил `parse`): дальше всё в HEUR, а неполная запись не растёт.
            self.banout.append(budget, app_id::HEUR, px);
            return;
        }
        let mut parser = (self.scan.parsers)(app_proto_for(app, pat.extra));
        let held = self.banout.take(budget, app_id::HEUR);
        if !held.is_empty() {
            self.run(&mut parser, budget, acts, &held);
        }
        self.run(&mut parser, budget, acts, px);
        self.stage = Stage::Parse(parser);
    }
}

impl Session for Banner1Session {
    /// Hello порта из общей таблицы скана.
    fn hello(&self) -> Option<&[u8]> {
        self.scan.hellos.hello(self.port).map(|h| &h[..])
    }

    /// `banner1_parse` одного сегмента. Пустой сегмент это отсутствие данных (у C `banner1_parse` пустым не зовут:
    /// `APP_RECV_PAYLOAD` несёт нагрузку).
    fn parse(&mut self, px: &[u8], budget: &mut ByteBudget, acts: &mut Vec<SessionAction>) {
        if px.is_empty() {
            return;
        }
        match std::mem::replace(&mut self.stage, Stage::Unknown) {
            // `:126-184`: один `smack_search_next` на сегмент, состояние smack между сегментами; ищется только
            // часть сегмента в окне.
            Stage::Classify { mut state, seen } => {
                let window = px.len().min(CLASSIFY_WINDOW.saturating_sub(seen));
                let head = px.get(..window).unwrap_or(px);
                match self.scan.classifier.search(&mut state, head) {
                    Some(id)
                        if PATTERNS
                            .get(id)
                            .is_some_and(|p| p.app != app_id::SSL3 || SSL_HELLO_SENT) =>
                    {
                        self.classified(id, px, budget, acts);
                    }
                    // Отвергнутый SSL3 (`:137-138`): первое совпадение решает, остаток потока `unknown` (E2.2).
                    Some(_) => self.banout.append(budget, app_id::HEUR, px),
                    None => {
                        let seen = seen.saturating_add(px.len());
                        if seen < CLASSIFY_WINDOW {
                            self.stage = Stage::Classify { state, seen };
                        }
                        self.banout.append(budget, app_id::HEUR, px);
                    }
                }
            }
            Stage::Unknown => self.banout.append(budget, app_id::HEUR, px),
            Stage::Parse(mut parser) => {
                self.run(&mut parser, budget, acts, px);
                self.stage = Stage::Parse(parser);
            }
        }
    }

    fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)> {
        if let Stage::Parse(parser) = &mut self.stage {
            parser.flush(&mut ParseCx {
                banout: &mut self.banout,
                budget,
                acts: &mut Vec::new(),
                base64: &mut self.base64,
                capture_html: self.scan.capture_html,
                tls_flags: self.scan.tls_flags,
                starttls: false,
            });
        }
        self.banout.flush(budget)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner1::driver::{StreamAction, banner_stream};
    use crate::banner1::hello::HelloSet;
    use rmasscan_core::banner::MAX_BANNER_BYTES;

    /// Парсер-метка: пишет в app 42 имя выбранного [`AppProto`] при первом вызове, затем байты; на `!` ставит
    /// `starttls` и шлёт `STARTTLS`.
    struct Tag {
        p: AppProto,
        started: bool,
    }

    impl Parser for Tag {
        fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
            if !self.started {
                self.started = true;
                let name = format!("{:?}|", self.p);
                cx.append(42, name.as_bytes());
            }
            for (i, b) in px.iter().enumerate() {
                if *b == b'!' {
                    cx.acts.push(SessionAction::Send(b"STARTTLS".to_vec()));
                    cx.starttls = true;
                    cx.append(42, &px[..i]);
                    return;
                }
            }
            cx.append(42, px);
        }
    }

    fn tagging(p: AppProto) -> Box<dyn Parser> {
        Box::new(Tag { p, started: false })
    }

    fn tag_config() -> BannerConfig {
        BannerConfig::with_parsers(&TcpBannerSettings::default(), tagging)
    }

    thread_local! {
        /// Байты, которые получил [`Record`] в этом потоке теста, по порядку вызовов.
        static SEEN: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    /// Парсер-самописец: каждый байт, который ему дали, в [`SEEN`] и в запись app 42.
    struct Record;

    impl Parser for Record {
        fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
            SEEN.with(|s| s.borrow_mut().extend_from_slice(px));
            cx.append(42, px);
        }
    }

    fn recording(_: AppProto) -> Box<dyn Parser> {
        Box::new(Record)
    }

    /// Что получил парсер-самописец с прошлого вызова.
    fn take_seen() -> Vec<u8> {
        SEEN.with(|s| std::mem::take(&mut *s.borrow_mut()))
    }

    /// Итог потока через сессию: `(app_proto, записи, действия)`.
    type Fed = (Option<u16>, Vec<(u16, Vec<u8>)>, Vec<SessionAction>);

    /// Поток через сессию.
    fn feed(cfg: &BannerConfig, port: u16, force: Option<u16>, segs: &[&[u8]]) -> Fed {
        let mut s = match force {
            Some(app) => cfg.forced(port, app),
            None => cfg.session(port),
        };
        let mut budget = ByteBudget::new(1 << 24);
        let mut acts = Vec::new();
        for seg in segs {
            s.parse(seg, &mut budget, &mut acts);
        }
        let app = s.app_proto();
        let recs = s.flush(&mut budget);
        assert_eq!(budget.left(), 1 << 24, "budget back after flush");
        (app, recs, acts)
    }

    fn bytewise(stream: &[u8]) -> Vec<&[u8]> {
        stream.chunks(1).collect()
    }

    /// E2.1: совпадение во втором сегменте (или в любом по байту) не оставляет записи `unknown`: байты до него
    /// повторены в парсер, и он видит поток с первого байта, как C на неразрезанном потоке.
    #[test]
    fn match_in_later_segment_gives_no_unknown_record() {
        let cfg = tag_config();
        let stream = b"HTTP/1.0 200 OK\r\n\r\n";
        let want = vec![(42, [&b"Http|"[..], stream].concat())];
        for segs in [
            vec![&stream[..]],
            vec![&b"HT"[..], &stream[2..]],
            bytewise(stream),
        ] {
            let (app, recs, _) = feed(&cfg, 80, None, &segs);
            assert_eq!(app, Some(app_id::HTTP));
            assert_eq!(recs, want, "{} segments", segs.len());
        }
        // Безъякорный шаблон после ведущих байтов: парсер получает и их.
        let stream = b"xx\xff\xfb\x01\xff\xfd\x03";
        for segs in [
            vec![&stream[..]],
            vec![&stream[..4], &stream[4..]],
            bytewise(stream),
        ] {
            let (app, recs, _) = feed(&cfg, 23, None, &segs);
            assert_eq!(app, Some(app_id::TELNET));
            assert_eq!(recs, [(42, [&b"Telnet|"[..], stream].concat())]);
        }
    }

    /// E2.2: первое совпадение решает. Отвергнутый SSL3 (hello TLS не слан, `src/proto-banner1.c:137-138`) делает
    /// весь поток `unknown`, и позднее `{"` или IAC классификатор уже не ищет.
    #[test]
    fn ssl3_first_match_makes_stream_unknown() {
        let cfg = tag_config();
        let stream: &[u8] = b"\x16\x03\x01\x00\x02\x02\x28{\"a\":1}\xff\xfb\x01\xff\xfb";
        for segs in [
            vec![stream],
            vec![&stream[..7], &stream[7..14], &stream[14..]],
            bytewise(stream),
        ] {
            let (app, recs, acts) = feed(&cfg, 443, None, &segs);
            assert_eq!(app, None);
            assert_eq!(recs, [(app_id::HEUR, stream.to_vec())]);
            assert!(acts.is_empty());
        }
        // SSL3 после ведущего байта не якорный: поток без совпадения, тоже unknown.
        let (app, recs, _) = feed(&cfg, 443, None, &[b"x\x16\x03\x01"]);
        assert_eq!(
            (app, recs),
            (None, vec![(app_id::HEUR, b"x\x16\x03\x01".to_vec())])
        );
    }

    /// `"220 "` на 25 и 587 это SMTP, на других портах FTP; `"220-"` FTP на любом (`src/proto-banner1.c:147-153`,
    /// E3.3).
    #[test]
    fn smtp_220_space_on_25_587_ftp_elsewhere() {
        let cfg = tag_config();
        for (port, stream, app, tag) in [
            (
                25u16,
                &b"220 mail.example.test\r\n"[..],
                app_id::SMTP,
                &b"Smtp|"[..],
            ),
            (587, b"220 mail.example.test\r\n", app_id::SMTP, b"Smtp|"),
            (21, b"220 ftp\r\n", app_id::FTP, b"Ftp|"),
            (2525, b"220 mail.example.test\r\n", app_id::FTP, b"Ftp|"),
            (0, b"220 x\r\n", app_id::FTP, b"Ftp|"),
            (u16::MAX, b"220 x\r\n", app_id::FTP, b"Ftp|"),
            (25, b"220-mail.example.test\r\n", app_id::FTP, b"Ftp|"),
            (587, b"220-x\r\n", app_id::FTP, b"Ftp|"),
            (25, b"521 no\r\n", app_id::SMTP, b"Smtp|"),
        ] {
            let (got, recs, _) = feed(&cfg, port, None, &[stream]);
            assert_eq!(got, Some(app), "{port} {stream:?}");
            assert_eq!(recs, [(42, [tag, stream].concat())], "{port}");
        }
    }

    /// Версия VNC из `extra` шаблона, SSH1 и SSH2 одним парсером с номером шаблона (`src/proto-banner1.c:153-155`,
    /// `:250-261`).
    #[test]
    fn classifier_picks_parser_and_c_number() {
        let cfg = tag_config();
        for (stream, app, tag) in [
            (&b"RFB 000.000\n"[..], 33u16, &b"Vnc(1)|"[..]),
            (b"RFB 003.005\n", 33, b"Vnc(3)|"),
            (b"RFB 003.007\n", 33, b"Vnc(7)|"),
            (b"RFB 003.889\n", 33, b"Vnc(8)|"),
            (b"SSH-1.99-x\r\n", 2, b"Ssh|"),
            (b"SSH-2.0-x\r\n", 3, b"Ssh|"),
            (b"+OK x\r\n", 12, b"Pop3|"),
            (b"* OK x\r\n", 13, b"Imap4|"),
            (b"STAT pid 1\r\n", 25, b"Memcached|"),
            (b"login: ", 29, b"Telnet|"),
            (
                b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x0f",
                30,
                b"Rdp|",
            ),
            (b"{\"x\":1}", 32, b"Minecraft|"),
            (b"\x82\x00\x00\x00", 10, b"Unported|"),
        ] {
            let (got, recs, _) = feed(&cfg, 9999, None, &[stream]);
            assert_eq!(got, Some(app), "{stream:?}");
            assert_eq!(recs, [(42, [tag, stream].concat())], "{stream:?}");
        }
    }

    /// SMB в 4b не перенесён (справка B6): `app_proto` 10 как у C, весь поток одной записью `unknown`, в любой
    /// нарезке, без действий.
    #[test]
    fn smb_classified_stream_is_unknown_in_4b() {
        let s = TcpBannerSettings::default();
        let stream: &[u8] = b"\x00\x00\x00\x27\xffSMBr\x00\x00\x00\x00\x98\x01\xc8";
        for segs in [
            vec![stream],
            vec![&stream[..2], &stream[2..]],
            bytewise(stream),
        ] {
            let r = banner_stream(&s, 445, None, &segs);
            assert_eq!(r.app_proto, Some(app_id::SMB));
            assert_eq!(r.records, [(app_id::HEUR, stream.to_vec())]);
            assert!(r.actions.is_empty());
        }
        let r = banner_stream(&s, 139, None, &[b"\x83\x00\x00\x01\x8f"]);
        assert_eq!(r.app_proto, Some(app_id::SMB));
        assert_eq!(
            r.records,
            [(app_id::HEUR, b"\x83\x00\x00\x01\x8f".to_vec())]
        );
    }

    /// `force_app` запускает парсер приложения без классификатора: поток с первого байта, без HEUR, номер C тот, что
    /// задан, даже если поток похож на другой протокол.
    #[test]
    fn banner_stream_force_app_skips_classifier() {
        let cfg = tag_config();
        let (app, recs, _) = feed(&cfg, 80, Some(app_id::FTP), &[b"HTTP/1.0", b" 200\r\n"]);
        assert_eq!(app, Some(app_id::FTP));
        assert_eq!(recs, [(42, b"Ftp|HTTP/1.0 200\r\n".to_vec())]);
        let (app, recs, _) = feed(&cfg, 5900, Some(33), &[b"x"]);
        assert_eq!(app, Some(33));
        assert_eq!(recs, [(42, b"Vnc(0)|x".to_vec())]);
        for (force, tag) in [
            (9u16, &b"Unported|"[..]),
            (10, b"Unported|"),
            (3, b"Ssh|"),
            (2, b"Ssh|"),
        ] {
            let (app, recs, _) = feed(&cfg, 1, Some(force), &[b"\x16\x03\x01"]);
            assert_eq!(app, Some(force));
            assert_eq!(recs, [(42, [tag, b"\x16\x03\x01"].concat())]);
        }
        // Через офлайн-драйвер: принудительный SSH получает HTTP-байты и сохраняет их как SSH (`src/proto-ssh.c:84`).
        let r = banner_stream(
            &TcpBannerSettings::default(),
            80,
            Some(app_id::SSH2),
            &[b"HTTP/1.0 200\r\n"],
        );
        assert_eq!(r.app_proto, Some(app_id::SSH2));
        assert_eq!(r.records, [(app_id::SSH2, b"HTTP/1.0 200\r\n".to_vec())]);
    }

    /// Передача STARTTLS: парсер ставит `starttls`, номер C становится SSL3 (9), со следующего сегмента всё в
    /// `unknown`; остаток своего сегмента парсер решает сам. Передача во время повтора HEUR тоже переключает до
    /// текущего сегмента.
    #[test]
    fn starttls_hands_the_rest_to_unknown() {
        let cfg = tag_config();
        let (app, recs, acts) = feed(
            &cfg,
            21,
            None,
            &[b"220-a\r\n", b"234 x!lost", b"\x16\x03\x01", b"more"],
        );
        assert_eq!(app, Some(app_id::SSL3));
        assert_eq!(
            recs,
            [
                (42, b"Ftp|220-a\r\n234 x".to_vec()),
                (app_id::HEUR, b"\x16\x03\x01more".to_vec())
            ]
        );
        assert_eq!(acts, [SessionAction::Send(b"STARTTLS".to_vec())]);
        // Совпадение во втором сегменте, передача в байтах первого (повтор HEUR): текущий сегмент уже unknown.
        let (app, recs, _) = feed(&cfg, 9999, None, &[b"!x", b"\xff\xfb\x01\xff\xfd tail"]);
        assert_eq!(app, Some(app_id::SSL3));
        assert_eq!(
            recs,
            [
                (42, b"Telnet|".to_vec()),
                (app_id::HEUR, b"\xff\xfb\x01\xff\xfd tail".to_vec())
            ]
        );
    }

    /// Пустой сегмент это отсутствие данных: ни записи HEUR длины 0, ни шага классификатора.
    #[test]
    fn empty_segment_is_no_data() {
        let cfg = tag_config();
        let (app, recs, _) = feed(&cfg, 80, None, &[b"", b"HT", b"", b"TP/1.0", b""]);
        assert_eq!(app, Some(app_id::HTTP));
        assert_eq!(recs, [(42, b"Http|HTTP/1.0".to_vec())]);
        let (app, recs, _) = feed(&cfg, 80, None, &[b""]);
        assert_eq!((app, recs), (None, Vec::new()));
    }

    /// Hello сессии это hello порта конфигурации.
    #[test]
    fn session_hello_is_the_port_hello() {
        let cfg = BannerConfig::new(&TcpBannerSettings {
            hello_strings: vec![(7, b"seven".to_vec())],
            ..TcpBannerSettings::default()
        });
        assert_eq!(cfg.session(7).hello(), Some(&b"seven"[..]));
        assert_eq!(cfg.session(23).hello(), Some(&b"\xff\xf6"[..]));
        assert_eq!(cfg.session(443).hello(), None);
        assert_eq!(cfg.forced(23, 29).hello(), Some(&b"\xff\xf6"[..]));
    }

    /// I1 ревью задачи 8: бюджет, отказавший записи HEUR в байте, делает её неполной, и такая запись в парсер не
    /// повторяется: парсер не получает `"HTP/1.0 200"` (поток с дырой), поток остаётся `unknown` с началом `"H"`, номер
    /// C тот, что выбрал классификатор, остальное считается выброшенным.
    #[test]
    fn lossy_heur_is_not_replayed_into_a_parser() {
        let cfg = BannerConfig::with_parsers(&TcpBannerSettings::default(), recording);
        let mut s = cfg.session(80);
        let mut budget = ByteBudget::new(1);
        let mut acts = Vec::new();
        take_seen();
        for seg in [&b"HT"[..], b"TP/1.0 200", b" OK\r\n"] {
            s.parse(seg, &mut budget, &mut acts);
        }
        assert_eq!(take_seen(), b"", "a lossy HEUR record reached the parser");
        assert_eq!(s.app_proto(), Some(app_id::HTTP));
        assert_eq!(budget.dropped(), 1 + 10 + 5);
        assert_eq!(s.flush(&mut budget), [(app_id::HEUR, b"H".to_vec())]);
        assert_eq!(budget.left(), 1);
        assert!(acts.is_empty());

        // Бюджета ровно на HEUR: запись полная, повтор целиком, запись парсера режется с конца.
        let mut s = cfg.session(80);
        let mut budget = ByteBudget::new(2);
        for seg in [&b"HT"[..], b"TP/1.0 200"] {
            s.parse(seg, &mut budget, &mut acts);
        }
        assert_eq!(take_seen(), b"HTTP/1.0 200");
        assert_eq!(s.flush(&mut budget), [(42, b"HT".to_vec())]);
        assert_eq!(budget.dropped(), 10);

        // Совпадение в первом сегменте: HEUR пуст, парсер получает поток, его запись режется с конца. При нехватке
        // бюджета итог поэтому зависит от нарезки (README).
        let mut s = cfg.session(80);
        let mut budget = ByteBudget::new(1);
        s.parse(b"HTTP/1.0 200", &mut budget, &mut acts);
        assert_eq!(take_seen(), b"HTTP/1.0 200");
        assert_eq!(s.flush(&mut budget), [(42, b"H".to_vec())]);
    }

    /// I1 ревью задачи 8: общий бюджет 12 байт. A держит 8, B получает 4 из `"0123456789"`, A сбрасывается и
    /// возвращает 8, но B больше не растёт: его запись `"0123"`, начало потока, а не `"0123tail"` из кусков с дырой.
    /// Каждый отказанный байт считается; новая сессия после сброса получает полную запись.
    #[test]
    fn budget_loss_truncates_never_splices() {
        let cfg = BannerConfig::new(&TcpBannerSettings::default());
        let mut budget = ByteBudget::new(12);
        let mut acts = Vec::new();
        let (mut a, mut b) = (cfg.session(9999), cfg.session(9999));
        a.parse(b"abcdefgh", &mut budget, &mut acts);
        b.parse(b"0123456789", &mut budget, &mut acts);
        assert_eq!(budget.dropped(), 6);
        assert_eq!(a.flush(&mut budget), [(app_id::HEUR, b"abcdefgh".to_vec())]);
        b.parse(b"tail", &mut budget, &mut acts);
        assert_eq!(budget.dropped(), 10);
        assert_eq!(budget.left(), 8);
        assert_eq!(b.flush(&mut budget), [(app_id::HEUR, b"0123".to_vec())]);
        assert_eq!(budget.left(), 12);
        let mut c = cfg.session(9999);
        c.parse(b"01234567", &mut budget, &mut acts);
        c.parse(b"tail", &mut budget, &mut acts);
        assert_eq!(
            c.flush(&mut budget),
            [(app_id::HEUR, b"01234567tail".to_vec())]
        );
        assert_eq!(budget.dropped(), 10);
        assert!(acts.is_empty());
    }

    /// Нарезки потока для правил окна: целиком, по байту, на границах окна и около совпадения, 8 случайных.
    fn window_splits(stream: &[u8], seed: u64) -> Vec<Vec<&[u8]>> {
        let mut out = vec![vec![stream], bytewise(stream)];
        for at in [
            CLASSIFY_WINDOW - 1,
            CLASSIFY_WINDOW,
            CLASSIFY_WINDOW + 1,
            stream.len() - 7,
            stream.len() - 6,
        ] {
            if at < stream.len() {
                out.push(vec![&stream[..at], &stream[at..]]);
            }
        }
        let mut rng = Rng(seed);
        for _ in 0..8 {
            let mut cuts: Vec<usize> = (0..1 + rng.below(12))
                .map(|_| rng.below(stream.len() + 1))
                .collect();
            cuts.sort_unstable();
            let mut segs = Vec::new();
            let mut at = 0;
            for c in cuts.into_iter().chain([stream.len()]) {
                segs.push(&stream[at..c]);
                at = c;
            }
            out.push(segs);
        }
        out
    }

    /// M1 ревью задачи 8: окно классификатора это первые 65 536 байт потока (Р5). `{"`, который впервые совпал бы
    /// за окном (70 000 `q` и `{"x":1}`, 70 007 байт), не ищется: поток `unknown`, его первые 65 536 байт, парсер не
    /// запускается, и итог один целиком, по байту и в каждой нарезке (у C предела нет, и он разобрал бы поток как
    /// Minecraft). Совпадение, кончающееся последним байтом окна (смещение 65 535), классифицирует, и парсер получает
    /// весь поток; на байт позже уже нет.
    #[test]
    fn classification_window_is_the_first_65536_bytes() {
        let cfg = BannerConfig::with_parsers(&TcpBannerSettings::default(), recording);
        let mc = b"{\"x\":1}";
        for (lead, classified) in [(70_000usize, false), (65_534, true), (65_535, false)] {
            let stream = [vec![b'q'; lead], mc.to_vec()].concat();
            let seed = 0x5DEE_CE66_D1CE_4E5B ^ u64::try_from(lead).expect("lead");
            for (i, segs) in window_splits(&stream, seed).iter().enumerate() {
                take_seen();
                let (app, recs, acts) = feed(&cfg, 25565, None, segs);
                let at = format!("lead {lead}, split {i} ({} segments)", segs.len());
                assert!(acts.is_empty(), "{at}");
                if classified {
                    assert_eq!(app, Some(app_id::MC), "{at}");
                    assert!(take_seen() == stream, "{at}: parser saw the whole stream");
                    assert!(recs == [(42, stream[..MAX_BANNER_BYTES].to_vec())], "{at}");
                } else {
                    assert_eq!(app, None, "{at}");
                    assert!(take_seen().is_empty(), "{at}: parser ran");
                    let want = [(app_id::HEUR, stream[..MAX_BANNER_BYTES].to_vec())];
                    assert!(recs == want, "{at}: records");
                }
            }
        }
        // Через офлайн-драйвер с заглушками: то же самое целиком и в нарезке случая ревью.
        let stream = [vec![b'q'; 70_000], mc.to_vec()].concat();
        let s = TcpBannerSettings::default();
        let whole = banner_stream(&s, 25565, None, &[&stream]);
        let split = banner_stream(&s, 25565, None, &[&stream[..70_000], &stream[70_000..]]);
        assert_eq!(whole, split);
        assert_eq!(whole.app_proto, None);
    }

    /// Финальное ревью, M1: KEX SSH (1248 байт) встаёт в очередь общим буфером процесса, как у C `TCP__static` на
    /// статический массив (`src/proto-ssh.c:147`), а не копией на каждый 7-байтовый пакет каждого соединения; байты
    /// те же, что прежде (драйвер отдаёт их как посылку).
    #[test]
    fn ssh_kex_blob_is_one_buffer_for_every_session() {
        let cfg = BannerConfig::new(&TcpBannerSettings::default());
        let stream: &[u8] = b"SSH-2.0-x\n\0\0\0\x08\x04\x14abcde\0\0\0\x08\x04\x15abcde";
        let mut blobs = Vec::new();
        for _ in 0..2 {
            let (_, _, acts) = feed(&cfg, 22, None, &[stream]);
            assert_eq!(acts.len(), 3, "{acts:?}");
            assert_eq!(
                acts[0],
                SessionAction::Send(b"SSH-2.0-OPENSSH_7.9\r\n".to_vec())
            );
            for a in &acts[1..] {
                let SessionAction::SendShared(b) = a else {
                    panic!("KEX not shared: {a:?}")
                };
                assert!(Arc::ptr_eq(b, super::super::ssh::kex()));
                assert_eq!(b.len(), 1248);
                blobs.push(Arc::clone(b));
            }
        }
        assert!(blobs.windows(2).all(|w| Arc::ptr_eq(&w[0], &w[1])));
    }

    /// M3, M4 ревью задачи 8: автомат классификатора собран при сборке конфигурации скана (тот же, что один на
    /// процесс), а сессии делят одну неизменяемую часть скана через `Arc`: hello порта это байты таблицы, а не копия в
    /// каждой сессии.
    #[test]
    fn sessions_share_the_scan_config() {
        let cfg = BannerConfig::new(&TcpBannerSettings::default());
        assert!(std::ptr::eq(cfg.scan.classifier, Classifier::banner1()));
        let (a, b) = (cfg.session(80), cfg.forced(80, app_id::HTTP));
        assert!(Arc::ptr_eq(&a.scan, &b.scan));
        assert_eq!(Arc::strong_count(&cfg.scan), 3);
        let table = cfg.scan.hellos.hello(80).map(|h| &h[..]);
        assert!(table.is_some());
        assert!(
            a.hello()
                .zip(table)
                .is_some_and(|(x, y)| std::ptr::eq(x, y))
        );
        assert!(
            b.hello()
                .zip(table)
                .is_some_and(|(x, y)| std::ptr::eq(x, y))
        );
        drop((a, b));
        assert_eq!(Arc::strong_count(&cfg.scan), 1);
    }

    /// Детерминированный xorshift64*, как в `tcb_never_panics`.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).expect("n")).expect("index")
        }
    }

    /// Р1 класс б: случайные потоки (начала шаблонов, их обломки в любом регистре, мусор, длинные хвосты до 70 000
    /// байт), случайные нарезки, порты 25/587/B4, опции hello, принудительный парсер и малый бюджет не роняют сессию.
    /// Записи не длиннее 65 536 байт, номера приложений C, бюджет сходится после сброса; без принуждения и вне
    /// SSL3/SMB записи заглушек это поток целиком (один `unknown`), и результат не зависит от нарезки.
    #[test]
    fn session_never_panics() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let ports = [
            0u16,
            21,
            22,
            23,
            25,
            80,
            139,
            443,
            445,
            587,
            3389,
            5900,
            11211,
            25565,
            u16::MAX,
        ];
        let (mut classified, mut long, mut starved) = (0usize, 0usize, 0usize);
        for round in 0..3000 {
            let mut stream = Vec::new();
            for _ in 0..1 + rng.below(6) {
                match rng.below(5) {
                    0 | 1 => {
                        let p = super::super::classify::PATTERNS[rng.below(60)];
                        let cut = 1 + rng.below(p.bytes.len());
                        let mut part = p.bytes[..cut].to_vec();
                        if rng.below(2) == 0 {
                            part.make_ascii_uppercase();
                        }
                        stream.extend(part);
                    }
                    2 => stream.extend((0..rng.below(40)).map(|_| rng.next().to_le_bytes()[0])),
                    3 => stream.extend_from_slice(b"{\"\xff\xfb\x01\xff\xfd"),
                    _ => {
                        if rng.below(20) == 0 {
                            stream.extend(std::iter::repeat_n(b'q', 66_000 + rng.below(4000)));
                        }
                    }
                }
            }
            let port = ports[rng.below(ports.len())];
            let force = (rng.below(6) == 0).then(|| u16::try_from(rng.below(40)).expect("app"));
            let settings = TcpBannerSettings {
                hello: HelloSet {
                    http: rng.below(2) == 0,
                    ssl: rng.below(3) == 0,
                    smbv1: rng.below(2) == 0,
                },
                ..TcpBannerSettings::default()
            };
            let budget_bytes = if rng.below(4) == 0 {
                rng.below(32)
            } else {
                1 << 24
            };
            let mut cuts: Vec<usize> = (0..rng.below(stream.len().min(30) + 1))
                .map(|_| rng.below(stream.len() + 1))
                .collect();
            cuts.sort_unstable();
            let mut segs: Vec<&[u8]> = Vec::new();
            let mut at = 0;
            for c in cuts.into_iter().chain([stream.len()]) {
                segs.push(&stream[at..c]);
                at = c;
            }
            let cfg = BannerConfig::new(&settings);
            let mut s = match force {
                Some(app) => cfg.forced(port, app),
                None => cfg.session(port),
            };
            let mut budget = ByteBudget::new(budget_bytes);
            let mut acts = Vec::new();
            for seg in &segs {
                s.parse(seg, &mut budget, &mut acts);
            }
            let _ = s.hello();
            let recs = s.flush(&mut budget);
            assert_eq!(budget.left(), budget_bytes, "round {round}: budget");
            let held: usize = recs.iter().map(|r| r.1.len()).sum();
            starved += usize::from(held < stream.len().min(MAX_BANNER_BYTES));
            long += usize::from(stream.len() > MAX_BANNER_BYTES);
            assert!(held <= budget_bytes, "round {round}");
            for (app, b) in &recs {
                assert!(
                    *app != 0 && usize::from(*app) < 37,
                    "round {round}: app {app}"
                );
                assert!(
                    !b.is_empty() && b.len() <= MAX_BANNER_BYTES,
                    "round {round}"
                );
            }
            // Нарезка не меняет записи и номер (Р13); действия сравниваются только целиком (справка E2).
            if budget_bytes == 1 << 24 {
                let whole = banner_stream(&settings, port, force, &[&stream]);
                let r = banner_stream(&settings, port, force, &segs);
                classified += usize::from(force.is_none() && r.app_proto.is_some());
                assert_eq!(r.app_proto, whole.app_proto, "round {round}: split");
                assert_eq!(r.records, whole.records, "round {round}: split");
                assert_eq!(r.records, recs, "round {round}: driver");
                // Не перенесённое (нет совпадения, отвергнутый SSL3, SMB) это поток целиком одной записью unknown.
                if force.is_none() && !stream.is_empty() && matches!(r.app_proto, None | Some(10)) {
                    assert_eq!(
                        r.records,
                        [(
                            app_id::HEUR,
                            stream[..stream.len().min(MAX_BANNER_BYTES)].to_vec()
                        )],
                        "round {round}: unported keeps the stream"
                    );
                    assert!(r.actions.is_empty() && acts.is_empty(), "round {round}");
                }
                assert!(
                    r.actions
                        .iter()
                        .all(|a| matches!(a, StreamAction::Send(_) | StreamAction::Close))
                );
            }
        }
        // Ход теста дошёл до каждого семейства входов.
        assert!(classified > 300, "{classified}");
        assert!(long > 20, "{long}");
        assert!(starved > 300, "{starved}");
    }
}
