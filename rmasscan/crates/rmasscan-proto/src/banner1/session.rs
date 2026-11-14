//! Сессия баннера одного соединения: `banner1_parse` (`src/proto-banner1.c:113-325`, справка B1) над `tcb->banout`
//! и `tcb->banner1_state`, и неизменяемая конфигурация скана, которая выдаёт сессии таблице ([`BannerConfig`]
//! вместо глобальных `banner1` и `payloads.tcp[]` C).
//!
//! Правила неразрезанного потока (Р13, справка E2): байты до совпадения лежат в записи HEUR; на совпадении запись
//! вынимается (E1.3), и парсер получает их, а затем весь текущий сегмент, так что он видит поток с первого байта, а
//! записи `unknown` из байтов до совпадения нет (E2.1; у C по сегментам она остаётся). Первое совпадение решает:
//! отвергнутый SSL3 (hello TLS не слан, B1.2) делает остаток потока `unknown` (E2.2; у C следующий сегмент ещё может
//! совпасть с `{"` или IAC).

use std::sync::Arc;

use crate::app::app_id;
use crate::tcp::app::{ByteBudget, Session, SessionAction, Sessions};

use super::banout::Banout;
use super::classify::{Classifier, PATTERNS};
use super::hello::{HelloTable, TcpBannerSettings};

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
}

/// Что видит парсер: буферы баннеров и бюджет таблицы, действия (`tcpapi_send` и `tcpapi_close` по порядку), порт
/// сервера (`tcb_state->port`), `--capture html`. `starttls` парсер ставит при передаче STARTTLS (у C
/// `app_proto = PROTO_SSL3`, `src/proto-ftp.c:93-104`, `src/proto-smtp.c:139-150`, `src/proto-pop3.c:122-133`): со
/// следующего сегмента поток идёт в `unknown`; остаток своего сегмента парсер решает сам.
pub(crate) struct ParseCx<'a> {
    pub(crate) banout: &'a mut Banout,
    pub(crate) budget: &'a mut ByteBudget,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "шлют и закрывают парсеры задач 9-12")
    )]
    pub(crate) acts: &'a mut Vec<SessionAction>,
    #[expect(dead_code, reason = "порт читают парсеры задач 9-12 (SMTP, FTP)")]
    pub(crate) port: u16,
    #[expect(dead_code, reason = "`--capture html` читает парсер HTTP, задачи 9-12")]
    pub(crate) capture_html: bool,
    pub(crate) starttls: bool,
}

impl ParseCx<'_> {
    /// `banout_append(banout, app, px, length)`.
    pub(crate) fn append(&mut self, app: u16, px: &[u8]) {
        self.banout.append(self.budget, app, px);
    }
}

/// Заглушка ещё не перенесённого протокола.
struct Unported;

impl Parser for Unported {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        cx.append(app_id::HEUR, px);
    }
}

/// Парсер приложения. Задачи 9-12 заменяют свою строку.
pub(crate) fn parser_for(p: AppProto) -> Box<dyn Parser> {
    match p {
        AppProto::Ftp
        | AppProto::Smtp
        | AppProto::Pop3
        | AppProto::Imap4
        | AppProto::Ssh
        | AppProto::Http
        | AppProto::Vnc(_)
        | AppProto::Memcached
        | AppProto::Telnet
        | AppProto::Rdp
        | AppProto::Minecraft
        | AppProto::Unported => Box::new(Unported),
    }
}

/// Неизменяемая конфигурация скана: hello по порту, запрос HTTP, `--capture html` и выбор парсера.
#[derive(Debug)]
pub(crate) struct BannerConfig {
    hellos: HelloTable,
    capture_html: bool,
    parsers: fn(AppProto) -> Box<dyn Parser>,
}

impl BannerConfig {
    pub(crate) fn new(s: &TcpBannerSettings) -> BannerConfig {
        BannerConfig {
            hellos: HelloTable::new(s),
            capture_html: s.capture_html,
            parsers: parser_for,
        }
    }

    /// Новая сессия порта `port` (`tcpcon_create_tcb`, `src/stack-tcp-core.c:1043-1049`).
    pub(crate) fn session(&self, port: u16) -> Banner1Session {
        Banner1Session {
            hello: self.hellos.hello(port).cloned(),
            port,
            capture_html: self.capture_html,
            parsers: self.parsers,
            app_proto: None,
            stage: Stage::Classify(0),
            banout: Banout::default(),
        }
    }

    /// Сессия, которая сразу разбирает поток парсером приложения `app` (номер C) без классификатора; у VNC версия 0,
    /// как у обнулённого `tcb_state` без шаблона.
    pub(crate) fn forced(&self, port: u16, app: u16) -> Banner1Session {
        let mut s = self.session(port);
        s.app_proto = Some(app);
        s.stage = Stage::Parse((self.parsers)(app_proto_for(app, 0)));
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

/// Где поток: классификатор (состояние smack), отвергнутый SSL3 или парсер приложения.
enum Stage {
    Classify(u32),
    Rejected,
    Parse(Box<dyn Parser>),
}

/// Сессия баннера одного соединения (`tcb->stream`, `tcb->banner1_state`, `tcb->banout`).
pub(crate) struct Banner1Session {
    hello: Option<Arc<[u8]>>,
    port: u16,
    capture_html: bool,
    parsers: fn(AppProto) -> Box<dyn Parser>,
    /// `tcb_state->app_proto`; `None` это PROTO_NONE.
    app_proto: Option<u16>,
    stage: Stage,
    banout: Banout,
}

/// `is_sent_sslhello` (`src/proto-banner1.h:249`): его ставит только отправка TLS hello (`banner_set_sslhello`,
/// `src/stack-tcp-app.c:157-163`), а его в 4b нет, поэтому совпадение SSL3 всегда отвергается (справка B1.2, B6).
const SSL_HELLO_SENT: bool = false;

impl Banner1Session {
    pub(crate) fn app_proto(&self) -> Option<u16> {
        self.app_proto
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
            port: self.port,
            capture_html: self.capture_html,
            starttls: false,
        };
        parser.parse(&mut cx, px);
        if cx.starttls {
            self.app_proto = Some(app_id::SSL3);
            *parser = Box::new(Unported);
        }
    }

    /// Совпадение шаблона `id` (`src/proto-banner1.c:136-182`): поправки порта и версии, номер C, парсер; запись
    /// HEUR вынимается и повторяется в парсер, затем весь текущий сегмент.
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
        let mut parser = (self.parsers)(app_proto_for(app, pat.extra));
        let held = self.banout.take(budget, app_id::HEUR);
        if !held.is_empty() {
            self.run(&mut parser, budget, acts, &held);
        }
        self.run(&mut parser, budget, acts, px);
        self.stage = Stage::Parse(parser);
    }
}

impl Session for Banner1Session {
    fn hello(&self) -> Option<&[u8]> {
        self.hello.as_deref()
    }

    /// `banner1_parse` одного сегмента. Пустой сегмент это отсутствие данных (у C `banner1_parse` пустым не зовут:
    /// `APP_RECV_PAYLOAD` несёт нагрузку).
    fn parse(&mut self, px: &[u8], budget: &mut ByteBudget, acts: &mut Vec<SessionAction>) {
        if px.is_empty() {
            return;
        }
        match std::mem::replace(&mut self.stage, Stage::Rejected) {
            // `:126-184`: один `smack_search_next` на сегмент, состояние smack между сегментами.
            Stage::Classify(mut state) => match Classifier::banner1().search(&mut state, px) {
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
                    self.stage = Stage::Classify(state);
                    self.banout.append(budget, app_id::HEUR, px);
                }
            },
            Stage::Rejected => self.banout.append(budget, app_id::HEUR, px),
            Stage::Parse(mut parser) => {
                self.run(&mut parser, budget, acts, px);
                self.stage = Stage::Parse(parser);
            }
        }
    }

    fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)> {
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
        let mut cfg = BannerConfig::new(&TcpBannerSettings::default());
        cfg.parsers = tagging;
        cfg
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
        // Через офлайн-драйвер (заглушки задачи 8): всё в unknown, номер заданный.
        let r = banner_stream(
            &TcpBannerSettings::default(),
            80,
            Some(app_id::SSH2),
            &[b"HTTP/1.0 200\r\n"],
        );
        assert_eq!(r.app_proto, Some(app_id::SSH2));
        assert_eq!(r.records, [(app_id::HEUR, b"HTTP/1.0 200\r\n".to_vec())]);
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
