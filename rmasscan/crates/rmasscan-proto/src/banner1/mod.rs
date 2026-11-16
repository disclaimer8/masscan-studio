//! Каркас баннеров TCP (подэтап 4b): порт `src/proto-banner1.c` (`banner1_parse`, `banner1_create`),
//! `src/proto-banout.c` и `src/smack1.c` masscan © Robert David Graham (github.com/robertdavidgraham/masscan, HEAD
//! 8e6b3b0), AGPL-3.0; справка `2026-11-13-rmasscan-banners-c-reference-tcp.md`, B1-B6, C2, C3, E2.
//!
//! [`classify`] это таблица шаблонов и автомат smack, [`banout`] буферы баннеров соединения, [`hello`] hello по
//! порту, [`session`] сессия соединения (классификатор, повтор HEUR, парсер приложения) и конфигурация скана, которая
//! раздаёт сессии таблице соединений ([`crate::tcp`]); [`driver`] офлайн-драйвер одной сессии.

pub(crate) mod banout;
pub(crate) mod classify;
mod driver;
mod ftp;
pub(crate) mod hello;
mod http;
mod imap4;
mod memcached;
mod minecraft;
mod pop3;
mod rdp;
pub(crate) mod session;
mod smtp;
mod ssh;
mod telnet;
pub(crate) mod tls;
pub(crate) mod tls_hello;
mod vnc;
pub(crate) mod x509;

use std::fmt;
use std::sync::Arc;

use rmasscan_core::stack::{TableParams, TcpStack, TcpStackFactory};

use crate::tcp::stack::new_stack;

pub use driver::{StreamAction, StreamResult, banner_stream, tls_stream, x509_stream};
pub use hello::{HelloSet, TcpBannerSettings};

use session::BannerConfig;

/// Фабрика таблиц соединений с баннерами: одна конфигурация скана на все приёмные потоки.
struct BannerStackFactory {
    cfg: Arc<BannerConfig>,
    connection_timeout_secs: u32,
}

impl fmt::Debug for BannerStackFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BannerStackFactory")
            .field("connection_timeout_secs", &self.connection_timeout_secs)
            .finish_non_exhaustive()
    }
}

impl TcpStackFactory for BannerStackFactory {
    fn new_table(&self, p: TableParams) -> Box<dyn TcpStack> {
        Box::new(new_stack(
            Arc::clone(&self.cfg) as Arc<dyn crate::tcp::app::Sessions>,
            self.connection_timeout_secs,
            p,
        ))
    }
}

/// Стек TCP с баннерами для движка: опции скана и `--connection-timeout` (0 это 30 с, как у C).
pub fn tcp_stack_factory(
    s: TcpBannerSettings,
    connection_timeout_secs: u32,
) -> Arc<dyn TcpStackFactory> {
    Arc::new(BannerStackFactory {
        cfg: Arc::new(BannerConfig::new(&s)),
        connection_timeout_secs,
    })
}

/// Детерминированный xorshift64* тестов парсеров (как `tcb_never_panics`).
#[cfg(test)]
pub(crate) struct TestRng(pub(crate) u64);

#[cfg(test)]
impl TestRng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub(crate) fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n.max(1)).expect("n")).expect("index")
    }
}

/// Нарезки потока для тестов парсеров: по байту и 8 случайных (seed), каждая со своим именем.
#[cfg(test)]
pub(crate) fn test_splits(stream: &[u8], seed: u64) -> Vec<(String, Vec<&[u8]>)> {
    let mut out = vec![("bytewise".to_owned(), stream.chunks(1).collect())];
    let mut rng = TestRng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    for k in 0..8 {
        let mut cuts: Vec<usize> = (0..1 + rng.below(stream.len().min(24)))
            .map(|_| rng.below(stream.len() + 1))
            .collect();
        cuts.sort_unstable();
        let mut segs = Vec::new();
        let mut at = 0;
        for c in cuts.into_iter().chain([stream.len()]) {
            segs.push(&stream[at..c]);
            at = c;
        }
        out.push((format!("random-{k}"), segs));
    }
    out
}

/// Поток через офлайн-драйвер с настройками по умолчанию целиком и в [`test_splits`]: записи, номер C и действия
/// каждой нарезки равны целому (Р13; у текстовых парсеров и действия не зависят от нарезки). Итог целого.
#[cfg(test)]
pub(crate) fn stream_in_splits(
    port: u16,
    force: Option<u16>,
    stream: &[u8],
    seed: u64,
) -> StreamResult {
    let s = TcpBannerSettings::default();
    let whole = banner_stream(&s, port, force, &[stream]);
    for (name, segs) in test_splits(stream, seed) {
        let r = banner_stream(&s, port, force, &segs);
        assert_eq!(r, whole, "{name}: {stream:?}");
    }
    whole
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::app_id;
    use rmasscan_core::banner::MAX_BANNER_BYTES;
    use rmasscan_core::stack::{ConnAddrs, ConnKey, SegmentIn, StackOutput};

    const T0: u64 = 1_700_000_000_000_000;
    const SEC: u64 = 1_000_000;
    /// ACK их SYN-ACK (наш ISN + 1) и их ISN.
    const S: u32 = 0x1000_0000;
    const R0: u32 = 0x2000_0000;
    const PSHACK: u8 = 0x18;
    const FINACK: u8 = 0x11;
    const SYNACK: u8 = 0x12;

    fn key(n: u8, port: u16) -> ConnKey {
        ConnKey {
            addrs: ConnAddrs::V4 {
                local: 0x0a00_0001,
                remote: 0x0a00_0100 | u32::from(n),
            },
            local_port: 40000,
            remote_port: port,
        }
    }

    fn seg(key: ConnKey, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> SegmentIn<'_> {
        SegmentIn {
            key,
            seq,
            ack,
            flags,
            ttl: 64,
            payload,
        }
    }

    fn table(budget: usize) -> Box<dyn TcpStack> {
        tcp_stack_factory(TcpBannerSettings::default(), 30).new_table(TableParams {
            seed: 0x1122_3344_5566_7788,
            capacity: 16,
            banner_byte_budget: budget,
        })
    }

    /// SYN-ACK и `total` байт бесконечного потока сервера (без шаблона) сегментами по 1400; номер следующего байта.
    fn endless(st: &mut dyn TcpStack, k: ConnKey, total: usize) -> u32 {
        let mut out = StackOutput::default();
        assert!(st.on_segment(T0, &seg(k, SYNACK, R0, S, b""), &mut out));
        let chunk = vec![b'z'; 1400];
        let mut seq = R0.wrapping_add(1);
        let mut sent = 0usize;
        while sent < total {
            let n = 1400.min(total - sent);
            let mut out = StackOutput::default();
            assert!(st.on_segment(T0 + SEC / 2, &seg(k, PSHACK, seq, S, &chunk[..n]), &mut out));
            assert!(out.banners.is_empty());
            seq = seq.wrapping_add(u32::try_from(n).expect("n"));
            sent += n;
        }
        seq
    }

    /// FIN сервера: сброс баннеров соединения.
    fn fin(st: &mut dyn TcpStack, k: ConnKey, seq: u32, ack: u32) -> Vec<(u16, Vec<u8>)> {
        let mut out = StackOutput::default();
        st.on_segment(T0 + SEC, &seg(k, FINACK, seq, ack, b""), &mut out);
        out.banners
            .into_iter()
            .flatten()
            .map(|r| (r.app, r.payload))
            .collect()
    }

    /// Review Focus 4 (телнет-болтун, SSH-тарпит): бесконечный поток сервера через настоящие сессии баннеров. Запись
    /// обрезается на 65 536 байтах (Р5), и байты за пределом в бюджет не идут и выброшенными не считаются; бюджет
    /// таблицы делится между живыми соединениями, недостача считается в `banner_bytes_dropped`, сброс возвращает
    /// байты, и следующее соединение снова получает полную запись.
    #[test]
    fn endless_stream_caps_record_and_budget() {
        let mut st = table(1 << 20);
        let a = key(1, 7000);
        let end = endless(st.as_mut(), a, 2_000_000);
        assert_eq!(
            fin(st.as_mut(), a, end, S),
            [(app_id::HEUR, vec![b'z'; MAX_BANNER_BYTES])]
        );
        assert_eq!(st.stats().banner_bytes_dropped, 0);

        let mut st = table(100_000);
        let (a, b, c) = (key(1, 7000), key(2, 7000), key(3, 7000));
        let end_a = endless(st.as_mut(), a, 200_000);
        let end_b = endless(st.as_mut(), b, 200_000);
        assert_eq!(
            st.stats().banner_bytes_dropped,
            (2 * MAX_BANNER_BYTES - 100_000) as u64
        );
        assert_eq!(
            fin(st.as_mut(), a, end_a, S),
            [(app_id::HEUR, vec![b'z'; MAX_BANNER_BYTES])]
        );
        assert_eq!(
            fin(st.as_mut(), b, end_b, S),
            [(app_id::HEUR, vec![b'z'; 100_000 - MAX_BANNER_BYTES])]
        );
        let end_c = endless(st.as_mut(), c, 70_000);
        assert_eq!(
            fin(st.as_mut(), c, end_c, S),
            [(app_id::HEUR, vec![b'z'; MAX_BANNER_BYTES])]
        );
        assert_eq!(
            st.stats().banner_bytes_dropped,
            (2 * MAX_BANNER_BYTES - 100_000) as u64
        );
        assert_eq!(st.stats().tcbs_created, 3);
    }

    /// Фабрика строит таблицу с сессиями баннеров: hello порта через 2 с (запрос HTTP C на 80), ответ сервера после
    /// подтверждения разбирается и сбрасывается на FIN; поток NULL (порт 443 в 4b) hello не шлёт.
    #[test]
    fn factory_sends_port_hello_and_flushes_the_reply() {
        let mut st = table(1 << 20);
        let k = key(1, 80);
        let mut out = StackOutput::default();
        st.on_segment(T0, &seg(k, SYNACK, R0, S, b""), &mut out);
        let mut out = StackOutput::default();
        st.on_tick(T0 + 2 * SEC, &mut out);
        assert_eq!(out.segments.len(), 1);
        assert_eq!(out.segments[0].payload, hello::HTTP_DEFAULT_REQUEST);
        let reply = b"HTTP/1.0 200 OK\r\n\r\n";
        let mut out = StackOutput::default();
        st.on_segment(
            T0 + 3 * SEC,
            &seg(k, PSHACK, R0 + 1, S + 99, reply),
            &mut out,
        );
        let got = fin(
            st.as_mut(),
            k,
            R0 + 1 + u32::try_from(reply.len()).expect("len"),
            S + 99,
        );
        assert_eq!(got, [(app_id::HTTP, b"HTTP/1.0 200 OK\r\n\r".to_vec())]);

        let k = key(2, 443);
        let mut out = StackOutput::default();
        st.on_segment(T0, &seg(k, SYNACK, R0, S, b""), &mut out);
        for t in 1..=10 {
            let mut out = StackOutput::default();
            st.on_tick(T0 + 2 * t * SEC, &mut out);
            assert!(
                out.segments
                    .iter()
                    .all(|s| s.payload.is_empty() && s.flags != PSHACK),
                "tick {t}"
            );
        }
    }

    /// Настоящий парсер за фабрикой: приветствие FTP на 21 получает в ответ `AUTH TLS` на проводе (действие парсера
    /// уходит сегментом с данными, `src/proto-ftp.c:73`), а записи ждут сброса.
    #[test]
    fn ftp_greeting_gets_auth_tls_on_the_wire() {
        let mut st = table(1 << 20);
        let k = key(1, 21);
        let mut out = StackOutput::default();
        st.on_segment(T0, &seg(k, SYNACK, R0, S, b""), &mut out);
        let greeting = b"220 lab FTP server ready\r\n";
        let mut out = StackOutput::default();
        st.on_segment(T0 + SEC / 2, &seg(k, PSHACK, R0 + 1, S, greeting), &mut out);
        assert!(
            out.segments
                .iter()
                .any(|s| s.flags == PSHACK && s.payload == b"AUTH TLS\r\n"),
            "{:?}",
            out.segments
        );
        assert!(out.banners.is_empty());
    }

    /// Согласие на STARTTLS (FTP 234, SMTP 220, POP3 `+OK`, справка B6): номер C SSL3 (9), как у C, hello TLS не
    /// шлётся, запись парсера кончается строкой согласия (у FTP и SMTP без LF, у POP3 с LF), а каждый байт после неё в
    /// одной записи `unknown`, в том же сегменте или в следующем, в любой нарезке. Байты, которые C в том же сегменте
    /// разобрал бы как новое приветствие со вторым `AUTH TLS` (`src/proto-ftp.c:101`), здесь тоже `unknown`.
    #[test]
    fn starttls_success_switches_to_unported_tls() {
        let tail: &[u8] = b"\x16\x03\x01\x00\x02\x02\x28220 again\r\n";
        for (port, dialogue, app, rec, cmds) in [
            (
                21u16,
                &b"220 lab FTP server ready\r\n234 AUTH TLS successful\r\n"[..],
                app_id::FTP,
                &b"220 lab FTP server ready\n234 AUTH TLS successful"[..],
                &[&b"AUTH TLS\r\n"[..]][..],
            ),
            (
                25,
                b"220-mail.example.test\r\n220 ok\r\n234-go\r\n",
                app_id::FTP,
                b"220-mail.example.test\n220 ok\n234-go",
                &[b"AUTH TLS\r\n"],
            ),
            (
                25,
                b"220 mail.example.test ESMTP\r\n250 STARTTLS\r\n220 2.0.0 Ready\r\n",
                app_id::SMTP,
                b"220 mail.example.test ESMTP\n250 STARTTLS\n220 2.0.0 Ready",
                &[b"EHLO masscan\r\n", b"STARTTLS\r\n"],
            ),
            (
                587,
                b"220 x\r\n250 ok\r\n220-go\r\n",
                app_id::SMTP,
                b"220 x\n250 ok\n220-go",
                &[b"EHLO masscan\r\n", b"STARTTLS\r\n"],
            ),
            (
                110,
                b"+OK lab ready\r\n+OK\r\nSTLS\r\n.\r\n+OK Begin TLS\r\n",
                app_id::POP3,
                b"+OK lab ready\n+OK\nSTLS\n.\n+OK Begin TLS\n",
                &[b"CAPA\r\n", b"STLS\r\n"],
            ),
        ] {
            let want_acts: Vec<StreamAction> = cmds
                .iter()
                .map(|c| StreamAction::Send(c.to_vec()))
                .collect();
            // Только строка согласия: запись парсера, номер 9, без hello TLS.
            let r = stream_in_splits(port, None, dialogue, u64::from(port));
            assert_eq!(r.app_proto, Some(app_id::SSL3), "{dialogue:?}");
            assert_eq!(r.records, [(app, rec.to_vec())], "{dialogue:?}");
            assert_eq!(r.actions, want_acts, "{dialogue:?}");
            // С хвостом: целиком, по байту, случайно и ровно по строке согласия хвост это одна запись unknown.
            let stream = [dialogue, tail].concat();
            let r = stream_in_splits(port, None, &stream, u64::from(port) + 1);
            let at = banner_stream(&TcpBannerSettings::default(), port, None, &[dialogue, tail]);
            assert_eq!(r, at, "{dialogue:?}: split at the go-ahead");
            assert_eq!(r.app_proto, Some(app_id::SSL3));
            assert_eq!(
                r.records,
                [(app, rec.to_vec()), (app_id::HEUR, tail.to_vec())],
                "{dialogue:?}"
            );
            assert_eq!(
                r.actions, want_acts,
                "{dialogue:?}: no TLS hello, no second command"
            );
        }

        // Запись парсера от 200 байт: хвост `unknown` идёт ПЕРЕД ней (порядок списка banout у C, справка B3: голова
        // списка переезжает, когда запись дорастает до 200 байт). От нарезки порядок не зависит.
        let long_greeting = [&b"220-"[..], &[b'x'; 300], b"\r\n220 ok\r\n234 go\r\n"].concat();
        let want_rec = [&b"220-"[..], &[b'x'; 300], b"\n220 ok\n234 go"].concat();
        let stream = [&long_greeting[..], b"TAILTAIL"].concat();
        let whole = stream_in_splits(21, None, &stream, 21);
        let at_go_ahead = banner_stream(
            &TcpBannerSettings::default(),
            21,
            None,
            &[&long_greeting[..], b"TAILTAIL"],
        );
        assert_eq!(whole, at_go_ahead);
        assert_eq!(whole.app_proto, Some(app_id::SSL3));
        assert_eq!(
            whole.records,
            [
                (app_id::HEUR, b"TAILTAIL".to_vec()),
                (app_id::FTP, want_rec)
            ]
        );
    }

    /// Р1 класс б: случайные потоки из обломков диалогов FTP, SMTP, POP3, IMAP4 (коды, разделители, CR, LF, TAB, NUL,
    /// 0x7F, 0x80, точки, звёзды, целые диалоги со STARTTLS), мусора и изредка 66 000 байт текста, на портах 21, 25,
    /// 587, 110, 143, 2525 и других, с классификатором и с принуждением каждого из четырёх парсеров, в случайных
    /// нарезках: ни паники, записи не длиннее 65 536 байт и не пустые, записи только этих приложений, действия только
    /// их команды и закрытие, hello TLS нет, записи, номер и действия не зависят от нарезки.
    #[test]
    fn text_parsers_never_panic() {
        const FRAGS: &[&[u8]] = &[
            b"220 ",
            b"220-",
            b"234 ",
            b"234-",
            b"530 ",
            b"250-",
            b"250 ",
            b"521 ",
            b"454 ",
            b"+OK",
            b"+OK ",
            b"-ERR",
            b".",
            b".\r\n",
            b"* OK ",
            b"* ok ",
            b"*",
            b" ",
            b"O",
            b"K",
            b"+",
            b"-",
            b"\r",
            b"\n",
            b"\r\n",
            b"\t",
            b"\x00",
            b"\x7f",
            b"\x80",
            b"\xff",
            b"ready",
            b"x",
            b"220 ok\r\n",
            b"250 ok\r\n",
            b"530 no\r\n",
            b"+OK\r\n",
            b"-ERR\r\n",
            b"* OK x\r\n",
            b"220 a\r\n234 b\r\n",
            b"220 a\r\n250 b\r\n220 c\r\n",
            b"+OK a\r\n+OK\r\n.\r\n+OK b\r\n",
        ];
        let commands: [&[u8]; 5] = [
            b"AUTH TLS\r\n",
            b"EHLO masscan\r\n",
            b"STARTTLS\r\n",
            b"CAPA\r\n",
            b"STLS\r\n",
        ];
        let ports = [21u16, 25, 587, 110, 143, 2525, 9999];
        let forced = [
            None,
            None,
            None,
            Some(app_id::FTP),
            Some(app_id::SMTP),
            Some(app_id::POP3),
            Some(app_id::IMAP4),
        ];
        let s = TcpBannerSettings::default();
        let mut rng = TestRng(0xC0FF_EE00_D15E_A5E5);
        let (mut handoffs, mut sends, mut closes, mut long) = (0usize, 0usize, 0usize, 0usize);
        for round in 0..10_000 {
            let mut stream = Vec::new();
            for _ in 0..1 + rng.below(12) {
                match rng.below(20) {
                    0..=13 => stream.extend_from_slice(FRAGS[rng.below(FRAGS.len())]),
                    14..=17 => {
                        stream.extend((0..rng.below(9)).map(|_| rng.next().to_le_bytes()[0]))
                    }
                    18 => {
                        stream.extend((0..1 + rng.below(4)).map(|_| b'0' + (rng.next() % 10) as u8))
                    }
                    _ => {
                        if rng.below(10) == 0 {
                            long += 1;
                            stream.extend(b"lab ".iter().copied().cycle().take(66_000));
                        }
                    }
                }
            }
            let port = ports[rng.below(ports.len())];
            let force = forced[rng.below(forced.len())];
            let whole = banner_stream(&s, port, force, &[&stream]);
            for k in 0..2 {
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
                let r = banner_stream(&s, port, force, &segs);
                assert_eq!(r, whole, "round {round} split {k}: port {port} {force:?}");
            }
            handoffs += usize::from(whole.app_proto == Some(app_id::SSL3));
            for (app, b) in &whole.records {
                assert!(
                    [
                        app_id::HEUR,
                        app_id::FTP,
                        app_id::SMTP,
                        app_id::POP3,
                        app_id::IMAP4
                    ]
                    .contains(app),
                    "round {round}: app {app}"
                );
                assert!(
                    !b.is_empty() && b.len() <= MAX_BANNER_BYTES,
                    "round {round}"
                );
            }
            for a in &whole.actions {
                match a {
                    StreamAction::Send(b) => {
                        sends += 1;
                        assert!(commands.contains(&b.as_slice()), "round {round}: {b:?}");
                    }
                    StreamAction::Close => closes += 1,
                }
            }
        }
        // Ход теста дошёл до передач, команд, закрытий и длинных строк.
        assert!(handoffs > 150, "{handoffs}");
        assert!(sends > 800, "{sends}");
        assert!(closes > 3000, "{closes}");
        assert!(long > 100, "{long}");
    }
}

#[cfg(test)]
mod memcached_mc_tests;
#[cfg(test)]
mod terminal_tests;
