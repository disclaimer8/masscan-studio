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
pub(crate) mod hello;
pub(crate) mod session;

use std::fmt;
use std::sync::Arc;

use rmasscan_core::stack::{TableParams, TcpStack, TcpStackFactory};

use crate::tcp::stack::new_stack;

pub use driver::{StreamAction, StreamResult, banner_stream};
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
        assert_eq!(got, [(app_id::HEUR, reply.to_vec())]);

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
}
