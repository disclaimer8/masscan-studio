//! Типы и трейт пользовательского стека TCP (AGPL-3.0, подэтап 4b). Порт границы между приёмным потоком
//! `src/main.c:962-1043` и таблицей соединений `src/stack-tcp-core.c` (`tcpcon_*`), masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0).
//!
//! Движок (`rmasscan-engine`) знает только этот трейт: разбирает кадр в [`SegmentIn`]
//! ([`crate::tcp_frame::tcp_segment`]), отдаёт его таблице и превращает [`SegmentOut`] в кадры
//! ([`crate::tcp_frame::TcpFrameBuilder`]). Реализация (автомат `stack_incoming_tcp` и парсеры баннеров) живёт в
//! `rmasscan-proto`, от которого движок обычной зависимостью не зависит (Р11).

use crate::banner::BannerRecord;

/// Адреса соединения: свой (`ip_me`) и удалённый (`ip_them`), одного семейства (`struct TCP_Control_Block`,
/// `src/stack-tcp-core.c:109-166`). `u128` IPv6 в порядке "старший байт первый", как `ipv6address {hi, lo}` в C.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnAddrs {
    V4 { local: u32, remote: u32 },
    V6 { local: u128, remote: u128 },
}

/// Ключ соединения: 4-кортеж `tcpcon_lookup_tcb` (`src/stack-tcp-core.c:1067`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub addrs: ConnAddrs,
    pub local_port: u16,
    pub remote_port: u16,
}

/// Входящий сегмент TCP, адресованный нам (`src/main.c:799-815`: `seqno_them = TCP_SEQNO`, `seqno_me =
/// TCP_ACKNO`). `ttl` это TTL IPv4 или hop limit IPv6: C для IPv6 его не заполняет (`src/proto-preprocess.c:127`,
/// справка E1.9), rmasscan берёт настоящий (Р2). `payload` кончается с IP-пакетом, без набивки Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentIn<'a> {
    pub key: ConnKey,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub ttl: u8,
    pub payload: &'a [u8],
}

/// Исходящий сегмент: аргументы `tcp_create_packet` (`src/templ-pkt.c:419-613`), которые кадр берёт не из шаблона.
/// `window: None` это 1200 шаблона стека (`:497-498`); `Some(600)` только для heartbleed в 4c (`tcp_set_window`,
/// `src/stack-tcp-core.c:1163-1164`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentOut {
    pub key: ConnKey,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub window: Option<u16>,
}

/// Что стек выдал за один вызов: сегменты в порядке отправки и баннеры по соединениям. Один внутренний `Vec` это
/// записи одного сброса (`banner_flush`, `src/stack-tcp-core.c:800`) в порядке C.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StackOutput {
    pub segments: Vec<SegmentOut>,
    pub banners: Vec<Vec<BannerRecord>>,
}

/// Счётчики таблицы: создано соединений, живых сейчас, отказов из-за полной таблицы, байтов баннеров, не
/// вместившихся в бюджет.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackStats {
    pub tcbs_created: u64,
    pub tcbs_live: u64,
    pub table_full: u64,
    pub banner_bytes_dropped: u64,
    /// Реконнекты, которым не нашлось другого порта/адреса источника (`ERRMSG` у C печатается один раз,
    /// `src/stack-tcp-core.c:1669`, справка 4c §D1).
    pub reconnect_no_port: u64,
}

/// Диапазоны источника таблицы для реконнекта (`stack->src`, `src/stack-src.h:9-28`): порты и адреса,
/// границы включительно, как `is_my_port`/`is_my_ip`. `(0, 0)`/`None` — диапазон не задан: только адрес и
/// порт самого соединения.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceRanges {
    pub ports: (u16, u16),
    pub ipv4: Option<(u32, u32)>,
    pub ipv6: Option<(u128, u128)>,
}

/// Параметры новой таблицы: `seed` скана, предел живых соединений и бюджет байтов баннеров. В C предела нет
/// (`tcpcon_create_table`, `src/stack-tcp-core.c:673-697`: размер только подсказка числа корзин).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableParams {
    pub seed: u64,
    pub capacity: usize,
    pub banner_byte_budget: usize,
    /// Диапазоны источника для второго соединения на TLS-порт (Р10); по умолчанию не заданы.
    pub source: SourceRanges,
}

/// Таблица соединений одного приёмного потока.
///
/// Контракт: сегмент с битами SYN и ACK движок отдаёт, только если проверил его cookie (`src/main.c:970-980`).
/// [`TcpStack::on_segment`] возвращает `true`, если сегмент взяло соединение (живое или новое) или он дал RST на
/// FIN без соединения (`src/main.c:1019-1041`). [`TcpStack::finish`] уничтожает до `max_connections` живых
/// соединений без кадров и отдаёт их баннеры (`tcpcon_destroy_table`, `src/stack-tcp-core.c:933-961`); `true`
/// значит, что живые соединения остались.
pub trait TcpStack: Send {
    /// Таймеры (`tcpcon_timeouts`, `src/main.c:777-797`).
    fn on_tick(&mut self, now_micros: u64, out: &mut StackOutput);
    /// Один входящий сегмент.
    fn on_segment(&mut self, now_micros: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool;
    /// Конец скана порциями.
    fn finish(&mut self, max_connections: usize, out: &mut StackOutput) -> bool;
    fn stats(&self) -> StackStats;
}

/// Создаёт таблицу на приёмный поток; движок держит фабрику, реализация живёт вне ядра.
pub trait TcpStackFactory: Send + Sync + std::fmt::Debug {
    fn new_table(&self, p: TableParams) -> Box<dyn TcpStack>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Таблица, которая берёт каждый сегмент и отвечает на него RST: проверка, что трейт пригоден как объект.
    #[derive(Default)]
    struct Echo {
        stats: StackStats,
    }

    impl TcpStack for Echo {
        fn on_tick(&mut self, _now_micros: u64, _out: &mut StackOutput) {}
        fn on_segment(&mut self, _now: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
            self.stats.tcbs_created += 1;
            out.segments.push(SegmentOut {
                key: seg.key,
                seq: seg.ack,
                ack: 0,
                flags: 0x04,
                payload: Vec::new(),
                window: None,
            });
            true
        }
        fn finish(&mut self, _max: usize, _out: &mut StackOutput) -> bool {
            false
        }
        fn stats(&self) -> StackStats {
            self.stats
        }
    }

    #[derive(Debug)]
    struct EchoFactory;

    impl TcpStackFactory for EchoFactory {
        fn new_table(&self, _p: TableParams) -> Box<dyn TcpStack> {
            Box::new(Echo::default())
        }
    }

    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn trait_objects_cross_threads_and_keys_hash() {
        assert_send::<Box<dyn TcpStack>>();
        assert_send_sync::<std::sync::Arc<dyn TcpStackFactory>>();
        let f: std::sync::Arc<dyn TcpStackFactory> = std::sync::Arc::new(EchoFactory);
        let mut t = f.new_table(TableParams {
            seed: 1,
            capacity: 4,
            banner_byte_budget: 0,
            source: SourceRanges::default(),
        });
        let key = ConnKey {
            addrs: ConnAddrs::V4 {
                local: 0x0a00_0001,
                remote: 0x0a00_0002,
            },
            local_port: 40000,
            remote_port: 80,
        };
        let seg = SegmentIn {
            key,
            seq: 7,
            ack: 9,
            flags: 0x11,
            ttl: 64,
            payload: b"",
        };
        let mut out = StackOutput::default();
        assert!(t.on_segment(0, &seg, &mut out));
        assert_eq!(out.segments.len(), 1);
        assert_eq!(out.segments[0].seq, 9);
        assert!(!t.finish(usize::MAX, &mut out));
        assert_eq!(t.stats().tcbs_created, 1);

        // V4 и V6 с одинаковыми числами это разные ключи.
        let v6 = ConnKey {
            addrs: ConnAddrs::V6 {
                local: 0x0a00_0001,
                remote: 0x0a00_0002,
            },
            ..key
        };
        let mut m = HashMap::new();
        m.insert(key, 1);
        m.insert(v6, 2);
        assert_eq!((m[&key], m[&v6]), (1, 2));
    }
}
