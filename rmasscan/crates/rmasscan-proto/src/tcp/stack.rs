//! Стек TCP баннеров для движка: [`TcpBannerStack`] это трейт `TcpStack` ядра над таблицей соединений
//! ([`super::table`]), слоем приложения ([`super::app`]) и фильтром RST ([`super::rstfilter`]). Разбор одного
//! сегмента повторяет стековый блок приёмного потока C (`src/main.c:962-1043`, справка A2).

use std::sync::Arc;

use rmasscan_core::stack::{
    ConnKey, SegmentIn, SegmentOut, StackOutput, StackStats, TableParams, TcpStack,
};

use super::app::Sessions;
use super::rstfilter::RstFilter;
use super::table::{Conn, Table};
use super::tcb::{TcbResult, What};

/// Срок жизни соединения по умолчанию: `timeout_connection` 0 значит 30 с (`tcpcon_create_table`,
/// `src/stack-tcp-core.c:665-667`).
const DEFAULT_LIFETIME_SECS: u32 = 30;

/// Таблица соединений одного приёмного потока с баннерами (`struct TCP_ConnectionTable`,
/// `src/stack-tcp-core.c:168-196`).
pub struct TcpBannerStack {
    table: Table,
    rst: RstFilter,
}

/// Таблица потока: сессии баннеров, `--connection-timeout` (0 это 30 с, как у C) и параметры движка (`seed` скана для
/// фильтра RST, предел соединений, бюджет байтов баннеров).
pub(crate) fn new_stack(
    sessions: Arc<dyn Sessions>,
    connection_timeout_secs: u32,
    p: TableParams,
) -> TcpBannerStack {
    let lifetime = if connection_timeout_secs == 0 {
        DEFAULT_LIFETIME_SECS
    } else {
        connection_timeout_secs
    };
    TcpBannerStack {
        table: Table::new(sessions, lifetime, p.capacity, p.banner_byte_budget),
        rst: RstFilter::new(p.seed),
    }
}

/// Нижняя граница памяти одного живого соединения: запись карты (ключ и соединение с TCB, состоянием приложения и
/// указателем на сессию) и запись таймера, без очереди отправки, буферов баннеров и самой сессии (её размер знает
/// реализация [`Sessions`]). Для README (задача 14).
#[doc(hidden)]
pub fn connection_memory_floor() -> usize {
    size_of::<(ConnKey, Conn)>() + size_of::<((u64, u64), ConnKey)>()
}

/// Биты флагов TCP (`TCP_IS_*`, `src/stack-tcp-core.h:15-21`).
const FIN: u8 = 0x01;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const SYN_ACK: u8 = 0x12;

impl TcpStack for TcpBannerStack {
    fn on_tick(&mut self, now_micros: u64, out: &mut StackOutput) {
        self.table.tick(now_micros, out);
    }

    /// Стековый блок `src/main.c:962-1043`. SYN-ACK (cookie уже проверил движок): нового ключа это новый блок
    /// (`tcpcon_create_tcb`, `seqno_me` их ACK, `seqno_them` их номер + 1, TTL SYN-ACK), затем событие SYNACK с
    /// `(seq + 1, ack)`; у живого блока только событие (EST_RECV и EST_SEND его игнорируют). Иначе у живого блока по
    /// порядку ACK (бит ACK), DATA (есть нагрузка), FIN (FIN без RST, номер за данными), RST, и кадр кончается на
    /// уничтожении (E1.5). Без блока FIN без RST даёт RST временного блока, если его пропустил фильтр (справка A7).
    fn on_segment(&mut self, now_micros: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool {
        let key = seg.key;
        let flags = seg.flags;
        if flags & SYN_ACK == SYN_ACK {
            if !self.table.contains(&key)
                && !self
                    .table
                    .create(key, seg.ack, seg.seq.wrapping_add(1), seg.ttl, now_micros)
            {
                return false;
            }
            let _ = self.table.event(
                &key,
                What::SynAck,
                &[],
                seg.seq.wrapping_add(1),
                seg.ack,
                now_micros,
                out,
            );
            return true;
        }
        if self.table.contains(&key) {
            let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
            let steps = [
                (flags & ACK != 0, What::Ack, &[][..], seg.seq),
                (!seg.payload.is_empty(), What::Data, seg.payload, seg.seq),
                (
                    flags & FIN != 0 && flags & RST == 0,
                    What::Fin,
                    &[][..],
                    fin_seq,
                ),
                (flags & RST != 0, What::Rst, &[][..], seg.seq),
            ];
            for (on, what, payload, seq) in steps {
                if !on {
                    continue;
                }
                match self
                    .table
                    .event(&key, what, payload, seq, seg.ack, now_micros, out)
                {
                    Some(TcbResult::Okay) => {}
                    Some(TcbResult::Destroyed) | None => break,
                }
            }
            return true;
        }
        // `src/main.c:1019-1041`: `tcpcon_send_RST(..., seqno_them, seqno_me)` временного блока
        // (`src/stack-tcp-core.c:1261-1282`): seq их ACK, ack их номер + 1, окно шаблона; от `--noreset` не зависит.
        if flags & FIN != 0 && flags & RST == 0 && !self.rst.is_filtered(&key) {
            out.segments.push(SegmentOut {
                key,
                seq: seg.ack,
                ack: seg.seq.wrapping_add(1),
                flags: RST,
                payload: Vec::new(),
                window: None,
            });
            return true;
        }
        false
    }

    fn finish(&mut self, max_connections: usize, out: &mut StackOutput) -> bool {
        self.table.finish(max_connections, out)
    }

    fn stats(&self) -> StackStats {
        self.table.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::app::{ByteBudget, Session, SessionAction};
    use crate::tcp::tcb::{SEND_QUEUE_MAX_SEGMENTS, TcpState};
    use rmasscan_core::banner::BannerRecord;
    use rmasscan_core::stack::ConnAddrs;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const SEC: u64 = 1_000_000;
    const MS: u64 = 1_000;
    const T0: u64 = 1_700_000_000_000_000;
    /// ACK их SYN-ACK (наш ISN + 1, будущий `seqno_me`) и их ISN.
    const S: u32 = 0x1000_0000;
    const R0: u32 = 0x2000_0000;
    /// `seqno_them` нового блока.
    const R: u32 = R0 + 1;
    /// Тип записей сессии-заглушки.
    const APP: u16 = 0x2a;

    const FIN: u8 = 0x01;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;
    const SYNACK: u8 = 0x12;
    const FINACK: u8 = 0x11;
    const PSHACK: u8 = 0x18;
    const FIN_PSH_ACK: u8 = 0x19;

    fn key(n: u8) -> ConnKey {
        ConnKey {
            addrs: ConnAddrs::V4 {
                local: 0x0a00_0001,
                remote: 0x0a00_0100 | u32::from(n),
            },
            local_port: 40000,
            remote_port: 80,
        }
    }

    /// Сценарий сессий: hello потока и действия на k-й разбор соединения (с нуля). Разбор пишет нагрузку в баннер
    /// `APP` столько, сколько дал бюджет.
    #[derive(Clone, Default)]
    struct Script {
        hello: Option<Vec<u8>>,
        replies: Vec<(usize, Vec<SessionAction>)>,
        parses: Arc<AtomicUsize>,
    }

    impl Script {
        fn hello(h: &[u8]) -> Script {
            Script {
                hello: Some(h.to_vec()),
                ..Script::default()
            }
        }

        fn null() -> Script {
            Script::default()
        }

        fn reply(mut self, k: usize, acts: Vec<SessionAction>) -> Script {
            self.replies.push((k, acts));
            self
        }

        fn parses(&self) -> usize {
            self.parses.load(Ordering::Relaxed)
        }
    }

    struct Stub {
        script: Script,
        banner: Vec<u8>,
        parsed: usize,
    }

    impl Session for Stub {
        fn hello(&self) -> Option<&[u8]> {
            self.script.hello.as_deref()
        }

        fn parse(&mut self, px: &[u8], budget: &mut ByteBudget, acts: &mut Vec<SessionAction>) {
            let n = budget.take(px.len());
            self.banner.extend_from_slice(px.get(..n).unwrap_or(px));
            for (k, a) in &self.script.replies {
                if *k == self.parsed {
                    acts.extend(a.iter().cloned());
                }
            }
            self.parsed += 1;
            self.script.parses.fetch_add(1, Ordering::Relaxed);
        }

        fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)> {
            if self.banner.is_empty() {
                return Vec::new();
            }
            budget.give(self.banner.len());
            vec![(APP, std::mem::take(&mut self.banner))]
        }
    }

    impl Sessions for Script {
        fn new_session(&self, _remote_port: u16) -> Box<dyn Session> {
            Box::new(Stub {
                script: self.clone(),
                banner: Vec::new(),
                parsed: 0,
            })
        }
    }

    fn stack_with(
        script: &Script,
        lifetime: u32,
        capacity: usize,
        budget: usize,
    ) -> TcpBannerStack {
        new_stack(
            Arc::new(script.clone()),
            lifetime,
            TableParams {
                seed: 0x1122_3344_5566_7788,
                capacity,
                banner_byte_budget: budget,
            },
        )
    }

    fn stack(script: &Script) -> TcpBannerStack {
        stack_with(script, 30, 64, 1 << 20)
    }

    /// Кадр в сравнении: флаги, seq, ack, длина нагрузки.
    type F = (u8, u32, u32, usize);

    fn frames(out: &StackOutput) -> Vec<F> {
        out.segments
            .iter()
            .map(|s| (s.flags, s.seq, s.ack, s.payload.len()))
            .collect()
    }

    fn payloads(out: &StackOutput) -> Vec<Vec<Vec<u8>>> {
        out.banners
            .iter()
            .map(|set| set.iter().map(|r| r.payload.clone()).collect())
            .collect()
    }

    fn seg_in(key: ConnKey, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> SegmentIn<'_> {
        SegmentIn {
            key,
            seq,
            ack,
            flags,
            ttl: 64,
            payload,
        }
    }

    /// Сегмент сервера и выдача стека за него.
    fn send(
        st: &mut TcpBannerStack,
        now: u64,
        key: ConnKey,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> (bool, StackOutput) {
        let mut out = StackOutput::default();
        let took = st.on_segment(now, &seg_in(key, flags, seq, ack, payload), &mut out);
        (took, out)
    }

    /// SYN-ACK с ISN `R0` на наш SYN (ACK `S`).
    fn synack(st: &mut TcpBannerStack, now: u64, key: ConnKey) -> StackOutput {
        let (took, out) = send(st, now, key, SYNACK, R0, S, b"");
        assert!(took, "SYN-ACK taken");
        out
    }

    fn tick(st: &mut TcpBannerStack, now: u64) -> StackOutput {
        let mut out = StackOutput::default();
        st.on_tick(now, &mut out);
        out
    }

    fn state(st: &TcpBannerStack, k: ConnKey) -> Option<TcpState> {
        st.table.tcb(&k).map(|t| t.state)
    }

    /// Сброс таблицы до конца (порции по 64, не больше 100 порций).
    fn finish_all(st: &mut TcpBannerStack) -> StackOutput {
        let mut out = StackOutput::default();
        for _ in 0..100 {
            if !st.finish(64, &mut out) {
                return out;
            }
        }
        panic!("finish never ends");
    }

    /// Сервер молчит: ACK на SYN-ACK сразу (`src/stack-tcp-core.c:2013-2026`), hello через 2 с (`tcpapi_set_timeout(2)`,
    /// `src/stack-tcp-app.c:76`, `:90-97`, `:187`); таймер +1 с создания (`src/stack-tcp-core.c:1035-1040`) заменён, тика
    /// на +1 с нет.
    #[test]
    fn hello_two_seconds_after_synack_when_server_silent() {
        let mut st = stack(&Script::hello(b"HELLO"));
        let out = synack(&mut st, T0, key(1));
        assert_eq!(frames(&out), [(ACK, S, R, 0)]);
        assert_eq!(out.segments[0].key, key(1));
        assert!(out.banners.is_empty());
        for at in [T0 + SEC, T0 + 2 * SEC - 1] {
            assert!(
                tick(&mut st, at).segments.is_empty(),
                "no frame at +{} us",
                at - T0
            );
        }
        let out = tick(&mut st, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(PSHACK, S, R, 5)]);
        assert_eq!(out.segments[0].payload, b"HELLO");
        assert_eq!(out.segments[0].window, None);
        assert_eq!(
            st.stats(),
            StackStats {
                tcbs_created: 1,
                tcbs_live: 1,
                table_full: 0,
                banner_bytes_dropped: 0
            }
        );
    }

    /// Сервер заговорил первым (`src/stack-tcp-app.c:100-105`): hello не уходит ни на каком тике, байты идут в разбор.
    #[test]
    fn server_first_data_suppresses_hello() {
        let script = Script::hello(b"HELLO");
        let mut st = stack(&script);
        synack(&mut st, T0, key(1));
        let (took, out) = send(
            &mut st,
            T0 + SEC / 2,
            key(1),
            PSHACK,
            R,
            S,
            b"SSH-2.0-x\r\n",
        );
        assert!(took);
        assert_eq!(frames(&out), [(ACK, S, R + 11, 0)]);
        for k in 1..=10 {
            assert!(
                tick(&mut st, T0 + 2 * k * SEC).segments.is_empty(),
                "tick +{} s",
                2 * k
            );
        }
        assert_eq!(script.parses(), 1);
        let out = finish_all(&mut st);
        assert_eq!(payloads(&out), [[b"SSH-2.0-x\r\n".to_vec()]]);
        assert!(out.segments.is_empty());
    }

    /// Поток NULL (порт без hello, `src/stack-tcp-app.c:94-98`): данных мы не шлём никогда, байты сервера разбираются,
    /// соединение кончается RST по сроку жизни.
    #[test]
    fn null_stream_never_sends() {
        let script = Script::null();
        let mut st = stack(&script);
        let mut all = frames(&synack(&mut st, T0, key(1)));
        let mut records = Vec::new();
        let mut at = T0;
        while at <= T0 + 40 * SEC {
            if at == T0 + 5 * SEC {
                let (_, out) = send(&mut st, at, key(1), PSHACK, R, S, b"hi");
                all.extend(frames(&out));
            }
            let out = tick(&mut st, at);
            all.extend(frames(&out));
            records.extend(payloads(&out));
            at += 100 * MS;
        }
        assert_eq!(
            all,
            [(ACK, S, R, 0), (ACK, S, R + 2, 0), (RST, S, R + 2, 0)]
        );
        assert_eq!(script.parses(), 1, "the server's bytes are parsed");
        assert_eq!(
            records,
            [[b"hi".to_vec()]],
            "flushed at the lifetime destroy"
        );
        assert_eq!(st.stats().tcbs_live, 0);
    }

    /// Пустой hello (Р1, справка B5): `App_SendFirst` ничего не шлёт и оставляет `App_SendNext` навсегда
    /// (`src/stack-tcp-app.c:183-194`): байты сервера подтверждаются, но не разбираются, их FIN не даёт ни сброса, ни
    /// нашего FIN (`APP_CLOSE` в `App_SendNext` не обрабатывается, `:206-209`), конец только RST по сроку жизни.
    #[test]
    fn empty_hello_stays_and_ignores_later_data() {
        let script = Script::hello(b"");
        let mut st = stack(&script);
        synack(&mut st, T0, key(1));
        assert!(tick(&mut st, T0 + 2 * SEC).segments.is_empty());
        let (_, out) = send(&mut st, T0 + 3 * SEC, key(1), PSHACK, R, S, b"220 hi\r\n");
        assert_eq!(frames(&out), [(ACK, S, R + 8, 0)]);
        let (_, out) = send(&mut st, T0 + 3 * SEC + 1, key(1), FINACK, R + 8, S, b"");
        assert_eq!(frames(&out), [(ACK, S, R + 9, 0)]);
        assert!(out.banners.is_empty());
        assert_eq!(state(&st, key(1)), Some(TcpState::CloseWait));
        let mut rest = Vec::new();
        let mut banners = 0;
        for k in 2..=16 {
            let out = tick(&mut st, T0 + 2 * k * SEC);
            rest.extend(frames(&out));
            banners += out.banners.len();
        }
        assert_eq!(rest, [(RST, S, R + 9, 0)]);
        assert_eq!(banners, 0);
        assert_eq!(script.parses(), 0);
        assert_eq!(st.stats().tcbs_live, 0);
    }

    /// Их FIN (`src/stack-tcp-app.c:131-135`): записи выходят на `APP_CLOSE`, наш FIN уходит за ACK их FIN (CLOSE_WAIT ->
    /// LAST_ACK, `src/stack-tcp-core.c:2092-2100`, `:2273-2276`), ACK нашего FIN уничтожает блок без кадра и без второго
    /// набора (`:2294-2298`).
    #[test]
    fn peer_fin_flushes_and_closes() {
        let mut st = stack(&Script::null());
        synack(&mut st, T0, key(1));
        // Данные и FIN одним сегментом: DATA, затем FIN с номером за данными (`src/main.c:997-1012`).
        let (took, out) = send(&mut st, T0 + SEC, key(1), FIN_PSH_ACK, R, S, b"220 ftp\r\n");
        assert!(took);
        assert_eq!(
            frames(&out),
            [
                (ACK, S, R + 9, 0),
                (ACK, S, R + 10, 0),
                (FIN_PSH_ACK, S, R + 10, 0)
            ]
        );
        assert_eq!(payloads(&out), [[b"220 ftp\r\n".to_vec()]]);
        assert_eq!(state(&st, key(1)), Some(TcpState::LastAck));
        let (took, out) = send(&mut st, T0 + SEC + 1, key(1), ACK, R + 10, S + 1, b"");
        assert!(took);
        assert!(out.segments.is_empty() && out.banners.is_empty());
        assert_eq!(st.stats().tcbs_live, 0);
        assert!(!st.table.contains(&key(1)));
    }

    /// Тики раз в 2 с (`src/stack-tcp-core.c:322-327`): hello без ACK повторяется на каждом (EST_SEND TIMEOUT,
    /// `:2067-2070`), на +32 с RST по сроку жизни; частые вызовы между тиками ничего не дают.
    #[test]
    fn ticks_every_two_seconds() {
        let mut st = stack(&Script::hello(b"HELLO"));
        synack(&mut st, T0, key(1));
        let mut seen = Vec::new();
        let mut at = T0;
        while at <= T0 + 40 * SEC {
            for s in &tick(&mut st, at).segments {
                seen.push(((at - T0) / (SEC / 4), s.flags));
            }
            at += SEC / 4;
        }
        // В четвертях секунды: hello на +2 с, повторы +4..+30 с, RST +32 с.
        let mut want: Vec<(u64, u8)> = (1..=15).map(|k| (8 * k, PSHACK)).collect();
        want.push((128, RST));
        assert_eq!(seen, want);
    }

    /// Р6: часы приходят на каждый срок с опозданием 7 мс, а сетка и проверка жизни идут по запланированным срокам: RST на
    /// тике +32 с при сроке жизни 30 и на +8 с при 6 (`src/stack-tcp-core.c:1970-1980`), а не тиком позже.
    #[test]
    fn lifetime_rst_on_tick_after_timeout_with_late_processing() {
        for (lifetime, rst_tick) in [(30u32, 32u64), (6, 8)] {
            let mut st = stack_with(&Script::null(), lifetime, 64, 1 << 20);
            synack(&mut st, T0, key(1));
            for k in 1..=rst_tick / 2 {
                let due = T0 + 2 * k * SEC;
                assert_eq!(
                    st.table.tcb(&key(1)).and_then(|t| t.deadline_micros),
                    Some(due),
                    "life {lifetime}: grid kept at +{} s",
                    2 * k
                );
                let out = tick(&mut st, due + 7 * MS);
                if 2 * k == rst_tick {
                    assert_eq!(frames(&out), [(RST, S, R, 0)], "life {lifetime}");
                } else {
                    assert!(
                        out.segments.is_empty(),
                        "life {lifetime}: tick +{} s",
                        2 * k
                    );
                }
            }
            assert_eq!(st.stats().tcbs_live, 0, "life {lifetime}");
        }
    }

    /// Конец скана порциями (`tcpcon_destroy_table`, `src/stack-tcp-core.c:933-961`): `finish(2)` уничтожает по два
    /// соединения без кадров, каждая запись выходит ровно один раз, записи, сброшенные раньше (их FIN), не повторяются.
    #[test]
    fn finish_is_incremental_and_complete() {
        let mut st = stack(&Script::null());
        for n in 1..=5u8 {
            synack(&mut st, T0, key(n));
            send(&mut st, T0 + SEC, key(n), PSHACK, R, S, &[b'a' + n; 3]);
        }
        let (_, early) = send(&mut st, T0 + SEC + 1, key(5), FINACK, R + 3, S, b"");
        assert_eq!(payloads(&early), [[vec![b'a' + 5; 3]]]);
        let mut got = Vec::new();
        let mut live = Vec::new();
        loop {
            let mut out = StackOutput::default();
            let more = st.finish(2, &mut out);
            assert!(out.segments.is_empty(), "the teardown sends nothing");
            got.extend(out.banners.iter().flatten().map(|r| r.payload.clone()));
            live.push(st.stats().tcbs_live);
            if !more {
                break;
            }
            assert!(live.len() < 10, "finish makes progress");
        }
        assert_eq!(live, [3, 1, 0]);
        got.sort();
        let want: Vec<Vec<u8>> = (1..=4u8).map(|n| vec![b'a' + n; 3]).collect();
        assert_eq!(got, want);
        let mut out = StackOutput::default();
        assert!(!st.finish(2, &mut out));
        assert!(out.banners.is_empty() && out.segments.is_empty());
    }

    /// Полная таблица (решение D7): SYN-ACK без соединения и без кадра, `table_full` растёт на каждый такой SYN-ACK
    /// (статус пишет движок); место освобождает уничтожение.
    #[test]
    fn table_full_counts_and_creates_nothing() {
        let mut st = stack_with(&Script::hello(b"HELLO"), 30, 2, 1 << 20);
        synack(&mut st, T0, key(1));
        synack(&mut st, T0, key(2));
        for _ in 0..2 {
            let (took, out) = send(&mut st, T0 + 1, key(3), SYNACK, R0, S, b"");
            assert!(!took);
            assert!(out.segments.is_empty() && out.banners.is_empty());
        }
        let (took, out) = send(&mut st, T0 + 2, key(3), PSHACK, R, S, b"x");
        assert!(
            !took && out.segments.is_empty(),
            "no TCB for the refused one"
        );
        assert!(!st.table.contains(&key(3)));
        assert_eq!(
            st.stats(),
            StackStats {
                tcbs_created: 2,
                tcbs_live: 2,
                table_full: 2,
                banner_bytes_dropped: 0
            }
        );
        let (took, _) = send(&mut st, T0 + 3, key(1), RST, R, 0, b"");
        assert!(took);
        let out = synack(&mut st, T0 + 4, key(3));
        assert_eq!(frames(&out), [(ACK, S, R, 0)]);
        assert_eq!(st.stats().tcbs_created, 3);
        assert_eq!(st.stats().table_full, 2);
    }

    /// Ёмкость 2^30 ничего не выделяет заранее: место только у живых соединений, фильтр RST без FIN без соединения
    /// памяти не держит.
    #[test]
    fn table_allocates_only_live_connections() {
        let mut st = stack_with(&Script::null(), 30, 1 << 30, 1 << 30);
        assert_eq!(st.table.allocated(), (0, 0));
        assert_eq!(st.rst.allocated(), 0);
        for n in 1..=3 {
            synack(&mut st, T0, key(n));
        }
        let (map, timers) = st.table.allocated();
        assert!(map < 16, "map capacity {map}");
        assert_eq!(timers, 3);
        assert_eq!(st.stats().tcbs_live, 3);
        assert_eq!(st.rst.allocated(), 0);
    }

    /// FIN без соединения (`src/main.c:1019-1041`): RST временного блока, seq = их ACK, ack = их номер + 1 без длины
    /// данных (`tcpcon_send_RST`, `src/stack-tcp-core.c:1261-1282`), пока корзина фильтра не насытится: 15 RST
    /// (справка A7, вектор оракула C в `rstfilter_matches_c_vectors`), потом сегмент не берётся.
    #[test]
    fn fin_without_tcb_rst_until_filter_saturates() {
        let mut st = stack(&Script::null());
        let k = ConnKey {
            addrs: ConnAddrs::V4 {
                local: 0x0a00_0001,
                remote: 0x0a00_0002,
            },
            local_port: 40000,
            remote_port: 80,
        };
        let mut got = Vec::new();
        for _ in 0..20 {
            let (took, out) = send(&mut st, T0, k, FIN_PSH_ACK, 0x3000, 0x4000, b"xyz");
            assert!(out.banners.is_empty());
            for s in &out.segments {
                assert_eq!((s.key, s.window, s.payload.len()), (k, None, 0));
            }
            got.push((took, frames(&out)));
        }
        let mut want = vec![(true, vec![(RST, 0x4000, 0x3001, 0)]); 15];
        want.extend(vec![(false, Vec::new()); 5]);
        assert_eq!(got, want);
        assert_eq!(st.stats(), StackStats::default());
    }

    /// RST без соединения игнорируется, и с FIN тоже (`src/main.c:1028-1029`), фильтр не спрашивается; сегмент без FIN и
    /// без соединения стек не берёт.
    #[test]
    fn rst_without_tcb_ignored() {
        let mut st = stack(&Script::null());
        for flags in [RST, RST | ACK, RST | FIN, RST | FIN | ACK, ACK, PSHACK, 0] {
            let (took, out) = send(&mut st, T0, key(1), flags, R, S, b"data");
            assert!(!took, "flags {flags:#x}");
            assert!(out.segments.is_empty() && out.banners.is_empty());
        }
        assert_eq!(st.rst.allocated(), 0, "the filter was not consulted");
        assert_eq!(st.stats(), StackStats::default());
    }

    /// Повторный SYN-ACK живого соединения: событие SYNACK (`src/main.c:986-987`), которое EST_RECV и EST_SEND
    /// игнорируют (`src/stack-tcp-core.c:2077-2078`, `:2115-2120`); блок не пересоздаётся, номера прежние.
    #[test]
    fn synack_for_live_tcb_is_ignored() {
        let mut st = stack(&Script::hello(b"HELLO"));
        synack(&mut st, T0, key(1));
        let before = st.table.tcb(&key(1)).cloned();
        let (took, out) = send(&mut st, T0 + 1, key(1), SYNACK, R0 + 77, S + 99, b"");
        assert!(took);
        assert!(out.segments.is_empty());
        assert_eq!(st.table.tcb(&key(1)).cloned(), before);
        tick(&mut st, T0 + 2 * SEC);
        assert_eq!(state(&st, key(1)), Some(TcpState::EstablishedSend));
        let (took, out) = send(&mut st, T0 + 2 * SEC + 1, key(1), SYNACK, R0, S, b"");
        assert!(took && out.segments.is_empty());
        assert_eq!(st.stats().tcbs_created, 1);
    }

    /// Записи сброса: время 0, адрес и порт сервера, `ip_proto` 6, TTL SYN-ACK, создавшего блок (`banner_flush`,
    /// `src/stack-tcp-core.c:810-823`); у IPv6 это hop limit (C его не заполняет, справка E1.9).
    #[test]
    fn records_carry_synack_ttl_and_server_address() {
        let remote6: u128 = 0x2001_0db8_0000_0000_0000_0000_0000_00aa;
        let v6 = ConnKey {
            addrs: ConnAddrs::V6 {
                local: (0x2001_0db8u128 << 96) | 1,
                remote: remote6,
            },
            local_port: 40000,
            remote_port: 443,
        };
        let mut st = stack(&Script::null());
        for (k, ttl) in [(key(1), 57u8), (v6, 61)] {
            let mut out = StackOutput::default();
            let syn = SegmentIn {
                ttl,
                ..seg_in(k, SYNACK, R0, S, b"")
            };
            assert!(st.on_segment(T0, &syn, &mut out));
            let data = SegmentIn {
                ttl: 200,
                ..seg_in(k, PSHACK, R, S, b"banner")
            };
            assert!(st.on_segment(T0 + SEC, &data, &mut out));
        }
        let out = finish_all(&mut st);
        let mut recs: Vec<BannerRecord> = out.banners.into_iter().flatten().collect();
        recs.sort_by_key(|r| r.port);
        let rec = |ip, port, ttl| BannerRecord {
            timestamp: 0,
            ip,
            ip_proto: 6,
            port,
            app: APP,
            ttl,
            payload: b"banner".to_vec(),
        };
        assert_eq!(
            recs,
            [
                rec(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), 80, 57),
                rec(IpAddr::V6(Ipv6Addr::from(remote6)), 443, 61),
            ]
        );
    }

    /// E1.5: события кадра после уничтожающего не идут (у C они берут вычищенный блок и шлют, например, ACK на
    /// 255.255.255.255:65535, `src/main.c:991-1018`). В CLOSING ACK нашего FIN уничтожает блок
    /// (`src/stack-tcp-core.c:2205-2211`), а повтор их FIN того же кадра на живом блоке дал бы ACK (`:1955-1960`).
    #[test]
    fn frame_processing_stops_at_destroyed() {
        let script = Script::null().reply(0, vec![SessionAction::Close]);
        let mut st = stack(&script);
        synack(&mut st, T0, key(1));
        let (_, out) = send(&mut st, T0 + SEC, key(1), PSHACK, R, S, b"x");
        assert_eq!(
            frames(&out),
            [(FIN_PSH_ACK, S, R + 1, 0), (ACK, S, R + 1, 0)]
        );
        let (_, out) = send(&mut st, T0 + SEC + 1, key(1), FINACK, R + 1, S, b"");
        assert_eq!(frames(&out), [(ACK, S, R + 2, 0), (ACK, S, R + 2, 0)]);
        assert_eq!(payloads(&out), [[b"x".to_vec()]]);
        assert_eq!(state(&st, key(1)), Some(TcpState::Closing));
        let (took, out) = send(&mut st, T0 + SEC + 2, key(1), FINACK, R + 1, S + 1, b"");
        assert!(took);
        assert!(out.segments.is_empty(), "{:?}", frames(&out));
        assert!(out.banners.is_empty());
        assert_eq!(st.stats().tcbs_live, 0);
    }

    /// Бюджет байтов баннеров таблицы (решение 8): не вместившееся обрезается и считается в `banner_bytes_dropped`,
    /// сброс возвращает байты; на ACK бюджет не влияет.
    #[test]
    fn byte_budget_truncates_and_counts() {
        let mut st = stack_with(&Script::null(), 30, 64, 10);
        synack(&mut st, T0, key(1));
        synack(&mut st, T0, key(2));
        send(&mut st, T0 + 1, key(1), PSHACK, R, S, b"abcdef");
        let (_, out) = send(&mut st, T0 + 2, key(2), PSHACK, R, S, b"ghijklmn");
        assert_eq!(frames(&out), [(ACK, S, R + 8, 0)]);
        assert_eq!(st.stats().banner_bytes_dropped, 4);
        assert_eq!(st.table.budget().left(), 0);
        let (_, out) = send(&mut st, T0 + 3, key(1), FINACK, R + 6, S, b"");
        assert_eq!(payloads(&out), [[b"abcdef".to_vec()]]);
        assert_eq!(st.table.budget().left(), 6);
        send(&mut st, T0 + 4, key(2), PSHACK, R + 8, S, b"op");
        let out = finish_all(&mut st);
        assert_eq!(payloads(&out), [[b"ghijop".to_vec()]]);
        assert_eq!(st.stats().banner_bytes_dropped, 4);
        assert_eq!(st.table.budget().left(), 10);
    }

    /// Ответ парсера уходит раньше ACK его данных (`_tcb_seg_recv`, `src/stack-tcp-core.c:1884-1896`), закрытие встаёт
    /// FIN-ом за ним (`tcpapi_send`, `tcpapi_close` из `banner1_parse`, `src/stack-tcp-core.c:2038-2041`).
    #[test]
    fn parser_reply_and_close_precede_the_ack() {
        let script = Script::null().reply(
            0,
            vec![
                SessionAction::Send(b"AUTH TLS\r\n".to_vec()),
                SessionAction::Close,
            ],
        );
        let mut st = stack(&script);
        synack(&mut st, T0, key(1));
        let (_, out) = send(&mut st, T0 + SEC, key(1), PSHACK, R, S, b"220 ftp\r\n");
        assert_eq!(frames(&out), [(PSHACK, S, R + 9, 10), (ACK, S, R + 9, 0)]);
        assert_eq!(out.segments[0].payload, b"AUTH TLS\r\n");
        assert_eq!(state(&st, key(1)), Some(TcpState::FinWait1Send));
    }

    /// Решение по hello (замечание M4 задачи 6): соединения одного порта держат в очереди один буфер hello, как у C
    /// указатель `TCP__static` на `stream->hello` (`src/stack-tcp-app.c:187`); на проводе по 1400 байт.
    #[test]
    fn hello_buffer_shared_across_connections() {
        let hello: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let mut st = stack(&Script::hello(&hello));
        for n in 1..=3 {
            synack(&mut st, T0, key(n));
        }
        let out = tick(&mut st, T0 + 2 * SEC);
        assert_eq!(frames(&out).len(), 3);
        for s in &out.segments {
            assert_eq!(s.payload, hello[..1400]);
        }
        let shared = st.table.hellos().get(80).cloned().expect("port 80 hello");
        assert_eq!(*shared, *hello);
        for n in 1..=3 {
            let tcb = st.table.tcb(&key(n)).expect("live");
            let spans: Vec<(usize, bool)> = tcb.queue_spans().iter().map(|s| (s.1, s.2)).collect();
            assert_eq!(spans, [(1400, false), (1400, false), (200, false)]);
            assert!(
                tcb.queue_buffers().iter().all(|b| Arc::ptr_eq(b, &shared)),
                "conn {n}"
            );
        }
        // Таблица и 3 x 3 сегмента, копий нет.
        assert_eq!(Arc::strong_count(&shared), 1 + 1 + 9);
    }

    /// Отличие от C (README): FIN в TIME_WAIT ставит таймер +5 с (`src/stack-tcp-core.c:2249-2253`), но не дальше тика
    /// `created + жизнь + 2 с`, где сетка даёт RST по сроку жизни. FIN на +20,5 с: TIME_WAIT кончается тихо на +25,5 с,
    /// как у C; FIN на +29,5 с: RST на +32 с, у C на +34,5 с (и FIN со следующим номером чаще раза в 5 с держит блок у C
    /// вечно: срок жизни проверяется только на таймауте, `:1970-1980`).
    #[test]
    fn time_wait_fin_cannot_outlive_lifetime() {
        for (fin_ms, end_ms, want_rst) in [(20_500u64, 25_500u64, false), (29_500, 32_000, true)] {
            let script = Script::null().reply(0, vec![SessionAction::Close]);
            let mut st = stack(&script);
            synack(&mut st, T0, key(1));
            send(&mut st, T0 + SEC, key(1), PSHACK, R, S, b"x");
            let (_, out) = send(&mut st, T0 + SEC + 1, key(1), ACK, R + 1, S + 1, b"");
            assert_eq!(
                payloads(&out),
                [[b"x".to_vec()]],
                "APP_CLOSE on the ACK of our FIN"
            );
            assert_eq!(state(&st, key(1)), Some(TcpState::FinWait2));
            let mut ended = None;
            let mut rsts = Vec::new();
            let mut at = T0 + 2 * SEC;
            while at <= T0 + 40 * SEC && ended.is_none() {
                if at == T0 + fin_ms * MS {
                    let (_, out) = send(&mut st, at, key(1), FINACK, R + 1, S + 1, b"");
                    assert_eq!(frames(&out), [(ACK, S + 1, R + 2, 0)]);
                    assert_eq!(state(&st, key(1)), Some(TcpState::TimeWait));
                }
                let out = tick(&mut st, at);
                rsts.extend(
                    out.segments
                        .iter()
                        .filter(|s| s.flags == RST)
                        .map(|s| (s.seq, s.ack)),
                );
                if st.stats().tcbs_live == 0 {
                    ended = Some((at - T0) / MS);
                }
                at += 100 * MS;
            }
            assert_eq!(ended, Some(end_ms), "FIN at {fin_ms} ms");
            let want: Vec<(u32, u32)> = if want_rst {
                vec![(S + 1, R + 2)]
            } else {
                Vec::new()
            };
            assert_eq!(rsts, want, "FIN at {fin_ms} ms");
        }
    }

    /// Остановка потока (часы прыгнули на 10 с): пропущенные тики не выдаются пачкой, тик один, со сроком сетки, и
    /// проверка жизни видит этот срок; сетка прежняя.
    #[test]
    fn late_ticks_collapse_into_one() {
        let mut st = stack(&Script::hello(b"HELLO"));
        synack(&mut st, T0, key(1));
        let out = tick(&mut st, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(PSHACK, S, R, 5)]);
        let out = tick(&mut st, T0 + 12 * SEC + 500 * MS);
        assert_eq!(frames(&out), [(PSHACK, S, R, 5)], "one resend, not five");
        assert_eq!(
            st.table.tcb(&key(1)).and_then(|t| t.deadline_micros),
            Some(T0 + 14 * SEC)
        );
        // Скачок за срок жизни: RST сразу, в том же вызове.
        let out = tick(&mut st, T0 + 45 * SEC);
        assert_eq!(frames(&out), [(RST, S, R, 0)]);
        assert_eq!(st.stats().tcbs_live, 0);
    }

    /// `--connection-timeout 0` значит 30 с, как у C (`src/stack-tcp-core.c:665-667`).
    #[test]
    fn zero_connection_timeout_means_thirty_seconds() {
        let mut st = stack_with(&Script::null(), 0, 64, 1 << 20);
        synack(&mut st, T0, key(1));
        for k in 1..=15 {
            assert!(tick(&mut st, T0 + 2 * k * SEC).segments.is_empty());
        }
        assert_eq!(frames(&tick(&mut st, T0 + 32 * SEC)), [(RST, S, R, 0)]);
    }

    #[test]
    fn memory_floor_counts_table_entry_and_tcb() {
        let floor = connection_memory_floor();
        assert!(floor > size_of::<crate::tcp::tcb::Tcb>(), "{floor}");
        assert!(floor < 1024, "{floor}");
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
        fn u32(&mut self) -> u32 {
            u32::try_from(self.next() >> 32).expect("u32")
        }
        fn small(&mut self, n: usize) -> u32 {
            u32::try_from(self.below(n)).expect("u32")
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next().to_le_bytes()[0]).collect()
        }
    }

    /// Сессии-хаос: hello по порту (NULL, пустой, короткий, длиннее 1400), разбор берёт байты из бюджета и иногда
    /// отвечает посылкой до 3000 байт, закрытием или обоими. `held` считает байты в буферах живых сессий.
    struct Chaos {
        seed: u64,
        made: AtomicU64,
        held: Arc<AtomicUsize>,
    }

    struct ChaosSession {
        rng: Rng,
        hello: Option<Vec<u8>>,
        banner: Vec<u8>,
        held: Arc<AtomicUsize>,
    }

    impl Sessions for Chaos {
        fn new_session(&self, remote_port: u16) -> Box<dyn Session> {
            let n = self.made.fetch_add(1, Ordering::Relaxed);
            let hello = match remote_port {
                80 => Some(b"GET / HTTP/1.0\r\n\r\n".to_vec()),
                23 => Some(Vec::new()),
                3389 => Some(vec![b'h'; 3000]),
                _ => None,
            };
            Box::new(ChaosSession {
                rng: Rng((self.seed ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1),
                hello,
                banner: Vec::new(),
                held: Arc::clone(&self.held),
            })
        }
    }

    impl Session for ChaosSession {
        fn hello(&self) -> Option<&[u8]> {
            self.hello.as_deref()
        }

        fn parse(&mut self, px: &[u8], budget: &mut ByteBudget, acts: &mut Vec<SessionAction>) {
            let n = budget.take(px.len());
            self.banner.extend_from_slice(px.get(..n).unwrap_or(px));
            self.held.fetch_add(n, Ordering::Relaxed);
            match self.rng.below(10) {
                0 => {
                    let len = self.rng.below(3000);
                    acts.push(SessionAction::Send(self.rng.bytes(len)));
                }
                1 => acts.push(SessionAction::Close),
                2 => {
                    acts.push(SessionAction::Send(b"QUIT\r\n".to_vec()));
                    acts.push(SessionAction::Close);
                }
                _ => {}
            }
        }

        fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)> {
            let n = self.banner.len();
            budget.give(n);
            self.held.fetch_sub(n, Ordering::Relaxed);
            if n == 0 {
                Vec::new()
            } else {
                vec![(7, std::mem::take(&mut self.banner))]
            }
        }
    }

    /// Р1 класс б: случайные сегменты (флаги, номера у границ очереди и любые, нагрузки до 2000 байт), часы с
    /// опозданиями и скачками, сессии-хаос не роняют стек. Таблица не больше `capacity`, у каждого соединения один
    /// таймер, очередь в пределе, кадры не длиннее 1400 и только флагов C, записи несут TTL создавшего SYN-ACK, бюджет
    /// сходится, и после каждого тика нет живого соединения старше `жизнь + 2 с`; `finish` продвигается до нуля.
    #[test]
    fn stack_never_panics() {
        const LIFETIMES: [u32; 5] = [0, 1, 6, 30, u32::MAX];
        let mut rng = Rng(0x2545_F491_4F6C_DD1D);
        let (mut created, mut full, mut no_tcb_rst, mut life_rst) = (0u64, 0u64, 0u64, 0u64);
        let (mut records, mut dropped, mut peer_ends, mut tick_ends) =
            (0usize, 0u64, 0usize, 0usize);
        let mut seen = [0usize; 10];
        for run in 0..400u64 {
            let lifetime = LIFETIMES[rng.below(LIFETIMES.len())];
            let capacity = [0usize, 1, 3, 8][rng.below(4)];
            let budget = [0usize, 7, 300, 1 << 20][rng.below(4)];
            let held = Arc::new(AtomicUsize::new(0));
            let chaos = Chaos {
                seed: rng.next(),
                made: AtomicU64::new(0),
                held: Arc::clone(&held),
            };
            let mut st = new_stack(
                Arc::new(chaos),
                lifetime,
                TableParams {
                    seed: rng.next(),
                    capacity,
                    banner_byte_budget: budget,
                },
            );
            let keys: Vec<ConnKey> = [80u16, 23, 3389, 21, 80, 22]
                .iter()
                .enumerate()
                .map(|(i, &port)| ConnKey {
                    addrs: if i < 4 {
                        ConnAddrs::V4 {
                            local: 0x0a00_0001,
                            remote: 0x0a00_0010 + u32::try_from(i).expect("u32"),
                        }
                    } else {
                        ConnAddrs::V6 {
                            local: 1,
                            remote: 0x2001_0db8 << 96 | u128::try_from(i).expect("u128"),
                        }
                    },
                    local_port: 40000,
                    remote_port: port,
                })
                .collect();
            let mut ttl_of: HashMap<ConnKey, u8> = HashMap::new();
            let mut now = if run % 10 == 0 { rng.next() >> 2 } else { T0 };
            let check_out = |out: &StackOutput, ttl_of: &HashMap<ConnKey, u8>| {
                for s in &out.segments {
                    assert!(keys.contains(&s.key));
                    assert!(s.payload.len() <= 1400);
                    assert!(
                        matches!(s.flags, 0x04 | 0x10 | 0x11 | 0x18 | 0x19),
                        "{:#x}",
                        s.flags
                    );
                    assert_eq!(s.window, None);
                }
                for set in &out.banners {
                    assert!(!set.is_empty());
                    for r in set {
                        let k = keys
                            .iter()
                            .find(|k| k.remote_port == r.port && records_ip(k) == r.ip)
                            .expect("record of a pool key");
                        assert_eq!((r.timestamp, r.ip_proto, r.app), (0, 6, 7));
                        assert_eq!(Some(&r.ttl), ttl_of.get(k));
                    }
                }
            };
            for _ in 0..300 {
                now = now.saturating_add(match rng.below(40) {
                    0 => 1 + rng.next() % (6 * SEC),
                    1 if rng.below(10) == 0 => 10_000_000 * SEC,
                    _ => rng.next() % (400 * MS),
                });
                let before = st.stats().tcbs_live;
                let mut out = StackOutput::default();
                st.on_tick(now, &mut out);
                check_out(&out, &ttl_of);
                life_rst += out.segments.iter().filter(|s| s.flags == RST).count() as u64;
                tick_ends += usize::from(st.stats().tcbs_live < before);
                records += out.banners.iter().map(Vec::len).sum::<usize>();
                st.table.check();
                for k in st.table.keys() {
                    let last = st.table.last_tick(&k).expect("live");
                    if last != u64::MAX {
                        assert!(now < last, "TCB alive past lifetime + 2 s");
                    }
                }
                for _ in 0..rng.below(4) {
                    let k = keys[rng.below(keys.len())];
                    let tcb = st.table.tcb(&k).cloned();
                    let flags = match rng.below(20) {
                        0..=2 => SYNACK,
                        3..=5 => ACK,
                        6..=10 => PSHACK,
                        11 | 12 => FINACK,
                        13 => FIN_PSH_ACK,
                        14 => RST,
                        15 => RST | ACK,
                        16 => FIN,
                        _ => rng.next().to_le_bytes()[0],
                    };
                    let seq = match &tcb {
                        Some(t) if rng.below(4) != 0 => t.seqno_them,
                        Some(t) => t
                            .seqno_them
                            .wrapping_add(rng.small(3000))
                            .wrapping_sub(1500),
                        None => rng.u32(),
                    };
                    let ack = match &tcb {
                        Some(t) => {
                            let spans = t.queue_spans();
                            match (rng.below(5), spans.get(rng.below(3))) {
                                (0, Some(&(seqno, len, fin))) => seqno
                                    .wrapping_add(u32::try_from(len).expect("len"))
                                    .wrapping_add(u32::from(fin)),
                                (1, Some(&(seqno, len, _))) => {
                                    seqno.wrapping_add(rng.small(len + 1))
                                }
                                (2, _) => t.seqno_me.wrapping_add(1),
                                (3, _) => rng.u32(),
                                _ => t.seqno_me,
                            }
                        }
                        None => rng.u32(),
                    };
                    let n = match rng.below(10) {
                        0 => rng.below(2001),
                        1..=3 => 0,
                        _ => rng.below(64),
                    };
                    let payload = rng.bytes(n);
                    let ttl = rng.next().to_le_bytes()[1];
                    let live = st.stats().tcbs_live;
                    let made = st.stats().tcbs_created;
                    let full_before = st.stats().table_full;
                    let seg = SegmentIn {
                        key: k,
                        seq,
                        ack,
                        flags,
                        ttl,
                        payload: &payload,
                    };
                    let mut out = StackOutput::default();
                    let took = st.on_segment(now, &seg, &mut out);
                    let s = st.stats();
                    if s.tcbs_created > made {
                        ttl_of.insert(k, ttl);
                    }
                    check_out(&out, &ttl_of);
                    st.table.check();
                    if tcb.is_none() && flags & 0x12 != 0x12 && took {
                        assert_eq!(frames(&out), [(RST, ack, seq.wrapping_add(1), 0)]);
                        no_tcb_rst += 1;
                    }
                    if tcb.is_some() {
                        assert!(took, "a live TCB takes every segment");
                    }
                    if s.table_full > full_before {
                        assert!(!took && out.segments.is_empty());
                    }
                    peer_ends += usize::from(tcb.is_some() && s.tcbs_live < live);
                    records += out.banners.iter().map(Vec::len).sum::<usize>();
                    for key in st.table.keys() {
                        let Some(t) = st.table.tcb(&key) else {
                            continue;
                        };
                        assert!(t.queue_spans().len() <= SEND_QUEUE_MAX_SEGMENTS + 1);
                        let idx = ALL_STATES
                            .iter()
                            .position(|&x| x == t.state)
                            .expect("state");
                        seen[idx] += 1;
                    }
                }
            }
            let s = st.stats();
            created += s.tcbs_created;
            full += s.table_full;
            dropped += s.banner_bytes_dropped;
            // Конец: порции по 0-3, каждая продвигается, пока живые есть.
            for _ in 0..100 {
                let live = st.stats().tcbs_live;
                let max = rng.below(4);
                let mut out = StackOutput::default();
                let more = st.finish(max, &mut out);
                assert!(out.segments.is_empty());
                check_out(&out, &ttl_of);
                records += out.banners.iter().map(Vec::len).sum::<usize>();
                let left = st.stats().tcbs_live;
                assert_eq!(left, live.saturating_sub(max as u64));
                assert_eq!(more, left > 0);
                if !more {
                    break;
                }
            }
            assert_eq!(st.stats().tcbs_live, 0);
            assert_eq!(held.load(Ordering::Relaxed), 0, "every banner byte flushed");
            assert_eq!(
                st.table.budget().left(),
                budget,
                "the budget is whole again"
            );
        }
        assert!(
            created > 1000
                && full > 100
                && no_tcb_rst > 50
                && life_rst > 50
                && records > 1000
                && dropped > 0
                && peer_ends > 300
                && tick_ends > 300,
            "created {created}, full {full}, RST without TCB {no_tcb_rst}, lifetime RSTs {life_rst}, records \
             {records}, dropped {dropped}, peer ends {peer_ends}, ticks that destroyed {tick_ends}"
        );
        // Через таблицу доходят все состояния, кроме SYN_SENT: SYN-ACK сразу переводит новый блок в EST_RECV.
        for (state, n) in ALL_STATES.iter().zip(seen) {
            if *state == TcpState::SynSent {
                assert_eq!(n, 0);
            } else {
                assert!(n >= 300, "{state:?} seen {n} times; {seen:?}");
            }
        }
    }

    const ALL_STATES: [TcpState; 10] = [
        TcpState::SynSent,
        TcpState::EstablishedSend,
        TcpState::EstablishedRecv,
        TcpState::CloseWait,
        TcpState::LastAck,
        TcpState::FinWait1Send,
        TcpState::FinWait1Recv,
        TcpState::FinWait2,
        TcpState::Closing,
        TcpState::TimeWait,
    ];

    /// Адрес записи для ключа.
    fn records_ip(k: &ConnKey) -> IpAddr {
        match k.addrs {
            ConnAddrs::V4 { remote, .. } => IpAddr::V4(Ipv4Addr::from(remote)),
            ConnAddrs::V6 { remote, .. } => IpAddr::V6(Ipv6Addr::from(remote)),
        }
    }
}
