//! Таблица соединений и таймеры одного приёмного потока: `tcpcon_create_tcb`, `tcpcon_lookup_tcb`,
//! `tcpcon_destroy_tcb`, `tcpcon_destroy_table` и `tcpcon_timeouts` (`src/stack-tcp-core.c:280-330`, `:837-1101`).
//!
//! Записи есть только у живых соединений: по `capacity` ничего не выделяется заранее, полная таблица новое соединение
//! не создаёт (решение D7; у C предела нет, `:673-697`). Время событий это часы движка (Р6), в микросекундах.
//!
//! Таймер: у каждого живого блока ровно один срок ([`Tcb::deadline_micros`]) и одна запись в `timers`. Тик отдаётся
//! автомату со **своим запланированным** сроком, и следующий ставится через 2 с от него (`:322-327`), поэтому
//! опоздание обработки (итерация RX до 50 мс) не сдвигает ни сетку, ни проверку жизни: по умолчанию RST на тике
//! +32 с, при `--connection-timeout 6` на +8 с. C считает от времени обработки и сравнивает срок жизни в целых секундах
//! (`when_created + timeout_connection < secs`, `:1970-1980`); на этой сетке его RST приходится на тот же тик.
//! Единственный срок вне сетки 2 с это TIME_WAIT (FIN + 5 с): там C сравнивает целые секунды по фазе своих часов, и
//! RST или тихое уничтожение у него различаются в окне короче секунды; здесь проверка по микросекундам, детерминирована.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rmasscan_core::banner::BannerRecord;
use rmasscan_core::cookie::{syn_cookie_ipv4, syn_cookie_ipv6};
use rmasscan_core::stack::{ConnAddrs, ConnKey, SourceRanges, StackOutput, StackStats};

use super::app::{AppLayer, AppState, ByteBudget, Session, Sessions};
use super::tcb::{Tcb, TcbResult, What, incoming};

const SEC: u64 = 1_000_000;

/// Шаг тиков: повтор, `APP_RECV_TIMEOUT` и проверка жизни раз в 2 с (`src/stack-tcp-core.c:322-327`).
const TICK: u64 = 2 * SEC;

/// Соединение таблицы: блок, состояние приложения и сессия баннера (`tcb->app_state`, `tcb->stream`, `tcb->banout`).
pub(crate) struct Conn {
    /// Номер создания: порядок записей таймера с одним сроком.
    id: u64,
    pub(crate) tcb: Tcb,
    app: AppState,
    session: Box<dyn Session>,
}

/// Таблица соединений.
pub(crate) struct Table {
    conns: HashMap<ConnKey, Conn>,
    /// `(срок, номер) -> ключ`: ровно одна запись на живое соединение.
    timers: BTreeMap<(u64, u64), ConnKey>,
    sessions: Arc<dyn Sessions>,
    lifetime_secs: u32,
    capacity: usize,
    budget: ByteBudget,
    next_id: u64,
    created: u64,
    full: u64,
    seed: u64,
    source: SourceRanges,
    no_port: u64,
}

impl Table {
    pub(crate) fn new(
        sessions: Arc<dyn Sessions>,
        lifetime_secs: u32,
        capacity: usize,
        banner_byte_budget: usize,
        seed: u64,
        source: SourceRanges,
    ) -> Table {
        Table {
            conns: HashMap::new(),
            timers: BTreeMap::new(),
            sessions,
            lifetime_secs,
            capacity,
            budget: ByteBudget::new(banner_byte_budget),
            next_id: 0,
            created: 0,
            full: 0,
            seed,
            source,
            no_port: 0,
        }
    }

    pub(crate) fn contains(&self, key: &ConnKey) -> bool {
        self.conns.contains_key(key)
    }

    /// `tcpcon_create_tcb` для нового ключа (`src/stack-tcp-core.c:970-1060`, вызов `src/main.c:977-985`):
    /// `seqno_me` это их ACK, `seqno_them` их номер + 1, TTL SYN-ACK, таймер +1 с. Полная таблица: `false`,
    /// соединения нет, `table_full` растёт.
    pub(crate) fn create(
        &mut self,
        key: ConnKey,
        seqno_me: u32,
        seqno_them: u32,
        ttl: u8,
        now: u64,
    ) -> bool {
        if self.conns.contains_key(&key) {
            return true;
        }
        let session = self.sessions.new_session(key.remote_port);
        self.insert(key, seqno_me, seqno_them, ttl, now, session)
    }

    /// Вставка нового блока с готовой сессией; полная таблица: `false`, `table_full` растёт.
    fn insert(
        &mut self,
        key: ConnKey,
        seqno_me: u32,
        seqno_them: u32,
        ttl: u8,
        now: u64,
        session: Box<dyn Session>,
    ) -> bool {
        if self.conns.len() >= self.capacity {
            self.full = self.full.saturating_add(1);
            return false;
        }
        let mut tcb = Tcb::new(key, seqno_me, seqno_them, ttl, now);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let deadline = tcb.deadline_micros.unwrap_or(now).min(self.ceiling(&tcb));
        tcb.deadline_micros = Some(deadline);
        self.timers.insert((deadline, id), key);
        self.conns.insert(
            key,
            Conn {
                id,
                tcb,
                app: AppState::default(),
                session,
            },
        );
        self.created = self.created.saturating_add(1);
        true
    }

    /// `tcpapi_reconnect` в итоге события Connected (`_do_reconnect`, `src/stack-tcp-core.c:1646-1700`,
    /// справка §D1): следующий порт/адрес по `_next_IP_port`, cookie нового четырёхкортежа, блок в SYN_SENT
    /// с сессией второго соединения. Тот же адрес и порт — счётчик без порта; живой блок на новом ключе —
    /// его `app_state` снова Connect, как перезапись у C.
    fn reconnect(&mut self, old_key: &ConnKey, now: u64) {
        let Some((addrs, local_port)) = next_ip_port(old_key, &self.source) else {
            self.no_port = self.no_port.saturating_add(1);
            return;
        };
        if addrs == old_key.addrs && local_port == old_key.local_port {
            self.no_port = self.no_port.saturating_add(1);
            return;
        }
        let key = ConnKey {
            addrs,
            local_port,
            remote_port: old_key.remote_port,
        };
        if let Some(conn) = self.conns.get_mut(&key) {
            conn.app = AppState::Connect;
            return;
        }
        let Some(session) = self.sessions.new_reconnect_session(key.remote_port) else {
            return;
        };
        let cookie = match key.addrs {
            ConnAddrs::V4 { local, remote } => syn_cookie_ipv4(
                remote,
                u32::from(key.remote_port),
                local,
                u32::from(local_port),
                self.seed,
            ),
            ConnAddrs::V6 { local, remote } => syn_cookie_ipv6(
                remote,
                u32::from(key.remote_port),
                local,
                u32::from(local_port),
                self.seed,
            ),
        } as u32;
        let _ = self.insert(key, cookie.wrapping_add(1), 0, 255, now, session);
    }

    /// Последний срок блока: `created + lifetime + 2 с`, тик сетки 2 с, на котором автомат даёт RST по сроку жизни.
    /// C позволяет FIN в FIN_WAIT2 и TIME_WAIT отодвинуть таймер на 5 с (`src/stack-tcp-core.c:2249-2253`) и проверяет
    /// срок жизни только на таймауте (`:1970-1980`), поэтому собеседник, который шлёт FIN со следующим номером чаще
    /// раза в 5 с, держит блок у C вечно; здесь срок не позже этого.
    fn ceiling(&self, tcb: &Tcb) -> u64 {
        Self::ceiling_of(tcb, self.lifetime_secs)
    }

    fn ceiling_of(tcb: &Tcb, lifetime_secs: u32) -> u64 {
        let secs = u64::from(lifetime_secs).saturating_add(TICK / SEC);
        tcb.created_micros.saturating_add(secs.saturating_mul(SEC))
    }

    /// Одно событие `stack_incoming_tcp` соединения `key` (`src/stack-tcp-core.c:1910-2313`) в момент `at`.
    /// `None`: соединения нет. Наборы `banner_flush` идут в `out.banners`, кадры в `out.segments`. После `Destroyed`
    /// баннеры сбрасываются (`tcpcon_destroy_tcb`, `:874-877`), соединение и его таймер уходят. Перед TIMEOUT срок
    /// снимается; после `Okay` блок, которому автомат или приложение срок не поставили, получает тик через 2 с от `at`
    /// (`tcpcon_timeouts`, `:322-327`), и любой срок не позже [`Table::ceiling`].
    #[allow(
        clippy::too_many_arguments,
        reason = "аргументы stack_incoming_tcp C и выдача"
    )]
    pub(crate) fn event(
        &mut self,
        key: &ConnKey,
        what: What,
        payload: &[u8],
        seq: u32,
        ack: u32,
        at: u64,
        out: &mut StackOutput,
    ) -> Option<TcbResult> {
        let lifetime_secs = self.lifetime_secs;
        let conn = self.conns.get_mut(key)?;
        let id = conn.id;
        let ceiling = Self::ceiling_of(&conn.tcb, lifetime_secs);
        // Запись таймера трогается только при смене срока: ACK, DATA и FIN его обычно не двигают (горячий путь).
        let old = conn.tcb.deadline_micros;
        if what == What::Timeout {
            conn.tcb.deadline_micros = None;
        }
        let mut flushed = Vec::new();
        let r = {
            let mut app = AppLayer {
                state: &mut conn.app,
                session: conn.session.as_mut(),
                budget: &mut self.budget,
                flushed: &mut flushed,
            };
            incoming(
                &mut conn.tcb,
                &mut app,
                what,
                payload,
                seq,
                ack,
                at,
                self.lifetime_secs,
                &mut out.segments,
            )
        };
        let ttl = conn.tcb.ttl;
        let want_reconnect = conn.tcb.reconnect_pending;
        conn.tcb.reconnect_pending = false;
        for set in flushed {
            out.banners.push(records(key, ttl, set));
        }
        match r {
            TcbResult::Destroyed => {
                let set = conn.session.flush(&mut self.budget);
                if !set.is_empty() {
                    out.banners.push(records(key, ttl, set));
                }
                if let Some(d) = old {
                    self.timers.remove(&(d, id));
                }
                self.conns.remove(key);
            }
            TcbResult::Okay => {
                let deadline = conn
                    .tcb
                    .deadline_micros
                    .unwrap_or_else(|| at.saturating_add(TICK))
                    .min(ceiling);
                conn.tcb.deadline_micros = Some(deadline);
                if old != Some(deadline) {
                    if let Some(d) = old {
                        self.timers.remove(&(d, id));
                    }
                    self.timers.insert((deadline, id), *key);
                }
            }
        }
        if want_reconnect && r == TcbResult::Okay {
            self.reconnect(key, at);
        }
        Some(r)
    }

    /// `tcpcon_timeouts` (`src/stack-tcp-core.c:283-329`): каждый блок со сроком не позже `now`, по сроку, получает
    /// TIMEOUT со своими `seqno_them`, `ackno_them` (`:308-312`) и временем своего срока. Опоздание больше шага
    /// (остановка потока, скачок часов) не выдаёт пропущенные тики пачкой: тик идёт с последним сроком сетки не позже
    /// `now`, `срок + 2 с × ⌊(now − срок) / 2 с⌋`, поэтому каждый блок получает за вызов не больше одного тика, а
    /// проверка жизни смотрит на сетку. Сроки, поставленные за вызов, ждут следующего вызова.
    pub(crate) fn tick(&mut self, now: u64, out: &mut StackOutput) {
        let due: Vec<ConnKey> = self
            .timers
            .range(..=(now, u64::MAX))
            .map(|(_, key)| *key)
            .collect();
        for key in due {
            let Some(conn) = self.conns.get(&key) else {
                continue;
            };
            let Some(d) = conn.tcb.deadline_micros.filter(|&d| d <= now) else {
                continue;
            };
            let at = d + (now - d) / TICK * TICK;
            let (seq, ack) = (conn.tcb.seqno_them, conn.tcb.ackno_them);
            let _ = self.event(&key, What::Timeout, &[], seq, ack, at, out);
        }
    }

    /// Порция `tcpcon_destroy_table` (`src/stack-tcp-core.c:933-961`): до `max` живых соединений уничтожаются без
    /// кадров, их баннеры сбрасываются. Порядок по таймеру (у C по корзинам хэша, `:944-947`). `true`: живые остались.
    pub(crate) fn finish(&mut self, max: usize, out: &mut StackOutput) -> bool {
        let mut keys: Vec<ConnKey> = Vec::new();
        let mut stale: Vec<(u64, u64)> = Vec::new();
        for (&entry, key) in &self.timers {
            if keys.len() >= max {
                break;
            }
            if self.conns.contains_key(key) {
                keys.push(*key);
            } else {
                // Запись без соединения (инвариант «одна запись на живой блок» нарушен): убираем, чтобы не вернуться к ней.
                stale.push(entry);
            }
        }
        for entry in stale {
            self.timers.remove(&entry);
        }
        if keys.is_empty() && max > 0 {
            // Страховка: соединение без записи таймера всё равно уходит.
            keys.extend(self.conns.keys().take(max).copied());
        }
        for key in keys {
            let Some(mut conn) = self.conns.remove(&key) else {
                continue;
            };
            if let Some(d) = conn.tcb.deadline_micros {
                self.timers.remove(&(d, conn.id));
            }
            let set = conn.session.flush(&mut self.budget);
            if !set.is_empty() {
                out.banners.push(records(&key, conn.tcb.ttl, set));
            }
        }
        !self.conns.is_empty()
    }

    pub(crate) fn stats(&self) -> StackStats {
        StackStats {
            tcbs_created: self.created,
            tcbs_live: u64::try_from(self.conns.len()).unwrap_or(u64::MAX),
            table_full: self.full,
            banner_bytes_dropped: self.budget.dropped(),
            reconnect_no_port: self.no_port,
        }
    }

    #[cfg(test)]
    pub(crate) fn tcb(&self, key: &ConnKey) -> Option<&Tcb> {
        self.conns.get(key).map(|c| &c.tcb)
    }

    #[cfg(test)]
    pub(crate) fn budget(&self) -> ByteBudget {
        self.budget
    }

    /// Выделено под соединения: место в карте и записи таймеров.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> (usize, usize) {
        (self.conns.capacity(), self.timers.len())
    }

    /// Инварианты таблицы: не больше `capacity` соединений, у каждого один срок не позже последнего и одна запись
    /// таймера, лишних записей нет.
    #[cfg(test)]
    pub(crate) fn check(&self) {
        assert!(self.conns.len() <= self.capacity);
        assert_eq!(self.timers.len(), self.conns.len());
        for (key, conn) in &self.conns {
            let d = conn
                .tcb
                .deadline_micros
                .expect("every live TCB has a timer");
            assert_eq!(self.timers.get(&(d, conn.id)), Some(key));
            assert!(d <= self.ceiling(&conn.tcb));
        }
    }

    /// `created + lifetime + 2 с` соединения.
    #[cfg(test)]
    pub(crate) fn last_tick(&self, key: &ConnKey) -> Option<u64> {
        self.conns.get(key).map(|c| self.ceiling(&c.tcb))
    }

    #[cfg(test)]
    pub(crate) fn keys(&self) -> Vec<ConnKey> {
        self.conns.keys().copied().collect()
    }
}

/// `_next_IP_port` (`src/stack-tcp-core.c:1603-1644`): следующий порт в диапазоне; обёртка порта двигает
/// адрес. Диапазоны включительные; незаданный диапазон — только адрес и порт самого соединения. Порт `last`
/// следующим не бывает (`>= last` оборачивает), у IPv6 сравнение строгое (`last < ip`), как у C.
pub(crate) fn next_ip_port(key: &ConnKey, source: &SourceRanges) -> Option<(ConnAddrs, u16)> {
    let (first, last) = if source.ports == (0, 0) {
        (u32::from(key.local_port), u32::from(key.local_port))
    } else {
        (u32::from(source.ports.0), u32::from(source.ports.1))
    };
    let mut port = first + (u32::from(key.local_port).wrapping_sub(first) + 1);
    let mut addrs = key.addrs;
    if port >= last {
        port = first;
        addrs = match key.addrs {
            ConnAddrs::V4 { local, remote } => {
                let (f, l) = source.ipv4.unwrap_or((local, local));
                let mut ip = f.wrapping_add(local.wrapping_sub(f).wrapping_add(1));
                if ip >= l {
                    ip = f;
                }
                ConnAddrs::V4 { local: ip, remote }
            }
            ConnAddrs::V6 { local, remote } => {
                let (f, l) = source.ipv6.unwrap_or((local, local));
                let mut ip = f.wrapping_add(local.wrapping_sub(f).wrapping_add(1));
                if l < ip {
                    ip = f;
                }
                ConnAddrs::V6 { local: ip, remote }
            }
        };
    }
    Some((addrs, u16::try_from(port).ok()?))
}

/// Записи одного `banner_flush` (`src/stack-tcp-core.c:810-823`): адрес и порт сервера, `ip_proto` 6, TTL SYN-ACK;
/// время 0 (его ставит движок, как запись статуса).
fn records(key: &ConnKey, ttl: u8, set: Vec<(u16, Vec<u8>)>) -> Vec<BannerRecord> {
    let ip = match key.addrs {
        ConnAddrs::V4 { remote, .. } => IpAddr::V4(Ipv4Addr::from(remote)),
        ConnAddrs::V6 { remote, .. } => IpAddr::V6(Ipv6Addr::from(remote)),
    };
    set.into_iter()
        .map(|(app, payload)| BannerRecord {
            timestamp: 0,
            ip,
            ip_proto: 6,
            port: key.remote_port,
            app,
            ttl,
            payload,
        })
        .collect()
}
