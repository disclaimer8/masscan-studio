//! Одно соединение TCP: `struct TCP_Control_Block` и автомат `stack_incoming_tcp` (`src/stack-tcp-core.c:109-166`,
//! `:1910-2313`), справка A3-A5, F1. Порт побитовый (Р1): повторяются и странности C, которые детерминированы
//! (справка E3.2): одна голова в полёте, частичный ACK вешает отправку до RST по сроку жизни, данные в состояниях
//! SEND не принимаются и не подтверждаются, данные из будущего отбрасываются без ACK, двойные ACK.
//!
//! Отличия от C (с приложениями C ни одно не меняет кадров на входе, который C разбирает без неопределённого
//! поведения):
//! - частичный ACK сегмента `TCP__static` у C двигает указатель `seg->buf`, не уменьшая длину (`:1541-1543`, справка
//!   E1.1); здесь байты сегмента не трогаются. Повтор после этого отказывает у обоих; разница только если `seqno_me`
//!   обойдёт 2^32 и вернётся на голову: C тогда шлёт из-за конца буфера, rmasscan шлёт сегмент;
//! - `assert(payload_length < 2000)` на обрезанном повторе (`:1941`, справка E1.2) не переносится;
//! - очередь отправки ограничена ([`SEND_QUEUE_MAX_SEGMENTS`]); C без предела, но его приложения предела не достают.
//!
//! Не переносятся поля, которые C читает только в отладочном журнале: `ackno_me`, `seqno_me_first`,
//! `seqno_them_first` (`:240-263`, `:1451-1455`), и `syns_sent` переподключения (4c). Баннер, состояние парсера и поток
//! hello (`banout`, `banner1_state`, `stream`, `app_state`) живут у приложения ([`App`]).

use std::collections::VecDeque;

use rmasscan_core::stack::{ConnKey, SegmentOut};

/// Наибольший сегмент, который стек ставит в очередь: `tcb->mss = 1400` (`src/stack-tcp-core.c:1031`), окно и MSS
/// собеседника не смотрятся.
pub(crate) const MSS: usize = 1400;

/// Предел очереди отправки: сегментов с данными. У C предела нет (`_tcb_seg_send`, `src/stack-tcp-core.c:1359-1375`),
/// но очередь растёт только внутри одного вызова приложения в EST_RECV (в EST_SEND данные не принимаются, пока всё не
/// подтверждено), и больше всех из одного сегмента ставит SSH: строка версии и по блобу KEX на каждый 7-байтовый
/// пакет, 208 сегментов на 1460 байт (`src/proto-ssh.c:83-160`). Посылка за пределом отбрасывается в той же точке и так
/// же, как посылка за FIN (`:1359-1371`). FIN предел не держит: за FIN ничего не встаёт, поэтому он в очереди не больше
/// одного.
pub(crate) const SEND_QUEUE_MAX_SEGMENTS: usize = 512;

const SEC: u64 = 1_000_000;

/// Флаги кадров стека (справка A6).
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;
const FIN_ACK: u8 = 0x11;
const PSH_ACK: u8 = 0x18;
const FIN: u8 = 0x01;

/// Окно кадров блока с `is_small_window` (`tcp_set_window(..., 600)`, `src/stack-tcp-core.c:1163-1164`).
const SMALL_WINDOW: u16 = 600;

/// Таймер FIN в FIN_WAIT2 и TIME_WAIT (`src/stack-tcp-core.c:2249-2253`).
const TIME_WAIT_SECS: u64 = 5;

/// Состояния `tcpstate` (`src/stack-tcp-core.c:199-211`), в порядке C.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcpState {
    SynSent,
    EstablishedSend,
    EstablishedRecv,
    CloseWait,
    LastAck,
    FinWait1Send,
    FinWait1Recv,
    FinWait2,
    Closing,
    TimeWait,
}

/// Событие автомата, `enum TCP_What` (`src/stack-tcp-core.h:99-107`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum What {
    Timeout,
    SynAck,
    Rst,
    Fin,
    Ack,
    Data,
    Close,
}

/// Событие приложения, `enum App_Event` без `APP_SENDING`: данные доходят до `_tcb_seg_send` только из `tcpapi_send`,
/// который уже перевёл блок в EST_SEND, а уведомление идёт только вне EST_SEND (`src/stack-tcp-core.c:1397-1398`,
/// `:1769`; справка F1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppEvent {
    Connected,
    RecvTimeout,
    RecvPayload,
    SendSent,
    Close,
}

/// Итог события, `enum TCB_result` (`src/stack-tcp-core.h:109-112`). После `Destroyed` блок не живёт: очередь пуста,
/// таймер снят, таблица его убирает и сбрасывает баннеры (`tcpcon_destroy_tcb`, `:837-925`).
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TcbResult {
    Okay,
    Destroyed,
}

/// Как сегмент держит байты после частичного ACK (`enum TCP__flags`, `src/stack-tcp-api.h:8-13`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hold {
    /// `TCP__static`: hello (`src/stack-tcp-app.c:187`) и парсеры с флагом 0. Частичный ACK байтов не меняет.
    Static,
    /// `TCP__copy`: ответы telnet (`src/proto-tcp-telnet.c:248`). Частичный ACK укорачивает сегмент спереди.
    Copy,
}

/// `struct TCP_Segment` (`src/stack-tcp-core.c:92-99`). FIN это сегмент без байтов (`TCP__close_fin` всегда с длиной
/// 0), сегмент с байтами никогда не FIN.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    seqno: u32,
    data: Vec<u8>,
    hold: Hold,
    is_fin: bool,
}

impl Segment {
    /// `seg->length` в беззнаковой 32-битной арифметике номеров (сегмент не длиннее [`MSS`]).
    fn len32(&self) -> u32 {
        wrap32(self.data.len())
    }
}

/// `size_t` в `uint32_t` номеров по модулю 2^32, как присваивание C.
fn wrap32(n: usize) -> u32 {
    n as u32
}

/// Блок соединения (`struct TCP_Control_Block`, `src/stack-tcp-core.c:109-166`, справка A3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tcb {
    /// 4-кортеж `ip_me`, `ip_them`, `port_me`, `port_them`.
    pub(crate) key: ConnKey,
    pub(crate) state: TcpState,
    /// Следующий номер к отправке (он же первый неподтверждённый).
    pub(crate) seqno_me: u32,
    /// Следующий ожидаемый номер собеседника.
    pub(crate) seqno_them: u32,
    /// Номер, который собеседник подтвердил; двигается вместе с `seqno_me`.
    pub(crate) ackno_them: u32,
    pub(crate) is_their_fin: bool,
    /// Окно 600 вместо 1200 шаблона (heartbleed, 4c).
    pub(crate) is_small_window: bool,
    /// TTL SYN-ACK (`parsed.ip_ttl`, `src/main.c:982`) для записей баннеров.
    pub(crate) ttl: u8,
    segments: VecDeque<Segment>,
    /// `when_created`: время создания по часам движка (справка E1.8), в микросекундах.
    pub(crate) created_micros: u64,
    /// Срок таймера блока; `None` значит, что запись таймера отвязана (`timeout_unlink`). Таблица снимает срок перед
    /// событием `Timeout` и ставит +2 с, если автомат его не поставил (`tcpcon_timeouts`, `:314-327`).
    pub(crate) deadline_micros: Option<u64>,
}

impl Tcb {
    /// Новый блок, `tcpcon_create_tcb` (`src/stack-tcp-core.c:970-1060`): состояние SYN_SENT, `seqno_me = ackno_them`
    /// из ACK SYN-ACK, `seqno_them` это их номер + 1 (вызывающий уже прибавил, `src/main.c:978-983`), таймер +1 с
    /// (`:1035-1040`).
    pub(crate) fn new(
        key: ConnKey,
        seqno_me: u32,
        seqno_them: u32,
        ttl: u8,
        now_micros: u64,
    ) -> Tcb {
        Tcb {
            key,
            state: TcpState::SynSent,
            seqno_me,
            seqno_them,
            ackno_them: seqno_me,
            is_their_fin: false,
            is_small_window: false,
            ttl,
            segments: VecDeque::new(),
            created_micros: now_micros,
            deadline_micros: Some(now_micros.saturating_add(SEC)),
        }
    }
}

/// Приложение соединения: `application_event` (`src/stack-tcp-app.c:43-218`) и парсеры за ним. Вызывается из
/// автомата посреди события (`application_notify`, `src/stack-tcp-core.c:1317-1332`) и действует через [`TcbCtl`].
pub(crate) trait App {
    fn on_event(&mut self, ctl: &mut TcbCtl<'_>, ev: AppEvent, payload: &[u8]);
}

/// Что приложение может сделать с соединением из обработчика события: `stack_handle_t` (`src/stack-tcp-api.h:20-25`)
/// и `tcpapi_*` (`src/stack-tcp-core.c:1712-1820`). Время события едет с ним, как `socket->secs`.
pub(crate) struct TcbCtl<'a> {
    tcb: &'a mut Tcb,
    out: &'a mut Vec<SegmentOut>,
    at_micros: u64,
    lifetime_secs: u32,
}

impl TcbCtl<'_> {
    /// `tcpapi_send(socket, buf, length, TCP__static)` (`src/stack-tcp-core.c:1757-1778`): EST_RECV сначала переходит в
    /// EST_SEND, в EST_SEND байты встают в очередь, и голова уходит сразу. В остальных состояниях отказ (`false`, у C
    /// `return 1` и `"TCP app attempted SEND in wrong state\n"`). `true` не значит, что байты встали: пустая посылка,
    /// посылка за FIN и за пределом очереди отбрасываются молча, как у C (`:1356-1371`).
    pub(crate) fn send(&mut self, bytes: &[u8]) -> bool {
        self.send_held(bytes, Hold::Static)
    }

    /// То же с `TCP__copy`, флагом ответов telnet (`src/proto-tcp-telnet.c:248`): разница только в частичном ACK
    /// (`src/stack-tcp-core.c:1533-1540`).
    pub(crate) fn send_copy(&mut self, bytes: &[u8]) -> bool {
        self.send_held(bytes, Hold::Copy)
    }

    fn send_held(&mut self, bytes: &[u8], hold: Hold) -> bool {
        match self.tcb.state {
            TcpState::EstablishedRecv | TcpState::EstablishedSend => {
                self.tcb.state = TcpState::EstablishedSend;
                seg_send(self.tcb, self.out, bytes, hold, false);
                true
            }
            _ => false,
        }
    }

    /// `tcpapi_recv` (`src/stack-tcp-core.c:1734-1755`): FIN_WAIT1_SEND и FIN_WAIT1_RECV переходят в FIN_WAIT1_RECV,
    /// любое другое состояние в EST_RECV (`default:` стоит при `case STATE_ESTABLISHED_SEND`).
    pub(crate) fn recv(&mut self) {
        self.tcb.state = match self.tcb.state {
            TcpState::FinWait1Send | TcpState::FinWait1Recv => TcpState::FinWait1Recv,
            _ => TcpState::EstablishedRecv,
        };
    }

    /// `tcpapi_close` (`src/stack-tcp-core.c:1811-1820`): событие CLOSE в тот же блок с его же номерами
    /// (`_tcb_seg_close`, `:1697-1708`), итог не смотрится. Ни одна ветка CLOSE приложению не пишет и блок не
    /// уничтожает, поэтому событие идёт через приложение без реакций и глубина вызова одна.
    pub(crate) fn close(&mut self) {
        let (seq, ack) = (self.tcb.seqno_them, self.tcb.ackno_them);
        let _ = incoming(
            self.tcb,
            &mut NoApp,
            What::Close,
            &[],
            seq,
            ack,
            self.at_micros,
            self.lifetime_secs,
            self.out,
        );
    }

    /// `tcpapi_set_timeout(socket, secs, 0)` (`src/stack-tcp-core.c:1712-1729`): срок от времени события
    /// (`socket->secs + secs`), прежний срок заменяется (`timeouts_add`, `src/event-timeout.c:113-116`).
    pub(crate) fn set_timeout(&mut self, secs: u32) {
        self.tcb.deadline_micros = Some(after(self.at_micros, u64::from(secs)));
    }
}

/// Приложение без реакций для CLOSE из [`TcbCtl::close`].
struct NoApp;

impl App for NoApp {
    fn on_event(&mut self, _ctl: &mut TcbCtl<'_>, _ev: AppEvent, _payload: &[u8]) {}
}

/// Время события и срок жизни, которые несёт каждое уведомление приложения.
#[derive(Clone, Copy)]
struct Cx {
    at_micros: u64,
    lifetime_secs: u32,
}

fn after(at_micros: u64, secs: u64) -> u64 {
    at_micros.saturating_add(secs.saturating_mul(SEC))
}

/// `stack_incoming_tcp` (`src/stack-tcp-core.c:1910-2313`): одно событие блока. `seq` и `ack` это `seqno_them` и
/// `ackno_them` C: номер и ACK сегмента собеседника; у `Fin` номер FIN (за данными сегмента), у `Timeout` и `Close`
/// номера самого блока. `at_micros` это время события: у `Timeout` **запланированный** срок тика (решение S1), у
/// остальных текущее время. `lifetime_secs` это `timeout_connection` (`--connection-timeout`, по умолчанию 30).
/// Кадры дописываются в `out` в порядке отправки.
///
/// Пролог (`:1917-1987`) для каждого события: нагрузка из прошлого целиком отбрасывается без ACK, частично старая
/// обрезается, из будущего отбрасывается без ACK (сборки нет); FIN с номером на 1 меньше ожидаемого это повтор, ему
/// ACK, FIN с любым другим неожиданным номером отбрасывается; `Timeout` позже `created + lifetime` даёт RST и
/// уничтожение; `Rst` уничтожает без кадра и без проверки номера. Дальше таблица состояний справки A4.
#[allow(
    clippy::too_many_arguments,
    reason = "аргументы stack_incoming_tcp C, набор закреплён планом подэтапа"
)]
pub(crate) fn incoming(
    tcb: &mut Tcb,
    app: &mut dyn App,
    what: What,
    payload: &[u8],
    seq: u32,
    ack: u32,
    at_micros: u64,
    lifetime_secs: u32,
    out: &mut Vec<SegmentOut>,
) -> TcbResult {
    use TcpState as St;
    use What as W;
    let cx = Cx {
        at_micros,
        lifetime_secs,
    };
    let mut payload = payload;
    let mut seq = seq;

    // FILTER: нагрузка не по порядку (`:1917-1949`). `int payload_offset = seqno_them - tcb->seqno_them`.
    if !payload.is_empty() {
        let offset = i64::from(seq.wrapping_sub(tcb.seqno_them) as i32);
        let len = i64::try_from(payload.len()).unwrap_or(i64::MAX);
        if offset < 0 {
            if offset <= -len {
                // Начало и конец в прошлом: отбросить, без ACK.
                return TcbResult::Okay;
            }
            // Укоротить спереди; `seqno_them -= payload_offset` даёт ровно `tcb->seqno_them`. Assert `:1941` не
            // переносится (справка E1.2).
            let skip = usize::try_from(offset.unsigned_abs()).unwrap_or(usize::MAX);
            payload = payload.get(skip..).unwrap_or(&[]);
            seq = tcb.seqno_them;
        } else if offset > 0 {
            // Из будущего: собеседник повторит, без ACK.
            return TcbResult::Okay;
        }
    }

    // FILTER: FIN не по порядку и повтор FIN (`:1951-1966`).
    if what == W::Fin {
        if seq == tcb.seqno_them.wrapping_sub(1) {
            send_ack(tcb, out);
            return TcbResult::Okay;
        } else if seq != tcb.seqno_them {
            return TcbResult::Okay;
        }
    }

    // Срок жизни (`:1970-1980`): `when_created + timeout_connection < secs`, здесь против запланированного срока тика.
    if what == W::Timeout && cx.at_micros > after(tcb.created_micros, u64::from(cx.lifetime_secs)) {
        send_packet(tcb, out, RST, &[]);
        return destroy(tcb);
    }

    if what == W::Rst {
        return destroy(tcb);
    }

    // Таблица состояний (`:1999-2311`). Пары, которых нет в ветке, у C печатают `"%s:%s **** UNHANDLED EVENT ****\n"`
    // и ничего не делают (`_ => {}` ниже).
    match tcb.state {
        St::SynSent => match what {
            // Переподключение (4c): SYN ещё раз (`:2005-2012`).
            W::Timeout => send_packet(tcb, out, SYN, &[]),
            W::SynAck => {
                // `:2013-2026`.
                tcb.seqno_them = seq;
                tcb.seqno_me = ack;
                send_ack(tcb, out);
                tcb.state = St::EstablishedRecv;
                notify(tcb, app, out, cx, AppEvent::Connected, &[]);
            }
            _ => {}
        },

        St::EstablishedSend => match what {
            W::Close => {
                seg_send(tcb, out, &[], Hold::Static, true);
                tcb.state = St::FinWait1Send;
            }
            W::Fin => {
                // `:2042-2052`: второй ACK вслед за ACK `_tcb_seg_recv`; ветка `else` после фильтра FIN недостижима.
                if seq == tcb.seqno_them {
                    seg_recv(tcb, app, out, cx, &[], seq, true);
                    tcb.state = St::FinWait1Send;
                    send_ack(tcb, out);
                } else {
                    send_ack(tcb, out);
                }
            }
            W::Ack => {
                // `:2053-2066`: итог подтверждения не смотрится, решает только очередь.
                seg_acknowledge(tcb, ack);
                if head_is_empty(tcb) {
                    tcb.state = St::EstablishedRecv;
                    notify(tcb, app, out, cx, AppEvent::SendSent, &[]);
                }
            }
            W::Timeout => seg_resend(tcb, out),
            // Данные в EST_SEND не принимаются: собеседник повторит (`:2071-2076`).
            W::Data | W::SynAck => {}
            _ => {}
        },

        St::EstablishedRecv => match what {
            W::Close => {
                seg_send(tcb, out, &[], Hold::Static, true);
                tcb.state = St::FinWait1Recv;
            }
            W::Fin => {
                if seq == tcb.seqno_them {
                    seg_recv(tcb, app, out, cx, &[], seq, true);
                    tcb.state = St::CloseWait;
                    // `application_notify(..., APP_CLOSE, 0, payload_length, ...)`: нагрузки у FIN нет.
                    notify(tcb, app, out, cx, AppEvent::Close, &[]);
                } else {
                    send_ack(tcb, out);
                }
            }
            W::Ack => {
                seg_acknowledge(tcb, ack);
            }
            W::Timeout => notify(tcb, app, out, cx, AppEvent::RecvTimeout, &[]),
            W::Data => seg_recv(tcb, app, out, cx, payload, seq, false),
            // Запоздалый SYN-ACK (`:2115-2120`).
            W::SynAck => {}
            _ => {}
        },

        St::FinWait1Send => match what {
            W::Fin => {}
            W::Ack => {
                if seg_acknowledge(tcb, ack) && head_is_empty(tcb) {
                    tcb.state = St::FinWait1Recv;
                    notify(tcb, app, out, cx, AppEvent::SendSent, &[]);
                }
            }
            W::Timeout => seg_resend(tcb, out),
            W::Data => {}
            _ => {}
        },

        St::FinWait1Recv => match what {
            W::Fin => {
                seg_recv(tcb, app, out, cx, &[], seq, true);
                tcb.state = St::Closing;
                send_ack(tcb, out);
                notify(tcb, app, out, cx, AppEvent::Close, &[]);
            }
            W::Ack => {
                if seg_acknowledge(tcb, ack) && they_have_acked_my_fin(tcb) {
                    tcb.state = St::FinWait2;
                    notify(tcb, app, out, cx, AppEvent::Close, &[]);
                }
            }
            W::Timeout => seg_resend(tcb, out),
            W::Data => seg_recv(tcb, app, out, cx, payload, seq, false),
            _ => {}
        },

        St::Closing => match what {
            W::Timeout => return destroy(tcb),
            W::Ack => {
                seg_acknowledge(tcb, ack);
                if they_have_acked_my_fin(tcb) {
                    return destroy(tcb);
                }
            }
            // Их FIN уже подтверждён, но ещё раз (`:2212-2215`).
            W::Fin => send_ack(tcb, out),
            // Второй `tcpapi_close` приложения, молча (`:2216-2222`).
            W::Close => {}
            _ => {}
        },

        St::FinWait2 | St::TimeWait => match what {
            W::Timeout => {
                if tcb.state == St::TimeWait {
                    return destroy(tcb);
                }
            }
            W::Fin => {
                seg_recv(tcb, app, out, cx, &[], seq, true);
                tcb.state = St::TimeWait;
                tcb.deadline_micros = Some(after(cx.at_micros, TIME_WAIT_SECS));
            }
            // ACK, SYN-ACK, RST, DATA и CLOSE (`:2241-2263`): данные здесь не подтверждаются.
            _ => {}
        },

        St::CloseWait => match what {
            W::Close => {
                seg_send(tcb, out, &[], Hold::Static, true);
                tcb.state = St::LastAck;
            }
            // Напоминание приложению, что его ждут (`:2277-2281`).
            W::Timeout => notify(tcb, app, out, cx, AppEvent::Close, &[]),
            _ => {}
        },

        St::LastAck => match what {
            W::Timeout => seg_resend(tcb, out),
            W::Ack => {
                // Хороший ACK уничтожает блок, даже если он снял данные перед FIN, а не сам FIN (`:2294-2298`).
                let good = seg_acknowledge(tcb, ack);
                if good {
                    return destroy(tcb);
                }
            }
            _ => {}
        },
    }
    TcbResult::Okay
}

/// Уничтожение блока со стороны автомата: очередь освобождена, таймер отвязан (`tcpcon_destroy_tcb`, `:884-909`).
/// Сброс баннеров и удаление из таблицы делает тот, кто получил `Destroyed`.
fn destroy(tcb: &mut Tcb) -> TcbResult {
    tcb.segments.clear();
    tcb.deadline_micros = None;
    TcbResult::Destroyed
}

/// `tcpcon_send_packet` (`src/stack-tcp-core.c:1107-1171`): seq `seqno_me - is_syn`, ack `seqno_them`.
fn send_packet(tcb: &Tcb, out: &mut Vec<SegmentOut>, flags: u8, payload: &[u8]) {
    let is_syn = flags == SYN;
    out.push(SegmentOut {
        key: tcb.key,
        seq: tcb.seqno_me.wrapping_sub(u32::from(is_syn)),
        ack: tcb.seqno_them,
        flags,
        payload: payload.to_vec(),
        window: tcb.is_small_window.then_some(SMALL_WINDOW),
    });
}

/// `_tcb_send_ack` (`src/stack-tcp-core.c:1835-1838`).
fn send_ack(tcb: &Tcb, out: &mut Vec<SegmentOut>) {
    send_packet(tcb, out, ACK, &[]);
}

/// `application_notify` (`src/stack-tcp-core.c:1316-1332`).
fn notify(
    tcb: &mut Tcb,
    app: &mut dyn App,
    out: &mut Vec<SegmentOut>,
    cx: Cx,
    ev: AppEvent,
    payload: &[u8],
) {
    let mut ctl = TcbCtl {
        tcb,
        out,
        at_micros: cx.at_micros,
        lifetime_secs: cx.lifetime_secs,
    };
    app.on_event(&mut ctl, ev, payload);
}

/// `tcb->segments == NULL || tcb->segments->length == 0` (`src/stack-tcp-core.c:2056`, `:2149`).
fn head_is_empty(tcb: &Tcb) -> bool {
    tcb.segments.front().is_none_or(|s| s.data.is_empty())
}

/// `_tcb_they_have_acked_my_fin` (`src/stack-tcp-core.c:1824-1832`): сравнение беззнаковое, не по кругу номеров.
fn they_have_acked_my_fin(tcb: &Tcb) -> bool {
    match tcb.segments.front() {
        Some(s) if s.is_fin && s.data.is_empty() => tcb.ackno_them >= s.seqno.wrapping_add(1),
        _ => false,
    }
}

/// `_tcb_seg_send` (`src/stack-tcp-core.c:1337-1427`); рекурсия по хвосту длиннее [`MSS`] развёрнута в цикл.
fn seg_send(tcb: &mut Tcb, out: &mut Vec<SegmentOut>, buf: &[u8], hold: Hold, is_fin: bool) {
    let mut rest = buf;
    loop {
        let (chunk, more) = rest
            .split_at_checked(rest.len().min(MSS))
            .unwrap_or((rest, &[]));
        if chunk.is_empty() && !is_fin {
            return;
        }
        // "can't send past a FIN" (`:1359-1371`): эта посылка и её хвост отбрасываются.
        if tcb.segments.iter().any(|s| s.is_fin) {
            return;
        }
        // Предел rmasscan, в той же точке и так же.
        if !is_fin && tcb.segments.len() >= SEND_QUEUE_MAX_SEGMENTS {
            return;
        }
        let seqno = tcb
            .segments
            .back()
            .map_or(tcb.seqno_me, |s| s.seqno.wrapping_add(s.len32()));
        tcb.segments.push_back(Segment {
            seqno,
            data: chunk.to_vec(),
            hold,
            is_fin: is_fin && more.is_empty(),
        });
        // `APP_SENDING` (`:1397-1398`) не шлётся: сюда данные приходят только в EST_SEND, FIN его не шлёт (справка F1).
        // Голова очереди уходит сразу (`:1405-1412`).
        if tcb.segments.len() == 1 {
            send_packet(tcb, out, PSH_ACK | if is_fin { FIN } else { 0 }, chunk);
            if !is_fin {
                tcb.state = TcpState::EstablishedSend;
            }
        }
        if more.is_empty() {
            return;
        }
        rest = more;
    }
}

/// `_tcb_seg_resend` (`src/stack-tcp-core.c:1289-1312`): повтор головы; если `seqno_me` ушёл от номера головы
/// (частичный ACK), у C `"SEQNO FAILURE diff=%d %s\n"` и ничего.
fn seg_resend(tcb: &Tcb, out: &mut Vec<SegmentOut>) {
    let Some(seg) = tcb.segments.front() else {
        return;
    };
    if tcb.seqno_me != seg.seqno {
        return;
    }
    if seg.is_fin && seg.data.is_empty() {
        send_packet(tcb, out, FIN_ACK, &[]);
    } else {
        send_packet(
            tcb,
            out,
            PSH_ACK | if seg.is_fin { FIN } else { 0 },
            &seg.data,
        );
    }
}

/// `_tcp_seg_acknowledge` (`src/stack-tcp-core.c:1431-1550`): `true`, если ACK "хороший".
fn seg_acknowledge(tcb: &mut Tcb, ackno: u32) -> bool {
    // Повтор текущего ACK.
    if ackno == tcb.seqno_me {
        return false;
    }
    // Из прошлого (по кругу номеров).
    if ackno.wrapping_sub(tcb.seqno_me) > 100_000 {
        return false;
    }
    // "Из будущего" (`:1461`): после проверки выше не срабатывает никогда, оставлено как у C.
    if tcb.seqno_me.wrapping_sub(ackno) < 100_000 {
        return false;
    }
    if tcb.segments.front().is_some_and(|s| s.is_fin) {
        return ack_fin(tcb, ackno);
    }
    // Снять подтверждённые целиком сегменты (`:1489-1523`).
    let mut length = ackno.wrapping_sub(tcb.seqno_me);
    while let Some(seg) = tcb.segments.front() {
        let seg_len = seg.len32();
        if length < seg_len {
            break;
        }
        if seg.is_fin {
            return ack_fin(tcb, ackno);
        }
        tcb.segments.pop_front();
        length -= seg_len;
        tcb.seqno_me = tcb.seqno_me.wrapping_add(seg_len);
        tcb.ackno_them = tcb.ackno_them.wrapping_add(seg_len);
        if ackno == tcb.ackno_them {
            return true;
        }
    }
    // Частичный ACK головы (`:1525-1545`): `seqno_me` уходит вперёд, номер головы нет, и повтор отказывает.
    if let Some(seg) = tcb.segments.front_mut()
        && length < seg.len32()
    {
        let moved = length.wrapping_add(u32::from(seg.is_fin));
        tcb.seqno_me = tcb.seqno_me.wrapping_add(moved);
        tcb.ackno_them = tcb.ackno_them.wrapping_add(moved);
        match seg.hold {
            // `seg->buf += length` без длины: здесь байты не трогаются (справка E1.1).
            Hold::Static => {}
            Hold::Copy => {
                let cut = usize::try_from(length)
                    .unwrap_or(usize::MAX)
                    .min(seg.data.len());
                seg.data.drain(..cut);
            }
        }
    }
    true
}

/// Метка `handle_fin` (`src/stack-tcp-core.c:1471-1487`): FIN в голове подтверждается только ровно на 1 за ним и
/// остаётся в очереди для `_tcb_they_have_acked_my_fin`.
fn ack_fin(tcb: &mut Tcb, ackno: u32) -> bool {
    match tcb.segments.front() {
        Some(seg) if seg.seqno.wrapping_add(1) == ackno => {
            tcb.seqno_me = tcb.seqno_me.wrapping_add(1);
            tcb.ackno_them = tcb.ackno_them.wrapping_add(1);
            true
        }
        _ => false,
    }
}

/// `_tcb_seg_recv` (`src/stack-tcp-core.c:1842-1899`). Приложение получает нагрузку раньше, чем уходит её ACK, поэтому
/// ответ парсера идёт на провод первым.
fn seg_recv(
    tcb: &mut Tcb,
    app: &mut dyn App,
    out: &mut Vec<SegmentOut>,
    cx: Cx,
    payload: &[u8],
    seqno_them: u32,
    is_fin: bool,
) {
    let behind = tcb.seqno_them.wrapping_sub(seqno_them);
    // Только FIN, ровно на месте (`:1850-1857`).
    if payload.is_empty() && is_fin && behind == 0 {
        tcb.is_their_fin = true;
        tcb.seqno_them = tcb.seqno_them.wrapping_add(1);
        send_ack(tcb, out);
        return;
    }
    // Старые данные: ACK (`:1860-1864`; из `stack_incoming_tcp` сюда не попасть, пролог отбросил их раньше).
    if u64::from(behind) > u64::try_from(payload.len()).unwrap_or(u64::MAX) {
        send_ack(tcb, out);
        return;
    }
    // Цикл `:1866-1870` сдвигает начало до `tcb->seqno_them`: ровно `behind` байт, их не больше длины.
    let payload = payload
        .get(usize::try_from(behind).unwrap_or(usize::MAX)..)
        .unwrap_or(&[]);
    // После их FIN нагрузка не принимается и не подтверждается (`:1872-1875`).
    if tcb.is_their_fin {
        return;
    }
    if payload.is_empty() {
        send_ack(tcb, out);
        return;
    }
    tcb.seqno_them = tcb
        .seqno_them
        .wrapping_add(wrap32(payload.len()))
        .wrapping_add(u32::from(is_fin));
    notify(tcb, app, out, cx, AppEvent::RecvPayload, payload);
    if is_fin {
        tcb.is_their_fin = true;
    }
    send_ack(tcb, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmasscan_core::stack::ConnAddrs;

    const KEY: ConnKey = ConnKey {
        addrs: ConnAddrs::V4 {
            local: 0x0a00_0001,
            remote: 0x0a00_0002,
        },
        local_port: 40000,
        remote_port: 80,
    };
    /// `seqno_me` и `seqno_them` нового блока: наш ISN + 1 и их ISN + 1.
    const S: u32 = 0x1000_0000;
    const R: u32 = 0x2000_0000;
    /// Время создания блока и срок жизни по умолчанию (`timeout_connection` 30, `src/stack-tcp-core.c:665-667`).
    const T0: u64 = 1_700_000_000_000_000;
    const LIFE: u32 = 30;

    /// Кадр в сравнении: флаги, seq, ack, длина нагрузки.
    type F = (u8, u32, u32, usize);

    fn frames(out: &[SegmentOut]) -> Vec<F> {
        out.iter()
            .map(|s| {
                assert_eq!(s.key, KEY);
                assert_eq!(s.window, None);
                (s.flags, s.seq, s.ack, s.payload.len())
            })
            .collect()
    }

    /// Приложение, которое записывает события и делает на них то, что велит `react`.
    struct Rec<Fr> {
        events: Vec<(AppEvent, Vec<u8>)>,
        react: Fr,
    }

    impl<Fr: FnMut(&mut TcbCtl<'_>, AppEvent, &[u8])> App for Rec<Fr> {
        fn on_event(&mut self, ctl: &mut TcbCtl<'_>, ev: AppEvent, payload: &[u8]) {
            self.events.push((ev, payload.to_vec()));
            (self.react)(ctl, ev, payload);
        }
    }

    fn rec<Fr: FnMut(&mut TcbCtl<'_>, AppEvent, &[u8])>(react: Fr) -> Rec<Fr> {
        Rec {
            events: Vec::new(),
            react,
        }
    }

    fn idle() -> Rec<impl FnMut(&mut TcbCtl<'_>, AppEvent, &[u8])> {
        rec(|_, _, _| {})
    }

    fn kinds<Fr>(app: &Rec<Fr>) -> Vec<AppEvent> {
        app.events.iter().map(|e| e.0).collect()
    }

    fn tcb_in(state: TcpState) -> Tcb {
        let mut t = Tcb::new(KEY, S, R, 64, T0);
        t.state = state;
        t
    }

    fn data_seg(seqno: u32, n: usize) -> Segment {
        Segment {
            seqno,
            data: vec![b'd'; n],
            hold: Hold::Static,
            is_fin: false,
        }
    }

    fn fin_seg(seqno: u32) -> Segment {
        Segment {
            seqno,
            data: Vec::new(),
            hold: Hold::Static,
            is_fin: true,
        }
    }

    #[allow(clippy::too_many_arguments, reason = "те же аргументы, что у incoming")]
    fn step(
        t: &mut Tcb,
        app: &mut dyn App,
        what: What,
        payload: &[u8],
        seq: u32,
        ack: u32,
        at: u64,
    ) -> (TcbResult, Vec<SegmentOut>) {
        let mut out = Vec::new();
        let r = incoming(t, app, what, payload, seq, ack, at, LIFE, &mut out);
        (r, out)
    }

    /// Тик таймера: `tcpcon_timeouts` отдаёт `tcb->seqno_them, tcb->ackno_them` (`src/stack-tcp-core.c:308-312`).
    fn tick(t: &mut Tcb, app: &mut dyn App, at: u64) -> (TcbResult, Vec<SegmentOut>) {
        let (seq, ack) = (t.seqno_them, t.ackno_them);
        step(t, app, What::Timeout, &[], seq, ack, at)
    }

    fn ack_of(t: &mut Tcb, app: &mut dyn App, ack: u32, at: u64) -> (TcbResult, Vec<SegmentOut>) {
        let seq = t.seqno_them;
        step(t, app, What::Ack, &[], seq, ack, at)
    }

    #[test]
    fn new_mirrors_tcpcon_create_tcb() {
        let t = Tcb::new(KEY, S, R, 57, T0);
        assert_eq!(t.state, TcpState::SynSent);
        assert_eq!((t.seqno_me, t.ackno_them, t.seqno_them), (S, S, R));
        assert_eq!(t.ttl, 57);
        assert!(!t.is_their_fin && !t.is_small_window);
        assert!(t.segments.is_empty());
        assert_eq!(t.created_micros, T0);
        // Таймер +1 с при создании (`src/stack-tcp-core.c:1035-1040`).
        assert_eq!(t.deadline_micros, Some(T0 + SEC));
    }

    #[derive(Clone, Copy)]
    enum Q {
        Empty,
        /// 10 байт с `S`.
        Data,
        /// FIN на `S`.
        Fin,
        /// 10 байт с `S`, FIN на `S + 10`.
        DataFin,
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Next {
        Same,
        To(TcpState),
        Destroyed,
    }

    #[derive(Clone, Copy)]
    enum Dl {
        /// Таймер создания не тронут.
        Keep,
        /// +5 с от времени события (`src/stack-tcp-core.c:2249-2253`).
        Plus5,
        /// Снят уничтожением (`timeout_unlink`, `:909`).
        Gone,
    }

    /// Строка справки A4: состояние и очередь до, событие, кадры, следующее состояние, события приложения, номера
    /// `(seqno_me, seqno_them)` после, длина очереди после и таймер.
    #[derive(Clone, Copy)]
    struct Row {
        cite: &'static str,
        state: TcpState,
        queue: Q,
        what: What,
        payload: &'static [u8],
        seq: u32,
        ack: u32,
        at: u64,
        frames: &'static [F],
        next: Next,
        events: &'static [(AppEvent, &'static [u8])],
        after: Option<(u32, u32)>,
        queue_after: Option<usize>,
        deadline: Dl,
    }

    const BASE: Row = Row {
        cite: "",
        state: TcpState::EstablishedRecv,
        queue: Q::Empty,
        what: What::Timeout,
        payload: b"",
        seq: R,
        ack: S,
        at: T0 + 2 * SEC,
        frames: &[],
        next: Next::Same,
        events: &[],
        after: None,
        queue_after: None,
        deadline: Dl::Keep,
    };

    use AppEvent as E;
    use TcpState as St;
    use What as W;

    /// Каждая строка справки A4 (и пролог), сверенные с `src/stack-tcp-core.c` (ссылки в `cite`). Приложение молчит.
    const ROWS: &[Row] = &[
        // SYN_SENT.
        Row {
            cite: ":2005-2012 SYN_SENT TIMEOUT -> SYN, seq seqno_me-1 (:1114, :1154)",
            state: St::SynSent,
            frames: &[(0x02, S - 1, R, 0)],
            ..BASE
        },
        Row {
            cite: ":2013-2026 SYN_SENT SYNACK -> ACK, EST_RECV, CONNECTED",
            state: St::SynSent,
            what: W::SynAck,
            seq: R + 5,
            ack: S + 7,
            frames: &[(0x10, S + 7, R + 5, 0)],
            next: Next::To(St::EstablishedRecv),
            events: &[(E::Connected, b"")],
            after: Some((S + 7, R + 5)),
            ..BASE
        },
        Row {
            cite: ":2027-2031 SYN_SENT ACK unhandled",
            state: St::SynSent,
            what: W::Ack,
            ack: S + 3,
            ..BASE
        },
        Row {
            cite: ":2027-2031 SYN_SENT DATA unhandled",
            state: St::SynSent,
            what: W::Data,
            payload: b"x",
            ..BASE
        },
        Row {
            cite: ":2027-2031 SYN_SENT FIN unhandled",
            state: St::SynSent,
            what: W::Fin,
            ..BASE
        },
        Row {
            cite: ":2027-2031 SYN_SENT CLOSE unhandled",
            state: St::SynSent,
            what: W::Close,
            ..BASE
        },
        // ESTABLISHED_SEND.
        Row {
            cite: ":2038-2041, :1405-1412 EST_SEND CLOSE, empty queue -> FIN head now 0x19",
            state: St::EstablishedSend,
            what: W::Close,
            frames: &[(0x19, S, R, 0)],
            next: Next::To(St::FinWait1Send),
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2038-2041, :1405 EST_SEND CLOSE behind data -> FIN queued, not sent",
            state: St::EstablishedSend,
            queue: Q::Data,
            what: W::Close,
            next: Next::To(St::FinWait1Send),
            queue_after: Some(2),
            ..BASE
        },
        Row {
            cite: ":2042-2047, :1851-1856 EST_SEND FIN -> ACK + second ACK, no APP_CLOSE",
            state: St::EstablishedSend,
            what: W::Fin,
            frames: &[(0x10, S, R + 1, 0), (0x10, S, R + 1, 0)],
            next: Next::To(St::FinWait1Send),
            after: Some((S, R + 1)),
            ..BASE
        },
        Row {
            cite: ":2053-2065, :1492-1522 EST_SEND ACK of all -> EST_RECV, SEND_SENT",
            state: St::EstablishedSend,
            queue: Q::Data,
            what: W::Ack,
            ack: S + 10,
            next: Next::To(St::EstablishedRecv),
            events: &[(E::SendSent, b"")],
            after: Some((S + 10, R)),
            queue_after: Some(0),
            ..BASE
        },
        Row {
            cite: ":2053-2065, :1525-1545 EST_SEND partial ACK -> seqno_me moves, stays",
            state: St::EstablishedSend,
            queue: Q::Data,
            what: W::Ack,
            ack: S + 4,
            after: Some((S + 4, R)),
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2053-2065, :1443-1445 EST_SEND duplicate ACK, empty queue: result ignored -> SEND_SENT",
            state: St::EstablishedSend,
            what: W::Ack,
            next: Next::To(St::EstablishedRecv),
            events: &[(E::SendSent, b"")],
            ..BASE
        },
        Row {
            cite: ":2056 EST_SEND ACK, head is the FIN (length 0) -> SEND_SENT",
            state: St::EstablishedSend,
            queue: Q::Fin,
            what: W::Ack,
            next: Next::To(St::EstablishedRecv),
            events: &[(E::SendSent, b"")],
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2067-2070, :1304-1309 EST_SEND TIMEOUT -> resend head 0x18",
            state: St::EstablishedSend,
            queue: Q::Data,
            frames: &[(0x18, S, R, 10)],
            ..BASE
        },
        Row {
            cite: ":2071-2076 EST_SEND DATA ignored, no ACK",
            state: St::EstablishedSend,
            what: W::Data,
            payload: b"abc",
            ..BASE
        },
        Row {
            cite: ":2077-2078 EST_SEND SYNACK ignored",
            state: St::EstablishedSend,
            what: W::SynAck,
            ..BASE
        },
        // ESTABLISHED_RECV.
        Row {
            cite: ":2088-2091, :1405-1412 EST_RECV CLOSE -> FIN head now 0x19",
            what: W::Close,
            frames: &[(0x19, S, R, 0)],
            next: Next::To(St::FinWait1Recv),
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2092-2100, :1851-1856 EST_RECV FIN -> one ACK, CLOSE_WAIT, APP_CLOSE",
            what: W::Fin,
            frames: &[(0x10, S, R + 1, 0)],
            next: Next::To(St::CloseWait),
            events: &[(E::Close, b"")],
            after: Some((S, R + 1)),
            ..BASE
        },
        Row {
            cite: ":2106-2108 EST_RECV ACK -> acknowledged, nothing else",
            queue: Q::Data,
            what: W::Ack,
            ack: S + 10,
            after: Some((S + 10, R)),
            queue_after: Some(0),
            ..BASE
        },
        Row {
            cite: ":2109-2111 EST_RECV TIMEOUT -> APP_RECV_TIMEOUT",
            events: &[(E::RecvTimeout, b"")],
            ..BASE
        },
        Row {
            cite: ":2112-2114, :1884-1896 EST_RECV DATA -> APP_RECV_PAYLOAD, then ACK",
            what: W::Data,
            payload: b"hello",
            frames: &[(0x10, S, R + 5, 0)],
            events: &[(E::RecvPayload, b"hello")],
            after: Some((S, R + 5)),
            ..BASE
        },
        Row {
            cite: ":2115-2120 EST_RECV SYNACK ignored",
            what: W::SynAck,
            ..BASE
        },
        // FIN_WAIT1_SEND.
        Row {
            cite: ":2140-2142 FIN_WAIT1_SEND FIN ignored",
            state: St::FinWait1Send,
            queue: Q::Fin,
            what: W::Fin,
            ..BASE
        },
        Row {
            cite: ":2143-2156 FIN_WAIT1_SEND ACK good, head FIN -> FIN_WAIT1_RECV, SEND_SENT",
            state: St::FinWait1Send,
            queue: Q::DataFin,
            what: W::Ack,
            ack: S + 10,
            next: Next::To(St::FinWait1Recv),
            events: &[(E::SendSent, b"")],
            after: Some((S + 10, R)),
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2143-2156, :1525-1545 FIN_WAIT1_SEND partial ACK -> good but head has bytes, stays",
            state: St::FinWait1Send,
            queue: Q::DataFin,
            what: W::Ack,
            ack: S + 4,
            after: Some((S + 4, R)),
            queue_after: Some(2),
            ..BASE
        },
        Row {
            cite: ":2145, :1443-1445 FIN_WAIT1_SEND duplicate ACK is not good -> stays",
            state: St::FinWait1Send,
            queue: Q::Fin,
            what: W::Ack,
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2157-2159, :1299-1303 FIN_WAIT1_SEND TIMEOUT, FIN head -> 0x11",
            state: St::FinWait1Send,
            queue: Q::Fin,
            frames: &[(0x11, S, R, 0)],
            ..BASE
        },
        Row {
            cite: ":2157-2159, :1304-1309 FIN_WAIT1_SEND TIMEOUT, data head -> 0x18",
            state: St::FinWait1Send,
            queue: Q::DataFin,
            frames: &[(0x18, S, R, 10)],
            ..BASE
        },
        Row {
            cite: ":2160-2162 FIN_WAIT1_SEND DATA ignored",
            state: St::FinWait1Send,
            queue: Q::Fin,
            what: W::Data,
            payload: b"abc",
            ..BASE
        },
        Row {
            cite: ":2163-2166 FIN_WAIT1_SEND CLOSE unhandled",
            state: St::FinWait1Send,
            queue: Q::Fin,
            what: W::Close,
            ..BASE
        },
        // FIN_WAIT1_RECV.
        Row {
            cite: ":2171-2176 FIN_WAIT1_RECV FIN -> ACK + second ACK, CLOSING, APP_CLOSE",
            state: St::FinWait1Recv,
            queue: Q::Fin,
            what: W::Fin,
            frames: &[(0x10, S, R + 1, 0), (0x10, S, R + 1, 0)],
            next: Next::To(St::Closing),
            events: &[(E::Close, b"")],
            after: Some((S, R + 1)),
            ..BASE
        },
        Row {
            cite: ":2177-2185, :1472-1480, :1824-1832 FIN_WAIT1_RECV ACK of my FIN -> FIN_WAIT2, APP_CLOSE",
            state: St::FinWait1Recv,
            queue: Q::Fin,
            what: W::Ack,
            ack: S + 1,
            next: Next::To(St::FinWait2),
            events: &[(E::Close, b"")],
            after: Some((S + 1, R)),
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2179, :1481-1486 FIN_WAIT1_RECV bad ACK of FIN -> nothing",
            state: St::FinWait1Recv,
            queue: Q::Fin,
            what: W::Ack,
            ack: S + 2,
            ..BASE
        },
        Row {
            cite: ":2186-2188, :1299-1303 FIN_WAIT1_RECV TIMEOUT -> pure FIN 0x11",
            state: St::FinWait1Recv,
            queue: Q::Fin,
            frames: &[(0x11, S, R, 0)],
            ..BASE
        },
        Row {
            cite: ":2189-2191 FIN_WAIT1_RECV DATA -> APP_RECV_PAYLOAD, ACK",
            state: St::FinWait1Recv,
            queue: Q::Fin,
            what: W::Data,
            payload: b"xy",
            frames: &[(0x10, S, R + 2, 0)],
            events: &[(E::RecvPayload, b"xy")],
            after: Some((S, R + 2)),
            ..BASE
        },
        Row {
            cite: ":2192-2195 FIN_WAIT1_RECV CLOSE unhandled",
            state: St::FinWait1Recv,
            queue: Q::Fin,
            what: W::Close,
            ..BASE
        },
        // CLOSING.
        Row {
            cite: ":2202-2204 CLOSING TIMEOUT -> destroy, no frame",
            state: St::Closing,
            queue: Q::Fin,
            next: Next::Destroyed,
            queue_after: Some(0),
            deadline: Dl::Gone,
            ..BASE
        },
        Row {
            cite: ":2205-2211 CLOSING ACK of my FIN -> destroy",
            state: St::Closing,
            queue: Q::Fin,
            what: W::Ack,
            ack: S + 1,
            next: Next::Destroyed,
            after: Some((S + 1, R)),
            queue_after: Some(0),
            deadline: Dl::Gone,
            ..BASE
        },
        Row {
            cite: ":2205-2211 CLOSING ACK not of my FIN -> stays",
            state: St::Closing,
            queue: Q::Fin,
            what: W::Ack,
            ..BASE
        },
        Row {
            cite: ":2212-2215 CLOSING FIN -> ACK again",
            state: St::Closing,
            queue: Q::Fin,
            what: W::Fin,
            frames: &[(0x10, S, R, 0)],
            ..BASE
        },
        Row {
            cite: ":2216-2222 CLOSING CLOSE silent",
            state: St::Closing,
            queue: Q::Fin,
            what: W::Close,
            ..BASE
        },
        Row {
            cite: ":2223-2226 CLOSING DATA unhandled",
            state: St::Closing,
            queue: Q::Fin,
            what: W::Data,
            payload: b"z",
            ..BASE
        },
        // FIN_WAIT2 и TIME_WAIT.
        Row {
            cite: ":2234-2240 FIN_WAIT2 TIMEOUT -> nothing",
            state: St::FinWait2,
            queue: Q::Fin,
            ..BASE
        },
        Row {
            cite: ":2243-2253, :1851-1856 FIN_WAIT2 FIN -> ACK, TIME_WAIT, timer +5 s",
            state: St::FinWait2,
            queue: Q::Fin,
            what: W::Fin,
            frames: &[(0x10, S, R + 1, 0)],
            next: Next::To(St::TimeWait),
            after: Some((S, R + 1)),
            deadline: Dl::Plus5,
            ..BASE
        },
        Row {
            cite: ":2243-2253 TIME_WAIT FIN -> ACK, timer +5 s",
            state: St::TimeWait,
            queue: Q::Fin,
            what: W::Fin,
            frames: &[(0x10, S, R + 1, 0)],
            after: Some((S, R + 1)),
            deadline: Dl::Plus5,
            ..BASE
        },
        Row {
            cite: ":2241-2242 FIN_WAIT2 ACK ignored",
            state: St::FinWait2,
            queue: Q::Fin,
            what: W::Ack,
            ack: S + 1,
            ..BASE
        },
        Row {
            cite: ":2255-2258 FIN_WAIT2 DATA ignored, not ACKed",
            state: St::FinWait2,
            queue: Q::Fin,
            what: W::Data,
            payload: b"abc",
            ..BASE
        },
        Row {
            cite: ":2255-2258 TIME_WAIT SYNACK ignored",
            state: St::TimeWait,
            queue: Q::Fin,
            what: W::SynAck,
            ..BASE
        },
        Row {
            cite: ":2259-2263 TIME_WAIT CLOSE ignored",
            state: St::TimeWait,
            queue: Q::Fin,
            what: W::Close,
            ..BASE
        },
        Row {
            cite: ":2234-2240 TIME_WAIT TIMEOUT -> destroy",
            state: St::TimeWait,
            queue: Q::Fin,
            next: Next::Destroyed,
            queue_after: Some(0),
            deadline: Dl::Gone,
            ..BASE
        },
        // CLOSE_WAIT.
        Row {
            cite: ":2273-2276, :1405-1412 CLOSE_WAIT CLOSE -> FIN head now 0x19, LAST_ACK",
            state: St::CloseWait,
            what: W::Close,
            frames: &[(0x19, S, R, 0)],
            next: Next::To(St::LastAck),
            queue_after: Some(1),
            ..BASE
        },
        Row {
            cite: ":2277-2281 CLOSE_WAIT TIMEOUT -> APP_CLOSE again",
            state: St::CloseWait,
            events: &[(E::Close, b"")],
            ..BASE
        },
        Row {
            cite: ":2282-2285 CLOSE_WAIT ACK unhandled (not applied)",
            state: St::CloseWait,
            queue: Q::Data,
            what: W::Ack,
            ack: S + 10,
            ..BASE
        },
        // LAST_ACK.
        Row {
            cite: ":2290-2293, :1299-1303 LAST_ACK TIMEOUT -> resend 0x11",
            state: St::LastAck,
            queue: Q::Fin,
            frames: &[(0x11, S, R, 0)],
            ..BASE
        },
        Row {
            cite: ":2294-2298 LAST_ACK ACK good -> destroy",
            state: St::LastAck,
            queue: Q::Fin,
            what: W::Ack,
            ack: S + 1,
            next: Next::Destroyed,
            after: Some((S + 1, R)),
            queue_after: Some(0),
            deadline: Dl::Gone,
            ..BASE
        },
        Row {
            cite: ":2294-2298 LAST_ACK ACK not good -> stays",
            state: St::LastAck,
            queue: Q::Fin,
            what: W::Ack,
            ..BASE
        },
        Row {
            cite: ":2300-2303 LAST_ACK FIN unhandled",
            state: St::LastAck,
            queue: Q::Fin,
            what: W::Fin,
            ..BASE
        },
        // Пролог.
        Row {
            cite: ":1955-1960 duplicate FIN -> ACK, return",
            what: W::Fin,
            seq: R - 1,
            frames: &[(0x10, S, R, 0)],
            ..BASE
        },
        Row {
            cite: ":1961-1965 FIN from the future dropped",
            what: W::Fin,
            seq: R + 3,
            ..BASE
        },
        Row {
            cite: ":1961-1965 FIN from the past (not the duplicate) dropped",
            what: W::Fin,
            seq: R - 2,
            ..BASE
        },
        Row {
            cite: ":1930-1936 fully old payload dropped without ACK",
            what: W::Data,
            payload: b"abc",
            seq: R - 3,
            ..BASE
        },
        Row {
            cite: ":1943-1948 payload from the future dropped without ACK",
            what: W::Data,
            payload: b"abc",
            seq: R + 1,
            ..BASE
        },
        Row {
            cite: ":1937-1942 partly old payload trimmed",
            what: W::Data,
            payload: b"abcdef",
            seq: R - 2,
            frames: &[(0x10, S, R + 4, 0)],
            events: &[(E::RecvPayload, b"cdef")],
            after: Some((S, R + 4)),
            ..BASE
        },
        Row {
            cite: ":1983-1987 RST destroys, nothing sent, no sequence check",
            state: St::EstablishedSend,
            queue: Q::DataFin,
            what: W::Rst,
            seq: 12345,
            ack: 678,
            next: Next::Destroyed,
            queue_after: Some(0),
            deadline: Dl::Gone,
            ..BASE
        },
        Row {
            cite: ":1970-1980 TIMEOUT past the lifetime -> RST seq seqno_me ack seqno_them, destroy",
            at: T0 + 32 * SEC,
            frames: &[(0x04, S, R, 0)],
            next: Next::Destroyed,
            queue_after: Some(0),
            deadline: Dl::Gone,
            ..BASE
        },
    ];

    #[test]
    fn state_table_rows() {
        for row in ROWS {
            let mut t = tcb_in(row.state);
            match row.queue {
                Q::Empty => {}
                Q::Data => t.segments.push_back(data_seg(S, 10)),
                Q::Fin => t.segments.push_back(fin_seg(S)),
                Q::DataFin => {
                    t.segments.push_back(data_seg(S, 10));
                    t.segments.push_back(fin_seg(S + 10));
                }
            }
            let queued = t.segments.len();
            let mut app = idle();
            let (r, out) = step(
                &mut t,
                &mut app,
                row.what,
                row.payload,
                row.seq,
                row.ack,
                row.at,
            );
            let cite = row.cite;
            assert_eq!(frames(&out), row.frames, "{cite}: frames");
            let next = if r == TcbResult::Destroyed {
                Next::Destroyed
            } else if t.state == row.state {
                Next::Same
            } else {
                Next::To(t.state)
            };
            assert_eq!(next, row.next, "{cite}: next state");
            let want_events: Vec<(AppEvent, Vec<u8>)> =
                row.events.iter().map(|&(e, p)| (e, p.to_vec())).collect();
            assert_eq!(app.events, want_events, "{cite}: app events");
            assert_eq!(
                (t.seqno_me, t.seqno_them),
                row.after.unwrap_or((S, R)),
                "{cite}: seqno_me, seqno_them"
            );
            assert_eq!(
                t.segments.len(),
                row.queue_after.unwrap_or(queued),
                "{cite}: queue"
            );
            let want_deadline = match row.deadline {
                Dl::Keep => Some(T0 + SEC),
                Dl::Plus5 => Some(row.at + 5 * SEC),
                Dl::Gone => None,
            };
            assert_eq!(t.deadline_micros, want_deadline, "{cite}: deadline");
            // `ackno_them` идёт вместе с `seqno_me` (`:1478-1479`, `:1501-1502`, `:1528-1529`).
            if row.what != W::SynAck {
                assert_eq!(t.ackno_them, t.seqno_me, "{cite}: ackno_them");
            }
        }
    }

    /// Ответ парсера на данные уходит раньше ACK этих данных (`_tcb_seg_recv`, `src/stack-tcp-core.c:1884-1896`), и у
    /// чистого ACK тот же seq, что у кадра данных: `seqno_me` двигает только подтверждение.
    #[test]
    fn payload_reaction_precedes_ack() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| {
            if ev == E::RecvPayload {
                assert!(ctl.send(b"PING"));
            }
        });
        let (r, out) = step(&mut t, &mut app, W::Data, b"hello", R, S, T0 + SEC);
        assert_eq!(r, TcbResult::Okay);
        assert_eq!(frames(&out), [(0x18, S, R + 5, 4), (0x10, S, R + 5, 0)]);
        assert_eq!(out[0].payload, b"PING");
        assert_eq!(t.state, St::EstablishedSend);
        assert_eq!(kinds(&app), [E::RecvPayload]);
    }

    /// Приложение закрывает соединение посреди события (`tcpapi_close` парсера и ответ на `APP_CLOSE`,
    /// `src/stack-tcp-app.c:106-108, :131-135`): FIN уходит раньше ACK данных, а на их FIN сначала ACK, потом наш FIN.
    #[test]
    fn app_close_inside_events_keeps_c_wire_order() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| {
            if ev == E::RecvPayload {
                ctl.close();
            }
        });
        let (_, out) = step(&mut t, &mut app, W::Data, b"HTTP/1.0 200", R, S, T0 + SEC);
        assert_eq!(frames(&out), [(0x19, S, R + 12, 0), (0x10, S, R + 12, 0)]);
        assert_eq!(t.state, St::FinWait1Recv);

        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| {
            if ev == E::Close {
                ctl.close();
            }
        });
        let (_, out) = step(&mut t, &mut app, W::Fin, &[], R, S, T0 + SEC);
        assert_eq!(frames(&out), [(0x10, S, R + 1, 0), (0x19, S, R + 1, 0)]);
        assert_eq!(t.state, St::LastAck);
        let (r, out) = ack_of(&mut t, &mut app, S + 1, T0 + 2 * SEC);
        assert_eq!((r, out.len()), (TcbResult::Destroyed, 0));
        assert_eq!(kinds(&app), [E::Close]);
    }

    /// Только голова очереди уходит сразу; следующий сегмент ждёт тика после подтверждения головы
    /// (`src/stack-tcp-core.c:1405-1412`, `:2053-2070`).
    #[test]
    fn only_head_segment_in_flight() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| {
            if ev == E::RecvTimeout {
                assert!(ctl.send(&[b'a'; 10]));
                assert!(ctl.send(&[b'b'; 20]));
            }
        });
        let (_, out) = tick(&mut t, &mut app, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(0x18, S, R, 10)]);
        assert_eq!(out[0].payload, [b'a'; 10]);
        let seqnos: Vec<u32> = t.segments.iter().map(|s| s.seqno).collect();
        assert_eq!(seqnos, [S, S + 10]);

        let (_, out) = ack_of(&mut t, &mut app, S + 10, T0 + 3 * SEC);
        assert!(out.is_empty(), "the ACK of the head sends nothing");
        assert_eq!(t.state, St::EstablishedSend);
        let (_, out) = tick(&mut t, &mut app, T0 + 4 * SEC);
        assert_eq!(frames(&out), [(0x18, S + 10, R, 20)]);
        assert_eq!(out[0].payload, [b'b'; 20]);
        let (_, out) = ack_of(&mut t, &mut app, S + 30, T0 + 5 * SEC);
        assert!(out.is_empty());
        assert_eq!(t.state, St::EstablishedRecv);
        assert_eq!(kinds(&app), [E::RecvTimeout, E::SendSent]);
    }

    /// Hello длиннее `mss` режется по 1400 (`src/stack-tcp-core.c:1350-1353`, `:1416-1423`), и каждый следующий
    /// кусок уходит на своём тике.
    #[test]
    fn hello_over_1400_advances_one_segment_per_tick() {
        let hello: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let mut t = tcb_in(St::EstablishedRecv);
        let h = hello.clone();
        let mut app = rec(move |ctl, ev, _| {
            if ev == E::RecvTimeout {
                assert!(ctl.send(&h));
            }
        });
        let (_, out) = tick(&mut t, &mut app, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(0x18, S, R, 1400)]);
        assert_eq!(out[0].payload, hello[..1400]);
        let parts: Vec<(u32, usize)> = t.segments.iter().map(|s| (s.seqno, s.data.len())).collect();
        assert_eq!(parts, [(S, 1400), (S + 1400, 1400), (S + 2800, 200)]);

        let mut at = T0 + 2 * SEC;
        for (k, (lo, hi)) in [(1400usize, 2800usize), (2800, 3000)]
            .into_iter()
            .enumerate()
        {
            let acked = S + u32::try_from(lo).expect("u32");
            let (_, out) = ack_of(&mut t, &mut app, acked, at + SEC);
            assert!(out.is_empty(), "segment {k}: the ACK sends nothing");
            at += 2 * SEC;
            let (_, out) = tick(&mut t, &mut app, at);
            assert_eq!(frames(&out), [(0x18, acked, R, hi - lo)], "segment {k}");
            assert_eq!(out[0].payload, hello[lo..hi], "segment {k}");
        }
        let (_, out) = ack_of(&mut t, &mut app, S + 3000, at + SEC);
        assert!(out.is_empty());
        assert_eq!(t.state, St::EstablishedRecv);
        assert!(t.segments.is_empty());
        assert_eq!(kinds(&app), [E::RecvTimeout, E::SendSent]);
    }

    /// `SF__close`: hello и сразу `tcpapi_close` (`src/stack-tcp-app.c:187-192`). FIN встаёт за hello и уходит на тике
    /// после его подтверждения (`src/stack-tcp-core.c:2038-2041`, `:2143-2156`, `:2186-2188`).
    #[test]
    fn fin_behind_hello_leaves_on_next_tick() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| match ev {
            E::RecvTimeout => {
                assert!(ctl.send(&[b'h'; 100]));
                ctl.close();
            }
            // App_SendNext: `tcpapi_recv` на SEND_SENT (`src/stack-tcp-app.c:198-202`).
            E::SendSent => ctl.recv(),
            _ => {}
        });
        let (_, out) = tick(&mut t, &mut app, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(0x18, S, R, 100)]);
        assert_eq!(t.state, St::FinWait1Send);
        assert_eq!(t.segments.len(), 2);

        let (_, out) = ack_of(&mut t, &mut app, S + 100, T0 + 3 * SEC);
        assert!(out.is_empty(), "the FIN does not leave on the ACK");
        assert_eq!(t.state, St::FinWait1Recv);
        let (_, out) = tick(&mut t, &mut app, T0 + 4 * SEC);
        assert_eq!(frames(&out), [(0x11, S + 100, R, 0)]);

        let (_, out) = ack_of(&mut t, &mut app, S + 101, T0 + 5 * SEC);
        assert!(out.is_empty());
        assert_eq!(t.state, St::FinWait2);
        let (_, out) = step(&mut t, &mut app, W::Fin, &[], R, S + 101, T0 + 6 * SEC);
        assert_eq!(frames(&out), [(0x10, S + 101, R + 1, 0)]);
        assert_eq!(t.state, St::TimeWait);
        assert_eq!(t.deadline_micros, Some(T0 + 11 * SEC));
        let (r, out) = tick(&mut t, &mut app, T0 + 11 * SEC);
        assert_eq!((r, out.len()), (TcbResult::Destroyed, 0));
        assert_eq!(
            kinds(&app),
            [E::RecvTimeout, E::SendSent, E::Close],
            "APP_CLOSE on the ACK of our FIN (:2180-2183)"
        );
    }

    /// Р1: частичный ACK двигает `seqno_me`, но не `seg->seqno`, повтор отказывает ("SEQNO FAILURE",
    /// `src/stack-tcp-core.c:1294-1297`), и соединение стоит до RST по сроку жизни. У `TCP__static` длина сегмента
    /// остаётся прежней (`:1541-1543`), поэтому и ACK остатка его не снимает.
    #[test]
    fn partial_ack_stalls_until_lifetime() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| {
            if ev == E::RecvTimeout {
                assert!(ctl.send(&[b'h'; 100]));
            }
        });
        let (_, out) = tick(&mut t, &mut app, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(0x18, S, R, 100)]);
        let (_, out) = ack_of(&mut t, &mut app, S + 40, T0 + 3 * SEC);
        assert!(out.is_empty());
        assert_eq!((t.seqno_me, t.state), (S + 40, St::EstablishedSend));
        // ACK остатка: у static длина не уменьшилась, снова частичный, сегмент на месте.
        let (_, out) = ack_of(&mut t, &mut app, S + 100, T0 + 3 * SEC + 1);
        assert!(out.is_empty());
        assert_eq!((t.seqno_me, t.segments.len()), (S + 100, 1));
        for k in 2..=15u64 {
            let (r, out) = tick(&mut t, &mut app, T0 + 2 * k * SEC);
            assert_eq!(r, TcbResult::Okay);
            assert!(out.is_empty(), "tick +{} s resends nothing", 2 * k);
        }
        let (r, out) = tick(&mut t, &mut app, T0 + 32 * SEC);
        assert_eq!(r, TcbResult::Destroyed);
        assert_eq!(frames(&out), [(0x04, S + 100, R, 0)]);
        assert_eq!(kinds(&app), [E::RecvTimeout]);
    }

    /// `TCP__copy` (ответы telnet): частичный ACK укорачивает голову (`src/stack-tcp-core.c:1533-1540`), повтор так же
    /// отказывает, но ACK остатка сегмент снимает.
    #[test]
    fn partial_ack_of_copy_segment_shrinks_the_head() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = rec(|ctl, ev, _| {
            if ev == E::RecvTimeout {
                assert!(ctl.send_copy(b"0123456789"));
            }
        });
        let (_, out) = tick(&mut t, &mut app, T0 + 2 * SEC);
        assert_eq!(frames(&out), [(0x18, S, R, 10)]);
        let (_, out) = ack_of(&mut t, &mut app, S + 4, T0 + 3 * SEC);
        assert!(out.is_empty());
        assert_eq!(t.segments[0].data, b"456789");
        assert_eq!(t.segments[0].seqno, S, "seg->seqno is not moved");
        let (_, out) = tick(&mut t, &mut app, T0 + 4 * SEC);
        assert!(out.is_empty(), "SEQNO FAILURE");
        let (_, out) = ack_of(&mut t, &mut app, S + 10, T0 + 5 * SEC);
        assert!(out.is_empty());
        assert!(t.segments.is_empty());
        assert_eq!(t.state, St::EstablishedRecv);
        assert_eq!(kinds(&app), [E::RecvTimeout, E::SendSent]);
    }

    /// Пролог (`src/stack-tcp-core.c:1920-1949`): старые целиком данные и данные из будущего отбрасываются без ACK и
    /// без события, номер не двигается.
    #[test]
    fn old_data_not_acked_future_dropped() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = idle();
        let cases: [(&[u8], u32); 5] = [
            (b"abcde", R - 5),
            (b"abc", R - 10),
            (b"x", R.wrapping_sub(0x8000_0000)),
            (b"x", R + 1),
            (b"abc", R + 100_000),
        ];
        for (payload, seq) in cases {
            let (r, out) = step(&mut t, &mut app, W::Data, payload, seq, S, T0 + SEC);
            assert_eq!(r, TcbResult::Okay);
            assert!(out.is_empty(), "seq {seq:#x}: nothing sent");
            assert_eq!(t.seqno_them, R);
        }
        assert!(app.events.is_empty());
        // То же в FIN_WAIT1_RECV, где данные принимаются.
        t.state = St::FinWait1Recv;
        let (_, out) = step(&mut t, &mut app, W::Data, b"zz", R + 2, S, T0 + SEC);
        assert!(out.is_empty() && app.events.is_empty());
    }

    /// Review Focus 3: повтор и перекрытие доходят до приложения один раз, с переходом номера через 2^32.
    #[test]
    fn retransmitted_and_overlapping_segments_append_once() {
        for base in [R, 0xFFFF_FFFE] {
            let mut t = tcb_in(St::EstablishedRecv);
            t.seqno_them = base;
            let mut app = idle();
            let segs: [(&[u8], u32); 6] = [
                (b"hello", base),
                (b"hello", base),
                (b"lo", base.wrapping_add(3)),
                (b"llo world", base.wrapping_add(2)),
                (b"world", base.wrapping_add(6)),
                (b"!", base.wrapping_add(11)),
            ];
            let mut acks = Vec::new();
            for (payload, seq) in segs {
                let (_, out) = step(&mut t, &mut app, W::Data, payload, seq, S, T0 + SEC);
                acks.extend(frames(&out));
            }
            let got: Vec<u8> = app.events.iter().flat_map(|e| e.1.clone()).collect();
            assert_eq!(got, b"hello world!", "base {base:#x}");
            assert_eq!(kinds(&app), [E::RecvPayload; 3]);
            assert_eq!(
                acks,
                [
                    (0x10, S, base.wrapping_add(5), 0),
                    (0x10, S, base.wrapping_add(11), 0),
                    (0x10, S, base.wrapping_add(12), 0),
                ],
                "one ACK per accepted segment, none for dropped ones"
            );
        }
    }

    /// Повтор FIN после принятого FIN получает ACK из пролога (`src/stack-tcp-core.c:1955-1960`) и состояния не меняет.
    #[test]
    fn duplicate_fin_acked() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = idle();
        let (_, out) = step(&mut t, &mut app, W::Fin, &[], R, S, T0 + SEC);
        assert_eq!(frames(&out), [(0x10, S, R + 1, 0)]);
        assert_eq!(t.state, St::CloseWait);
        for _ in 0..2 {
            let (r, out) = step(&mut t, &mut app, W::Fin, &[], R, S, T0 + SEC);
            assert_eq!(r, TcbResult::Okay);
            assert_eq!(frames(&out), [(0x10, S, R + 1, 0)]);
            assert_eq!((t.state, t.seqno_them), (St::CloseWait, R + 1));
        }
        assert_eq!(kinds(&app), [E::Close]);
        // В TIME_WAIT повтор FIN таймер не продлевает: пролог возвращается раньше ветки `:2243-2253`.
        let mut t = tcb_in(St::TimeWait);
        t.seqno_them = R + 1;
        t.deadline_micros = Some(T0 + 7 * SEC);
        let (_, out) = step(&mut t, &mut app, W::Fin, &[], R, S, T0 + 3 * SEC);
        assert_eq!(frames(&out), [(0x10, S, R + 1, 0)]);
        assert_eq!(t.deadline_micros, Some(T0 + 7 * SEC));
    }

    const ALL_STATES: [TcpState; 10] = [
        St::SynSent,
        St::EstablishedSend,
        St::EstablishedRecv,
        St::CloseWait,
        St::LastAck,
        St::FinWait1Send,
        St::FinWait1Recv,
        St::FinWait2,
        St::Closing,
        St::TimeWait,
    ];

    /// RST уничтожает блок в любом состоянии, ничего не шлёт и номера не смотрит (`src/stack-tcp-core.c:1983-1987`).
    #[test]
    fn rst_destroys_silently() {
        for state in ALL_STATES {
            for (seq, ack) in [(R, S), (0, 0), (R + 77, S.wrapping_sub(5))] {
                let mut t = tcb_in(state);
                t.segments.push_back(data_seg(S, 10));
                t.segments.push_back(fin_seg(S + 10));
                let mut app = idle();
                let (r, out) = step(&mut t, &mut app, W::Rst, &[], seq, ack, T0 + SEC);
                assert_eq!(r, TcbResult::Destroyed, "{state:?}");
                assert!(out.is_empty() && app.events.is_empty(), "{state:?}");
                assert!(t.segments.is_empty() && t.deadline_micros.is_none());
            }
        }
    }

    /// Срок жизни (Р6, `src/stack-tcp-core.c:1970-1980`) сравнивается с запланированным временем тика (решение
    /// контроллера S1): тик +30 с соединение не трогает, тик +32 с даёт RST (seq `seqno_me`, ack `seqno_them`, `0x04`).
    #[test]
    fn lifetime_uses_scheduled_tick_time() {
        let mut t = tcb_in(St::EstablishedRecv);
        let mut app = idle();
        let (_, out) = step(&mut t, &mut app, W::Data, b"hey", R, S, T0 + 5 * SEC);
        assert_eq!(frames(&out), [(0x10, S, R + 3, 0)]);
        let (r, out) = tick(&mut t, &mut app, T0 + 30 * SEC);
        assert_eq!((r, out.len()), (TcbResult::Okay, 0));
        // Не-тик после срока жизни соединение не рвёт: проверка только у TIMEOUT.
        let (r, _) = step(&mut t, &mut app, W::Ack, &[], R + 3, S, T0 + 31 * SEC);
        assert_eq!(r, TcbResult::Okay);
        let (r, out) = tick(&mut t, &mut app, T0 + 32 * SEC);
        assert_eq!(r, TcbResult::Destroyed);
        assert_eq!(frames(&out), [(0x04, S, R + 3, 0)]);
        assert_eq!(kinds(&app), [E::RecvPayload, E::RecvTimeout]);

        // Сравнение строгое (`<` C), в микросекундах; срок берётся из аргумента; в любом состоянии, и FIN_WAIT2
        // кончается только так.
        for (state, lifetime, at, dies) in [
            (St::EstablishedRecv, 30, T0 + 30 * SEC + 1, true),
            (St::EstablishedRecv, 10, T0 + 10 * SEC, false),
            (St::EstablishedRecv, 10, T0 + 12 * SEC, true),
            (St::FinWait2, 30, T0 + 32 * SEC, true),
            (St::SynSent, 30, T0 + 32 * SEC, true),
            (St::EstablishedRecv, 0, T0, false),
            (St::EstablishedRecv, 0, T0 + 1, true),
        ] {
            let mut t = tcb_in(state);
            let mut out = Vec::new();
            let r = incoming(
                &mut t,
                &mut idle(),
                W::Timeout,
                &[],
                R,
                S,
                at,
                lifetime,
                &mut out,
            );
            assert_eq!(
                r == TcbResult::Destroyed,
                dies,
                "{state:?} life {lifetime} at +{}",
                at - T0
            );
            if dies {
                assert_eq!(frames(&out), [(0x04, S, R, 0)]);
            }
        }
    }

    /// `tcpapi_send` (`src/stack-tcp-core.c:1757-1778`) работает только в EST_RECV и EST_SEND; в остальных
    /// состояниях отказ, кадров и очереди нет.
    #[test]
    fn send_in_wrong_state_refused() {
        for state in ALL_STATES {
            for copy in [false, true] {
                let mut t = tcb_in(state);
                let mut out = Vec::new();
                let mut ctl = TcbCtl {
                    tcb: &mut t,
                    out: &mut out,
                    at_micros: T0 + SEC,
                    lifetime_secs: LIFE,
                };
                let ok = if copy {
                    ctl.send_copy(b"data")
                } else {
                    ctl.send(b"data")
                };
                let in_est = matches!(state, St::EstablishedRecv | St::EstablishedSend);
                assert_eq!(ok, in_est, "{state:?}");
                if in_est {
                    assert_eq!(frames(&out), [(0x18, S, R, 4)]);
                    assert_eq!(t.state, St::EstablishedSend);
                } else {
                    assert!(out.is_empty() && t.segments.is_empty(), "{state:?}");
                    assert_eq!(t.state, state);
                }
            }
        }
        // Пустая посылка в EST_RECV: состояние уже EST_SEND, сегмента нет (`:1356-1357`, `:1769`).
        let mut t = tcb_in(St::EstablishedRecv);
        let mut out = Vec::new();
        let mut ctl = TcbCtl {
            tcb: &mut t,
            out: &mut out,
            at_micros: T0,
            lifetime_secs: LIFE,
        };
        assert!(ctl.send(b""));
        assert!(out.is_empty() && t.segments.is_empty());
        assert_eq!(t.state, St::EstablishedSend);
    }

    /// Посылка за FIN в очереди и посылка за пределом очереди отбрасываются, а `tcpapi_send` всё равно "успешен"
    /// (`src/stack-tcp-core.c:1359-1371`).
    #[test]
    fn send_past_fin_and_past_the_bound_dropped() {
        let mut t = tcb_in(St::EstablishedRecv);
        t.segments.push_back(fin_seg(S));
        let mut out = Vec::new();
        let mut ctl = TcbCtl {
            tcb: &mut t,
            out: &mut out,
            at_micros: T0,
            lifetime_secs: LIFE,
        };
        assert!(ctl.send(b"late"));
        assert!(out.is_empty());
        assert_eq!(t.segments.len(), 1);
        assert_eq!(t.state, St::EstablishedSend);

        let mut t = tcb_in(St::EstablishedRecv);
        let mut out = Vec::new();
        let mut ctl = TcbCtl {
            tcb: &mut t,
            out: &mut out,
            at_micros: T0,
            lifetime_secs: LIFE,
        };
        for _ in 0..SEND_QUEUE_MAX_SEGMENTS - 1 {
            assert!(ctl.send(b"k"));
        }
        // Три сегмента, место для одного: первый встаёт, остальные отброшены вместе с хвостом, как за FIN.
        assert!(ctl.send(&[b'x'; 3 * MSS]));
        assert!(ctl.send(b"y"));
        assert_eq!(ctl.tcb.segments.len(), SEND_QUEUE_MAX_SEGMENTS);
        // FIN предел не держит: за ним ничего не встаёт, так что он в очереди не больше одного.
        ctl.close();
        assert_eq!(t.segments.len(), SEND_QUEUE_MAX_SEGMENTS + 1);
        let tail: Vec<(usize, bool)> = t
            .segments
            .iter()
            .rev()
            .take(2)
            .map(|s| (s.data.len(), s.is_fin))
            .collect();
        assert_eq!(tail, [(0, true), (MSS, false)]);
        assert_eq!(frames(&out), [(0x18, S, R, 1)], "only the head left");
        assert_eq!(t.state, St::FinWait1Send);
    }

    /// `CLOSE` не доходит до приложения ни в одном состоянии: поэтому `TcbCtl::close` гонит его через приложение без
    /// реакций (`_tcb_seg_close`, `src/stack-tcp-core.c:1697-1708`).
    #[test]
    fn close_never_reaches_the_app() {
        for state in ALL_STATES {
            for queue in [Q::Empty, Q::Data, Q::Fin, Q::DataFin] {
                let mut t = tcb_in(state);
                match queue {
                    Q::Empty => {}
                    Q::Data => t.segments.push_back(data_seg(S, 10)),
                    Q::Fin => t.segments.push_back(fin_seg(S)),
                    Q::DataFin => {
                        t.segments.push_back(data_seg(S, 10));
                        t.segments.push_back(fin_seg(S + 10));
                    }
                }
                let mut app = idle();
                let (r, _) = step(&mut t, &mut app, W::Close, &[], R, S, T0 + SEC);
                assert_eq!(r, TcbResult::Okay, "{state:?}");
                assert!(app.events.is_empty(), "{state:?}");
            }
        }
    }

    /// `tcpapi_recv` (`src/stack-tcp-core.c:1734-1755`): FIN_WAIT1_* -> FIN_WAIT1_RECV, остальное -> EST_RECV.
    #[test]
    fn recv_follows_tcpapi_recv() {
        for state in ALL_STATES {
            let mut t = tcb_in(state);
            let mut out = Vec::new();
            let mut ctl = TcbCtl {
                tcb: &mut t,
                out: &mut out,
                at_micros: T0,
                lifetime_secs: LIFE,
            };
            ctl.recv();
            let want = match state {
                St::FinWait1Send | St::FinWait1Recv => St::FinWait1Recv,
                _ => St::EstablishedRecv,
            };
            assert_eq!(t.state, want, "{state:?}");
            assert!(out.is_empty());
        }
    }

    /// `tcpapi_set_timeout` считает срок от времени события (`socket->secs`, `src/stack-tcp-core.c:1723-1727`); у тика
    /// это запланированный срок.
    #[test]
    fn set_timeout_counts_from_event_time() {
        let mut t = Tcb::new(KEY, S, R, 64, T0);
        let mut app = rec(|ctl, ev, _| match ev {
            E::Connected => ctl.set_timeout(2),
            E::RecvTimeout => ctl.set_timeout(7),
            _ => {}
        });
        let (_, out) = step(&mut t, &mut app, W::SynAck, &[], R, S, T0 + 123);
        assert_eq!(frames(&out), [(0x10, S, R, 0)]);
        assert_eq!(t.deadline_micros, Some(T0 + 123 + 2 * SEC));
        let (_, _) = tick(&mut t, &mut app, T0 + 2 * SEC);
        assert_eq!(t.deadline_micros, Some(T0 + 9 * SEC));
        assert_eq!(kinds(&app), [E::Connected, E::RecvTimeout]);
    }

    /// `is_small_window` (heartbleed, 4c) ставит окно 600 на каждый кадр блока, RST тоже
    /// (`src/stack-tcp-core.c:1163-1164`).
    #[test]
    fn small_window_marks_every_frame() {
        let mut t = tcb_in(St::EstablishedRecv);
        t.is_small_window = true;
        let mut app = idle();
        let (_, mut out) = step(&mut t, &mut app, W::Data, b"a", R, S, T0 + SEC);
        let (_, rst) = tick(&mut t, &mut app, T0 + 40 * SEC);
        out.extend(rst);
        let flags: Vec<(u8, Option<u16>)> = out.iter().map(|s| (s.flags, s.window)).collect();
        assert_eq!(flags, [(0x10, Some(600)), (0x04, Some(600))]);
    }

    /// Детерминированный xorshift64*, как в `udp_parsers_never_panic`: без внешних крейтов, воспроизводим.
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
        /// Номер рядом с `base`: чаще всего точно он или в пределах сегмента, иногда что угодно.
        fn near(&mut self, base: u32) -> u32 {
            match self.below(6) {
                0 => self.u32(),
                1 | 2 => base,
                3 => base.wrapping_sub(u32::try_from(self.below(3000)).expect("u32")),
                _ => base.wrapping_add(u32::try_from(self.below(3000)).expect("u32")),
            }
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next().to_le_bytes()[0]).collect()
        }
    }

    /// Приложение, которое на каждое событие делает случайное: шлёт (иногда очень много), закрывает, переходит на
    /// приём, ставит таймер.
    struct Chaos {
        rng: Rng,
        events: usize,
    }

    impl App for Chaos {
        fn on_event(&mut self, ctl: &mut TcbCtl<'_>, _ev: AppEvent, payload: &[u8]) {
            self.events += 1;
            assert!(payload.len() <= 2000);
            for _ in 0..self.rng.below(4) {
                match self.rng.below(14) {
                    0..=3 => {
                        let n = self.rng.below(3 * MSS + 2);
                        let b = self.rng.bytes(n);
                        ctl.send(&b);
                    }
                    4 => {
                        let n = self.rng.below(40);
                        let b = self.rng.bytes(n);
                        ctl.send_copy(&b);
                    }
                    5 => {
                        for _ in 0..self.rng.below(700) {
                            ctl.send(b"flood");
                        }
                    }
                    6 => ctl.close(),
                    7..=9 => ctl.recv(),
                    _ => {
                        let secs = match self.rng.below(3) {
                            0 => u32::MAX,
                            _ => u32::try_from(self.rng.below(10)).expect("u32"),
                        };
                        ctl.set_timeout(secs);
                    }
                }
            }
        }
    }

    /// Р1 класс б: случайные события, номера и приложение не роняют автомат; очередь не длиннее предела, кадры не
    /// длиннее `mss`, флаги только те, что шлёт C (справка A6); заметная доля прогонов доходит до каждого состояния.
    #[test]
    fn tcb_never_panics() {
        // Веса событий: RST редок, иначе соединения не живут дольше пары событий.
        const WHATS: [(What, usize); 7] = [
            (W::Timeout, 6),
            (W::SynAck, 2),
            (W::Rst, 1),
            (W::Fin, 4),
            (W::Ack, 8),
            (W::Data, 8),
            (W::Close, 2),
        ];
        let total: usize = WHATS.iter().map(|w| w.1).sum();
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut seen = [0usize; 10];
        let mut destroyed = 0usize;
        let mut app_events = 0usize;
        let mut at_bound = 0usize;
        for conn in 0..10_000u32 {
            let created = if conn % 50 == 0 {
                u64::MAX - u64::from(rng.u32())
            } else {
                rng.next() >> 8
            };
            let mut t = Tcb::new(KEY, rng.u32(), rng.u32(), 64, created);
            let lifetime = match rng.below(8) {
                0 => 0,
                1 => u32::MAX,
                _ => 30,
            };
            let mut app = Chaos {
                rng: Rng(rng.next() | 1),
                events: 0,
            };
            let mut at = created;
            for _ in 0..120 {
                // Половина событий по делу: SYN-ACK в SYN_SENT, данные и ACK с номерами блока.
                let what = if t.state == St::SynSent && rng.below(2) == 0 {
                    W::SynAck
                } else {
                    let mut k = rng.below(total);
                    let mut pick = W::Timeout;
                    for &(w, n) in &WHATS {
                        if k < n {
                            pick = w;
                            break;
                        }
                        k -= n;
                    }
                    pick
                };
                let seq = rng.near(t.seqno_them);
                // ACK по краям сегментов очереди (голова, FIN + 1, конец, середина) или рядом с `seqno_me`.
                let pick = rng.below(4);
                let ack = match t.segments.get(pick) {
                    Some(s) if rng.below(2) == 0 => {
                        let len = u32::try_from(s.data.len()).expect("len");
                        match rng.below(4) {
                            0 => s.seqno.wrapping_add(1),
                            1 => s.seqno.wrapping_add(len),
                            2 => s.seqno.wrapping_add(rng.u32() % (len + 1)),
                            _ => s.seqno,
                        }
                    }
                    _ => rng.near(t.seqno_me),
                };
                let n = match rng.below(8) {
                    0 => rng.below(2001),
                    1 | 2 => 0,
                    _ => rng.below(64),
                };
                let payload = rng.bytes(n);
                let dt = if rng.below(10) == 0 { 3 * SEC } else { SEC / 3 };
                at = at.saturating_add(
                    u64::try_from(rng.below(usize::try_from(dt).expect("dt"))).expect("u64"),
                );
                let mut out = Vec::new();
                let r = incoming(
                    &mut t, &mut app, what, &payload, seq, ack, at, lifetime, &mut out,
                );
                let data_segs = t.segments.iter().filter(|s| !s.is_fin).count();
                let fins = t.segments.len() - data_segs;
                assert!(data_segs <= SEND_QUEUE_MAX_SEGMENTS && fins <= 1);
                at_bound += usize::from(data_segs == SEND_QUEUE_MAX_SEGMENTS);
                assert!(
                    t.segments.iter().take(data_segs).all(|s| !s.is_fin),
                    "a FIN is always last"
                );
                for s in &out {
                    assert!(s.payload.len() <= MSS);
                    assert!(
                        matches!(s.flags, 0x02 | 0x04 | 0x10 | 0x11 | 0x18 | 0x19),
                        "{:#x}",
                        s.flags
                    );
                    assert_eq!(s.key, KEY);
                }
                let idx = ALL_STATES
                    .iter()
                    .position(|&s| s == t.state)
                    .expect("state");
                seen[idx] += 1;
                if r == TcbResult::Destroyed {
                    assert!(t.segments.is_empty() && t.deadline_micros.is_none());
                    destroyed += 1;
                    break;
                }
            }
            app_events += app.events;
        }
        for (state, n) in ALL_STATES.iter().zip(seen) {
            assert!(n >= 300, "{state:?} reached only {n} times");
        }
        assert!(
            destroyed > 5000 && app_events > 20_000 && at_bound > 100,
            "destroyed {destroyed}, app events {app_events}, events at the queue bound {at_bound}"
        );
    }
}
