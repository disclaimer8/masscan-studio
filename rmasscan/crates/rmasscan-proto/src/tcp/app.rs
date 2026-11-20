//! Слой приложения соединения: `application_event` (`src/stack-tcp-app.c:43-218`, справка B5) между автоматом TCB
//! ([`super::tcb`]) и сессией баннера. Сессия это поток hello порта и разбор ответа сервера (`tcb->stream`,
//! `banner1_parse`, `tcb->banout`); её даёт [`Sessions`] на каждое соединение. Повторяются и странности C: поток NULL
//! hello не шлёт никогда, сервер, заговоривший первым, hello не получает, пустой hello оставляет приложение в
//! `App_SendNext`, где байты сервера подтверждаются, но не разбираются.

use std::sync::Arc;

use super::tcb::{App, AppEvent, TcbCtl};

/// Бюджет байтов баннеров таблицы (Р5, решение 8): общий для живых соединений одной таблицы. Сессия перед дописыванием
/// `n` байт берёт `take(n)` и дописывает столько, сколько дали; не вместившееся считается в `dropped`. Сброс баннеров
/// возвращает их байты (`give`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ByteBudget {
    left: usize,
    dropped: u64,
}

impl ByteBudget {
    pub(crate) fn new(bytes: usize) -> ByteBudget {
        ByteBudget {
            left: bytes,
            dropped: 0,
        }
    }

    /// Сколько из `n` байт можно дописать: столько уходит из остатка, остальное считается выброшенным.
    pub(crate) fn take(&mut self, n: usize) -> usize {
        let got = n.min(self.left);
        self.left -= got;
        let lost = u64::try_from(n - got).unwrap_or(u64::MAX);
        self.dropped = self.dropped.saturating_add(lost);
        got
    }

    /// `n` байт не дописываются, не взяв бюджета, и считаются выброшенными: запись, от которой бюджет уже отказал,
    /// больше не растёт (потеря только с конца записи, [`crate::banner1::banout::Banout::append`]).
    pub(crate) fn refuse(&mut self, n: usize) {
        let lost = u64::try_from(n).unwrap_or(u64::MAX);
        self.dropped = self.dropped.saturating_add(lost);
    }

    /// Atomic metadata reservation. Loss counters count refused output bytes,
    /// so a failed reservation leaves both the balance and counters untouched.
    pub(crate) fn reserve_record(&mut self, bytes: usize) -> bool {
        if self.left < bytes {
            return false;
        }
        self.left -= bytes;
        true
    }

    /// Вернуть `n` байт (сброс баннеров).
    pub(crate) fn give(&mut self, n: usize) {
        self.left = self.left.saturating_add(n);
    }

    #[cfg(test)]
    pub(crate) fn left(&self) -> usize {
        self.left
    }

    /// Байты, не вместившиеся в бюджет, за жизнь таблицы.
    pub(crate) fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// Действие сессии из разбора: `tcpapi_send(..., TCP__static)` и `tcpapi_close` парсеров баннеров
/// (`src/stack-tcp-api.h:45-76`), в порядке вызова.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionAction {
    Send(Vec<u8>),
    SendCopy(Vec<u8>),
    /// `TCP__static` неизменного блоба процесса (KEX SSH, `src/proto-ssh.c:10-41`, `:147`): у C в очереди указатель на
    /// статическую память (`src/stack-tcp-core.c:1381-1385`), здесь общий буфер без копии на соединение; байты на
    /// проводе те же, что у [`SessionAction::Send`].
    SendShared(Arc<[u8]>),
    Close,
}

/// Поток порта (`struct ProtocolParserStream`, `src/proto-banner1.h`): hello и его флаги. `hello: None` это
/// поток NULL (hello не шлётся никогда), `Some` с пустым буфером — поток с пустым hello (`hello_length == 0`,
/// справка B5). `next` — hello второго соединения (`stream->next`, справка 4c §A1, §D1); исполняет его слой
/// приложения и таблица в задаче 7, как и `close_after_hello` (`SF__close`) и `small_window` (heartbleed).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct StreamDesc {
    pub hello: Option<Arc<[u8]>>,
    pub close_after_hello: bool,
    pub next: Option<Arc<[u8]>>,
    pub small_window: bool,
    pub is_tls: bool,
    /// Поток и есть `banner_ssl`/`banner_ssl_12`: его отправка ставит `is_sent_sslhello` (кладж по указателю,
    /// `src/stack-tcp-app.c:157-163`); копия `--hello-string` на TLS-порту этого не делает.
    pub sets_ssl_hello: bool,
}

impl StreamDesc {
    /// Поток только с hello, без флагов TLS.
    pub(crate) fn plain(hello: Option<Arc<[u8]>>) -> StreamDesc {
        StreamDesc {
            hello,
            ..StreamDesc::default()
        }
    }
}

/// Сессия баннера одного соединения: поток hello порта (`tcb->stream`, `src/stack-tcp-core.c:1043-1048`) и разбор
/// байтов сервера (`banner_parse`, `src/stack-tcp-app.c:126`).
pub(crate) trait Session: Send {
    /// Поток порта этой сессии.
    fn stream(&self) -> &StreamDesc;
    /// Отправка TLS hello состоялась (`banner_set_sslhello`, `src/stack-tcp-app.c:157-163`): классификатор
    /// после этого принимает совпадение SSL3. Ставят слой приложения (SendFirst, задача 7) и передача
    /// STARTTLS (задача 6); до них вызовов нет.
    #[allow(dead_code)]
    fn note_tls_hello_sent(&mut self) {}
    /// Байты сервера по порядку; ответы и закрытие в `acts`.
    fn parse(&mut self, px: &[u8], budget: &mut ByteBudget, acts: &mut Vec<SessionAction>);
    /// `banner_flush` (`src/stack-tcp-core.c:800-830`): записи `(app, байты)` в порядке C, буферы освобождаются, их
    /// байты возвращаются в бюджет.
    fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)>;
}

/// Источник сессий таблицы (`banner1->payloads.tcp[port_them]` и классификатор).
pub(crate) trait Sessions: Send + Sync {
    fn new_session(&self, remote_port: u16) -> Box<dyn Session>;
    /// Сессия второго соединения (`stream->next`): `None`, если источник вторых сессий не даёт (заглушки тестов
    /// без реконнекта); таблица тогда соединение не создаёт.
    fn new_reconnect_session(&self, _remote_port: u16) -> Option<Box<dyn Session>> {
        None
    }
}

/// Состояние приложения, `enum App_*` (`src/stack-tcp-app.c:11-18`) без `App_SendFirst` (переход внутри одного
/// вызова, `:94-97`, `:154-195`) и `App_Close` (C его не ставит).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum AppState {
    #[default]
    Connect,
    ReceiveHello,
    ReceiveNext,
    SendNext,
}

/// `application_event` для одного события одного соединения: состояние приложения и сессия соединения, бюджет и
/// hello таблицы. Наборы записей `banner_flush` из `APP_CLOSE` дописываются в `flushed` по одному на сброс (пустой
/// сброс набора не даёт); записи из них делает таблица.
pub(crate) struct AppLayer<'a> {
    pub(crate) state: &'a mut AppState,
    pub(crate) session: &'a mut dyn Session,
    pub(crate) budget: &'a mut ByteBudget,
    pub(crate) flushed: &'a mut Vec<Vec<(u16, Vec<u8>)>>,
}

impl AppLayer<'_> {
    /// `banner_flush(socket)` из `APP_CLOSE` (`src/stack-tcp-app.c:107`, `:134`).
    fn flush(&mut self) {
        let set = self.session.flush(self.budget);
        if !set.is_empty() {
            self.flushed.push(set);
        }
    }

    /// `App_SendFirst` (`src/stack-tcp-app.c:154-195`): кладжи TLS (`banner_set_sslhello` только настоящему
    /// потоку `banner_ssl`, не копии `--hello-string`; малое окно heartbleed), hello, если он не пустой, FIN за
    /// ним при `SF__close`, и `App_SendNext`.
    fn send_first(&mut self, ctl: &mut TcbCtl<'_>) {
        let (hello, close_after, small, sets_hello) = {
            let d = self.session.stream();
            (
                d.hello.clone(),
                d.close_after_hello,
                d.small_window,
                d.sets_ssl_hello,
            )
        };
        if sets_hello {
            self.session.note_tls_hello_sent();
        }
        if small {
            ctl.set_small_window();
        }
        if let Some(hello) = hello
            && !hello.is_empty()
        {
            ctl.send_shared(&hello);
            if close_after {
                ctl.close();
            }
        }
        *self.state = AppState::SendNext;
    }
}

impl App for AppLayer<'_> {
    fn on_event(&mut self, ctl: &mut TcbCtl<'_>, ev: AppEvent, payload: &[u8]) {
        use AppEvent as E;
        use AppState as A;
        // Пары, которых нет в ветке, у C печатают `"TCP.app: unhandled event: state=%s event=%s\n"` и ничего не делают
        // (`_ => {}`); в `App_SendNext` так пропадает и нагрузка сервера (её подтвердил автомат, но не разобрал никто).
        match (*self.state, ev) {
            // `:56-80`: сначала переподключение по `stream->next`, затем ожидание hello; `SF__nowait_hello` ни у
            // одного перенесённого потока нет.
            (A::Connect, E::Connected) => {
                if self.session.stream().next.is_some() {
                    ctl.reconnect();
                }
                ctl.set_timeout(2);
                ctl.recv();
                *self.state = A::ReceiveHello;
            }
            // `:90-99`: без потока (NULL) ничего, и так до конца соединения.
            (A::ReceiveHello, E::RecvTimeout) => {
                if self.session.stream().hello.is_some() {
                    self.send_first(ctl);
                }
            }
            // `:100-105`, `:119-130`: сервер заговорил первым, hello не будет; нагрузка идёт в разбор.
            (A::ReceiveHello | A::ReceiveNext, E::RecvPayload) => {
                *self.state = A::ReceiveNext;
                let mut acts = Vec::new();
                self.session.parse(payload, self.budget, &mut acts);
                for act in acts {
                    match act {
                        SessionAction::Send(bytes) => {
                            ctl.send(&bytes);
                        }
                        SessionAction::SendCopy(bytes) => {
                            ctl.send_copy(&bytes);
                        }
                        SessionAction::SendShared(buf) => {
                            ctl.send_shared(&buf);
                        }
                        SessionAction::Close => ctl.close(),
                    }
                }
            }
            // `:106-109`, `:131-136`: их FIN или подтверждение нашего, сброс баннеров и наш FIN.
            (A::ReceiveHello | A::ReceiveNext, E::Close) => {
                self.flush();
                ctl.close();
            }
            // `:198-203`: hello подтверждён, приём.
            (A::SendNext, E::SendSent) => {
                ctl.recv();
                *self.state = A::ReceiveNext;
            }
            // `:137-146`: таймаут и SEND_SENT в приёме ничего не делают.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_budget_takes_what_is_left_and_counts_the_rest() {
        let mut b = ByteBudget::new(10);
        assert_eq!(b.take(6), 6);
        assert_eq!((b.left(), b.dropped()), (4, 0));
        assert_eq!(b.take(7), 4);
        assert_eq!((b.left(), b.dropped()), (0, 3));
        assert_eq!(b.take(5), 0);
        assert_eq!((b.left(), b.dropped()), (0, 8));
        b.give(6);
        assert_eq!(b.take(2), 2);
        assert_eq!((b.left(), b.dropped()), (4, 8));
        b.give(usize::MAX);
        assert_eq!(b.left(), usize::MAX);
        let mut z = ByteBudget::new(0);
        assert_eq!(z.take(usize::MAX), 0);
        assert_eq!(z.dropped(), u64::try_from(usize::MAX).unwrap_or(u64::MAX));
    }
}
