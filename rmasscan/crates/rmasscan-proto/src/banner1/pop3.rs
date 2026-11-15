//! Парсер баннера POP3: порт `pop3_parse` (`src/proto-pop3.c:20-152`) masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0; справка D4, B6.
//!
//! CR пропускается в любом состоянии до разбора (`:36-37`), каждый другой байт до остановки пишется в запись `pop`,
//! проверки `isprint` нет. Приветствие `+OK` (байт пишется и при несовпадении) до LF, затем `CAPA`; ответ `-` это
//! строка и закрытие, `STLS` не шлётся; ответ `+OK` это строки до строки из одной точки, затем `STLS`; ответ `+OK`
//! на него до LF (LF пишется) это передача STARTTLS ([`ParseCx::hand_off_starttls`]), `-` строка и закрытие.

use crate::app::app_id;

use super::session::{ParseCx, Parser};

/// `state = 0xffffffff`: разбор кончен (`default: i = length`, `src/proto-pop3.c:146-148`).
const DONE: u32 = u32::MAX;

/// `pstate->state` POP3; своей части `sub` у парсера нет.
#[derive(Debug, Default)]
pub(crate) struct Pop3 {
    state: u32,
}

impl Parser for Pop3 {
    /// `pop3_parse`, байт за байтом; `state` между вызовами в `self` (`pstate->state = state`, `:151`). Байт до
    /// остановки пишется раньше проверки (`banout_append_char` первым в каждом состоянии).
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut state = self.state;
        for (i, &c) in px.iter().enumerate() {
            // `:36-37`: CR пропускается в любом состоянии, и в `DONE` тоже.
            if c == b'\r' {
                continue;
            }
            match state {
                // `:41-48`: `+OK` с учётом регистра (классификатор его не учитывает).
                0..=2 => {
                    cx.append(app_id::POP3, &[c]);
                    if b"+OK".get(state as usize) == Some(&c) {
                        state += 1;
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:49-55`: приветствие до LF, затем `CAPA`.
                3 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'\n' {
                        cx.send(b"CAPA\r\n");
                        state = 4;
                    }
                }
                // `:56-87`: ответ на CAPA (4-6) и на STLS (204-206): `-` это строка и закрытие (100), `+OK` дальше.
                4 | 204 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'-' {
                        state = 100;
                    } else if c == b'+' {
                        state += 1;
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                5 | 205 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'O' {
                        state += 1;
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:78-87`: `state += 2` (у C «oops, I had too many states here»): 6 -> 8, 206 -> 208.
                6 | 206 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'K' {
                        state += 2;
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:88-116`: строки списка CAPA (8), начало строки (9), строка из точки (10), затем `STLS`.
                8 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'\n' {
                        state = 9;
                    }
                }
                9 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'.' {
                        state = 10;
                    } else if c != b'\n' {
                        state = 8;
                    }
                }
                10 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'\n' {
                        cx.send(b"STLS\r\n");
                        state = 204;
                    } else {
                        state = 8;
                    }
                }
                // `:118-135`: ответ `+OK` на STLS до LF (LF пишется), затем передача без проверки кода.
                208 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'\n' {
                        self.state = DONE;
                        cx.hand_off_starttls(px.get(i + 1..).unwrap_or_default());
                        return;
                    }
                }
                // `:137-145`: строка `-` до LF (пишется), затем закрытие.
                100 => {
                    cx.append(app_id::POP3, &[c]);
                    if c == b'\n' {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:146-148`: `DONE` (и 7, 207, любое другое значение) кончает разбор.
                _ => break,
            }
        }
        self.state = state;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::banner1::driver::StreamAction;
    use crate::banner1::stream_in_splits;

    const CAPA: &[u8] = b"CAPA\r\n";
    const STLS: &[u8] = b"STLS\r\n";

    fn send(b: &[u8]) -> StreamAction {
        StreamAction::Send(b.to_vec())
    }

    /// `-` на CAPA (`src/proto-pop3.c:59-60`, `:137-145`): строка записана с LF, закрытие, `STLS` не шлётся, дальше
    /// ничего не читается; без LF строка записана, закрытия ещё нет.
    #[test]
    fn pop3_capa_minus_stops_without_stls() {
        let r = stream_in_splits(
            110,
            None,
            b"+OK POP3 server ready\r\n-ERR unknown command\r\n+OK\r\n.\r\n",
            1,
        );
        assert_eq!(r.app_proto, Some(app_id::POP3));
        assert_eq!(
            r.records,
            [(
                app_id::POP3,
                b"+OK POP3 server ready\n-ERR unknown command\n".to_vec()
            )]
        );
        assert_eq!(r.actions, [send(CAPA), StreamAction::Close]);
        let r = stream_in_splits(110, None, b"+OK x\r\n-ERR no", 2);
        assert_eq!(r.records, [(app_id::POP3, b"+OK x\n-ERR no".to_vec())]);
        assert_eq!(r.actions, [send(CAPA)]);
    }

    /// Список CAPA (`src/proto-pop3.c:88-116`): строки до строки из одной точки, пустые строки и строки с точкой в
    /// начале его не кончают, `STLS` шлётся и без `STLS` в списке; ответ на `STLS` проверяется как `+OK`.
    #[test]
    fn pop3_capa_list_until_dot_then_stls() {
        let close = StreamAction::Close;
        for (stream, rec, acts) in [
            (
                &b"+OK ready\r\n+OK\r\nUSER\r\nUIDL\r\n.\r\n-ERR unknown\r\n"[..],
                &b"+OK ready\n+OK\nUSER\nUIDL\n.\n-ERR unknown\n"[..],
                vec![send(CAPA), send(STLS), close.clone()],
            ),
            (
                b"+OK ready\r\n+OK\r\n.hidden\r\n\r\n\r\nX\r\n.\r\n-ERR no\r\n",
                b"+OK ready\n+OK\n.hidden\n\n\nX\n.\n-ERR no\n",
                vec![send(CAPA), send(STLS), close.clone()],
            ),
            (
                b"+OK x\r\n+OK\r\n.\r\n+ON\r\n",
                b"+OK x\n+OK\n.\n+ON",
                vec![send(CAPA), send(STLS), close.clone()],
            ),
            (
                b"+OK ready\r\nhello\r\n",
                b"+OK ready\nh",
                vec![send(CAPA), close.clone()],
            ),
            (
                b"+OK ready\r\n+NO\r\n",
                b"+OK ready\n+N",
                vec![send(CAPA), close.clone()],
            ),
            (
                b"+OK lab\t\x01\x80\xff ready\r\n-ERR\r\n",
                b"+OK lab\t\x01\x80\xff ready\n-ERR\n",
                vec![send(CAPA), close.clone()],
            ),
            (b"+OK ready", b"+OK ready", vec![]),
            // Пустая строка оставляет начало строки (`:101-102`): точка сразу за ней кончает список.
            (
                b"+OK ready\r\n+OK\r\nA\r\n\r\n.\r\n-ERR no\r\n",
                b"+OK ready\n+OK\nA\n\n.\n-ERR no\n",
                vec![send(CAPA), send(STLS), close.clone()],
            ),
            (b"+ok pop3\r\n", b"+o", vec![close.clone()]),
        ] {
            let r = stream_in_splits(110, None, stream, stream.len() as u64);
            assert_eq!(r.records, [(app_id::POP3, rec.to_vec())], "{stream:?}");
            assert_eq!(r.actions, acts, "{stream:?}");
        }
        // Принуждение: CR пропускается и внутри `+OK`; несовпавший первый байт записан.
        let r = stream_in_splits(1, Some(app_id::POP3), b"\r+\rO\rK \n", 3);
        assert_eq!(r.records, [(app_id::POP3, b"+OK \n".to_vec())]);
        assert_eq!(r.actions, [send(CAPA)]);
        let r = stream_in_splits(1, Some(app_id::POP3), b"x+OK\r\n", 4);
        assert_eq!(r.records, [(app_id::POP3, b"x".to_vec())]);
        assert_eq!(r.actions, [close]);
    }
}
