//! Парсер баннера FTP: порт `ftp_parse` (`src/proto-ftp.c:13-123`) masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0; справка D2, B6, E3.3.
//!
//! Строки приветствия, каждая с кодом из трёх цифр, разделителем (`' '` у последней, `'-'` у остальных) и текстом,
//! пишутся в запись `ftp` (CR пропускается, LF пишется); после последней шлётся `AUTH TLS`. Ответ на него пишется до
//! первого LF без него самого: 234 это передача STARTTLS ([`ParseCx::hand_off_starttls`]), любой другой код
//! закрывает соединение. Не цифра там, где ждётся цифра, плохой разделитель, NUL или байт вне `isprint` в тексте
//! закрывают соединение. Так разбирается и `"220-"` почтового сервера на 25 (справка E3.3).

use crate::app::app_id;

use super::session::{ParseCx, Parser};

/// `state = 0xffffffff`: разбор кончен, остаток потока не читается (`default: i = length`, `src/proto-ftp.c:117-119`).
const DONE: u32 = u32::MAX;

/// Состояние потока FTP: `pstate->state` и `struct FTPSTUFF` (`src/proto-banner1.h:123-126`).
#[derive(Debug, Default)]
pub(crate) struct Ftp {
    state: u32,
    code: u32,
    is_last: bool,
}

/// `isprint` локали C (masscan `setlocale` не зовёт): 0x20-0x7E; NUL (`px[i] == '\0'`) в это не входит.
fn c_isprint(c: u8) -> bool {
    matches!(c, 0x20..=0x7e)
}

impl Parser for Ftp {
    /// `ftp_parse`, байт за байтом; `state` между вызовами в `self` (`pstate->state = state`, `:122`).
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut state = self.state;
        for (i, &c) in px.iter().enumerate() {
            match state {
                // `:32-52`: 0 и 100 обнуляют код и проваливаются в разбор цифры; три цифры кода пишутся.
                0 | 100 | 1..=3 | 101..=103 => {
                    if state == 0 || state == 100 {
                        self.code = 0;
                        state = state.wrapping_add(1);
                    }
                    if c.is_ascii_digit() {
                        self.code = self.code.wrapping_mul(10).wrapping_add(u32::from(c - b'0'));
                        state = state.wrapping_add(1);
                        cx.append(app_id::FTP, &[c]);
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:53-67`: `' '` у последней строки, `'-'` у остальных; пишется.
                4 | 104 => {
                    if c == b' ' || c == b'-' {
                        self.is_last = c == b' ';
                        state = state.wrapping_add(1);
                        cx.append(app_id::FTP, &[c]);
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:68-87`: текст приветствия; после последней строки `AUTH TLS` (`:73`).
                5 => {
                    if c == b'\r' {
                        continue;
                    } else if c == b'\n' {
                        if self.is_last {
                            cx.send(b"AUTH TLS\r\n");
                            state = 100;
                        } else {
                            state = 0;
                        }
                        cx.append(app_id::FTP, &[c]);
                    } else if !c_isprint(c) {
                        state = DONE;
                        cx.close();
                    } else {
                        cx.append(app_id::FTP, &[c]);
                    }
                }
                // `:88-116`: текст ответа на `AUTH TLS`; его LF не пишется, на нём 234 это STARTTLS (`:93-104`),
                // остальное закрывает.
                105 => {
                    if c == b'\r' {
                        continue;
                    } else if c == b'\n' {
                        if self.code == 234 {
                            self.state = DONE;
                            cx.hand_off_starttls(px.get(i + 1..).unwrap_or_default());
                            return;
                        }
                        state = DONE;
                        cx.close();
                    } else if !c_isprint(c) {
                        state = DONE;
                        cx.close();
                    } else {
                        cx.append(app_id::FTP, &[c]);
                    }
                }
                // `:117-119`: `DONE` (и любое другое значение) кончает разбор.
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

    const AUTH: &[u8] = b"AUTH TLS\r\n";

    fn send(b: &[u8]) -> StreamAction {
        StreamAction::Send(b.to_vec())
    }

    /// Ответ на `AUTH TLS` пишется без своего последнего LF (`src/proto-ftp.c:91-108`: LF в состоянии 105 не
    /// пишется), затем закрытие; ответ без перевода строки пишется весь, закрытия нет. Во всех нарезках.
    #[test]
    fn ftp_auth_reply_without_final_newline() {
        let r = stream_in_splits(
            21,
            None,
            b"220 lab FTP server ready\r\n530 Please login with USER and PASS\r\n",
            1,
        );
        assert_eq!(r.app_proto, Some(app_id::FTP));
        assert_eq!(
            r.records,
            [(
                app_id::FTP,
                b"220 lab FTP server ready\n530 Please login with USER and PASS".to_vec()
            )]
        );
        assert_eq!(r.actions, [send(AUTH), StreamAction::Close]);
        // Без перевода строки: запись та же, закрытия нет, ждём дальше.
        let r = stream_in_splits(21, None, b"220 ok\r\n530 not logged in", 2);
        assert_eq!(
            r.records,
            [(app_id::FTP, b"220 ok\n530 not logged in".to_vec())]
        );
        assert_eq!(r.actions, [send(AUTH)]);
        // Многострочный ответ: только первая строка, закрытие на её LF, вторая не читается.
        let r = stream_in_splits(21, None, b"220 ok\r\n530-first\r\n530 second\r\n", 3);
        assert_eq!(r.records, [(app_id::FTP, b"220 ok\n530-first".to_vec())]);
        assert_eq!(r.actions, [send(AUTH), StreamAction::Close]);
    }

    /// Р1, справка E3.3: порт выбирает только hello. `"220-"` почтового сервера на 25 и 587 классифицируется как FTP
    /// (`src/proto-banner1.c:147-153` правит только `"220 "`), и ему шлётся `AUTH TLS`; `"220 "` на 2525 тоже FTP.
    #[test]
    fn smtp_220_dash_on_25_parsed_as_ftp() {
        for port in [25u16, 587] {
            let r = stream_in_splits(
                port,
                None,
                b"220-mail.example.test ESMTP\r\n220 ok\r\n502 5.5.2 Error: command not recognized\r\n",
                u64::from(port),
            );
            assert_eq!(r.app_proto, Some(app_id::FTP), "{port}");
            assert_eq!(
                r.records,
                [(
                    app_id::FTP,
                    b"220-mail.example.test ESMTP\n220 ok\n502 5.5.2 Error: command not recognized"
                        .to_vec()
                )],
                "{port}"
            );
            assert_eq!(r.actions, [send(AUTH), StreamAction::Close], "{port}");
        }
        let r = stream_in_splits(2525, None, b"220 mail.example.test ESMTP\r\n", 4);
        assert_eq!(r.app_proto, Some(app_id::FTP));
        assert_eq!(r.actions, [send(AUTH)]);
    }

    /// Грамматика строк (`src/proto-ftp.c:32-87`): код на каждой строке, CR в тексте пропускается, CR на месте цифры,
    /// TAB, NUL, байт за 0x7E, плохой разделитель и короткий код закрывают без записи этого байта; строка 234 в
    /// приветствии это ещё приветствие.
    #[test]
    fn ftp_greeting_lines_and_stops() {
        for (stream, rec, acts) in [
            (
                &b"220-a\r\n220-b\r\n220 c\r\n500 no\r\n"[..],
                &b"220-a\n220-b\n220 c\n500 no"[..],
                &[send(AUTH), StreamAction::Close][..],
            ),
            (
                b"220 a\rb\r\r\n530 c\rd\r\n",
                b"220 ab\n530 cd",
                &[send(AUTH), StreamAction::Close],
            ),
            (
                b"220-a\r\n  more\r\n220 b\r\n",
                b"220-a\n",
                &[StreamAction::Close],
            ),
            (
                b"220-a\r\n\r\n220 b\r\n",
                b"220-a\n",
                &[StreamAction::Close],
            ),
            (b"220 lab\tFTP\r\n", b"220 lab", &[StreamAction::Close]),
            (b"220 lab\x00x\r\n", b"220 lab", &[StreamAction::Close]),
            (b"220 caf\xe9\r\n", b"220 caf", &[StreamAction::Close]),
            (b"220 a\x7f\r\n", b"220 a", &[StreamAction::Close]),
            (b"220-a\r\n220xb\r\n", b"220-a\n220", &[StreamAction::Close]),
            (b"220-a\r\n22 b\r\n", b"220-a\n22", &[StreamAction::Close]),
            (
                b"220 ok\r\n2345 x\r\n",
                b"220 ok\n234",
                &[send(AUTH), StreamAction::Close],
            ),
            (
                b"220 ok\r\nhello\r\n",
                b"220 ok\n",
                &[send(AUTH), StreamAction::Close],
            ),
            (
                b"220 ok\r\n530 a\tb\r\n",
                b"220 ok\n530 a",
                &[send(AUTH), StreamAction::Close],
            ),
            (
                b"220-x\r\n234 not a reply\r\n530 no\r\n",
                b"220-x\n234 not a reply\n530 no",
                &[send(AUTH), StreamAction::Close],
            ),
            (
                b"220 ok\n530 no\n",
                b"220 ok\n530 no",
                &[send(AUTH), StreamAction::Close],
            ),
        ] {
            let r = stream_in_splits(21, None, stream, stream.len() as u64);
            assert_eq!(r.records, [(app_id::FTP, rec.to_vec())], "{stream:?}");
            assert_eq!(r.actions, acts, "{stream:?}");
        }
        // После остановки ничего не читается: ни запись, ни второе закрытие.
        let r = stream_in_splits(21, None, b"220 a\tb\r\n220 c\r\n530 d\r\n", 5);
        assert_eq!(r.records, [(app_id::FTP, b"220 a".to_vec())]);
        assert_eq!(r.actions, [StreamAction::Close]);
    }

    /// Парсер с принуждением (`force_app`): первый байт не цифра это закрытие без записи; строка приветствия без
    /// шаблона разбирается так же.
    #[test]
    fn ftp_forced_from_the_first_byte() {
        let r = stream_in_splits(1, Some(app_id::FTP), b"x220 ok\r\n", 6);
        assert_eq!((r.records, r.actions), (vec![], vec![StreamAction::Close]));
        let r = stream_in_splits(1, Some(app_id::FTP), b"999 ok\r\n", 7);
        assert_eq!(r.records, [(app_id::FTP, b"999 ok\n".to_vec())]);
        assert_eq!(r.actions, [send(AUTH)]);
    }
}
