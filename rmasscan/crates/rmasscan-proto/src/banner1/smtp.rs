//! Парсер баннера SMTP: порт `smtp_parse` (`src/proto-smtp.c:34-169`) masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0; справка D3, B6.
//!
//! Классификатор отдаёт сюда `"220 "` на 25 и 587 и `"521 "` на любом порту (`src/proto-banner1.c:147-153`). Три
//! фазы с грамматикой строк FTP (код из трёх цифр, `' '` у последней строки, `'-'` у остальных, текст; CR в тексте
//! пропускается, LF пишется), всё в запись `smtp`: приветствие, после последней строки `EHLO masscan`; ответ на EHLO,
//! после последней строки `STARTTLS`, что бы EHLO ни ответил (`:114-133`); ответ на STARTTLS до первого LF без него:
//! 220 это передача STARTTLS ([`ParseCx::hand_off_starttls`]), иначе закрытие.

use crate::app::app_id;

use super::session::{ParseCx, Parser};

/// `state = 0xffffffff`: разбор кончен (`default: i = length`, `src/proto-smtp.c:163-165`).
const DONE: u32 = u32::MAX;

/// Состояние потока SMTP: `pstate->state` и `struct SMTPSTUFF` (`src/proto-banner1.h:136-139`).
#[derive(Debug, Default)]
pub(crate) struct Smtp {
    state: u32,
    code: u32,
    is_last: bool,
}

/// `isprint` локали C: 0x20-0x7E (как у FTP).
fn c_isprint(c: u8) -> bool {
    matches!(c, 0x20..=0x7e)
}

impl Parser for Smtp {
    /// `smtp_parse`, байт за байтом; `state` между вызовами в `self` (`pstate->state = state`, `:168`).
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut state = self.state;
        for (i, &c) in px.iter().enumerate() {
            match state {
                // `:53-77`: 0, 100 и 200 обнуляют код и проваливаются в разбор цифры; три цифры кода пишутся.
                0 | 100 | 200 | 1..=3 | 101..=103 | 201..=203 => {
                    if state == 0 || state == 100 || state == 200 {
                        self.code = 0;
                        state = state.wrapping_add(1);
                    }
                    if c.is_ascii_digit() {
                        self.code = self.code.wrapping_mul(10).wrapping_add(u32::from(c - b'0'));
                        state = state.wrapping_add(1);
                        cx.append(app_id::SMTP, &[c]);
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:78-93`: `' '` у последней строки, `'-'` у остальных; пишется.
                4 | 104 | 204 => {
                    if c == b' ' || c == b'-' {
                        self.is_last = c == b' ';
                        state = state.wrapping_add(1);
                        cx.append(app_id::SMTP, &[c]);
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:94-133`: текст приветствия (после последней строки `EHLO`, `:99`) и ответа на EHLO (после
                // последней строки `STARTTLS` при любом коде, `:119`).
                5 | 105 => {
                    if c == b'\r' {
                        continue;
                    } else if c == b'\n' {
                        if self.is_last {
                            if state == 5 {
                                cx.send(b"EHLO masscan\r\n");
                                state = 100;
                            } else {
                                cx.send(b"STARTTLS\r\n");
                                state = 200;
                            }
                        } else {
                            state = if state == 5 { 0 } else { 100 };
                        }
                        cx.append(app_id::SMTP, &[c]);
                    } else if !c_isprint(c) {
                        state = DONE;
                        cx.close();
                    } else {
                        cx.append(app_id::SMTP, &[c]);
                    }
                }
                // `:134-162`: текст ответа на STARTTLS; его LF не пишется, на нём 220 это передача (`:139-150`),
                // остальное закрывает.
                205 => {
                    if c == b'\r' {
                        continue;
                    } else if c == b'\n' {
                        if self.code == 220 {
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
                        cx.append(app_id::SMTP, &[c]);
                    }
                }
                // `:163-165`: `DONE` (и любое другое значение) кончает разбор.
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

    const EHLO: &[u8] = b"EHLO masscan\r\n";
    const STARTTLS: &[u8] = b"STARTTLS\r\n";

    fn send(b: &[u8]) -> StreamAction {
        StreamAction::Send(b.to_vec())
    }

    /// `STARTTLS` уходит после последней строки ответа на EHLO при любом коде и списке (`src/proto-smtp.c:114-124`):
    /// со STARTTLS в списке, без него, при отказе 500 и на многострочный 554; ответ на STARTTLS не 220 закрывает.
    #[test]
    fn smtp_ehlo_then_starttls_whatever_ehlo_said() {
        let close = StreamAction::Close;
        for (port, stream, rec, acts) in [
            (
                25u16,
                &b"220 mail.example.test ESMTP\r\n250-mail.example.test\r\n250 STARTTLS\r\n454 4.7.0 not now\r\n"[..],
                &b"220 mail.example.test ESMTP\n250-mail.example.test\n250 STARTTLS\n454 4.7.0 not now"[..],
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
            (
                25,
                b"220 x\r\n250 8BITMIME\r\n502 no\r\n",
                b"220 x\n250 8BITMIME\n502 no",
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
            (
                587,
                b"220 x\r\n500 unrecognized\r\n503 bad\r\n",
                b"220 x\n500 unrecognized\n503 bad",
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
            (
                2525,
                b"521 no mail\r\n554-a\r\n554 b\r\n",
                b"521 no mail\n554-a\n554 b\n",
                vec![send(EHLO), send(STARTTLS)],
            ),
        ] {
            let r = stream_in_splits(port, None, stream, u64::from(port));
            assert_eq!(r.app_proto, Some(app_id::SMTP), "{stream:?}");
            assert_eq!(r.records, [(app_id::SMTP, rec.to_vec())], "{stream:?}");
            assert_eq!(r.actions, acts, "{stream:?}");
        }
    }

    /// Остановки (`src/proto-smtp.c:68-162`): TAB, 0x7F и строка без кода закрывают без записи байта, плохой
    /// разделитель и CR на месте цифры тоже; ответ на STARTTLS читается до первого LF, без LF записан весь.
    #[test]
    fn smtp_reply_lines_and_stops() {
        let close = StreamAction::Close;
        for (stream, rec, acts) in [
            (
                &b"220 x\r\n250-mail\texample\r\n"[..],
                &b"220 x\n250-mail"[..],
                vec![send(EHLO), close.clone()],
            ),
            (
                b"220 x\r\n250-ok\r\n  continued\r\n",
                b"220 x\n250-ok\n",
                vec![send(EHLO), close.clone()],
            ),
            (
                b"220 x\r\n250 ok\r\n454 later",
                b"220 x\n250 ok\n454 later",
                vec![send(EHLO), send(STARTTLS)],
            ),
            (
                b"220 x\r\n250 ok\r\n454-first\r\n454 second\r\n",
                b"220 x\n250 ok\n454-first",
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
            (
                b"220 x\r\n250 ok\r\n454 \x7f\r\n",
                b"220 x\n250 ok\n454 ",
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
            (
                b"220 x\r\n250+ok\r\n",
                b"220 x\n250",
                vec![send(EHLO), close.clone()],
            ),
            (
                b"220 x\r\n\r\n",
                b"220 x\n",
                vec![send(EHLO), close.clone()],
            ),
            (
                b"220 x\r\n250 ok\r\nabc",
                b"220 x\n250 ok\n",
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
            (b"220 x\ty\r\n", b"220 x", vec![close.clone()]),
            // Передача только на 220, не на 221 или 22x (`src/proto-smtp.c:139`).
            (
                b"220 x\r\n250 ok\r\n221 2.0.0 bye\r\n",
                b"220 x\n250 ok\n221 2.0.0 bye",
                vec![send(EHLO), send(STARTTLS), close.clone()],
            ),
        ] {
            let r = stream_in_splits(25, None, stream, stream.len() as u64);
            assert_eq!(r.records, [(app_id::SMTP, rec.to_vec())], "{stream:?}");
            assert_eq!(r.actions, acts, "{stream:?}");
        }
        // Принуждение: первый байт не цифра.
        let r = stream_in_splits(1, Some(app_id::SMTP), b"x", 9);
        assert_eq!((r.records, r.actions), (vec![], vec![close]));
    }
}
