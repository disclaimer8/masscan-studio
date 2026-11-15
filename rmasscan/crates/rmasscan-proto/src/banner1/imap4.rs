//! Парсер баннера IMAP4: порт `imap4_parse` (`src/proto-imap4.c:20-193`) masscan © Robert David Graham
//! (github.com/robertdavidgraham/masscan, HEAD 8e6b3b0), AGPL-3.0; справка D5, E3.4.
//!
//! Странность C, которая повторяется (Р1): состояние 1 на первом байте не пробел ставит `DONE` и закрывает, затем
//! проваливается в состояние 2 (`:49-57`), которое пишет байт и на `'O'` делает `state++` (`:58-61`): `0xffffffff + 1`
//! это 0. Следующий байт (`'K'` шаблона `"* OK "`) в состоянии 0 не `'*'`: второе закрытие. Каждое приветствие IMAP
//! это запись `imap` `"* OK"` и два закрытия, `a001 CAPABILITY` и `a002 STARTTLS` (`:92`, `:159`) не шлются никогда.
//!
//! Поэтому в начале цикла состояние бывает только 0, 1 или `DONE`: в 1 попадают только из 0, из 1 выходят только
//! через `DONE` (`:54`), а в 2 только провалом. Состояния 2-5 и 100-400 (`:58-184`) в начале цикла недостижимы и не
//! перенесены; провал из 1 в 2 перенесён.

use crate::app::app_id;

use super::session::{ParseCx, Parser};

/// `state = 0xffffffff`: разбор кончен (`case 0xffffffff: default: i = length`, `src/proto-imap4.c:186-189`).
const DONE: u32 = u32::MAX;

/// `pstate->state` IMAP4.
#[derive(Debug, Default)]
pub(crate) struct Imap4 {
    state: u32,
}

impl Parser for Imap4 {
    /// `imap4_parse`, байт за байтом; `state` между вызовами в `self` (`pstate->state = state`, `:192`).
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        let mut state = self.state;
        for &c in px {
            // `:36-37`: CR пропускается в любом состоянии.
            if c == b'\r' {
                continue;
            }
            match state {
                // `:40-48`: звезда.
                0 => {
                    cx.append(app_id::IMAP4, &[c]);
                    if c == b'*' {
                        state = 1;
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:49-57`: пробелы после звезды пишутся; первый другой байт ставит `DONE`, закрывает и проваливается
                // в `case 2` (`:58-66`): байт пишется, на `'O'` `state++` переносит `DONE` в 0, иначе `DONE` и второе
                // закрытие.
                1 => {
                    if c == b' ' {
                        cx.append(app_id::IMAP4, &[c]);
                        continue;
                    }
                    state = DONE;
                    cx.close();
                    cx.append(app_id::IMAP4, &[c]);
                    if c == b'O' {
                        state = state.wrapping_add(1);
                    } else {
                        state = DONE;
                        cx.close();
                    }
                }
                // `:186-189`: `DONE`; другие состояния в начале цикла недостижимы (заголовок модуля).
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

    /// Р1, справка E3.4: приветствие IMAP любой длины, с CAPABILITY и STARTTLS или весь диалог STARTTLS дают запись
    /// `"* OK"` и два закрытия (`src/proto-imap4.c:49-66`), ничего не шлётся; строчные `"* ok "` дают `"* o"`.
    /// Без шаблона `"* OK "` (два пробела, `* BYE`, `* OK` и сразу CRLF) парсер не запускается, поток `unknown`.
    #[test]
    fn imap4_banner_is_star_ok() {
        let two = [StreamAction::Close, StreamAction::Close];
        for (stream, rec) in [
            (&b"* OK IMAP4rev1 ready\r\n"[..], &b"* OK"[..]),
            (
                b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] lab ready\r\n",
                b"* OK",
            ),
            (
                b"* OK ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK done\r\na002 OK Begin TLS\r\n",
                b"* OK",
            ),
            (b"* OK ", b"* OK"),
            (b"* ok imap\r\n", b"* o"),
            (b"* Ok imap\r\n", b"* Ok"),
        ] {
            let r = stream_in_splits(143, None, stream, stream.len() as u64);
            assert_eq!(r.app_proto, Some(app_id::IMAP4), "{stream:?}");
            assert_eq!(r.records, [(app_id::IMAP4, rec.to_vec())], "{stream:?}");
            assert_eq!(r.actions, two, "{stream:?}");
        }
        for stream in [
            &b"*  OK ready\r\n"[..],
            b"* BYE server shutting down\r\n",
            b"* OK\r\n",
        ] {
            let r = stream_in_splits(143, None, stream, 7);
            assert_eq!(r.app_proto, None, "{stream:?}");
            assert_eq!(r.records, [(app_id::HEUR, stream.to_vec())], "{stream:?}");
            assert!(r.actions.is_empty());
        }
    }

    /// Автомат на любом потоке (принуждение): `'O'` после звезды и пробелов возвращает в 0 (перенос `DONE + 1`), и
    /// следующая звезда начинает заново; каждый выход из 1 закрывает, CR пропускается везде (`:36-37`).
    #[test]
    fn imap4_automaton_from_any_byte() {
        let c = StreamAction::Close;
        for (stream, rec, closes) in [
            (&b"* O* OK\r\n"[..], &b"* O* OK"[..], 3usize),
            (b"*\n", b"*\n", 2),
            (b"x* OK", b"x", 1),
            (b"*OK", b"*OK", 2),
            (b"\r*\r \rO\rK", b"* OK", 2),
            (b"*  \r\n", b"*  \n", 2),
            (b"*O", b"*O", 1),
        ] {
            let r = stream_in_splits(1, Some(app_id::IMAP4), stream, stream.len() as u64);
            assert_eq!(r.records, [(app_id::IMAP4, rec.to_vec())], "{stream:?}");
            assert_eq!(r.actions, vec![c.clone(); closes], "{stream:?}");
        }
    }
}
