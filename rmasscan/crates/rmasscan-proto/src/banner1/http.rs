//! HTTP (`src/proto-http.c:487-691`), правило неразрезанного потока E2.3.
use super::banout::Banout;
use super::session::{ParseCx, Parser};
use crate::app_id;
use crate::http_request::c_space;

#[derive(Default)]
pub(crate) struct Http {
    state: u8,
    header: Banout,
    name_len: usize,
    server: bool,
    title: usize,
}
impl Parser for Http {
    fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]) {
        for &c in px {
            // C пишет заголовок одним append ПОСЛЕ Server, не включая LF пустой строки (:554-559).
            // Отложенная запись использует тот же бюджет, предел и lossy, что обычная (Р5, E2.3).
            if self.state < 13 && !(self.state == 9 && c == b'\n') {
                self.header.append(cx.budget, app_id::HTTP, &[c]);
            }
            match self.state {
                0..=4 => {
                    if b"HTTP/"
                        .get(usize::from(self.state))
                        .is_some_and(|b| *b == c.to_ascii_uppercase())
                    {
                        self.state += 1;
                    } else {
                        self.fail(cx);
                    }
                }
                5 => {
                    if c == b'.' {
                        self.state = 6;
                    } else if !c.is_ascii_digit() {
                        self.fail(cx);
                    }
                }
                6 => {
                    if c_space(c) {
                        self.state = 7;
                    } else if !c.is_ascii_digit() {
                        self.fail(cx);
                    }
                }
                7 => {
                    if c == b'\n' {
                        self.state = 9;
                    }
                }
                9 => {
                    if c == b'\r' {
                        continue;
                    }
                    if c == b'\n' {
                        cx.banout.commit_deferred_http(&mut self.header);
                        self.state = 13;
                        self.title = 0;
                    } else {
                        self.name_len = 0;
                        self.server = true;
                        self.state = 10;
                        self.name(c);
                    }
                }
                10 => self.name(c),
                11 => {
                    if c == b'\n' {
                        self.state = 9;
                    } else if !c_space(c) {
                        self.state = 12;
                        self.value(cx, c);
                    }
                }
                12 => self.value(cx, c),
                13 => {
                    if cx.capture_html {
                        cx.append(app_id::HTML_FULL, &[c]);
                    }
                    // smack HTML имеет единственный шаблон <TiTle, без границы имени (:41-44, :630-649).
                    let pat = b"<title";
                    if pat
                        .get(self.title)
                        .is_some_and(|b| *b == c.to_ascii_lowercase())
                    {
                        self.title += 1;
                    } else {
                        self.title = usize::from(c == b'<');
                    }
                    if self.title == pat.len() {
                        self.state = 14;
                    }
                }
                14 => {
                    if cx.capture_html {
                        cx.append(app_id::HTML_FULL, &[c]);
                    }
                    if c == b'>' {
                        self.state = 15;
                    }
                }
                15 => {
                    if cx.capture_html {
                        cx.append(app_id::HTML_FULL, &[c]);
                    }
                    // '<' съеден, а не повторён в matcher; title поглощает всё до него (:659-670).
                    if c == b'<' {
                        self.state = 13;
                    } else {
                        cx.append(app_id::HTML_TITLE, &[c]);
                    }
                }
                _ => break,
            }
        }
    }

    fn flush(&mut self, cx: &mut ParseCx<'_>) {
        cx.banout.commit_deferred_http(&mut self.header);
    }
}

impl Http {
    /// FIELD_NAME: поиск Server: якорный, ':' и LF неякорные (`src/proto-http.c:26-35, :551-592`). CR внутри
    /// имени виден smack на целом потоке; только CR в FIELD_START пропускается.
    fn name(&mut self, c: u8) {
        if c == b'\n' {
            self.state = 9;
        } else if c == b':' {
            self.server &= self.name_len == 6;
            self.state = 11;
        } else {
            self.server &= b"server"
                .get(self.name_len)
                .is_some_and(|b| *b == c.to_ascii_lowercase());
            self.name_len = self.name_len.saturating_add(1);
        }
    }
    fn value(&mut self, cx: &mut ParseCx<'_>, c: u8) {
        if c == b'\n' {
            self.state = 9;
        } else if c != b'\r' && self.server {
            cx.append(app_id::HTTP_SERVER, &[c]);
        }
    }
    /// Неуспешная версия отбрасывает ВЕСЬ статус, включая прошлые сегменты, и освобождает его бронь (E2.3,
    /// `src/proto-http.c:520-545, :678-681`); закрытие одно, дальнейшие байты игнорируются.
    fn fail(&mut self, cx: &mut ParseCx<'_>) {
        self.header.flush(cx.budget);
        self.state = 16;
        cx.close();
    }
}

#[cfg(test)]
mod tests {
    use super::super::session::BannerConfig;
    use super::super::{TestRng, stream_in_splits, test_splits};
    use crate::tcp::app::{ByteBudget, Session};
    use crate::{StreamAction, TcpBannerSettings, app_id, banner_stream};

    // Ловит раннюю запись HTTP перед Server и неверный перенос головы banout на 200 байтах.
    #[test]
    fn banout_order_http_matches_c() {
        for n in [1, 250] {
            let server = vec![b's'; n];
            let header = [&b"HTTP/1.0 200 OK\r\nServer: "[..], &server, b"\r\n\r"].concat();
            let stream = [&header[..], b"\n<title>t</title>"].concat();
            let r = stream_in_splits(80, None, &stream, n as u64);
            let want = if n < 200 {
                vec![(31, server), (17, b"t".to_vec()), (4, header)]
            } else {
                vec![(17, b"t".to_vec()), (4, header), (31, server)]
            };
            assert_eq!(r.records, want);
            assert!(r.actions.is_empty());
        }
    }
    #[test]
    fn server_values_concatenated() {
        let r = stream_in_splits(
            80,
            None,
            b"HTTP/1.0 200\r\nServer:  gws \r\nserver:\tx\r\nServer : lost\r\n\r\n",
            1,
        );
        assert_eq!(r.records[0], (app_id::HTTP_SERVER, b"gws x".to_vec()));
    }
    #[test]
    fn title_prefix_match_absorbs_body_without_lt() {
        for title in [b"<title>".as_slice(), b"<TITLE id=x>", b"<titlex>"] {
            let stream = [b"HTTP/1.0 200\r\n\r\n".as_slice(), title, b"a\n&x; rest"].concat();
            let r = stream_in_splits(80, None, &stream, 2);
            assert_eq!(
                r.records,
                [
                    (4, b"HTTP/1.0 200\r\n\r".to_vec()),
                    (17, b"a\n&x; rest".to_vec())
                ]
            );
        }
    }
    #[test]
    fn capture_html_full_body() {
        let body = b"before<title>x</title>after<TITLE id=x>y<end";
        let stream = [b"HTTP/1.0 200\r\nServer: gws\r\n\r\n".as_slice(), body].concat();
        let settings = TcpBannerSettings {
            capture_html: true,
            ..Default::default()
        };
        let whole = banner_stream(&settings, 80, None, &[&stream]);
        assert_eq!(
            whole.records,
            [
                (31, b"gws".to_vec()),
                (17, b"xy".to_vec()),
                (18, body.to_vec()),
                (4, b"HTTP/1.0 200\r\nServer: gws\r\n\r".to_vec())
            ]
        );
        for (_, split) in test_splits(&stream, 3) {
            assert_eq!(banner_stream(&settings, 80, None, &split), whole);
        }
    }
    #[test]
    fn failed_status_line_split_matches_unsplit() {
        for stream in [b"HTTP/1.1x\r\nServer: gws\r\n\r\n".as_slice(), b"HTTP/1.x"] {
            let r = stream_in_splits(80, None, stream, 4);
            assert_eq!(r.records, []);
            assert_eq!(r.actions, [StreamAction::Close]);
        }
    }
    // Ловит замену C isspace одним пробелом и требование хотя бы одной цифры версии (:530-545).
    #[test]
    fn status_uses_c_whitespace_and_allows_empty_numbers() {
        for (stream, header) in [
            (
                b"HTTP/1.0\t200\r\n\r\n".as_slice(),
                b"HTTP/1.0\t200\r\n\r".as_slice(),
            ),
            (b"HTTP/1.0\r200\r\n\r\n", b"HTTP/1.0\r200\r\n\r"),
            (b"HTTP/1.0\n200\r\n\r\n", b"HTTP/1.0\n200\r\n\r"),
            (b"HTTP/1.0\x0b200\r\n\r\n", b"HTTP/1.0\x0b200\r\n\r"),
            (b"HTTP/1.0\x0c200\r\n\r\n", b"HTTP/1.0\x0c200\r\n\r"),
            (b"hTtP/. 200\r\n\r\n", b"hTtP/. 200\r\n\r"),
        ] {
            let r = stream_in_splits(80, Some(app_id::HTTP), stream, 9);
            assert_eq!(r.records, [(app_id::HTTP, header.to_vec())]);
            assert!(r.actions.is_empty());
        }
    }
    #[test]
    fn incomplete_headers_flush_once() {
        for stream in [b"HTTP/1.".as_slice(), b"HTTP/1.1 200\r\nServer: gws"] {
            let r = stream_in_splits(80, None, stream, 5);
            let mut want = vec![];
            if stream.ends_with(b"gws") {
                want.push((31, b"gws".to_vec()));
            }
            want.push((4, stream.to_vec()));
            assert_eq!(r.records, want);
        }
        let cfg = BannerConfig::new(&TcpBannerSettings::default());
        let mut s = cfg.forced(80, 4);
        let mut b = ByteBudget::new(100);
        let mut a = Vec::new();
        s.parse(b"HTTP/1.", &mut b, &mut a);
        assert_eq!(b.left(), 93);
        assert_eq!(s.flush(&mut b), [(4, b"HTTP/1.".to_vec())]);
        assert_eq!(b.left(), 100);
        assert!(s.flush(&mut b).is_empty());
        assert_eq!(b.left(), 100);
    }
    // Р5 действует и пока статус ждёт проверки/сброса: длинная версия не выделяет память за пределом записи.
    #[test]
    fn deferred_header_caps_before_flush_and_releases_on_failure() {
        let cfg = BannerConfig::new(&TcpBannerSettings::default());
        for fail in [false, true] {
            let mut s = cfg.forced(80, app_id::HTTP);
            let mut b = ByteBudget::new(1 << 20);
            let mut acts = Vec::new();
            s.parse(b"HTTP/1.", &mut b, &mut acts);
            s.parse(&vec![b'1'; 70_000], &mut b, &mut acts);
            assert_eq!(b.left(), (1 << 20) - 65_536);
            assert_eq!(b.dropped(), 0);
            if fail {
                s.parse(b"x", &mut b, &mut acts);
                assert_eq!(b.left(), 1 << 20);
                assert_eq!(acts, [crate::tcp::app::SessionAction::Close]);
                assert!(s.flush(&mut b).is_empty());
            } else {
                assert_eq!(
                    s.flush(&mut b),
                    [(4, [b"HTTP/1.".as_slice(), &vec![b'1'; 65_529]].concat())]
                );
            }
            assert_eq!(b.left(), 1 << 20);
            assert!(s.flush(&mut b).is_empty());
            assert_eq!(b.left(), 1 << 20);
        }
    }
    // Ловит unbudgeted staging, повторное освобождение и дописывание после отказа в байте.
    #[test]
    fn deferred_headers_keep_budget_and_prefix_after_refusal() {
        let cfg = BannerConfig::new(&TcpBannerSettings::default());
        let mut s = cfg.forced(80, 4);
        let mut b = ByteBudget::new(4);
        let mut a = Vec::new();
        s.parse(b"HTTP/1.0 200\r\n", &mut b, &mut a);
        assert_eq!(b.left(), 0);
        b.give(100);
        s.parse(b"X: tail\r\n\r\n<title>x</title>", &mut b, &mut a);
        assert_eq!(
            s.flush(&mut b),
            [(4, b"HTTP".to_vec()), (17, b"x".to_vec())]
        );
        assert_eq!(b.left(), 104);
        assert!(s.flush(&mut b).is_empty());
        assert_eq!(b.left(), 104);
        let mut s = cfg.forced(80, 4);
        let mut b = ByteBudget::new(10);
        s.parse(b"HTTP/1.", &mut b, &mut a);
        assert_eq!(b.left(), 3);
        s.parse(b"x", &mut b, &mut a);
        assert_eq!(b.left(), 10);
        assert!(s.flush(&mut b).is_empty());
        assert_eq!(b.left(), 10);

        // Даже короткий сохранённый префикс переносит голову на логических 200 байтах C (:258-286 banout).
        let mut s = cfg.forced(80, 4);
        let mut b = ByteBudget::new(4);
        s.parse(b"HTTP/1.0 200\r\nX: ", &mut b, &mut a);
        s.parse(&[b'h'; 250], &mut b, &mut a);
        b.give(100);
        s.parse(b"\r\n\r\n<title>x</title>", &mut b, &mut a);
        assert_eq!(
            s.flush(&mut b),
            [(17, b"x".to_vec()), (4, b"HTTP".to_vec())]
        );
        assert_eq!(b.left(), 104);
        assert!(s.flush(&mut b).is_empty());
        assert_eq!(b.left(), 104);
    }
    #[test]
    fn http_never_panics() {
        let mut rng = TestRng(0xC0FF_EE10_D15E_A5E5);
        let frags: &[&[u8]] = &[
            b"HTTP/1.",
            b"200\r\n",
            b"Server:",
            b"\r\n\r\n",
            b"<title",
            b">",
            b"</title>",
            b"x",
            b"\0\xff",
            b"1",
            b" ",
        ];
        for round in 0..3000 {
            let mut stream = Vec::new();
            for _ in 0..1 + rng.below(20) {
                stream.extend_from_slice(frags[rng.below(frags.len())]);
            }
            if round % 20 == 0 {
                stream.extend(std::iter::repeat_n(b'1', 70_000));
            }
            let settings = TcpBannerSettings {
                capture_html: round % 2 == 0,
                ..Default::default()
            };
            let whole = banner_stream(&settings, 80, Some(4), &[&stream]);
            let at = rng.below(stream.len() + 1);
            assert_eq!(
                banner_stream(&settings, 80, Some(4), &[&stream[..at], &stream[at..]]),
                whole,
                "round {round}"
            );
            for (_, b) in whole.records {
                assert!(!b.is_empty() && b.len() <= 65_536);
            }
        }
    }
}
