//! Построитель запроса HTTP masscan (`src/proto-http.c:124-396`, справка C3).

/// Опции `--http-*` одного скана; порядок применения задан `src/main.c:656-718`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpRequestOptions {
    pub method: Option<Vec<u8>>,
    pub url: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
    pub host: Option<Vec<u8>>,
    pub user_agent: Option<Vec<u8>>,
    pub payload: Option<Vec<u8>>,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
    pub cookies: Vec<Vec<u8>>,
}

/// Запрос после применения опций в порядке C3 (`src/main.c:656-718`).
pub fn http_request(o: &HttpRequestOptions) -> Result<Vec<u8>, String> {
    if o.headers.len() > 16 || o.cookies.len() > 16 {
        return Err("at most 16 HTTP headers and 16 cookies are supported".to_owned());
    }
    let mut h = crate::banner1::hello::HTTP_DEFAULT_REQUEST.to_vec();
    if let Some(v) = &o.payload {
        // Первая правка над шаблоном с пустой нагрузкой (`src/main.c:656`, `src/stack-tcp-core.c:405-424`).
        h.extend_from_slice(v);
        field(
            &mut h,
            b"Content-Length:",
            (v.len() as u32).to_string().as_bytes(),
            false,
        );
    }
    for (name, value) in [
        (b"User-Agent:".as_slice(), &o.user_agent),
        (b"Host:", &o.host),
    ] {
        if let Some(v) = value {
            field(&mut h, name, v, false);
        }
    }
    for (item, value) in [&o.method, &o.url, &o.version].into_iter().enumerate() {
        if let Some(v) = value {
            requestline(&mut h, item, v);
        }
    }
    for (k, v) in &o.headers {
        field(&mut h, k, v, false);
    }
    for v in &o.cookies {
        field(&mut h, b"Cookie:", v, true);
    }
    Ok(h)
}

/// `isspace` локали C (`src/proto-http.c:65-95, :226-288`), включая VT и FF.
pub(crate) fn c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t'..=b'\r')
}

/// `_skip(spaces|notspaces)` (`src/proto-http.c:65-95`): LF не пропускается, CR перед ним возвращаются.
fn skip(h: &[u8], mut at: usize, spaces: bool) -> usize {
    while let Some(&b) = h.get(at) {
        if if spaces {
            b == b'\n' || !c_space(b)
        } else {
            c_space(b)
        } {
            break;
        }
        at += 1;
    }
    if spaces && h.get(at) == Some(&b'\n') {
        while at > 0 && h.get(at - 1) == Some(&b'\r') {
            at -= 1;
        }
    }
    at
}

/// `http_change_requestline` items 0..2 (`src/proto-http.c:125-191`); safe splice вместо realloc до memmove
/// (`:110-114`, E1 класс а: при уменьшении C читает уже отрезанный хвост).
fn requestline(h: &mut Vec<u8>, item: usize, value: &[u8]) {
    let mut at = skip(h, 0, true);
    for (i, default) in [b"GET".as_slice(), b"/", b"HTTP/1.0"]
        .into_iter()
        .enumerate()
    {
        let start = at;
        if at == h.len() {
            h.extend_from_slice(default);
        }
        at = skip(h, at, false);
        if i == item {
            h.splice(start..at, value.iter().copied());
            return;
        }
        if at == h.len() {
            h.push(b' ');
        }
        at = skip(h, at, true);
    }
}

/// `_next_field` (`src/proto-http.c:239-254`): только LF после whitespace пропускается. Голый LF остаётся на
/// месте; `_field_length` там ноль, поиск останавливается и следующая правка вставляет поле ПЕРЕД ним.
fn next(h: &[u8], at: usize) -> usize {
    let end = h
        .get(at..)
        .and_then(|s| s.iter().position(|b| *b == b'\n'))
        .map_or(h.len(), |n| at + n);
    if end > at && h.get(end - 1).is_some_and(|b| c_space(*b)) {
        (end + 1).min(h.len())
    } else {
        end
    }
}

fn field_matches(h: &[u8], mut at: usize, name: &[u8]) -> bool {
    while h.get(at).is_some_and(|b| *b != b'\n' && c_space(*b)) {
        at += 1;
    }
    let Some(end) = at.checked_add(name.len()) else {
        return false;
    };
    let Some(candidate) = h.get(at..end) else {
        return false;
    };
    let mut p = end;
    while h.get(p).is_some_and(|b| c_space(*b)) {
        p += 1;
    }
    h.get(p) == Some(&b':') && candidate.eq_ignore_ascii_case(name)
}

/// `http_change_field` (`src/proto-http.c:293-382`): имя C-string, значения с явной длиной, replace/add.
fn field(h: &mut Vec<u8>, name: &[u8], value: &[u8], mut add: bool) {
    let mut name = name.split(|b| *b == 0).next().unwrap_or_default();
    while name.last().is_some_and(|b| *b == b':' || c_space(*b)) {
        name = name.get(..name.len() - 1).unwrap_or_default();
    }
    let mut at = next(h, 0);
    while at < h.len() {
        if field_matches(h, at, name) {
            break;
        }
        let line = h.get(at..).unwrap_or_default();
        let len = line.iter().position(|b| *b == b'\n').unwrap_or(line.len());
        if line
            .get(..len)
            .unwrap_or_default()
            .iter()
            .all(|b| c_space(*b))
        {
            add = true;
            break;
        }
        let n = next(h, at);
        if n <= at {
            add = true;
            break;
        }
        at = n;
    }
    let end = if add { at } else { next(h, at) };
    let line = [name, b": ", value, b"\r\n"].concat();
    h.splice(at..end, line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::path::Path;

    const DEFAULT: &[u8] = b"GET / HTTP/1.0\r\nUser-Agent: ivre-masscan/1.3 https://github.com/robertdavidgraham/\r\nAccept: */*\r\n\r\n";
    const DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/golden/tcp-banners/requests"
    );

    fn cases() -> Vec<(String, HttpRequestOptions)> {
        let mut v = vec![("default".to_owned(), HttpRequestOptions::default())];
        for (key, value) in [
            ("method", &b"POST"[..]),
            ("method", b""),
            ("method", b" A B "),
            ("url", b"/x"),
            ("url", b"/a b"),
            ("url", b""),
            ("version", b"HTTP/1.1"),
            ("version", b""),
            ("version", b"a\r\nb"),
            ("host", b"lab.test"),
            ("host", b""),
            ("host", b"a\nb"),
            ("user_agent", b"x"),
            ("user_agent", b""),
            ("user_agent", b" x "),
            ("payload", b"abc"),
            ("payload", b""),
            ("payload", b"a\0b\xff"),
        ] {
            let mut o = HttpRequestOptions::default();
            *match key {
                "method" => &mut o.method,
                "url" => &mut o.url,
                "version" => &mut o.version,
                "host" => &mut o.host,
                "user_agent" => &mut o.user_agent,
                _ => &mut o.payload,
            } = Some(value.to_vec());
            v.push((format!("{key}-{}", v.len()), o));
        }
        for (name, headers) in [
            (
                "replace-case",
                vec![
                    (b"accept".to_vec(), b"x".to_vec()),
                    (b"AcCePt:".to_vec(), b"y".to_vec()),
                ],
            ),
            ("no-colon", vec![(b"X-Lab".to_vec(), b"v".to_vec())]),
            ("crlf", vec![(b"X".to_vec(), b"a\r\nY: z".to_vec())]),
            (
                "bare-lf",
                vec![
                    (b"X".to_vec(), b"a\nb".to_vec()),
                    (b"Z".to_vec(), b"last".to_vec()),
                ],
            ),
            (
                "space-empty",
                vec![
                    (b" X: \t".to_vec(), b"  ".to_vec()),
                    (Vec::new(), Vec::new()),
                ],
            ),
            ("binary", vec![(b"X\0Y".to_vec(), b"a\0b\xff".to_vec())]),
        ] {
            v.push((
                name.to_owned(),
                HttpRequestOptions {
                    headers,
                    ..Default::default()
                },
            ));
        }
        v.push((
            "cookies".to_owned(),
            HttpRequestOptions {
                cookies: vec![b"a=b".to_vec(), b"c=d".to_vec(), Vec::new()],
                ..Default::default()
            },
        ));
        v.push((
            "combined".to_owned(),
            HttpRequestOptions {
                payload: Some(b"abcd".to_vec()),
                user_agent: Some(b"x".to_vec()),
                host: Some(b"lab.test".to_vec()),
                method: Some(b"PUT".to_vec()),
                url: Some(b"/lab".to_vec()),
                version: Some(b"HTTP/1.1".to_vec()),
                headers: vec![
                    (b"content-length".to_vec(), b"7".to_vec()),
                    (b"Cookie".to_vec(), b"first".to_vec()),
                ],
                cookies: vec![b"second".to_vec(), b"third".to_vec()],
            },
        ));
        v
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    fn input(o: &HttpRequestOptions) -> String {
        let mut s = String::new();
        for (k, v) in [
            ("payload", &o.payload),
            ("User-Agent:", &o.user_agent),
            ("Host:", &o.host),
            ("method", &o.method),
            ("url", &o.url),
            ("version", &o.version),
        ] {
            if let Some(v) = v {
                let _ = writeln!(s, "{k} {}", hex(v));
            }
        }
        for (k, v) in &o.headers {
            let _ = writeln!(s, "header {} {}", hex(k), hex(v));
        }
        for v in &o.cookies {
            let _ = writeln!(s, "Cookie: {}", hex(v));
        }
        s
    }

    // Ловит потерю запроса по умолчанию или добавление Host без опции: байты на проводе, не текст константы.
    #[test]
    fn default_request_is_99_bytes() {
        let r = http_request(&HttpRequestOptions::default()).expect("request");
        assert_eq!(r, DEFAULT);
        assert_eq!(r.len(), 99);
    }
    // Независимые байты C; ловит неверный порядок, нормализацию CR/LF и ошибочное редактирование токенов.
    #[test]
    fn http_request_golden_matches_c() {
        if let Some(dir) = std::env::var_os("RMASSCAN_HTTP_INPUTS") {
            let dir = Path::new(&dir);
            std::fs::create_dir_all(dir).expect("mkdir");
            for (name, o) in cases() {
                std::fs::write(dir.join(format!("{name}.in.txt")), input(&o)).expect("input");
            }
            return;
        }
        for (name, o) in cases() {
            assert_eq!(
                std::fs::read(format!("{DIR}/{name}.in.txt")).expect("input"),
                input(&o).as_bytes(),
                "{name}: input"
            );
            assert_eq!(
                http_request(&o).expect("request"),
                std::fs::read(format!("{DIR}/{name}.out")).expect("C"),
                "{name}"
            );
        }
    }
    #[test]
    fn payload_sets_content_length() {
        let r = http_request(&HttpRequestOptions {
            payload: Some(b"a\0b".to_vec()),
            ..Default::default()
        })
        .expect("request");
        assert!(r.ends_with(b"Content-Length: 3\r\n\r\na\0b"));
    }
    #[test]
    fn header_replace_respells_name_in_place() {
        let r = http_request(&HttpRequestOptions {
            headers: vec![(b"aCcEpT: \t".to_vec(), b"lab".to_vec())],
            ..Default::default()
        })
        .expect("request");
        assert_eq!(r, [&DEFAULT[..84], b"aCcEpT: lab\r\n\r\n"].concat());
    }
    #[test]
    fn user_agent_replace_matches_c() {
        let r = http_request(&HttpRequestOptions {
            user_agent: Some(b"x".to_vec()),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(r, b"GET / HTTP/1.0\r\nUser-Agent: x\r\nAccept: */*\r\n\r\n");
    }
    #[test]
    fn bare_lf_value_moves_later_headers_like_c() {
        let r = http_request(&HttpRequestOptions {
            host: Some(b"a\nb".to_vec()),
            headers: vec![(b"X".to_vec(), b"z".to_vec())],
            ..Default::default()
        })
        .expect("request");
        assert_eq!(r, [&DEFAULT[..97], b"Host: aX: z\r\n\nb\r\n\r\n"].concat());
    }
    #[test]
    fn crlf_value_reproduced() {
        let r = http_request(&HttpRequestOptions {
            host: Some(b"a\r\nX: b".to_vec()),
            ..Default::default()
        })
        .expect("request");
        assert_eq!(r, [&DEFAULT[..97], b"Host: a\r\nX: b\r\n\r\n"].concat());
    }
    #[test]
    fn cookies_add_lines() {
        let r = http_request(&HttpRequestOptions {
            cookies: vec![b"a=b".to_vec(), b"c=d".to_vec()],
            ..Default::default()
        })
        .expect("request");
        assert_eq!(
            r,
            [&DEFAULT[..97], b"Cookie: c=d\r\nCookie: a=b\r\n\r\n"].concat()
        );
    }
    #[test]
    fn more_than_16_headers_refused() {
        for (h, c) in [(17, 0), (0, 17), (17, 17)] {
            assert!(
                http_request(&HttpRequestOptions {
                    headers: vec![(b"X".to_vec(), b"v".to_vec()); h],
                    cookies: vec![b"c".to_vec(); c],
                    ..Default::default()
                })
                .is_err()
            );
        }
        assert!(
            http_request(&HttpRequestOptions {
                headers: vec![(b"X".to_vec(), b"v".to_vec()); 16],
                cookies: vec![b"c".to_vec(); 16],
                ..Default::default()
            })
            .is_ok()
        );
    }

    // Р1: любые байты, пустые токены и несколько переводов строки не приводят к неверным диапазонам splice
    // или поиску поля без продвижения; единственный отказ API — превышение 16 заголовков/cookie.
    #[test]
    fn http_request_never_panics() {
        use crate::banner1::TestRng;
        fn bytes(rng: &mut TestRng) -> Vec<u8> {
            let alphabet = b"a :\t\r\n\x0b\x0c\0\xff/x";
            (0..rng.below(40))
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect()
        }
        let mut rng = TestRng(0x478B_C002_FD34_D1F7);
        for round in 0..3000 {
            let mut o = HttpRequestOptions::default();
            for slot in [
                &mut o.payload,
                &mut o.user_agent,
                &mut o.host,
                &mut o.method,
                &mut o.url,
                &mut o.version,
            ] {
                if rng.below(3) != 0 {
                    *slot = Some(bytes(&mut rng));
                }
            }
            for _ in 0..rng.below(19) {
                o.headers.push((bytes(&mut rng), bytes(&mut rng)));
            }
            for _ in 0..rng.below(19) {
                o.cookies.push(bytes(&mut rng));
            }
            if round % 200 == 0 {
                o.payload = Some(vec![b'p'; 66_000]);
            }
            let r = http_request(&o);
            assert_eq!(
                r.is_err(),
                o.headers.len() > 16 || o.cookies.len() > 16,
                "round {round}"
            );
        }
    }
}
