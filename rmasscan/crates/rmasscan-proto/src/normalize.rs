//! Нормализаторы строк баннера: `src/output.c:143-170`, `src/out-json.c:68-97`.

/// Буфер `normalize_string` у C (`src/output.c`).
const TEXT_BUF: usize = 8192;
/// Буфер `normalize_json_string` у C (`src/out-json.c:108`).
const JSON_BUF: usize = 65_536;

/// `isprint` в C-локали (masscan не вызывает `setlocale`) и не один из `< > & \ " '`.
fn plain(c: u8) -> bool {
    (0x20..=0x7E).contains(&c) && !matches!(c, b'<' | b'>' | b'&' | b'\\' | b'"' | b'\'')
}

fn hex(n: u8) -> char {
    char::from(b"0123456789abcdef"[usize::from(n & 0xF)])
}

/// Побайтно по C, включая «дыры»: печатный байт добавляется при `offset + 2 < buf`,
/// экранирование при `offset + esc < buf` (место под завершающий NUL).
fn normalize(px: &[u8], buf: usize, esc: usize, json: bool) -> String {
    let mut out = String::new();
    for &c in px {
        let offset = out.len();
        if plain(c) {
            if offset + 2 < buf {
                out.push(char::from(c));
            }
        } else if offset + esc < buf {
            out.push('\\');
            out.push(if json { 'u' } else { 'x' });
            if json {
                out.push_str("00");
            }
            out.push(hex(c >> 4));
            out.push(hex(c));
        }
    }
    out
}

/// `normalize_string` (`src/output.c:143-170`): `\xNN` строчными, буфер 8192.
pub fn normalize_string(px: &[u8]) -> String {
    normalize(px, TEXT_BUF, 5, false)
}

/// `normalize_json_string` (`src/out-json.c:68-97`): `\u00nn` строчными, буфер 65 536.
pub fn normalize_json_string(px: &[u8]) -> String {
    normalize(px, JSON_BUF, 7, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_string_escapes_c_set() {
        for b in 0u8..=255 {
            let got = normalize_string(&[b]);
            let printable = (0x20..=0x7E).contains(&b) && !b"<>&\\\"'".contains(&b);
            if printable {
                assert_eq!(got, char::from(b).to_string(), "byte {b:#x}");
            } else {
                assert_eq!(got, format!("\\x{b:02x}"), "byte {b:#x}");
            }
        }
    }

    #[test]
    fn normalize_string_holes_near_8190() {
        let mut px = vec![b'A'; 8187];
        px.push(1);
        px.extend_from_slice(b"abc");
        let s = normalize_string(&px);
        assert_eq!(s.len(), 8190);
        assert!(s.ends_with("abc") && !s.contains("\\x01"));
        assert_eq!(&s[..8187], "A".repeat(8187));

        let mut px = vec![b'A'; 8186];
        px.push(1);
        px.push(b'a');
        let s = normalize_string(&px);
        assert_eq!(s.len(), 8190);
        assert!(s.ends_with("\\x01") && !s.contains('a'));
        assert_eq!(&s[..8186], "A".repeat(8186));
    }

    #[test]
    fn normalize_json_string_latin1() {
        assert_eq!(normalize_json_string(b"\xC3\xA9"), "\\u00c3\\u00a9");
        assert_eq!(normalize_json_string(b"a\"b"), "a\\u0022b");
    }

    #[test]
    fn normalize_json_truncates_at_65536_rule() {
        let s = normalize_json_string(&vec![b'A'; 70_000]);
        assert_eq!(s.len(), 65_534);
        // 10922 экранов по 6 = 65532; следующий не влезает (65532 + 7 >= 65536), печатный влезает.
        let mut px = vec![1u8; 10_922];
        px.push(1);
        px.extend_from_slice(b"xyz");
        let s = normalize_json_string(&px);
        assert_eq!(s.len(), 65_532 + 2);
        assert!(s.ends_with("xy"));
    }
}
