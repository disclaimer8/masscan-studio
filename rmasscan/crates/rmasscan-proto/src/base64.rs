//! Base64 значения `--hello-string` (`src/crypto-base64.c:104-160`, справка C2).

/// Значение знака алфавита (`rstr`, `src/crypto-base64.c:71-104`); `None` вне алфавита.
fn value_of(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

/// Раскодирует значение `--hello-string` побайтно как `base64_decode`
/// (`src/crypto-base64.c:104-160`) на верном входе по определению справки C2: только знаки
/// алфавита, затем не больше двух `=` и ничего после них; с `n` знаками алфавита
/// `n mod 4 != 1`, а при набивке `n mod 4` это 2 с ровно `==` или 3 с ровно `=`; пустая
/// строка верна (пустой hello). Любой другой вход это ошибка (E1.6: декодер C на части из
/// них зависает на позициях 3-4 квартета, `:134`, `:146`). Младшие биты последнего квартета
/// игнорируются, как у C.
pub fn decode_hello_base64(s: &str) -> Result<Vec<u8>, String> {
    let invalid = || format!("invalid base64 hello string: {s:?}");
    let bytes = s.as_bytes();
    let pad_at = bytes.iter().position(|&b| b == b'=').unwrap_or(bytes.len());
    let (alphabet, padding) = bytes.split_at(pad_at);
    if padding.iter().any(|&b| b != b'=') || padding.len() > 2 {
        return Err(invalid());
    }
    let mut values = Vec::with_capacity(alphabet.len());
    for &b in alphabet {
        values.push(value_of(b).ok_or_else(invalid)?);
    }
    match (values.len() % 4, padding.len()) {
        (_, 0) if values.len() % 4 != 1 => {}
        (2, 2) | (3, 1) => {}
        _ => return Err(invalid()),
    }
    let mut out = Vec::with_capacity(values.len() / 4 * 3 + 3);
    let (quads, remainder) = values.as_chunks::<4>();
    for q in quads {
        out.push((q[0] << 2) | (q[1] >> 4));
        out.push(((q[1] & 0x0f) << 4) | (q[2] >> 2));
        out.push(((q[2] & 0x03) << 6) | q[3]);
    }
    match remainder {
        [a, b] => out.push((a << 2) | (b >> 4)),
        [a, b, c] => {
            out.push((a << 2) | (b >> 4));
            out.push(((b & 0x0f) << 4) | (c >> 2));
        }
        _ => {}
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::decode_hello_base64;

    /// Векторы из декодера C на верном входе (справка C2): стандартное раскодирование, младшие биты последнего
    /// квартета игнорируются; всё вне определения «верный base64» это ошибка, а не зависание C (E1.6).
    #[test]
    fn decode_hello_base64_matches_c_vectors() {
        for (input, want) in [
            ("", &b""[..]),
            ("QQ==", &b"A"[..]),
            ("QUE=", &b"AA"[..]),
            ("QUJD", &b"ABC"[..]),
            ("QQ", &b"A"[..]),
            ("QUE", &b"AA"[..]),
            ("aGVsbG8=", &b"hello"[..]),
            ("aGVsbG8", &b"hello"[..]),
            ("+/+/", &[0xfb, 0xff, 0xbf][..]),
            ("QR==", &b"A"[..]), // младшие биты R игнорируются, как у C
            ("QUJDRA==", &b"ABCD"[..]),
        ] {
            assert_eq!(decode_hello_base64(input).as_deref(), Ok(want), "{input}");
        }
        for bad in [
            "QU JD", "QU=JD", "QUJD=", "Q", "QUJD*", "QUJD\n", "=", "==", "QQ=", "QUE==", "QQQ==",
            "QUJDRA=", "éé",
        ] {
            assert!(decode_hello_base64(bad).is_err(), "{bad:?}");
        }
    }

    /// Р1 класс б: любой вход разбирается без паники и без цикла без продвижения.
    #[test]
    fn decode_hello_base64_never_panics() {
        use crate::banner1::TestRng;
        let alphabet = b"ABab09+/= \xff\t";
        let mut rng = TestRng(0x0013_b64b);
        for _ in 0..2000 {
            let bytes: Vec<u8> = (0..rng.below(24))
                .map(|_| alphabet[rng.below(alphabet.len())])
                .collect();
            let s = String::from_utf8_lossy(&bytes);
            let _ = decode_hello_base64(&s);
        }
    }
}
