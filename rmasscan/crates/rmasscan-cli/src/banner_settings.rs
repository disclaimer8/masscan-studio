//! Настройки TCP-баннеров из конфигурации скана (справка C2, C3): построение
//! [`TcpBannerSettings`] для стека задачи 14 и превращение `--hello-file` в `hello-string`.

use std::io::Read as _;

use rmasscan_core::config::{ScanConfig, apply_core_kv, hello_port_index};
use rmasscan_proto::base64::decode_hello_base64;
use rmasscan_proto::{HelloSet, HttpRequestOptions, TcpBannerSettings, http_request};

/// Самый длинный hello из файла: C кодирует в буфер 16383 байта и молча обрезает на 12285
/// (`src/main-conf.c:1246-1247`); здесь длиннее это отказ (E1.14).
const MAX_HELLO_FILE_BYTES: usize = 12285;

/// Настройки баннеров TCP из разобранной конфигурации: раскодирование `hello-string` (справка C2, порядок
/// задания сохранён, первая запись порта выигрывает уже в таблице hello), запрос HTTP из опций `--http-*`
/// (`src/main.c:656-718`, справка C3) и `--capture html`.
pub fn tcp_banner_settings(cfg: &ScanConfig) -> Result<TcpBannerSettings, String> {
    let mut hello_strings = Vec::with_capacity(cfg.hello_strings.len());
    for (port, value) in &cfg.hello_strings {
        hello_strings.push((*port, decode_hello_base64(value)?));
    }
    let bytes = |v: &Option<String>| v.as_ref().map(|s| s.as_bytes().to_vec());
    let request = http_request(&HttpRequestOptions {
        method: bytes(&cfg.http.method),
        url: bytes(&cfg.http.url),
        version: bytes(&cfg.http.version),
        host: bytes(&cfg.http.host),
        user_agent: bytes(&cfg.http.user_agent),
        payload: bytes(&cfg.http.payload),
        headers: cfg
            .http
            .headers
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect(),
        cookies: cfg
            .http
            .cookies
            .iter()
            .map(|c| c.as_bytes().to_vec())
            .collect(),
    })?;
    Ok(TcpBannerSettings {
        hello: HelloSet {
            http: cfg.hello_http,
            ssl: cfg.hello_ssl,
            smbv1: cfg.hello_smbv1,
        },
        hello_strings,
        http_request: request,
        capture_html: cfg.capture.html,
    })
}

/// `base64_encode` (`src/crypto-base64.c:10-62`): три байта в четыре знака, хвост с `=`/`==`.
fn encode_base64(data: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(B64[((n >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Текст `strerror(errno)` (`src/main-conf.c:1233`): у ошибки ОС это её описание без хвоста ` (os error N)`,
/// который добавляет `Display` std; у прочих ошибок их текст как есть.
fn c_strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_string),
        None => text,
    }
}

/// `--hello-file[PORT] <file>` (`SET_hello_file`, `src/main-conf.c:1207-1254`): файл читается (не больше
/// [`MAX_HELLO_FILE_BYTES`] байт и ещё один), кодируется и дальше ведёт себя как `hello-string[PORT]`; сам
/// ключ в эхо не пишется. Пустой файл это текст C `[FAILED] could not read hello file` (`:1239`); ошибка
/// открытия это две строки C (`:1232-1234`). Читает слой CLI: ядро файлов не трогает.
pub fn apply_hello_file(cfg: &mut ScanConfig, name: &str, filename: &str) -> Result<(), String> {
    let port = hello_port_index(name, filename).map_err(|e| e.to_string())?;
    // Каталог у C открывается, но `fread` даёт 0 байт: это текст «could not read», а не ошибка открытия.
    if std::fs::metadata(filename).is_ok_and(|m| m.is_dir()) {
        return Err("[FAILED] could not read hello file".to_string());
    }
    let read = std::fs::File::open(filename).and_then(|f| {
        let mut buf = Vec::new();
        f.take((MAX_HELLO_FILE_BYTES + 1) as u64)
            .read_to_end(&mut buf)
            .map(|_| buf)
    });
    let data = match read {
        Ok(data) => data,
        Err(e) => {
            return Err(format!(
                "[-] [FAILED] --hello-file\n[-] {filename}: {}",
                c_strerror(&e)
            ));
        }
    };
    if data.is_empty() {
        return Err("[FAILED] could not read hello file".to_string());
    }
    if data.len() > MAX_HELLO_FILE_BYTES {
        return Err(format!(
            "{filename}: hello file longer than {MAX_HELLO_FILE_BYTES} bytes"
        ));
    }
    let key = format!("hello-string[{port}]");
    let taken = apply_core_kv(cfg, &key, &encode_base64(&data)).map_err(|e| e.to_string())?;
    debug_assert!(taken);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::tcp_banner_settings;
    use rmasscan_core::config::{ScanConfig, apply_core_kv};

    fn cfg_with(kvs: &[(&str, &str)]) -> ScanConfig {
        let mut cfg = ScanConfig::default();
        for (k, v) in kvs {
            apply_core_kv(&mut cfg, k, v).unwrap();
        }
        cfg
    }

    /// Верный base64 справки C2 раскодируется побайтно как `src/crypto-base64.c:104-160`: с `==`, с `=`, без
    /// набивки и пустая строка (пустой hello, справка B5); для порта выигрывает первая заданная.
    #[test]
    fn hello_string_valid_base64_decodes_like_c() {
        let cfg = cfg_with(&[
            ("hello-string[80]", "QQ=="),
            ("hello-string[81]", "QUE="),
            ("hello-string[82]", "QUJD"),
            ("hello-string[83]", "QUE"),
            ("hello-string[84]", ""),
            ("hello-string[80]", "aGVsbG8="),
            ("hello", "http"),
        ]);
        let s = tcp_banner_settings(&cfg).unwrap();
        assert_eq!(
            s.hello_strings,
            [
                (80, b"A".to_vec()),
                (81, b"AA".to_vec()),
                (82, b"ABC".to_vec()),
                (83, b"AA".to_vec()),
                (84, Vec::new()),
                (80, b"hello".to_vec()),
            ]
        );
        assert!(s.hello.http && !s.hello.ssl && !s.hello.smbv1);
        // Неверная строка в программно собранной конфигурации отказывает и здесь.
        let mut bad = ScanConfig::default();
        bad.hello_strings.push((80, "Q".to_string()));
        assert!(tcp_banner_settings(&bad).is_err());
    }

    /// `--capture html` (`banner1->is_capture_html`) доходит до `TcpBannerSettings`; опции `--http-*` строят
    /// запрос через `http_request` задачи 10, включая CRLF в значениях.
    #[test]
    fn capture_html_reaches_settings() {
        let plain = tcp_banner_settings(&ScanConfig::default()).unwrap();
        assert!(!plain.capture_html);
        assert_eq!(plain.http_request.len(), 99);
        let cfg = cfg_with(&[
            ("capture", "html"),
            ("http-host", "a\r\nX: b"),
            ("http-method", "POST"),
        ]);
        let s = tcp_banner_settings(&cfg).unwrap();
        assert!(s.capture_html);
        assert!(s.http_request.starts_with(b"POST / HTTP/1.0\r\n"));
        assert!(
            s.http_request.windows(13).any(|w| w == b"Host: a\r\nX: b"),
            "{:?}",
            String::from_utf8_lossy(&s.http_request)
        );
        let off = cfg_with(&[("capture", "html"), ("nocapture", "html")]);
        assert!(!tcp_banner_settings(&off).unwrap().capture_html);
    }
}
