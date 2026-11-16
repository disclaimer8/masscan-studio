//! Настройки TCP-баннеров из конфигурации скана (справка C2, C3): построение
//! [`TcpBannerSettings`] для стека задачи 14 и превращение `--hello-file` в `hello-string`.

use std::io::Read as _;

use rmasscan_core::config::{ScanConfig, apply_core_kv, hello_port_index};
use rmasscan_proto::base64::decode_hello_base64;
use rmasscan_proto::{HelloSet, HttpRequestOptions, TcpBannerSettings, TlsSettings, http_request};

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
    // Hello TLS строятся один раз на скан на текущем времени (`ssl_hello` в `tcpcon_set_parameter`,
    // справка 4c §A2); режимы проверок добавит задача 9, захват уже разобран в 4a.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut tls = TlsSettings::new(now);
    tls.capture_cert = cfg.capture.cert;
    tls.capture_heartbleed = cfg.capture.heartbleed;
    tls.capture_ticketbleed = cfg.capture.ticketbleed;
    Ok(TcpBannerSettings {
        hello: HelloSet {
            http: cfg.hello_http,
            ssl: cfg.hello_ssl,
            smbv1: cfg.hello_smbv1,
        },
        hello_strings,
        http_request: request,
        capture_html: cfg.capture.html,
        tls,
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

/// Текст `strerror(errno)` после `fopen` (`src/main-conf.c:1231-1234`) на этой ОС. В Linux и macOS код ошибки ОС
/// и есть `errno`, а описание std это `strerror_r` той же libc, что у C: берётся оно без хвоста ` (os error N)`,
/// который добавляет `Display` std. В Windows код std это код Win32 (`GetLastError`), а текст std это
/// `FormatMessageW` ("The system cannot find the file specified."); C там печатает `strerror` CRT от `errno`, в
/// который `fopen` переводит тот же код Win32: перевод [`crt_errno_of_win32`] и текст [`crt_strerror`]. У ошибок без
/// кода ОС их текст как есть.
fn c_strerror(e: &std::io::Error) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) if cfg!(windows) => crt_strerror(crt_errno_of_win32(code)).to_string(),
        Some(code) => text
            .strip_suffix(&format!(" (os error {code})"))
            .map_or_else(|| text.clone(), str::to_string),
        None => text,
    }
}

/// `errno` CRT (`errno.h` MSVC) по номеру.
mod crt {
    pub(super) const ENOENT: i32 = 2;
    pub(super) const E2BIG: i32 = 7;
    pub(super) const ENOEXEC: i32 = 8;
    pub(super) const EBADF: i32 = 9;
    pub(super) const ECHILD: i32 = 10;
    pub(super) const EAGAIN: i32 = 11;
    pub(super) const ENOMEM: i32 = 12;
    pub(super) const EACCES: i32 = 13;
    pub(super) const EEXIST: i32 = 17;
    pub(super) const EXDEV: i32 = 18;
    pub(super) const EISDIR: i32 = 21;
    pub(super) const EINVAL: i32 = 22;
    pub(super) const EMFILE: i32 = 24;
    pub(super) const ENOSPC: i32 = 28;
    pub(super) const EPIPE: i32 = 32;
    pub(super) const ENOTEMPTY: i32 = 41;
    pub(super) const EILSEQ: i32 = 42;
}

/// `errno` CRT для кода Win32, как его ставит `fopen` (`_dosmaperr`, таблица `errtable` UCRT `errno.cpp`; у
/// msvcrt `dosmap.c` та же без 1113): коды таблицы, затем 19-36 (`ERROR_WRITE_PROTECT`..
/// `ERROR_SHARING_BUFFER_EXCEEDED`) это `EACCES`, 188-202 (`ERROR_INVALID_STARTING_CODESEG`..
/// `ERROR_INFLOOP_IN_RELOC_CHAIN`) `ENOEXEC`, остальное `EINVAL`.
fn crt_errno_of_win32(code: i32) -> i32 {
    use crt::*;
    match code {
        // FILE_NOT_FOUND, PATH_NOT_FOUND, INVALID_DRIVE, NO_MORE_FILES, BAD_NETPATH, BAD_NET_NAME, BAD_PATHNAME,
        // FILENAME_EXCED_RANGE.
        2 | 3 | 15 | 18 | 53 | 67 | 161 | 206 => ENOENT,
        4 => EMFILE,
        // ACCESS_DENIED, CURRENT_DIRECTORY, LOCK_VIOLATION, NETWORK_ACCESS_DENIED, CANNOT_MAKE, FAIL_I24,
        // DRIVE_LOCKED, SEEK_ON_DEVICE, NOT_LOCKED, LOCK_FAILED, и диапазон 19-36 (SHARING_VIOLATION 32 в нём).
        5 | 16 | 19..=36 | 65 | 82 | 83 | 108 | 132 | 158 | 167 => EACCES,
        6 | 114 | 130 => EBADF,
        7..=9 | 1816 => ENOMEM,
        10 => E2BIG,
        11 | 188..=202 => ENOEXEC,
        17 => EXDEV,
        80 | 183 => EEXIST,
        89 | 164 | 215 => EAGAIN,
        109 => EPIPE,
        112 => ENOSPC,
        128 | 129 => ECHILD,
        145 => ENOTEMPTY,
        1113 => EILSEQ,
        _ => EINVAL,
    }
}

/// `strerror` CRT (`_sys_errlist`, UCRT `syserr.cpp`, у msvcrt те же тексты) для каждого `errno`, который даёт
/// [`crt_errno_of_win32`]. ENOENT, EACCES, EISDIR и прочие частые совпадают с glibc; ENOMEM у CRT "Not enough
/// space".
fn crt_strerror(errno: i32) -> &'static str {
    use crt::*;
    match errno {
        ENOENT => "No such file or directory",
        E2BIG => "Arg list too long",
        ENOEXEC => "Exec format error",
        EBADF => "Bad file descriptor",
        ECHILD => "No child processes",
        EAGAIN => "Resource temporarily unavailable",
        ENOMEM => "Not enough space",
        EACCES => "Permission denied",
        EEXIST => "File exists",
        EXDEV => "Improper link",
        EISDIR => "Is a directory",
        EINVAL => "Invalid argument",
        EMFILE => "Too many open files",
        ENOSPC => "No space left on device",
        EPIPE => "Broken pipe",
        ENOTEMPTY => "Directory not empty",
        EILSEQ => "Illegal byte sequence",
        _ => "Unknown error",
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

    /// Текст ошибки `fopen` у C на каждой ОС (4b, приёмка на госте Windows): в Windows код Win32 идёт через
    /// `_dosmaperr` в `errno` и `strerror` CRT, а не в текст `FormatMessageW`; в Linux и macOS это `strerror` libc.
    /// Сам перевод проверяется на любой ОС.
    #[test]
    fn open_errors_print_the_c_library_text() {
        use super::{c_strerror, crt_errno_of_win32, crt_strerror};
        let win = |code| crt_strerror(crt_errno_of_win32(code));
        for (code, text) in [
            (2, "No such file or directory"),   // ERROR_FILE_NOT_FOUND
            (3, "No such file or directory"),   // ERROR_PATH_NOT_FOUND
            (206, "No such file or directory"), // ERROR_FILENAME_EXCED_RANGE
            (5, "Permission denied"),           // ERROR_ACCESS_DENIED (у CRT и каталог)
            (32, "Permission denied"),          // ERROR_SHARING_VIOLATION, диапазон 19-36
            (4, "Too many open files"),         // ERROR_TOO_MANY_OPEN_FILES
            (8, "Not enough space"),            // ERROR_NOT_ENOUGH_MEMORY
            (123, "Invalid argument"),          // ERROR_INVALID_NAME, вне таблицы
            (1113, "Illegal byte sequence"),    // ERROR_NO_UNICODE_TRANSLATION
            (193, "Exec format error"),         // ERROR_BAD_EXE_FORMAT, диапазон 188-202
        ] {
            assert_eq!(win(code), text, "Win32 {code}");
        }
        assert_eq!(crt_strerror(super::crt::EISDIR), "Is a directory");
        // Код 2 это ENOENT в Linux и macOS и ERROR_FILE_NOT_FOUND в Windows: один текст C везде, без хвоста std.
        assert_eq!(
            c_strerror(&std::io::Error::from_raw_os_error(2)),
            "No such file or directory"
        );
        assert_eq!(c_strerror(&std::io::Error::other("x")), "x");
    }
}
