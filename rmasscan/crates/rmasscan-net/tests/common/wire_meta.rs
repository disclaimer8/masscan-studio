// Приёмка меты независимого свидетеля захвата (tcpdump, `rmasscan-lab capture dump`).
//
// Файл подключается и тестом `linux_wire.rs`, и тестами `rmasscan-lab` (через `include!`):
// один предикат на обе стороны, поэтому схема меты не может разойтись с приёмкой.

/// Сырое значение поля верхнего уровня в «сжатом» JSON (без пробелов): текст до `,` или `}`.
/// Только для плоских скаляров; вложенные массивы/объекты этим не разбираются.
pub fn raw_field<'a>(compact: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\":");
    let start = compact.find(&needle)? + needle.len();
    let rest = &compact[start..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// `None` — захват признан свидетелем полным и без потерь; иначе причина.
/// Требуется: `valid:true`, `kernel_drops:0`, `interface_drop_delta:0` (измерено, не null),
/// `interface_drops` равен 0 либо отсутствует в выводе tcpdump (null: старая версия не печатает
/// строку; тогда решает измеренная дельта sysfs), `invalid_reasons` пуст.
pub fn capture_meta_problem(compact: &str) -> Option<String> {
    let want = |key: &str, ok: &[&str]| match raw_field(compact, key) {
        Some(v) if ok.contains(&v) => None,
        other => Some(format!("{key}={other:?}")),
    };
    [
        want("valid", &["true"]),
        want("kernel_drops", &["0"]),
        want("interface_drop_delta", &["0"]),
        want("interface_drops", &["0", "null"]),
        (!compact.contains("\"invalid_reasons\":[]")).then(|| "invalid_reasons not empty".into()),
    ]
    .into_iter()
    .flatten()
    .next()
}

/// Мета, как её пишет `rmasscan-lab capture dump` для чистого захвата (значения от c01 run1).
/// Тест `rmasscan-lab` сверяет набор ключей с настоящим выводом свидетеля: образец не отстанет.
#[allow(dead_code)]
pub const SAMPLE_META: &str = r#"{"end_marker_frames":3,"iface_rxtx_delta_hi":10,"iface_rxtx_delta_lo":10,"interface_drop_delta":0,"interface_drops":0,"invalid_reasons":[],"kernel_drops":0,"pcap_frames":10,"pcap_sha256":"3914af3dc16215bde48e5aa2603f6ada7511284914e9e8006b9ac784b47660ee","pcap_size_bytes":780,"quiesced_before_stop":true,"received_by_filter":10,"start_marker_frames":1,"tcpdump_argv":["tcpdump","-i","lab0","-U","--immediate-mode"],"tcpdump_captured":10,"valid":true}"#;
