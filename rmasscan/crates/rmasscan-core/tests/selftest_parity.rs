//! Карта соответствия C self-tests -> Rust-тесты (AGPL-3.0, masscan © Robert
//! David Graham, HEAD 8e6b3b0).
//!
//! `masscan --selftest` вызывает 31 тест подряд (src/main.c:1821-1851,
//! `Operation_Selftest`). Таблица `PARITY` фиксирует для каждого из них, какой
//! Rust-тест его переносит, либо что он отложен на этап 2 или не переносится,
//! с причиной. Тест `every_named_rust_test_exists` читает исходники через
//! `include_str!` и проверяет, что каждое названное имя это реальная
//! `fn имя(` с атрибутом `#[test]` рядом, так что переименование теста без
//! обновления карты роняет сборку тестов.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    /// Весь IPv4/TCP-смысл C-теста покрыт.
    Ported,
    /// Покрыта IPv4/TCP-часть; остальное (IPv6, UDP, TCP-опции) вне v1/этапа 1.
    Partial,
    /// Относится к I/O и приёмной части: этап 2.
    Stage2,
    /// Не переносится вообще (нет аналога в порте).
    NotPorted,
}
use Status::*;

/// `(файл, имя теста)`; файл относителен `rmasscan-core`.
type RustTest = (&'static str, &'static str);

struct Entry {
    /// Имя C-функции.
    c_test: &'static str,
    /// Строка вызова в main.c.
    main_c_line: u32,
    /// Определение теста в C.
    c_def: &'static str,
    status: Status,
    rust: &'static [RustTest],
    reason: &'static str,
}

const PARITY: &[Entry] = &[
    Entry {
        c_test: "massip_selftest",
        main_c_line: 1821,
        c_def: "massip.c:112",
        status: Partial,
        rust: &[
            (
                "src/massip.rs",
                "excludes_then_optimize_change_counts_and_pick",
            ),
            ("src/massip.rs", "empty_range_is_zero"),
            (
                "tests/scan_golden.rs",
                "list_scan_matches_c_oracle_fixtures",
            ),
        ],
        reason: "C-тест целиком на IPv6 (2607:f8b0:4002:801::2004/124, excludes, range); \
                 IPv6 вне v1. IPv4-аналог: excludes -> optimize -> count/pick, плюс golden -sL.",
    },
    Entry {
        c_test: "ranges6_selftest",
        main_c_line: 1822,
        c_def: "massip-rangesv6.c:697",
        status: NotPorted,
        rust: &[],
        reason: "IPv6-диапазоны вне v1 (спека §3); парсер возвращает Ipv6NotSupported.",
    },
    Entry {
        c_test: "dedup_selftest",
        main_c_line: 1823,
        c_def: "main-dedup.c:333",
        status: Stage2,
        rust: &[],
        reason: "Дедупликация ответов приёмной части; в этапе 1 нет приёма.",
    },
    Entry {
        c_test: "checksum_selftest",
        main_c_line: 1824,
        c_def: "util-checksum.c:229",
        status: Partial,
        rust: &[
            ("src/checksum.rs", "checksum_ipv4_reference_vectors"),
            ("src/checksum.rs", "fold_u64_overflowing_incremental_sum"),
            ("src/checksum.rs", "tcp_ipv4_partial_matches_c"),
        ],
        reason: "Векторы IPv4 TCP/UDP/ICMP перенесены дословно; IPv6-векторы (checksum_ipv6) вне v1.",
    },
    Entry {
        c_test: "ipv4address_selftest",
        main_c_line: 1825,
        c_def: "massip-addr.c:307",
        status: Ported,
        rust: &[("src/scan.rs", "format_line_single_vs_multi_port")],
        reason: "Проверка вывода точечной записи IPv4; в Rust форматирует core::net::Ipv4Addr, \
                 формат строки -sL закреплён тестом и golden-фикстурами.",
    },
    Entry {
        c_test: "ipv6address_selftest",
        main_c_line: 1826,
        c_def: "massip-addr.c:276",
        status: NotPorted,
        rust: &[],
        reason: "IPv6 вне v1.",
    },
    Entry {
        c_test: "proto_coap_selftest",
        main_c_line: 1827,
        c_def: "proto-coap.c:646",
        status: Stage2,
        rust: &[],
        reason: "Разбор баннеров CoAP: приём/баннеры, этап 2+.",
    },
    Entry {
        c_test: "smack_selftest",
        main_c_line: 1828,
        c_def: "smack1.c:1690",
        status: Stage2,
        rust: &[],
        reason: "Автомат поиска шаблонов для баннеров (SMACK): этап 2+.",
    },
    Entry {
        c_test: "sctp_selftest",
        main_c_line: 1829,
        c_def: "proto-sctp.c:195",
        status: NotPorted,
        rust: &[],
        reason: "SCTP вне v1 (только TCP); смещение порт-пространства сохранено константой.",
    },
    Entry {
        c_test: "base64_selftest",
        main_c_line: 1830,
        c_def: "crypto-base64.c:180",
        status: Stage2,
        rust: &[],
        reason: "Нужен для баннеров/вывода; в этапе 1 нет.",
    },
    Entry {
        c_test: "banner1_selftest",
        main_c_line: 1831,
        c_def: "proto-banner1.c:706",
        status: Stage2,
        rust: &[],
        reason: "Баннеры вне этапа 1.",
    },
    Entry {
        c_test: "output_selftest",
        main_c_line: 1832,
        c_def: "output.c:995",
        status: Stage2,
        rust: &[],
        reason: "Форматы вывода результатов (XML/JSON/grep): этап 2+; \
                 -sL и --echo покрыты golden-тестами.",
    },
    Entry {
        c_test: "siphash24_selftest",
        main_c_line: 1833,
        c_def: "crypto-siphash24.c:246",
        status: Ported,
        rust: &[
            ("src/cookie.rs", "siphash24_reference_vectors"),
            ("src/cookie.rs", "syn_cookie_matches_c_values"),
        ],
        reason: "Векторы из C; реализация siphasher =1.0.4.",
    },
    Entry {
        c_test: "ntp_selftest",
        main_c_line: 1834,
        c_def: "proto-ntp.c:289",
        status: Stage2,
        rust: &[],
        reason: "UDP-протокол NTP: вне v1.",
    },
    Entry {
        c_test: "snmp_selftest",
        main_c_line: 1835,
        c_def: "proto-snmp.c:675",
        status: Stage2,
        rust: &[],
        reason: "UDP-протокол SNMP: вне v1.",
    },
    Entry {
        c_test: "proto_isakmp_selftest",
        main_c_line: 1836,
        c_def: "proto-isakmp.c:547",
        status: Stage2,
        rust: &[],
        reason: "UDP-протокол ISAKMP: вне v1.",
    },
    Entry {
        c_test: "templ_payloads_selftest",
        main_c_line: 1837,
        c_def: "templ-payloads.c:903",
        status: Stage2,
        rust: &[],
        reason: "UDP-нагрузки: вне v1.",
    },
    Entry {
        c_test: "blackrock_selftest",
        main_c_line: 1838,
        c_def: "crypto-blackrock.c:373",
        status: Ported,
        rust: &[
            ("src/blackrock.rs", "shuffle_unshuffle_round_trip"),
            ("src/blackrock.rs", "shuffle_is_a_permutation"),
            (
                "src/blackrock.rs",
                "tiny_ranges_are_permutations_and_round_trip",
            ),
            (
                "tests/blackrock_golden.rs",
                "listscan_order_matches_oracle_for_single_range_single_port",
            ),
        ],
        reason: "Round-trip (range 1000, 4 раунда) и перестановка; сверх C: golden-порядок оракула. \
                 Диапазоны перестановки отличаются от C (:401-408), см. прогресс T3.",
    },
    Entry {
        c_test: "rawsock_selftest",
        main_c_line: 1839,
        c_def: "rawsock.c:999",
        status: Stage2,
        rust: &[],
        reason: "Raw-сокеты/pcap/адаптеры: I/O, этап 2.",
    },
    Entry {
        c_test: "lcg_selftest",
        main_c_line: 1840,
        c_def: "crypto-lcg.c:364",
        status: NotPorted,
        rust: &[],
        reason: "LCG-перемешиватель нигде не вызывается из пути сканирования, только из selftest \
                 (grep lcg_ в src/*.c); сканирование использует BlackRock.",
    },
    Entry {
        c_test: "template_selftest",
        main_c_line: 1841,
        c_def: "templ-pkt.c:1525",
        status: Partial,
        rust: &[
            ("src/packet.rs", "default_template_is_58_bytes"),
            ("src/packet.rs", "syn_frame_fixed_fields"),
            ("src/packet.rs", "syn_frame_checksums_validate"),
            ("src/packet.rs", "syn_frame_matches_c_bytes"),
        ],
        reason: "SYN-шаблон и его контрольные суммы перенесены; вложенный templ_tcp_selftest \
                 (templ-tcp-hdr.c:1531, правка TCP-опций) — этап 2.",
    },
    Entry {
        c_test: "ranges_selftest",
        main_c_line: 1842,
        c_def: "massip-rangesv4.c:1234",
        status: Ported,
        rust: &[
            ("src/ranges.rs", "sort_merges_overlapping_ipv4"),
            ("src/ranges.rs", "pick_reproduces_sorted_list"),
            ("src/ranges.rs", "removal_reference_selftest"),
            ("src/ranges.rs", "ports_selftest"),
            ("src/ranges.rs", "range_is_cidr_cases"),
            ("src/ranges.rs", "exclude_matches_reference_algorithm"),
            ("src/targets.rs", "parse_ipv4_single_cidr_dash"),
        ],
        reason: "Включает exclude_selftest (massip-rangesv4.c:1154, вызов :1242): \
                 exclude_matches_reference_algorithm. Парсинг диапазонов из C-теста — в targets.rs.",
    },
    Entry {
        c_test: "massip_parse_selftest",
        main_c_line: 1843,
        c_def: "massip-parse.c:1275",
        status: Partial,
        rust: &[
            ("src/targets.rs", "add_target_string_selftest_cases"),
            ("src/targets.rs", "add_target_string_ipv6_and_edges"),
            ("src/targets.rs", "parse_ports_forms"),
        ],
        reason: "IPv4-часть перенесена; IPv6-таблица test_cases вне v1 (парсер даёт Ipv6NotSupported).",
    },
    Entry {
        c_test: "pixie_time_selftest",
        main_c_line: 1844,
        c_def: "pixie-timer.c:270",
        status: Partial,
        rust: &[("src/throttle.rs", "system_clock_is_monotonic_micros")],
        reason: "Проверяется монотонность и единицы SystemClock; тест C со сном 456789 мкс \
                 (допуск 0.9-1.9x) в Rust не воспроизведён как flaky по времени.",
    },
    Entry {
        c_test: "rte_ring_selftest",
        main_c_line: 1845,
        c_def: "rte-ring.c:376",
        status: NotPorted,
        rust: &[],
        reason: "Кольцо между потоками передачи и приёма; в этапе 1 один поток, std-каналы при необходимости.",
    },
    Entry {
        c_test: "mainconf_selftest",
        main_c_line: 1846,
        c_def: "main-conf.c:3946",
        status: NotPorted,
        rust: &[],
        reason: "Проверяет trim() и masscan_conf_contains() C-парсера argv; в Rust разбор на clap и \
                 config::read, их покрывают тесты config/echo/CLI (напр. read_skips_comments_blank_and_punct_lines).",
    },
    Entry {
        c_test: "zeroaccess_selftest",
        main_c_line: 1847,
        c_def: "proto-zeroaccess.c:274",
        status: Stage2,
        rust: &[],
        reason: "UDP-протокол ZeroAccess: вне v1.",
    },
    Entry {
        c_test: "nmapserviceprobes_selftest",
        main_c_line: 1848,
        c_def: "read-service-probes.c:1131",
        status: Stage2,
        rust: &[],
        reason: "Файл nmap-service-probes для баннеров: этап 2+.",
    },
    Entry {
        c_test: "rstfilter_selftest",
        main_c_line: 1849,
        c_def: "misc-rstfilter.c:138",
        status: Stage2,
        rust: &[],
        reason: "Фильтр RST на приёмной стороне: этап 2.",
    },
    Entry {
        c_test: "masscan_app_selftest",
        main_c_line: 1850,
        c_def: "masscan-app.c:115",
        status: Stage2,
        rust: &[],
        reason: "Имена протоколов приложений для вывода баннеров: этап 2+.",
    },
    Entry {
        c_test: "icmp_selftest",
        main_c_line: 1851,
        c_def: "proto-icmp.c:57",
        status: Stage2,
        rust: &[],
        reason: "Разбор ICMP-ответов: приёмная часть, этап 2.",
    },
];

/// Исходники, в которых ищутся названные тесты. Список явный: новый файл с
/// тестом нужно добавить сюда, иначе тест карты его не увидит.
const SOURCES: &[(&str, &str)] = &[
    ("src/massip.rs", include_str!("../src/massip.rs")),
    ("src/checksum.rs", include_str!("../src/checksum.rs")),
    ("src/scan.rs", include_str!("../src/scan.rs")),
    ("src/cookie.rs", include_str!("../src/cookie.rs")),
    ("src/blackrock.rs", include_str!("../src/blackrock.rs")),
    ("src/packet.rs", include_str!("../src/packet.rs")),
    ("src/ranges.rs", include_str!("../src/ranges.rs")),
    ("src/targets.rs", include_str!("../src/targets.rs")),
    ("src/throttle.rs", include_str!("../src/throttle.rs")),
    ("tests/scan_golden.rs", include_str!("scan_golden.rs")),
    (
        "tests/blackrock_golden.rs",
        include_str!("blackrock_golden.rs"),
    ),
];

fn is_test_fn(src: &str, name: &str) -> bool {
    let needle = format!("fn {name}(");
    src.match_indices(&needle).any(|(pos, _)| {
        // `#[test]` в пределах трёх строк выше (допускаем #[ignore], #[should_panic]).
        let head = &src[..pos];
        head.lines().rev().take(4).any(|l| l.trim() == "#[test]")
    })
}

#[test]
fn every_named_rust_test_exists() {
    for e in PARITY {
        for (file, name) in e.rust {
            let (_, src) = SOURCES
                .iter()
                .find(|(f, _)| f == file)
                .unwrap_or_else(|| panic!("{}: файл {file} не в SOURCES", e.c_test));
            assert!(
                is_test_fn(src, name),
                "{}: нет #[test] fn {name} в {file}",
                e.c_test
            );
        }
    }
}

#[test]
fn map_covers_all_31_c_selftests_in_main_c_order() {
    assert_eq!(PARITY.len(), 31, "main.c:1821-1851 вызывает 31 self-test");
    for (k, e) in PARITY.iter().enumerate() {
        assert_eq!(e.main_c_line as usize, 1821 + k, "{}", e.c_test);
    }
    let mut names: Vec<_> = PARITY.iter().map(|e| e.c_test).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 31, "имена не уникальны");
}

#[test]
fn statuses_are_consistent_with_mappings_and_reasons() {
    for e in PARITY {
        assert!(!e.reason.is_empty(), "{}: нужна причина", e.c_test);
        assert!(e.c_def.contains(".c:"), "{}", e.c_test);
        match e.status {
            Ported | Partial => assert!(!e.rust.is_empty(), "{}: нет Rust-тестов", e.c_test),
            Stage2 | NotPorted => assert!(e.rust.is_empty(), "{}: есть тесты", e.c_test),
        }
    }
}

#[test]
fn print_parity_summary() {
    // Видно с `--nocapture`: сводка по статусам.
    let count = |s| PARITY.iter().filter(|e| e.status == s).count();
    println!(
        "selftest parity: ported={} partial={} stage2={} not_ported={}",
        count(Ported),
        count(Partial),
        count(Stage2),
        count(NotPorted)
    );
}
