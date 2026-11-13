# rmasscan: баннеры, подэтап 4a (записи баннеров и UDP) — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development`. Шаги в чекбоксах (`- [ ]`).
> Цикл на каждую задачу: RED (тест) → FAIL → минимальная реализация со ссылкой на C `файл:строка` → PASS → коммит.

**Goal:** записи баннеров (`-oB` типы 9/13 и их текстовые формы) во всех форматах вывода и в `--readscan` побайтово как
у masscan `8e6b3b0`, `--banners`/`--rawudp` для UDP-сканов с разбором ответов DNS, NTP, NetBIOS, SNMP, memcached, CoAP,
ISAKMP и ZeroAccess, плюс хвосты этапа IPv6.

**Architecture:** новый крейт `rmasscan-proto` (`#![forbid(unsafe_code)]`, без зависимостей кроме `rmasscan-core`)
держит таблицу приложений, нормализаторы строк, тип записи баннера и UDP-парсеры как чистые функции. `rmasscan-core`
отдаёт полезную нагрузку UDP-ответа, `rmasscan-engine` вызывает парсеры после дедупа и доставляет баннеры CLI новым
аддитивным API, не трогая `Event`. `rmasscan-cli` пишет баннеры во все форматы и читает их в `--readscan`.

**Tech Stack:** Rust 1.99.1, workspace `rmasscan/`, без новых внешних крейтов (CRC-32 ZeroAccess пишется руками).

**Spec:** [docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md](../specs/2026-11-13-rmasscan-banners-design.md)
(Р1–Р17) и её справка
[записи баннеров и UDP](../specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md) (разделы A и B — источник всех
байтов этого плана; план на неё ссылается, а не копирует).

## Global Constraints

- `#![forbid(unsafe_code)]` в `rmasscan-proto`; `Cargo.lock` меняется только добавлением нового крейта workspace;
  `deny.toml` без изменений; ни одного файла C, C++ или скрипта на запрещённом интерпретаторе (`language-guard`).
- `studio/` не меняется ни на байт; `Event`, `Reply` и существующие методы `EngineHandle` не меняются (Р11). Studio
  собирается и проходит `cargo xtask test` без правок.
- Без `--banners`/`--rawudp` вывод и кадры rmasscan не меняются ни на байт (регресс-тест в задаче 6).
- Каждый парсер — тотальная функция: никакого `panic!`, `unwrap` на данных, индексации без проверки, рекурсии без
  предела, цикла без продвижения (Р1 класс б). Тест «никогда не паникует» на случайном входе обязателен для каждого.
- Офлайн-тесты не шлют ни одного кадра; живые окна только на стенде (`wire-lab.sh`), доказательства в нейтральных
  каталогах, `rmasscan-lab privacy-scan` перед коммитом доказательств; репозиторий публичный.
- Сборки и тесты на ноутбуке Linux или Mac; Windows/macOS clippy ловит GitHub CI. Каталог сборки — свой
  `CARGO_TARGET_DIR` вне дерева; после задачи `rmasscan/target` не должно быть.
- Комментарии к коду — со ссылкой на C `src/файл.c:строка`; языковая политика текстов как в соседних файлах.

## Review Focus

1. **Граница длины `-oB`:** полезная нагрузка 113/114 байт (IPv4) и 100/101 (IPv6) переключает однобайтовую длину на
   двухбайтовую, а 16 370 / 16 357 байт выбрасывают запись молча — тест `binary_banner_length_boundaries` (задача 2).
2. **Усечение нормализаторов с «дырами»:** печатные байты после позиции 8187 продолжают дописываться, когда `\xNN` уже
   не влезает — тест `normalize_string_holes_near_8190` (задача 1).
3. **Дубль UDP-ответа и повтор зонда:** у C каждая датаграмма даёт статус и баннеры, у rmasscan статус дедуплицирован;
   баннеры должны идти только за ответом, прошедшим дедуп — тест `udp_duplicate_reply_gives_one_status_and_one_banner_set`
   (задача 6).
4. **Пользовательские нагрузки (`--nmap-payloads`) без cookie:** DNS/NBNS/SNMP молчат, CoAP/memcached пишут
   ` IP-MISMATCH`, ISAKMP уходит в raw (справка B10) — тест `user_payload_cookie_semantics` (задача 6).
5. **ISAKMP с полезной нагрузкой нулевой длины и SNMP с длинной OID:** у C бесконечный цикл и переполнение `u64` —
   тесты `isakmp_zero_length_payload_terminates` и `snmp_huge_subid_does_not_overflow` (задача 5 и 4).

---

### Задача 0: хвосты этапа IPv6

Список из журнала финального ревью этапа IPv6 (PR #58). Каждый пункт сначала проверить на текущем коде: если уже
исправлен, отметить в отчёте и пропустить.

**Files:**
- Modify: `rmasscan/crates/rmasscan-net/src/ndp_resolve.rs`, `rmasscan/crates/rmasscan-net/src/arp_resolve.rs` (только
  если нужен общий помощник), `rmasscan/crates/rmasscan-core/src/{ndp.rs,config.rs,ndp_tests.rs}`,
  `rmasscan/crates/rmasscan-core/src/receive.rs` (проптесты), `rmasscan/README.md`

- [ ] **Step 1: тесты.** `ndp_policy_zero_interval_is_invalid` и `ndp_policy_huge_timeout_is_invalid` (резолвер NDP
  отказывает `InvalidPolicy` так же, как ARP в `arp_resolve.rs:177-186`, без деления на ноль и переполнения срока);
  `exclude_required_prints_c_second_hint` (текст `ConfigError::ExcludeRequired` — три строки C
  `src/main.c:1236-1238`, включая ` [hint] use "--exclude 255.255.255.255" as a simple confirmation`); `r24_boundary_exactly_1e9` (ровно 1 000 000 000
  адресов не требует подтверждения, 1 000 000 001 требует; IPv4 плюс IPv6-исключение — по правилу R23 этапа IPv6).
- [ ] **Step 2: FAIL**, затем реализация: политика NDP проверяется как ARP; сроки через checked-арифметику.
- [ ] **Step 3: проптесты IPv6/NDP глубже.** Генераторы `parse_reply` для IPv6 и декодеров NS/NA: `next ∈ {0, 6}`
  с цепочкой расширений, обрезка кратна 3, пересчёт контрольной суммы ICMPv6, чтобы вход доходил до разбора опций.
  Критерий: в отчёте задачи доля входов, дошедших до цепочки расширений и до разбора опций (не меньше половины).
- [ ] **Step 4: комментарии и README.** Ссылки C: `ndp_resolve.rs:6` (цикл повторов — `stack-ndpv6.c:425-440`),
  `ndp.rs` (флаги NA `stack-ndpv6.c:161`, проверка `:112`, `stack_ndpv6_resolve` `:312-487`); README:317-318
  переписать по коду: Linux и Windows отсеивают tentative и duplicate (DAD failed) и ставят deprecated последними,
  «detached» не упоминать.
- [ ] **Step 5: PASS** `cargo test -p rmasscan-core -p rmasscan-net`, clippy, fmt; **коммит**
  `fix(rmasscan): IPv6 stage follow-ups: NDP policy checks, ExcludeRequired hint, deeper proptests, cites`.

### Задача 1: крейт `rmasscan-proto`: приложения, нормализаторы, запись баннера

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/{Cargo.toml,src/lib.rs,src/app.rs,src/normalize.rs,src/banner.rs}`
- Modify: `rmasscan/Cargo.toml` (members)

**Interfaces:**
- Produces:
  - `pub fn app_name(app: u16) -> Cow<'static, str>` — справка A3: 0..=36 по таблице, иначе `(N)`.
  - `pub fn app_from_name(name: &str) -> Option<u16>` — `masscan_string_to_app`, регистр важен, 0/1/36 не выбираются.
  - `pub fn normalize_string(px: &[u8]) -> String` — A2, буфер 8192 (не больше 8190 символов, «дыры»).
  - `pub fn normalize_json_string(px: &[u8]) -> String` — A2, буфер 65 536, `\u00xx`.
  - `pub const MAX_BANNER_BYTES: usize = 65_536;` (Р5).
  - `pub struct BannerRecord { pub timestamp: u64, pub ip: std::net::IpAddr, pub ip_proto: u8, pub port: u16,
    pub app: u16, pub ttl: u8, pub payload: Vec<u8> }`.
  - `pub mod app_id { pub const NONE: u16 = 0; pub const DNS_VERSIONBIND: u16 = 6; pub const SNMP: u16 = 7;
    pub const NBTSTAT: u16 = 8; pub const ZEROACCESS: u16 = 14; pub const NTP: u16 = 19; pub const MEMCACHED: u16 = 25;
    pub const COAP: u16 = 28; pub const ISAKMP: u16 = 35; … }` — все 37 значений `src/masscan-app.h:8-49`.

- [ ] **Step 1: тесты** `app_names_match_c_table` (все 0..=36, 37 → `(37)`, 65535 → `(65535)`, 2 и 3 → `ssh`,
  23 и 33 → `vnc`); `app_from_name_matches_c` (`ssh1`→2, `ssh`→3, `x509`→15, `vnc-old`→23, `vnc`→33, `unknown` и
  `error` → `None`, `HTTP` → `None`); `normalize_string_escapes_c_set` (0x00..=0xFF: печатные 0x20..=0x7E кроме
  `" & ' < > \` как есть, остальное `\xNN` строчными); `normalize_string_holes_near_8190` (8186 печатных + `\x01` +
  `abc` даёт 8186 символов, затем `abc` до 8190, без `\x01`); `normalize_json_string_latin1` (`\xC3\xA9` →
  `Ã©`); `normalize_json_truncates_at_65536_rule`.
- [ ] **Step 2: FAIL** → реализация побайтно по A2 (условия `offset + 2 < len` и `offset + 5 < len` / `offset + 7 < len`).
- [ ] **Step 3: PASS**, clippy; **коммит** `feat(rmasscan-proto): app table, C string normalisers, banner record`.

### Задача 2: записи баннеров во всех форматах и в консоли

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/output/{formats.rs,grepable.rs,pipeline.rs,mod.rs,record.rs}`,
  `rmasscan/crates/rmasscan-cli/src/args.rs` (снять отказ `certs`, `args.rs:42-43`), `rmasscan/crates/rmasscan-cli/Cargo.toml`
- Test: `#[cfg(test)]` в `formats.rs`, `pipeline.rs`

**Interfaces:**
- Consumes: задача 1.
- Produces: `Formatter::banner(&mut self, w: &mut dyn Write, cx: &FileCtx, b: &BannerRecord) -> io::Result<()>`
  (у каждого формата своя реализация, у `Unicornscan` пустая); `Format::Certs`; `Pipeline::report_banner(&mut self,
  b: &BannerRecord) -> Result<(), String>`; `Sink::report_banner(&mut self, b: &BannerRecord) -> Result<(), String>`.

- [ ] **Step 1: тесты** по байтам справки A4 (пример IPv4 udp/53 ttl 57 app 6 ts 0x6553F100 `9.18.24`):
  `list_banner_bytes` (`banner udp 53 192.0.2.1 1700000000 dns-ver 9.18.24\n`; пустой баннер оставляет пробел),
  `json_banner_bytes_and_shared_comma` (статус, затем баннер: `,\n` перед вторым; `} } ]`), `ndjson_banner_bytes`,
  `xml_banner_reason_by_app_id` (app 6 → `syn-ack`, app 4 TCP → `response`; ` />` с пробелом), `grepable_banner_bytes`,
  `binary_banner_type9_example` (ровно `09 15 65 53 F1 00 C0 00 02 01 11 00 35 00 06 39 39 2E 31 38 2E 32 34`),
  `binary_banner_type13_layout`, `binary_banner_length_boundaries` (113/114, 100/101, 16 369 пишется, 16 370 нет),
  `hostonly_banner_adds_ip_line`, `unicornscan_banner_only_file_is_header_footer`,
  `certs_prints_pem_to_stdout_and_finished_to_file` (снятие `cert:` при длине > 5, строки по 72),
  `console_banner_line_padded_to_79` (`Banner on port 53/udp on 192.0.2.1: [dns-ver] 9.18.24` + пробелы до 79 + `\n`),
  `banner_ignores_show_filter_and_counts` (`--noshow open` не скрывает баннер, `up=`/`down=` XML не растут),
  `banner_without_file_is_silent` (нет строк `no output file`), `banner_triggers_lazy_header`.
- [ ] **Step 2: FAIL** → реализация по A1 (порядок шагов пайплайна баннера) и A4.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-cli` (все старые эталоны форматов зелёные); **коммит**
  `feat(cli): banner records in every output format, certs, console line`.

### Задача 3: `--readscan` баннеров, `--banner-types`, офлайн-эталоны C

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/readscan.rs`, `rmasscan/crates/rmasscan-cli/src/args.rs`,
  `rmasscan/crates/rmasscan-core/src/config.rs` (ключ `banner-types` и синонимы `banner-type`, `banner-apps`,
  `banner-app`), `rmasscan/crates/rmasscan-cli/examples/format_inputs.rs`, `rmasscan/scripts/build-format-goldens.sh`,
  `rmasscan/tests/golden/formats/{manifest.json,README.md,inputs/,outputs/}`,
  `rmasscan/crates/rmasscan-cli/tests/formats_golden.rs`

**Interfaces:**
- Consumes: задачи 1–2.
- Produces: `ReadFilter.banner_types: BTreeSet<u16>`; чтение типов 3, 4, 5, 9, 13 по таблице A5.

- [ ] **Step 1: юнит-тесты** `readscan_type3_short_body_is_corrupt_not_crash` (Р2: у C ~4 ГиБ чтения; у нас запись
  отбрасывается с `[-] file corrupt` — текст и код как у прочих битых записей), `readscan_type4_reads_extra_byte`
  (как C, A5), `readscan_type5_and_9_short_skipped`, `readscan_type13_bad_version_prints_corrupt_record`,
  `banner_types_drop_all_status_records`, `banner_types_bad_name_fails` (`FAIL: bad banner app: X` и `err`, код 1),
  `types_3_4_5_bypass_filters`, `binary_rewrites_3_4_5_as_9`.
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: входы эталонов.** `format_inputs.rs` пишет `banners.scan.bin` (IPv4 и IPv6 баннеры: app 0..=36, 37,
  65535; ip_proto 0, 1, 6, 17, 132, 99; все 256 байтов в полезной нагрузке; пустая; 113/114 и 100/101; 16 369 байт;
  статус и баннер вперемешку) и `banners-legacy.scan.bin` (типы 3, 4, 5 с корректными телами). `walk_records` в
  `build-format-goldens.sh` принимает типы 9 и 13 с двухбайтовой длиной и 3/4/5.
- [ ] **Step 4: снятие эталонов на хосте оракула** (как в `tests/golden/formats/README.md`): для обоих входов все
  18 случаев форматов плюс `--banner-types dns-ver`, `--banner-types ssl,http`, `--range`/`-p` на баннерах,
  `--output-format certs --output-filename F` (stdout и файл), формат по умолчанию (stdout). Манифест дополняется;
  `formats_golden.rs` проигрывает их тем же путём.
- [ ] **Step 5: PASS** все эталоны (старые 119 и новые), privacy-scan по новым файлам; **коммит**
  `feat(cli): --readscan banner types 3/4/5/9/13 and --banner-types, C goldens`.

### Задача 4: оракул парсеров и UDP-парсеры DNS, NTP, NetBIOS, SNMP

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/udp/{mod.rs,dns.rs,ntp.rs,netbios.rs,snmp.rs}`,
  `rmasscan/tests/golden/udp-banners/{README.md,manifest.json,cases/*.bin,cases/*.out}`
- Test: `#[cfg(test)]` в каждом модуле, `rmasscan/crates/rmasscan-proto/tests/udp_golden.rs`

**Interfaces:**
- Produces:
  - `pub struct UdpContext { pub port_them: u16, pub cookie: u32, pub rawudp: bool }` (`cookie` — тот же
    `syn_cookie(ip_them, port_them | Templ_UDP, ip_me, port_me, entropy)`, что вычисляет приём, справка B10).
  - `pub fn handle_udp(cx: &UdpContext, payload: &[u8]) -> Vec<(u16 /*app*/, Vec<u8>)>` — баннеры одного ответа в
    порядке C по таблице B0 (без статуса: его пишет движок). Сырой баннер — вся полезная нагрузка датаграммы, в том
    числе на 11211 и неразобранных портах (Р2: у C там чтение за концом).

- [ ] **Step 1: оракул вне репозитория.** На хосте оракула рядом с `~/rmasscan-oracle/masscan` собрать обвязку из
  `src/proto-{udp,dns,ntp,netbios,snmp,memcached,coap,isakmp,zeroaccess}.c` с заглушками вывода, которая читает
  датаграмму и параметры (порт, cookie, rawudp) и печатает список `(app, байты)` из `output_report_banner`. Обвязка не
  коммитится (Р14); её хэш и коммит C пишутся в `manifest.json`. Входы: векторы selftest C, ответы, собранные по
  описанию B1–B8 (успех, каждый ранний выход, неверный cookie, `--rawudp`), и их обрезки. Чтение за концом C на 11211 и
  неразобранных портах в эталоне помечается и не сравнивается по содержимому.
- [ ] **Step 2: тесты** `udp_golden_matches_c` (по манифесту, порты 53/123/137/161), `dns_rcode_strings`,
  `dns_chaos_txt_first_string_only`, `dns_short_payload_is_mismatch` (Р2: у C неинициализированный id),
  `ntp_v2_mode7_monlist_texts` (обе строки примера B2, без разделителя перед `Response`),
  `nbtstat_mac_repeats_first_byte` (как у C, B3), `snmp_selftest_vector`
  (`sysObjectID:okidata.1.1.1.297.93.1.27.2.2.1`), `snmp_v2c_gives_no_banner`, `snmp_huge_subid_does_not_overflow`,
  `udp_parsers_never_panic` (случайные датаграммы 0..2000 байт на каждом порту).
- [ ] **Step 3: FAIL** → реализация по B0–B4. Сопоставление OID — самый длинный префикс по таблице `mib[]` с правилом
  `SMACK_SNMP_HACK` (байт 0x80 пропускается внутри шаблона), без smack.
- [ ] **Step 4: PASS**; **коммит** `feat(rmasscan-proto): UDP banners for DNS, NTP, NetBIOS, SNMP with C oracle goldens`.

### Задача 5: UDP-парсеры memcached, CoAP, ISAKMP, ZeroAccess

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/udp/{memcached.rs,coap.rs,isakmp.rs,zeroaccess.rs}`,
  `rmasscan/crates/rmasscan-proto/src/memcached_text.rs` (текстовый разбор `STAT`, общий с TCP в 4b)
- Modify: `rmasscan/crates/rmasscan-proto/src/udp/mod.rs`, эталоны `udp-banners` (порты 500, 5683, 11211, 16464..)

- [ ] **Step 1: тесты** `udp_golden_matches_c` (новые порты), `memcached_stats_keeps_uptime_time_version`
  (`uptime=12345 time=1700000000 version=1.6.21 `), `memcached_soft_cookie_ip_mismatch`, `coap_token_bug_reproduced`
  (токен из байтов заголовка, печать `0x<десятичное>` — B6, детерминировано, Р1), `coap_invalid_goes_def64_then_raw`,
  `isakmp_selftest_prefixes` (строки `src/proto-isakmp.c:556-568`), `isakmp_zero_length_payload_terminates` (Р2),
  `zeroaccess_crc_and_lter`, `udp_parsers_never_panic` для новых портов.
- [ ] **Step 2: FAIL** → реализация по B5–B8; чтение «за концом» у `e_next_*` (`src/util-extract.c`) моделируется
  как C: значение из одних единиц без сдвига смещения. CRC-32 — табличная, руками.
- [ ] **Step 3: PASS**; **коммит** `feat(rmasscan-proto): UDP banners for memcached, CoAP, ISAKMP, ZeroAccess`.

### Задача 6: опции, движок и CLI: UDP-баннеры в живом скане

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/{receive.rs,config.rs}`, `rmasscan/crates/rmasscan-engine/src/{engine.rs,lib.rs}`,
  `rmasscan/crates/rmasscan-cli/src/{args.rs,conf.rs,live.rs,lib.rs}`, `rmasscan/README.md`
- Test: `rmasscan/crates/rmasscan-engine/tests/udp_banners.rs`, тесты CLI в `lib.rs`

**Interfaces:**
- Consumes: задачи 1–5.
- Produces:
  - `rmasscan_core::receive::udp_payload(frame: &[u8], link: LinkType) -> Option<&[u8]>` — полезная нагрузка UDP того
    же кадра, который `parse_reply` принял.
  - `EngineOptions.banners: Option<BannerOptions>` (по умолчанию `None`), `BannerOptions { rawudp: bool }`.
  - `EngineHandle::recv_output_timeout(&self, timeout: Duration) -> Result<Output, TryRecvError>`, где
    `pub enum Output { Event(Event), Banner(BannerRecord) }`. Гарантия: баннеры ответа приходят после его записи
    статуса и до записи любого более позднего ответа. `recv_event_timeout` и `try_event` прежние; при `banners: None`
    `Output::Banner` не бывает. Способ (общая очередь или вторая с порядковыми номерами) — решение строителя.
  - Конфиг: `banners`/`banner` (`F_BOOL`), `nobanners`/`nobanner`, `rawudp` (включает и `banners`), `capture`/
    `nocapture` (значения `cert`, `servername`, `html`, `heartbleed`, `ticketbleed`; в 4a только разбор и `--echo`),
    порядок argv и `--echo` как у C (`src/main-conf.c:1106-1180`, `:1546-1554`, `:2377-2403`).

- [ ] **Step 1: тесты движка** (`FakeAdapter` + `ManualClock`, ответчик возвращает UDP-ответ на зонд):
  `udp_banner_follows_its_status` (DNS CHAOS TXT → статус `open udp`, затем `dns-ver`), `banners_off_changes_nothing`
  (байты кадров и события без `banners` равны прежним), `udp_duplicate_reply_gives_one_status_and_one_banner_set`,
  `wrong_cookie_dns_gives_status_without_banner`, `rawudp_adds_raw_everywhere`, `udp_banner_ipv6`,
  `user_payload_cookie_semantics`, `timestamp_of_banner_equals_its_status`.
- [ ] **Step 2: тесты CLI** `banners_with_tcp_ports_is_refused_in_4a` (код 1; текст говорит, что TCP-баннеры
  появятся в следующем подэтапе; `-pU:53` и `--banners` проходят), `banners_echo_like_c`, `nobanners_after_banners`,
  `capture_values_parse_and_echo`, `capture_bad_value_fails`.
- [ ] **Step 3: FAIL** → реализация: в `run_rx` после `DedupCache::insert` для UDP-ответа с `ip_proto == 17` вызвать
  `handle_udp` (cookie — `syn_cookie_ipv4`/`syn_cookie_ipv6` с `Templ_UDP`, как в B10; для пользовательской нагрузки
  без мутатора — по правилу B10) и выдать баннеры с той же меткой времени и TTL, что у статуса. CLI: `--banners` в
  `Sink::report_banner`; README: опции 4a, отличия (сырой баннер без чтения за концом, дедуп UDP, не перенесённые
  протоколы, Р3 и Р17).
- [ ] **Step 4: PASS** всё (`cargo test --workspace`, clippy на всех целях ноутбука, fmt, language-guard); studio:
  `cargo check` и `cargo xtask test` без правок в `studio/`; **коммит**
  `feat(rmasscan): --banners and --rawudp for UDP scans (C proto-udp parity)`.

### Задача 7: стенд: окно `banners` (UDP), фаззинг и приёмка 4a

**Files:**
- Create: `rmasscan/crates/rmasscan-lab/src/{banners_suite.rs,banners_suite_tests.rs,banners_verify.rs,
  banners_verify_tests.rs,fuzz.rs}`
- Modify: `rmasscan/crates/rmasscan-lab/src/{main.rs,lib.rs,protocols_suite.rs}` (общий ответчик),
  `rmasscan/scripts/wire-lab.sh` (`--suite banners`), `rmasscan/docs/rust-lab.md`
- Create (после окна): `docs/experiments/2026-11-13-rmasscan-banners-4a-acceptance.md`,
  `docs/experiments/2026-11-13-rmasscan-banners-4a-raw/`

- [ ] **Step 1: ответчик.** UDP-ответчик стенда отвечает на зонды портов 53, 123, 137, 161, 500, 5683, 11211, 16464 по
  сценариям из справки C3.2 (успех, неверный cookie, rcode != 0, `qr = 0`, v2c, ошибка NTP), копируя идентификатор
  зонда. Сценарий выбирается по адресу цели (по адресу на сценарий), чтобы C и rmasscan получали одно и то же.
- [ ] **Step 2: верификатор** `banners-verify`: статусы равны C; множество баннеров на `(ip, порт, app)` равно C без
  учёта времени и порядка; сырые баннеры 11211 и неразобранных портов сравниваются только по наличию и длине (Р2);
  кадры rmasscan — те же зонды, что у C. Тесты верификатора на фикстурах (PASS, лишний баннер, потерянный баннер,
  чужой app, рассогласование cookie) — как у соседних `*_verify_tests.rs`.
- [ ] **Step 3: фаззер** `rmasscan-lab fuzz udp --seed N --duration D`: мутации корпуса (эталоны задачи 4–5 и
  захваты окна), обрезки, вставки; считает входы, падения, превышения времени на вход (> 100 мс) и рост памяти.
  Короткий режим (10 с) идёт в `cargo test`. Живой прогон ≥ 1 ч на каждом из 8 портов, итог в отчёте.
- [ ] **Step 4: живое окно** на стенде Linux (C-оракул `8e6b3b0`, IPv4 и IPv6, `--seed` один, `--retries 0`) плюс
  полная регрессия: ipv6, protocols, scan-control, output, autodetect, Windows VM. Доказательства в нейтральном
  каталоге, `MANIFEST`, privacy-scan, затем копия в `docs/experiments/…-raw/`.
- [ ] **Step 5: отчёт приёмки** (по образцу `2026-11-08-rmasscan-ipv6-acceptance.md`): код, на котором снято окно,
  результаты, отличия от C, NOT RUN; поправка (i) в спеку порта §«Исправления» и §9 «Изменения по итогам» в спеке
  этапа; **коммит** доказательств и отчёта отдельными коммитами.
