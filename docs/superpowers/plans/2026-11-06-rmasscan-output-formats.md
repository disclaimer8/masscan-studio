# rmasscan: форматы вывода masscan, `--readscan` и строка статуса — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rmasscan` пишет результаты скана в форматах masscan `-oL/-oJ/-oD/-oG/-oX/-oB/-oH/-oU` побайтно как C
`8e6b3b0`, конвертирует файлы `-oB` командой `--readscan`, печатает строку статуса masscan на stderr и корректно
завершает вывод по Ctrl-C.

**Architecture:** весь продуктовый код в `rmasscan-cli` (новый модуль `output/` вместо `output.rs`, `readscan.rs`,
`status.rs`, правки `args.rs`, `live.rs`, `lib.rs`, `main.rs`, `os_backend.rs`) плюс два малых FFI-модуля в
`rmasscan-net` (`localtime`, `interrupt`). Форматтеры — чистые функции над `Write` и типом `Record`; конвейер-`Sink`
повторяет `output_report_status` C. Паритет доказывается офлайн: C `--readscan` превращает закоммиченные входы `-oB`
в эталоны всех форматов, Rust сравнивает байты (CI, три ОС); живой паритет — новый набор `--suite output` на Linux netns.

**Tech Stack:** Rust 1.99.1, существующий workspace (`clap =4.6.7`, `libc =0.2.191`, `windows-sys` в `rmasscan-net`),
без новых crates. Bash для скрипта эталонов.

**Spec:** [docs/superpowers/specs/2026-11-06-rmasscan-output-formats-design.md](../specs/2026-11-06-rmasscan-output-formats-design.md)
(решения Р1–Р19); байты C — [2026-11-06-rmasscan-output-formats-c-reference.md](../specs/2026-11-06-rmasscan-output-formats-c-reference.md)
(далее «справка»; ссылки `файл:строка` — на `src/` upstream masscan `8e6b3b0`, клон лежит в `~/masscan` на Mac).

## Global Constraints

- `rmasscan-cli`, `rmasscan-core`, `rmasscan-engine`, `rmasscan-lab` остаются `#![forbid(unsafe_code)]`; `unsafe` только в `rmasscan-net`.
- Новых crates нет; в `windows-sys` можно добавить feature (`Win32_System_Console`, `Win32_System_Time`), `deny.toml` не меняется.
- `rmasscan-core` и `rmasscan-engine`: поведение не меняется; в core допустимы только аддитивные `pub` read-only помощники, если без них не обойтись.
- Байты по умолчанию (без `-o…`): stdout как в PR #49 — `Discovered open port N/tcp on IP`, пробелы до 79, `\n`, flush на строку.
- Одинаковые байты на трёх ОС (Р12): никакого перевода `\n` → `\r\n`; XML пишет свои `\r\n` сам.
- Константы C: `MASSCAN_VERSION = "1.3.9-integration"`, магия binary `masscan/1.1`, заголовок/подвал binary по 99 байт.
- Сообщения C дословно: `missing output filename`, `nmap(%s): unsupported output format` (`-oA`, `-oN`, `-oS`), `nmap(%s): unknown output format`, `out: could not open file for writing` / `appending`, `waiting several seconds to exit...` + 44 пробела.
- Флаги вывода и статуса вне живого скана и `--readscan` — отказ `output options apply only to a scan or --readscan`, exit 1 (Р19).
- Живые кадры только на запечатанных стендах, только `198.18.0.0/24`; физические NIC не используются; Mac `sudo` делает только пользователь (этот план его не требует).
- Evidence для репозитория: только нейтральные каталоги (`/tmp/rmasscan-out.XXXXXX` на хостах, `mktemp -d /private/tmp/rmasscan-out.XXXXXX` на Mac); privacy-grep (`grep -ralwE` по hostname и учётным записям всех хостов, `-a` для pcap) перед копированием; хэшированные evidence после копирования не правятся — только переснимаются.
- Гигиена агентов: приватный `CARGO_TARGET_DIR` на роль (`$SCRATCH/target-impl`, `target-review`), `CARGO_INCREMENTAL=0`; каталоги удаляются по окончании роли.
- Перед push: `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo fmt --check` в `rmasscan/` на Mac; полные тесты на minipc и в госте Windows перед финальным ревью.
- GO и merge только при зелёном CI на точном HEAD (`rmasscan`, `Studio`, `language-guard`) и одобренном итоговом ревью.

## Review Focus

1. **Отказ записи посреди скана** (диск заполнен, файл удалён/без прав): скан останавливается, `[+] finished: …` печатается, exit 1, ни одной записи не теряется молча — тест `write_error_mid_scan_stops_and_fails` (Задача 4).
2. **`--interactive` вместе с `-oL -`**: обе ветки пишут в один stdout в порядке C (сначала строка `Discovered`, потом запись файла) — тест `interactive_and_list_to_stdout_interleave_like_c` (Задача 4).
3. **Граничные значения записей**: порт 0 и 65535, TTL 0 и 255, флаги 0 (`none`) и 0xFF (`fin-syn-rst-psh-ack-urg-ece-cwr`), IP `255.255.255.255`, порт без записи в services (`unknown`), ширины `%5d`/`%16s`/`%-3d` unicornscan — входы эталонов (Задача 7) плюс юнит-тест `edge_values_render_like_c` (Задачи 1 и 2).
4. **Повреждённый вход `--readscan`**: короче 99 байт, чужая магия, обрезанная последняя запись, неизвестный тип — сообщение, подвал вывода дописан, exit 1 — тест `corrupt_inputs_finish_output_and_fail` (Задача 3).
5. **Ctrl-C до первой записи** (во время ARP или при нуле ответов): файл остаётся 0 байт, exit 0, второго нажатия не нужно — тест `interrupt_without_records_leaves_empty_file` (Задача 6).

---

### Task 1: записи, шесть простых форматов и конвейер вывода

**Files:**
- Create: `rmasscan/crates/rmasscan-cli/src/output/mod.rs` (содержимое прежнего `output.rs`: `Sink`, `io_fail`, `discovered_line`; плюс `pub mod record; pub mod formats; pub mod pipeline;` и реэкспорты)
- Create: `rmasscan/crates/rmasscan-cli/src/output/record.rs`, `.../output/formats.rs`, `.../output/pipeline.rs`
- Delete: `rmasscan/crates/rmasscan-cli/src/output.rs`
- Modify: `rmasscan/crates/rmasscan-cli/src/lib.rs` (`run` вызывает `Pipeline` вместо `Interactive`), `rmasscan/crates/rmasscan-cli/src/live.rs` (`run_live` вызывает `sink.open()`)

**Interfaces:**
- Consumes: `rmasscan_core::receive::{Reply, PortStatus}` (`remote_ip: u32`, `remote_port: u16`, `status`, `tcp_flags: u8`, `ttl: u8`).
- Produces:
  - `record.rs`: `pub enum Status { Open, Closed }`; `pub struct Record { pub timestamp: u64, pub ip: Ipv4Addr, pub port: u16, pub status: Status, pub reason: u8, pub ttl: u8 }` (`Copy`, `Eq`); `impl Record { pub fn from_reply(r: &Reply, timestamp: u64) -> Record }`; `pub fn status_str(s: Status) -> &'static str` (`open`/`closed`); `pub fn reason_string(flags: u8) -> String` (`output.c:118–136`); `pub const MASSCAN_VERSION: &str = "1.3.9-integration";`.
  - `formats.rs`: `pub enum Format { Default, Interactive, List, Json, Ndjson, Grepable, Xml, Binary, Hostonly, Unicornscan, None }`; `pub struct Counts { pub open: u64, pub closed: u64 }`; `pub struct FileCtx<'a> { pub now: u64, pub utc_offset_secs: i32, pub scan_started: u64, pub file_opened: u64, pub counts: Counts, pub stylesheet: Option<&'a str>, pub tcp_ports: &'a [(u16, u16)], pub services: &'a ServiceNames }`; `pub trait Formatter { fn header(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()>; fn record(&mut self, w: &mut dyn Write, cx: &FileCtx, r: &Record) -> io::Result<()>; fn footer(&mut self, w: &mut dyn Write, cx: &FileCtx) -> io::Result<()>; }`; `pub fn formatter(f: Format) -> Option<Box<dyn Formatter>>` (`None` для `Default`/`Interactive`/`None` — это `null_output` C). В этой задаче реализованы List, Json, Ndjson, Hostonly, Xml, Binary; для Grepable и Unicornscan `formatter` временно возвращает `None` (без `panic!`/`unimplemented!`), Задача 2 подключает их.
  - `ServiceNames` — тип из Задачи 2; в Задаче 1 создать заглушку `pub struct ServiceNames;` в `output/services.rs` с `pub fn empty() -> ServiceNames`, Задача 2 её наполняет (имя и путь не меняются).
  - `pipeline.rs`: `pub trait Wall { fn unix_time(&self) -> u64; fn utc_offset_secs(&self, unix: u64) -> i32; }`; `pub struct OutputOptions { pub format: Format, pub filename: Option<String>, pub append: bool, pub flush: bool, pub show_open: bool, pub show_closed: bool, pub show_host: bool, pub interactive: bool, pub stylesheet: Option<String> }` с `Default` = C (`show_open: true`, остальное `false`/`None`, `format: Format::Default`); `pub struct OutputEnv<'a> { pub wall: &'a dyn Wall, pub services: ServiceNames, pub tcp_ports: Vec<(u16, u16)>, pub scan_started: Option<u64> }`; `pub struct Pipeline<'a>`; `impl<'a> Pipeline<'a> { pub fn new(opts: OutputOptions, stdout: &'a mut dyn Write, env: OutputEnv<'a>) -> Pipeline<'a>; pub fn set_scan_started_if_unset(&mut self, ts: u64); pub fn report_record(&mut self, r: &Record) -> Result<(), String> }`; `impl Sink for Pipeline` (`report` строит `Record::from_reply(reply, wall.unix_time())`, Р9).
  - `Sink` получает `fn open(&mut self) -> Result<(), String>;` (обязательный метод): `Pipeline::open` открывает файл (или берёт stdout для `-`), фиксирует `file_opened` и (если `scan_started` не задан явно как «из первой записи») `scan_started = wall.unix_time()`.

- [ ] **Step 1: Red — байты форматов.** В `formats.rs` тесты на одной записи `Record { timestamp: 1_700_000_000, ip: 1.2.3.4, port: 80, status: Open, reason: 0x12, ttl: 57 }` и второй (closed, `10.0.0.255`, порт 443, флаги `0x14`, TTL 64), строки — из справки §1.1–1.6, §1.9:
  - `list_bytes_match_c`: `#masscan\n` + `open tcp 80 1.2.3.4 1700000000\n` + `closed tcp 443 10.0.0.255 …\n` + `# end\n`.
  - `json_prepends_comma_from_the_second_record`: `[\n{   "ip": "1.2.3.4",   "timestamp": "1700000000", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 57} ] }\n,\n{ …443… "reason": "rst-ack", "ttl": 64} ] }\n]\n`.
  - `ndjson_is_compact_without_header`: `{"ip":"1.2.3.4","timestamp":"1700000000","port":80,"proto":"tcp","rec_type":"status","data":{"status":"open","reason":"syn-ack","ttl":57}}\n`.
  - `hostonly_prints_ip_per_record`: `1.2.3.4\n10.0.0.255\n`, без заголовка и подвала.
  - `xml_uses_crlf_and_c_header`: заголовок с `now = 1_700_000_005`: `<?xml version="1.0"?>\r\n<!-- masscan v1.0 scan -->\r\n<nmaprun scanner="masscan" start="1700000005" version="1.0-BETA"  xmloutputversion="1.03">\r\n<scaninfo type="syn" protocol="tcp" />\r\n`; со `stylesheet = Some("http://nmap.org/svn/docs/nmap.xsl")` — строка `<?xml-stylesheet href="…" type="text/xsl"?>\r\n` после комментария; запись — `<host endtime="1700000000"><address addr="1.2.3.4" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="57"/></port></ports></host>\r\n`; подвал при `now = 1_700_000_100`, `file_opened = 1_700_000_000`, `utc_offset_secs = 3600`, `counts {open 1, closed 1}`: `<runstats>\r\n<finished time="1700000100" timestr="2023-11-14 23:15:00" elapsed="100" />\r\n<hosts up="1" down="1" total="2" />\r\n</runstats>\r\n</nmaprun>\r\n`.
  - `binary_header_record_footer`: заголовок 99 байт = `b"masscan/1.1\ns:1700000000\n"` + нули; запись `[6, 13, ts BE 4, ip BE 4, 6, port BE 2, 0x12, 57]` (15 байт), closed — тип 7; подвал 99 байт = `b"masscan/1.1"` + 88 нулей.
  - `edge_values_render_like_c` (Review Focus 3): `reason_string(0) == "none"`, `reason_string(0xFF) == "fin-syn-rst-psh-ack-urg-ece-cwr"`, порт 0/65535 и TTL 0/255 в list/json/xml/binary; `timestamp = 4_294_967_296 + 5` рендерится как C: list `%u` → `5`, json `(int)` → `5`, xml `%u` → `5`, binary — младшие 32 бита.
- [ ] **Step 2: Red — конвейер** (`pipeline.rs`, фейковый `Wall`, запись в `Vec<u8>` через `filename = Some("-")` и в файл во временном каталоге):
  - `default_format_prints_discovered_only`: `Format::Default` → stdout `discovered_line(...)` для open, closed отброшен (`show_closed = false`), файл не открывается.
  - `closed_line_when_shown`: `show_closed = true`, формат Default → `Discovered closed port 443/tcp on 10.0.0.255` + пробелы до 79 + `\n`.
  - `file_format_keeps_stdout_silent`: `Format::List`, файл → stdout пуст (Р3); с `interactive = true` → обе ветки.
  - `header_is_lazy_and_footer_needs_a_record`: 0 записей → файл существует, 0 байт после `finish` (Р7); 1 запись → заголовок, запись, подвал.
  - `show_filters_before_counting`: `show_open = false, show_closed = true` → в XML `up="0" down="1"`.
  - `flush_option_flushes_each_record` (Writer, считающий `flush`), `append_reopens_and_writes_header_again` (Р15).
  - `open_failure_message_matches_c`: каталог вместо файла → `Err` с первой строкой `out: could not open file for writing` и второй `<путь>: <ошибка ОС>` (Р8), с `append` — `appending`.
- [ ] **Step 3: Run** `cargo test -p rmasscan-cli --lib output` — FAIL (нет типов).
- [ ] **Step 4: Implement** `record.rs`, `formats.rs`, `pipeline.rs` по Interfaces; порядок в `report_record` = `output.c:746–880` (справка §2): фильтр show → интерактивная строка (`out`, flush) → если форматтера нет — выход → счётчики → ленивый заголовок → запись → flush при `opts.flush`. Локальное время в `timestr` = `now + utc_offset_secs`, разложенное в `%Y-%m-%d %H:%M:%S` чистой арифметикой (civil-from-days); эту функцию `civil(unix_secs: i64) -> (y, m, d, hh, mm, ss, weekday)` положить в `record.rs` как `pub(crate)` — её использует Задача 2. Для `filename = "-"` писать в переданный `stdout`; для файла — `BufWriter<File>` (`OpenOptions` `write+create+truncate` или `append`). Вывод `Default`/`Interactive` без файла — как прежний `Interactive`.
- [ ] **Step 5: Rewire.** `lib.rs::run`: `live::run_live(&cfg, backend, &mut Pipeline::new(OutputOptions::default(), &mut *out, env), log)` (env с `ServiceNames::empty()`, пустыми портами); `Backend` в этой задаче получает `utc_offset_secs(&self, unix: u64) -> i32` и становится `Backend: Wall` (у `Wall::unix_time` та же сигнатура, что у существующего `Backend::unix_time` — метод переезжает в `Wall`); fake-бэкенды трёх тестовых наборов (`lib.rs` tests, `tests/live_fake.rs`, `tests/detect_readonly.rs`, если там есть `Backend`) возвращают `0`; `OsBackend` пока тоже `0` (настоящую функцию даёт Задача 4). `run_live` вызывает `sink.open()` после `print_detection` и до ARP; ошибка → `Err`, ни одного кадра.
- [ ] **Step 6: Run** `cargo test -p rmasscan-cli` — PASS, включая все прежние тесты `live_fake.rs` и `differential.rs` без изменений ожиданий.
- [ ] **Step 7: Commit** `feat(cli): output records, list/json/ndjson/hostonly/xml/binary formatters and the masscan output pipeline`.

### Task 2: grepable, unicornscan, имена сервисов и время C-локали

**Files:**
- Create: `rmasscan/crates/rmasscan-cli/src/output/grepable.rs` (grepable и unicornscan)
- Modify: `rmasscan/crates/rmasscan-cli/src/output/services.rs` (заглушка → реализация), `.../output/formats.rs` (`formatter` для Grepable/Unicornscan)

**Interfaces:**
- Consumes: `Formatter`, `FileCtx`, `Record`, `civil` (Задача 1).
- Produces: `ServiceNames { … }` с `pub fn empty() -> ServiceNames`, `pub fn parse(text: &str) -> ServiceNames`, `pub fn host() -> ServiceNames` (читает `/etc/services`; на Windows `%SystemRoot%\System32\drivers\etc\services`, без переменной — `C:\Windows\…`; нечитаемый файл → `empty()`), `pub fn tcp(&self, port: u16) -> &str` (`unknown`, если нет); `pub fn c_locale_ctime(unix: u64) -> String` (`%a %b %e %H:%M:%S %Y` в GMT) в `grepable.rs`.

- [ ] **Step 1: Red.**
  - `services_first_tcp_entry_wins`: `parse("http 80/tcp www # web\nhttp-alt 80/tcp\nfoo 80/udp\n# x 81/tcp\nbar\t81/tcp\n")` → `tcp(80) == "http"`, `tcp(81) == "bar"`, `tcp(82) == "unknown"`, комментарии и пустые/битые строки пропускаются.
  - `ctime_matches_c_locale`: `c_locale_ctime(1_390_335_802) == "Tue Jan 21 20:23:22 2014"`, `c_locale_ctime(1_388_620_800) == "Thu Jan  2 00:00:00 2014"` (`%e` с пробелом).
  - `grepable_header_record_footer`: `scan_started = 1_390_335_802`, `tcp_ports = [(80,80),(443,443)]` → `# Masscan 1.3.9-integration scan initiated Tue Jan 21 20:23:22 2014\n# Ports scanned: TCP(2;80-80,443-443) UDP(0;) SCTP(0;) PROTOCOLS(0;)\n`; пустые порты → `TCP(0;) UDP(0;) SCTP(0;) PROTOCOLS(0;)`; запись `Timestamp: 1700000000\tHost: 1.2.3.4 ()\tPorts: 80/open/tcp//http//\n`; подвал `# Masscan done at <ctime(now)>\n`.
  - `unicornscan_widths`: `#masscan\n`, запись `TCP open\t            http[   80]\t\tfrom 1.2.3.4  ttl 57 \n`, `# end\n`; `edge_values_render_like_c`: порт 65535 → `[65535]`, TTL 255 → `ttl 255\n`, TTL 0 → `ttl 0  \n`, сервис длиннее 16 не обрезается.
- [ ] **Step 2: Run** `cargo test -p rmasscan-cli --lib grepable services` — FAIL.
- [ ] **Step 3: Implement** по справке §1.4, §1.7; число портов в `TCP(n;…)` = сумма длин диапазонов; разделитель `,` между диапазонами (TCP-only конфиг, «хвостовая запятая» C при не-TCP диапазонах неприменима — отметить комментарием со ссылкой `out-grepable.c:42–62`).
- [ ] **Step 4: Run** `cargo test -p rmasscan-cli` — PASS.
- [ ] **Step 5: Commit** `feat(cli): grepable and unicornscan formats with host service names`.

### Task 3: чтение `-oB` и операция `--readscan`

**Files:**
- Create: `rmasscan/crates/rmasscan-cli/src/readscan.rs`
- Modify: `rmasscan/crates/rmasscan-cli/src/output/formats.rs` (или новый `output/binary.rs`: читатель рядом с писателем), `rmasscan/crates/rmasscan-cli/src/lib.rs` (`pub mod readscan;`)

**Interfaces:**
- Consumes: `Record`, `Status`, `Pipeline::{report_record, set_scan_started_if_unset}`, `Sink::{open, finish}`.
- Produces: `pub fn read_records(r: &mut dyn Read, f: &mut dyn FnMut(Record) -> Result<(), String>) -> Result<(), ReadError>` с `pub enum ReadError { Io(io::Error), NotMasscan, Corrupt(String), Unsupported(u64) }`; `pub struct ReadFilter { pub targets: rmasscan_core::massip::MassIp, pub by_ip: bool, pub by_port: bool }` с `pub fn from_config(cfg: &ScanConfig) -> ReadFilter` (копия `cfg.targets`, `apply_excludes(&mut excludes)`, подготовка для `has_ip`/`has_port` так, как этого требует `RangeList::is_contains`; `by_ip` — если задана хоть одна цель, `by_port` — если задан хоть один порт; C `filter->count_ipv4s`, `count_ports`) и `pub fn keeps(&self, r: &Record) -> bool`; `pub fn run_readscan(files: &[String], filter: &ReadFilter, sink: &mut Pipeline, log: &mut dyn Write) -> Result<(), String>`.

- [ ] **Step 1: Red** (`readscan.rs`, входы собираются писателем binary из Задачи 1 в `Vec<u8>`):
  - `roundtrip_status_records`: записать 3 записи (open, closed, open) → `read_records` возвращает те же `Record` в том же порядке.
  - `footer_is_skipped_as_m_record` и `header_must_be_masscan_1_1` (`b"nmap…"` → `NotMasscan`).
  - `unsupported_types_are_errors` (Р13): типы 1, 2, 3, 5, 8, 9, 10, 13 → `Unsupported(t)`; запись типа 6 с протоколом 17 → `Unsupported` с текстом про протокол.
  - `corrupt_inputs_finish_output_and_fail` (Review Focus 4): файл короче 99 байт, обрезанная последняя запись, длина > 1 MiB, неизвестный тип 0x7E → `run_readscan` пишет подвал `-oJ` (`]\n` после уже выведенных записей), возвращает `Err`; тексты: `[-] <file>: unknown file format (expected "masscan/1.1")`, `[-] file corrupt`, `<file>: unsupported record type N`.
  - `scan_started_comes_from_the_first_record`: `-oB` → `-oB` даёт заголовок `s:<ts первой записи>` (`in-binary.c:65`).
  - `filters_apply_like_c`: цели `10.0.0.0/30` и `-p80` → записи вне пропущены; без целей и портов — всё.
  - `stderr_names_each_file`: `log` содержит `[+] --readscan <file>\n` на файл (`in-binary.c`, справка §1.9).
- [ ] **Step 2: Run** `cargo test -p rmasscan-cli --lib readscan` — FAIL.
- [ ] **Step 3: Implement** по справке §1.9: заголовок — ровно 99 байт и префикс `masscan/1.1`; далее varint-тип и varint-длина (7-битные группы, бит 7 — продолжение), длина ≤ 1 MiB, тело `length` байт; `'m'` пропускается; тип 6/7 — 13 байт тела, протокол 6; короткое чтение в середине записи — `Corrupt`; конец файла ровно на границе записи — успех. Каждые 65536 записей — `[+] <file>: %8u\r` в `log`. Ошибка открытия: `[-] FAIL: --readscan` и `[-] <file>: <ошибка>`.
- [ ] **Step 4: Run** `cargo test -p rmasscan-cli` — PASS.
- [ ] **Step 5: Commit** `feat(cli): read masscan -oB status records for --readscan`.

### Task 4: флаги вывода в CLI, бэкенд и подключение к скану и `--readscan`

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/args.rs`, `.../src/lib.rs`, `.../src/main.rs`, `.../src/live.rs`, `.../src/os_backend.rs`
- Create: `rmasscan/crates/rmasscan-net/src/localtime.rs` (+ `pub mod localtime;` в `lib.rs` крейта)
- Test: `rmasscan/crates/rmasscan-cli/tests/live_fake.rs`, юнит-тесты `args.rs` и `lib.rs`

**Interfaces:**
- Consumes: всё из Задач 1–3.
- Produces:
  - `rmasscan_net::localtime::utc_offset_secs(unix: i64) -> Result<i32, NetError>` (Unix: `localtime_r` + `tm_gmtoff`; Windows: `SystemTimeToTzSpecificLocalTime` над `FILETIME`, смещение = локальное − UTC).
  - `Backend` получает `fn services(&self) -> ServiceNames;` (`OsBackend` → `ServiceNames::host()`; fakes → `ServiceNames::empty()` или фикстура); `OsBackend::utc_offset_secs` → `localtime::utc_offset_secs`, ошибка → 0.
  - `args.rs`: `pub enum ParseError { Clap(clap::Error), Masscan(String) }`; `Cli::try_parse_masscan(...) -> Result<Cli, ParseError>`; `preprocess_args(...) -> Result<Vec<String>, String>` переводит `-o<L|J|D|G|X|B|H|U> FILE` в `--output-format <list|json|ndjson|grepable|xml|binary|hostonly|unicornscan> --output-filename FILE` (FILE = следующий argv; `-` разрешён; отсутствие или `-…` → `missing output filename`), `-oA/-oN/-oS` → `nmap(-oA): unsupported output format`, иная буква или голый `-o` → `nmap(-oZ): unknown output format`; `-oR` → `nmap(-oR): unsupported output format` (Р1).
  - Новые поля `Cli`: `output_format: Option<String>`, `output_filename: Option<String>` (alias `output-file`), `append_output: bool` (alias `output-append`), `output_flush: bool`, `open: bool` (alias `open-only`), `show: Vec<String>` (alias `output-show`, `output-status`), `noshow: Vec<String>` (alias `output-noshow`), `interactive: bool`, `nointeractive: bool`, `stylesheet: Option<String>`, `webxml: bool`, `status: bool`, `nostatus: bool`, `ndjson_status: bool` (alias `status-ndjson`), `readscan: Vec<String>` (`--readscan FILE…`, `num_args = 1..`); `impl Cli { pub fn output_options(&self) -> Result<OutputOptions, String>; pub fn output_flags_given(&self) -> bool; }`. Повтор `--output-format`/`--output-filename` — побеждает последний (Р17).
  - `main.rs`: `ParseError::Masscan(text)` → текст в stderr, exit 1; `ParseError::Clap(e)` → `e.exit()` как сейчас.
- [ ] **Step 1: Red — разбор** (`args.rs`):
  - `dash_o_letters_map_to_formats`: каждая буква → ожидаемый `Format` и имя файла; `-oX -` → stdout.
  - `dash_o_errors_match_c`: `["-oX"]`, `["-oX","-p80"]` → `Masscan("missing output filename")`; `-oA`, `-oN`, `-oS`, `-oR` → `nmap(-oA): unsupported output format` и т. д.; `-oZ` → `nmap(-oZ): unknown output format`.
  - `output_filename_alone_means_xml` (Р5), `unknown_output_format_is_an_error` (Р6, `--output-format nmap` → `Err`, текст называет допустимые: `list, json, ndjson, grepable, xml, binary, hostonly, unicornscan, interactive, none`), `redis_certs_rotate_are_refused` (`--output-format redis|certs`, `--rotate 3600`, `--rotate-dir x`, `--rotate-size 1m` → отказ с причиной).
  - `show_and_noshow_tokens`: `--show open,closed` → оба true; `--show close` = closed; `--show all` → open, closed, host; `--noshow open`; неизвестный токен → `FAIL: unknown 'show' spec: X` / `FAIL: unknown 'noshow' spec: X`; `--open` возвращает умолчание C; `--webxml` → stylesheet `http://nmap.org/svn/docs/nmap.xsl`; `--stylesheet` без формата → XML.
  - `last_output_option_wins`: `-oX a -oJ b` → Json, `b`.
  - Существующий `unsupported_option_errors` меняет ожидание: `-oX x.xml` теперь разбирается, а `run` без целей отказывает (цели нужны); `--banners` по-прежнему ошибка.
- [ ] **Step 2: Red — `run`** (`lib.rs` tests, `tests/live_fake.rs`):
  - `output_flags_refused_outside_scan_and_readscan` (Р19): `-sL`, `--echo`, `--offline`, `--iflist` с `-oL x` → `output options apply only to a scan or --readscan`, stdout пуст.
  - `readscan_converts_to_every_format` (через `run` с fake-бэкендом, вход из писателя binary в temp): `--readscan in.scan -oL -` → байты как в юнит-тесте list.
  - live_fake: `live_scan_writes_list_file_and_keeps_stdout_silent`, `interactive_and_list_to_stdout_interleave_like_c` (Review Focus 2), `open_failure_sends_no_frame` (каталог вместо файла: exit 1, ни одного кадра у `FakeAdapter`, ни одного ARP), `write_error_mid_scan_stops_and_fails` (Review Focus 1: файл в каталоге, который тест делает недоступным после первой записи — либо, проще, `-oL -` с stdout-`Write`, который отказывает после N байт; ожидание: `[+] finished:` в log, `Err`).
- [ ] **Step 3: Run** `cargo test -p rmasscan-cli` — FAIL.
- [ ] **Step 4: Implement.** `run`: если `output_flags_given()` и операция не скан и не `--readscan` → отказ Р19; `--readscan` — новая операция, взаимоисключающая с `-sL`, `--echo*`, `--offline`, `--iflist` (clap `conflicts_with_all`), не требует `--seed` и прав; `OutputEnv`: `wall = backend`, `services = backend.services()` только для Grepable/Unicornscan (иначе `empty()`), `tcp_ports` из портов конфигурации (для `--readscan` — из `-p`, если дан), `scan_started = None` для `--readscan` (из первой записи) и `Some(wall.unix_time())` при `open` для скана. `localtime.rs` с тестами `utc_offset_is_within_14_hours` (|смещение| ≤ 50 400 с для текущего времени и для `0`) и `utc_offset_is_stable` (два вызова с одним `unix` равны); окружение `TZ` тесты не меняют.
- [ ] **Step 5: Run** `cargo test -p rmasscan-cli -p rmasscan-net` — PASS; `cargo clippy --locked --workspace --all-targets -- -D warnings` — чисто.
- [ ] **Step 6: Commit** `feat(cli): masscan output options, --readscan and file output for live scans`.

### Task 5: строка статуса

**Files:**
- Create: `rmasscan/crates/rmasscan-cli/src/status.rs`
- Modify: `rmasscan/crates/rmasscan-cli/src/live.rs` (цикл событий `run_live`), `.../src/lib.rs` (`pub mod status;`), `.../tests/live_fake.rs` (помощник `plus_lines` нормализует `\r`)

**Interfaces:**
- Consumes: `rmasscan_engine::{Event::{Started, Progress, Results, Finished}, Progress { sent, next_index, received, discarded, duplicates, rate }}`; `Backend::clock()` (микросекунды через `Clock`), `ScanConfig.wait_secs`.
- Produces: `pub enum StatusMode { Text, Ndjson, Off }`; `pub struct StatusLine`; `impl StatusLine { pub fn new(mode: StatusMode, start_micros: u64) -> StatusLine; pub fn tick(&mut self, now_micros: u64, count: u64, max_count: u64, pps: f64, found: u64, exiting: Option<i64>, log: &mut dyn Write) -> io::Result<()>; pub fn finish(&mut self, log: &mut dyn Write) -> io::Result<()>; }`; чистые `pub fn running_line(kpps: f64, percent: f64, remaining_secs: f64, found: u64) -> String`, `pub fn waiting_line(kpps: f64, percent: f64, exiting: i64, found: u64) -> String`, `pub fn ndjson_running(...) -> String`, `pub fn ndjson_waiting(...) -> String`; `pub fn normalize_stderr_line(line: &str) -> &str` (текст после последнего `\r` — то, что видит терминал; используют тесты и лаборатория).

- [ ] **Step 1: Red.**
  - `running_line_matches_c`: `running_line(0.1, 12.5, 3725.0, 3) == "rate:  0.10-kpps, 12.50% done,   1:02:05 remaining, found=3       \r"`.
  - `waiting_line_matches_c`: `waiting_line(0.0, 100.0, 7, 8) == "rate:  0.00-kpps, 100.00% done, waiting 7-secs, found=8       \r"`.
  - `ndjson_lines_match_c`: running → `{"state":"running","rate":{"kpps":0.10,"pps":100.00},"progress":{"percent":12.50,"eta":{"hours":1,"mins":2,"seconds":5},"syn":{"sent":25,"total":200,"remaining":175},"found":3}}\n`; waiting → `{"state":"waiting","rate":{"kpps":0.00,"pps":0.00},"progress":{"percent":100.00,"seconds":7,"found":8,"syn":{"sent":200,"total":200,"remaining":0}}}\n` (`main-status.c:56–125`).
  - `tick_cadence`: в фазе передачи печать не чаще раза в 750 мс, в ожидании (`exiting = Some`) — каждый вызов не чаще 250 мс; `elapsed ≤ 0` → ничего; скорость оставшегося времени — среднее 8 последних отсчётов (кольцо нулей в начале), печатаемая kpps — `pps / 1000` (не сглаженная, `main-status.c:247`).
  - `finish_blanks_the_line`: 77 пробелов + `\r`; `Off` → ничего.
  - live_fake: `status_lines_on_stderr_by_default` (на `ManualClock` с шагом ≥ 1 с хотя бы одна строка `rate:`; `[+] finished` после нормализации — отдельная строка), `nostatus_prints_elapsed_to_stdout` (`--nostatus` → строк `rate:` нет, в stdout последняя строка `N milliseconds elapsed\n`, `main.c:1548–1552`), `ndjson_status_lines`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement.** В `run_live`: `Started { range }` задаёт `max_count`; на каждом `Progress(p)` — `status.tick(clock.now_micros(), p.next_index, max_count, p.rate, open_found, exiting, log)`, где `exiting = Some(wait_secs − секунд с момента, когда next_index достиг max_count)`; после `Finished` — `status.finish`, затем прежний `[+] finished: …`. `found` = число open `Reply` (C `total_synacks`). Режим: `--ndjson-status` → Ndjson; `--nostatus` → Off; по умолчанию Text. `plus_lines` в `live_fake.rs` берёт `normalize_stderr_line` каждой строки.
- [ ] **Step 4: Run** `cargo test -p rmasscan-cli` — PASS (все прежние live-тесты).
- [ ] **Step 5: Commit** `feat(cli): masscan status line on stderr`.

### Task 6: Ctrl-C

**Files:**
- Create: `rmasscan/crates/rmasscan-net/src/interrupt.rs` (+ `pub mod interrupt;`), тест `rmasscan/crates/rmasscan-net/tests/interrupt.rs` (только Unix)
- Modify: `rmasscan/crates/rmasscan-net/Cargo.toml` (feature `Win32_System_Console` у `windows-sys`, если нет), `rmasscan/crates/rmasscan-cli/src/live.rs`, `.../src/os_backend.rs`, fake-бэкенды тестов, `.../tests/live_fake.rs`

**Interfaces:**
- Produces: `rmasscan_net::interrupt::install() -> Result<(), NetError>` (идемпотентно; Unix `sigaction(SIGINT)` без `SA_RESETHAND`, обработчик: `PRESSES.fetch_add(1)`, при значении ≥ 1 до инкремента — `libc::_exit(1)`; Windows `SetConsoleCtrlHandler` для `CTRL_C_EVENT`/`CTRL_BREAK_EVENT`, второе нажатие — `ExitProcess(1)`), `rmasscan_net::interrupt::presses() -> u32`; `Backend` получает `fn interrupts(&self) -> u32` (`OsBackend`: при первом вызове `install()`, затем `presses()`; fakes — счётчик, который тест может поднять после k-го опроса).
- [ ] **Step 1: Red.**
  - live_fake: `first_interrupt_stops_and_finishes_outputs` (fake поднимает счётчик после первой пачки `Results`; ожидания: в stderr строка `waiting several seconds to exit...` + 44 пробела + `\n`, `[+] finished: Stopped`, `Ok`, файл `-oJ` закрыт `]\n`, `-oX` — `</nmaprun>\r\n`), `interrupt_without_records_leaves_empty_file` (Review Focus 5: счётчик поднят до первого ответа → файл 0 байт, `Ok`).
  - `tests/interrupt.rs` (Unix): `first_sigint_is_counted_not_fatal` — `install()`, `libc::raise(SIGINT)`, `presses() == 1`, процесс жив (второй `raise` не делать).
  - Юнит-тест Windows-обработчика (`#[cfg(windows)]`): прямой вызов функции-обработчика с `CTRL_C_EVENT` возвращает `TRUE` и увеличивает счётчик (без `GenerateConsoleCtrlEvent`).
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement.** `run_live` вызывает `backend.interrupts()` один раз до ARP (установка), затем на каждой итерации цикла событий: при первом наблюдении `> 0` — строка C в `log`, `handle.stop()`, далее обычное завершение (`join`, `sink.finish`, `[+] finished`). Код выхода `Stopped` уже 0 (`conclude`). Обработчик ничего не печатает (async-signal-safety); всё печатает цикл.
- [ ] **Step 4: Run** `cargo test -p rmasscan-cli -p rmasscan-net` — PASS.
- [ ] **Step 5: Commit** `feat(cli): Ctrl-C stops the scan and completes the output files`.

### Task 7: эталоны C через `--readscan` и офлайн-паритет

**Files:**
- Create: `rmasscan/crates/rmasscan-cli/examples/format_inputs.rs` (пишет входы), `rmasscan/scripts/build-format-goldens.sh`, `rmasscan/tests/golden/formats/` (`inputs/*.scan`, эталоны, `services`, `manifest.json`, `README.md`), `rmasscan/crates/rmasscan-cli/tests/formats_golden.rs`

**Interfaces:**
- Consumes: писатель binary, `run` с `--readscan`, `ServiceNames::parse`.
- Produces: `manifest.json` `{ "oracle": {"git_head": "8e6b3b0c…", "binary_sha256": "8afc8ec8…"}, "captured_at", "host", "isolation": "sudo unshare -n", "services_source": "getent services <port>/tcp on the oracle host", "cases": [ {"name", "input", "args": [...], "output", "sha256", "masks": [ {"kind": "xml_start" | "xml_finished" | "grepable_done"} ] } ] }`.

- [ ] **Step 1: Входы.** `examples/format_inputs.rs OUTDIR` пишет детерминированно: `basic.scan` (8 записей: open/closed на IP 10.0.0.1, 10.0.0.2, 10.0.0.3, 192.0.2.7, порты 80/443/8080/22), `edge.scan` (порт 0 и 65535, TTL 0 и 255, флаги 0, 0x04, 0x12, 0x14, 0xFF, IP `0.0.0.1` и `255.255.255.255`, порт без services, например 47001), `many.scan` (70 000 записей — проверка `[+] …\r` каждые 65536 и производительности), `empty.scan` (только заголовок и подвал). Время записей — константы от `1_700_000_000`. Закоммитить `inputs/`.
- [ ] **Step 2: Скрипт.** `build-format-goldens.sh --oracle BIN --inputs DIR --out DIR` (bash, `set -euo pipefail`): проверяет sha256 оракула `8afc8ec81f2e051389116908b01a4482b42e020bc48254585b7dcca4b25e2a3e`, отсутствие `/etc/masscan/masscan.conf`, запускает под `sudo -n unshare -n` для каждого входа: `-oL/-oJ/-oD/-oG/-oX/-oB/-oH/-oU <out>` с `--show open,closed` и без; `-oX` дополнительно с `--webxml`; фильтр `--range 10.0.0.0/31 -p80 --readscan basic.scan -oL out` (цели и порты стоят до `--readscan`: C считает файлами все следующие за ним аргументы без `-`, `main-conf.c:3266–3278`, `main.c:1764`; IP `basic.scan` — `10.0.0.1`, `10.0.0.2`, `10.0.0.3`, `192.0.2.7`); каждый прогон дважды, сравнение после масок; `getent services <port>/tcp` для всех портов входов → `services` (формат `/etc/services`); `manifest.json` — тот же формат, что у `tests/golden/manifest.json` по стилю (sha256 каждого выхода и argv).
- [ ] **Step 3: Съёмка на minipc.** Скопировать `inputs/` и скрипт в `/tmp/rmasscan-out.XXXXXX` на minipc, запустить с `~/rmasscan-oracle/masscan/bin/masscan`, скопировать результат в `tests/golden/formats/`, удалить каталог на minipc. Privacy-grep выходов.
- [ ] **Step 4: Red — тест.** `formats_golden.rs`: для каждого кейса манифеста — `rmasscan_cli::run` в процессе с fake-бэкендом (`services` = `ServiceNames::parse(fixture)`, `utc_offset_secs = 0`, `unix_time` — константа), те же argv, выход в temp; маски по `kind` (`xml_start`: значение `start="…"`; `xml_finished`: `time`, `timestr`, `elapsed`; `grepable_done`: строка `# Masscan done at …`); остальные байты равны эталону. Тест `every_golden_case_is_checked` (число кейсов манифеста = число проверенных).
- [ ] **Step 5: Run** `cargo test -p rmasscan-cli --test formats_golden` — PASS (при FAIL — чинить продукт, не эталон; расхождение с C, которое оставляем, — только из Р6–Р13 и с записью в README эталонов).
- [ ] **Step 6: Commit** `test(cli): C oracle goldens for every output format via --readscan`.

### Task 8: лаборатория — строки статуса в верификаторах и набор `--suite output`

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/autodetect_verify.rs` (`parse_stderr`), `.../src/autodetect_verify_tests.rs`, `rmasscan/scripts/wire-lab.sh` (`--suite output`), `.../src/main.rs`, `.../src/lib.rs`
- Create: `rmasscan/crates/rmasscan-lab/src/output_suite.rs`, `output_verify.rs`, `output_suite_tests.rs`, `output_verify_tests.rs`

**Interfaces:**
- Consumes: `rmasscan_cli::status::normalize_stderr_line` — **нет**: лаборатория не зависит от CLI-крейта; правило нормализации повторяется в лаборатории (своя копия, как `ROUTER_HINTS`, чтобы дрейф продукта был находкой).
- Produces: `rmasscan-lab output-suite linux --out DIR --work DIR --ns-a … --ns-b … --iface-a … --iface-b … --mac-a … --mac-b … --rmasscan PATH --oracle PATH --conf-masked 0|1 --lab-id ID [--only TAG …]`, `rmasscan-lab output-verify --dir DIR`; коды 0 PASS / 1 FAIL / 2 INVALID|NOT RUN, без повышения.

- [ ] **Step 1: Red — `parse_stderr`.** `status_fragments_are_skipped`: stderr `[+] interface = …\nrate:  0.10-kpps, …       \r<77 пробелов>\r[+] finished: Completed, sent 12, replies 12, open 8\n` разбирается как раньше; фрагмент перед `\r`, не похожий на строку статуса (`rate:…\r`, 77 пробелов, `{"state":…}`), — ошибка; `waiting several seconds to exit...` + 44 пробела — допустимая отдельная строка.
- [ ] **Step 2: Implement `parse_stderr`** и прогнать `autodetect-verify --dir` по четырём закоммиченным каталогам `docs/experiments/2026-10-27-rmasscan-autodetect-acceptance-raw/{linux-r1,windows-r1,macos-r1,macos-root-r1}` (во временную копию): вердикты и хэши вердиктов байт в байт как в отчёте §11 (`64c9e6aa…`, `94b72583…`, `e3dafaf7…`, `26ff9103…`).
- [ ] **Step 3: Red — набор и верификатор.** Таблица кейсов (одна, как `CaseSpec` autodetect) для стенда autodetect Linux (`198.18.0.1` сканер, пиры `198.18.0.2-198.18.0.5`, ответчик слушает 80 и 8080, остальное RST), общие аргументы `198.18.0.2-198.18.0.5 -p80,443,8080 --seed 1 --rate 100 --wait 3`:
  - `o01_list` … `o08_unicornscan`: C и rmasscan, `-o<буква> FILE --show open,closed`;
  - `o09_json_default_show` (без `--show`: closed отсутствуют), `o10_list_stdout` (`-oL -`: stdout = список, строк `Discovered` нет), `o11_interactive` (`-oL FILE --interactive`), `o12_nostatus` (`-oJ FILE --nostatus`), `o13_open_fail` (только rmasscan, `-oL /nonexistent-rmasscan-dir/x`: exit 1, 0 кадров в захвате пира), `o14_interrupt_json`, `o15_interrupt_xml`, `o16_interrupt_binary` (только rmasscan, `--rate 20`, `-p1-1000`, SIGINT через 2 с: exit 0, файл целый), `o17_readscan` (офлайн после живых: `--readscan` бинарника `o06` у rmasscan и у C → `-oL`, сравнение).
  - Верификатор: множества записей C и rmasscan равны после маскирования времени (порядок нормализован); заголовки/подвалы равны после масок; время записей в окне прогона; open = {80, 8080} × 4 пира, closed = {443} × 4 пира при `--show open,closed`; XML `up`/`down` равны числам записей; JSON — `[\n` + записи через `,\n` + `]\n`; binary — 99 + 15n + 99 байт; stderr: строки статуса по грамматике, `[+] finished` с `sent` = SYN на проводе пира; 0 кадров лаборатории вне стенда (как autodetect `isolation.json`); privacy — через `capture::Scrubber` и проверку токенов, как у autodetect.
  - Тесты верификатора на синтетических каталогах: `a_consistent_run_is_pass`, `record_mismatch_is_fail`, `missing_footer_after_interrupt_is_fail`, `frames_on_open_failure_is_fail`, `private_token_is_fail`.
- [ ] **Step 4: Implement** `output_suite.rs`/`output_verify.rs`, переиспользуя `autodetect_suite` (netns-запуск, свидетель пира, `oracle_argv`, teardown-запись с `lab_id`, `Scrubber`) — общие помощники выносятся в `pub(crate)` без изменения поведения autodetect (его тесты зелёные без правок ожиданий); `wire-lab.sh`: ветка `--suite output` как `autodetect` (`--rmasscan` обязателен).
- [ ] **Step 5: Run** `cargo test -p rmasscan-lab` — PASS; `bash -n scripts/wire-lab.sh`.
- [ ] **Step 6: Commit** `feat(lab): output-suite and output-verify on the Linux netns stand; verifiers skip status lines`.

### Task 9: живые окна и регрессия

**Files:**
- Create: `docs/experiments/2026-11-06-rmasscan-output-acceptance-raw/` (`linux-output-r1/`, `linux-autodetect-r2/`, `windows-autodetect-r2/`, `verification/`, `README.md`, `MANIFEST.sha256`)

- [ ] **Step 1: Сборка и выкладка** кода C = HEAD после Задачи 8 на minipc (`git archive` в `/tmp/rmasscan-out.XXXXXX`, `cargo build --release --locked`), полные тесты рабочей области там; гость Windows — по `rmasscan/docs/rust-lab.md` (экспорт `C:\Users\lab\src\rmasscan-<sha>`, `cargo test --locked --workspace`).
- [ ] **Step 2: Linux output** — `sudo -n wire-lab.sh --oracle ~/rmasscan-oracle/masscan/bin/masscan --out $OUT --suite output --rmasscan <бинарь>`; `output-verify --dir $OUT` → PASS (rc 0) на всех 17 кейсах.
- [ ] **Step 3: Регрессия** — `--suite autodetect` Linux PASS 13/13; Windows: агент поднимает `n2` (`sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab up …`, VM с `lab.env`, `w32tm /resync`), `windows-suite --plan autodetect` PASS 10/10, затем снимает `n2`. macOS — **NOT RUN** (код ниже CLI не менялся; окно Mac требует `sudo` пользователя).
- [ ] **Step 4: Evidence** — копия в репозиторий, хэши до/после совпадают, privacy-grep чист, `MANIFEST.sha256`, README по-русски (что, где, на каком C, отклонения). Удалить экспорты на minipc, home-pc и в госте.
- [ ] **Step 5: Commit** `test(cli): record output-format acceptance on the Linux stand and the autodetect regression on Linux and the Windows VM`.

### Task 10: документация

**Files:**
- Create: `docs/experiments/2026-11-06-rmasscan-output-acceptance.md`
- Modify: `rmasscan/README.md` («Команды», «Отличия от masscan» — список §8 спеки, «Ограничения», «Статус»), `docs/experiments/2026-10-24-rmasscan-readiness.md` (строка «CLI output formats»), `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md` (раздел «Исправления»: поправка к строке «Форматы вывода» §3 со ссылкой на спеку этапа), `.github/workflows/rmasscan.yml` (только если новые тесты требуют шага — иначе не трогать)

- [ ] **Step 1:** Отчёт приёмки (структура как у autodetect: итог, стенды, кейсы, вердикты с хэшами, CI-таблица заполняется после зелёного CI, отклонения, NOT RUN: macOS живой, Windows Ctrl-C, физические NIC).
- [ ] **Step 2:** README и readiness; пункт README «нет обработчика Ctrl-C» заменён описанием Р18.
- [ ] **Step 3:** `cargo test --locked --workspace`, clippy, fmt в `rmasscan/` — PASS.
- [ ] **Step 4: Commit** `docs(cli): output formats acceptance report, README and readiness`.
