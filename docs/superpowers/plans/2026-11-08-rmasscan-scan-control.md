# rmasscan: управление сканом — план реализации

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ — `superpowers:subagent-driven-development`.
> Шаги в чекбоксах (`- [ ]`). Каждая задача идёт строго по циклу RED → запуск (FAIL) → минимальная реализация со ссылкой
> на C `файл:строка` → запуск (PASS) → коммит.

**Goal:** поведенческий паритет `rmasscan` с `masscan` (`8e6b3b0`) по управлению сканом: `--retries`, `--shard`,
`paused.conf` / `--resume`, фаза ожидания после Ctrl-C (`--wait`), `--infinite`, диапазоны источника, `-c`/`-iL`,
несколько адаптеров (`nic[0..8)`), `--pcap`, `--ttl`, `--badsum`, `--noreset` и TCP-опции SYN-шаблона.

**Architecture:** генератор индексов, `ProbeCursor` по внешнему индексу `i`, диапазоны источника и шаблоны TCP/IP-опций —
чистая логика в `rmasscan-core`; многоадаптерный запуск, пауза с `wait`-фазой, `--infinite` и потокобезопасный перехват
кадров для `--pcap` — в `rmasscan-engine`; чтение/запись `paused.conf`, позиционный разбор `-c`/`-iL`/`--resume`, флаги
CLI и строка статуса `*` — в `rmasscan-cli`.

**Tech Stack:** Rust 1.99.1, Cargo workspace `rmasscan/`, без новых крейтов (`clap =4.6.7`, `libc =0.2.191`).

**Spec:** [docs/superpowers/specs/2026-11-08-rmasscan-scan-control-design.md](../specs/2026-11-08-rmasscan-scan-control-design.md) (решения Р1–Р9).

## Global Constraints

- `#![forbid(unsafe_code)]` во всех крейтах, кроме `rmasscan-net`.
- Ноль новых зависимостей; `Cargo.lock` и `deny.toml` без изменений; дерево только Rust/docs (`language-guard` зелёный).
- **Контракт `Studio` заморожен:** структура `AdapterBinding` в `rmasscan-core/src/probe.rs` обязана сохранить ровно свои
  6 публичных полей (`studio/crates/studio-protocol/src/lib.rs:147` конструирует её литералом без `..Default::default()`),
  `ReadyPlan::new(eff, binding)` сохраняет v1-контракт для `Studio`, а `canonical_job_bytes` в
  `rmasscan-engine/src/identity.rs` остаётся побайтно прежним на дефолтных TCP/IPv4 заданиях. Новые возможности CLI
  подключаются через новый конструктор плана (`ReadyPlan::new_cli` / `NicBinding`), не ломая `studio`.
- Ноль живого трафика и открытия реальных NIC в офлайн-тестах — только `FakeAdapter` и `ManualClock`.
- Приватность публичного репо: ни имён хостов/учёток, ни домашних путей, ни LAN-адресов в коде, тестах, фикстурах и комментах.
- Гигиена сборки: приватный `CARGO_TARGET_DIR` на роль (`$SCRATCH/target-impl`, `target-review`), `CARGO_INCREMENTAL=0`;
  перед пушем — `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`,
  `cargo fmt --check` в `rmasscan/` и проверка сборки/тестов `studio/`; **Windows/macOS clippy+тесты окончательно
  проверяет GitHub CI**.
- TDD: сперва красный тест, затем минимальная реализация со ссылкой на C `файл:строка` в комментарии и сообщении коммита.

## Review Focus

1. **Пауза посреди пачки повторов (`retries > 0`) при `shard.of > 1`:** если курсор увеличивал позицию на число
   отправленных кадров вместо внешнего индекса `i` из `transmit_index_stream`, `--resume paused.conf` пропускает цели
   или дублирует чужой шард — тест `cursor_tracks_outer_index_across_retries_and_shards` (Задача 1) и
   `resume_mid_retry_burst_completes_exact_multiset` (Задача 3).
2. **`paused.conf` от оригинального C `masscan` с `adapter-port = p-(p+16)` (17 портов) и переопределение флагами правее
   `--resume`:** C сам пишет не-степень-двойки `17` в `paused.conf` (`main.c:1318`, `main-conf.c:3668`) — тест
   `reads_c_paused_conf_with_17_port_quirk_and_cli_overrides` (Задача 2).
3. **Зависание `--wait` при `--nostatus` и второе нажатие Ctrl-C во время `wait`-фазы:** в C `--nostatus` блокирует
   выход из `wait` навсегда (`main.c:1399, 1530`), а второе нажатие не должно терять уже сброшенный `paused.conf` —
   тест `first_ctrl_c_waits_with_nostatus_and_writes_paused_conf_before_wait` (Задача 4).
4. **Завершение при усечённом `--resume-count` с `--retries > 0` и индекс адаптера `--adapter[8]`:** в C цикл статуса
   ждёт `min_index >= range` и зависает при `resume_count < range` (`main.c:1425`), а `nic[8]` переполняет массив
   (`main-conf.c:2438`) — тесты `resume_count_with_retries_terminates_cleanly` (Задача 3) и
   `adapter_index_out_of_bounds_fails` (Задача 7).
5. **Переполнение длины TCP-опций и сохранность L3-чексуммы при `--badsum`:** комбинация всех четырёх TCP-опций обязана
   выравниваться EOL до 4 байт (`doff <= 15`), а `--badsum` обязан портить только TCP-чексумму, оставляя IPv4 header
   checksum равной `0xFFFF` — тест `all_tcp_options_and_badsum_keep_valid_ipv4_header` (Задача 6).

---

### Задача 1: генератор индексов и `ProbeCursor` в `rmasscan-core` (`--shard`, `--retries`, multi-NIC)

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/probe.rs`, `rmasscan/crates/rmasscan-core/src/scan.rs`
- Test: `#[cfg(test)]` в `probe.rs` и `scan.rs`

**Interfaces:**
- Consumes: `scan::transmit_index_stream` (`scan.rs:178–214`), `BlackRock::new(range, seed, rounds)`.
- Produces:
  - `pub struct NicBinding { pub binding: AdapterBinding, pub source_ipv4_last: u32, pub legacy_c_17_port_mask: bool }`
    (`From<AdapterBinding>` ставит `source_ipv4_last = binding.source_ipv4`, `legacy_c_17_port_mask = false`).
  - `ReadyPlan::new_cli(effective: EffectiveConfig, nics: Vec<NicBinding>) -> Result<ReadyPlan, PlanError>` — принимает
    любой валидный `Shard` (`1 <= one <= of`), `retries <= 999`, `blackrock_rounds >= 1`, `resume_index`, `resume_count`
    и `1 <= nics.len() <= 8`, оставляя `ReadyPlan::new(effective, binding)` неизменным для `Studio`.
  - `ReadyPlan::effective_end(&self, nic_index: u32) -> u64` (`main.c:269–273`:
    `min(range, start + resume_count) + u64::from(retries) * range`) и `ReadyPlan::cursor_for_nic(&self, nic_index: u32,
    resume_override: Option<u64>) -> Result<ProbeCursor, PlanError>`.
  - `ProbeCursor::position(&self) -> u64` возвращает внешний индекс `i` следующего неотправленного пакета (при старте —
    `start`, внутри пачки из `retries + 1` повторов одного `i` — текущий `i`, после завершения всех повторов последнего
    шага — `effective_end`, как `parms->my_index = i` в `main.c:431`).

- [ ] **Шаг 1 — красный тест:** добавить в `probe.rs` юнит-тесты:
  - `shards_partition_full_range_without_gaps_or_overlaps`: `range = 37` (простое число: 37 адресов `198.18.0.0-198.18.0.36` ×
    1 порт `80`), `seed = 0x1234_5678`, `shard = 1/3, 2/3, 3/3` через `ReadyPlan::new_cli` → попарно не пересекаются,
    объединение даёт все 37 пар `(ip_them, port_them)` в точности как `for_each_probe`. Парный тест
    `shards_partition_multi_port_range_with_cartesian_excludes`: `198.18.0.0/29` × портов `80-84` минус исключение
    `198.18.0.5-198.18.0.7` = 5 адресов × 5 портов = 25 (исключения декартовы: убирают адрес со всеми портами).
  - `multi_nic_and_shards_match_c_increment`: `shard = 2/3`, `nics.len() = 2` → поток `nic 0` стартует с `i = 2`, шаг `6`,
    поток `nic 1` стартует с `i = 3`, шаг `6`; объединение всех 6 потоков `(shard 1..=3 × nic 0..=1)` равно полному
    множеству `0..range`.
  - `retries_stream_matches_for_each_probe`: `range = 10`, `retries = 2`, `max_rate = 7.0` → курсор выдаёт ровно
    `(2 + 1) * (2 + 1) * 10 = 90` кадров, побайтно совпадающих с `for_each_probe` (`(i + r * 7) % 10`, `r = 3, 2, 1`).
  - `cursor_tracks_outer_index_across_retries_and_shards` (Review Focus 1): при `retries = 2`, `shard = 1/2`, `nic_count = 1`
    после 1-го и 2-го отправленного кадра `cursor.position() == 0`, после 3-го кадра (`r` дошёл до `0`) —
    `cursor.position() == 2` (`start + increment`).
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core cursor_tracks_outer_index` — не компилируется / падает.
- [ ] **Шаг 3 — реализация:** связать `ProbeCursor` с `transmit_index_stream(range, shard, nic_count, nic_index, start_from,
  resume_count, retries, max_rate)` (`~/masscan/src/main.c:212–223, 269–273, 328–334, 421–431`,
  `crypto-blackrock.c:260–295`), храня в буфере элементы `(outer_i, x)` и вычисляя `position()` как `front.outer_i` (или
  следующий `i` итератора / `effective_end`, если поток исчерпан).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core` — все тесты зелёные.
- [ ] **Шаг 5 — коммит:** явные пути `rmasscan/crates/rmasscan-core/src/{probe,scan}.rs` со ссылкой на `main.c:269–431`.

### Задача 2: `paused.conf` — запись, расширение `echo` и round-trip чтения

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/config.rs`
- Create: `rmasscan/crates/rmasscan-cli/src/conf.rs` (+ `pub mod conf;` в `rmasscan/crates/rmasscan-cli/src/lib.rs`)
- Test: `#[cfg(test)]` в `config.rs` и `conf.rs`

**Interfaces:**
- Produces:
  - В `rmasscan-core::config`: расширение `ScanConfig` / `EffectiveConfig` полями `nics: Vec<NicConfig>` (с синхронизацией
    одиночных полей `adapter_*`/`router_*`/`source_port` с `nics[0]` ради обратной совместимости со `Studio` и прежними
    тестами), `ttl: Option<u8>`, `badsum: bool`, `noreset: bool`, `infinite: bool`, `tcp_opts: TcpHeaderOptions`,
    `legacy_c_17_port_mask: bool`; обновление `echo()` и `apply_core_kv(&mut ScanConfig, key, val)` без изменения вывода
    `echo()` на старых конфигурациях (все golden-тесты `--echo` остаются побайтно прежними).
  - В `rmasscan-cli::conf`: `pub struct FullConf { pub scan: ScanConfig, pub output: OutputConfPatch, pub pcap_filename:
    Option<String>, pub ndjson_status: bool }`, `pub fn format_paused_conf(conf: &FullConf, resume_index: u64) -> String`
    (`main-conf.c:395–416, 2402–2422, 3636–3780`) и `pub fn parse_conf_str(text: &str, base: &mut FullConf, include_loader:
    &mut dyn FnMut(&Path) -> Result<String, String>, depth: usize) -> Result<(), String>`.

- [ ] **Шаг 1 — красный тест:** в `conf.rs` и `config.rs`:
  - `paused_conf_section_order_and_roundtrip_match_c`: запись `FullConf` с `resume_index = 420`, `shard = 2/4`,
    `retries = 2`, `-oJ scan.json`, `--pcap cap.pcap`, `--ndjson-status`, `nic[0]` + `nic[1]`, `ports = 80,443`,
    `198.18.0.0/24` с `exclude = 198.18.0.1` → проверка точного порядка строк (`# resume information`, `nocapture` ×2,
    пустая строка, `output-*`, пустая строка, `adapter[0]`/`adapter[1]`, `# TARGET SELECTION`, вычтенные `range = ...`)
    и побайтной идемпотентности `format_paused_conf → parse_conf_str → format_paused_conf`.
  - `reads_c_paused_conf_with_17_port_quirk_and_cli_overrides` (Review Focus 2): входной текст `paused.conf` от C с
    `adapter-port = 41234-41250` (`41250 - 41234 == 16`) и `output-filename = a.json` читается без ошибки, при режиме
    `--resume` выставляет `output-append = true` (`main-conf.c:2926–2928`), а последующий CLI-аргумент `--rate 500`
    переопределяет `rate` из файла.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli paused_conf` — падает.
- [ ] **Шаг 3 — реализация:** реализовать `format_paused_conf` и `parse_conf_str` по `~/masscan/src/main-conf.c:294–416,
  1619–1688, 1913–1942, 2038–2096, 2402–2422, 3636–3924` (включая `wait = forever` → `i32::MAX as u32` по `:3028–3032`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-cli` — все тесты, включая старые
  `--echo` дифф-тесты, зелёные.
- [ ] **Шаг 5 — коммит:** `rmasscan/crates/rmasscan-core/src/config.rs`, `rmasscan/crates/rmasscan-cli/src/{conf,lib}.rs`.

### Задача 3: `--resume` и многопоточный прогресс в `rmasscan-engine` и `rmasscan-cli`

**Files:**
- Modify: `rmasscan/crates/rmasscan-engine/src/engine.rs`, `rmasscan/crates/rmasscan-cli/src/args.rs`,
  `rmasscan/crates/rmasscan-cli/src/live.rs`
- Test: `rmasscan/crates/rmasscan-engine/src/engine.rs` (`#[cfg(test)]`), `rmasscan/crates/rmasscan-cli/tests/live_fake.rs`

**Interfaces:**
- Produces:
  - `Engine::start_cli_with_clock(plan: ReadyPlan, ios: Vec<AdapterPair>, options: EngineOptions, clock: Arc<dyn Clock +
    Send + Sync>, pcap_sink: Option<Arc<dyn Fn(&[u8], u64) + Send + Sync>>) -> Result<EngineHandle, StartError>` —
    запускает по паре потоков TX/RX на каждый `nic_index` (для `ios.len() == 1` эквивалентно `start_with_clock`), считает
    `next_index = min_k my_index[k]` (`main.c:1408–1414`) и завершает скан, когда каждый `nic_index` достиг своего
    `effective_end(nic_index)`. Существующие `Engine::start` / `Engine::resume` для `Studio` не меняют сигнатуру.
  - Разбор `--resume <file>` в `args.rs` (`preprocess_args` / позиционное слияние в `FullConf`).

- [ ] **Шаг 1 — красный тест:**
  - `resume_mid_retry_burst_completes_exact_multiset` (Review Focus 1): на `FakeAdapter` запустить план с `range = 12`,
    `retries = 1`, `shard = 1/2`, поставить паузу после 5 отправленных пакетов, прочитать `CheckpointReady { next_index }`,
    запустить второй прогон с `resume_index = next_index` → конкатенация отправленных кадров двух прогонов равна
    мультимножеству кадров непрерывного прогона без единого пропуска или лишнего повтора.
  - `resume_count_with_retries_terminates_cleanly` (Review Focus 4): `range = 100`, `resume_index = 10`,
    `resume_count = Some(8)`, `retries = 1` → движок отправляет ровно ожидаемое подмножество и выдаёт
    `Finished { reason: Reason::Completed }` без зависания.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-engine resume_mid_retry` — падает.
- [ ] **Шаг 3 — реализация:** подключить `ReadyPlan::cursor_for_nic` и `effective_end` в `engine.rs`
  (`~/masscan/src/main.c:269–273, 1408–1428`) и позиционную загрузку `--resume` в `args.rs`/`live.rs` с принудительным
  `output_options.append = true`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-engine -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `engine.rs`, `args.rs`, `live.rs`, `live_fake.rs`.

### Задача 4: фаза ожидания ответов (`--wait`) и запись `paused.conf` по первому Ctrl-C

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/live.rs`, `rmasscan/crates/rmasscan-cli/src/os_backend.rs`,
  `rmasscan/crates/rmasscan-cli/tests/live_fake.rs`

**Interfaces:**
- Produces:
  - Расширение шва `Backend`: `fn write_paused_conf(&self, content: &str) -> Result<(), String>` (`OsBackend` пишет
    `./paused.conf` и возвращает ошибку при отказе ФС; фейковый бэкенд сохраняет строку в память без трогания диска).
  - В `run_live`: первое наблюдение `backend.interrupts() > 0` печатает `INTERRUPT_LINE`, вызывает `handle.pause()`
    (вместо прежнего `handle.stop()`), по приходу `Event::CheckpointReady { next_index }` при `next_index < effective_end
    && !eff.infinite()` печатает 70 пробелов + `\r` + `saving resume file to: paused.conf\n` (`main-conf.c:398–399`) и
    вызывает `backend.write_paused_conf(...)`, затем остаётся в цикле событий на время `wait_secs`, принимая
    `Event::Results` и печатая `waiting N-secs` до прихода `Event::Finished { reason: Reason::Paused }`, закрывает подвал
    `sink.finish()` и возвращает код выхода `0` (`[+] finished: Paused...`).

- [ ] **Шаг 1 — красный тест:** в `tests/live_fake.rs`:
  - `first_ctrl_c_pauses_saves_conf_waits_for_late_reply_and_closes_footer`: `wait_secs = 3`, `ManualClock` двигается по
    250 мс; после 2 отправленных SYN поднимается `interrupts() = 1`, во время `wait`-окна `FakeAdapter` впрыскивает
    поздний SYN-ACK → ответ попадает в `-oJ`, подвал `]\n` закрыт, в памяти фейка записан `paused.conf` с верным
    `resume-index`, в `stderr` есть `saving resume file to: paused.conf\n` и `waiting 2-secs`, итог `Paused`, `Ok`.
  - `first_ctrl_c_waits_with_nostatus_and_writes_paused_conf_before_wait` (Review Focus 3): тот же сценарий с
    `--nostatus` не зависает, завершается за `wait_secs` по `ManualClock`, а `paused.conf` уже записан до первого тика
    ожидания.
  - `ctrl_c_after_tx_done_skips_paused_conf`: если `next_index >= effective_end` к моменту `SIGINT`, `paused.conf` не
    пишется (`main.c:1447`).
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli --test live_fake first_ctrl_c_pauses` — падает
  (сейчас `live.rs:529` вызывает `handle.stop()` без `wait` и без `paused.conf`).
- [ ] **Шаг 3 — реализация:** переключить `live.rs:525–567` на `handle.pause()`, обработку `Event::CheckpointReady`,
  таймер `exiting` от момента паузы (`main.c:1447–1540`, `main-conf.c:395–416`) и поддержку `Reason::Paused` в `conclude`
  с кодом выхода `0`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-cli` — все тесты зелёные (обновить в `live_fake.rs`
  ожидание прежнего теста Р18 с `Stopped` на `Paused`).
- [ ] **Шаг 5 — коммит:** `live.rs`, `os_backend.rs`, `tests/live_fake.rs`.

### Задача 5: `--infinite` и строка статуса `*`

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/probe.rs`, `rmasscan/crates/rmasscan-engine/src/engine.rs`,
  `rmasscan/crates/rmasscan-cli/src/status.rs`, `rmasscan/crates/rmasscan-cli/src/args.rs`,
  `rmasscan/crates/rmasscan-cli/src/live.rs`
- Test: `probe.rs`, `status.rs`, `tests/live_fake.rs`

**Interfaces:**
- Produces:
  - `ProbeCursor::advance_pass(&mut self)` (когда `effective.infinite()` включён и текущий проход дошёл до `effective_end`,
    пересоздаёт `BlackRock::new(range, seed.wrapping_add(repeats + 1), rounds)`, увеличивает `repeats += 1` и сбрасывает
    поток на `start = (shard.one - 1) * nic_count + nic_index`, сохраняя `builder.entropy = initial_seed`,
    `main.c:225–228, 269, 445–449`).
  - `status::infinite_line(kpps: f64, syn_ps: f64, ack_ps: f64, tcb_ps: f64, tcbs: u64) -> String` и
    `status::ndjson_infinite(...) -> String` (`main-status.c:56–69, 214`).

- [ ] **Шаг 1 — красный тест:**
  - `infinite_restarts_with_incremented_seed_and_constant_entropy`: `range = 4`, `seed = 10` → первые 4 кадра равны
    проходу с `seed = 10, repeats = 0`, следующие 4 кадра имеют порядок целей от `BlackRock(seed = 11)` и `repeats = 1`,
    но `seqno` считается с `entropy = 10`, так что `receive` подтверждает SYN-ACK от обоих проходов.
  - `infinite_status_lines_match_c`: `infinite_line(0.10, 100.0, 5.0, 0.0, 0) ==
    "rate:  0.10-kpps, syn/s=100 ack/s=5 tcb-rate=0, 0-tcbs,         \r"` и NDJSON `{"state":"*",...}`
    (`main-status.c:56–69, 214`).
  - `infinite_scan_runs_multiple_passes_until_ctrl_c`: на `FakeAdapter` с `range = 3` пропускает ≥ 9 кадров и штатно
    выходит по `interrupts() = 1` без записи `paused.conf`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli infinite` — падает.
- [ ] **Шаг 3 — реализация:** реализовать `advance_pass` в `probe.rs`, цикл бесконечных проходов в TX-потоке `engine.rs`,
  флаг `--infinite` в `args.rs` и ветку `infinite` в `status.rs` / `live.rs` (`~/masscan/src/main.c:225–228, 445–449,
  1447`, `main-status.c:56–69, 214`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-engine -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `probe.rs`, `engine.rs`, `status.rs`, `args.rs`, `live.rs`, `tests/live_fake.rs`.

### Задача 6: параметры зонда (`--adapter-ip A-B`, `--ttl`, `--badsum`, `--noreset`, TCP-опции)

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/packet.rs`, `rmasscan/crates/rmasscan-core/src/probe.rs`,
  `rmasscan/crates/rmasscan-core/src/receive.rs`, `rmasscan/crates/rmasscan-core/src/config.rs`,
  `rmasscan/crates/rmasscan-cli/src/args.rs`
- Test: `#[cfg(test)]` в `packet.rs`, `probe.rs`, `args.rs`

**Interfaces:**
- Produces:
  - `pub struct TcpHeaderOptions { pub mss: Option<u16>, pub sackok: bool, pub wscale: Option<u8>, pub tsecho: Option<u32> }`
    (`Default`: `mss = Some(1460)`, остальное `false`/`None`).
  - `pub struct PacketModifiers { pub ttl: u8, pub badsum: bool, pub tcp: TcpHeaderOptions }` (`Default`: `ttl = 255`,
    `badsum = false`, `tcp = Default`).
  - `TcpSynTemplate::new_with_options(source_mac, router_mac, link, mods: &PacketModifiers) -> Self`
    (`templ-pkt.c:1474–1488`, `templ-tcp-hdr.c:1066–1119`): при `mods == Default` байты совпадают с `DEFAULT_TCP_TEMPLATE`
    (58 байт); при `--badsum` финальная L4-чексумма сдвигается `csum.wrapping_sub(1)`.
  - Диапазон `--adapter-ip A-B` степени двойки (`ipv4_mask = last_ip - first_ip` в `Builder::fill`, `probe.rs:128–141`,
    и проверка `ip_them_of_reply ∈ first_ip..=last_ip` в `receive.rs`).

- [ ] **Шаг 1 — красный тест:** в `packet.rs` и `probe.rs`:
  - `default_template_bytes_unchanged`: `new_with_options(..., &PacketModifiers::default())` даёт те же 58 байт, что и
    `TcpSynTemplate::new`.
  - `tcp_options_layout_and_padding_match_c`:
    - `mss = None` → 54 байта (`ip.total_len = 40`, `tcp.doff = 0x50`, опций 0 байт);
    - `mss = Some(1400), sackok = true` → опции `[02, 04, 05, 78, 04, 02, 00, 00]` (8 байт, EOL-паддинг 2 байта,
      `doff = 0x70`, `ip.total_len = 48`);
    - `wscale = Some(7)` → `[02, 04, 05, b4, 03, 03, 07, 00]` (`doff = 0x70`);
    - `tsecho = Some(0xdead_beef)` → `[02, 04, 05, b4, 08, 0a, de, ad, be, ef, 00, 00, 00, 00, 00, 00]` (16 байт опций,
      `doff = 0x90`, старший байт `0xde` сохранён — Р9).
  - `all_tcp_options_and_badsum_keep_valid_ipv4_header` (Review Focus 5): комбинация всех 4 опций + `ttl = 64` +
    `badsum = true` даёт `frame[22] == 64`, валидную IPv4 header checksum (`ip_header_checksum == 0`) и гарантированно
    невалидную `tcp_checksum_is_valid(frame) == false`.
  - `adapter_ip_power_of_two_range_rotates_source_ip`: `198.18.0.16-198.18.0.19` (ширина 4, `ipv4_mask = 3`) выбирает
    адреса внутри диапазона по `((ck >> 16) as u32) & 3` (`main.c:384`), а `198.18.0.16-198.18.0.18` (ширина 3)
    отклоняется ошибкой степени двойки.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core tcp_options_layout` — падает.
- [ ] **Шаг 3 — реализация:** реализовать сборку TCP-опций, `--ttl` и `--badsum` по `~/masscan/src/templ-pkt.c:942–1021,
  1474–1488` и `templ-tcp-hdr.c:1066–1119`, разбор `--ttl`, `--badsum`, `--noreset`, `--tcp-mss`, `--tcp-sackok`,
  `--tcp-wscale`, `--tcp-tsecho` и `--adapter-ip A-B` в `config.rs`/`args.rs`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `packet.rs`, `probe.rs`, `receive.rs`, `config.rs`, `args.rs`.

### Задача 7: `-c`/`--conf`, `-iL`/`--includefile`, массив адаптеров `nic[0..8)` и захват `--pcap`

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/args.rs`, `rmasscan/crates/rmasscan-cli/src/conf.rs`,
  `rmasscan/crates/rmasscan-cli/src/lib.rs`, `rmasscan/crates/rmasscan-cli/src/live.rs`,
  `rmasscan/crates/rmasscan-cli/src/os_backend.rs`
- Create: `rmasscan/crates/rmasscan-cli/src/pcap_writer.rs`
- Test: `pcap_writer.rs`, `args.rs`, `rmasscan/crates/rmasscan-cli/tests/live_fake.rs`

**Interfaces:**
- Produces:
  - `PcapWriter`: потокобезопасная обёртка `Mutex<BufWriter<File>>` (или произвольный `Box<dyn Write + Send>` в тестах),
    записывающая при открытии 24-байтовый заголовок `d4 c3 b2 a1 02 00 04 00 00 00 00 00 00 00 00 00 ff ff 00 00 01 00
    00 00` и на каждый подходящий входящий кадр (`<= 1514` байт, адресованный нашему `ip_me` и `port_me`,
    `main.c:829, 935, 943–951`) — 16-байтовый LE-заголовок `[ts_sec, ts_usec, len, len]` + кадр
    (`rawsock-pcapfile.c:669–712, 857–932`).
  - Поддержка `-c` / `--conf` / `--config`, `-iL` / `--includefile` и индексированных ключей `--adapter[0..7]` в `args.rs`
    и `live::prepare_multi`.

- [ ] **Шаг 1 — красный тест:**
  - `conf_and_includefile_respect_argv_order_and_detect_cycles`: `-c base.conf --rate 900 -iL targets.txt` применяет
    ключи в порядке появления, рекурсивный `conf = self.conf` обрывается на глубине > 16 с `Err` и `exit 1`.
  - `adapter_index_out_of_bounds_fails` (Review Focus 4): `--adapter[8] eth0` и `adapter[-1] = eth0` возвращают ошибку с
    кодом `1`; `--adapter[0] veth0 --adapter[1] veth1` на двух `FakeAdapter` делят зонды по чётным/нечётным индексам и
    пишут ответы в единый `Sink`.
  - `pcap_captures_inbound_frames_to_scanner_only`: на `FakeAdapter` впрыснуть чужой кадр, валидный SYN-ACK и RST с
    битым SYN-cookie (но на наш `ip_me:port_me`) → в `PcapWriter` записаны ровно 2 кадра (SYN-ACK и RST, чужой отброшен),
    байты заголовка `.pcap` валидны; передача `--pcap` вместе с `--offline` или `-sL` отклоняется с `exit 1`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli pcap_captures` — падает.
- [ ] **Шаг 3 — реализация:** реализовать `pcap_writer.rs` (`~/masscan/src/rawsock-pcapfile.c:669–712, 857–932`,
  `main.c:943–951`), фильтр до проверки cookie в RX-потоке, позиционный разбор `-c`/`-iL` (`main-conf.c:3332–3338,
  3375–3377, 3868–3924`) и цикл инициализации `nic[0..nic_count)` в `live.rs` (`main.c:1257–1390`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked --workspace` в `rmasscan/` и `cargo check --workspace` в `studio/` —
  всё зелёное.
- [ ] **Шаг 5 — коммит:** `args.rs`, `conf.rs`, `lib.rs`, `live.rs`, `os_backend.rs`, `pcap_writer.rs`, `tests/live_fake.rs`.

### Задача 8: живая приёмка (`--suite scan-control`) и документация

**Files:**
- Create: `rmasscan/crates/rmasscan-lab/src/scan_control_suite.rs`, `scan_control_verify.rs`,
  `docs/experiments/2026-11-08-rmasscan-scan-control-acceptance.md`
- Modify: `rmasscan/crates/rmasscan-lab/src/{lib,main}.rs`, `rmasscan/scripts/wire-lab.sh` (`--suite scan-control`),
  `rmasscan/README.md`, `docs/experiments/2026-10-24-rmasscan-readiness.md`,
  `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md` (пометка о закрытии этапа scan-control)

**Interfaces:**
- Produces: подкоманды `rmasscan-lab scan-control-suite linux ...` и `rmasscan-lab scan-control-verify --dir DIR`
  (коды `0` PASS / `1` FAIL / `2` INVALID, как у `autodetect` и `output`).

- [ ] **Шаг 1 — тесты верификатора (RED → GREEN):** юнит-тесты `scan_control_verify` на синтетических артефактах кейсов:
  `sc01_shards_union` (`1/2` + `2/2` покрывают весь набор SYN и находок оракула без пересечений),
  `sc02_pause_wait_resume` (`SIGINT` → `wait` ловит поздний ответ → `paused.conf` → `--resume` досылает остаток с
  `output-append`), `sc03_retries` (`--retries 2`), `sc04_packet_mods_and_pcap` (`--ttl 42 --tcp-sackok --tcp-wscale 7`,
  отдельный прогон `--badsum`, проверка `--pcap`), `sc05_infinite_interrupt`, `sc06_dual_veth` (`--adapter[0]` +
  `--adapter[1]` во втором veth-линке netns).
- [ ] **Шаг 2 — живое окно на запечатанном стенде:** прогнать `wire-lab.sh --suite scan-control` и регрессии
  `--suite autodetect` + `--suite output` на Linux (minipc, только `198.18.0.0/24`), а также `windows-suite --plan
  autodetect` на Windows VM и `cargo xtask test` в `studio/`; выполнить privacy-grep до копирования артефактов.
- [ ] **Шаг 3 — документация:** обновить `rmasscan/README.md` («Команды», «Отличия от masscan» по Р1–Р9, «Ограничения»,
  «Статус»), записать отчёт `docs/experiments/2026-11-08-rmasscan-scan-control-acceptance.md` и строку в `readiness.md`.
- [ ] **Шаг 4 — финальная проверка и коммит:** `cargo test --locked --workspace`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo fmt --check`, зелёный GitHub CI на точном HEAD
  (`rmasscan`, `Studio`, `language-guard`).

---

## Самопроверка

1. Покрытие спеки: Р1 → Задачи 2, 3, 4; Р2 → Задачи 1, 3, 7; Р3 → Задачи 1, 3; Р4 → Задача 4; Р5 → Задача 5; Р6 →
   Задачи 2, 6; Р7 → Задача 7; Р8 → Задача 7; Р9 → Задача 6; §6.2/§8 → Задача 8.
2. Каждый шаг даёт одну проверяемую вещь с точным именем теста и командой запуска.
3. Имена и типы (`NicBinding`, `ReadyPlan::new_cli`, `FullConf`, `PacketModifiers`, `PcapWriter`) согласованы между
   задачами, а 6-польный `AdapterBinding` и `ReadyPlan::new` для `Studio` не затронуты.
4. Все 5 пунктов Review Focus привязаны к именованным тестам в задачах 1, 2, 3, 4, 6 и 7.
5. План соразмерен задаче и не вводит лишних абстракций или внешних зависимостей.
