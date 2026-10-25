# rmasscan: база macOS (BPF) и контракты адаптера

Дата: 2026-10-25. Этап 2C, задача 0. Кода нет. Документ фиксирует (1) контракты, которым обязан
удовлетворять macOS-адаптер, со ссылками на проверенные места кода; (2) значения Mac, снятые
только чтением; (3) результат четырёх проверок репозитория на macOS до любого кода адаптера.

## Область и границы утверждений

* Этап измеряет **один** Mac: macOS 27.0.1 (сборка 26A434), Apple Silicon (arm64, Apple M4 Pro).
  Это не «macOS 14+»: CI-раннер `macos-14` проверяет только сборку и seam-тесты.
* Windows GO достигнут на VM (QEMU, e1000e), см. `2026-10-24-rmasscan-windows-vm-acceptance.md`.
  Физический NIC Windows **не измерен**. Физический NIC macOS **не измерен**: стенд этапа это пара
  `feth`, то есть копирование в ядре.
* Поведение при sleep/wake Mac: **NOT RUN** (Mac не усыпляется).
* Привилегированные команды не выполнялись (`sudo` не вызывался, raw-сокеты не открывались,
  `ifconfig create` не запускался). Всё в разделе «База Mac» получено чтением.

## Закреплённое дерево

| Параметр | Значение |
| --- | --- |
| Ветка | `feat/rmasscan-stage2c-macos-bpf` |
| BASE | `2cc2bec` (`2cc2bec19ae2b5810a0104f95d6bf3dd6cf4e3bd`, merge PR #9, stage 2B-Windows) |
| Дерево на момент замеров | чистое относительно BASE (untracked: `.superpowers/`, план stage 2C) |
| CI на точном HEAD | NOT RUN: push не разрешён |

## Контракты macOS-адаптера

Пути относительно `rmasscan/crates/`. Номера строк проверены на BASE `2cc2bec`.

### 1. `Rx::health` и `kernel_drops`

* `rmasscan-engine/src/io.rs:42-48` `RxHealth.kernel_drops: Option<u64>`: кумулятивно с начала
  попытки, `Some(0)` только при успешном измерении, `None` значит «измерить нельзя», неизвестное
  никогда не превращается в ноль. `io.rs:51-57` `Rx::health(&mut self, timeout)` обязателен,
  возвращается не позже `timeout`.
* `rmasscan-engine/src/engine.rs:350-371` `check_rx_health`: `Some(0)` продолжает; `Some(n)` →
  `FailReason::RxLoss { kernel_drops: n }` (`engine.rs:357`); `None` →
  `FailReason::RxStatsUnavailable` (`engine.rs:361`); `Err(e)` → `kernel_drops = None` и
  `FailReason::RxError(e.message)` (`engine.rs:366-368`). Все варианты без checkpoint.
* `engine.rs:392-401` страховка: `Completed`/`Stopped`/`Paused` невозможны без подтверждённого
  `Some(0)`; с `None` каждый запуск заканчивается `Failed(RxStatsUnavailable)`.
* Периодичность: `engine.rs:43` `RX_HEALTH_INTERVAL_MICROS = 250_000`, проверка по часам engine
  (`engine.rs:634-640`) и обязательная финальная до публикации `rx_end` (`engine.rs:648-651`).
* Образцы источника: Linux `linux/mod.rs:218-236` `collect_kernel_stats` (`PACKET_STATISTICS`
  сбрасывается при чтении, поэтому дельты складываются в `Counters::kernel_drops`) и
  `linux/mod.rs:324-` `health`; Windows `windows/adapter.rs:68-71` `publish_drops`,
  `windows/adapter.rs:200-215` `health` (`ps_drop` через `DropCounter`, ошибка `pcap_stats` это
  `Err`), `windows/handle.rs:395-421` `DropCounter` (база при открытии, `wrapping_sub`, сумма дельт).
  Общий тип `NetStats`/`Counters`: `rmasscan-net/src/lib.rs:94-166`.
* Источник на macOS: `BIOCGSTATS.bs_drop` RX-дескриптора (кумулятивный с открытия, чтение не
  сбрасывает, `u32` оборачивается), база снимается при открытии, перенос через `u32` делает
  общий `DropCounter` (переезд из `windows/handle.rs:403` без изменения поведения). Это **нижняя
  граница**: потери ниже BPF (в `feth`/драйвере NIC) не видны, как `ps_drop` NPF и
  `PACKET_STATISTICS`. Ошибка `ioctl` это `Err`, а не ноль.

### 2. TX stall и исходы записи

* `rmasscan-engine/src/io.rs:22-33` `SendStatus`: `Sent` (единственный двигает cursor),
  `WouldBlockUnsent` (кадр точно не отправлен), `Uncertain` (неизвестно, без повтора).
* `engine.rs:520-556` TX-цикл: `Sent` двигает cursor и `sent` (`engine.rs:520-527`);
  `WouldBlockUnsent` не двигает cursor, копит `stall_since`, по `idle >= stall_micros` вызывает
  `stall_fail` (`engine.rs:530-546`), `stall_fail` даёт `FailReason::TxStalled { idle_millis }`
  (`engine.rs:564-568`); `Uncertain` → `FailReason::TxUncertain` (`engine.rs:550-552`).
* `engine.rs:39` `DEFAULT_TX_STALL_TIMEOUT = 10 с`; `engine.rs:75-78` поле
  `EngineOptions::tx_stall_timeout`; `engine.rs:757` ноль запрещён.
* Эталон Linux `linux/mod.rs:120-168` `TxStep`/`step`: полная запись → `Sent`; короткая →
  `Uncertain` (`:138`); `EAGAIN` и `EINTR` до первого байта → `WouldBlockUnsent` (`:139-161`).
  Windows `windows/adapter.rs:8-30` и `:84-107`: `pcap_sendpacket` rc 0 → `Sent`, иначе
  `Uncertain`, `WouldBlockUnsent` не выдаётся никогда, статус не выводится из текста ошибки.
* Для macOS: `write()` в BPF: полная запись → `Sent`; `ENOBUFS`/`EAGAIN` → `WouldBlockUnsent` с
  ограниченным повтором до дедлайна; частичная запись → `Uncertain`; `EINTR` до первого байта →
  повтор без продления дедлайна; статус только по `errno` и длине.
* Тестовый образец сценариев: `rmasscan-engine/src/fake.rs:74-78` `TxStep`
  (`Sent`/`WouldBlockUnsent`/`Uncertain`), `:84-90` `RxStep` (`Frame`/`Fail`/`Idle`), `:262-292`
  поведение `send`, `:348-362` `health` (`Some(n)` или `None`).

### 3. Дедлайн ввода-вывода

* `engine.rs:37` `MAX_IO_TIMEOUT = 50 мс`; `engine.rs:763` `io_timeout.min(MAX_IO_TIMEOUT)`.
  Каждый `send`/`recv`/`health` возвращается не позже `min(timeout, MAX_IO_TIMEOUT)`.
* Эталон: `linux/mod.rs:80-101` `Deadline` (`Instant::now() + timeout.min(MAX_IO_TIMEOUT)`,
  фиксируется один раз на вызов; `expired`, `eintr_wait` с потолком `EINTR_BACKOFF_MAX = 1 мс`
  (`linux/mod.rs:72`), `poll_ms` с округлением вверх). Повторы после `EINTR` и ложные пробуждения
  дедлайн не продлевают; мусорные кадры тоже (`linux/mod.rs:203-` `RxStep`, `:250` `deadline`).
  Windows: `windows/adapter.rs:50` `IO_BUDGET = 42 мс` (решение контролёра по спайку),
  `windows/adapter.rs:161` `Instant::now() + timeout.min(MAX_IO_TIMEOUT).min(IO_BUDGET)`.
* Для macOS: RX всегда `O_NONBLOCK` + `poll()` с остатком дедлайна ≤50 мс; блокирующий `read` не
  используется; TX `write` без блокировки.

### 4. Stop, Pause, resume

* `engine.rs:4-9` модель `halt`: `RUN < PAUSE < STOP < FAIL`, TX выходит при любом `halt != RUN`
  и проверяет его перед каждой отправкой, RX выходит при `halt >= STOP`; при `PAUSE` RX дочитывает
  `wait`. `engine.rs:48` `PAUSE`, `engine.rs:406` исход `Paused` только при `rx_end == END_NATURAL`.
  Контракт: Stop ≤1 с; Pause прекращает TX ≤1 с и ждёт RX drain `wait` (приёмка с wait=3).
* Resume: `engine.rs:692-736` новая попытка имеет новый `attempt_id`, равный id checkpoint
  отклоняется (`engine.rs:728`); `engine.rs:863` `Engine::attempt_id`.
* `Stop`/`Pause` укладываются в 1 с за счёт того, что вызовы адаптера не длиннее 50 мс.

### 5. Часы

* Engine и адаптер используют `std::time::Instant`. `rmasscan-core/src/throttle.rs:32-37`
  `SystemClock` поверх `Instant` (монотонные, не идут назад). На macOS `Instant` это
  `CLOCK_UPTIME_RAW`: не идёт во сне. Метки времени pcap это стенные часы
  (`bpf_hdr.bh_tstamp`, микросекунды). Поведение при sleep/wake: **NOT RUN**.

### 6. Состояние macOS в коде сейчас

* `rmasscan-net/src/lib.rs:188-202` три `open_explicit`: `cfg(target_os = "linux")` →
  `linux::open`, `cfg(windows)` → `windows::open`, `cfg(not(any(target_os = "linux", windows)))`
  → `Err(NetError::UnsupportedPlatform)`. Следовательно, на macOS `open_explicit` сейчас всегда
  даёт `UnsupportedPlatform`; `lib.rs:208-214` `inventory()` для не-Windows тоже.
* Подтверждено **чтением кода**. Существующего теста на это нет: единственное упоминание
  `UnsupportedPlatform` в тестах (`windows/tests/adapter_tests.rs:290`) это отрицательная проверка
  на Windows. Тест на macOS появится вместе с адаптером (задачи 1 и далее).

## База Mac (только чтение)

Хост: Apple M4 Pro, 51 539 607 552 байт ОЗУ (`sysctl -n machdep.cpu.brand_string`, `hw.memsize`).
Дата снятия: 2026-10-25. Привилегированные команды не запускались.

| Команда | Значение |
| --- | --- |
| `sw_vers` | ProductName `macOS`, ProductVersion `27.0.1`, BuildVersion `26A434` |
| `uname -m` | `arm64` |
| `ls -l /dev/bpf*` | существуют **только** `/dev/bpf0`, `bpf1`, `bpf2`, `bpf3`; все `crw-------  root  wheel` (major 0x17, minor 0..3) |
| `sysctl debug.bpf_maxbufsize` | `524288` (512 KiB) |
| `sysctl debug.bpf_maxdevices` | `256` |
| `sysctl net.inet.ip.forwarding` | `0` |
| `sysctl net.link.fake.hwcsum` | `0` |
| `tcpdump --version` | `tcpdump version 4.99.1 -- Apple version 161`, `libpcap version 1.10.1`, `LibreSSL 3.3.6` |
| `route -n get default` | gateway `192.168.1.1`, interface `en0`, flags `<UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>`, mtu 1500 |
| `ifconfig -l` | `lo0 gif0 stf0 anpi0 anpi1 anpi2 en4 en5 en6 en1 en2 en3 bridge0 pktap0 utun0 ap1 en0 awdl0 llw0 utun1 utun2 utun3 nan0 utun4 utun5 utun6 utun7` (интерфейсов `feth*` нет) |
| `id -Gn` | `staff everyone localaccounts _appserverusr admin _appserveradm com.apple.sharepoint.group.1 _appstore _lpadmin _lpoperator _developer _analyticsusers com.apple.access_ftp com.apple.access_screensharing com.apple.access_ssh com.apple.access_remote_ae` (группа `staff` есть; `wheel` нет) |
| `rustc --version` | `rustc 1.99.1 (58cf8f9c3 2026-10-13) (Homebrew)` |
| `cargo --version` | `cargo 1.99.1 (5f94df478 2026-08-27)` (Homebrew, rustup нет) |
| `cargo fmt --version` / `cargo clippy --version` | `rustfmt 1.10.0` / `clippy 0.1.99` |

Выводы для плана:

* Права на `/dev/bpf*` по умолчанию `0600 root:wheel`, как заложено в плане. Пользователь в `staff`,
  поэтому `0660 root:staff` на время сессии даст сканеру доступ без root.
* **Наблюдение, не вывод**: сейчас на диске только `bpf0..bpf3`, а план везде говорит
  `bpf0..15`. Узлы старше `bpf3` на момент снятия не существуют. Создаёт ли их ядро по требованию
  при открытии, этой задачей не проверялось (проверка требует открытия `/dev/bpf*`, то есть
  привилегий). Задача 3 (спайк) и действие `bpf-access --grant` должны учесть это: не считать
  отсутствие `bpf4..15` ошибкой стенда и не предполагать, что `chmod` по маске `bpf0..15`
  применим к несуществующим узлам. Требуется ли root для создания узла, **не измерено**.
* `debug.bpf_maxbufsize = 524288` подтверждает решение 2 плана (`BIOCSBLEN = min(4 MiB, maxbufsize)`
  даёт 512 KiB). Поднятие до 4 MiB требует root, **не выполнялось**.
* `net.inet.ip.forwarding = 0` подтверждает посылку решения 1 (пакеты, пришедшие на `feth4201`,
  ядро не маршрутизирует). `net.link.fake.hwcsum = 0` сохранён для сравнения со спайком (влияет на
  контрольные суммы на `feth`).
* `feth` и `bridge0` в `ifconfig -l`: `feth*` нет, `bridge0` системный (Thunderbolt Bridge), стенд
  его не использует.

## Проверки репозитория на macOS

Каталог сборки: `CARGO_TARGET_DIR=/private/tmp/claude-501/-Users-denyskolomiiets-masscan/3c73b7a2-86d2-4a31-816e-712b40c2aec5/scratchpad/target-2c-impl`
(приватный, вне дерева; решение контролёра). Рабочий каталог `rmasscan/` для `cargo`, корень
репозитория для `scripts/language-guard.sh`. Все четыре команды выполнены на чистом BASE `2cc2bec`.

| Команда | rc |
| --- | --- |
| `cargo fmt --all --check` | 0 |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | 0 |
| `cargo test --locked --workspace` | см. ниже: первый прогон 101, повтор 0 |
| `bash scripts/language-guard.sh` | 0 (`language guard: PASS (4219 tracked files checked)`) |

### Тесты: сводка `test result`

Первый прогон `cargo test --locked --workspace` (одновременно с холодной сборкой, нагрузка на
машину) завершился **rc 101**: упали 2 теста `rmasscan-lab --lib` (386 passed, 2 failed). Поскольку
cargo прекращает прогон после упавшего крейта, этот прогон не дошёл до крейтов после `rmasscan-lab`
в порядке запуска; поэтому полная картина получена повтором.

Упавшие тесты (оба используют `fake-tcpdump.sh`, скрипт `sh` с `trap ... INT` и циклом
`sleep 0.02`, `rmasscan-lab/src/dump_tests.rs:277`):

* `dump::tests::sequence::a_complete_capture_is_acknowledged_finalised_and_valid`
  (`dump_tests.rs:326`)
* `dump::tests::linux_wire_gate::real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate`
  (`dump_tests.rs:495`, случай `c01_one_addr_port_synack`)

Причина в обоих: `invalid_reasons` содержит `"tcpdump did not exit after SIGINT"` и, как следствие,
`captured=None`. То есть поддельный свидетель не завершился за отведённый бюджет под нагрузкой.
Тесты **зависят от времени** (дедлайн 5000 мс и планирование процессов `sh`), что противоречит
уроку плана «тесты не зависят от точности sleep». К macOS BPF это не относится, но это
существующая нестабильность на BASE.

Повторы после прогрева сборки:

* `cargo test --locked -p rmasscan-lab --lib dump::` → `17 passed; 0 failed`.
* `cargo test --locked --workspace --no-fail-fast` → rc 0.
* `cargo test --locked --workspace` (повтор буквально той же команды) → **rc 0**, 37 строк
  `test result: ok`, суммарно **828 passed, 0 failed, 8 ignored** (`rmasscan-lab --lib`:
  `388 passed; 0 failed`; `rmasscan-core --lib`: `136 passed`; `rmasscan-cli` бинарь:
  `15 passed`; `rmasscan-net --lib`: `83 passed`, без Linux- и Windows-ветк).

Вердикт по условию GREEN «три проверки rc 0»: после повтора все три rc 0, но первый прогон дал 101.
Это зафиксировано как **flaky на BASE** (нагрузка), не как исправленное. Рекомендация контролёру:
в последующих задачах полный `cargo test --locked --workspace` запускать не параллельно с другой
сборкой; если флейк повторится, завести отдельную задачу на удаление зависимости теста от времени.

## Ограничения и открытые пункты

1. CI на точном HEAD: NOT RUN (push не разрешён).
2. Физические NIC (Windows и macOS): не измерены; macOS измеряется на `feth`.
3. sleep/wake Mac: NOT RUN.
4. Создание `/dev/bpf4..15`, `chmod`, `feth`, `lladdr`, `bridge`: не проверялось, нужен root.
5. Нестабильность двух тестов `rmasscan-lab` под нагрузкой (раздел выше).
6. Одна машина (macOS 27.0.1, Apple M4 Pro): результаты не обобщаются на «macOS 14+».
