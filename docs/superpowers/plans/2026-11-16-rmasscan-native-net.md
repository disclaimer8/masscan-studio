# rmasscan-net: нативный Rust, фаза 1 — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans`.
> Шаги в чекбоксах (`- [ ]`). Цикл задачи: RED (тест) → FAIL → минимальная правка → PASS на названных ОС → замер (если
> задача о скорости) → коммит.

**Goal:** `rmasscan-net` пишется идиоматичным Rust и становится быстрее на горячем пути, каждое ускорение подтверждено
замером; поведение не меняется, кроме трёх решённых пользователем изменений P1–P3 и удаления тестового спайка BPF.

**Architecture:** сначала страховка (раскладка ABI, флаги сокетов, точные тексты ошибок, конкурентный тест счётчиков,
микробенч адаптера, стенд и калибровка шума), затем правки, которые она охраняет: счётчики, переносимый разбор, общие
примитивы Unix, FFI macOS, общие помощники бэкендов и `as`, netlink и переносимый адаптер Linux, `recvmmsg`, чистка
Windows; P1–P3 последними, у каждой своя ячейка стенда. Публичный API не меняется; новый `unsafe` появляется только в
блоках, названных в P1 и P2.

**Tech Stack:** Rust 1.99.1, edition 2024, workspace `rmasscan/`; `libc =0.2.191` (Unix), `windows-sys =0.61.2`
(Windows); новых зависимостей нет.

**Spec:** [docs/superpowers/specs/2026-11-16-rmasscan-native-rust-design.md](../specs/2026-11-16-rmasscan-native-rust-design.md)
(«Решения пользователя» и «Ограничения» главнее этого плана).

**Опора (строки на базе `a275ea9e`):** `lib.rs` — контракт времени :19-29, `NetStats` :247, доки
`tx_batches`/`tx_batch_max` :265-275, `Counters` :279-304, `snapshot` :322, `TxMode` :357, `OpenedAdapter` :364;
`linux/mod.rs` — шов `PacketIo` :52, `TxHalf::step` :139, `Tx for TxHalf` :176, `RxHalf::step` :251, `Rx for RxHalf`
:303, `tx_mode` :424; `linux/socket.rs` — `open` :38, `send` :100, `recv` :114; `linux/route.rs` — `Netlink` :71-173;
`macos/adapter.rs` — `parse_record` :293, `RxHalf::step` :379, дедлайн `recv` :478; `macos/ifinfo.rs` — разбор
`sockaddr` :145-200, `prefix_from_sockaddr` :399; `windows/adapter.rs` — `send_batch` :176, `RxHalf::wait` :254,
`Rx for RxHalf` :282, проверка nonblock :420-424; `windows/ffi.rs` — `pcap_api!` и `REQUIRED_SYMBOLS` :232-314;
`windows/loader.rs` — необязательный `pcap_init` :204-215. Движок: `Err` из `send_batch` → `FailReason::TxError(текст)`,
`Uncertain` → `TxUncertain` без текста, `kernel_drops > 0` → `RxLoss` и остановка (`engine.rs:764-773`, `1255-1263`).
Потребители: `rmasscan-lab`, `rmasscan-cli`, `studio/` (`studio-runner` зовёт `open_explicit`, `os_route_table`,
`plan_physical`) — все только через публичный API.

## Global Constraints

- **Файлы.** Меняются только `rmasscan/crates/rmasscan-net/**` (включая `examples/`) и документы
  `rmasscan/README.md`, `rmasscan/BENCHMARKS.md`, `rmasscan/docs/macos-feth-lab.md`, `rmasscan/docs/rust-lab.md`,
  `rmasscan/docs/windows-wire-lab.md`, `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md`.
  `rmasscan-engine`, `-cli`, `-lab`, `-proto`, `-core` и `studio/` не меняются ни на байт: 4c меняет engine, cli, lab и
  proto на `feat/rmasscan-banners-4c`.
- **Зависимости.** Новых нет, фич `windows-sys` не прибавляется, `Cargo.lock` и `studio/Cargo.lock` не меняются
  (`git diff --exit-code a275ea9e -- rmasscan/Cargo.lock studio/Cargo.lock`). Rust 1.99.1, edition 2024.
- **Публичный API заморожен.** Ни одна существующая `pub`-сигнатура не меняется; допустимы только новые элементы.
  `TxMode` и `NetStats` — исчерпывающие `pub`-типы: ни вариантов, ни полей не добавлять. Внутренние (`pub(crate)`)
  швы и типы меняются свободно.
- **Поведение байт в байт вне P1–P3:** кадры на проводе и их порядок, чтение кадров, счётчики `NetStats`, семантика
  ОС (флаги сокетов, порядок вызовов, повторы EINTR/EAGAIN), тексты ошибок, результаты разбора. Тексты не меняются
  нигде, даже там, где их сейчас никто не сверяет.
- **Тексты errno.** `errno_msg` печатает номер таблицей ОС хоста (`io::Error::from_raw_os_error`): номер Linux 11 на
  Mac выглядит как EDEADLK, а не EAGAIN. Тест, сверяющий текст с errno, строит ожидание той же функцией хоста;
  переносимые тесты кода Linux сверяют вид ошибки (вариант `NetError`, `SendStatus`, код), а не текст ОС.
- **Тесты, которые не мигают.** Утверждения о времени — только верхние границы; существующие нижние границы остаются
  под `#[cfg(target_os = "linux")]`, когда их тест начинает собираться на других ОС. Никаких подсчётов по всему
  процессу в параллельном `cargo test` (число открытых fd, два снимка списка потоков): только проверки конкретного
  fd и инварианты одного снимка. Тест, зависящий от свойств процесса ОС, живёт под `cfg` своей ОС.
- **`unsafe`.** Только узкие блоки, у каждого `// SAFETY:`, и каждый `SAFETY` опирается только на условия, которые
  обёртка проверяет сама (длины, число слотов, границы). `deny(clippy::undocumented_unsafe_blocks)`,
  `deny(unsafe_op_in_unsafe_fn)` и `deny(unsafe_code)` на уровне crate остаются. Новых `unsafe fn` и `unsafe impl` нет
  (кроме расширения контракта существующего `unsafe trait Module` в задаче 16). Число блоков `unsafe {` в рабочем коде
  (`unsafe_count`, раздел «Команды»; база 199; тестовые файлы `*_tests.rs` не считаются) в конце каждой задачи не
  больше, чем в конце предыдущей. Исключения только названные: задача 15 (P1) +1 — вызов `sendmmsg`; задача 16 (P2)
  +3 — `transmute` символа `pcap_getevent`, вызов `pcap_getevent`, вызов функции ожидания. Число пишется в заметки.
- **Сборки.** Каждая команда задаёт `CARGO_TARGET_DIR` вне дерева; `rmasscan/target` не создаётся. Фоновые процессы в
  zsh: `trap 'trap - EXIT INT TERM; kill 0' EXIT INT TERM` (не `trap 'kill 0' …`: крутит CPU); по окончании
  `ps -Ao pid,%cpu,etime,command | awk '$2>80'` и остановка только своих процессов.
- **ОС проверки.** На Mac установлен только `aarch64-apple-darwin`: код только для Linux или только для Windows здесь не
  компилируется. Такая задача проверяется сборкой и тестами на Linux-хосте стенда (`L-gate`) и в Windows-госте стенда
  (`W-gate`); ворота повторяют шаги CI (`clippy --workspace`, `--features lab`). CI — только после push, а push и PR —
  только с согласия пользователя. Скрипты Windows копируются файлом и запускаются
  `pwsh -NoProfile -ExecutionPolicy Bypass -File …`, никогда `-Command "…"`.
- **Скорость.** Числа с Mac только ранжируют. Задача о скорости в `rmasscan-net` доказывается ячейкой `U` на
  Linux-стенде по протоколу раздела «Замеры» (калибровка «база против базы» и парные A/B в одной сессии), а
  существующая матрица 4×5 остаётся 40/40 VALID без потерь RX. Физические NIC не используются: скан реальной сети —
  внешнее действие.
- **Гигиена публичного репозитория.** Ни локальных путей, ни имён пользователей, хостов и LAN-адресов: хосты
  называются по роли (`$LINUX_HOST` — Linux-хост стенда, CPU оракула; `$WIN_GUEST` — Windows-гость стенда). Перед
  каждым коммитом `git diff --cached -U0 | grep '^+' | hygiene` (раздел «Команды») печатает пустоту.
- **Коммиты.** `git add` только явных путей; сообщение через `git commit -F -` с последней строкой
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Ветка `refactor/rmasscan-native-net` от `a275ea9e`.
- **Заметки.** Исполнитель пишет решения, находки и числа по ходу в
  `.superpowers/sdd/2026-11-16-rmasscan-native-net/task-N-notes.md`. Каталог `.superpowers/` игнорируется через
  `.git/info/exclude` основного репозитория, а не `.gitignore`; на свежем клоне строку туда добавить до первой
  заметки.
- **Вне плана.** Старый разбор `GetAdaptersAddresses` в `windows/sys.rs` не трогается; ленивый дедлайн Linux не
  делается; всё из раздела «Фаза 2» спеки (borrowing RX, mmap-кольца, свой `TxMode` для Linux, новые поля
  `NetStats`, `lookup_many`, типизированный `NetError`) — не здесь.

## Команды

```bash
# Общие переменные (Mac, корень worktree)
export CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rmasscan-native-net-target"
EVID=$(mktemp -d "${TMPDIR:-/tmp}/rmasscan-native-net.XXXXXX")   # доказательства задачи, вне репозитория
SHA=$(git rev-parse --short HEAD)

# M-gate (Mac)
(cd rmasscan && cargo fmt --all --check \
  && cargo clippy --locked --workspace --all-targets -- -D warnings \
  && cargo clippy --locked -p rmasscan-net --all-targets --features lab -- -D warnings \
  && cargo test --locked -p rmasscan-net \
  && cargo test --locked -p rmasscan-net --features lab --lib lab_io \
  && cargo test --locked -p rmasscan-net --example wire_scan) \
  && git diff --exit-code a275ea9e -- rmasscan/Cargo.lock studio/Cargo.lock

# L-gate (Linux-хост стенда): всё дерево HEAD, сборка вне дерева
git archive --format=tar --prefix="rnn-$SHA/" HEAD | ssh "$LINUX_HOST" 'mkdir -p ~/rnn && tar -x -C ~/rnn'
ssh "$LINUX_HOST" "cd ~/rnn/rnn-$SHA/rmasscan && export CARGO_TARGET_DIR=/tmp/rnn-target \
  && ~/.cargo/bin/cargo clippy --locked --workspace --all-targets -- -D warnings \
  && ~/.cargo/bin/cargo clippy --locked -p rmasscan-net --all-targets --features lab -- -D warnings \
  && ~/.cargo/bin/cargo test --locked -p rmasscan-net \
  && ~/.cargo/bin/cargo test --locked -p rmasscan-net --features lab --lib lab_io \
  && ~/.cargo/bin/cargo test --locked -p rmasscan-net --example wire_scan"

# W-gate (Windows-гость): zip дерева HEAD; копирование в гостя — путём из rmasscan/docs/rust-lab.md
git archive --format=zip -o "$EVID/rnn-$SHA.zip" HEAD
#   в госте: pwsh -NoProfile -ExecutionPolicy Bypass -File rnn-test.ps1 -Zip rnn-<sha>.zip
```

`rnn-test.ps1` (файл в `$EVID`, в репозиторий не кладётся):

```powershell
param([Parameter(Mandatory)][string]$Zip)
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP ([IO.Path]::GetFileNameWithoutExtension($Zip))
Expand-Archive -Path $Zip -DestinationPath $root -Force
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'rnn-target'
Set-Location (Join-Path $root 'rmasscan')
foreach ($a in @('clippy --locked --workspace --all-targets -- -D warnings',
                 'clippy --locked -p rmasscan-net --all-targets --features lab -- -D warnings',
                 'test --locked -p rmasscan-net',
                 'test --locked -p rmasscan-net --features lab --lib lab_io',
                 'test --locked -p rmasscan-net --example wire_scan')) {
  & cargo @($a -split ' '); if ($LASTEXITCODE) { exit 1 }
}
```

```bash
# Гигиена: шаблон (локальные пути, имена хостов и учётки, LAN) собран из частей, чтобы его не содержал сам план
hygiene() { grep -nE '/Use''rs/|mini''pc|home''-pc|192\.168|den''ys'; }

# Число блоков unsafe в рабочем коде (из rmasscan/crates/rmasscan-net; база 199)
unsafe_count() {
  find src -name '*.rs' ! -name '*_tests.rs' ! -name 'tests.rs' ! -path '*/tests/*' ! -name 'spike.rs' ! -name 'live.rs' \
    | xargs sed -E 's://.*$::' | grep -oE '\bunsafe[[:space:]]*\{' | wc -l
}
```

Фильтр одного теста: `cargo test --locked -p rmasscan-net <имя>`. Любая команда на хосте идёт из дерева архива
`~/rnn/rnn-<sha>/rmasscan` с `CARGO_TARGET_DIR=/tmp/rnn-target`, в госте — из распакованного дерева с
`CARGO_TARGET_DIR=$env:TEMP\rnn-target`; RED для кода только Linux или только Windows подтверждается там же с фильтром
теста.

## Замеры на стенде

**Стенд S** — одноразовый скрипт на `$LINUX_HOST` в `mktemp -d /tmp/rmasscan-native-net.XXXX` (в репозиторий не
кладётся; задача 1 записывает его итоговый текст в `BENCHMARKS.md`, дальше он берётся оттуда без изменений). Под
`sudo -n` он поднимает изоляцию по правилам `scripts/wire-lab.sh`: две netns `rnn-a`/`rnn-b`, пара veth
`rnn-va`/`rnn-vb` (qdisc по умолчанию, `noqueue`, как в матрице), без uplink, моста и NAT, IPv6 выключен на обоих
концах, маршрута по умолчанию нет; MAC `02:aa:00:00:00:01`/`02:aa:00:00:00:02`, сканер `10.200.0.1/24` (адрес адаптера
`10.200.0.100` не назначен), у пира `10.200.0.2-5/24` без слушателей (ядро пира отвечает RST на каждый SYN); проверка
изоляции — `rmasscan-lab capture isolation`, как в `wire-lab.sh`; снятие —
`trap 'trap - EXIT INT TERM; ip netns del rnn-a; ip netns del rnn-b' EXIT INT TERM`. Сканер всегда запускается под
`taskset -c <набор>`; набор один на сессию и записан в тексте ячейки.

**Ячейка U.** `wire_scan` (release) из `ip netns exec rnn-a` с `--iface rnn-va --src-ip 10.200.0.100
--src-mac 02:aa:00:00:00:01 --router-mac 02:aa:00:00:00:02 --seed 1 --source-port 40000 --wait 1`. CPU потоков движка
берётся из `workers.tx_cpu_ns`/`rx_cpu_ns` JSON (задача 1), а не из CPU всего процесса.

- `U-TX` — `--rate 100000000 --targets 10.200.0.0/16 --ports 1-64` (4 194 304 пробы, отвечают только `.2-.5`).
  Метрики: `timing.steady_pps`; CPU потока TX на отправленный кадр; `net.tx_would_block`. Годный прогон:
  `reason == "Completed"`, `net.tx_sent` равен числу проб, прирост RX-пакетов `rnn-vb` по `ip -s -j link` не меньше
  `net.tx_sent`, `rx_health.kernel_drops == 0`.
- `U-RX` — CPU потока RX на принятый кадр при фиксированной скорости `R_RX`, `--targets 10.200.0.2-10.200.0.5
  --ports 1-65535` (262 140 проб, на каждую RST). `R_RX` выбирается в калибровке сессии: наибольшая из лестницы
  400 000, 300 000, 200 000, 150 000, 100 000 pps, на которой все прогоны базы в калибровке годны. Годный прогон:
  `reason == "Completed"`, `rx_health.kernel_drops == 0`, ответов не меньше числа проб. Движок обрывает скан на первой
  потере ядра (`RxLoss`), поэтому прогон без ограничения скорости здесь не годен по определению.
- Негодный прогон — INVALID: никогда не PASS, в медианы не идёт. INVALID базы в калибровке — сессия не годна (для
  `U-RX` — шаг вниз по лестнице, для `U-TX` — новая сессия). INVALID новой версии при годной базе — FAIL задачи.
- **Протокол сессии** (одна сессия = один подъём стенда S, без перезапуска хоста): (1) калибровка «база против базы» —
  5 пар чередованием (база, база); разброс `S_AA = |медиана₁ − медиана₂| / медиана` по каждой метрике; порог
  `T = max(2 %, S_AA)`; (2) парные A/B — 5 пар чередованием (база, новая) в той же сессии; (3) C-оракул — отдельной
  серией после A/B, только для справки. База — коммит ветки до первой правки задачи (sha в заметках), сборка из
  `git archive`, как `L-gate`.
- Ворота «без регрессии»: медиана новой версии хуже медианы базы не больше чем на `T` по каждой метрике ячейки.
  Ворота «ускорение»: по целевой метрике задачи медиана новой версии лучше медианы базы больше чем на `T`, и не меньше
  4 из 5 повторов новой версии лучше медианы базы; прочие метрики — «без регрессии». Если ворота «ускорение» не
  пройдены, продуктовая правка не коммитится, отрицательный замер с `T` пишется в `BENCHMARKS.md`, решение за
  пользователем.

**Матрица** (существующая, 40 ячеек) и полный набор Rust на том же дереве; `ORACLE` — путь к закреплённому C-оракулу
на хосте (переменная окружения хоста):

```bash
ssh "$LINUX_HOST" "cd ~/rnn/rnn-$SHA/rmasscan && export CARGO_TARGET_DIR=/tmp/rnn-target \
  RMASSCAN_LAB_BIN=/tmp/rnn-target/release/rmasscan-lab OUT=\$(mktemp -d /tmp/rmasscan-native-net.XXXX) \
  && ~/.cargo/bin/cargo build --locked --release -p rmasscan-lab \
  && ~/.cargo/bin/cargo build --locked --release -p rmasscan-net --example wire_scan \
  && scripts/wire-lab.sh --oracle \"\$ORACLE\" --out \$OUT/perf --suite perf --reps 5 \
       --rust-bin /tmp/rnn-target/release/examples/wire_scan \
  && scripts/wire-lab.sh --oracle \"\$ORACLE\" --out \$OUT/rust --suite rust \
       --rust-bin /tmp/rnn-target/release/examples/wire_scan --fixtures tests/golden/wire \
  && RMASSCAN_WIRE_RESULTS=\$OUT/rust RMASSCAN_WIRE_PERF_RESULTS=\$OUT/perf \
       ~/.cargo/bin/cargo test --locked -p rmasscan-net --test linux_wire -- --ignored"
```

Ожидается: матрица 40/40 VALID, `rust_kernel_drops_per_run` и `rust_rx_incomplete_runs` нули, набор `rust` без FAIL и
NOT RUN, все `linux_wire --ignored` ok. `--suite rust` нужен задачам 13, 15 и 17 и приёмке; матрица — каждой задаче
о скорости.

**Дымовой прогон адаптера** (задачи 1, 6, 13, 15, 17): `cargo test --locked --release -p rmasscan-net --test linux_io
--no-run`, затем бинарник из вывода под `sudo -n ip netns exec rnn-a env RMASSCAN_LAB_IFACE=rnn-va
RMASSCAN_LAB_IP=10.200.0.100 RMASSCAN_LAB_MAC=02:aa:00:00:00:01 RMASSCAN_LAB_PEER_MAC=02:aa:00:00:00:02 <bin> --ignored
--test-threads=1 lab_`; `lab_open_without_privilege_is_permission_denied` — под `setpriv --reuid=nobody --regid=nogroup
--clear-groups`, иначе он записывается NOT RUN.

## Review Focus

1. **Пачка `recvmmsg` со смесью записей** (свой исходящий кадр на ядре без `PACKET_IGNORE_OUTGOING`, чужой ifindex,
   кадр длиннее буфера, запись с коротким адресом): порядок выдачи, счётчики и фатальная ошибка ровно на своей записи —
   как у покадрового пути. Тест `rx_batch_mixed_records_match_the_per_frame_path` (задача 13).
2. **`sendmmsg` принял часть пачки, а ядро потеряло ошибку** (вернуло `k < n` без errno): повтор с первого
   неотправленного кадра даёт настоящий errno, префикс засчитан один раз, дедлайн один на весь вызов. Тест
   `tx_batch_lost_error_is_resolved_by_reissue_within_one_deadline` (задача 15).
3. **Старый wpcap без `pcap_getevent` или NULL-событие:** RX работает прежним опросом 1 мс, без `MissingCapability`.
   Тест `missing_or_null_event_falls_back_to_one_ms_polling` (задача 16).
4. **Событие Npcap, которое остаётся сигнальным при пустом буфере:** RX не крутится вхолостую, число пробуждений за
   бюджет ограничено. Тест `signalled_but_empty_event_does_not_spin` (задача 16).
5. **`health` между пачками RX:** при кадрах, лежащих во внутреннем кольце, `health` делает свежее чтение
   `PACKET_STATISTICS`, а кадры кольца выдаются после него без потерь и без повторного счёта. Тест
   `health_between_batches_reads_fresh_drops_and_keeps_buffered_frames` (задача 13).

## Карта файлов

- Новые: `src/linux/layout_tests.rs` и `src/unix_fd_tests.rs` (задача 1; второй — тестовый помощник флагов fd,
  `fcntl(F_GETFL)`/`fcntl(F_GETFD)`, вне `unsafe_count`), `src/counters.rs` (2: счётчики и их стороны записи),
  `src/unix_sys.rs` и `src/unix_sys_tests.rs` (6: примитивы Unix — единственное место их `unsafe` — и их тесты),
  `src/adapter_common.rs` (9: общие помощники трёх адаптеров, без `unsafe`), `src/linux/abi.rs` (12: константы
  Linux без `libc`).
- Удаляется: `src/macos/spike.rs` (7).
- Горячий путь: `src/lib.rs`, `src/linux/{mod,socket}.rs`, `src/macos/{adapter,sys}.rs`,
  `src/windows/{adapter,handle,ffi,loader}.rs`.
- Разбор и обнаружение: `src/route_parse.rs` (+ тесты), `src/linux/{route,route_observation}.rs`,
  `src/macos/{ifinfo,route}.rs`, `src/windows/{sys,process}.rs`, `src/discover.rs`, `src/neighbours.rs`,
  `src/interrupt.rs`, `src/lab_io.rs`.
- Лабораторный harness (наш): `examples/wire_scan.rs` (CPU потоков движка, задача 1).

---

### Задача 1: страховка — раскладка ABI, флаги сокетов, точные тексты, счётчики, микробенч, стенд

Проверяет: Mac (macOS и переносимые фейки Windows), Linux-хост (`L-gate`), Windows-гость (`W-gate`); стенд S
(дымовой прогон, первая калибровка). Продуктовый код не меняется, кроме видимости констант, которые сверяют тесты.

**Files:**
- Create: `src/linux/layout_tests.rs` (`#[cfg(all(test, target_os = "linux"))] mod layout_tests;` в `linux/mod.rs`),
  `src/unix_fd_tests.rs` (`#[cfg(all(test, unix))] #[allow(unsafe_code)] mod unix_fd_tests;` в `lib.rs`)
- Modify (тесты): `src/macos/tests/layout_tests.rs`, `src/route_parse_tests.rs`, `src/linux/route_tests.rs`,
  `src/linux/route_observation_tests.rs`, `src/linux/tests.rs`, `src/macos/route.rs` (модуль `bounded_tests`),
  `src/macos/tests/adapter_tests.rs`, `src/windows/tests/adapter_tests.rs`, `src/windows/tests.rs`,
  `tests/linux_io.rs`
- Modify (видимость): приватные константы `route_parse::{rtsock::{SDL_DATA, SIN6_LEN, SIN6_ADDR}, netlink::RTA_HDRLEN}`
  → `pub(crate)`
- Modify (harness): `examples/wire_scan.rs`; `rmasscan/BENCHMARKS.md` (текст стенда S и ячейки U, первая калибровка)

**Interfaces:**
- Produces: `unix_fd_tests::fd_flags(fd: BorrowedFd<'_>) -> (c_int, bool)` — флаги состояния (`F_GETFL`) и
  `FD_CLOEXEC` (`F_GETFD`) конкретного fd.
- Produces (держатся зелёными до конца ветки): тесты раскладки ниже; `*_keep_their_flags`; `error_texts_are_byte_identical`
  и `stats_snapshot_is_monotonic_and_exact_under_concurrent_tx_and_rx` в тестах каждого из трёх адаптеров;
  `#[ignore] adapter_hot_path_two_threads` там же.
- Produces (harness): JSON `wire_scan` получает `workers.tx_cpu_ns` и `workers.rx_cpu_ns` — время на CPU потока движка
  из первого поля `/proc/thread-self/schedstat`, прочитанное в `Drop` обёрток `HarnessTx` и `IdRx` (они уничтожаются в
  потоках движка); не Linux или файла нет — `null`. Поля дописываются в конец объекта `workers`.

- [ ] **Step 1: тесты раскладки.**
  - `darwin_route_socket_constants_match_libc` (`route_parse_tests.rs`, `#[cfg(target_os = "macos")]`):
    `RT_MSGHDR_LEN == size_of::<libc::rt_msghdr>()`; каждый `OFF_*` равен `offset_of!(libc::rt_msghdr, rtm_msglen |
    rtm_version | rtm_type | rtm_index | rtm_flags | rtm_addrs | rtm_pid | rtm_seq | rtm_errno)`; `RTM_VERSION`,
    `RTM_GET`, `RTA_DST_BIT`, `RTA_IFP_BIT`, все `RTF_*`, `AF_LINK`, `AF_INET6_DARWIN` равны значениям `libc`;
    `SDL_DATA == offset_of!(libc::sockaddr_dl, sdl_data)`, `SIN6_LEN == size_of::<libc::sockaddr_in6>()`,
    `SIN6_ADDR == offset_of!(libc::sockaddr_in6, sin6_addr)`.
  - `bpf_program_layout_matches_libc` (`macos/tests/layout_tests.rs`): размер `BpfProgram` и смещение `bf_insns`
    равны `libc::bpf_program`.
  - `netlink_constants_match_libc` (`linux/layout_tests.rs`): `NLMSG_HDRLEN == size_of::<libc::nlmsghdr>()`,
    `RTA_HDRLEN == size_of::<libc::rtattr>()`, `NLMSG_ERROR`, `NLMSG_DONE`, `RTM_{NEW,GET}ROUTE`, `RTM_{NEW,GET}ADDR`,
    `NLM_F_REQUEST`, `NLM_F_DUMP`, `RTA_{DST,OIF,GATEWAY,PRIORITY,TABLE,PREFSRC}`, все `RTN_*`, `RT_TABLE_MAIN`,
    `IFA_{ADDRESS,LOCAL,FLAGS}`, `IFA_F_*`, `AF_INET`, `AF_INET6_LINUX` равны `libc`; `SLL_MIN_LEN ==
    offset_of!(libc::sockaddr_ll, sll_addr)`.
  - `observation_constants_and_offsets_match_libc` (`route_observation_tests.rs`, видит приватные константы через
    `super::*`): `HEADER_LEN`, `NLMSG_ERROR`, `NLMSG_DONE`, `NLM_F_DUMP_INTR`, `RTM_{NEW,GET}LINK`, `RTM_{NEW,GET}ADDR`
    равны `libc`; `size_of::<libc::ifinfomsg>() == 16`, смещения `ifi_type` 2, `ifi_index` 4, `ifi_flags` 8;
    `size_of::<libc::ifaddrmsg>() == 8`, смещения `ifa_prefixlen` 1, `ifa_index` 4.
  - `windows_dad_and_iftype_constants_match_windows_sys` (`#[cfg(windows)]` в `windows/tests.rs`): `WIN_DAD_*` равны
    `windows_sys::Win32::Networking::WinSock::IpDadState{Tentative,Duplicate,Deprecated,Preferred}`, `IF_TYPE_*` —
    константам `Win32::NetworkManagement::IpHelper`.
- [ ] **Step 2: флаги сокетов в местах вызова** (через `fd_flags` на возвращённом fd, без подсчёта fd процесса):
  `netlink_sockets_keep_their_flags` (`route_tests.rs`, Linux): `Netlink::open()` — `FD_CLOEXEC` есть, `O_NONBLOCK`
  нет; сокет ioctl `IfSock::open()` — `FD_CLOEXEC` есть, `O_NONBLOCK` нет; `observation_socket_keeps_its_flags`
  (`route_observation_tests.rs`): `Socket::open()` — оба есть; `route_socket_keeps_its_flags` (`macos/route.rs`,
  `bounded_tests`): `route_socket(AF_INET)` — `O_NONBLOCK` есть, `FD_CLOEXEC` нет. AF_PACKET (нужны привилегии):
  `#[ignore] lab_packet_sockets_are_nonblocking_and_cloexec` в `tests/linux_io.rs` — множество `/proc/self/fd` до и
  после `open_explicit`, у каждого нового сокета в `/proc/self/fdinfo/<fd>` есть `O_NONBLOCK` и `O_CLOEXEC`; идёт только
  в дымовом прогоне (`--test-threads=1`).
- [ ] **Step 3: точные тексты.** `error_texts_are_byte_identical` в каждом адаптере сравнивает `to_string()` каждого
  `NetError` и `IoError::message`, который фейк умеет вызвать, с литералом; часть errno ожидание строит тем же
  `std::io::Error::from_raw_os_error(e)`. Linux (`linux/tests.rs`): тексты `verify_binding` (тип канала, имя, «no such
  interface», «disappeared», `if_nametoindex`/`SIOCGIFHWADDR`), виды `map_open_error`, `send: …`,
  `poll(POLLOUT): socket error`, `poll(POLLOUT): …`, `recvfrom: …`, `poll(POLLIN): …`,
  `getsockopt(PACKET_STATISTICS): …`, закрытый адаптер. macOS: три текста `check_binding`, подсказка гранта,
  `no free /dev/bpf* device (N busy)`, `open /dev/bpfN: …`, два текста `check_dlt`, малый буфер, длина TX,
  `write: … ; nothing was sent` (EMSGSIZE), все тексты разбора записи, `read returned …`, тексты `poll`,
  `ioctl(BIOCGSTATS): …`. Windows: `check_binding`, длина TX, три текста `send_batch`, `pcap_next_ex failed (code N): …`,
  EOF, `pcap_stats failed (code N): …`, и `pcap_setnonblock did not take effect on the RX handle` при
  `getnonblock_override` −1 и 0. Наблюдение Linux (`route_observation_tests.rs`, через фейк `DatagramIo`):
  `netlink observation: short send`, `netlink observation: malformed empty or truncated datagram`,
  `netlink observation: interrupted dump`, `netlink observation reply limit exceeded`,
  `netlink observation retry limit exceeded`, `network preparation cancelled`, `network observation deadline expired`,
  `sendto(NETLINK_ROUTE observation): …`, `recvfrom(NETLINK_ROUTE observation): …`, `poll(NETLINK_ROUTE write|read): …`.
- [ ] **Step 4: конкурентный тест.** `stats_snapshot_is_monotonic_and_exact_under_concurrent_tx_and_rx` (по одному на
  адаптер, на фейке своего шва): поток TX делает 20 000 `send` кадра 60 байт, поток RX — `recv`, пока не выдано
  20 000 кадров, третий поток снимает `snapshot()`, пока оба не кончили. Утверждения: каждое поле каждого снимка не
  меньше, чем в предыдущем; в итоге `tx_sent == 20_000`, `rx_packets == 20_000`, прочие счётчики 0.
- [ ] **Step 5: микробенч.** `#[ignore] adapter_hot_path_two_threads` в тех же трёх модулях: свой фейк без замков
  (`send`/`write` → `Ok(len)`, приём копирует заготовленный кадр), потоки TX и RX стартуют через `Barrier`, по
  1 000 000 вызовов, печать `ns/frame` каждого потока. Запуск: `cargo test --locked --release -p rmasscan-net
  adapter_hot_path -- --ignored --nocapture` на Mac (macOS и Windows) и на хосте (Linux); числа — в заметки.
- [ ] **Step 6: harness.** Тест `wire_scan` `success_json_reports_engine_thread_cpu` (ключи `tx_cpu_ns`, `rx_cpu_ns` в
  `workers`, значение — число или `null`); FAIL → реализация → PASS.
- [ ] **Step 7: PASS.** `M-gate`, `L-gate`, `W-gate` зелёные (страховка проходит на неизменённом продукте);
  `unsafe_count` = 199 записан.
- [ ] **Step 8: стенд.** Скрипт стенда S и ячейки U написан; дымовой прогон (все `lab_*` ok, включая флаги AF_PACKET);
  первая сессия калибровки «база против базы» для `U-TX` и `U-RX` (с выбором `R_RX`). В `BENCHMARKS.md` новый раздел
  «rmasscan-net: нативный Rust, фаза 1 (Linux-стенд)»: полный текст скрипта, протокол сессии, правила годности и
  ворот, `T` первой калибровки, таблица «задача | коммит | ячейка | метрика | `T` | база (медиана, мин–макс) | новая |
  вердикт».
- [ ] **Step 9: коммит** путей из Files: `test(rmasscan-net): safety net for the native-Rust refactor`.

### Задача 2: счётчики TX и RX на разных строках кэша, один писатель — по построению

Проверяет: Mac, `L-gate`, `W-gate`; стенд: сессия `U-TX` и `U-RX` (ворота «без регрессии»), матрица. Выигрыш
`store(load + n)` и разнесения строк — наносекунды на кадр рядом с системным вызовом в сотни наносекунд: на стенде он
ниже шума, единственное его свидетельство — микробенч задачи 1. «Без регрессии» на стенде не читается как
подтверждение ускорения.

**Files:**
- Create: `src/counters.rs`
- Modify: `src/lib.rs` (`NetStatsHandle` берёт снимок у `counters`), `src/linux/mod.rs`, `src/macos/adapter.rs`,
  `src/windows/adapter.rs`, `src/linux/tests.rs` (помощник `counters()`), `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces (`counters`, `pub(crate)`, если не сказано иначе):
  - Приватно в модуле: `struct Counter(AtomicU64)` с записью `store(load.wrapping_add(n), Relaxed)` (`max` —
    `store(load.max(n))`); `#[repr(align(128))] struct TxCounters { sent, would_block, uncertain, errors, batches,
    batch_max, over_budget: Counter }`; `#[repr(align(128))] struct RxCounters { packets, truncated, outgoing,
    wrong_interface, errors, kernel_drops: Counter, kernel_drops_known: AtomicBool }`; `struct Counters { tx, rx }`.
  - `fn counters() -> (TxSide, RxSide, Arc<Counters>)` — единственный конструктор сторон; `Arc<Counters>` уходит в
    `NetStatsHandle::new`, а у `Counters` снаружи только `fn snapshot(&self) -> NetStats`.
  - `struct TxSide(Arc<Counters>)` и `struct RxSide(Arc<Counters>)` — не `Clone`; все методы записи берут `&mut self`
    и трогают только свой блок. `TxSide`: `sent(&mut self, n: u64)`, `would_block(&mut self)`,
    `uncertain(&mut self, n: u64)`, `error(&mut self)`, `batch(&mut self, n: u64)` (`batches + 1`, `batch_max` — max),
    `over_budget(&mut self)`, `record(&mut self, s: SendStatus)`. `RxSide`: `packet`, `truncated`, `outgoing`,
    `wrong_interface`, `error` (`&mut self`), `add_kernel_drops(&mut self, delta: u64) -> u64` (Linux, итог),
    `publish_drops(&mut self, total: u64)` (macOS, Windows: `kernel_drops` Relaxed, затем `kernel_drops_known` Release).
  - Половины адаптеров хранят `TxSide`/`RxSide` вместо `Arc<Counters>`; второй писатель не компилируется: методы
    записи `Counter` не видны вне модуля, сторона одна и не клонируется.

- [ ] **Step 1: тест** `counter_blocks_live_on_separate_cache_lines`: `align_of::<TxCounters>() == 128`,
  `align_of::<RxCounters>() == 128`, `offset_of!(Counters, rx).abs_diff(offset_of!(Counters, tx)) >= 128` (порядок
  полей `repr(Rust)` не задан). FAIL (модуля нет).
- [ ] **Step 2: реализация** по Interfaces; три адаптера пишут через свою сторону; Linux копит `kernel_drops` через
  `add_kernel_drops`; Windows `tx_batch_max` — `batch(n)`.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`, `W-gate`; тексты и конкурентные тесты задачи 1 зелёные.
- [ ] **Step 4: замер.** Микробенч задачи 1 до/после (Mac, хост) — строка Mac «ранжирование, не ворота»; стенд —
  сессия по протоколу (`U-TX`: pps и CPU TX на кадр; `U-RX`: CPU RX на кадр при `R_RX`), матрица; строка в
  `BENCHMARKS.md`.
- [ ] **Step 5: коммит**: `perf(rmasscan-net): TX and RX counters on separate cache lines, one writer by construction`.

### Задача 3: переносимый разбор netlink без двойников

Проверяет: Mac (весь модуль переносим, 2700 строк тестов разбора идут на любой ОС); `L-gate` (потребитель
`linux/route.rs`).

**Files:**
- Modify: `src/route_parse.rs` (`mod netlink`), `src/route_parse_tests.rs`, `src/route_parse6_tests.rs`,
  `src/linux/route.rs` (только если меняются имена типов)

**Interfaces:**
- Produces (`route_parse::netlink`, `pub(crate)`):
  - `fn nl_message(ty: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8>` — заголовок 16 байт (`nlmsg_pid` 0) и
    полезная нагрузка; через него `netlink_route_request`, `netlink_route_request6`, `netlink_addr_request6`.
  - `fn route_request(family: u8, seq: u32, dst: Option<&[u8]>) -> Vec<u8>` — общий `RTM_GETROUTE` (`dst_len` =
    8 × длина адреса).
  - `fn for_each_payload(buf: &[u8], want: u16, f: impl FnMut(&[u8]) -> Result<(), NlError>) -> Result<(), NlError>` —
    `NLMSG_DONE` останавливает, `NLMSG_ERROR` с кодом ≠ 0 даёт `Kernel(-code)`, ACK пропускается; тело сообщения
    разбирается до перехода к следующему (порядок решает, какая из двух ошибок побеждает).
  - `struct NlAttrs<'a>`: `Iterator<Item = Result<(u16, &'a [u8]), NlError>>`, тексты `truncated rtattr` и
    `rta_len out of bounds`, тип без флагов NLA.
  - Маршрут одного вида на оба семейства: `trait RouteFamily { const AF: u8; type Addr: Copy;
    fn addr_at(p: &[u8]) -> Option<Self::Addr>; const PREFSRC: bool; }`, маркеры `V4`/`V6`,
    `struct NlRouteOf<F: RouteFamily>`; `NlRoute`/`NlRoute6` — псевдонимы; `netlink_defaults`/`6` — одна обобщённая
    функция; `route_from_nl`/`route6_from_nl` остаются двумя тонкими обёртками (разные `Route`/`RouteV6`).
  - Новые типы `RouteKind(u8)` (константы `RTN_*`) и `IfaFlags(u32)` (константы `IFA_F_*`, `contains`).

- [ ] **Step 1: тесты до правки.** `netlink_requests_are_byte_identical_to_base`: hex всех построителей запросов (оба
  семейства, lookup и dump, `seq` 7 и `u32::MAX`), снятый на базе до правки. `netlink_first_error_wins_as_on_base`:
  IPv4 с коротким значением атрибута перед неверным `rta_len` даёт `short route attribute` (IPv4 проверяет по ходу),
  тот же ввод IPv6 даёт `rta_len out of bounds` (IPv6 сначала проверяет все атрибуты); искажённое тело перед
  `NLMSG_ERROR` даёт `Malformed`, `NLMSG_ERROR` перед искажённым телом — `Kernel`. PASS на базе.
- [ ] **Step 2: реализация** по Interfaces. IPv4 потребляет `NlAttrs` по ходу, IPv6 и адреса IPv6 сначала
  `collect::<Result<Vec<_>, _>>()` — так сохраняется порядок ошибок каждого. IPv4 по-прежнему не читает `RTA_PREFSRC`
  (`V4::PREFSRC = false`).
- [ ] **Step 3: PASS** весь `route_parse*` на Mac, `M-gate`, `L-gate`.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): one netlink request and reply walker for both families`.

### Задача 4: переносимый разбор route socket Darwin и IP Helper

Проверяет: Mac; `W-gate` (потребитель `windows::os`).

**Files:**
- Modify: `src/route_parse.rs` (`mod rtsock`, `mod iphlp`), `src/route_parse_tests.rs`, `src/route_parse6_tests.rs`,
  `src/macos/route.rs`, `src/windows/mod.rs` (только если меняются имена)

**Interfaces:**
- Produces:
  - Darwin: `fn rt_request(seq: i32, pid: i32, dst: &[u8]) -> Vec<u8>` — общий `RTM_GET` для `rt_get_request`/`6`;
    `fn rt_route_parts(r: &RtReply) -> Option<RtParts>` (ifindex, имя, `local`, шлюз-байты) и тонкие
    `route_from_rt`/`route6_from_rt`, `lookup_from_rt`/`6`, `defaults_from_rt`/`6` поверх него; `RtFlags(i32)` с
    константами `RTF_*` и `contains`.
  - IP Helper: `trait FwdRow { fn ifindex(&self) -> u32; fn metric(&self) -> u32; fn prefix_len(&self) -> u8;
    fn mib_loopback(&self) -> bool; fn set_loopback_if(&mut self, on: bool); }` для `Fwd`/`Fwd6`; одна обобщённая
    `mark_loopback`, одна сортировка маршрутов по умолчанию; имя интерфейса по ifindex ищется прямо в `&[WinAdapter]`,
    без сборки `Vec<Iface>` всех адаптеров; `DadState(i32)` с константами `WIN_DAD_*`.

- [ ] **Step 1: тесты до правки** `rt_requests_are_byte_identical_to_base` (hex на базе, оба семейства, `seq`/`pid`
  0 и `i32::MAX`) и `win_name_lookup_matches_iface_list` (имя по ifindex из `&[WinAdapter]` совпадает со старым
  результатом на тех же данных, в том числе для отсутствующего индекса). PASS на базе.
- [ ] **Step 2: реализация** по Interfaces; тексты и порядок результатов прежние.
- [ ] **Step 3: PASS** `M-gate`, `W-gate`.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): shared Darwin and IP Helper route decoding`.

### Задача 5: курсор записей BPF и мелкие идиомы переносимого кода

Проверяет: Mac; `L-gate` и `W-gate` (переносимые `discover` и `neighbours` собираются там же).

**Files:**
- Modify: `src/macos/adapter.rs`, `src/macos/tests/adapter_tests.rs`, `src/discover.rs`, `src/neighbours.rs`,
  `src/macos/ifinfo.rs`

**Interfaces:**
- Produces (`macos::adapter`, `pub(crate)`): `enum Record<'a> { Frame(&'a [u8]), Truncated }`;
  `struct RecordCursor { off: usize, end: usize }` с `new(end: usize)`, `is_empty(&self) -> bool`,
  `next<'b>(&mut self, buf: &'b [u8]) -> Option<Result<Record<'b>, &'static str>>`. После `Err` курсор пуст
  (`off = end`): остаток буфера недостоверен. Шаг, тексты ошибок и правило «последней записи можно без выравнивания»
  прежние. `parse_record` удаляется.
- `discover`: одна константа `pub(crate) const DARWIN_MASKED_MAC: [u8; 6]` вместо `DARWIN_PLACEHOLDER_MAC` и
  `ifinfo::MASKED_MAC`.

- [ ] **Step 1: тесты** `parse_record_*` и `rx_record_walk_*` переписаны на `RecordCursor` с теми же ожидаемыми
  значениями; новый `cursor_is_empty_after_a_malformed_record`. FAIL (курсора нет).
- [ ] **Step 2: реализация** курсора; `RxHalf` хранит `rbuf` и `RecordCursor`.
- [ ] **Step 3: идиомы.** `iflist_text` пишет через `write!`/`writeln!` в `String` (точный текст охраняет
  `iflist_text_marks_masked_macs_and_lists_ipv4s_and_defaults`); в `neighbours` числа микросекунд — именованные
  константы рядом с `NEIGHBOUR_BUDGET` (`35_000_000` выводится из него); `ifinfo::merge` берёт `&[RawAddr]`,
  `observations` больше не клонирует вектор.
- [ ] **Step 4: PASS** `M-gate`, `L-gate`, `W-gate`.
- [ ] **Step 5: коммит**: `refactor(rmasscan-net): BPF record cursor and small portable idioms`.

### Задача 6: общие примитивы Unix

Проверяет: Mac (части macOS, `interrupt`, `lab_io` с `--features lab`), `L-gate` (части Linux), дымовой прогон
адаптера на стенде S.

**Files:**
- Create: `src/unix_sys.rs` (`#[cfg(unix)] #[allow(unsafe_code)] mod unix_sys;` в `lib.rs`), `src/unix_sys_tests.rs`
  (`#[cfg(test)] #[path]`-модуль `unix_sys`; вне `unsafe_count`)
- Modify: `src/lib.rs`, `src/linux/socket.rs`, `src/linux/route.rs`, `src/linux/route_observation.rs`,
  `src/linux/mod.rs`, `src/linux/tests.rs`, `src/macos/route.rs`, `src/macos/sys.rs`, `src/macos/ifinfo.rs`,
  `src/interrupt.rs`, `src/lab_io.rs`, `Cargo.toml` (комментарий со списком модулей с `unsafe`)

**Interfaces:**
- Produces (`unix_sys`, `pub(crate)`; узкие блоки: `socket` — два, вызов и `OwnedFd::from_raw_fd`;
  `install_handler` — три; остальные по одному):
  - `fn last_errno() -> i32` (`EIO`, если ОС не дала номера);
  - `fn socket(domain: c_int, ty: c_int, proto: c_int) -> Result<OwnedFd, i32>` — флаги передаются как есть;
  - `fn poll_one(fd: BorrowedFd<'_>, events: c_short, timeout_ms: c_int) -> Result<(c_int, c_short), i32>` —
    `(n, revents)`, толкование у вызывающего;
  - `fn setsockopt_int(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: c_int) -> Result<(), i32>`;
  - `fn install_handler(sig: c_int, handler: extern "C" fn(c_int)) -> Result<(), i32>` — `SA_RESTART`, пустая маска;
    обнуление, `sigemptyset`, `sigaction` — отдельные блоки;
  - Linux: `fn nl_kernel_addr() -> libc::sockaddr_nl` (ядро: `nl_pid` 0) и `fn mac_from_c_chars(src: &[c_char]) ->
    [u8; 6]`.
- Внутренний шов Linux: `IfaceInfo::hw_addr` → `fn link_family(&self, name: &str) -> Result<u16, Errno>` (MAC никто не
  читал); поле `KernelStats.packets` удаляется.

- [ ] **Step 1: тесты примитивов** (`unix_sys_tests.rs`, флаги — `fd_flags` задачи 1): `socket_passes_flags_through`
  (Linux: с `SOCK_CLOEXEC | SOCK_NONBLOCK` у fd есть оба; без флагов — ни одного; macOS: `PF_ROUTE` без флага —
  нет `FD_CLOEXEC`), `socket_error_is_errno` (неверный домен → `Err(EAFNOSUPPORT)`; fd не возвращается, подсчёта
  fd процесса нет), `poll_one_times_out_on_an_idle_udp_socket` (`(0, 0)` за 0 мс),
  `poll_one_reports_pollout_on_a_fresh_udp_socket`, `setsockopt_int_reports_enoprotoopt`,
  Linux `nl_kernel_addr_is_the_kernel`, `mac_from_c_chars_copies_six_bytes`. FAIL (модуля нет).
- [ ] **Step 2: реализация** `unix_sys`; затем по одному модулю перевод вызовов: сокеты и `OwnedFd`, одиночный `poll`,
  `last_errno`, `sockaddr_nl`, два `sigaction` (`interrupt`, `lab_io`; `lab_io` строит `io::Error` из errno, текст
  `sigaction(SIGINT): …` прежний). В `linux/socket.rs`: `sockaddr_ll` литералом структуры (все поля публичны, два
  блока `zeroed` уходят), `SLL_MIN_LEN = offset_of!(libc::sockaddr_ll, sll_addr)`, `libc::PACKET_IGNORE_OUTGOING`
  вместо своей `23`, копии MAC через `mac_from_c_chars`; `PACKET_IGNORE_OUTGOING` идёт через `setsockopt_int`,
  результат по-прежнему игнорируется. Флаги каждого места вызова прежние: AF_PACKET `SOCK_NONBLOCK | SOCK_CLOEXEC`,
  блокирующий netlink и сокет ioctl — только `SOCK_CLOEXEC`, netlink наблюдения — оба; их держат тесты флагов задачи 1.
- [ ] **Step 3: ловушки (не менять).** Сокет `PF_ROUTE` macOS открывается без `CLOEXEC`, а `O_NONBLOCK` ставится
  `fcntl` после; `ready()` macOS и наблюдение Linux округляют остаток вниз до мс (последняя миллисекунда — неблокирующий
  `poll`), TX/RX Linux — вверх (`div_ceil`), macOS-адаптер — вверх по наносекундам: округление остаётся у вызывающих.
  `retry_until` Linux (не больше 4096 попыток; `network preparation cancelled`, `network observation deadline
  expired`, `netlink observation retry limit exceeded`) и macOS (без предела; `network observation cancelled`,
  `route observation deadline expired`) не объединяются. Обработка EINTR у каждого места своя.
- [ ] **Step 4: PASS** `M-gate`, `L-gate`; `unsafe_count` меньше, чем после задачи 5 (ожидается около −17: около −25 в
  местах вызова, +8 в `unix_sys`).
- [ ] **Step 5: дымовой прогон** адаптера на стенде S: все `lab_*` из `tests/linux_io.rs` ok.
- [ ] **Step 6: коммит**: `refactor(rmasscan-net): one audited set of Unix syscall primitives`.

### Задача 7: FFI macOS через std, безопасный разбор `sockaddr`, удаление спайка

Проверяет: Mac (живой `macos_live` — только в окне гранта BPF, по желанию пользователя; иначе NOT RUN).

**Files:**
- Modify: `src/macos/sys.rs`, `src/macos/ifinfo.rs`, `src/macos/mod.rs`, `src/lib.rs` (строки документации 13 и 43),
  `src/macos/tests/iface_tests.rs`, `rmasscan/docs/macos-feth-lab.md` (строка 72: «scans and spike» → «scans»)
- Delete: `src/macos/spike.rs` (отчёт спайка в `docs/experiments/` остаётся)

**Interfaces:**
- `macos::sys::BpfFd { file: std::fs::File, buflen: usize }`: `open_node(index)` —
  `OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK).open(format!("/dev/bpf{index}"))` (std
  добавляет `O_CLOEXEC`; флаги те же), errno — `e.raw_os_error().unwrap_or(libc::EIO)`; `write`/`read` через
  `Write::write`/`Read::read` (один системный вызов, без повтора EINTR, как сейчас); ioctl через `file.as_raw_fd()`;
  `poll_in` через `unix_sys::poll_one`.
- `macos::ifinfo`: `IfAddrs::entries(&self) -> Vec<Entry<'_>>`, `Entry { name: &CStr, flags: u32, addr: Option<&[u8]>,
  netmask: Option<&[u8]> }`. Адрес читается как `max(sa_len, 2)` байт (семейство — байт 1, как сейчас читается
  `sa_family` при любом `sa_len`), разбор семейства — по первым `sa_len` байтам. Маска читается как **ровно `sa_len`**
  байт, пустой срез допустим: маска 0.0.0.0 у Darwin приходит с `sa_len` 0 и сегодня даёт `prefix: None`, так и
  остаётся. Чистая `fn addr_kind(addr: Option<&[u8]>, netmask: Option<&[u8]>) -> AddrKind` разбирает три семейства без
  предположений о выравнивании.

- [ ] **Step 1: тесты до правки** (записывают нынешний декодер маски, PASS на базе):
  `netmask_records_decode_as_on_base` — `prefix_from_sockaddr` на записях маски длиной 0 и 1 байт → `None`; 5, 6, 7 и
  8 байт (`[len, 2, 0, 0, 255, …]`) → /8, /16, /24, /32; запись с разрывом единиц → `None`.
- [ ] **Step 2: тесты новой формы** `open_node_of_a_missing_index_is_enoent` (`BpfFd::open_node(100_000)` →
  `Err(ENOENT)`, без привилегий); `addr_kind_*`: AF_INET ровно 16 байт → `V4` с адресом и префиксом из маски; AF_INET
  с `sa_len` ровно 8 (нынешняя граница `SIN_MIN`) → `V4`, с 7 → `Other`; маска `sa_len` 0, 1 и короткая (5–7) → те же
  префиксы, что в шаге 1 (`None` при 0 и 1); AF_INET6 28 байт → `V6` без KAME-зоны; AF_LINK → `Link`; адрес `sa_len`
  0 и 1 → `Other`; та же запись с невыровненного смещения 1 в `Vec<u8>` даёт тот же результат. FAIL.
- [ ] **Step 3: реализация** по Interfaces. Ловушка: текст ошибки строится только `errno_msg(op, errno)`, а не
  `Display` у `io::Error` из std; разница std — повтор EINTR внутри `open` (`cvt_r`), для узла `/dev/bpfN` не наблюдаемо,
  записать в заметки.
- [ ] **Step 4: PASS** `M-gate`; `unsafe_count` меньше, чем после задачи 6 (−4 в `sys`, −4 в `ifinfo`).
- [ ] **Step 5: коммит** правок `sys` и `ifinfo`: `refactor(rmasscan-net): std file I/O for BPF and safe sockaddr
  decoding`.
- [ ] **Step 6: спайк** — отдельный коммит: удалить `spike.rs` и `mod spike` в `macos/mod.rs`, упоминания в
  документации модулей, строку `macos-feth-lab.md:72`. Число тестов падает на 2 обычных и 9 `#[ignore]`. `M-gate`;
  коммит (`git rm` и явные пути): `chore(rmasscan-net): drop the closed BPF spike`.

### Задача 8: macOS RX — дедлайн по первой нужде

Проверяет: Mac (фейк, микробенч). Утверждения о скорости только для ранжирования: живой стенд macOS требует окна
гранта и в ворота не входит.

**Files:**
- Modify: `src/macos/adapter.rs`, `src/macos/tests/adapter_tests.rs`, `src/lib.rs` (контракт времени :19-29: у
  `recv` на macOS отсчёт идёт с первой нужды), `rmasscan/BENCHMARKS.md` (строка Mac)

**Interfaces:**
- `struct LazyDeadline { timeout: Duration, at: Option<Deadline> }`, `fn get(&mut self) -> &Deadline` (первый вызов
  читает часы). `recv` не читает часы, если отдаёт кадр из уже прочитанного буфера, не отбросив ни одной записи;
  дедлайн создаётся на первой отброшенной записи, первом `read` или первом `poll`. Документация контракта: отсчёт
  начинается с первой нужды, сдвиг не больше времени разбора записей буфера перед ней (микросекунды против запаса
  17 мс до 50 мс). Ленивый дедлайн только в RX macOS: TX (`write` может блокировать) и Linux не меняются.
- Шов теста: `#[cfg(test)] thread_local!` счётчик вызовов `Deadline::new`.

- [ ] **Step 1: тесты** `buffered_frame_is_returned_without_reading_the_clock` (одно чтение даёт три записи: первый
  `recv` читает часы, второй и третий — нет) и `dropped_record_starts_the_deadline_once` (записи со своим MAC, затем
  кадр: в этом вызове ровно одно чтение часов). FAIL.
- [ ] **Step 2: реализация** и строка контракта в `lib.rs`; существующие `rx_empty_poll_times_out_within_the_deadline`,
  `rx_garbage_stream_cannot_extend_the_deadline`, `rx_eintr_backs_off_bounded_and_keeps_deadline` зелёные (новые
  утверждения о времени — только верхние границы).
- [ ] **Step 3: PASS** `M-gate`; микробенч задачи 1 до/после → строка Mac в `BENCHMARKS.md` («ранжирование»).
- [ ] **Step 4: коммит**: `perf(rmasscan-net): macOS RX reads the clock only when it needs a deadline`.

### Задача 9: общие помощники трёх адаптеров

Проверяет: Mac (адаптеры macOS и Windows на фейках), `L-gate`, `W-gate`.

**Files:**
- Create: `src/adapter_common.rs` (`#[cfg(any(target_os = "linux", target_os = "macos", windows, test))]`, без `unsafe`)
- Modify: `src/lib.rs`, `src/linux/mod.rs`, `src/macos/adapter.rs`, `src/macos/ifinfo.rs`, `src/macos/mod.rs`,
  `src/windows/adapter.rs`

**Interfaces:**
- Produces (`adapter_common`, `pub(crate)`): `type Errno = i32`; `enum Readiness { Timeout, Ready, Failed }`;
  `fn closed_error() -> IoError`; `fn errno_msg(op: &str, e: Errno) -> String`; `fn mac_text(mac: &[u8; 6]) -> String`;
  `fn check_binding(binding: &AdapterBinding, adapter: &str) -> Result<(), NetError>` (`adapter` — «macOS BPF adapter»,
  «Windows Npcap adapter»; три текста прежние); `fn valid_ifname(name: &str) -> bool` и `const IFNAMSIZ: usize = 16`;
  `fn map_setup_errno(op: &str, e: Errno) -> NetError` (EPERM/EACCES → `PermissionDenied`, ENXIO/ENODEV →
  `InterfaceMismatch`, иначе `System`) с константами `errno::{EPERM = 1, EACCES = 13, ENXIO = 6, ENODEV = 19}` —
  одинаковы на Linux и macOS; тест сверяет их с `libc` (Unix) и `macos::abi::errno`.
- Не объединяются: `Deadline` (Linux округляет микросекунды вверх, macOS — наносекунды, бюджеты 50/33/42 мс), `is_again`
  (EAGAIN 11 на Linux, 35 на macOS), правило коротких кадров (Windows отдаёт кадр короче 14 байт, macOS считает его
  `rx_truncated`, Linux отдаёт любой). Копия `mac_text` в `examples/support` остаётся (пример видит только `pub`).

- [ ] **Step 1: тесты** `adapter_common_errnos_match_every_os` и `check_binding_texts_name_the_adapter`. FAIL.
- [ ] **Step 2: реализация** и перевод трёх адаптеров и `ifinfo::verify_binding`.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`, `W-gate`; `error_texts_are_byte_identical` ×3 зелёные.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): shared adapter helpers, one text per error`.

### Задача 10: касты `as` — по бэкенду

Проверяет: шаг 1 — Mac; шаг 2 — `L-gate`; шаг 3 — `W-gate`; шаг 4 — все три.

**Files:**
- Modify: продуктовые файлы с `as` (около 124 мест; больше всего `windows/sys.rs`, `windows/handle.rs`,
  `linux/route_observation.rs`, `linux/socket.rs`, `linux/route.rs`, `route_parse.rs`, `windows/sys/observation.rs`,
  `windows/process.rs`), `src/unix_sys.rs`, `src/lib.rs`

**Interfaces:**
- Produces: `unix_sys::socklen_of::<T>() -> libc::socklen_t` (`const fn`, `const`-проверка размера; единственный
  `as` с `#[allow(…, reason = …)]`).
- Правило замены: значение то же на всём диапазоне входа. Переинтерпретация знака — `cast_signed()`/`cast_unsigned()`;
  расширение — `From`; сужение — `try_from` только там, где диапазон доказан (`min` перед ним или `const`-проверка), с
  тем же результатом (`i32::try_from(ms.min(50)).unwrap_or(i32::MAX)`); в `const` — `as` с `const`-проверкой рядом и
  `#[allow(clippy::cast_possible_truncation, reason = "…")]`. Два стиля одного перевода (`arp_resolve.rs:191`,
  `ndp_resolve.rs:184`) сводятся к одному.

- [ ] **Step 1:** переносимый код и macOS; `M-gate`; коммит `refactor(rmasscan-net): explicit casts in portable and
  macOS code`.
- [ ] **Step 2:** Linux; `L-gate`; коммит `refactor(rmasscan-net): explicit casts in the Linux backend`.
- [ ] **Step 3:** Windows; `W-gate`; коммит `refactor(rmasscan-net): explicit casts in the Windows backend`.
- [ ] **Step 4:** в `lib.rs` `#![cfg_attr(not(test), deny(clippy::cast_possible_truncation, clippy::cast_possible_wrap))]`
  (тесты свободны); clippy на трёх ОС чистый (`M-gate`, `L-gate`, `W-gate`); коммит `chore(rmasscan-net): deny lossy
  casts in product code`.

### Задача 11: один разбор netlink

Проверяет: Mac (перенесённые тесты разбора наблюдения идут на любой ОС), `L-gate`.

**Files:**
- Modify: `src/route_parse.rs` (`netlink`), `src/route_parse_tests.rs` (сюда переезжают тесты разбора наблюдения),
  `src/linux/route_observation.rs`, `src/linux/route_observation_tests.rs`, `src/linux/route.rs`,
  `src/linux/route_tests.rs`, `src/linux/layout_tests.rs`

**Interfaces:**
- Consumes: `nl_message` (задача 3), `unix_sys::{socket, poll_one, nl_kernel_addr}` (задача 6).
- Produces (`route_parse::netlink`, переносимо): `fn observation_dump_request(kind: u16, seq: u32) -> Vec<u8>`,
  `fn observation_messages(bytes: &[u8], seq: u32) -> Result<Vec<&[u8]>, NetError>`,
  `fn observations(links: &[u8], link_seq: u32, addrs: &[u8], addr_seq: u32) -> Result<Vec<InterfaceObservation>,
  NetError>`; константы `RTM_NEWLINK`, `RTM_GETLINK`, `NLM_F_DUMP_INTR`, `ARPHRD_ETHER: u16 = 1`, `IFF_UP: u32 = 1`,
  `AF_UNSPEC: u8 = 0` (сверка с `libc` в `linux/layout_tests.rs`). Чтения полей — `bytes::*` с теми же текстами
  `netlink observation: malformed u16`/`u32` вместо `.unwrap()`.
- Сокет: `linux::route::NlSocket(OwnedFd)`, `open(label: &str, nonblocking: bool)` (тексты `socket(NETLINK_ROUTE)` и
  `socket(NETLINK_ROUTE observation)`; блокирующий ставит `SO_RCVTIMEO` 1 с с прежним текстом), `send_to_kernel(&self,
  req) -> Result<usize, Errno>`, `recv_from(&self, buf) -> Result<(usize, libc::sockaddr_nl, libc::socklen_t), Errno>`.
  Старая (блокирующая) политика обмена получает шов, как у наблюдения `DatagramIo`: `trait BlockingNl { fn send(&mut
  self, req: &[u8]) -> Result<usize, Errno>; fn recv(&mut self, buf: &mut [u8]) -> Result<(usize, u32), Errno>; }`
  (`u32` — `nl_pid` отправителя). Каждая политика оставляет свой предикат отправителя (старая: только `nl_pid == 0`;
  наблюдение: длина адреса, `AF_NETLINK` и `nl_pid == 0`), свой повтор EINTR и свои тексты.
- Решение: обходчики сообщений и атрибутов наблюдения не сливаются с `NlAttrs` задачи 3 — у них другие тексты ошибок;
  общими становятся модуль, константы и чтения полей. `retry_until` и `exchange_until` остаются в `linux::route`
  (политика, не разбор).

- [ ] **Step 1:** перенести тесты разбора (`network_plan_keeps_all_alias_prefixes_…`, `…prefix_extremes…`,
  `…rejects_truncated_link_and_address_attributes`, `…kernel_*_route_kinds…`) в `route_parse_tests.rs`; там они
  FAIL (функций в `route_parse` нет). Добавить `legacy_netlink_texts_are_byte_identical` (через `BlockingNl`, литералы
  с базы `linux/route.rs:86-173`): `netlink: short send`, `netlink: no reply within 1 s` (EAGAIN по `SO_RCVTIMEO`),
  `netlink: reply of N bytes truncated`, `netlink: dump did not end within 4096 datagrams`,
  `sendto(NETLINK_ROUTE): …`, `recvfrom(NETLINK_ROUTE): …`; чужой отправитель пропускается, EINTR повторяется.
- [ ] **Step 2: реализация** переноса, `NlSocket` и `BlockingNl`; тесты флагов задачи 1 переходят на `NlSocket::open`
  с теми же утверждениями. Ловушка: `sys("netlink dump", e)` печатает errno таблицей хоста — перенесённые тесты на Mac
  сверяют подстроку операции и вид ошибки, не текст ОС.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`; `unsafe_count` не больше, чем после задачи 10.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): one netlink decoder and one netlink socket`.

### Задача 12: переносимый адаптер Linux

Проверяет: Mac и `W-gate` (тесты `linux/tests.rs` теперь идут там), `L-gate`.

**Files:**
- Create: `src/linux/abi.rs` (номера errno Linux, `ARPHRD_ETHER`, `PACKET_OUTGOING`, без `libc`)
- Modify: `src/lib.rs` (`#[cfg(any(target_os = "linux", test))] mod linux;`), `src/linux/mod.rs` (`socket`, `route` и
  `open` — `#[cfg(target_os = "linux")]`; `layout_tests` остаётся `#[cfg(all(test, target_os = "linux"))]`),
  `src/linux/tests.rs`, `src/linux/layout_tests.rs`

**Interfaces:**
- Produces: `linux::abi::errno` — реэкспорт общих `adapter_common::errno::{EPERM, EACCES, ENXIO, ENODEV}` (задача 9)
  плюс `EINTR = 4, EIO = 5, EBADF = 9, EAGAIN = 11, EWOULDBLOCK = 11, EPROTO = 71, ENOPROTOOPT = 92, ENETDOWN = 100,
  ENOBUFS = 105`; `ARPHRD_ETHER: u16 = 1`, `PACKET_OUTGOING: u8 = 4`; `linux/layout_tests.rs` сверяет всё с `libc` на
  Linux (образец — `macos::abi`). `TxHalf`, `RxHalf`, `verify_binding`, шов `PacketIo` и `IfaceInfo` собираются на
  любой ОС в тестах.

- [ ] **Step 1:** `linux/tests.rs` переходит на `abi::errno::*` вместо `libc::*`; на Mac FAIL (модуль не собирается).
- [ ] **Step 2: реализация.** Ловушки: на Mac и Windows `errno_msg` печатает номер Linux таблицей хоста — тексты с
  errno сверяются только под `#[cfg(target_os = "linux")]`, переносимые тесты — по виду (тест `error_texts_…` Linux
  строит ожидание той же функцией хоста и поэтому идёт везде). Существующие нижние границы времени
  (`e >= 19 мс` и подобные, `linux/tests.rs` :189, :405, :432 и рядом) оборачиваются в `#[cfg(target_os = "linux")]`;
  верхние границы идут везде.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`, `W-gate`; число тестов на Mac растёт на тесты Linux-адаптера.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): portable Linux adapter logic, tested on every OS`.

### Задача 13: пакетный приём Linux `recvmmsg`

Проверяет: Mac (фейк), `L-gate`; стенд: сессия `U-RX` (ворота «ускорение» по CPU потока RX на принятый кадр при
`R_RX`) и `U-TX` («без регрессии»), матрица, `--suite rust`, дымовой прогон.

**Files:**
- Modify: `src/linux/mod.rs`, `src/linux/socket.rs`, `src/linux/tests.rs`, `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces: `const RX_BATCH: usize = 32`, `const RX_SLOT: usize = 2048`; `type SlotMeta = Result<RecvMeta, Errno>`
  (`Err(EPROTO)` — адрес короче `SLL_MIN_LEN`); в шове `PacketIo`: `fn recv_batch(&mut self, slots: &mut [[u8;
  RX_SLOT]], metas: &mut [SlotMeta]) -> Result<usize, Errno>` (≥ 1 или `Err`, пусто — `EAGAIN`). `recv` в шве
  остаётся (прямой путь). Число сообщений считает чистая `fn batch_len(slots: usize, metas: usize) -> Result<usize,
  Errno>` = `min(slots, metas, RX_BATCH)`, ноль — `Err(EINVAL)` без системного вызова.
- `PacketFd`: один примитив `recvmmsg` (`MSG_TRUNC`, таймаут NULL) и для `recv_batch`, и для `recv` (один буфер —
  буфер вызывающего, `iov_len` = его длина); `recvfrom` уходит, число блоков `unsafe` не растёт. `iovec`, `msghdr`,
  `mmsghdr`, `sockaddr_ll` — литералы на стеке вызова, их не больше `batch_len`. `SAFETY` опирается на проверенное:
  число сообщений `batch_len`, каждый `iov` — свой слот длиной ровно `RX_SLOT` (или буфер вызывающего), ядро пишет в
  слот не больше `iov_len`. На каждое сообщение: `msg_namelen` выставляется перед вызовом и проверяется после
  (`< SLL_MIN_LEN` → `Err(EPROTO)` в слоте), длина — `msg_len` (истинная при `MSG_TRUNC`, может быть больше
  `RX_SLOT`). Ошибка не-`EAGAIN` после принятого префикса: ядро отдаёт префикс, а ошибку — следующим вызовом; исход тот
  же, что у покадрового пути, на вызов позже (строка в doc-комментарии).
- `RxHalf`: внутреннее кольцо `RX_BATCH × RX_SLOT`. Пока в кольце есть кадры, выдаются они, и только потом — любой
  новый приём; прямой путь (буфер вызывающего длиннее `RX_SLOT`, семантика длинных кадров та же) — только при пустом
  кольце. Фильтры (`PACKET_OUTGOING`, чужой ifindex, длина больше буфера вызывающего — `rx_truncated`), счётчики,
  `since_stats`, проверка дедлайна после отброшенного кадра — по одной записи, в том же порядке. Срез кадра из слота
  берётся только после проверки `len <= buffer.len()` (≤ `RX_SLOT`) и через `get(..len)`. Слот с `Err(EPROTO)` даёт
  фатальную ошибку с прежним текстом `recvfrom: …`, когда до него доходит очередь. Кадры в кольце при закрытии
  теряются (раньше они так же лежали в очереди сокета) — строка в doc-комментарии.
- Фейк: `recv_batch` берёт подряд `Ok`-кадры сценария до первой ошибки или `batch_len`; ошибка в голове очереди —
  `Err`. Существующие сценарии RX работают без правок.

- [ ] **Step 1: тесты** `rx_batch_delivers_buffered_frames_without_a_syscall`,
  `rx_batch_mixed_records_match_the_per_frame_path` (Review Focus 1: в одной пачке исходящий, чужой ifindex, длинный,
  обычный и короткий адрес, затем ошибка не-`EAGAIN` после префикса — порядок выдачи, счётчики и `recvfrom: …` на
  своей позиции равны явным ожиданиям, снятым с того же сценария на базе, где путь покадровый),
  `rx_ring_is_drained_before_the_direct_path`, `rx_caller_buffer_larger_than_a_slot_uses_the_direct_path`,
  `batch_len_never_asks_for_more_slots_than_fit` (ноль слотов или метаданных → `EINVAL`; больше `RX_BATCH` →
  `RX_BATCH`), `rx_batch_partial_fill_then_eagain_waits_until_the_deadline`,
  `health_between_batches_reads_fresh_drops_and_keeps_buffered_frames` (Review Focus 5). FAIL.
- [ ] **Step 2: реализация**; вся группа RX и `kernel_drops_*` зелёные без правки сценариев.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`; `unsafe_count` не больше, чем после задачи 12.
- [ ] **Step 4: стенд** — сессия `U-RX` и `U-TX` по протоколу, матрица, `--suite rust`, дымовой прогон; строка в
  `BENCHMARKS.md`.
- [ ] **Step 5: коммит**: `perf(rmasscan-net): Linux RX drains bursts with one recvmmsg`.

### Задача 14: чистка Windows — таблица маршрутов, телеметрия процесса, мелочи sendqueue

Проверяет: `W-gate` (код только Windows), Mac (переносимые `handle`, `adapter`, `loader` на фейке). Три коммита.

**Files:**
- Modify: `src/windows/sys.rs`, `src/windows/process.rs`, `src/windows/handle.rs`, `src/windows/adapter.rs`,
  `src/windows/loader.rs`, `src/windows/tests.rs`, `src/windows/tests/adapter_tests.rs`

**Interfaces:**
- `sys`: `fn iphlp_error(label: &str, e: u32) -> NetError` — единственное место текста `{label} error {e}`;
  `fn forward_rows<T>(family: ADDRESS_FAMILY, label: &str, decode: fn(&MIB_IPFORWARD_ROW2) -> T) ->
  Result<Vec<T>, NetError>` — один `slice::from_raw_parts(base, NumEntries)` вместо цикла по индексу;
  `fn best_route_raw(to: &SOCKADDR_INET, label: &str) -> Result<Option<(MIB_IPFORWARD_ROW2, SOCKADDR_INET)>, NetError>`;
  метки `GetIpForwardTable2`, `GetIpForwardTable2(AF_INET6)`, `GetBestRoute2`, `GetBestRoute2(AF_INET6)`;
  `fwd_from_row`/`fwd6_from_row` берут `&MIB_IPFORWARD_ROW2` и держат `unsafe` только вокруг чтений объединения;
  `HMODULE` хранится через `expose_provenance`/`ptr::with_exposed_provenance_mut`; `os_version` без лишнего `clone`.
- `process`: снимок Toolhelp и токен — `OwnedHandle` (`HandleOrInvalid` для снимка), без ручного `CloseHandle`; один
  итератор идентификаторов потоков; `thread_count() = thread_ids().map(|v| v.len())` — один снимок, оба `None` на
  пустом.
- `handle`: `SendQueue.records` только под `#[cfg(test)]`; `c_int::from(bool)`; `send_raw -> Result<(), c_int>`,
  `get_nonblock -> Result<bool, c_int>` (`Ok(v == 1)` для неотрицательного, иначе `Err`; адаптер по-прежнему отвечает
  одним текстом на всё, кроме `Ok(true)`); проверка длины одного кадра пачки — один раз (охраняют существующие
  `pre_send_validation_errors_are_io_errors…` и `a_bad_length_anywhere_in_the_batch_sends_nothing…`); `loader::sha256_hex`
  пишет `write!`; устаревшие `cfg_attr(not(test), allow(dead_code))` на трёх аксессорах `NpcapApi` и их комментарий
  удаляются.

- [ ] **Step 1: маршруты.** Тесты (Windows) `iphlp_error_texts_are_byte_identical` (четыре метки, литералы с базы
  `windows/sys.rs`: `GetIpForwardTable2 error 5`, `GetIpForwardTable2(AF_INET6) error 5`, `GetBestRoute2 error 5`,
  `GetBestRoute2(AF_INET6) error 5`) и `forward_rows_decode_a_synthetic_table_for_both_families` (буфер `#[repr(C)]` с
  заголовком и двумя строками каждой семьи); FAIL → реализация → `W-gate`; коммит `refactor(rmasscan-net): one IP
  Helper route table walk`.
- [ ] **Step 2: процесс.** Тесты (Windows, один снимок на утверждение) `thread_ids_contain_the_current_thread` и
  `thread_count_is_at_least_one`; реализация → `W-gate`; коммит `refactor(rmasscan-net): owned handles for Windows
  process probes`.
- [ ] **Step 3: sendqueue и загрузчик** — мелочи `handle`/`adapter`/`loader`; `M-gate` (фейк) и `W-gate`;
  `unsafe_count` меньше, чем после задачи 13; коммит `refactor(rmasscan-net): Windows sendqueue and loader tidy-up`.

### Задача 15: P1 — пакетная отправка Linux `sendmmsg`

Проверяет: Mac (фейк), `L-gate`; стенд: сессия `U-TX` (ворота «ускорение» по pps; CPU потока TX на кадр — «без
регрессии»), C-оракул отдельной серией, матрица 40/40, `--suite rust` (пауза и продолжение: склейка захватов равна
непрерывному), дымовой прогон.

**Влияние на лабораторию (проверено чтением на базе).** Код `rmasscan-lab` правок не требует: Linux-набор
`wire_suite.rs` сверяет `tx_sent == sent`, `tx_uncertain == 0`, `tx_errors == 0` и границы паузы, а не `tx_mode` или
`tx_batches`; правила `verify.rs::sendqueue_identity` действуют только для каталогов Windows с `tx_mode_expected` в
манифесте; `examples/wire_scan.rs` уже режет пачку ровно на `--pause-after` (`HarnessTx::send_batch`) и печатает режим
из `OpenedAdapter.tx_mode`. Фатальная ошибка внутри пачки по-прежнему доходит до движка как `TxError("send: …")`
(правило ниже), поэтому случай `veth_removal` и его требование `TxError` не меняются. Видимые следствия P1:
идентичность Linux-прогонов `wire_scan` — `"tx_mode":"sendqueue","tx_batch_cap":64`, `net.tx_batches`/`tx_batch_max`
ненулевые, пауза и остановка — с точностью до пачки. Studio и CLI `tx_mode` не читают.

**Files:**
- Modify: `src/linux/mod.rs`, `src/linux/socket.rs`, `src/linux/tests.rs`, `src/lib.rs` (доки: `TxMode::SendQueue` —
  «Windows — Npcap sendqueue, Linux — `sendmmsg`»; `tx_batches` — «Linux: вызовы `send_batch` с n ≥ 2, дошедшие до
  ядра (выполнен хотя бы один `sendmmsg`); macOS — 0»; `tx_uncertain` — «при исходе `Uncertain` пачки Windows
  прибавляет все неподтверждённые кадры (`n − sent`), Linux — единицу, как одиночный путь»; `tx_over_budget` на Linux
  не измеряется), `rmasscan/README.md` (раздел «Лабораторная приёмка Linux (2B)»: Linux шлёт пачками до 64 кадров
  одним `sendmmsg`, пауза и остановка — с точностью до пачки), `rmasscan/docs/rust-lab.md` (раздел о sendqueue:
  `tx_mode` `sendqueue` теперь и у Linux через `sendmmsg`; `tx_over_budget` у Linux не измеряется, правило бюджета к
  Linux не применяется), `rmasscan/docs/windows-wire-lab.md` (строка 141: «`single` adapters (Linux, macOS)» → macOS
  `single`, Linux `sendqueue` через `sendmmsg`, оба бюджет не измеряют),
  `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md` (строка 239: датированная пометка «позже,
  2026-11: Linux шлёт пачками `sendmmsg`, см. `rmasscan/BENCHMARKS.md`»; исторический текст не переписывается),
  `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces: `linux::TX_BATCH_FRAMES: usize = 64`; `open` возвращает `tx_mode: TxMode::SendQueue { max_batch:
  TX_BATCH_FRAMES }`; шов `PacketIo::send_many(&mut self, frames: &[&[u8]], lens: &mut [usize]) -> Result<usize,
  Errno>` — число принятых сообщений (ошибка первого — `Err`), `lens[j]` — байты сообщения j. Число сообщений —
  `min(frames.len(), lens.len(), TX_BATCH_FRAMES)`, ноль — `Err(EINVAL)` без системного вызова.
- `PacketFd::send_many`: один блок `unsafe` — `sendmmsg(fd, msgs, n, MSG_NOSIGNAL)`; массивы `iovec`/`mmsghdr` длины
  `TX_BATCH_FRAMES` на стеке вызова, заполнены первые `n` (сырые указатели не хранятся в `PacketFd`, он остаётся
  `Send`); `SAFETY` опирается на проверенное `n` и на то, что срезы кадров живы весь вызов, ядро их только читает и
  пишет `msg_len`.
- `TxHalf { io: Option<I>, side: TxSide, deferred: Option<String> }`; `max_batch() = TX_BATCH_FRAMES`.
  `send_batch(frames, timeout)`:
  - `deferred` есть → `Err(IoError::new(deferred.take()))` без нового счёта; после него — прежний «adapter closed…»;
  - пусто или больше `TX_BATCH_FRAMES` → `Err` с текстами Windows (`send_batch called with no frames; nothing was
    sent`, `send_batch called with N frames, more than 64; nothing was sent`); n == 1 → прежний `send`;
  - один `Deadline` на весь вызов (контракт движка для `max_batch > 1`); цикл с первого неотправленного кадра i:
    `send_many(&frames[i..])` → k ≥ 1: если `lens[j] != len` при j < k → `TxBatch { sent: i + j, rest: Uncertain }`
    (как короткая запись одиночного пути); иначе i += k, при i == n → `Sent`, иначе повтор с i (ядро теряет errno при
    k ≥ 1, повтор возвращает настоящий). `Ok(0)` — фатальная ошибка `EIO` (не цикл);
  - ошибка на кадре i получает ровно исход одиночного пути: `EAGAIN` — `poll(POLLOUT)` до дедлайна вызова, по
    истечении `TxBatch { sent: i, rest: WouldBlockUnsent }` (движок предложит кадр i снова со свежим дедлайном, как
    сегодня); EINTR — пауза ≤ 1 мс и повтор; фатальная — текст `errno_msg("send", e)`, `side.error()`, fd закрывается;
    при i == 0 это `Err(текст)`, при i > 0 — `Ok(TxBatch { sent: i, rest: WouldBlockUnsent })` с текстом в `deferred`:
    движок засчитывает ровно префикс, следующий вызов получает `Err` с тем же текстом → `TxError("send: …")`, как
    сегодня;
  - счётчики (задача 2): `side.sent(sent)`; исход `WouldBlockUnsent` по `EAGAIN` — `side.would_block()`; `Uncertain` —
    `side.uncertain(1)`; отложенная фатальная — только `side.error()`, без `would_block`; `side.batch(n)` на каждый
    вызов с n ≥ 2, в котором выполнен хотя бы один `sendmmsg`; `tx_over_budget` на Linux по-прежнему 0.

- [ ] **Step 1: тесты** `tx_batch_of_n_is_one_sendmmsg_and_counts_one_batch`, `tx_batch_of_one_uses_plain_send`,
  `tx_batch_frames_reach_the_socket_in_order_unchanged`, `tx_partial_sendmmsg_reissues_from_the_first_unsent_frame`,
  `tx_batch_lost_error_is_resolved_by_reissue_within_one_deadline` (Review Focus 2: k = 3 из 8 без ошибки, затем
  `EAGAIN` навсегда → `TxBatch { sent: 3, rest: WouldBlockUnsent }`, сумма `poll_ms` ≤ 50),
  `tx_batch_fatal_error_keeps_the_single_path_outcome` (ENETDOWN на позиции 0 → `Err("send: …")`; на позициях 1 и
  n − 1 → `TxBatch { sent: позиция, WouldBlockUnsent }`, следующий вызов → `Err` с тем же текстом, затем «adapter
  closed…»; `tx_errors` 1, `tx_would_block` 0, `tx_sent` = позиция), `tx_batch_zero_accepted_is_fatal_not_a_spin`
  (`send_many` → `Ok(0)` без errno: фатальная `EIO`, один вызов шва), `tx_batch_short_message_is_uncertain_at_that_frame`,
  `tx_batch_whole_call_respects_one_deadline`, `tx_batch_rejects_empty_and_oversized`,
  `send_many_count_is_bounded` (`min(frames, lens, 64)`, ноль → `EINVAL`), `tx_batch_invariant_sent_eq_n_iff_sent`
  (перебор сценариев), `tx_batch_counters_match_the_single_path_accounting`. FAIL.
- [ ] **Step 2: реализация**, доки `lib.rs`; `unsafe_count` = значение после задачи 14 + 1.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`; `examples/wire_scan.rs` тесты зелёные.
- [ ] **Step 4: стенд** — сессия `U-TX` по протоколу, C-оракул отдельной серией, матрица, `--suite rust`, дымовой
  прогон; README, `rust-lab.md`, `windows-wire-lab.md`, пометка в отчёте sendqueue, строка в `BENCHMARKS.md`. При
  провале ворот — правило раздела «Замеры».
- [ ] **Step 5: коммит**: `perf(rmasscan-net): Linux TX sends batches of up to 64 frames with sendmmsg (P1)`.

### Задача 16: P2 — ожидание события Npcap на Windows

Проверяет: Mac (переносимый фейк), `W-gate`; спайк на Windows VM стенда (по образцу спайка sendqueue).

**Files:**
- Modify: `src/windows/ffi.rs`, `src/windows/loader.rs`, `src/windows/sys.rs`, `src/windows/handle.rs`,
  `src/windows/adapter.rs`, `src/windows/tests/fake.rs`, `src/windows/tests/adapter_tests.rs`, `src/windows/live.rs`
  (живой `#[ignore]`-спайк), `rmasscan/BENCHMARKS.md` (итог спайка)

**Interfaces:**
- `ffi`: `type GetEventFn = unsafe extern "C" fn(*mut PcapT) -> *mut c_void`; `type WaitFn = unsafe extern "system"
  fn(*mut c_void, u32) -> u32`; `const SYM_PCAP_GETEVENT: &str = "pcap_getevent"` — **вне** `pcap_api!`, то есть не в
  `REQUIRED_SYMBOLS` (иначе старый wpcap стал бы `MissingCapability`); `WAIT_OBJECT_0 = 0`, `WAIT_TIMEOUT = 258`
  (сверка с `windows-sys` на Windows).
- `loader`: `unsafe trait Module` получает `fn wait_object(&self) -> WaitFn`; `# Safety` трейта дополняется: функция
  ведёт себя как `WaitForSingleObject`, вызывается только с событием живого `pcap_t` и не держит его после возврата.
  `OsModule` отдаёт `WaitForSingleObject` из `windows-sys` (фича `Win32_System_Threading` уже включена), фейк —
  `fake::f_wait`. `NpcapApi::rx_event(&self) -> Option<(GetEventFn, WaitFn)>` — `Some`, только если `pcap_getevent`
  разрешился (как `pcap_init`).
- `handle`: `PcapHandle::wait_readable(&mut self, ms: u32) -> EventWait`, `enum EventWait { Signaled, TimedOut,
  Unavailable, Failed(u32) }`; событие берётся у `pcap_t` при первом ожидании и не закрывается (им владеет `pcap_t`;
  `SAFETY` у `unsafe impl Send for PcapHandle` дополняется).
- `adapter`: `const EVENT_SLACK: Duration = Duration::from_millis(16)` (такт таймера Windows по умолчанию 15,625 мс) и
  `const EVENT_WAIT_SLICE: Duration = Duration::from_millis(10)` (спайк может уменьшить оба). `RxHalf::wait`: если
  событие есть и остаток `left > EVENT_SLACK` — ждать `min(left - EVENT_SLACK, EVENT_WAIT_SLICE)` в мс вниз (потерянное
  пробуждение стоит не больше одного среза); `Signaled`/`TimedOut` → снова `pcap_next_ex`. `Signaled`, за которым
  сразу `Empty`, даёт один сон 1 мс, как опрос; три таких подряд — событие этой половины выключается до конца.
  `Unavailable` или `Failed` — тоже выключение; дальше прежний опрос (сон 1 мс, `yield_now` ниже 3 мс). Последние
  `EVENT_SLACK` всегда идут прежним опросом, поэтому бюджет 42 мс держится при любом такте таймера.
- Новые блоки `unsafe` (ровно 3): `transmute` адреса `pcap_getevent` в `loader`, вызов `pcap_getevent` и вызов
  `WaitFn` в `handle`.

- [ ] **Step 1: тесты** (фейк, Mac) `pcap_getevent_is_optional_not_required`,
  `missing_or_null_event_falls_back_to_one_ms_polling` (Review Focus 3: без символа и с NULL-событием — ни одного
  вызова ожидания, `recv` как раньше), `event_wait_never_asks_past_the_slack_or_the_slice` (таймауты 50, 42, 20, 5 мс:
  запрошено ≤ `min(left - EVENT_SLACK, EVENT_WAIT_SLICE)`, при остатке ≤ `EVENT_SLACK` ожиданий нет),
  `signalled_but_empty_event_does_not_spin` (Review Focus 4: событие всегда сигнально, кадров нет — за один
  `recv(50 мс)` не больше трёх ожиданий, затем событие выключено, вызовов `pcap_next_ex` не больше 50, время < 50 мс),
  `signalled_event_delivers_the_frame_without_sleeping`, `wait_failure_disables_the_event_for_this_half`,
  `idle_recv_with_event_returns_within_the_budget` (только верхняя граница: < 50 мс). FAIL.
- [ ] **Step 2: реализация**; `unsafe_count` = значение после задачи 15 + 3.
- [ ] **Step 3: PASS** `M-gate`, `W-gate`.
- [ ] **Step 4: спайк на VM** (`#[ignore] live_rx_event_wait_budget_latency_and_idle_cpu` в `src/windows/live.rs`,
  окружение и стенд — как у живых тестов этого файла): длительность пустого `recv(50 мс)` и задержка выдачи кадра от
  его прихода, не меньше 2000 значений каждой величины на условие; CPU RX-потока за 10 с простоя; режимы «опрос» и
  «событие»; условия «тихо» и «поток мусора» (свои кадры); 3 повтора. Ворота — по хвосту, не по медиане: длительность
  пустого `recv` — p99 ≤ 43 мс и max < 50 мс; задержка выдачи — p99 и max не хуже опроса больше чем на 2 мс; CPU
  простоя ниже опроса; всё в обоих условиях и во всех повторах. `EVENT_SLACK` — наименьшее из 16/8/4/2 мс, прошедшее
  ворота. Итог в `BENCHMARKS.md`. Провал при 16 мс — правило раздела «Замеры».
- [ ] **Step 5: коммит**: `perf(rmasscan-net): Windows RX waits on the Npcap read event (P2)`.

### Задача 17: P3 — настройка TX-сокета Linux

Проверяет: стенд (сначала выполнимость); при продолжении — Mac (фейк после задачи 12), `L-gate`, сессия `U-TX`,
матрица, `--suite rust`.

**Files:**
- Modify (только для подшагов, прошедших выполнимость): `src/linux/mod.rs`, `src/linux/socket.rs`,
  `src/linux/tests.rs`, `rmasscan/README.md`; всегда — `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Consumes: `unix_sys::setsockopt_int` (задача 6) — новых блоков `unsafe` нет.
- `ENOBUFS` в одиночном и пакетном TX (если подшаг выполним): ядро не приняло кадр (qdisc или драйвер его отбросили) —
  пауза `min(1 мс, остаток)` и повтор до дедлайна, по истечении `WouldBlockUnsent` (сегодня — фатальная `send: …`).

- [ ] **Step 1: выполнимость** на HEAD, стенд S, `U-TX`, две конфигурации: (а) пара veth как есть (`noqueue`, как в
  матрице); (б) очередь с ограничением только на `rnn-va` внутри netns `rnn-a` (`tc qdisc replace dev rnn-va root tbf
  …`, умирает вместе с netns). Замеры: число `poll` потока TX на 1000 отправленных кадров (`perf trace -s -p <pid>`;
  нет `perf` — `strace -c -f -p <pid>` с пометкой об искажении темпа), исход скана (обрыв `send: No buffer space
  available` или нет), отбросы `tc -s qdisc`, фактический `tb` по `ss -0 -m`. Подшаг выполним, только если стенд
  показывает то, что он меняет: `ENOBUFS` — обрыв скана по `ENOBUFS` воспроизводится в (б); `SO_SNDBUF` — в (а) не
  меньше одного `poll` потока TX на 1000 кадров; `PACKET_QDISC_BYPASS` — в (а) есть путь qdisc, который можно обойти
  (на `noqueue` его нет, а в (б) обход лишь снимает искусственный шейпер — это не замер). Невыполнимый подшаг кода не
  меняет: находка с числами пишется в `BENCHMARKS.md`, решение уходит пользователю. Ни один не выполним — P3
  заканчивается здесь коммитом только `BENCHMARKS.md`: `docs(rmasscan): P3 feasibility on the veth stand`.
  Физический NIC не используется.
- [ ] **Step 2: `ENOBUFS`** (если выполним): тесты `tx_enobufs_storm_backs_off_and_ends_unsent_at_the_deadline`
  (каждая пауза ≤ 1 мс, сумма ≤ таймаута, исход `WouldBlockUnsent`, `tx_would_block` 1) и
  `tx_batch_enobufs_after_a_prefix_is_retried_like_eagain`; FAIL → реализация → PASS (`M-gate`, `L-gate`); на стенде в
  (б) скан больше не обрывается, в (а) матрица прежняя. README: `ENOBUFS` больше не обрывает скан. Коммит
  `fix(rmasscan-net): ENOBUFS on Linux TX is unsent, not fatal (P3)`.
- [ ] **Step 3: `SO_SNDBUF`** (если выполним): TX-сокет просит 4 МиБ (`setsockopt_int`, отказ игнорируется, ядро режет
  до `wmem_max`); сессия `U-TX` в (а), ворота «ускорение»; коммит `perf(rmasscan-net): larger Linux TX socket buffer
  (P3)` или отрицательный замер.
- [ ] **Step 4: `PACKET_QDISC_BYPASS`** (если выполним и шаг 2 сделан): на TX-сокете (`setsockopt_int`, отказ
  игнорируется); сессия `U-TX`, ворота «ускорение», матрица, `--suite rust`; README: «qdisc интерфейса скана
  обходится, шейпинг `tc` на нём не действует»; коммит `perf(rmasscan-net): Linux TX bypasses the qdisc (P3)` или
  отрицательный замер.

### Задача 18: приёмка ветки

Проверяет: все три ОС, стенд, Studio.

- [ ] **Step 1:** `M-gate` плюс `cargo test --locked --workspace` на Mac; `L-gate` и `W-gate` плюс
  `cargo test --locked --workspace` на хосте и в госте.
- [ ] **Step 2: Studio** без правок: `cd studio && CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rmasscan-native-net-studio"
  cargo check --locked && CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rmasscan-native-net-studio" cargo xtask test`.
- [ ] **Step 3: границы правок:** `git diff --stat a275ea9e -- . ':!rmasscan/crates/rmasscan-net'
  ':!rmasscan/README.md' ':!rmasscan/BENCHMARKS.md' ':!rmasscan/docs/macos-feth-lab.md' ':!rmasscan/docs/rust-lab.md'
  ':!rmasscan/docs/windows-wire-lab.md' ':!docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md'
  ':!docs/superpowers'` пуст; `Cargo.lock` и `studio/Cargo.lock` без изменений;
  `git diff a275ea9e -U0 | grep '^+' | hygiene` пуст; `unsafe_count` итоговый и разбивка по файлам — в заметки.
- [ ] **Step 4: стенд** — сессия ячейки `U` HEAD против коммита задачи 1 (продукт тот же, что на `a275ea9e`, а harness
  уже даёт CPU потоков), C-оракул отдельной серией, матрица, `--suite rust`, дымовой прогон; итоговая строка в
  `BENCHMARKS.md`.
- [ ] **Step 5:** удалить деревья `~/rnn/*` и `/tmp/rnn-target` на хосте, распакованные деревья и `rnn-target` в
  госте, `CARGO_TARGET_DIR` на Mac; `ps -Ao pid,%cpu,etime,command | awk '$2>80'` — своих процессов нет.
- [ ] **Step 6:** коммит `BENCHMARKS.md`: `docs(rmasscan): native-Rust phase 1 results for rmasscan-net`; финальное
  ревью ветки; push и PR — только с согласия пользователя.
