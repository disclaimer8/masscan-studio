# rmasscan-net: нативный Rust, фаза 1 — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans`.
> Шаги в чекбоксах (`- [ ]`). Цикл задачи: RED (тест) → FAIL → минимальная правка → PASS на названных ОС → замер (если
> задача о скорости) → коммит.

**Goal:** `rmasscan-net` пишется идиоматичным Rust и становится быстрее на горячем пути, каждое ускорение подтверждено
замером; поведение не меняется, кроме трёх решённых пользователем изменений P1–P3 и удаления тестового спайка BPF.

**Architecture:** сначала страховка (раскладка ABI, точные тексты ошибок, конкурентный тест счётчиков, микробенч
адаптера), затем правки, которые она охраняет: счётчики, переносимый разбор, общие примитивы Unix, FFI macOS, общие
помощники бэкендов и `as`, netlink и переносимый адаптер Linux, `recvmmsg`, чистка Windows; P1–P3 последними, у каждой
своя ячейка стенда. Публичный API не меняется; новый `unsafe` появляется только в блоках, названных в P1 и P2.

**Tech Stack:** Rust 1.99.1, edition 2024, workspace `rmasscan/`; `libc =0.2.191` (Unix), `windows-sys =0.61.2`
(Windows); новых зависимостей нет.

**Spec:** [docs/superpowers/specs/2026-11-16-rmasscan-native-rust-design.md](../specs/2026-11-16-rmasscan-native-rust-design.md)
(«Решения пользователя» и «Ограничения» главнее этого плана).

**Опора (строки на базе `a275ea9e`):** `lib.rs` — `NetStats` :247, доки `tx_batches`/`tx_batch_max` :265-275,
`Counters` :279-304, `snapshot` :322, `TxMode` :357, `OpenedAdapter` :364; `linux/mod.rs` — шов `PacketIo` :52,
`TxHalf::step` :139, `Tx for TxHalf` :176, `RxHalf::step` :251, `Rx for RxHalf` :303, `tx_mode` :424;
`linux/socket.rs` — `open` :38, `send` :100, `recv` :114; `macos/adapter.rs` — `parse_record` :293, `RxHalf::step` :379,
дедлайн `recv` :478; `windows/adapter.rs` — `send_batch` :176, `RxHalf::wait` :254, `Rx for RxHalf` :282;
`windows/ffi.rs` — `pcap_api!` и `REQUIRED_SYMBOLS` :232-314; `windows/loader.rs` — необязательный `pcap_init` :204-215.
Потребители: `rmasscan-lab`, `rmasscan-cli`, `studio/` (`studio-runner` зовёт `open_explicit`, `os_route_table`,
`plan_physical`) — все только через публичный API.

## Global Constraints

- **Файлы.** Меняются только `rmasscan/crates/rmasscan-net/**` (включая `examples/`) и документы
  `rmasscan/README.md`, `rmasscan/BENCHMARKS.md`, `rmasscan/docs/macos-feth-lab.md`,
  `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md`. `rmasscan-engine`, `-cli`, `-lab`, `-proto`,
  `-core` и `studio/` не меняются ни на байт: 4c меняет engine, cli, lab и proto на `feat/rmasscan-banners-4c`.
- **Зависимости.** Новых нет, фич `windows-sys` не прибавляется, `Cargo.lock` и `studio/Cargo.lock` не меняются
  (`git diff --exit-code a275ea9e -- rmasscan/Cargo.lock studio/Cargo.lock`). Rust 1.99.1, edition 2024.
- **Публичный API заморожен.** Ни одна существующая `pub`-сигнатура не меняется; допустимы только новые элементы.
  `TxMode` и `NetStats` — исчерпывающие `pub`-типы: ни вариантов, ни полей не добавлять. Внутренние (`pub(crate)`)
  швы и типы меняются свободно.
- **Поведение байт в байт вне P1–P3:** кадры на проводе и их порядок, чтение кадров, счётчики `NetStats`, семантика
  ОС (флаги сокетов, порядок вызовов, повторы EINTR/EAGAIN), тексты ошибок. Тексты не меняются нигде, даже там, где
  их сейчас никто не сверяет.
- **Тексты errno.** `errno_msg` печатает номер таблицей ОС хоста (`io::Error::from_raw_os_error`): номер Linux 11 на
  Mac выглядит как EDEADLK, а не EAGAIN. Тест, сверяющий текст с errno, строит ожидание той же функцией хоста;
  переносимые тесты кода Linux сверяют вид ошибки (вариант `NetError`, `SendStatus`, код), а не текст ОС.
- **Тесты времени.** Тесты на реальных часах с фейками терпят джиттер CI только потому, что проверяют верхние
  границы; новые утверждения о времени — тоже только верхние границы. Тест, зависящий от свойств процесса ОС (потоки,
  handle, память), живёт под `cfg` своей ОС.
- **`unsafe`.** Только узкие блоки, у каждого `// SAFETY:`; `deny(clippy::undocumented_unsafe_blocks)`,
  `deny(unsafe_op_in_unsafe_fn)` и `deny(unsafe_code)` на уровне crate остаются. Новых `unsafe fn` и `unsafe impl` нет
  (кроме расширения контракта существующего `unsafe trait Module` в задаче 16). Число блоков `unsafe {` в рабочем коде
  (`unsafe_count`, раздел «Команды»; база 199) в конце каждой задачи не больше, чем в конце предыдущей. Исключения
  только названные: задача 15 (P1) +1 — вызов `sendmmsg`; задача 16 (P2) +3 — `transmute` символа `pcap_getevent`,
  вызов `pcap_getevent`, вызов функции ожидания. Число пишется в заметки задачи.
- **Сборки.** Каждая команда задаёт `CARGO_TARGET_DIR` вне дерева; `rmasscan/target` не создаётся. Фоновые процессы в
  zsh: `trap 'trap - EXIT INT TERM; kill 0' EXIT INT TERM` (не `trap 'kill 0' …`: крутит CPU); по окончании
  `ps -Ao pid,%cpu,etime,command | awk '$2>80'` и остановка только своих процессов.
- **ОС проверки.** На Mac установлен только `aarch64-apple-darwin`: код только для Linux или только для Windows здесь не
  компилируется. Такая задача проверяется сборкой и тестами на Linux-хосте стенда (`L-gate`) и в Windows-госте стенда
  (`W-gate`); CI — только после push, а push и PR — только с согласия пользователя. Скрипты Windows копируются файлом и
  запускаются `pwsh -NoProfile -ExecutionPolicy Bypass -File …`, никогда `-Command "…"`.
- **Скорость.** Числа с Mac только ранжируют. Задача о скорости в `rmasscan-net` доказывается ячейкой `U` на
  Linux-стенде (раздел «Замеры») против базы, а существующая матрица 4×5 остаётся 40/40 VALID без потерь RX.
- **Гигиена публичного репозитория.** Ни локальных путей, ни имён пользователей, хостов и LAN-адресов: хосты
  называются по роли (`$LINUX_HOST` — Linux-хост стенда, CPU оракула; `$WIN_GUEST` — Windows-гость стенда). Перед
  каждым коммитом `git diff --cached -U0 | grep '^+' | hygiene` (раздел «Команды») печатает пустоту.
- **Коммиты.** `git add` только явных путей; сообщение через `git commit -F -` с последней строкой
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Ветка `refactor/rmasscan-native-net` от `a275ea9e`.
- **Заметки.** Исполнитель пишет решения, находки и числа по ходу в
  `.superpowers/sdd/2026-11-16-rmasscan-native-net/task-N-notes.md` (каталог в gitignore).
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
  && cargo clippy --locked -p rmasscan-net --all-targets -- -D warnings \
  && cargo clippy --locked -p rmasscan-net --all-targets --features lab -- -D warnings \
  && cargo test --locked -p rmasscan-net \
  && cargo test --locked -p rmasscan-net --features lab --lib lab_io \
  && cargo test --locked -p rmasscan-net --example wire_scan \
  && cargo check --locked --workspace --all-targets) \
  && git diff --exit-code a275ea9e -- rmasscan/Cargo.lock studio/Cargo.lock

# L-gate (Linux-хост стенда): всё дерево HEAD, сборка вне дерева
git archive --format=tar --prefix="rnn-$SHA/" HEAD | ssh "$LINUX_HOST" 'mkdir -p ~/rnn && tar -x -C ~/rnn'
ssh "$LINUX_HOST" "cd ~/rnn/rnn-$SHA/rmasscan && export CARGO_TARGET_DIR=/tmp/rnn-target \
  && ~/.cargo/bin/cargo clippy --locked -p rmasscan-net --all-targets -- -D warnings \
  && ~/.cargo/bin/cargo clippy --locked -p rmasscan-net --all-targets --features lab -- -D warnings \
  && ~/.cargo/bin/cargo test --locked -p rmasscan-net \
  && ~/.cargo/bin/cargo test --locked -p rmasscan-net --features lab --lib lab_io \
  && ~/.cargo/bin/cargo test --locked -p rmasscan-net --example wire_scan \
  && ~/.cargo/bin/cargo check --locked --workspace --all-targets"

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
foreach ($a in @('clippy --locked -p rmasscan-net --all-targets -- -D warnings',
                 'test --locked -p rmasscan-net',
                 'test --locked -p rmasscan-net --example wire_scan',
                 'check --locked --workspace --all-targets')) {
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

**Стенд S** — одноразовый скрипт на `$LINUX_HOST` в `mktemp -d /tmp/rmasscan-native-net.XXXX` (в репозиторий
не кладётся; его итоговый текст задача 2 записывает в `BENCHMARKS.md`, дальше он берётся оттуда без изменений). Под
`sudo -n` он поднимает изоляцию по правилам `scripts/wire-lab.sh`: две netns `rnn-a`/`rnn-b`, пара veth
`rnn-va`/`rnn-vb`, без uplink, моста и NAT, IPv6 выключен на обоих концах, маршрута по умолчанию нет; MAC
`02:aa:00:00:00:01`/`02:aa:00:00:00:02`, сканер `10.200.0.1/24` (адрес адаптера `10.200.0.100` не назначен), у пира
`10.200.0.2-5/24` без слушателей (ядро пира отвечает RST на каждый SYN); проверка изоляции —
`rmasscan-lab capture isolation`, как в `wire-lab.sh`; снятие —
`trap 'trap - EXIT INT TERM; ip netns del rnn-a; ip netns del rnn-b' EXIT INT TERM`.

**Ячейка U** (без ограничения скорости) на стенде S, `wire_scan` (release) из `ip netns exec rnn-a`,
`--iface rnn-va --src-ip 10.200.0.100 --src-mac 02:aa:00:00:00:01 --router-mac 02:aa:00:00:00:02 --seed 1
--source-port 40000 --wait 1 --rate 100000000`, под `/usr/bin/time -v`:

- `U-TX`: `--targets 10.200.0.0/16 --ports 1-64` (4 194 304 пробы, отвечают только `.2-.5`). Метрики: `timing.steady_pps`
  из JSON, CPU (user+sys) на отправленный кадр, `net.tx_would_block`, свидетель провода — прирост RX-пакетов `rnn-vb`
  по `ip -s -j link` не меньше `net.tx_sent`.
- `U-RX`: `--targets 10.200.0.2-10.200.0.5 --ports 1-65535` (262 140 проб, на каждую RST). Метрики:
  `rx_health.kernel_drops`, `net.rx_packets` против числа проб, CPU на принятый кадр.
- Чередование база/новая версия, 5 повторов каждой; C-оракул (`$ORACLE`, те же цели, порты, `--rate`, адаптер и MAC)
  по разу в каждом повторе — для справки. База — коммит ветки до первой правки задачи (sha в заметках), сборка из
  `git archive`, как `L-gate`.
- Ворота «без регрессии»: медианы новой версии по pps и CPU на кадр хуже базы не больше чем на 2 %, потери RX ядра не
  выше базы. Ворота «ускорение»: по целевой метрике задачи медиана новой версии лучше медианы базы и не меньше 4 из 5
  повторов новой версии лучше медианы базы; прочие метрики — ворота «без регрессии». Если ворота «ускорение» не
  пройдены, продуктовая правка не коммитится, отрицательный замер пишется в `BENCHMARKS.md`, решение за пользователем.

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

**Дымовой прогон адаптера** (задачи 6, 13, 15, 17): `cargo test --locked --release -p rmasscan-net --test linux_io
--no-run`, затем бинарник из вывода под `sudo -n ip netns exec rnn-a env RMASSCAN_LAB_IFACE=rnn-va
RMASSCAN_LAB_IP=10.200.0.100 RMASSCAN_LAB_MAC=02:aa:00:00:00:01 RMASSCAN_LAB_PEER_MAC=02:aa:00:00:00:02 <bin> --ignored
lab_`; `lab_open_without_privilege_is_permission_denied` — под `setpriv --reuid=nobody --regid=nogroup --clear-groups`,
иначе он записывается NOT RUN.

## Review Focus

1. **Пачка `recvmmsg` со смесью записей** (свой исходящий кадр на ядре без `PACKET_IGNORE_OUTGOING`, чужой ifindex,
   кадр длиннее буфера, запись с коротким адресом): порядок выдачи, счётчики и фатальная ошибка ровно на своей записи —
   как у покадрового пути. Тест `rx_batch_mixed_records_match_the_per_frame_path` (задача 13).
2. **`sendmmsg` принял часть пачки, а ядро потеряло ошибку** (вернуло `k < n` без errno): повтор с первого
   неотправленного кадра даёт настоящий errno, префикс засчитан один раз, дедлайн один на весь вызов. Тест
   `tx_batch_lost_error_is_resolved_by_reissue_within_one_deadline` (задача 15).
3. **Старый wpcap без `pcap_getevent` или NULL-событие:** RX работает прежним опросом 1 мс, без `MissingCapability`.
   Тест `missing_or_null_event_falls_back_to_one_ms_polling` (задача 16).
4. **Шторм `ENOBUFS` (обход qdisc, кольцо драйвера полно):** отправка не крутится вхолостую, паузы не длиннее 1 мс, к
   дедлайну исход `WouldBlockUnsent`. Тест `tx_enobufs_storm_backs_off_and_ends_unsent_at_the_deadline` (задача 17).
5. **`health` между пачками RX:** при кадрах, лежащих во внутреннем кольце, `health` делает свежее чтение
   `PACKET_STATISTICS`, а кадры кольца выдаются после него без потерь и без повторного счёта. Тест
   `health_between_batches_reads_fresh_drops_and_keeps_buffered_frames` (задача 13).

## Карта файлов

- Новые: `src/linux/layout_tests.rs` (задача 1), `src/unix_sys.rs` (6: примитивы Unix, единственное место их
  `unsafe`), `src/adapter_common.rs` (9: общие помощники трёх адаптеров, без `unsafe`), `src/linux/abi.rs`
  (12: константы Linux без `libc`).
- Удаляется: `src/macos/spike.rs` (7).
- Горячий путь: `src/lib.rs`, `src/linux/{mod,socket}.rs`, `src/macos/{adapter,sys}.rs`,
  `src/windows/{adapter,handle,ffi,loader}.rs`.
- Разбор и обнаружение: `src/route_parse.rs` (+ тесты), `src/linux/{route,route_observation}.rs`,
  `src/macos/{ifinfo,route}.rs`, `src/windows/{sys,process}.rs`, `src/discover.rs`, `src/neighbours.rs`,
  `src/interrupt.rs`, `src/lab_io.rs`.

---

### Задача 1: страховка — раскладка ABI, точные тексты ошибок, конкурентный тест счётчиков, микробенч адаптера

Проверяет: Mac (macOS и переносимые фейки Windows), Linux-хост (`L-gate`), Windows-гость (`W-gate`). Продуктовый код
не меняется, кроме видимости констант, которые сверяют тесты.

**Files:**
- Create: `rmasscan/crates/rmasscan-net/src/linux/layout_tests.rs` (`#[cfg(test)] mod layout_tests;` в `linux/mod.rs`)
- Modify (тесты): `src/macos/tests/layout_tests.rs`, `src/route_parse_tests.rs`, `src/linux/route_observation_tests.rs`,
  `src/linux/tests.rs`, `src/macos/tests/adapter_tests.rs`, `src/windows/tests/adapter_tests.rs`, `src/windows/tests.rs`
- Modify (видимость): приватные константы `route_parse::{rtsock::{SDL_DATA, SIN6_LEN, SIN6_ADDR}, netlink::RTA_HDRLEN}`
  → `pub(crate)`

**Interfaces:**
- Produces (держатся зелёными до конца ветки): `error_texts_are_byte_identical` и
  `stats_snapshot_is_monotonic_and_exact_under_concurrent_tx_and_rx` в тестах каждого из трёх адаптеров;
  `#[ignore] adapter_hot_path_two_threads` там же (печатает нс на кадр TX и RX); тесты раскладки ниже.

- [ ] **Step 1: тесты раскладки.**
  - `darwin_route_socket_constants_match_libc` (macOS, `route_parse_tests.rs`, `#[cfg(target_os = "macos")]`):
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
- [ ] **Step 2: точные тексты.** `error_texts_are_byte_identical` в каждом адаптере сравнивает `to_string()` каждого
  `NetError` и `IoError::message`, который фейк умеет вызвать, с литералом; часть errno ожидание строит тем же
  `std::io::Error::from_raw_os_error(e)`. Linux (`linux/tests.rs`): тексты `verify_binding` (тип канала, имя, «no such
  interface», «disappeared», `if_nametoindex`/`SIOCGIFHWADDR`), виды `map_open_error`, `send: …`,
  `poll(POLLOUT): socket error`, `poll(POLLOUT): …`, `recvfrom: …`, `poll(POLLIN): …`,
  `getsockopt(PACKET_STATISTICS): …`, закрытый адаптер. macOS: три текста `check_binding`, подсказка гранта,
  `no free /dev/bpf* device (N busy)`, `open /dev/bpfN: …`, два текста `check_dlt`, малый буфер, длина TX,
  `write: … ; nothing was sent` (EMSGSIZE), все тексты разбора записи, `read returned …`, тексты `poll`,
  `ioctl(BIOCGSTATS): …`. Windows: `check_binding`, длина TX, три текста `send_batch`, `pcap_next_ex failed (code N): …`,
  EOF, `pcap_stats failed (code N): …`, `pcap_setnonblock did not take effect on the RX handle`.
- [ ] **Step 3: конкурентный тест.** `stats_snapshot_is_monotonic_and_exact_under_concurrent_tx_and_rx` (по одному на
  адаптер, на фейке своего шва): поток TX делает 20 000 `send` кадра 60 байт, поток RX — `recv`, пока не выдано
  20 000 кадров, третий поток снимает `snapshot()`, пока оба не кончили. Утверждения: каждое поле каждого снимка не
  меньше, чем в предыдущем; в итоге `tx_sent == 20_000`, `rx_packets == 20_000`, прочие счётчики 0.
- [ ] **Step 4: микробенч.** `#[ignore] adapter_hot_path_two_threads` в тех же трёх модулях: свой фейк без замков
  (`send`/`write` → `Ok(len)`, приём копирует заготовленный кадр), потоки TX и RX стартуют через `Barrier`, по
  1 000 000 вызовов, печать `ns/frame` каждого потока. Запуск: `cargo test --locked --release -p rmasscan-net
  adapter_hot_path -- --ignored --nocapture` на Mac (macOS и Windows) и на хосте (Linux); числа — в заметки.
- [ ] **Step 5: PASS.** `M-gate`, `L-gate`, `W-gate` зелёные (тесты страховки проходят на неизменённом коде);
  `unsafe_count` = 199 записан.
- [ ] **Step 6: коммит** путей из Files: `test(rmasscan-net): safety net for the native-Rust refactor`.

### Задача 2: счётчики TX и RX на разных строках кэша

Проверяет: Mac, `L-gate`, `W-gate`; стенд: ячейка `U` (ворота «без регрессии», выигрыш записывается) и матрица.

**Files:**
- Modify: `src/lib.rs` (`Counters`, `snapshot`), `src/linux/mod.rs`, `src/macos/adapter.rs`, `src/windows/adapter.rs`,
  `src/linux/tests.rs` (помощник `counters()`), `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces (в `lib.rs`, `pub(crate)`):
  - `struct Counter(AtomicU64)`: `inc(&self)`, `add(&self, n: u64)`, `max(&self, n: u64)`, `get(&self) -> u64`. Запись —
    `store(load.wrapping_add(n), Relaxed)` (`max` — `store(load.max(n))`), без RMW: у каждого счётчика ровно один
    писатель — половина-владелец через `&mut self` (doc-комментарий называет это инвариантом; второй писатель
    потребует RMW обратно).
  - `#[repr(align(128))] struct TxCounters { sent, would_block, uncertain, errors, batches, batch_max, over_budget:
    Counter }` и `fn record(&self, s: SendStatus)` (одна запись `sent`/`would_block`/`uncertain`).
  - `#[repr(align(128))] struct RxCounters { packets, truncated, outgoing, wrong_interface, errors, kernel_drops:
    Counter, kernel_drops_known: AtomicBool }` и `fn publish_drops(&self, total: u64)` (`kernel_drops` Relaxed, затем
    `kernel_drops_known` Release, как сейчас).
  - `struct Counters { tx: TxCounters, rx: RxCounters }`; `Counters::bump` удаляется.

- [ ] **Step 1: тест** `counter_blocks_live_on_separate_cache_lines`: `align_of::<TxCounters>() == 128`,
  `align_of::<RxCounters>() == 128`, `offset_of!(Counters, rx) - offset_of!(Counters, tx) >= 128`. FAIL (типов нет).
- [ ] **Step 2: реализация** по Interfaces; три адаптера пишут через `counters.tx.*`/`counters.rx.*`; Linux копит
  `kernel_drops` через `rx.kernel_drops.add(delta)`; macOS и Windows — `rx.publish_drops`; Windows `tx_batch_max` —
  `tx.batch_max.max(n)`.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`, `W-gate`; тексты и конкурентные тесты задачи 1 зелёные.
- [ ] **Step 4: замер.** Микробенч задачи 1 до/после (Mac, хост); стенд S, ячейка `U` (`U-TX` и `U-RX`) против базы,
  матрица. В `BENCHMARKS.md` новый раздел «rmasscan-net: нативный Rust, фаза 1 (Linux-стенд)»: полный текст скрипта
  стенда S и ячейки U, метод и ворота, таблица «задача | коммит | ячейка | метрика | база (медиана, мин–макс) | новая |
  вердикт», строка этой задачи; Mac-числа отдельной строкой с пометкой «ранжирование, не ворота».
- [ ] **Step 5: коммит**: `perf(rmasscan-net): TX and RX counters on separate cache lines`.

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
- Create: `src/unix_sys.rs` (`#[cfg(unix)] #[allow(unsafe_code)] mod unix_sys;` в `lib.rs`)
- Modify: `src/lib.rs`, `src/linux/socket.rs`, `src/linux/route.rs`, `src/linux/route_observation.rs`,
  `src/linux/mod.rs`, `src/linux/tests.rs`, `src/macos/route.rs`, `src/macos/sys.rs`, `src/macos/ifinfo.rs`,
  `src/interrupt.rs`, `src/lab_io.rs`, `Cargo.toml` (комментарий со списком модулей с `unsafe`)

**Interfaces:**
- Produces (`unix_sys`, `pub(crate)`, один `unsafe`-блок на примитив):
  - `fn last_errno() -> i32` (`EIO`, если ОС не дала номера);
  - `fn socket(domain: c_int, ty: c_int, proto: c_int) -> Result<OwnedFd, i32>` — флаги передаются как есть;
  - `fn poll_one(fd: BorrowedFd<'_>, events: c_short, timeout_ms: c_int) -> Result<(c_int, c_short), i32>` —
    `(n, revents)`, толкование у вызывающего;
  - `fn setsockopt_int(fd: BorrowedFd<'_>, level: c_int, name: c_int, value: c_int) -> Result<(), i32>`;
  - `fn install_handler(sig: c_int, handler: extern "C" fn(c_int)) -> Result<(), i32>` — `SA_RESTART`, пустая маска;
    обнуление, `sigemptyset`, `sigaction` — отдельные узкие блоки;
  - Linux: `fn nl_kernel_addr() -> libc::sockaddr_nl` (ядро: `nl_pid` 0) и `fn mac_from_c_chars(src: &[c_char]) ->
    [u8; 6]`.
- Внутренний шов Linux: `IfaceInfo::hw_addr` → `fn link_family(&self, name: &str) -> Result<u16, Errno>` (MAC никто не
  читал); поле `KernelStats.packets` удаляется.

- [ ] **Step 1: тесты примитивов** (в `unix_sys.rs`): `socket_passes_flags_through` (Linux: с `SOCK_CLOEXEC` у fd есть
  `FD_CLOEXEC`; macOS: `PF_ROUTE` без флага — нет), `socket_error_is_errno_and_leaks_nothing` (неверный домен →
  `EAFNOSUPPORT`, число открытых fd прежнее), `poll_one_times_out_on_an_idle_udp_socket` (`(0, 0)` за 0 мс),
  `poll_one_reports_pollout_on_a_fresh_udp_socket`, `setsockopt_int_reports_enoprotoopt`,
  Linux `nl_kernel_addr_is_the_kernel`, `mac_from_c_chars_copies_six_bytes`. FAIL (модуля нет).
- [ ] **Step 2: реализация** `unix_sys`; затем по одному модулю перевод вызовов: сокеты и `OwnedFd`, одиночный `poll`,
  `last_errno`, `sockaddr_nl`, два `sigaction` (`interrupt`, `lab_io`; `lab_io` строит `io::Error` из errno, текст
  `sigaction(SIGINT): …` прежний). В `linux/socket.rs`: `sockaddr_ll` литералом структуры (все поля публичны, два
  блока `zeroed` уходят), `SLL_MIN_LEN = offset_of!(libc::sockaddr_ll, sll_addr)`, `libc::PACKET_IGNORE_OUTGOING`
  вместо своей `23`, копии MAC через `mac_from_c_chars`; `PACKET_IGNORE_OUTGOING` идёт через `setsockopt_int`,
  результат по-прежнему игнорируется.
- [ ] **Step 3: ловушки (не менять).** Сокет `PF_ROUTE` macOS открывается без `CLOEXEC`, а `O_NONBLOCK` ставится
  `fcntl` после; `ready()` macOS и наблюдение Linux округляют остаток вниз до мс (последняя миллисекунда — неблокирующий
  `poll`), TX/RX Linux — вверх (`div_ceil`), macOS-адаптер — вверх по наносекундам: округление остаётся у вызывающих.
  `retry_until` Linux (не больше 4096 попыток; `network preparation cancelled`, `network observation deadline
  expired`, `netlink observation retry limit exceeded`) и macOS (без предела; `network observation cancelled`,
  `route observation deadline expired`) не объединяются. Обработка EINTR у каждого места своя.
- [ ] **Step 4: PASS** `M-gate`, `L-gate`; `unsafe_count` меньше, чем после задачи 5 (ожидается около −14).
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
  netmask: Option<&[u8]> }` — запись `sockaddr` читается как ровно `max(sa_len, 2)` байт (сначала байт `sa_len`, затем
  срез); чистая `fn addr_kind(addr: Option<&[u8]>, netmask: Option<&[u8]>) -> AddrKind` разбирает три семейства без
  предположений о выравнивании.

- [ ] **Step 1: тесты** `open_node_of_a_missing_index_is_enoent` (`BpfFd::open_node(100_000)` → `Err(ENOENT)`, без
  привилегий); `addr_kind_*`: запись AF_INET ровно 16 байт → `V4` с адресом и префиксом из маски; AF_INET с `sa_len` 7 →
  `Other`; AF_INET6 28 байт → `V6` без KAME-зоны; AF_LINK → `Link`; `sa_len` 0 и 1 → `Other`; та же запись с
  невыровненного смещения 1 в `Vec<u8>` даёт тот же результат. FAIL.
- [ ] **Step 2: реализация** по Interfaces. Ловушка: текст ошибки строится только `errno_msg(op, errno)`, а не
  `Display` у `io::Error` из std; разница std — повтор EINTR внутри `open` (`cvt_r`), для узла `/dev/bpfN` не наблюдаемо,
  записать в заметки.
- [ ] **Step 3: спайк.** Удалить `spike.rs` и `mod spike` в `macos/mod.rs`, упоминания в документации модулей, строку
  `macos-feth-lab.md:72`. Число тестов падает на 2 обычных и 8 `#[ignore]`.
- [ ] **Step 4: PASS** `M-gate`; `unsafe_count` меньше, чем после задачи 6 (−4 в `sys`, −4 в `ifinfo`).
- [ ] **Step 5: коммит** (`git add` правок и `git rm` спайка): `refactor(rmasscan-net): std file I/O for BPF, safe
  sockaddr decoding, drop the closed BPF spike`.

### Задача 8: macOS RX — дедлайн по первой нужде

Проверяет: Mac (фейк, микробенч). Утверждения о скорости только для ранжирования: живой стенд macOS требует окна
гранта и в ворота не входит.

**Files:**
- Modify: `src/macos/adapter.rs`, `src/macos/tests/adapter_tests.rs`, `rmasscan/BENCHMARKS.md` (строка Mac)

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
- [ ] **Step 2: реализация**; существующие `rx_empty_poll_times_out_within_the_deadline`,
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
  `src/linux/layout_tests.rs`

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
  Каждая политика обмена оставляет свой предикат отправителя (старый путь: только `nl_pid == 0`; наблюдение: длина
  адреса, `AF_NETLINK` и `nl_pid == 0`) и свои тексты.
- Решение: обходчики сообщений и атрибутов наблюдения не сливаются с `NlAttrs` задачи 3 — у них другие тексты ошибок;
  общими становятся модуль, константы и чтения полей. `retry_until` и `exchange_until` остаются в `linux::route`
  (политика, не разбор).

- [ ] **Step 1:** перенести тесты разбора (`network_plan_keeps_all_alias_prefixes_…`, `…prefix_extremes…`,
  `…rejects_truncated_link_and_address_attributes`, `…kernel_*_route_kinds…`) в `route_parse_tests.rs`; там они
  FAIL (функций в `route_parse` нет).
- [ ] **Step 2: реализация** переноса и `NlSocket`. Ловушка: `sys("netlink dump", e)` печатает errno таблицей хоста —
  перенесённые тесты на Mac сверяют подстроку операции и вид ошибки, не текст ОС.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`; `unsafe_count` не больше, чем после задачи 10.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): one netlink decoder and one netlink socket`.

### Задача 12: переносимый адаптер Linux

Проверяет: Mac и `W-gate` (тесты `linux/tests.rs` теперь идут там), `L-gate`.

**Files:**
- Create: `src/linux/abi.rs` (номера errno Linux, `ARPHRD_ETHER`, `PACKET_OUTGOING`, без `libc`)
- Modify: `src/lib.rs` (`#[cfg(any(target_os = "linux", test))] mod linux;`), `src/linux/mod.rs` (`socket` и `route` —
  `#[cfg(target_os = "linux")]`, `open` — тоже), `src/linux/tests.rs`, `src/linux/layout_tests.rs`

**Interfaces:**
- Produces: `linux::abi::errno` — реэкспорт общих `adapter_common::errno::{EPERM, EACCES, ENXIO, ENODEV}` (задача 9)
  плюс `EINTR = 4, EIO = 5, EBADF = 9, EAGAIN = 11, EWOULDBLOCK = 11, EPROTO = 71, ENOPROTOOPT = 92, ENETDOWN = 100,
  ENOBUFS = 105`; `ARPHRD_ETHER: u16 = 1`, `PACKET_OUTGOING: u8 = 4`; `linux/layout_tests.rs` сверяет всё с `libc` на
  Linux (образец — `macos::abi`).
  `TxHalf`, `RxHalf`, `verify_binding`, шов `PacketIo` и `IfaceInfo` собираются на любой ОС в тестах.

- [ ] **Step 1:** `linux/tests.rs` переходит на `abi::errno::*` вместо `libc::*`; на Mac FAIL (модуль не собирается).
- [ ] **Step 2: реализация.** Ловушка: на Mac и Windows `errno_msg` печатает номер Linux таблицей хоста; тексты с
  errno сверяются только под `#[cfg(target_os = "linux")]`, переносимые тесты — по виду. Тест `error_texts_…` Linux
  строит ожидание той же функцией хоста и поэтому идёт везде.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`, `W-gate`; число тестов на Mac растёт на тесты Linux-адаптера.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): portable Linux adapter logic, tested on every OS`.

### Задача 13: пакетный приём Linux `recvmmsg`

Проверяет: Mac (фейк), `L-gate`; стенд: `U-RX` (ворота «ускорение» по CPU на принятый кадр, потери ядра не выше),
`U-TX` (без регрессии), матрица, `--suite rust`, дымовой прогон.

**Files:**
- Modify: `src/linux/mod.rs`, `src/linux/socket.rs`, `src/linux/tests.rs`, `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces: `const RX_BATCH: usize = 32`, `const RX_SLOT: usize = 2048`; `type SlotMeta = Result<RecvMeta, Errno>`
  (`Err(EPROTO)` — адрес короче `SLL_MIN_LEN`); в шове `PacketIo`: `fn recv_batch(&mut self, slots: &mut [u8], slot_len:
  usize, metas: &mut [SlotMeta]) -> Result<usize, Errno>` (≥ 1 или `Err`, пусто — `EAGAIN`). `recv` в шве остаётся
  (прямой путь).
- `PacketFd`: один примитив `recvmmsg` (`MSG_TRUNC`, таймаут NULL) и для `recv_batch` (32 слота), и для `recv` (один
  слот — буфер вызывающего); `recvfrom` уходит, число блоков `unsafe` не растёт. `iovec`, `msghdr`, `mmsghdr`,
  `sockaddr_ll` — литералы на стеке вызова. На каждое сообщение: `msg_namelen` выставляется перед вызовом и
  проверяется после (`< SLL_MIN_LEN` → `Err(EPROTO)` в слоте), длина — `msg_len` (истинная при `MSG_TRUNC`).
- `RxHalf`: внутреннее кольцо `RX_BATCH × RX_SLOT`. Если буфер вызывающего длиннее `RX_SLOT` — прямой путь (семантика
  длинных кадров та же). Иначе сначала выдаются кадры кольца; фильтры (`PACKET_OUTGOING`, чужой ifindex, длина больше
  буфера вызывающего), счётчики, `since_stats`, проверка дедлайна после отброшенного кадра — по одной записи, в том же
  порядке. Слот с `Err(EPROTO)` даёт фатальную ошибку с прежним текстом `recvfrom: …`, когда до него доходит очередь.
  Кадры в кольце при закрытии теряются (раньше они так же лежали в очереди сокета) — строка в doc-комментарии.
- Фейк: `recv_batch` берёт подряд `Ok`-кадры сценария до первой ошибки или `RX_BATCH`; ошибка в голове очереди —
  `Err`. Существующие сценарии RX работают без правок.

- [ ] **Step 1: тесты** `rx_batch_delivers_buffered_frames_without_a_syscall`,
  `rx_batch_mixed_records_match_the_per_frame_path` (Review Focus 1: в одной пачке исходящий, чужой ifindex, длинный,
  обычный и короткий адрес — порядок выдачи, счётчики и `recvfrom: …` на своей позиции равны явным ожиданиям, снятым
  с того же сценария на базе, где путь покадровый), `rx_caller_buffer_larger_than_a_slot_uses_the_direct_path`,
  `rx_batch_partial_fill_then_eagain_waits_until_the_deadline`,
  `health_between_batches_reads_fresh_drops_and_keeps_buffered_frames` (Review Focus 5). FAIL.
- [ ] **Step 2: реализация**; вся группа RX и `kernel_drops_*` зелёные без правки сценариев.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`; `unsafe_count` не больше, чем после задачи 12.
- [ ] **Step 4: стенд** — `U-RX`, `U-TX`, матрица, `--suite rust`, дымовой прогон; строка в `BENCHMARKS.md`.
- [ ] **Step 5: коммит**: `perf(rmasscan-net): Linux RX drains bursts with one recvmmsg`.

### Задача 14: чистка Windows — таблица маршрутов, телеметрия процесса, мелочи sendqueue

Проверяет: `W-gate` (код только Windows), Mac (переносимые `handle`, `adapter`, `loader` на фейке).

**Files:**
- Modify: `src/windows/sys.rs`, `src/windows/process.rs`, `src/windows/handle.rs`, `src/windows/adapter.rs`,
  `src/windows/loader.rs`, `src/windows/tests.rs`, `src/windows/tests/adapter_tests.rs`

**Interfaces:**
- `sys`: `fn forward_rows<T>(family: ADDRESS_FAMILY, label: &str, decode: fn(&MIB_IPFORWARD_ROW2) -> T) ->
  Result<Vec<T>, NetError>` — один `slice::from_raw_parts(base, NumEntries)` вместо цикла по индексу; `label`
  сохраняет тексты `GetIpForwardTable2 error {e}` и `GetIpForwardTable2(AF_INET6) error {e}`;
  `fn best_route_raw(to: &SOCKADDR_INET, label: &str) -> Result<Option<(MIB_IPFORWARD_ROW2, SOCKADDR_INET)>, NetError>`
  с текстами `GetBestRoute2 error {e}`/`GetBestRoute2(AF_INET6) error {e}`; `fwd_from_row`/`fwd6_from_row` берут
  `&MIB_IPFORWARD_ROW2` и держат `unsafe` только вокруг чтений объединения; `HMODULE` хранится через
  `expose_provenance`/`ptr::with_exposed_provenance_mut`; `os_version` без лишнего `clone`.
- `process`: снимок Toolhelp и токен — `OwnedHandle` (`HandleOrInvalid` для снимка), без ручного `CloseHandle`; один
  итератор идентификаторов потоков; `thread_count() = thread_ids().map(|v| v.len())` (оба `None` на пустом снимке).
- `handle`: `SendQueue.records` только под `#[cfg(test)]`; `c_int::from(bool)`; `send_raw -> Result<(), c_int>`,
  `get_nonblock -> Result<bool, c_int>` (`Ok(v == 1)` для неотрицательного, иначе `Err`); проверка длины одного кадра
  пачки — один раз; `loader::sha256_hex` пишет `write!`; устаревшие `cfg_attr(not(test), allow(dead_code))` на трёх
  аксессорах `NpcapApi` и их комментарий удаляются.

- [ ] **Step 1: тесты** (Windows) `forward_rows_decode_a_synthetic_table_for_both_families` (буфер `#[repr(C)]` с
  заголовком и двумя строками каждой семьи), `thread_ids_contain_the_current_thread`,
  `thread_count_equals_thread_ids_len`; (Mac, фейк) `one_frame_batch_checks_the_length_once` (неверная длина: ровно
  один `tx_errors`). FAIL там, где проверяется новое.
- [ ] **Step 2: реализация.**
- [ ] **Step 3: PASS** `M-gate`, `W-gate`; `unsafe_count` меньше, чем после задачи 13.
- [ ] **Step 4: коммит**: `refactor(rmasscan-net): Windows route table, process probes and sendqueue tidy-up`.

### Задача 15: P1 — пакетная отправка Linux `sendmmsg`

Проверяет: Mac (фейк), `L-gate`; стенд: `U-TX` (ворота «ускорение» по pps), сравнение с C, матрица 40/40,
`--suite rust` (пауза и продолжение: склейка захватов равна непрерывному), дымовой прогон.

**Влияние на лабораторию (проверено чтением на базе).** Код `rmasscan-lab` правок не требует: Linux-набор
`wire_suite.rs` сверяет `tx_sent == sent`, `tx_uncertain == 0`, `tx_errors == 0` и границы паузы, а не `tx_mode` или
`tx_batches`; правила `verify.rs::sendqueue_identity` действуют только для каталогов Windows с `tx_mode_expected` в
манифесте; `examples/wire_scan.rs` уже режет пачку ровно на `--pause-after` (`HarnessTx::send_batch`) и печатает режим
из `OpenedAdapter.tx_mode`. Видимое следствие: идентичность Linux-прогонов `wire_scan` становится
`"tx_mode":"sendqueue","tx_batch_cap":64`, `net.tx_batches`/`tx_batch_max` ненулевые. Studio и CLI `tx_mode` не читают.

**Files:**
- Modify: `src/linux/mod.rs`, `src/linux/socket.rs`, `src/linux/tests.rs`, `src/lib.rs` (доки `TxMode::SendQueue`:
  «Windows — Npcap sendqueue, Linux — `sendmmsg`»; `tx_batches`, `tx_batch_max`: Linux считает вызовы `send_batch` с
  n ≥ 2, macOS — по-прежнему 0), `rmasscan/README.md` (раздел «Лабораторная приёмка
  Linux (2B)»: Linux шлёт пачками до 64 кадров одним `sendmmsg`, пауза и остановка — с точностью до пачки),
  `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md` (строка 239: датированная пометка «позже,
  2026-11: Linux шлёт пачками `sendmmsg`, см. `rmasscan/BENCHMARKS.md`»; исторический текст не переписывается),
  `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces: `linux::TX_BATCH_FRAMES: usize = 64`; `open` возвращает `tx_mode: TxMode::SendQueue { max_batch:
  TX_BATCH_FRAMES }`; шов `PacketIo::send_many(&mut self, frames: &[&[u8]], lens: &mut [usize]) -> Result<usize,
  Errno>` — число принятых сообщений k ≥ 1 (ошибка первого — `Err`), `lens[j]` — байты сообщения j.
- `PacketFd::send_many`: один блок `unsafe` — `sendmmsg(fd, msgs, n, MSG_NOSIGNAL)`; массивы `iovec`/`mmsghdr` на стеке
  вызова (сырые указатели не хранятся в `PacketFd`, он остаётся `Send`); `SAFETY`: срезы кадров живы весь вызов, ядро
  их только читает и пишет `msg_len`.
- `TxHalf::max_batch() = TX_BATCH_FRAMES`; `send_batch(frames, timeout)`:
  - пусто или больше `TX_BATCH_FRAMES` → `Err` с текстами Windows (`send_batch called with no frames; nothing was
    sent`, `send_batch called with N frames, more than 64; nothing was sent`); n == 1 → прежний `send`;
  - один `Deadline` на весь вызов; цикл с первого неотправленного кадра i: `send_many(&frames[i..])` → k: если
    `lens[j] != len` при j < k → `TxBatch { sent: i + j, rest: Uncertain }`; иначе i += k, при i == n → `Sent`, иначе
    сразу повтор с i (повтор возвращает настоящий errno, который ядро теряет при k ≥ 1). `EAGAIN` — `poll(POLLOUT)` до
    дедлайна, по истечении `WouldBlockUnsent`; EINTR — пауза ≤ 1 мс; иная ошибка при i == 0 — как одиночный путь
    (`Err`, текст `send: …`, fd закрывается), при i > 0 — `Ok(TxBatch { sent: i, rest: Uncertain })`, fd закрывается
    (как цикл `Tx::send_batch` по умолчанию);
  - счётчики (задача 2): `tx.sent.add(sent)`; исход `rest`, отличный от `Sent`, — одна запись `tx.record(rest)`;
    фатальная ошибка — `tx.errors.inc()` без записи `uncertain`; `tx.batches.inc()` и `tx.batch_max.max(n)` на каждый
    вызов с n ≥ 2, в котором выполнен хотя бы один `sendmmsg`; `tx_over_budget` на Linux по-прежнему 0.

- [ ] **Step 1: тесты** `tx_batch_of_n_is_one_sendmmsg_and_counts_one_batch`, `tx_batch_of_one_uses_plain_send`,
  `tx_batch_frames_reach_the_socket_in_order_unchanged`, `tx_partial_sendmmsg_reissues_from_the_first_unsent_frame`,
  `tx_batch_lost_error_is_resolved_by_reissue_within_one_deadline` (Review Focus 2: k = 3 из 8 без ошибки, затем
  `EAGAIN` навсегда → `TxBatch { sent: 3, rest: WouldBlockUnsent }`, сумма `poll_ms` ≤ 50),
  `tx_batch_fatal_after_a_prefix_is_prefix_then_uncertain_and_closes`, `tx_batch_fatal_first_is_err_like_single`,
  `tx_batch_short_message_is_uncertain_at_that_frame`, `tx_batch_whole_call_respects_one_deadline`,
  `tx_batch_rejects_empty_and_oversized`, `tx_batch_invariant_sent_eq_n_iff_sent` (перебор сценариев),
  `tx_batch_counters_match_the_single_path_accounting`. FAIL.
- [ ] **Step 2: реализация**, доки `lib.rs`; `unsafe_count` = значение после задачи 14 + 1.
- [ ] **Step 3: PASS** `M-gate`, `L-gate`; `examples/wire_scan.rs` тесты зелёные.
- [ ] **Step 4: стенд** — `U-TX` против базы и C, матрица, `--suite rust`, дымовой прогон; README, пометка в отчёте
  sendqueue, строка в `BENCHMARKS.md`. При провале ворот — правило раздела «Замеры».
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
- `loader`: `unsafe trait Module` получает `fn wait_object(&self) -> WaitFn` (контракт трейта: функция ведёт себя как
  `WaitForSingleObject`); `OsModule` отдаёт `WaitForSingleObject` из `windows-sys` (фича `Win32_System_Threading` уже
  включена), фейк — `fake::f_wait`. `NpcapApi::rx_event(&self) -> Option<(GetEventFn, WaitFn)>` — `Some`, только если
  `pcap_getevent` разрешился (как `pcap_init`).
- `handle`: `PcapHandle::wait_readable(&mut self, ms: u32) -> EventWait`, `enum EventWait { Signaled, TimedOut,
  Unavailable, Failed(u32) }`; событие берётся у `pcap_t` при первом ожидании и не закрывается (им владеет `pcap_t`;
  `SAFETY` у `unsafe impl Send for PcapHandle` дополняется).
- `adapter`: `const EVENT_SLACK: Duration = Duration::from_millis(16)` (такт таймера Windows по умолчанию 15,625 мс;
  спайк может уменьшить). `RxHalf::wait`: если событие есть и остаток `left > EVENT_SLACK` — ждать
  `(left - EVENT_SLACK)` в мс вниз; `Signaled`/`TimedOut` → снова `pcap_next_ex`; `Unavailable` или `Failed` →
  событие этой половины выключается до конца, дальше прежний опрос (сон 1 мс, `yield_now` ниже 3 мс). Последние
  `EVENT_SLACK` всегда идут прежним опросом, поэтому бюджет 42 мс держится при любом такте таймера.
- Новые блоки `unsafe` (ровно 3): `transmute` адреса `pcap_getevent` в `loader`, вызов `pcap_getevent` и вызов
  `WaitFn` в `handle`.

- [ ] **Step 1: тесты** (фейк, Mac) `pcap_getevent_is_optional_not_required`,
  `missing_or_null_event_falls_back_to_one_ms_polling` (Review Focus 3: без символа и с NULL-событием — ни одного
  вызова ожидания, `recv` как раньше), `event_wait_never_asks_past_the_slack` (таймауты 50, 42, 20, 5 мс: запрошено
  ≤ `left - EVENT_SLACK`, при остатке ≤ `EVENT_SLACK` ожиданий нет), `signalled_event_delivers_the_frame_without_sleeping`,
  `wait_failure_disables_the_event_for_this_half`, `idle_recv_with_event_returns_within_the_budget` (только верхняя
  граница: < 50 мс). FAIL.
- [ ] **Step 2: реализация**; `unsafe_count` = значение после задачи 15 + 3.
- [ ] **Step 3: PASS** `M-gate`, `W-gate`.
- [ ] **Step 4: спайк на VM** (`#[ignore] live_rx_event_wait_budget_latency_and_idle_cpu` в `src/windows/live.rs`,
  окружение и стенд — как у живых тестов этого файла): длительность пустого `recv(50 мс)` (p50, p99.9, max на ≥ 2000
  вызовов), задержка выдачи кадра от его прихода, CPU RX-потока за 10 с простоя; режимы «опрос» и «событие»; условия
  «тихо» и «поток мусора» (свои кадры); 3 повтора. Ворота: max < 50 мс и p99.9 ≤ 43 мс в обоих условиях, CPU простоя
  ниже опроса, медиана задержки не хуже. `EVENT_SLACK` — наименьшее из 16/8/4/2 мс, прошедшее ворота во всех повторах.
  Итог в `BENCHMARKS.md`. Провал при 16 мс — правило раздела «Замеры».
- [ ] **Step 5: коммит**: `perf(rmasscan-net): Windows RX waits on the Npcap read event (P2)`.

### Задача 17: P3 — настройка TX-сокета Linux

Проверяет: Mac (фейк после задачи 12), `L-gate`; стенд: замер `EAGAIN`, `U-TX`, матрица, `--suite rust`.

**Files:**
- Modify: `src/linux/mod.rs`, `src/linux/socket.rs`, `src/linux/tests.rs`, `rmasscan/README.md`,
  `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Consumes: `unix_sys::setsockopt_int` (задача 6) — новых блоков `unsafe` нет.
- `ENOBUFS` в одиночном и пакетном TX: ядро не приняло кадр (qdisc или драйвер его отбросили) — пауза
  `min(1 мс, остаток)` и повтор до дедлайна, по истечении `WouldBlockUnsent` (раньше — фатальная `send: …`).

- [ ] **Step 1: замер частоты `EAGAIN`** на HEAD: `U-TX` под `perf trace -s -p <pid>` (нет `perf` — `strace -c -f -p
  <pid>` с пометкой, что он искажает темп): число `poll` потока TX на 1000 отправленных кадров, `ss -0 -m`
  (фактический `tb`). Числа в заметки и `BENCHMARKS.md`.
- [ ] **Step 2: `SO_SNDBUF`** — только если `poll` потока TX ≥ 1 на 1000 кадров: TX-сокет просит 4 МиБ
  (`setsockopt_int`, отказ игнорируется, ядро режет до `wmem_max`); `U-TX` против шага 1 (ворота «ускорение»); иначе
  шаг пропускается с записью числа.
- [ ] **Step 3: тесты `ENOBUFS`** `tx_enobufs_storm_backs_off_and_ends_unsent_at_the_deadline` (Review Focus 4: каждая
  пауза ≤ 1 мс, сумма ≤ таймаута, исход `WouldBlockUnsent`, `tx_would_block` 1) и
  `tx_batch_enobufs_after_a_prefix_is_retried_like_eagain`. FAIL → реализация → PASS (`M-gate`, `L-gate`). README:
  `ENOBUFS` больше не обрывает скан.
- [ ] **Step 4: `PACKET_QDISC_BYPASS`** на TX-сокете (`setsockopt_int`, отказ игнорируется), только после шага 3;
  `U-TX` (ворота «ускорение»), матрица, `--suite rust`. Прошло — README: «qdisc интерфейса скана обходится, шейпинг
  `tc` на нём не действует»; нет — правка откатывается, отрицательный замер в `BENCHMARKS.md`.
- [ ] **Step 5: коммиты** — по одному на сохранённый шаг: `perf(rmasscan-net): larger Linux TX socket buffer (P3)`,
  `fix(rmasscan-net): ENOBUFS on Linux TX is unsent, not fatal (P3)`, `perf(rmasscan-net): Linux TX bypasses the qdisc
  (P3)`.

### Задача 18: приёмка ветки

Проверяет: все три ОС, стенд, Studio.

- [ ] **Step 1:** `M-gate` плюс `cargo test --locked --workspace` и `cargo clippy --locked --workspace --all-targets
  -- -D warnings` на Mac; `L-gate` и `W-gate` плюс `cargo test --locked --workspace` на хосте и в госте.
- [ ] **Step 2: Studio** без правок: `cd studio && CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rmasscan-native-net-studio"
  cargo check --locked && CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rmasscan-native-net-studio" cargo xtask test`.
- [ ] **Step 3: границы правок:** `git diff --stat a275ea9e -- . ':!rmasscan/crates/rmasscan-net'
  ':!rmasscan/README.md' ':!rmasscan/BENCHMARKS.md' ':!rmasscan/docs/macos-feth-lab.md'
  ':!docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md' ':!docs/superpowers'` пуст; `Cargo.lock`
  и `studio/Cargo.lock` без изменений; `git diff a275ea9e -U0 | grep '^+' | hygiene` пуст; `unsafe_count` итоговый и
  разбивка по файлам — в заметки.
- [ ] **Step 4: стенд** — ячейка `U` HEAD против `a275ea9e` (C для справки), матрица, `--suite rust`, дымовой прогон;
  итоговая строка в `BENCHMARKS.md`.
- [ ] **Step 5:** удалить деревья `~/rnn/*` и `/tmp/rnn-target` на хосте, распакованные деревья и `rnn-target` в
  госте, `CARGO_TARGET_DIR` на Mac; `ps -Ao pid,%cpu,etime,command | awk '$2>80'` — своих процессов нет.
- [ ] **Step 6:** коммит `BENCHMARKS.md`: `docs(rmasscan): native-Rust phase 1 results for rmasscan-net`; финальное
  ревью ветки; push и PR — только с согласия пользователя.
