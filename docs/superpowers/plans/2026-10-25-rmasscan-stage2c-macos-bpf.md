# Rust masscan: 2C-macOS / BPF — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** получить macOS-адаптер raw I/O на `/dev/bpf*` (Apple Silicon) с настоящим SYN TX/RX,
честным RX health, доказанными Stop и pause/resume на запечатанном `feth`-стенде на Mac
разработчика, с тем же стандартом доказательств, что части A, B и C приёмки Windows VM.

**Architecture:** сохранить net → engine → core и публичный
`open_explicit(&AdapterBinding) -> Result<OpenedAdapter, NetError>`. Новый `net::macos`
открывает два отдельных дескриптора `/dev/bpfN` (TX и RX) через `libc` и реализует те же
`AdapterPair` / `Tx` / `Rx` / health контракты, что `src/linux/` и `src/windows/`. Engine, cookie,
порядок probe и checkpoint не меняются. Лабораторный стенд это Rust-подкоманды `rmasscan-lab`
(`macos-lab`, `macos-suite`, `macos-verify`); привилегированные действия выполняет только
пользователь, явно и с отменой.

**Tech Stack:** Rust 1.99.1, существующий workspace, `libc = 0.2.191` (только объявления FFI,
C не компилируется), ioctl-константы BPF из `libc` и из SDK-заголовка
`/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/bpf.h` (только как
источник ABI для сверки), системные `ifconfig`/`route`/`arp`/`netstat`/`tcpdump` как внешние
инструменты ОС.

**Spec:** [Rust-порт](../specs/2026-10-23-masscan-rust-port-design.md) (§5.1–5.3 строки 358–410,
§6, таблица этапов строка 609, риск macOS строка 707), [контракты 2A](2026-10-23-rmasscan-stage2a-engine.md),
[план Linux](2026-10-23-rmasscan-stage2b-linux.md), [план Windows](2026-10-24-rmasscan-stage2b-windows.md),
[план Windows VM](2026-10-24-rmasscan-windows-vm-next-stage.md),
[приёмка Windows VM](../../experiments/2026-10-24-rmasscan-windows-vm-acceptance.md) (§9 ограничения, §12 дефекты CI-only),
[перечень готовности](../../experiments/2026-10-24-rmasscan-readiness.md), [Rust-лаборатория](../../../rmasscan/docs/rust-lab.md).

Репозиторий: `$REPO` (рабочий worktree Mac), ветка `feat/rmasscan-stage2c-macos-bpf`
от `main` `2cc2bec` (2B-Linux и 2B-Windows слиты 2026-10-25). Windows VM correctness GO на запечатанном
QEMU-стенде. Репозиторий Rust-only по решению пользователя, включая лабораторные инструменты.

## Исходное состояние и порядок

- Код macOS отсутствует: `open_explicit` на macOS возвращает `NetError::UnsupportedPlatform`
  (`rmasscan-net/src/lib.rs`, строки 198–202); `inventory()`, `nic_mac()`, `os_version()`,
  `process_sample()`, `lab_thread_ids()` на macOS возвращают `Err`/`None`.
- Mac разработчика (замер 2026-10-25, только чтение): macOS **27.0.1** (сборка 26A434), `arm64`;
  `/dev/bpf0..3` существуют, `crw------- root wheel` (0600); `debug.bpf_maxbufsize = 524288`,
  `debug.bpf_maxdevices = 256`; `net.inet.ip.forwarding = 0`; `sysctl net.link.fake.*` присутствует
  (драйвер `if_fake`, то есть `feth` доступен; `net.link.fake.hwcsum = 0`); `tcpdump 4.99.1 (Apple 161)`,
  `libpcap 1.10.1`; uplink по умолчанию `en0`, шлюз `192.168.1.1`; пользователь в группах `staff`, `admin`.
  Crate `libc 0.2.191` на apple объявляет `BIOCGBLEN/BIOCSBLEN/BIOCFLUSH/BIOCPROMISC/BIOCGDLT/BIOCGETIF/
  BIOCSETIF/BIOCGSTATS/BIOCIMMEDIATE/BIOCVERSION/BIOCGHDRCMPLT/BIOCSHDRCMPLT`, `ifreq`, `sockaddr_dl`,
  `timeval32`, `getifaddrs`, `if_nametoindex`, `sysctlbyname`, `proc_pidinfo`, `pthread_threadid_np`,
  но **не** объявляет `bpf_hdr`, `bpf_insn`, `bpf_program`, `bpf_stat`, `BIOCSETF`, `BIOCSETFNR`,
  `BIOCSSEESENT`, `BIOCGSEESENT`, `BIOCSRTIMEOUT`: их объявляет Задача 1.
- Спека называет целью macOS 14+; измерения этого этапа относятся к **macOS 27.0.1 на Apple Silicon**.
  CI `macos-14` даёт только сборку и офлайн-тесты. Утверждение «работает на macOS 14» этим планом не выдаётся.

Порядок: **0 — контракты и база → 1 — ABI и сведения об интерфейсе → 2 — стенд `macos-lab` →
(действие пользователя: `up`) → 3 — спайк STOP/GO → 4 — адаптер → 5 — harness и метрики →
6 — suite, verifier, фикстуры → 7 — живая приёмка A/B/C → 8 — отчёт, CI, GO**. Пока стенд не
поднят пользователем, выполняются только офлайн-части; приёмка raw I/O остаётся NOT RUN и CI-сборкой
не подменяется.

## Global Constraints

- **Pure Rust.** Никакого C, C++, Python, Swift ни в репозитории, ни в инструментах. FFI-объявления
  `libc` допустимы (C не компилируется). `unsafe` только в `rmasscan-net`, в private-модулях
  `macos::{sys, ifinfo, process}` под `#[allow(unsafe_code)]`, каждый `unsafe`-блок с комментарием `SAFETY`;
  `lib.rs` сохраняет `deny(unsafe_code)`, `deny(unsafe_op_in_unsafe_fn)`, `deny(clippy::undocumented_unsafe_blocks)`.
  Репозиторный language guard (`scripts/language-guard.sh`, allowlist) остаётся PASS; новые типы файлов
  в evidence только из allowlist (`json pcap gz txt csv log err sha256 md`). **Никогда не запускать python или
  python3 ни в каком виде** (ни `python -c`, ни `python3 -m`, ни через `env`, ни в тестах, ни «для проверки
  JSON»): агенты оступались трижды. Это правило повторяется в каждой задаче.
- **Живые кадры только на запечатанном стенде.** На Mac это пара `feth4201` (сторона сканера) ↔
  `feth4202` (сторона пира), созданная пользователем командой `macos-lab up`: без uplink, без bridge,
  без IP на `feth4201`, без маршрутов наружу, без изменения default route, DNS, firewall (pf) и
  реальных NIC. Сканируется только `198.18.0.2`. Каждый живой прогон сопровождается захватом на uplink
  (интерфейс default route, сейчас `en0`) с фильтром лаборатории; в нём должно быть **0 кадров**, как `eno1`
  на Windows. Кадр лаборатории на uplink это FAIL без права повтора.
- **Привилегии.** `/dev/bpf*` по умолчанию `0600 root:wheel`; создание `feth` требует root. Агенты пароль не
  вводят и `sudo` не вызывают. Все привилегированные действия перечислены в разделе «Действия пользователя»
  и выполняются пользователем (в сессии с префиксом `!`), каждое с командой отмены. Постоянных изменений
  системы нет: `feth` и права на `/dev/bpf*` не переживают перезагрузку; `down` возвращает всё явно.
- **Правила доказательств, как на Windows:** свидетель захвата на стороне пира (`tcpdump` на `feth4202`);
  шлюз на каждый прогон (стенд проверен `macos-lab status` до и после, nonce, статус); неполный захват это
  INVALID, отсутствующий результат это NOT RUN, повышение до PASS невозможно; sha256 каждого артефакта
  записывается в момент его закрытия в рабочем каталоге **до** копирования в каталог доказательств и
  сверяется после; байтовый паритет SYN с закреплённым C masscan `8e6b3b0`. C собирается и выполняется
  **только на minipc** (Ubuntu); фикстуры для binding Mac снимаются там же, как для Windows.
- **Уроки, обязательные в каждой задаче:** каждый агент работает в приватном
  `CARGO_TARGET_DIR` (например `export CARGO_TARGET_DIR=$(mktemp -d /tmp/rmasscan-target-XXXXXX)` один раз на
  задачу); каталоги доказательств байтово точны (`docs/experiments/** -text` уже в `.gitattributes`);
  тесты не зависят от точности `sleep`, не используют время для уникальных имён (суффикс из `getrandom`),
  не ждут немедленного освобождения `flock`, не читают события конкурентно в тестах переполнения; перед push
  полный `cargo test --locked --workspace` на всех трёх ОС; CI (`ubuntu-24.04`, `macos-14`, `windows-2022`)
  зелёный на точном HEAD для GO.
- Runtime остаётся: IPv4/TCP, NIC=1, TX=1, RX=1, shard=1/1, retries=0, BlackRock rounds=14; seed ненулевой.
  Source IP/MAC явные; владение source IP интерфейсом не проверяется (как на Linux/Windows).
- I/O deadline ≤50 мс (абсолютный); Stop ≤1 с; Pause прекращает TX ≤1 с и ждёт RX drain `wait` (приёмка с
  wait=3). Только `Sent` двигает cursor; `Uncertain` → Failed без checkpoint и без повтора;
  `WouldBlockUnsent` только когда кадр точно не отправлен.
- Promiscuous mode не включается. Ответы приходят на MAC интерфейса; `source_mac`, отличный от MAC
  `feth4201`, без promiscuous ответов не получит (ограничение, не скрытая настройка), как на Windows.
- Никакого автоматического выбора адаптера, маршрута или MAC в продукте; discovery/ARP, sendqueue,
  runner, UI в этот этап не входят.

## Review Focus

1. **Короткое замыкание стека хоста.** Оба `feth` живут в одном ядре: SYN-ACK пира может не дойти до BPF
   на `feth4201`, ядро может ответить RST за сканера, статический ARP может не примениться. Проверяется
   спайком до адаптера; стенд считается рабочим только после честного SYN-ACK/RST в захвате — задачи 2/3.
2. **Разбор буфера BPF.** `bpf_hdr` на LP64 содержит `timeval32` (8 байт), `bh_hdrlen` на проводе 20;
   неверное смещение или доверие `sizeof` даёт мусор вместо кадров. Смещения проверяются тестами
   раскладки и живым первым кадром; продвижение только по `bh_hdrlen` и `BPF_WORDALIGN(4)` — задачи 1/3/4.
3. **Свои кадры и переполнение.** RX не должен видеть собственные TX (`BIOCSSEESENT 0` плюс фильтр
   `not ether src` плюс программная проверка MAC), TX-дескриптор не должен копить захват (`ret #0`);
   `bs_drop` обязан быть `Some(n)` кумулятивно с начала попытки, ошибка `BIOCGSTATS` это `Err`, а не ноль — задачи 3/4.
4. **Исход записи.** `write()` в BPF: полная запись → `Sent`; `ENOBUFS`/`EAGAIN` → кадр точно не ушёл →
   `WouldBlockUnsent` с ограниченным повтором до дедлайна; частичная запись → `Uncertain`; `EINTR` до
   первого байта → повтор без продления дедлайна. Нельзя выводить статус из текста ошибки — задача 4.
5. **Шлюз доказательств.** Статус стенда до/после, uplink 0 кадров, хэши до копирования, INVALID/NOT RUN
   никогда не PASS, `perm_denied` без единого кадра, фикстуры C с тем же binding без нормализации — задачи 2/6/7.

## Карта файлов

- Изменить `rmasscan/crates/rmasscan-net/src/lib.rs`: cfg-диспетчер `macos`, `BPF_ABI_ID`,
  `BpfInventory`/`inventory_bpf()`, `nic_mac`/`os_version`/`process_sample`/`lab_thread_ids`/
  `lab_current_thread_id` для macOS; существующие типы сохраняются.
- Создать `rmasscan/crates/rmasscan-net/src/macos/{mod,sys,ifinfo,adapter,process,tests}.rs` и
  `src/macos/tests/{fake,adapter_tests,layout_tests}.rs`; `src/macos/spike.rs` (`cfg(all(target_os = "macos", test))`, все `#[ignore]`).
- Создать `rmasscan/crates/rmasscan-net/src/drop_counter.rs` (общий `DropCounter`, перенос из
  `windows/handle.rs` без изменения поведения).
- Создать `rmasscan/crates/rmasscan-net/tests/macos_live.rs` (opt-in, `#[ignore]`, через публичный API и Engine).
- Изменить `rmasscan/crates/rmasscan-net/examples/wire_scan.rs`, `examples/support/{mod,metrics}.rs`:
  macOS-инвентарь, идентичность, метрики процесса.
- Создать `rmasscan/crates/rmasscan-lab/src/{macos_lab,macos_suite,macos_verify}.rs` и их тесты;
  изменить `lib.rs`, `main.rs`, `link.rs` (MAC интерфейса на macOS), `dump.rs` (`Probe` через `netstat`,
  argv `tcpdump` для macOS), `peer.rs` (`counters` на macOS), `oracle.rs` (`--src-mac`).
- Создать `rmasscan/docs/macos-feth-lab.md` (руководство оператора и пользователя).
- Создать `docs/experiments/2026-10-25-rmasscan-macos-bpf-baseline.md`,
  `docs/experiments/2026-10-25-rmasscan-macos-bpf-spike.md` + `-spike-raw/`,
  `docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md` + `-acceptance-raw/{fixtures,functional-r1,failure-r1,perf-r1}`.
- Изменить `.github/workflows/rmasscan.yml` (комментарий о macOS; шаг `cargo test -p rmasscan-net` уже покрывает
  seam-тесты macOS), `docs/experiments/2026-10-24-rmasscan-readiness.md` (строка macOS).

## Константы стенда (единые для всех задач)

| Параметр | Значение |
| --- | --- |
| Интерфейс сканера (A) | `feth4201`, MAC `02:ac:00:00:00:01`, без IPv4-адреса, `up` |
| Интерфейс пира (B) | `feth4202`, MAC `02:ac:00:00:00:02`, `inet 198.18.0.2/30`, `up`, `peer feth4201` |
| Source IP сканера | `198.18.0.1` (никому не назначен; статический ARP `198.18.0.1 → 02:ac:00:00:00:01` на `feth4202`) |
| Цель | только `198.18.0.2` |
| Открытые порты пира | `80,443,8000-8007` (как Windows); остальные дают RST ядра |
| seed / rate / wait / retries | 1 / 100 / 3 / 0 (part C: rate 100, 1000, 10000, 100000) |
| Фильтр захвата uplink | `net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host 02:ac:00:00:00:01 or ether host 02:ac:00:00:00:02 or ether proto 0x88b5` |
| Манифест стенда | `$HOME/.rmasscan-lab/macos-m1.json` (`--run-id m1`) |
| Доступ к BPF | `/dev/bpf0..15` → `0660 root:staff` на время сессии (`macos-lab bpf-access --grant`), обратно `0600 root:wheel` (`--revoke`, `down`, перезагрузка) |

## Задача 0. Контракты и база macOS

**Files:** создать `docs/experiments/2026-10-25-rmasscan-macos-bpf-baseline.md`. Кода нет.

**Constraints:** приватный `CARGO_TARGET_DIR`; никаких `sudo`, raw-сокетов, `ifconfig create`; **никакого python/python3**.

**Контракты, которым обязан удовлетворять macOS-адаптер** (источник: `rmasscan-engine/src/io.rs`,
`src/linux/mod.rs`, `src/windows/adapter.rs`, спека §0.1 cross-platform):

- `Rx::health(timeout) -> Result<RxHealth, IoError>` обязателен. `kernel_drops: Option<u64>` кумулятивно с
  начала попытки; `None` значит «измерить нельзя» и не превращается в 0. `Completed`/`Stopped`/`Paused`
  возможны только при подтверждённом `Some(0)`; с `None` каждый запуск заканчивается
  `Failed(RxStatsUnavailable)`. Источник на macOS: `BIOCGSTATS.bs_drop` RX-дескриптора (кумулятивный с
  открытия, чтение не сбрасывает, `u32` оборачивается) с базовым значением, снятым при открытии; это
  **нижняя граница** (потери ниже BPF не видны), как `ps_drop` NPF и `PACKET_STATISTICS`.
- Потеря RX даёт `FailReason::RxLoss { kernel_drops }`, ошибка запроса статистики даёт
  `FailReason::RxError(String)`; все без checkpoint. Проверка каждые ~250 мс по часам engine и обязательно
  перед исходом.
- TX stall: `EngineOptions::tx_stall_timeout` по умолчанию 10 с; `WouldBlockUnsent` не продвигает курсор;
  итог `FailReason::TxStalled { idle_millis }` без checkpoint. Адаптер возвращает `WouldBlockUnsent` только
  когда кадр точно не отправлен (`ENOBUFS`, `EAGAIN`, `EINTR` до первого байта).
- Каждый вызов `send`/`recv`/`health` возвращается не позже `min(timeout, MAX_IO_TIMEOUT = 50 мс)` по
  абсолютному дедлайну, фиксированному один раз на вызов; мусор, `EINTR` и ложные пробуждения его не продлевают.
- Только `Sent` двигает cursor; неопределённый результат → `Uncertain` → Failed без повтора; Stop ≤1 с; Pause
  останавливает TX ≤1 с, затем RX drain `wait`; новая попытка resume имеет новый attempt_id.
- Часы: engine и адаптер используют `std::time::Instant` (на macOS `CLOCK_UPTIME_RAW`: не идёт во сне, не идёт
  назад; `rmasscan-core/src/throttle.rs`, строка 33). Метки времени pcap это стенные часы (`bpf_hdr.bh_tstamp`
  в микросекундах). Поведение при sleep/wake Mac в этом этапе **NOT RUN** (Mac не усыпляется).

- [ ] Прочитать `rmasscan-engine/src/io.rs`, `src/linux/{mod,socket}.rs`, `src/windows/{adapter,handle}.rs`,
  `rmasscan-engine/src/fake.rs`; выписать в baseline список контрактов выше со ссылками на строки кода
  (не пересказ, а проверенные места: `Deadline`, `TxStep`, `RxStep`, `DropCounter`, `publish_drops`).
- [ ] Снять базу Mac только чтением: `sw_vers`, `uname -m`, `ls -l /dev/bpf*`, `sysctl debug.bpf_maxbufsize
  debug.bpf_maxdevices net.inet.ip.forwarding net.link.fake.hwcsum`, `tcpdump --version`, `route -n get default`,
  `ifconfig -l`, `id -Gn`, `rustc --version`; записать значения и команды.
- [ ] Выполнить на Mac в приватном `CARGO_TARGET_DIR`: `cargo fmt --all --check`, `cargo clippy --locked --workspace
  --all-targets -- -D warnings`, `cargo test --locked --workspace`, `bash scripts/language-guard.sh`; записать коды
  выхода и строки `test result`. Подтвердить тестом (существующим или чтением кода), что `open_explicit` на macOS
  сейчас даёт `UnsupportedPlatform`.
- [ ] Записать, что Windows GO достигнут на VM, что физический NIC Windows и macOS не измерены, и что этот этап
  измеряет **один** Mac (macOS 27.0.1, Apple Silicon), а не «macOS 14+».
  Commit: `docs(net): macOS BPF stage baseline and adapter contracts`.

**GREEN:** документ существует, все значения с командами, три проверки rc 0, language guard PASS.

## Задача 1. ABI BPF, сведения об интерфейсе и инвентарь без привилегий

**Files:** создать `rmasscan/crates/rmasscan-net/src/macos/{mod,sys,ifinfo}.rs`, `src/macos/tests/layout_tests.rs`;
изменить `src/lib.rs`.

**Constraints:** приватный `CARGO_TARGET_DIR`; `unsafe` только в `macos::sys` и `macos::ifinfo` с `SAFETY`;
ни одного `open("/dev/bpf*")` в этой задаче (инвентарь только `stat`); никаких `sudo`; **никакого python/python3**.

**Interfaces:**

```rust
// lib.rs (все платформы)
pub const BPF_ABI_ID: &str = "/dev/bpf* ioctl via libc; own declarations v1; aarch64";
#[derive(Debug, Clone, PartialEq, Eq)] pub struct BpfDevice { pub path: String, pub mode: u32, pub uid: u32, pub gid: u32 }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct IfaceReport { pub name: String, pub index: u32, pub mac: Option<[u8; 6]>, pub ethernet: bool, pub up: bool, pub ipv4: Vec<std::net::Ipv4Addr> }
#[derive(Debug, Clone, PartialEq, Eq)] pub struct BpfInventory { pub os_version: Option<String>, pub kernel_version: Option<String>, pub bpf_maxbufsize: Option<u32>, pub bpf_maxdevices: Option<u32>, pub devices: Vec<BpfDevice>, pub interfaces: Vec<IfaceReport>, pub instant_clock: &'static str }
pub fn inventory_bpf() -> Result<BpfInventory, NetError>;   // macOS; остальные UnsupportedPlatform
// macOS: nic_mac(name) -> Option<[u8;6]>; os_version() -> Some("27.0.1 (26A434)")
// macos::ifinfo (crate): trait IfaceInfo { fn ifindex(&self, name: &str) -> Result<Option<u32>, Errno>; fn link(&self, name: &str) -> Result<Option<LinkInfo>, Errno>; }
// struct LinkInfo { pub sdl_type: u8, pub mac: Option<[u8; 6]> }; fn verify_binding(q: &dyn IfaceInfo, b: &AdapterBinding) -> Result<u32, NetError>
```

`macos::sys` объявляет (private, `#[repr(C)]`): `BpfHdr { bh_tstamp: libc::timeval32, bh_caplen: u32, bh_datalen: u32, bh_hdrlen: u16 }`,
`BpfInsn { code: u16, jt: u8, jf: u8, k: u32 }`, `BpfProgram { bf_len: u32, bf_insns: *mut BpfInsn }`,
`BpfStat { bs_recv: u32, bs_drop: u32 }`; константы `BIOCSETF = 0x8010_4267`, `BIOCSETFNR = 0x8010_427e`,
`BIOCSSEESENT = 0x8004_4277`, `BIOCGSEESENT = 0x4004_4276`, `BIOCSRTIMEOUT = 0x8010_426d`; `DLT_EN10MB = 1`,
`DLT_NULL = 0`, `IFT_ETHER = 0x06`, `BPF_ALIGNMENT = 4`, `fn bpf_wordalign(x: usize) -> usize`; остальные BIOC из `libc`.

- [ ] Red: `layout_tests.rs` (cfg `target_os = "macos"`): `size_of::<BpfHdr>() == 18`, `offset_of!(BpfHdr, bh_caplen) == 8`,
  `bh_datalen == 12`, `bh_hdrlen == 16`, `bpf_wordalign(18) == 20`; `size_of::<BpfInsn>() == 8`, `BpfProgram == 16`,
  `BpfStat == 8`, `size_of::<libc::ifreq>() == 32`; функция `ioc(dir, group, num, len)` воспроизводит **каждую**
  константу `libc` (`BIOCSETIF == 0x8020426c`, `BIOCIMMEDIATE == 0x80044270`, `BIOCSBLEN == 0xc0044266`,
  `BIOCGBLEN == 0x40044266`, `BIOCGSTATS == 0x4008426f`, `BIOCSHDRCMPLT == 0x80044275`, `BIOCGDLT == 0x4004426a`,
  `BIOCPROMISC == 0x20004269`, `BIOCFLUSH == 0x20004268`) и пять своих; тест `own_constants_match_the_sdk_header`
  читает `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/bpf.h`, если файл есть, и сверяет
  номера `'B',103/126/119/118/109` и `BPF_TIMEVAL timeval32` под `__LP64__`; без SDK тест печатает `NOT RUN` и
  падает (пропуск не PASS) только при `RMASSCAN_REQUIRE_SDK=1`, иначе проходит с пометкой.
- [ ] `ifinfo.rs`: `OsIface` через `if_nametoindex` и `getifaddrs`/`freeifaddrs` (AF_LINK → `sockaddr_dl`,
  `sdl_type`, `sdl_alen == 6`, MAC в `sdl_data[sdl_nlen..sdl_nlen+6]`), AF_INET адреса для инвентаря, флаги
  `IFF_UP`. Освобождение списка ровно один раз (owned guard с Drop). `verify_binding`: `link_type` только
  `Ethernet`, имя по правилам `valid_ifname` (`< IFNAMSIZ = 16`, без NUL, `/`, пробелов, `.`/`..`), интерфейс
  существует, `sdl_type == IFT_ETHER` и MAC есть, иначе `UnsupportedLink` (например `lo0` IFT_LOOP 24,
  `utun*`, `bridge0`); несуществующий → `InterfaceMismatch`. Source IP/MAC с ОС не сверяются.
- [ ] Тесты с подставным `IfaceInfo` (имена как в `linux/tests.rs`): `binding_matching_the_os_yields_the_ifindex`,
  `non_ethernet_link_type_is_rejected_before_any_os_query`, `non_ethernet_interface_is_unsupported_link`,
  `missing_interface_is_a_mismatch`, `source_ip_and_mac_are_not_validated_against_the_os`,
  `hostile_interface_names_never_reach_the_os`. Тесты на реальной ОС без привилегий (cfg macos):
  `lo0_is_not_ethernet`, `a_nonexistent_interface_is_a_mismatch`, `nic_mac_of_lo0_is_none`.
- [ ] `inventory_bpf()`: `sysctlbyname` для `kern.osproductversion`, `kern.osversion`, `debug.bpf_maxbufsize`,
  `debug.bpf_maxdevices`; `stat` `/dev/bpf0..bpf{maxdevices-1}` пока файл существует (без открытия);
  интерфейсы из `getifaddrs`; `instant_clock = "CLOCK_UPTIME_RAW (std::time::Instant; stops during sleep)"`.
  Тест `inventory_lists_lo0_and_bpf0_without_opening_anything` (проверка: `/dev/bpf0` в списке с `mode & 0o777`,
  `lo0` с `ethernet == false`).
- [ ] `lib.rs`: `#[cfg(target_os = "macos")] mod macos;` и диспетчер; `open_explicit` на macOS пока возвращает
  `Err(NetError::System("macOS BPF adapter: open is implemented in task 4"))`, чтобы тесты задачи 1 не ждали
  задачи 4; остальные платформы без изменений. `cargo test --locked -p rmasscan-net` на Mac и (сборка) на
  Linux/Windows через `cargo check --target` не требуется, достаточно CI после push.
  Commit: `feat(net): macOS BPF ABI declarations, interface info and bpf inventory`.

**GREEN:** все тесты раскладки и `IfaceInfo` PASS на Mac; `cargo test --locked -p rmasscan-net` на Mac PASS;
clippy `-D warnings` чист; `unsafe` только в `sys.rs`/`ifinfo.rs`; language guard PASS.

## Задача 2. Запечатанный стенд `macos-lab` и адаптация лаборатории под macOS

**Files:** создать `rmasscan/crates/rmasscan-lab/src/macos_lab.rs` (+ `#[cfg(test)]` модуль),
`rmasscan/docs/macos-feth-lab.md`; изменить `lib.rs`, `main.rs` (команда `macos-lab`), `link.rs`
(`iface_mac` на macOS через `rmasscan_net::nic_mac`), `dump.rs` (`MacProbe`, `tcpdump_argv_macos`), `peer.rs`
(`Cmd::Counters` на macOS через `netstat`).

**Constraints:** `rmasscan-lab` остаётся `#![forbid(unsafe_code)]`; команды ОС только массивом аргументов, без
shell; тесты через seam `trait Host` (как `vm_lab.rs`, строки 123–160) с подставными ответами; в тестах ни одного
реального `ifconfig`/`route`/`arp`; **никакого `sudo` агентом; никакого python/python3**.

**Interfaces:** `rmasscan-lab macos-lab plan|up|status|down|bpf-access|link --run-id ID --manifest FILE
[--grant|--revoke] [--down|--up]`. Коды выхода: 0 ok; 2 NOT RUN (аргументы, чужие объекты, отсутствие root для
`up/down/bpf-access/link`); 3 стенд не запечатан (`status`); 10 частичный `up` с откатом. `status` печатает JSON
`{"raw_run_allowed":bool,"checks":[{"name","ok","detail"}],"bpf_access":"granted|denied|mixed","uplink":"en0",...}`
и не требует root. Манифест: run-id, имена, MAC, IP, uplink и шлюз на момент `up`, список `/dev/bpfN`, прежние
режимы, `created_utc`, `token` (16 байт `getrandom`, hex).

Команды `up` (root, в этом порядке; `plan` печатает их без выполнения):

```text
ifconfig feth4201 create;  ifconfig feth4202 create
ifconfig feth4201 lladdr 02:ac:00:00:00:01;  ifconfig feth4202 lladdr 02:ac:00:00:00:02
ifconfig feth4201 peer feth4202
ifconfig feth4202 inet 198.18.0.2 netmask 255.255.255.252
ifconfig feth4201 up;  ifconfig feth4202 up
arp -S 198.18.0.1 02:ac:00:00:00:01 ifscope feth4202     # точную форму сверить с `man arp` на Mac; альтернатива `arp -s ... ifscope`
<открыть /dev/bpf0..15 одновременно как root (std::fs::File, RDWR) и закрыть: ядро создаёт недостающие узлы>
```

`bpf-access --grant`: `chmod 0660` и `chgrp staff` на `/dev/bpf0..15` (прежний режим в манифест);
`--revoke`: `0600 root:wheel`. `down`: `arp -d 198.18.0.1 ifscope feth4202`, `ifconfig feth4201 destroy`,
`ifconfig feth4202 destroy`, `--revoke`, удаление манифеста. `link --down|--up`: `ifconfig feth4202 down|up`
(только для случая linkloss части B).

Правила печати (`status`, также выполняются в `up` до первого изменения и после последнего):

1. `feth4201`/`feth4202` существуют, MAC равны константам, `status: active`, `peer:` указывает друг на друга;
2. на `feth4201` нет `inet`; на `feth4202` ровно `198.18.0.2` с маской `0xfffffffc`;
3. `route -n get default`: интерфейс и шлюз равны записанным при `up` (default route не изменился) и не `feth*`;
4. `netstat -rn -f inet`: ни одного маршрута через `feth*`, кроме `198.18.0/30` на `feth4202`; `route -n get 8.8.8.8`
   не через `feth*`;
5. `arp -an`: запись `198.18.0.1` с MAC `02:ac:00:00:00:01` на `feth4202`, `permanent` (MAC нормализуется: macOS
   печатает `2:ac:0:0:0:1`);
6. `ifconfig bridge*`: ни одного `member: feth`; `sysctl net.inet.ip.forwarding` = 0;
7. `/dev/bpf0..15` существуют; `bpf_access` по режимам (`granted` все `0660` gid staff; `denied` все `0600`);
8. до `up`: имена `feth4201/4202` не существуют, `198.18.0.0/30` не пересекается ни с одним адресом/маршрутом
   (повторно использовать логику `overlap` из `vm_lab.rs`), манифест и файл-метка отсутствуют (чужой стенд не
   трогается и не переиспользуется).

- [ ] Red (seam `Host`): `plan_prints_commands_and_runs_nothing`, `up_refuses_existing_feth_names`,
  `up_refuses_overlapping_198_18_route`, `up_refuses_without_root`, `up_rolls_back_created_interfaces_on_failure`
  (создан только первый `feth` → `destroy` только его), `status_fails_closed_when_default_route_changed`,
  `status_fails_closed_when_feth_is_a_bridge_member`, `status_parses_arp_without_leading_zeros`,
  `status_reports_bpf_access_from_modes`, `down_touches_only_manifest_objects_and_revokes_bpf`,
  `second_down_is_safe`, `bpf_access_records_previous_modes`.
- [ ] Реализовать `macos_lab.rs` по правилам выше; `up` отказывается, если `geteuid() != 0`, проверяя это через
  `std::process::Command("id","-u")` (лаборатория без `unsafe`).
- [ ] `link.rs`: `#[cfg(target_os = "macos")] iface_mac` через `rmasscan_net::nic_mac`; `dump.rs`: `MacProbe`
  реализует `Probe` через `netstat -I IFACE -b -d -n` (строка `<Link#`, столбцы `Ipkts`, `Opkts`, `Ierrs`, `Drop`
  по заголовку; отсутствие столбца это `Err` → INVALID) и `tcpdump_argv_macos(iface, pcap, filter: Option<&str>) =
  ["tcpdump","-i",IF,"-n","-U","--immediate-mode","-s","0","-w",PCAP, FILTER?]` (без `-Z root`, `-B`,
  `--time-stamp-precision=nano`: их macOS tcpdump не принимает); `peer.rs`: `Cmd::Counters` через тот же парсер.
  Тесты парсера `netstat` на двух записанных образцах (один с `Drop`, один без → `Err`).
- [ ] `rmasscan/docs/macos-feth-lab.md`: назначение, константы, команды пользователя с отменой, правила печати,
  коды выхода, что стенд **не** меняет (default route, DNS, pf, реальные NIC), риск сессии с `bpf-access --grant`
  (любой процесс пользователя может читать BPF на всех интерфейсах до `--revoke`), отсутствие постоянных изменений.
  Commit: `feat(lab): sealed macOS feth stand (macos-lab) and macOS capture probes`.

**GREEN:** `cargo test --locked -p rmasscan-lab` PASS на Mac и Linux (seam-тесты платформенно нейтральны);
`macos-lab plan --run-id m1 --manifest /tmp/x.json` печатает команды и rc 0 без изменений в системе;
`macos-lab status` на Mac без стенда даёт rc 3 и `raw_run_allowed: false`; language guard PASS.

**Действие пользователя A (после merge этой задачи в ветку):** см. раздел «Действия пользователя», шаг 1.

## Задача 3. Спайк BPF на стенде: STOP/GO до адаптера

**Files:** создать `rmasscan/crates/rmasscan-net/src/macos/spike.rs` (`#[cfg(all(target_os = "macos", test))]`,
все тесты `#[ignore]`), `docs/experiments/2026-10-25-rmasscan-macos-bpf-spike.md`,
`docs/experiments/2026-10-25-rmasscan-macos-bpf-spike-raw/`.

**Constraints:** стенд поднят пользователем (`macos-lab status` rc 0 с `bpf_access: granted` до и после каждого
прогона, вывод сохраняется); каждая отправка проходит `assert_lab_frame` (dst MAC `02:ac:00:00:00:02`, src MAC
`02:ac:00:00:00:01` или спайковый `02:ac:00:00:00:11`, dst IP `198.18.0.2`); захват `tcpdump` на `feth4202` и на
uplink в каждом прогоне, sha256 до копирования; приватный `CARGO_TARGET_DIR`; `sudo` не вызывается;
**никакого python/python3**.

**Interfaces:** окружение `RMASSCAN_BPF_LAB_MANIFEST` (путь к манифесту `macos-lab`), `RMASSCAN_BPF_OUT_DIR`,
`RMASSCAN_BPF_COND`; без них тест падает с `NOT RUN`. Спайк открывает `/dev/bpfN` напрямую через `macos::sys`
(временный код теста), пишет CSV длительностей каждого вызова и сырые коды возврата. Один кадр на `write`, без
отдельных потоков отправки.

- [ ] **Стенд и путь ответа (STOP/GO).** Один SYN на `198.18.0.2:80` (listener `rmasscan-lab peer listeners`,
  не root) и один на `:81`: в захвате `feth4202` ровно SYN → SYN-ACK от `02:ac:00:00:00:02`, SYN → RST; в RX-BPF на
  `feth4201` те же ответы; на uplink 0 кадров. Проверить, что ядро **не** шлёт RST за сканера (нет RST с src
  `198.18.0.1`), что статический ARP применился (нет ARP-запросов в захвате), что `lladdr` на `feth` сработал
  (MAC в кадрах равны константам), что listener на порту 80 открылся без root. STOP, если SYN-ACK не доходит
  до BPF на `feth4201`: тогда вариант «ядерный TCP на `feth4202`» заменяется Rust-ответчиком на BPF `feth4202`
  (решение в разделе решений), а не ослаблением проверки.
- [ ] **Раскладка на проводе.** Первый прочитанный `bpf_hdr`: `bh_hdrlen == 20`, `bh_caplen == bh_datalen`,
  байты `[hdrlen+12..hdrlen+14]` это ethertype `0x0800`/`0x0806`/`0x88b5`; несколько записей в одном `read`
  разбираются по `bh_hdrlen` и `bpf_wordalign` без остатка.
- [ ] **RX дедлайн.** `poll(POLLIN)` на RX-дескрипторе с `O_NONBLOCK`, `BIOCIMMEDIATE 1`, без `BIOCSRTIMEOUT`:
  1000 вызовов с дедлайном 50 мс на пустом канале → p50/p95/max длительности и максимум превышения;
  при потоке 20k pps мусора от пира (`rmasscan-lab peer inject` на `feth4202`) → max; `POLLNVAL`/`POLLERR` не
  появляются. Если `poll` не просыпается на приход кадра или не уважает таймаут, повторить измерение через
  `kevent(EVFILT_READ)` и записать выбор; адаптер задачи 4 использует измеренный механизм.
- [ ] **Свои кадры.** С `BIOCSSEESENT 0` RX-дескриптор на `feth4201` не видит ни одного кадра, записанного
  TX-дескриптором того же интерфейса (1000 кадров, 0 собственных в RX); с `BIOCSSEESENT 1` (контроль) видит их.
  Кадр со src MAC `02:ac:00:00:00:11` при `BIOCSHDRCMPLT 1` приходит на пир с тем же MAC (ядро не подменяет).
- [ ] **TX.** `write()` 5000 кадров подряд и 1000 по 1 кадр/мс: p50/p95/max, коды возврата, число `ENOBUFS`/`EAGAIN`
  (ожидается 0 на `feth`; это записывается как «не воспроизведено на feth», не как доказательство). Кадр длиннее
  1514 байт → `EMSGSIZE` без отправки.
- [ ] **RX health STOP/GO.** `BIOCGSTATS` на чистом прогоне: `bs_drop == 0`; при искусственном переполнении (пир
  шлёт 200k кадров, RX не читает 2 с, затем читает всё) `bs_drop > 0`, кумулятивен, повторное чтение не
  сбрасывает, `bs_recv - прочитанные == bs_drop` для этого дескриптора; второй независимый RX-дескриптор на
  `feth4201`, читающий непрерывно, даёт верхнюю границу; вызов ≤50 мс. STOP только если честное кумулятивное
  значение на попытку построить нельзя. Записать семантику «нижняя граница».
- [ ] **Stop.** 60 раундов: поток TX и поток RX с дедлайном 50 мс наблюдают флаг за измеренное время; join обоих
  ≤1 с (ожидание ≤ ~55 мс).
- [ ] Отчёт в формате спайка Windows (таблица решений GO/STOP с цифрами, окружение, изоляция на каждом прогоне,
  таймингов таблица p50/p95/max, ограничения), сырьё с `MANIFEST.sha256`. Вывод `macos-lab status` до/после и
  `uplink.pcap` каждого прогона в сырье. Решение контролёра о внутреннем бюджете вызова (`IO_BUDGET`): 50 мс, если
  максимум превышения ≤ запаса планировщика, принятого тестами Linux; иначе `50 − (max превышение + 2 мс)`,
  как 42 мс на Windows. Commit: `test(net): macOS BPF deadline, own-frame and drop-counter spike`.

**GREEN:** все пункты измерены и записаны с цифрами; GO по стенду, раскладке, дедлайну, своим кадрам, TX,
health и Stop (или явный STOP с решением); uplink 0 кадров во всех прогонах; `MANIFEST.sha256` сходится.

## Задача 4. Реализовать macOS AdapterPair

**Files:** создать `src/macos/adapter.rs`, `src/macos/tests/{fake,adapter_tests}.rs`, `src/drop_counter.rs`,
`tests/macos_live.rs`; изменить `src/macos/{mod,sys}.rs`, `src/windows/{handle,adapter}.rs` (импорт общего
`DropCounter`), `src/lib.rs` (`open_explicit` на macOS → `macos::open`).

**Constraints:** логика TX/RX безопасна и работает через seam `trait BpfIo` (как `linux::PacketIo`); `unsafe`
только в `macos::sys` (`open`, `ioctl`, `read`, `write`, `poll`/`kevent`, `close` через `OwnedFd`); каждый
дескриптор принадлежит одному потоку; никаких blanket `unsafe impl Sync`; живые тесты только `#[ignore]` с
окружением; приватный `CARGO_TARGET_DIR`; **никакого python/python3**.

**Interfaces:**

```rust
pub(crate) trait BpfIo: Send {
    fn write(&mut self, frame: &[u8]) -> Result<usize, Errno>;             // неблокирующий
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Errno>;            // пачка записей bpf_hdr
    fn poll_in(&mut self, timeout_ms: i32) -> Result<Readiness, Errno>;    // Timeout | Ready | Failed
    fn stats(&mut self) -> Result<BpfStat, Errno>;                         // BIOCGSTATS, не сбрасывает
    fn backoff(&mut self, wait: Duration);                                 // реально ждёт
    fn buffer_len(&self) -> usize;                                         // BIOCGBLEN после настройки
}
pub(crate) fn open(binding: &AdapterBinding) -> Result<OpenedAdapter, NetError>;
pub(crate) const IO_BUDGET: Duration;              // решение спайка (50 мс или меньше)
pub(crate) const MIN_TX_FRAME: usize = 14; pub(crate) const MAX_TX_FRAME: usize = 1514;  // MTU 1500 + 14, VLAN не принимается
pub(crate) fn own_mac_filter(mac: [u8; 6]) -> [BpfInsn; 6];  pub(crate) fn drop_all_filter() -> [BpfInsn; 1];
```

Открытие (в `sys`): перебор `/dev/bpf0..` (`O_RDWR | O_NONBLOCK | O_CLOEXEC`): `EBUSY` → следующий; `EACCES` →
запомнить, следующий; `ENOENT` → конец; ничего не открыто → `PermissionDenied` при хотя бы одном `EACCES`
(текст: «/dev/bpf* is 0600 root:wheel; run `rmasscan-lab macos-lab bpf-access --grant`»), иначе `System`.
RX: `BIOCSBLEN(min(4 MiB, debug.bpf_maxbufsize))` → `BIOCSETIF(ifr_name)` → `BIOCGDLT == DLT_EN10MB` (иначе
`UnsupportedLink`) → `BIOCIMMEDIATE 1` → `BIOCSSEESENT 0` → `BIOCSETF(own_mac_filter)` → `BIOCGBLEN` (буфер
пользователя ровно этой длины) → базовое `BIOCGSTATS`. TX: `BIOCSBLEN 4096` → `BIOCSETIF` → `BIOCGDLT` →
`BIOCSHDRCMPLT 1` → `BIOCSSEESENT 0` → `BIOCSETF(drop_all_filter)`. `BIOCPROMISC` не вызывается. Любая ошибка после
первого открытия закрывает оба дескриптора. Ошибки `BIOCSETIF`: `ENXIO`/`ENODEV` → `InterfaceMismatch`.

Программа фильтра `own_mac_filter` (6 инструкций, `code/jt/jf/k`): `0x20/0/0/6` (ld [6:4]); `0x15/0/3/be32(mac[0..4])`;
`0x28/0/0/10` (ldh [10]); `0x15/0/1/be16(mac[4..6])`; `0x06/0/0/0` (свой кадр: отбросить); `0x06/0/0/0xffff_ffff`
(принять целиком). `drop_all_filter`: `0x06/0/0/0`.

RX (`RxHalf`): абсолютный дедлайн `min(timeout, MAX_IO_TIMEOUT, IO_BUDGET)`; очередь уже прочитанных записей в
собственном буфере; на пустой очереди `read`; `EAGAIN` → `poll_in(остаток, округление вверх)`; `EINTR` → `backoff`
с сохранением дедлайна; разбор записей: `bh_hdrlen` в `18..=64`, `off + hdrlen + caplen <= n`, иначе `Malformed` →
фатально (счётчик `rx_errors`, дескриптор закрыт); `caplen != datalen` → `rx_truncated`, кадр не выдаётся; кадр
со src MAC == `source_mac` → `rx_outgoing` (вторая линия после фильтра ядра); кадр длиннее буфера вызывающего →
`rx_truncated`; остальное копируется в буфер вызывающего, `rx_packets`. Отброшенные кадры дедлайн не продлевают.
`health`: свежий `BIOCGSTATS` → `DropCounter::update(bs_drop)` → `publish_drops` → `Some(total)`; ошибка → `Err`.
`Drop` для `RxHalf` делает финальный `flush_drops`. `Err` после фатальной ошибки: «adapter closed after an earlier fatal error».

TX (`TxHalf`): проверка длины до записи (иначе `IoError`, `tx_errors`); `write`: `n == len` → `Sent`; `0 < n < len`
→ `Uncertain`; `ENOBUFS`/`EAGAIN`/`EWOULDBLOCK` → если дедлайн истёк `WouldBlockUnsent`, иначе `backoff(min(1 мс,
остаток))` и повтор того же кадра; `EINTR` → как Linux; `EMSGSIZE` → `IoError` без закрытия (кадр не ушёл);
другие errno → фатально (закрыть fd, `Err`). `poll(POLLOUT)` на BPF не используется (ядро всегда «готово»).

- [ ] Вынести `DropCounter` в `src/drop_counter.rs` без изменения семантики; тесты Windows (`health_survives_the_u32_wrap`
  и соседние) остаются зелёными на всех платформах (`cargo test -p rmasscan-net` на Mac собирает `windows` под `test`).
- [ ] Red fake-seam тесты (`adapter_tests.rs`, собираются на всех платформах, как `windows/tests`):
  `tx_full_write_is_sent`, `tx_enobufs_until_deadline_is_would_block_unsent`, `tx_enobufs_then_success_is_sent_once`,
  `tx_partial_write_is_uncertain_and_keeps_fd_open`, `tx_eintr_flood_does_not_extend_the_deadline`,
  `tx_emsgsize_is_an_io_error_and_the_fd_stays_open`, `tx_fatal_errno_closes_the_fd_and_later_calls_fail`,
  `tx_timeout_is_capped_at_the_budget`, `rx_one_read_with_three_records_yields_three_frames`,
  `rx_record_walk_uses_bh_hdrlen_and_wordalign`, `rx_caplen_shorter_than_datalen_is_truncated_not_returned`,
  `rx_malformed_header_is_fatal_and_closes_the_fd`, `rx_own_mac_frames_are_dropped_before_the_caller_sees_them`,
  `rx_peer_syn_ack_and_rst_are_never_filtered_and_parse_as_replies`, `rx_frame_larger_than_callers_buffer_is_dropped_and_counted`,
  `rx_empty_poll_times_out_within_the_deadline`, `rx_garbage_stream_cannot_extend_the_deadline`,
  `rx_eintr_backs_off_bounded_and_keeps_deadline`, `health_reports_cumulative_drops_from_the_open_baseline`,
  `health_survives_the_u32_wrap`, `a_stats_error_is_an_error_never_a_false_zero_or_a_cached_value`,
  `net_stats_final_totals_survive_closing_the_handles`, `own_mac_filter_program_bytes_are_exact`,
  `own_mac_filter_interpreted_drops_own_and_accepts_peer` (мини-интерпретатор ld/ldh/jeq/ret в тесте),
  `open_configures_rx_then_tx_exactly_as_documented` (seam записывает порядок ioctl),
  `every_open_failure_after_the_first_fd_closes_both`, `non_ethernet_dlt_is_unsupported_link_and_closes`,
  `eacces_on_every_device_is_permission_denied_with_the_grant_hint`, `ebusy_devices_are_skipped`.
- [ ] Реализовать `adapter.rs` и `sys::BpfFd: BpfIo`; `macos::open`; диспетчер в `lib.rs`. Счётчики `NetStats`
  работают; `rx_wrong_interface` всегда 0 и помечен «структурно неприменимо» (дескриптор привязан к одному интерфейсу).
- [ ] `tests/macos_live.rs` (зеркало `tests/windows_live.rs`, cfg macos, `#[ignore]`, окружение
  `RMASSCAN_BPF_LAB_MANIFEST`, `RMASSCAN_BPF_OUT_DIR`; `GuardTx` на каждый кадр): `a_full_scan_through_the_engine_completes_with_exactly_one_advance_per_sent`,
  `stop_ends_the_run_quickly_and_nothing_is_sent_afterwards` (≤1 с, после исхода 0 SYN в захвате),
  `pause_stops_tx_then_resume_continues_without_gaps_or_duplicates`, `rx_loss_from_a_stalled_reader_fails_the_run_and_keeps_the_results`,
  `an_uncertain_send_fails_the_run_without_checkpoint_retry_or_more_sends` (через обёртку Tx, как Windows).
  Запуск оператором на стенде: `cargo test --locked -p rmasscan-net --test macos_live -- --ignored`.
- [ ] Проверить Stop/Pause, Uncertain и panic через общий runtime (fake); fmt, clippy, cargo deny, workspace tests на
  трёх ОС. Commit: `feat(net): implement bounded macOS BPF adapters`.

**GREEN:** fake-тесты PASS на Mac/Linux/Windows; живые тесты PASS на стенде с uplink 0 кадров; `unsafe` только в
`macos/{sys,ifinfo}.rs`; `cargo deny check bans licenses sources` чист; language guard PASS.

## Задача 5. Harness `wire_scan` и метрики процесса на macOS

**Files:** изменить `examples/wire_scan.rs`, `examples/support/{mod,metrics}.rs`; создать `src/macos/process.rs`;
изменить `src/lib.rs` (`process_sample`, `lab_thread_ids`, `lab_current_thread_id` на macOS).

**Constraints:** `wire_scan` остаётся `#![forbid(unsafe_code)]`; метрики, которые измерить нельзя, это `None`
(`null`), не 0; поведение Linux/Windows не меняется; приватный `CARGO_TARGET_DIR`; **никакого python/python3**.

**Interfaces:** `--inventory` на macOS печатает `BpfInventory` (без открытия BPF и без отправки); идентичность
получает поле `"raw_io_abi"` (на macOS `BPF_ABI_ID`, на Windows `NPCAP_ABI_ID`, на Linux `"AF_PACKET via libc"`) при
сохранении `"npcap_abi"` для существующего верификатора Windows; `os.version` из `os_version()`. Коды выхода без
изменений: 5 для `PermissionDenied` (EACCES на `/dev/bpf*`) с подсказкой про `bpf-access --grant`.
`process_sample()` на macOS: `getrusage(RUSAGE_SELF)` → `cpu_user_ms`, `cpu_kernel_ms`, `peak_working_set_bytes`
(`ru_maxrss`, байты на macOS); `proc_pidinfo(getpid(), PROC_PIDTASKINFO)` → `threads` (`pti_threadnum`),
`working_set_bytes` (`pti_resident_size`); `handles` = число записей `read_dir("/dev/fd")` минус 1 (сам дескриптор
каталога), задокументировать. `lab_current_thread_id` через `pthread_threadid_np(null, &mut id)`;
`lab_thread_ids` через `proc_pidinfo(PROC_PIDLISTTHREADS)`.

- [ ] Red: `inventory_mode_never_opens_bpf_or_sends` (на Mac: `--inventory` rc 0 при `0600` на `/dev/bpf*`, в выводе
  `devices[0].mode == 0o600` и `instant_clock`); `reference_pcap_mode_needs_no_bpf`; `identity_has_raw_io_abi_and_os_version`;
  `process_sample_fields_are_some_on_macos` (threads ≥ 1, handles ≥ 3, cpu ≥ 0 — только существование `Some`, не величины);
  `thread_ids_contain_the_current_thread`.
- [ ] Реализовать `macos/process.rs` (`#[allow(unsafe_code)]`, `SAFETY` на каждый вызов); `support/metrics.rs` для
  `target_os = "macos"` через `rmasscan_net::process_sample`.
- [ ] `wire_scan`: `--inventory` для macOS; `--src-mac` обязателен (как на Linux); проверка `--src-mac == nic_mac(iface)`
  с `--allow-foreign-source-mac` как на Windows (без promiscuous ответы не придут); код 6 при расхождении.
- [ ] Прогнать на Mac без стенда: `--inventory` rc 0; скан с `--iface feth4201` без стенда → rc 2 `InterfaceMismatch`
  (ни одного кадра, адаптер не открыт). Commit: `feat(net): wire_scan inventory and process metrics on macOS`.

**GREEN:** тесты PASS на Mac; `cargo test --locked -p rmasscan-net --example wire_scan` PASS на трёх ОС (CI);
JSON `--inventory` содержит `raw_io_abi`, `instant_clock`, список `/dev/bpf*` с режимами.

## Задача 6. `macos-suite`, `macos-verify` и фикстуры C для binding Mac

**Files:** создать `rmasscan/crates/rmasscan-lab/src/{macos_suite,macos_verify}.rs` и `src/{macos_suite_tests,macos_verify_tests}.rs`;
изменить `lib.rs`, `main.rs`, `oracle.rs` (`--src-mac MAC`, по умолчанию прежнее Windows-значение), `docs/rust-lab.md`,
`docs/macos-feth-lab.md`.

**Constraints:** `#![forbid(unsafe_code)]`; команды массивами аргументов; никаких `sudo` в коде suite (стенд уже
поднят, linkloss выполняет пользователь); тесты верификатора на синтетических и мутированных каталогах, без сети;
уникальные имена через `getrandom`; **никакого python/python3**.

**Interfaces:** `rmasscan-lab macos-suite --out DIR --suite ID --plan functional|failure|perf --commit SHA --repo PATH
--wire-scan PATH --fixtures DIR --manifest LAB_MANIFEST [--reps N] [--rates CSV] [--only TAGS] [--rerun] [--list]`;
`rmasscan-lab macos-verify --dir DIR [--out DIR/verdict.json]` (коды 0 PASS, 1 FAIL, 2 INVALID/NOT RUN);
`oracle-fixtures --src-mac 02:ac:00:00:00:01 --peer-mac 02:ac:00:00:00:02 ...`. Один suite за раз: `flock`-эквивалент через
`std::fs::OpenOptions::create_new` lock-файла в `$HOME/.rmasscan-lab/` с pid и стартом процесса; протухший lock
(pid мёртв) снимается явно, не автоматически.

Шлюз каждого прогона (без него прогон NOT RUN, адаптер не открывается): `macos-lab status` rc 0 → `status-pre.json`
(`raw_run_allowed: true`, `bpf_access: granted`, кроме `perm_denied_*`, где требуется `denied`); listeners пира
перезапущены и `ready` (`listeners.json`); свидетель `tcpdump` на `feth4202` готов и стартовый маркер в pcap
(`capture dump` с `--ready/--ack`); `tcpdump` на uplink с фильтром лаборатории запущен; nonce прогона
(`getrandom`) в имени каталога и в `run.json` через `--observe`-поле или аргумент `--nonce` harness; после прогона:
3 конечных маркера после тишины счётчиков `netstat`, остановка `tcpdump`, статистика `tcpdump` (`captured ==
received`, `dropped by kernel == 0`), `status-post.json`, sha256 всех файлов в `hashes-before-copy.txt` в рабочем
каталоге, копирование в `--out/runs/<tag>.<nonce>/`, повторная сверка sha256. Любой кадр лаборатории на uplink →
`safety_trips`, FAIL всего каталога, suite останавливается (код 13).

План `functional` (как Windows: `verify::functional_cases()`, `cases_psv()`): c01–c06 ×2, x01 ×2, группы pause
N=0/1/8/15 для 16 probe (continuous + pause + resume, scan_id постоянный, attempt_id новый), `refuse_completed`.
План `failure`: `stop_silent`, `stop_load`, `stop_drain`, `stop_fullqueue` (rate 1, wait 10; `stop_to_outcome_ms <
1000`, 0 SYN после исхода), `overflow_queue` (`--result-capacity` малый + `--no-consume` → `ConsumerTooSlow`, rc 3,
без checkpoint), `rxloss` (`--rx-stall-ms 3000`, порты `1-65535`, rate 100000 → `Failed(RxLoss{kernel_drops>0})`, rc 3,
без checkpoint; результаты подмножество истины без чужих/дублей), `ckpt_*` ×8 (как Windows), `perm_denied_scan`
(выполняется **до** `bpf-access --grant`: rc 5, `tx_sent 0`, 0 SYN в захвате, `status-pre.bpf_access == denied`),
`perm_inventory_control` (rc 0 при `denied`), `linkloss` (только если пользователь выполняет `macos-lab link --down`
по сигналу suite и `--up` через 3 с; иначе NOT RUN с пометкой «user action not performed»). План `perf`: 20 ячеек
`perf.<rate>.r<rep>` (100/1000/10000/100000 × 5, порты `1-500`, `1-5000`, `1-50000`, `1-65535`), медианы `steady_pps_wire`
по SYN-меткам `peer.pcap`, `cpu_user_ms`, `cpu_kernel_ms`, `peak_working_set_bytes`, `join_ms`, `drain_s`; `rate_gate` MET
при медиане в ±20%, OPEN иначе, NOT RUN при <3 Completed PASS; INVALID по правилам полноты захвата.

- [ ] Red `macos_verify_tests.rs`: `missing_run_json_is_not_run_never_pass`, `incomplete_capture_is_invalid_not_pass`,
  `a_lab_frame_on_uplink_is_fail_and_a_safety_trip`, `hash_mismatch_after_copy_is_invalid`,
  `status_pre_or_post_not_allowed_is_not_run`, `syn_bytes_differ_from_fixture_is_fail`,
  `pause_resume_legs_must_equal_continuous_and_fixture`, `completed_with_unknown_or_nonzero_drops_is_fail`,
  `rxloss_with_zero_or_unknown_drops_is_fail`, `perm_denied_run_with_any_syn_is_fail`,
  `perf_gate_is_open_outside_twenty_percent_and_not_run_under_three_cells`, `fixture_binding_must_equal_run_binding`
  (MAC/IP без нормализации), `verdict_counts_add_up`.
- [ ] Red `macos_suite_tests.rs` (seam команд): `gate_refuses_when_status_pre_not_allowed`, `gate_refuses_when_start_marker_missing`,
  `hashes_are_taken_before_copy_and_checked_after`, `uplink_frame_stops_the_suite_with_exit_13`,
  `perm_denied_requires_bpf_access_denied`, `only_and_rerun_accept_discardable_runs_only`, `lock_file_refuses_a_second_suite`,
  `options_are_validated_by_name` (как `options_for`).
- [ ] Реализовать `macos_suite.rs` (локальный запуск `wire_scan`, `peer listeners`, `capture dump`, `tcpdump` uplink,
  `macos-lab status`) и `macos_verify.rs`, переиспользуя `pcap.rs` (сравнение SYN), `verify::{case_by_name, functional_cases,
  cases_psv, expected_args}`, `windows_suite::{parse_tcpdump, nonce, hash, options_for}`, `wire_suite::{capture_complete,
  rx_is_complete}`; evidence-схема `macos_capture_schema: 1` с перечнем файлов прогона в `README` каталога.
- [ ] `oracle.rs`: опция `--src-mac` (валидация MAC, подстановка в `WIRELAB_MAC_A`); тест
  `oracle_plan_uses_the_given_source_mac_and_quotes_it`. Фикстуры для Mac снимаются оператором на minipc командой
  `rmasscan-lab oracle-fixtures --out docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance-raw/fixtures --src-mac 02:ac:00:00:00:01
  --peer-mac 02:ac:00:00:00:02 --remote-lab /abs/path/linux/rmasscan-lab --host minipc` (Linux-сборка `rmasscan-lab` на
  minipc, C-оракул `$HOME/rmasscan-oracle/masscan/bin/masscan` pinned `8e6b3b0`, netns-стенд `wire-lab.sh`; требуется
  `sudo -n` на minipc — см. открытый вопрос 1).
- [ ] Документация: `docs/rust-lab.md` (раздел macOS: сборка, команды, порядок A/B/C, коды выхода, где лежит
  evidence), `docs/macos-feth-lab.md` (операторская часть). Commit: `feat(lab): macOS suite, verifier and oracle fixtures for the Mac binding`.

**GREEN:** `cargo test --locked -p rmasscan-lab` PASS на Mac и Linux; `macos-suite --list --plan perf` печатает 20 тегов
без действий; `macos-verify` на пустом каталоге даёт NOT RUN (rc 2), на мутированном синтетическом каталоге FAIL/INVALID,
никогда PASS; language guard PASS.

## Задача 7. Живая приёмка на Mac: части A, B, C

**Files:** `docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance-raw/{fixtures,functional-r1,failure-r1,perf-r1}`
(каждый с `manifest.json`, `runs/`, `runs_discarded/`, `verdict.json`, `README.md`, `MANIFEST.sha256`).

**Constraints:** выполняет оператор по правилам шлюза; код под тестом это один закреплённый коммит, собранный из чистого
дерева (`git_dirty=false` в манифесте suite), `wire_scan` и `rmasscan-lab` из приватного `CARGO_TARGET_DIR` с
`RMASSCAN_SOURCE_COMMIT`/`RMASSCAN_LAB_BUILD_COMMIT`; большие pcap после снятия хэшей `gzip -9 -n`; личные пути в текстах
заменяются `$HOME`/`$REPO`, pcap не трогаются; никаких `--rerun` без записи причины; **никакого sudo агентом; никакого python/python3**.

- [ ] Фикстуры C на minipc (команда задачи 6), `fixtures/manifest.json` с `all_valid: true`, binding `02:ac:00:00:00:01`/
  `02:ac:00:00:00:02`/`198.18.0.1`; sha256 каждого pcap. Без фикстур части A и C NOT RUN.
- [ ] Перед частью A (стенд `up`, `bpf_access: denied`): `failure-r1` только `--only perm_denied_scan perm_inventory_control`;
  затем **действие пользователя B** (`bpf-access --grant`), затем остальные прогоны `failure-r1` и части A, C.
- [ ] Часть A `functional-r1`: 29 пунктов (24 прогона + 4 группы pause/resume + manifest) PASS; байты SYN и порядок равны
  фикстуре без нормализации; полнота Open/Closed равна истине listeners без дублей; `x01` отклоняет чужие ответы;
  `refuse_completed` без единого SYN.
- [ ] Часть B `failure-r1`: `stop_*` 4 PASS (`stop_to_outcome_ms < 1000`, 0 SYN после исхода, потоки завершены, fd не утекли),
  `overflow_queue`, `rxloss` (измеренные `kernel_drops > 0`, значение одинаково во всех чтениях), `ckpt_*` ×8, `perm_*` ×2;
  `linkloss` PASS или NOT RUN с причиной.
- [ ] Часть C `perf-r1`: 20 ячеек; таблица медиан по скоростям; `rate_gate` по ячейкам; INVALID-ячейки с причиной
  (ожидаемая причина на 100k: `dropped by kernel` у свидетеля `tcpdump` при `-U --immediate-mode`); gate не ослабляется.
- [ ] Uplink: 0 кадров лаборатории во **всех** прогонах (суммарный счёт в README каждого каталога); `status-pre/post`
  `raw_run_allowed: true` везде; `MANIFEST.sha256` (`shasum -a 256`) на каждый каталог; `verdict.json` от `macos-verify`.
  Commit: `test(net): record macOS BPF wire, failure and performance acceptance`.

**GREEN:** `macos-verify` overall PASS для `functional-r1` и `failure-r1` (кроме явно NOT RUN `linkloss`, если действие не
выполнено — тогда overall NOT RUN by design для этого пункта с записью), `perf-r1` overall PASS или INVALID-ячейки честно
записаны; uplink 0 кадров; хэши сходятся. *(Поправка 2026-10-25, см. «GO и дальнейшая очередь»: `linkloss` может быть
PASS, NOT RUN или INVALID с документированной причиной.)*

## Задача 8. Отчёт, readiness, CI и итоговое ревью

**Files:** создать `docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md`; изменить
`docs/experiments/2026-10-24-rmasscan-readiness.md` (строка macOS), `.github/workflows/rmasscan.yml` (комментарий:
macOS raw I/O реализован, живые тесты `#[ignore]`, CI их не выполняет), `rmasscan/README.md` (если перечисляет платформы).

**Constraints:** статусы PASS/FAIL/INVALID/NOT RUN/OPEN никогда не повышаются; GO объявляется только при зелёном CI на
точном HEAD; **никакого python/python3**.

- [ ] Отчёт по образцу приёмки Windows VM: §1 итог и границы (единый список условий GO), §2 коммиты и чистота дерева,
  §3 хэши, §4 топология (`feth`, uplink), §5 версии (macOS 27.0.1, Darwin, tcpdump/libpcap, `bpf_maxbufsize`), §6 результаты
  A/B/C, §7 хэширование и полнота, §9 ошибки и ограничения (нижняя граница `bs_drop`; `feth` не физический NIC; sleep/wake
  NOT RUN; macOS 14 не измерен; linkloss при отсутствии действия пользователя), §10 ревью, §12 CI, §13 заявление.
- [ ] Readiness: строка «macOS correctness (feth)» со статусом и точным gate; слои физического NIC macOS (Ethernet-адаптер
  USB/Thunderbolt) и throughput на физическом NIC — NOT RUN/OPEN.
- [ ] Workspace-тесты на трёх ОС вручную (Mac, minipc Linux, Windows VM) перед push с логами в `verification/`;
  push ветки; CI зелёный на точном HEAD (`ubuntu-24.04`, `macos-14`, `windows-2022`, `language-guard`).
- [ ] Итоговое Opus-ревью ветки (unsafe/lifetimes/deadlines в `macos/*`, лаборатория, evidence); исправления; живая
  перепроверка изменённых путей (минимум `c01` и `perm_denied_scan`) на исправленном коммите.
  Commit: `docs(net): macOS BPF acceptance report and readiness`.

**GREEN:** отчёт существует с единым списком условий; CI зелёный на HEAD; ревью APPROVED; readiness обновлён.

## GO и дальнейшая очередь

**GO macOS correctness (feth):** код macOS принят ревью; CI зелёный на точном HEAD на трёх ОС; на запечатанном
`feth`-стенде Mac разработчика части A (29 PASS), B (все пункты PASS, `linkloss` PASS или NOT RUN с записью) и C
(20 ячеек, честные `rate_gate`) пройдены на одном закреплённом коммите; байты SYN равны C-оракулу `8e6b3b0`; Stop ≤1 с;
pause/resume без потерь и дублей; `kernel_drops` честный `Some(n)`; нет ложного checkpoint, скрытых потерь, утечек fd и
потоков; uplink 0 кадров во всех прогонах; версии и ограничения зафиксированы. **GO не распространяется** на
физический NIC macOS, другие версии macOS, sleep/wake, throughput на физическом NIC, discovery/ARP, runner/IPC, UI.

> **Поправка к критерию GO, 2026-10-25 (одобрена пользователем 2026-10-25).** Часть B `linkloss` может быть **PASS**,
> **NOT RUN** или **INVALID** с документированной причиной: «на `feth` у сканера нет события линка при падении линка на
> стороне пира» (в живой приёмке сканер завершился `Completed`, отказа TX/линка не было). Класс отказа линка переносится
> **OPEN** на этап физического NIC. Это **смена критерия, а не повышение статуса**: INVALID остаётся INVALID, он не становится
> PASS и не равен прежнему NOT RUN. Прочие пункты GO (в том числе исправления ревью `11c6764` P1–P3, пересчёт архива
> исправленным верификатором с неизменными вердиктами и зелёный CI на точном финальном SHA) не меняются.

Далее: **discovery/ARP и сеть/VPN/sleep → sendqueue/скорость (Linux `PACKET_TX_RING`, Windows sendqueue, macOS
батчи `write`) → сессионный runner + IPC + durable checkpoint ACK → настоящий Scan из Slint**.

## Решения этого плана (с причиной и ценой ошибки)

1. **Стенд: пара `feth` с ядерным TCP на `feth4202` и статическим ARP.** Причина: честные SYN-ACK/RST от ядра (как
   netns-пир Linux и Windows VM), свидетель `tcpdump` на стороне пира, listeners без root (macOS ≥10.14 разрешает
   порты <1024 без root). Source IP `198.18.0.1` никому не назначен: ядро не отвечает RST за сканера, forwarding=0 →
   приходящие на `feth4201` SYN-ACK отбрасываются ядром и видны только BPF. Цена ошибки: если спайк (задача 3) покажет,
   что ответы не доходят до BPF `feth4201` или ARP не применяется, запасной вариант — Rust-ответчик на BPF `feth4202`
   в `rmasscan-lab` (синтетические SYN-ACK/RST из `rmasscan-core`), стоимость ≈1 задача, доказательство слабее (ответчик
   наш), что фиксируется в отчёте. Вариант «bridge + два feth» отклонён: `bridge` это ещё один L2-объект без выгоды.
2. **BPF-параметры.** `BIOCSBLEN = min(4 MiB, debug.bpf_maxbufsize)` (сейчас 512 KiB; буфер нужен лишь на срывы
   планировщика, RX читается непрерывно); `BIOCIMMEDIATE 1`; `BIOCSHDRCMPLT 1` на TX (кадр уходит байт в байт);
   `BIOCSSEESENT 0` на обоих + фильтр ядра `not ether src <own>` + программная проверка MAC (три линии, как
   Windows/Linux); TX-фильтр `ret #0`; promiscuous нет; дедлайн через `O_NONBLOCK + poll()` (без `BIOCSRTIMEOUT`, чьё
   взаимодействие с `select/poll` на BPF исторически ненадёжно по заметкам libpcap), `kevent` как измеренный запасной
   вариант. Цена ошибки: если `poll` ненадёжен, замена seam-реализации в `sys.rs` без изменения `adapter.rs`.
3. **RX health = `BIOCGSTATS.bs_drop`** с базой при открытии и переносом через `u32` (`DropCounter`), семантика
   «нижняя граница» (потери ниже BPF, в `feth`/драйвере NIC, не видны), паритет с NPF и `PACKET_STATISTICS`. Ошибка
   `ioctl` → `Err`, не 0. Цена ошибки: если `bs_drop` окажется не per-descriptor или сбрасывается — STOP спайка и
   отдельное решение, не подмена `None` нулём.
4. **Stop/Pause ≤1 с:** RX всегда `O_NONBLOCK` + `poll` с остатком дедлайна ≤50 мс; TX `write` синхронный, но без
   блокировки (ENOBUFS → `WouldBlockUnsent`), поэтому engine видит `halt` между вызовами не позже ~50 мс. Блокирующий
   `read` не используется вообще. Цена ошибки: если `write` способен блокироваться дольше контракта на реальном NIC
   (на `feth` не воспроизводимо), это открытый пункт для физического NIC, не ослабление лимита.
5. **Живые `feth`-тесты в CI (`macos-14`, passwordless sudo): рекомендация — нет** (по умолчанию). Причины: CI-VM не
   даёт независимого свидетеля на uplink под нашим контролем, стандарт доказательств (шлюз, хэши, статус, ревью
   оператора) CI не выполняет, нестабильность `feth` на runner блокировала бы merge, а GO всё равно опирается на стенд
   пользователя. Допустимый компромисс позже: отдельный `workflow_dispatch` smoke (один `c01`) без влияния на GO.
   **Решение пользователя.**
6. **Throughput и часть C.** Ожидание: `feth` это копирование в ядре, один `write` на кадр ≈5–15 мкс на Apple Silicon →
   потолок сканера порядка 10^5 pps; свидетель `tcpdump -U --immediate-mode` вероятно теряет кадры на 100k pps → ячейки
   INVALID (честно, gate не ослабляется). Ожидаемо MET на 100/1k/10k, OPEN/INVALID на 100k. Измерение: как Windows
   (`steady_pps_wire` из меток `peer.pcap`, CPU через `getrusage`, RSS через `ru_maxrss`/`proc_pidinfo`). Это измерение
   `feth`, не физического NIC. Опциональное действие пользователя: поднять `debug.bpf_maxbufsize` до 4 MiB на сессию
   (см. раздел действий), только если спайк покажет потери RX-буфера на 10k/100k.
7. **Права: наименьшие.** Root нужен только пользователю для `up/down/bpf-access/link`; сканер, свидетель, listeners и
   suite работают без root благодаря `0660 root:staff` на `/dev/bpf0..15` на время сессии. Отклонено: запуск агентов под
   `sudo` (пароль, кэш `sudo` привязан к tty), постоянный LaunchDaemon вида ChmodBPF (постоянное изменение системы).
   Цена: на время сессии любой процесс пользователя может читать BPF любого интерфейса; `--revoke`/`down` закрывают это.
8. **Адреса и порты те же, что на Windows** (`198.18.0.1/2`, `80,443,8000-8007`, те же case-листы), MAC новые и
   фиксированные через `lladdr`. Причина: переиспользование case-листов, verifier-правил и правил полноты; фикстуры C
   снимаются заново для новых MAC. Цена ошибки: если `lladdr` на `feth` не применяется, MAC берутся из созданных
   интерфейсов и фикстуры снимаются для них (повторять при пересоздании стенда).

## Действия пользователя (точные команды, когда, отмена)

Все команды выполняет пользователь в сессии с префиксом `!`; пароль `sudo` вводит он. `LAB` ниже это
`rmasscan/target/release/rmasscan-lab`, собранный из ветки после задачи 2 (`cargo build --locked --release -p rmasscan-lab`
из `rmasscan/`), `M=$HOME/.rmasscan-lab/macos-m1.json`.

| № | Когда | Команда | Что меняет | Отмена |
| --- | --- | --- | --- | --- |
| 1 | после задачи 2, перед задачей 3 | `sudo $LAB macos-lab up --run-id m1 --manifest $M` (сначала `$LAB macos-lab plan ...` без sudo, чтобы увидеть команды) | создаёт `feth4201`/`feth4202`, MAC, IP `198.18.0.2/30`, статический ARP, узлы `/dev/bpf0..15` | `sudo $LAB macos-lab down --manifest $M`; также перезагрузка |
| 2 | после `perm_denied_*` части B (и перед спайком задачи 3, затем снова после `perm` прогонов, если `down` был между ними) | `sudo $LAB macos-lab bpf-access --grant --manifest $M` | `/dev/bpf0..15` → `0660 root:staff` на сессию | `sudo $LAB macos-lab bpf-access --revoke --manifest $M`; `down`; перезагрузка |
| 3 (опц.) | часть B, прогон `linkloss`, по сигналу оператора | `sudo $LAB macos-lab link --down --manifest $M`, через 3 с `... link --up ...` | `feth4202` down/up | `link --up`; `down` |
| 4 (опц.) | часть C, только если спайк показал потери RX-буфера | `sudo sysctl -w debug.bpf_maxbufsize=4194304` | лимит буфера BPF до перезагрузки | `sudo sysctl -w debug.bpf_maxbufsize=524288` (значение из baseline) |
| 5 | после части C и перепроверки задачи 8 | `sudo $LAB macos-lab down --manifest $M` | уничтожает `feth`, удаляет ARP, возвращает `0600 root:wheel`, удаляет манифест | — (это и есть отмена) |
| 6 (вне Mac) | задача 7, фикстуры | подтвердить, что на minipc для оператора работает `sudo -n true` (нужно `wire-lab.sh`); иначе выполнить команду `oracle-fixtures` из задачи 6 самостоятельно | netns-стенд на minipc на время снятия, удаляется скриптом | скрипт удаляет свои netns; `ip netns list \| grep wl-` пуст |

Постоянных изменений системы план не делает: `feth`, ARP, режимы `/dev/bpf*` и `sysctl` не переживают перезагрузку.

## Источники и самопроверка

- `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/net/bpf.h` (прочитан 2026-10-25): `BPF_ALIGNMENT
  sizeof(int32_t)`, `BPF_TIMEVAL timeval32` под `__LP64__`, `struct bpf_hdr/bpf_stat/bpf_program`, номера `BIOC*`
  ('B', 102–121, 126), `BPF_MAXBUFSIZE 0x80000`, `DLT_EN10MB 1`.
- `libc 0.2.191` (`src/unix/bsd/mod.rs` 432–443): числовые значения `BIOC*`, сверяемые тестом раскладки задачи 1.
- `man 4 bpf`, `man 8 ifconfig` (`lladdr`, `peer`), `man 8 arp`, `man 8 tcpdump` на Mac; `sysctl net.link.fake` как
  свидетельство наличия `if_fake`/`feth`.
- `pcap_get_selectable_fd(3PCAP)` / libpcap `pcap-bpf.c`: предупреждение о `select/poll` на BPF с read timeout
  (причина решения 2 не использовать `BIOCSRTIMEOUT`).
- Код: `rmasscan-engine/src/io.rs` (контракты), `rmasscan-net/src/linux/{mod,socket}.rs` (Deadline, PacketIo),
  `rmasscan-net/src/windows/{adapter,handle}.rs` (IO_BUDGET, DropCounter, фильтры), `rmasscan-lab/src/{vm_lab,dump,
  wire_suite,windows_suite,verify,oracle}.rs` (seam `Host`, `Probe`, шлюз, правила PASS/FAIL/INVALID/NOT RUN).
- Review Focus 1→2/3; 2→1/3/4; 3→3/4; 4→4; 5→2/6/7. Публичный API сохранён (`open_explicit`, `OpenedAdapter`,
  `NetStatsHandle`); новые типы `BpfInventory`/`BpfDevice`/`IfaceReport` и константа `BPF_ABI_ID` определены в задаче 1.
  Все привилегированные действия вынесены пользователю с отменой; живые испытания отделены от CI; каждая задача несёт
  запрет python/python3 и приватный `CARGO_TARGET_DIR`.
