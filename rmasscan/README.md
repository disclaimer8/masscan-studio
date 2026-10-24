# rmasscan

Порт ядра сканера [masscan](https://github.com/robertdavidgraham/masscan) на
чистый Rust. Лицензия: AGPL-3.0-only. Оригинал © Robert David Graham; сверка
ведётся с HEAD `8e6b3b0` (версия `1.3.9-integration`).

Документы:

- спека порта (исторический проект): `../docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`
- спека Studio, **§0 это текущий перечень возможностей и контракты engine** (привязан к commit): `../docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`
- планы этапов 0–2A: `../docs/superpowers/plans/`
- статус этапа 2A: `../docs/experiments/2026-10-23-rmasscan-stage2a.md` (исторический)
- приёмка Linux 2B (wire parity, pause/resume, Stop, скорость): `../docs/experiments/2026-10-23-rmasscan-stage2b-linux.md` (исторический)
- замеры скорости: [BENCHMARKS.md](BENCHMARKS.md)
- golden-фикстуры оракула: [tests/golden/README.md](tests/golden/README.md)

## Команды

```bash
cd rmasscan
cargo test
cargo run -p rmasscan-cli -- -sL 10.0.0.0/30 -p80,443 --seed 1
cargo run -p rmasscan-cli -- --echo 10.0.0.0/24 -p80 --seed 1
cargo run -p rmasscan-cli -- --offline --packet-trace 10.0.0.0/30 -p80 --seed 1 \
  --adapter-ip 10.255.0.1 --adapter-mac 00-11-22-33-44-55 \
  --router-mac 66-55-44-33-22-11 --source-port 40000-40003
```

Этап 1 поддерживает `-sL`, `--echo`/`--echo-all` и `--offline --packet-trace`.
`-sL` и `--echo` побайтно совпадают с golden-фикстурами C.

### Отличия от masscan

- `--seed` обязателен и не может быть 0 (в C 0 означает случайную энтропию).
- Ошибки целей, портов и значений фатальны (в C ошибка `--range` не фатальна).
- Операции `-sL`, `--echo`, `--echo-all`, `--packet-trace` взаимоисключающие;
  обычный скан без `--offline --packet-trace` не поддержан.
- `--offline --packet-trace` требует `--adapter-ip`, `--adapter-mac`,
  `--router-mac` и `--source-port` (обнаружения адаптера нет; C берёт
  `40000 + time % 20000`). Трасса печатается осознанно, в C она пуста.
- Любая другая опция masscan (например `--banners`) - ошибка.
- Закрытый stdout (`| head`) завершает процесс сразу с кодом 0.
- `--adapter-ip` принимает один адрес (в C это диапазон).
- Грамматика `--excludefile` уже, чем у `massip_parse_file`: по одной записи на строку
  (IPv4, CIDR, диапазон), без остальных форм C.
- Осознанные отказы парсера там, где C молча принимает ввод: перевёрнутый диапазон,
  завершающая точка, пустой CIDR, пустой октет, мусор в списке портов.
- `-sL` с `--retries` > 0 в C может зависнуть (main-listscan.c:35,
  crypto-blackrock.c:268-276); `list_scan` и CLI это обнаруживают и завершаются ошибкой
  `ScanError::NonTerminating` до любого вывода, зациклиться может только сырой
  `list_scan_indices` с ручным shuffle-циклом. Передача от этого свободна.

## Проверка «без C в сборке»

Граф сборки не должен содержать C-тулчейн (`cc`, `cmake`, `bindgen`,
`pkg-config`, libpcap). Проверяют два механизма: интеграционный тест
`crates/rmasscan-core/tests/no_c_in_build.rs` (`cargo tree -e normal,build,dev`) и
`cargo deny`. Точные команды для CI:

```bash
cargo install --locked cargo-deny@0.20.2
cargo deny check bans licenses sources
cargo test -p rmasscan-core --test no_c_in_build   # граф --workspace: включает engine и sha2
```

## Лабораторная приёмка Linux (2B)

Crate `rmasscan-net` (единственный, где допущен `unsafe`) открывает AF_PACKET по явному
binding. Это НЕ пользовательское сканирование: CLI по-прежнему не умеет живой скан.
Проверка идёт только в замкнутом стенде (две netns + veth, без uplink/bridge/NAT):

```bash
# на Linux-хосте со sudo -n, ip, ethtool, tcpdump, python3 и закреплённым C-oracle
cargo build --locked --release -p rmasscan-net --example wire_scan
scripts/wire-lab.sh --oracle /path/to/oracle/masscan --out OUT --suite rust \
  --rust-bin target/release/examples/wire_scan --fixtures tests/golden/wire
scripts/wire-lab.sh --oracle /path/to/oracle/masscan --out OUT-perf --suite perf \
  --rust-bin target/release/examples/wire_scan --reps 5
RMASSCAN_WIRE_RESULTS=OUT RMASSCAN_WIRE_PERF_RESULTS=OUT-perf \
  cargo test --locked -p rmasscan-net --test linux_wire -- --ignored
python3 scripts/verify-wire.py --self-test
```

`examples/wire_scan.rs` это лабораторный harness (`ReadyPlan` + `Engine` + `open_explicit`,
`--pause-after N`, `--resume-checkpoint FILE`), а не CLI. Тесты `linux_wire.rs` с `--ignored`
без каталога результатов падают с «NOT RUN», пропуск никогда не PASS.

## Ограничения

Raw-сокеты и сеть используются только в лабораторных тестах `rmasscan-net` (нужны
CAP_NET_RAW и замкнутый стенд); обычные `cargo test` и CI их не запускают. Живое
сканирование не работает: обычный скан без `--offline --packet-trace` по-прежнему не
поддержан.

## Статус

Состояние на commit `27e3042` (код; evidence `8479ff2`; 2026-10-24, ветка `feat/rmasscan-stage2b-linux`);
полная таблица (capability / слой / реализовано / проверка / ограничение / следующий этап)
находится в §0.2 спеки Studio. Кратко: raw I/O есть только для Linux AF_PACKET
(замкнутый стенд); Windows и macOS не реализованы. Дедупликация живёт в engine
(ограниченный FIFO), не в core. VLAN не поддержан (`Unsupported`). ARP: только кодек,
resolver нет. Парсер paused.conf есть, пользовательского импорта нет. Engine реализует
контроль достоверности приёма (`Rx::health`, `RxLoss`/`RxStatsUnavailable`/`RxError`,
`Outcome.rx_health`) и watchdog TX (`EngineOptions::tx_stall_timeout`, 10 с,
`TxStalled`); `Completed` означает завершение с доступной статистикой без kernel drops,
а не обнаружение всех открытых портов. Дальнейшие абзацы этого раздела описывают
моменты 2A и этапа 1 (исторически).

Этап 2A (офлайн, без сети): crate `crates/rmasscan-engine` с отменяемым runtime
(один TX и один RX поток, Pause/Stop, ограниченные очереди), разбором недоверенных
RX-кадров, checkpoint/resume и fake-адаптером в памяти. Тесты проверяют побайтный
resume, остановку в пределах 1 с и ограниченную память на пространстве /0 (см.
`../docs/experiments/2026-10-23-rmasscan-stage2a.md`). Настоящий сетевой I/O
(AF_PACKET, BPF, Npcap), golden pcap и привилегированный runner это этап 2B и
позже; статус CI смотреть для конкретного HEAD. BENCHMARKS.md по-прежнему
описывает только офлайн-генерацию, не скорость передачи.

Этап 1 закрыт. Критерии выхода выполнены: `-sL` и `--echo` побайтно совпадают с C,
self-тесты C отображены на Rust (`tests/selftest_parity.rs`), передача и SYN покрыты
тестами и дифференциалами с C, генерация offline около 0.96–0.99 от C на minipc
(см. BENCHMARKS.md), C в графе сборки нет.

Статус CI относится к конкретному commit и в этом файле не фиксируется; CI собирает и гоняет offline-тесты, но не Windows/macOS raw I/O.

Первые задачи этапа 2:

- API сканирования: ранний выход (`ControlFlow`) и колбэк со структурой `Probe`, принимающий
  `&EffectiveConfig`; перенос шага source-port/cookie/frame из CLI в core.
  (Уже сделано в ветке: приватные поля `EffectiveConfig`, отказ от seed 0 в `validate`,
  усиленная защита «без C».)
- Контракт вызывающего для throttle: один `Throttler` на поток передачи, запускаемый с
  `max_rate/nic_count` после 1-секундного ожидания; одни и те же часы для `start` и
  `next_batch`; возврат 0 означает «вызвать снова»; `current_rate` публикуется через
  `AtomicU64`.
