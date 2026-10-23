# Rust masscan: закрытие 2A и первый сетевой этап 2B — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** исправить два дефекта ревью 2A и доказать реальный SYN TX/RX,
остановку и resume Rust-движка на изолированном Linux namespace/veth.

**Architecture:** `rmasscan-core` хранит чистые алгоритмы, `rmasscan-engine`
управляет потоками и жизненным циклом, новый `rmasscan-net` реализует системный
I/O. Зависимости направлены net → engine → core; CLI собирает их вместе.
Linux сначала получает явно заданный адаптер и адреса; автоматический выбор
маршрута и интеграция со Slint остаются следующими самостоятельными задачами.

**Tech Stack:** Rust workspace, std, системный Linux AF_PACKET через libc,
существующие FakeAdapter и golden fixtures; C masscan только как тестовый оракул.

**Spec:** [спека Rust-порта](../specs/2026-10-23-masscan-rust-port-design.md),
включая errata; [план 2A](2026-10-23-rmasscan-stage2a-engine.md) задаёт актуальный
runtime API вместо раннего наброска §10.2. Последующие разрешения пользователя
на реализацию заменяют исторический запрет реализации в заголовке спеки.
Этот запрос — подготовка плана; сам план ничего не запускает.

## Исходное состояние

- Проверенная база: `feat/rmasscan-stage2a`, `6ce7a5db23e11f300b9b49e921b610701d704c2f`.
- Ревью: два воспроизводимых P2 — принятие ответа вне задания и потеря
  непрочитанных событий в `join_drain` при панике рабочего потока.
- Локально: 282 passed, 0 failed, 1 ignored; fmt и Clippy проходят.
- [CI этой базы](https://github.com/disclaimer8/masscan-studio/actions/runs/40006103078):
  macos-14, ubuntu-24.04 и windows-2022 — success. Утверждение отчёта 2A
  «push не делался» устарело; это нужно исправить при закрытии 2A.
- Реального I/O пока нет. Запуск ранее отправленного Windows EXE не подтверждает
  работу нового сканера, Npcap или этого commit.

## Global Constraints

- IPv4 TCP SYN; runtime: один TX, один RX, NIC=1, shard=1/1, retries=0,
  rounds=14, явный ненулевой seed. Поддержка source-port range сохраняется.
- `Pause` прекращает TX ≤1 с, затем RX drain `wait`; `Stop` пропускает drain
  и завершает оба потока ≤1 с при соблюдении адаптером I/O-контракта ≤50 мс.
- Cursor движется только после `Sent`; `WouldBlockUnsent` повторяет тот же кадр;
  `Uncertain` завершает Failed без checkpoint. Сдача пакета ОС не означает
  доставку по сети: wire capture проверяется отдельно.
- `CheckpointReady` не означает durable Paused. Хранилище, IPC ACK и runner — этап 3.
- Core/engine/CLI остаются `forbid(unsafe_code)`. Unsafe допускается только
  внутри net, рядом с документированными условиями корректности FFI.
- Нет C/C++ в продуктовой сборке, libpcap, SDK Npcap или build-time bindgen.
  Системная libc допустима; существующий `cargo deny` и no-C guard сохраняются.
- AGPL-3.0 и NOTICE сохраняются. Nmap остаётся внешним; UI остаётся Slint.
- Существующее разрешение §12 покрывает C-oracle capture в изолированном Ubuntu
  namespace. Rust wire-tests выполняются в том же замкнутом стенде в рамках
  поручения на реализацию. Другие сети этим планом не включены в испытания.
- Никаких изменений firewall, bridge/NAT к сети хоста или глобального `pkill`.
  Cleanup удаляет только namespace, процессы и файлы конкретного запуска.

## Review Focus

1. Поздний корректный ответ старого скана с тем же seed: чужие и исключённые
   IP/порты не попадают в результаты — задача 1.
2. Паника после принятого результата: событие и итоговые счётчики доступны
   вызывающему — задача 2.
3. Нет пакетов, постоянный WouldBlock либо поток EINTR: CPU не занят spin-loop,
   исходный дедлайн не продлевается, Stop укладывается в контракт — задачи 3/5.
4. Переполненный capture buffer, усечённый/исходящий кадр: нет ложного Open и
   нельзя выдавать неполный захват за доказательство паритета — задачи 4–6.
5. Адаптер исчез или ошибка произошла после отправки: Failed, нет checkpoint
   и нет молчаливого переключения интерфейса — задачи 5/6.

## Границы следующего результата

Следующий принимаемый результат — **GO Linux explicit-binding**, а не GO всех
трёх ОС. Он включает задачи 1–6 ниже. Windows проверяется следующим сетевым
подэтапом; macOS, discovery/ARP и sendqueue завершают общий 2B.
Это разбиение работы не ослабляет критерий трёхплатформенной v1.

## Задача 1. Фильтровать RX по текущему заданию

**Files:** modify `rmasscan/crates/rmasscan-core/src/receive.rs`;
test `rmasscan/crates/rmasscan-core/tests/receive.rs`.

**Interfaces:** сохранить `parse_reply(frame, link, &ReadyPlan)` и
`parse_reply_with`; читать итоговые `plan.effective().massip().ipv4()/ports()`.
Источник истины — набор после исключений, не `source_targets`.

- [ ] Добавить тесты `reject_previous_job_target_with_valid_cookie`,
  `reject_previous_job_port_with_valid_cookie`, `reject_excluded_target` и
  `reject_excluded_port`: валидные checksum и cookie, тот же seed/binding,
  ответ построен для предыдущего задания; ожидать `Ok(None)`.
- [ ] Запустить `cargo test --locked -p rmasscan-core --test receive` из
  `rmasscan/`; подтвердить падение новых assertions на базе 2A.
- [ ] В `parse_ipv4_tcp` проверить remote IP/port по итоговым диапазонам
  перед cookie/checksum. Использовать отсортированные диапазоны с двоичным
  поиском, чтобы не вводить линейный обход тысяч целей для каждого пакета.
- [ ] Повторить тесты; добавить положительные проверки границ диапазонов
  и valid RST. Старые golden и cookie-тесты должны остаться зелёными.
- [ ] Отдельный commit: `fix(core): reject replies outside effective scan targets`.

## Задача 2. Сохранять результаты при панике

**Files:** modify `rmasscan/crates/rmasscan-engine/src/engine.rs`;
test `rmasscan/crates/rmasscan-engine/tests/lifecycle.rs`.

**Interfaces:** сохранить тип
`join_drain(self) -> Result<(Outcome, Vec<Event>), EngineError>`.
Когда terminal outcome существует, worker panic возвращается как
`Ok((Outcome { reason: Failed(WorkerPanicked), .. }, events))`.
Ошибка отсутствия outcome остаётся `Err(NoOutcome)`; checkpoint при панике нет.

- [ ] Добавить `rx_panic_preserves_accepted_results_on_join_drain`:
  RX отдаёт валидный SYN-ACK, затем panic; дождаться outcome, получить ровно
  один reply и `received == 1` через `join_drain`.
- [ ] Добавить аналогичный TX panic после подтверждённой отправки/приёма,
  синхронизируя тест барьером, а не произвольным sleep.
- [ ] Запустить `cargo test --locked -p rmasscan-engine --test lifecycle`;
  подтвердить красные новые тесты, затем исправить путь `join_drain`.
- [ ] Проверить `Failed(WorkerPanicked)`, отсутствие checkpoint, освобождение
  handles, отсутствие дублей уже прочитанных событий. Уточнить rustdoc `join`.
- [ ] Отдельный commit: `fix(engine): retain accepted events after worker panic`.

## Задача 3. Подготовить ожидания runtime к реальному адаптеру

**Files:** modify `rmasscan/crates/rmasscan-engine/src/engine.rs`,
`rmasscan/crates/rmasscan-core/src/throttle.rs`;
test `rmasscan/crates/rmasscan-engine/tests/lifecycle.rs`.

**Interfaces:** `Tx`, `Rx`, `SendStatus` пока не менять. Временные системные
ошибки обрабатывает net в пределах исходного дедлайна; наружу `IoError`
означает фатальный сбой. `Ok(None)` остаётся нормальным timeout RX.

- [ ] Добавить тест постоянного `WouldBlockUnsent`: повторяется один кадр,
  cursor не движется, между попытками есть ожидание; Pause/Stop ≤1 с.
- [ ] Добавить тест отмены непосредственно перед throttle sleep:
  после обнаружения отмены новый сон не начинается.
- [ ] Реализовать interruptible backoff 1 мс после `WouldBlockUnsent`
  через существующие Clock; проверить отмену до и после ожидания.
  **1 мс — новое решение этого плана**, а не измерение производительности.
- [ ] Запустить `cargo test --locked -p rmasscan-engine` и
  `cargo test --locked -p rmasscan-core throttle`; не менять порядок probe.
- [ ] Обновить `docs/experiments/2026-10-23-rmasscan-stage2a.md`:
  закрытые дефекты, текущий CI, остаточные ограничения.
- [ ] Отдельный commit: `fix(engine): bound retries before live adapter integration`.

## Задача 4. Независимый C wire oracle и формат свидетельств

**Create:** `rmasscan/scripts/wire-lab.sh`,
`rmasscan/scripts/wire_capture.py`, `rmasscan/scripts/verify-wire.py`,
`rmasscan/tests/golden/wire/manifest.json`,
`rmasscan/tests/golden/wire/README.md`, небольшие `*.pcap` fixtures.
**Read/reuse:** `rmasscan/scripts/build-oracle.sh` и существующий golden manifest.
Не выполнять старый скрипт целиком: он содержит глобальный cleanup процессов.

**Interfaces:** `wire-lab.sh --oracle BIN --out DIR` создаёт два уникальных
network namespace с veth между ними; recorder пишет classic pcap и JSON manifest.
`verify-wire.py --expected PCAP --actual PCAP` сравнивает упорядоченный поток
исходящих SYN, не временные метки и не посторонние ARP/RST.
Capture использует Python stdlib AF_PACKET только как независимый test tool.
`verify-wire.py --self-test` запускает offline проверки самого comparator.

- [ ] Добавить offline self-test comparator: равные кадры проходят,
  перестановка/пропуск/дубль/изменённый байт SYN падают; truncated pcap падает.
- [ ] Реализовать стенд без uplink, bridge и default route; capture стартует
  до scanner с явным readiness ACK. До отправки сохранить topology и routes.
- [ ] Использовать уже собранный проверяемый C oracle, если он доступен;
  иначе собрать pinned upstream по ранее данному разрешению. Для wire нужен
  оригинальный бинарник, не исправленная для `--offline` копия.
- [ ] В обоих namespace явно задать MAC/IP, seed, source-port, rate,
  rounds=14, retries=0 и wait=3. Сохранить effective echo и наличие/хэш
  `/etc/masscan/masscan.conf`; непустой влияющий конфиг исключить из стенда,
  не редактируя глобальный файл хоста.
- [ ] Снять небольшие кейсы: один адрес/порт; несколько адресов и портов;
  исключение; source-port single/range; SYN-ACK и RST. Responder создаёт
  известные ответы на peer, без зависимостей от внешних серверов.
- [ ] Manifest включает commit/sha256 oracle и harness, команды, версии ОС,
  binding, ожидаемые количества, capture drops/truncation и hashes pcap.
  Потери захвата делают сравнение недействительным, а не успешным.
- [ ] Проверить cleanup после успеха, ошибки и SIGINT: завершаются только
  собственные дочерние процессы, удаляются только собственные namespace.
- [ ] Отдельный commit: `test(net): add isolated wire oracle and capture fixtures`.

## Задача 5. Linux AF_PACKET с ограниченным временем I/O

**Create:** `rmasscan/crates/rmasscan-net/Cargo.toml`,
`src/lib.rs`, `src/linux/mod.rs`, `src/linux/socket.rs`,
`tests/linux_io.rs` внутри нового crate.
**Modify:** `rmasscan/Cargo.toml`, `Cargo.lock`, `deny.toml`,
`rmasscan/crates/rmasscan-core/tests/no_c_in_build.rs` при необходимости.

**Interfaces:** `rmasscan_net::open_explicit(binding: &AdapterBinding)
-> Result<OpenedAdapter, NetError>`; `OpenedAdapter { io: AdapterPair,
stats: NetStatsHandle }`. Клонируемый `NetStatsHandle::snapshot() -> NetStats`
возвращает накопленные `rx_packets`, `rx_truncated`, `rx_outgoing`,
`kernel_drops: Option<u64>` (все остальные счётчики u64); `None` означает,
что показатель недоступен. Handle не владеет socket fd и переживает их закрытие.
`NetError` различает UnsupportedPlatform,
UnsupportedLink, PermissionDenied, InterfaceMismatch и System(String).
На этом шаге Linux поддерживает Ethernet; другие платформы/типы дают явную
ошибку до отправки. `interface_id` — имя, проверенное через ОС, не shell-аргумент.

- [ ] Зафиксировать libc из существующего lockfile точной версией.
  Net не наследует workspace `forbid(unsafe_code)`; использует
  `deny(unsafe_op_in_unsafe_fn)`, private FFI-модуль и owned fd.
  Не ослаблять forbid в остальных crates или запрет C в графе.
- [ ] Добавить unit-тесты через private syscall seam: EAGAIN/EINTR,
  readiness без последующего пакета, partial send, закрытие после ошибки,
  усечённый кадр, PACKET_OUTGOING, неверный ifindex/link type.
- [ ] Реализовать отдельные TX/RX fd, nonblocking + poll до абсолютного
  дедлайна; timeout ограничен 50 мс. Повтор EINTR не перезапускает дедлайн.
  Привязать оба fd к выбранному ifindex, проверить IP/MAC binding.
- [ ] `send == frame.len()` → Sent; подтверждённый EAGAIN → WouldBlockUnsent;
  частичная/неопределённая отправка → Uncertain; остальные ошибки → IoError.
  Не требовать promisc и не менять настройки сетевого интерфейса.
- [ ] RX отбрасывает исходящие и усечённые кадры, не выдаёт длину больше
  caller buffer. Учёт отброшенных кадров и kernel drops доступен отчёту
  испытаний; чтение статистики не сбрасывает ранее накопленные значения.
- [ ] Проверить реальные empty-RX timeout, отсутствие прав, неверный
  интерфейс и fd cleanup внутри стенда. Системные тесты явно opt-in/ignored
  вне лаборатории; skip не обозначать как PASS.
- [ ] Запустить workspace tests, fmt, Clippy, no-C и cargo deny на трёх ОС.
  На macOS/Windows этот шаг проверяет переносимость сборки, не raw I/O.
- [ ] Отдельный commit: `feat(net): implement bounded Linux AF_PACKET adapters`.

## Задача 6. Сквозная приёмка Linux и реальные checkpoint/resume

**Create:** `rmasscan/crates/rmasscan-net/examples/wire_scan.rs`,
`rmasscan/crates/rmasscan-net/tests/linux_wire.rs`,
`docs/experiments/2026-10-23-rmasscan-stage2b-linux.md`.
**Modify:** `wire-lab.sh`, `verify-wire.py`, `rmasscan/README.md`,
`.github/workflows/rmasscan.yml` для обычных offline checks нового crate.

**Interfaces:** лабораторный example принимает явные targets/ports/binding,
seed/rate, `--pause-after N` и `--resume-checkpoint FILE`.
Он использует ReadyPlan + Engine + open_explicit; выводит JSON summary и
checkpoint bytes. Это test harness, не новый пользовательский CLI сканирования.
В Engine передаётся `OpenedAdapter.io`, stats handle остаётся у harness.

- [ ] Проверить непрерывную передачу: исходящие SYN совпадают с C oracle
  по порядку и байтам, ответы дают ожидаемые Open/Closed без дублей.
- [ ] Для точной паузы использовать TX-декоратор: после N подтверждённых
  отправок запросить Pause, не пропуская N+1; это сохраняет реальный I/O.
  Сравнить конкатенацию pcap pause+resume с непрерывной трассой побайтно.
- [ ] Проверить N=0, середину, последний pending probe и завершённое задание;
  менять attempt_id, сохранять scan_id. Изменение rate/binding/targets
  отклоняется до открытия отправки; corrupt checkpoint также отклоняется.
- [ ] На rate=1 проверить Stop при тишине, RX drain и заполнении очереди;
  удаление veth во время скана → диагностируемый Failed, без checkpoint.
  После Stop подтвердить отсутствие последующих TX, живых workers и fd.
- [ ] Снять 5 повторов C/Rust на 100, 1k, 10k, 100k pps: transmitted,
  captured, received, drops, CPU/RSS и время остановки. Отдельно оценивать
  rate по steady-state отправкам, исключив startup и wait из знаменателя.
  Стенд должен обеспечивать достаточный диапазон для измерения; неполный
  захват помечается INVALID, а не маскируется нормализацией.
- [ ] Запустить из `rmasscan/`: `cargo test --locked --workspace`,
  `cargo fmt --all --check`,
  `cargo clippy --locked --workspace --all-targets -- -D warnings`,
  `cargo deny check bans licenses sources`; затем отдельный opt-in wire suite.
- [ ] Зафиксировать команды лабораторного запуска, hashes, сырые результаты,
  привилегии и все NOT RUN. Независимое ревью unsafe/timeout/resume до GO.
- [ ] Отдельный commit: `test(net): verify Linux wire parity and pause resume`.

## Критерий GO Linux

Оба P2 закрыты regression-тестами; нет C в сборке; CI трёх ОС зелёный;
Linux wire sequence совпадает с C; pause/resume не пропускает и не добавляет
SYN; Stop ≤1 с при тишине и нагрузке; нет fd/thread leaks или ложного
checkpoint при ошибках. Метрики скорости приложены; недостигнутый паритет
±20% на 100–100k pps остаётся открытым gate всего 2B, а не объявляется PASS.

## Порядок после GO Linux — отдельные планы реализации

| Этап | Результат и проверка | Что блокирует переход |
| --- | --- | --- |
| 2B-Windows, сразу после Linux | `net/windows` + dynamic Npcap; EXE лабораторного harness для пользователя. Проверить отсутствие Npcap, Admin-only, доверенный путь DLL, отдельные TX/RX, пустой RX и собственный deadline; реальные wire traces, Stop и pause/resume | Запуск окна или EXE без raw TX/RX не считается приёмкой. Нет оборудования/pcap — NOT RUN. Не переносить проблему до интеграции Slint |
| 2B-macOS | `net/macos` с BPF; проверка ABI/буферов по SDK, native arm64, bounded read и same wire suite. Ethernet и NULL/RAW проверяются отдельно | Ethernet-тест не доказывает работу VPN/utun. Ошибка подписи приложения из прежнего crash report проверяется отдельно перед GUI-поставкой |
| 2B-discovery/ARP | Получение адаптеров и маршрута, ARP next-hop и ответы на ARP, RX source MAC metadata; валидированный фиксированный binding до Engine::start | Таймаут ARP/смена адреса/сеть/VPN/sleep должны завершать или явно прерывать задание, не переключать источник молча |
| 2B-source identity | Закрыть хвост source IPv4 range либо явно согласовать сохранение single-IP ограничения; учесть source range и resolve-параметры в версии identity | Нельзя молча расширить AdapterBinding, оставив старый digest и checkpoint version |
| 2B-sendqueue/скорость | Npcap batch send, подтверждение только реально принятых пакетов; частичная/неопределённая отправка → Failed без checkpoint; повторить performance matrix | Текущий Tx API подтверждает один кадр. До batching отдельно определить batch receipt API и версию контракта; нельзя скрытно буферизовать кадры за Sent |
| 3-Studio | Сессионный Rust runner, IPC/handshake, потеря канала останавливает engine; durable checkpoint ACK; pinned snapshot и миграция getters; реальное Scan из Slint | GO всех трёх ОС, отдельный план хранения без C и решённый конфликт прежнего rusqlite/bundled. Nmap без повышения прав; системная тема и host actions сохраняются |

Требование отсутствия постоянного демона остаётся. Переход на встроенный engine
устраняет отдельный процесс masscan, но не отменяет проверку смерти runner при
разрыве IPC. Swift-версия остаётся рабочим эталоном до полной приёмки замены.

## Источники и самопроверка

- [Linux packet(7)](https://man7.org/linux/man-pages/man7/packet.7.html):
  CAP_NET_RAW, bind по ifindex, PACKET_OUTGOING, MSG_TRUNC и статистика.
- [Npcap nonblocking](https://npcap.com/guide/wpcap/pcap_setnonblock.html):
  `pcap_next_ex`/dispatch возвращают 0 при отсутствии пакетов; loop для такого
  ожидания не подходит. Эта документация не доказывает deadline TX sendqueue.
- Review Focus 1→задача 1; 2→2; 3→3/5; 4→4/5/6; 5→5/6.
- Все API текущего runtime сохранены, кроме уточнения результата panic в join;
  новые интерфейсы здесь явно помечены как проектируемые.
- Этот документ создаёт только план. Исходники, зависимости, сетевые настройки,
  установленное приложение, история сканов и git commits при подготовке не меняются.
