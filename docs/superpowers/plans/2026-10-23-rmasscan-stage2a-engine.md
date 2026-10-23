# rmasscan — этап 2A: runtime движка и подготовка raw I/O

> Для исполнения: `superpowers:executing-plans` или
> `superpowers:subagent-driven-development`, по задачам с RED→GREEN.
> Сейчас заказаны проверка и план, реализация этим документом не начинается.

**Goal:** получить отменяемый Rust-движок с типизированными результатами,
Pause/Resume и проверяемым checkpoint на in-memory адаптере; подготовить точную
границу подключения реальных адаптеров этапа 2B.

**Architecture:** core остаётся чистой логикой. Новый `rmasscan-engine` владеет
потоками, состоянием и очередями и зависит только от core и Rust-зависимостей.
Trait адаптера определяется в engine; будущий `rmasscan-net` реализует его и
зависит от engine. CLI и будущий Studio runner соединяют engine и net.
Циклической зависимости engine↔net нет; Slint в runner отсутствует.

**Tech Stack:** Rust 1.99.1 / edition 2024; existing pinned dependencies;
std channels/threads; SHA-256 через pure-Rust `sha2` после проверки графа.
Не добавлять Tokio, libpcap, SQLite или новый GUI в этот этап.

**Spec:** актуальная спека порта в worktree `masscan-studio-rmasscan`,
`docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`, включая раздел
«Исправления после этапов 0–1», §4/5/6/7/9/10. Для Studio — rev 7 и
`2026-10-23-rmasscan-studio-integration.md`.
Фактическая база: [отчёт](../../experiments/2026-10-23-rmasscan-status-and-next-stage.md).

## Границы и порядок

1. Этапы 0–1 уже в remote main `04df2490bc627964907e4e13cb8e61dd8fe176be`.
   Начинать отдельную ветку от этого commit; не merge/reset грязный checkout Studio.
   Не дублировать параллельную работу в `feat/rmasscan-port`.
2. 2A выполняется без сети и повышенных прав. Включает настоящий runtime,
   но тестовый транспорт. Его успешный прогон не закрывает Npcap/BPF/AF_PACKET.
3. 2B — платформенные адаптеры и реальные захваты. Его очерёдность ниже;
   отдельный подробный план пишется после стабилизации API 2A.
4. Authenticated runner/IPC и подключение настоящего Scan к Studio — этап 3,
   после raw I/O. Существующий Process fixture пока сохраняет явную маркировку.

## Global Constraints

- Core и engine: `#![forbid(unsafe_code)]`; FFI/unsafe только в будущем net.
- Никаких C/C++ build dependencies, SDK Packet.lib или статической libpcap.
  ОС API и динамический Npcap остаются согласованными исключениями.
- IPv4 TCP SYN; Nmap внешний. Без баннеров, UDP/IPv6, firewall changes,
  постоянных служб, автоматической установки драйверов и автостарта скана.
- Studio сохраняет rate 1..10_000_000, wait=3, новый seed 1..UInt32.max.
  Внутри engine seed/index u64; seed 0 для runtime запрещён. Echo-паритет
  отдельно и не является разрешением запуска. Ни одно u64 не идёт в UI Number.
- Базовый runtime: один TX и один RX. Core сохраняет тестируемые shard/retries
  алгоритмы; runtime v1 принимает только shard=1/1, NIC=1, retries=0 и rounds=14.
  Остальное возвращает UnsupportedConfig, не игнорируется. Это соответствует
  текущим настройкам Studio; расширение runtime не переписывает core-оракул.
- Источник IP/MAC, router MAC, link type и source-port для теста задаются явно.
  Автовыбор одного порта против 16-портового диапазона пока не решать: оба
  существующих явных варианта сохранить, выбранный диапазон фиксировать в identity.
- При Pause прекращение TX ≤1 с, затем приём финальных ответов в течение wait.
  Stop не ждёт wait и завершает рабочие потоки ≤1 с на соблюдающем контракт I/O.
  Это новые критерии приёмки runtime, не измеренные гарантии платформы.
- Completed/Stopped/Failed и CheckpointReady различаются. Только Studio после
  durable commit и ACK вправе показывать сохранённое Paused.

## Review Focus

1. Pause/Stop на rate=1, во время throttle, при пустом RX и полной очереди.
2. Ошибка/частичная отправка: индекс не перепрыгивает неподтверждённые кадры.
3. Враждебный RX: обрезанные заголовки, неверные длины, фрагменты, чужой cookie.
4. Resume после изменения rate/адресов/исключений/портов/источника/версии движка.
5. Потеря consumer и Drop handle: фоновые потоки и raw handles не остаются жить.

## Контракты, общие для задач

Все сигнатуры ниже — новые предлагаемые API, не утверждение об их наличии.

```rust
// rmasscan-core::probe; поля ReadyPlan приватны, конструктор fallible
ReadyPlan::new(effective: EffectiveConfig, binding: AdapterBinding)
    -> Result<ReadyPlan, PlanError>;
ProbeCursor::new(plan: &ReadyPlan, next_index: u64) -> Result<ProbeCursor, PlanError>;
ProbeCursor::current(&mut self) -> Option<&Probe>; // повторный вызов не продвигает
ProbeCursor::advance_sent(&mut self); // ровно один успешно отправленный probe
ProbeCursor::position(&self) -> u64; // следующий неподтверждённый индекс

// Probe содержит index, ip/port источника и цели, seqno, frame: Vec<u8>.
// AdapterBinding: interface_id, link_type, source_ipv4, source_mac,
// next_hop_mac, source_ports (first,last). Это resolved immutable values.

// rmasscan-engine::io; каждый handle принадлежит ровно одному потоку
trait Tx: Send {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError>;
}
trait Rx: Send {
    fn recv(&mut self, buffer: &mut [u8], timeout: Duration) -> Result<Option<usize>, IoError>;
}
// SendStatus = Sent | WouldBlockUnsent | Uncertain.
// Uncertain -> Failed, без безопасного checkpoint. Нет скрытого retry после него.
struct AdapterPair { tx: Box<dyn Tx>, rx: Box<dyn Rx> }

Engine::start(plan: ReadyPlan, io: AdapterPair, options: EngineOptions)
    -> Result<EngineHandle, StartError>;
Engine::resume(plan: ReadyPlan, checkpoint: Checkpoint, io: AdapterPair,
               options: EngineOptions) -> Result<EngineHandle, StartError>;
EngineHandle::pause(&self);
EngineHandle::stop(&self);
EngineHandle::try_event(&self) -> Result<Event, TryRecvError>;
EngineHandle::join(self) -> Result<Outcome, EngineError>;
```

EngineOptions: scan_id/attempt_id (16 байт каждый), wait из плана,
result_capacity=4096, event_batch_limit=1000, progress_interval=250 мс.
I/O timeout максимум 50 мс; TX проверяет отмену перед каждой отправкой.
Часы/sleep внедряются через внутренний test runtime, чтобы тесты не ждали секунды.
Outcome хранится отдельно от result queue; наблюдение результата завершения
не разрешает потерять уже принятые события. Продвижение счётчика sent — только
после Sent. Внешний watchdog зависшего системного вызова остаётся задачей runner.

## Задача 1. Закрыть API core и защитить будущий граф сборки

**Files:** `rmasscan-core/src/config.rs`, `scan.rs`, CLI `main.rs/args.rs`,
`rmasscan-core/tests/no_c_in_build.rs`, `rmasscan/deny.toml`, existing golden tests.

**Consumes:** нынешние ScanConfig, EffectiveConfig и golden-фикстуры.
**Produces:** private EffectiveConfig + read-only getters; runtime validation;
проверка normal/build/dev всего workspace для всех target-платформ.
Сохранить в EffectiveConfig нормализованные исходные target/exclusion ranges
отдельно от итогового massip: они нужны для identity, а сейчас после validate
в объекте остаётся только эффективный набор.

- [ ] RED: библиотечный Scan с seed=0 отвергается; Echo сохраняет golden;
  вход CLI `-sL --retries 1` получает явную ошибку до цикла, не зависает.
  Проверить обход запрета через новую target-specific dev-зависимость в fixture-графе.
- [ ] Run `cargo test --locked --workspace`; получить воспроизводимые FAIL
  новых тестов без запуска заведомо бесконечного цикла в общем test process.
- [ ] Сделать поля EffectiveConfig private, добавить getters и мигрировать
  потребителей. В core-проверку seed добавить разделение операции. CLI list+retries
  запрещать явно; transmit и прежние golden с retries сохраняются.
- [ ] no-C: `cargo tree --locked --workspace --target all -e normal,build,dev
  --prefix none`; сравнивать имена пакетов целиком. Запретить также pcap-sys/
  libpcap-sys. В cargo-deny включить allowlist build scripts, executables=deny,
  include-archives=true; разрешения системных import libraries адресные,
  а не blanket исключение `windows-*`.
- [ ] GREEN: все golden/property тесты, fmt, Clippy и cargo-deny. Зафиксировать
  обоснованные исключения build scripts с версиями; не выдать чистый граф
  только по поиску слова `cc` в lockfile.

## Задача 2. Перенести генерацию probe из CLI в отменяемый core API

**Files:** new `rmasscan-core/src/probe.rs`, `scan.rs`, `lib.rs`;
modify CLI `main.rs`; new `rmasscan-core/tests/probe_cursor.rs`.
**Consumes:** закрытый EffectiveConfig, existing cookie/template/index logic.
**Produces:** ReadyPlan, AdapterBinding, Probe и ProbeCursor из контракта выше.

- [ ] RED: текущий probe возвращается повторно до advance_sent; после n Sent
  position=n; восстановление с n даёт точный suffix эталонного trace.
  Range=1, rate=1/10M, максимальный seed, оба source-port варианта, границы
  range-1/range/range+1. range означает конец, range+1 — ошибка.
- [ ] RED: ошибка callback/отмена после 3 probes прекращает обход большого
  диапазона; не просто подавляет callback до конца генерации. Невалидные
  source_ports и неразрешённые runtime retries/shard отвергаются.
- [ ] ReadyPlan для нового запуска отвергает nonzero legacy resume_index и
  ненулевой resume_count; продолжение runtime принимается только через
  Engine::resume с проверенным checkpoint. Эти поля не игнорировать молча.
- [ ] Перенести CLI формулу source-port/cookie/frame без изменения байтов.
  Для callback-обёртки использовать ControlFlow, останавливающий генератор.
  ReadyPlan не принимает неполный Echo-job. Саму перестановку заново не писать.
- [ ] GREEN: `cargo test --locked -p rmasscan-core --test probe_cursor` и
  полный workspace. Сохранить побайтовый результат CLI packet-trace тестов.

## Задача 3. RX parser и валидация ответа — без сети

**Files:** new `rmasscan-core/src/receive.rs`, `arp.rs`, `tests/receive.rs`.
**Consumes:** ReadyPlan, cookie/checksum, входные байты и LinkType.
**Produces:** `parse_reply(frame, link, &ReadyPlan) -> Result<Option<Reply>, ParseError>`;
Reply = remote/local IPv4+ports, Open/Closed, flags, ttl, timestamp задаётся engine.

- [ ] RED: валидный SYN-ACK -> Open; подтверждённый RST -> Closed по cookie-
  правилам upstream. Чужой tuple/ACK, чужая цель/порт, пакет TX, UDP не дают результата.
- [ ] RED: каждый усечённый префикс валидного кадра, IPv4 IHL/total length,
  TCP data offset, IPv4 fragments, VLAN и неизвестный link type; без panic/OOB.
  VLAN явно распознать либо вернуть Unsupported; не интерпретировать как IPv4.
- [ ] Реализовать bounds-first parser для Ethernet/NULL/RAW. Выделить wire
  checksums и cookie validation; политика checksum-offload должна быть явной,
  не отключать проверки глобально. Сравнить SYN-ACK/RST ветки с upstream main.c.
- [ ] ARP request/reply codec: фиксированные типы/длины, проверка адресата и
  sender tuple; неподходящий ответ не завершает ожидающий resolve.
- [ ] GREEN: `cargo test --locked -p rmasscan-core --test receive`, property-
  тесты произвольных байтов. cargo-fuzz не добавлять: C++-исключение не согласовано.

## Задача 4. Runtime, ограниченные очереди и корректное завершение

**Files:** new `rmasscan-engine/{Cargo.toml,src/{lib,io,events,engine,fake}.rs}`;
`tests/{lifecycle,backpressure}.rs`, workspace manifest;
modify `rmasscan-core/src/throttle.rs` с тестами отмены внутри throttle.
**Consumes:** ReadyPlan/ProbeCursor/Reply, Tx/Rx trait.
**Produces:** EngineHandle и Event: Started, Progress, Results, CheckpointReady,
Finished. Ровно один terminal outcome, после остановки TX/RX.

- [ ] RED: complete, stop сразу/при rate=1/в drain/при полной очереди,
  send failure, WouldBlockUnsent, Uncertain, RX error, закрытый consumer,
  Drop handle. Все worker handles joined; после terminal новых отправок нет.
- [ ] FakeAdapter записывает отправленные frames и управляемо выдаёт ответы,
  ошибки, задержки и дубли. В нём нет socket API. Тестовые часы детерминированы.
- [ ] Один TX, один RX; у каждого свой handle. Перенести throttle контракт
  из BENCHMARKS/README: те же часы start/next_batch, 0 означает повторить,
  `current_rate.to_bits()` публикуется AtomicU64. Длительный sleep разбивать
  на отменяемые части ≤50 мс. Добавить
  `next_batch_interruptible(packet_count, clock, cancelled: impl Fn() -> bool)
  -> Result<u64, ThrottleCancelled>` с проверкой флага внутри всех повторов
  и до/после каждого sleep. Старый next_batch оставить совместимой обёрткой
  с cancelled=false для golden/benchmark. Проверки только снаружи next_batch
  недостаточно. Проверять stop также перед send.
- [ ] Progress coalesce; Results не терять молча. При переполнении bounded
  result queue остановить TX, завершить Failed(ConsumerTooSlow), сохранить уже
  принятые результаты для drain. Это не Completed и не валидная пауза.
  Учитывать overflow/drop счётчики ОС в будущем net; «без потерь» не обещать.
- [ ] Dedup по remote/local tuple, ограниченный cache до 100k записей с явной
  политикой eviction; повтор после eviction допустим, Studio обеспечивает
  устойчивую уникальность результатов. Не хранить HashSet на все адреса /0.
- [ ] GREEN: `cargo test --locked -p rmasscan-engine`; stop ≤1 с на fake I/O,
  обработка отмены не зависит от дренирования очереди пользователем.

## Задача 5. Checkpoint и продолжение той же последовательности

**Files:** new `rmasscan-engine/src/{checkpoint,identity}.rs`,
`tests/{pause_resume,identity}.rs`; extend engine state machine.
**Consumes:** cursor следующего неподтверждённого probe, неизменяемый ReadyPlan.
**Produces:** versioned Checkpoint с scan_id, attempt_id, engine/protocol version,
job_digest, next_index; `Engine::resume` из общего контракта.

- [ ] RED: pause на каждом индексе малого задания; prefix + resume suffix
  побайтно совпадает с uninterrupted trace. Покрыть pause до первой отправки,
  последний probe, pause во время WouldBlock, обычное завершение во время pause.
- [ ] RED: изменение любого identity поля отвергает resume до первого send;
  повреждённый version/index/scan_id также отвергается. Uncertain/Failed/Stop
  не выдаёт CheckpointReady. Одновременный Stop побеждает Pause.
- [ ] SHA-256 identity по versioned canonical binary encoding (фиксированный
  endian, length prefixes): нормализованные цели/порты/исключения, seed, rate,
  retries/shard/rounds, wait, source binding и engine algorithm version.
  Не использовать DefaultHasher или неоднозначное склеивание строк.
  Engine требует прежний binding при resume; смена сети -> отказ/Interrupted.
  scan_id сохраняется, attempt_id нового запуска отличается от attempt_id
  checkpoint; последний фиксирует происхождение и не выдаётся за текущую попытку.
  algorithm version — явная версия алгоритма/формата, не hash каждого commit:
  изменение комментария не делает сохранённое задание несовместимым.
- [ ] Pause: TX перестаёт отправлять, RX дренирует wait, pending results
  доступны до checkpoint. При заполнении очереди — Failed, не успешная пауза.
  next_index=range -> завершено, а не Resume с пустым range.
- [ ] GREEN: `cargo test --locked -p rmasscan-engine --test pause_resume --test identity`.
  CheckpointReady ещё не persistent Paused; SQLite/ACK не имитировать в engine.

## Задача 6. Приёмка 2A и подготовка подключения Studio

**Files:** `.github/workflows/rmasscan.yml`, `rmasscan/README.md`,
new `docs/experiments/<date>-rmasscan-stage2a.md`; Studio adapter migration note.
**Consumes:** реализованные задачи 1–5, существующая CI матрица.
**Produces:** зафиксированный commit API, рабочий fake-engine harness и отчёт.

- [ ] Включить engine и его no-C graph в CI на всех трёх ОС. Прогнать
  `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets
  -- -D warnings`, `cargo test --locked --workspace`, `cargo deny check bans licenses sources`.
- [ ] Fresh review: IPC-ready immutable boundary, cancellation, queue failure,
  identity, partial send. Исправить важные находки тестами до следующей стадии.
- [ ] Измерить bounded memory на генерации /0 и пустом RX; генератор не
  материализует весь range. Отдельно отметить, что RSS UI лимит здесь не измерялся.
- [ ] Подготовить обновление snapshot Studio с NOTICE/LICENSE и checksum manifest;
  заменить доступ к полям EffectiveConfig на getters. До публикации commit
  API не копировать mutable worktree в Studio. Офлайн preview тесты сохраняются.
- [ ] GO 2A: все проверки выше проходят; trace resume совпадает; остановка
  укладывается в контракт. FAIL: зависший worker, пробел в последовательности,
  принятый чужой reply или ложный CheckpointReady после ошибки.

## Этап 2B: что следует после 2A

Это дорожная карта следующего сетевого этапа, не замена подробного плана 2B.

| Очерёдность | Результат | Как принимаем |
| --- | --- | --- |
| 1. Golden pcap | Воспроизводимый C oracle capture + committed harness/manifest | Изолированный Linux namespace/veth, фиксированные seed/rate/source/adapter; трасса всех TX и ответов, версии и hashes. Существующее разрешение на такой oracle capture уже записано в §12; повторно не спрашивать его |
| 2. Linux AF_PACKET | rmasscan-net, explicit adapter/source/gateway, send/recv | Bind к выбранному ifindex; открытие требует CAP_NET_RAW. Проверка байтов, SYN-ACK/RST, drop counters, pause/resume в том же изолированном стенде. Никаких маршрутов наружу |
| 3. Ранний Windows spike | Dynamic Npcap, отдельные TX/RX handles, bounded receive | Известный доверенный путь DLL, отсутствие Npcap не ломает offline; ARM/ABI не путать. Физическая Windows 11: send/recv и pause/resume trace, не только запуск EXE. Нет машины/драйвера — NOT RUN, не PASS |
| 4. macOS BPF | ioctl/буферы/выравнивание bpf_hdr, выбор link type | ABI по установленному SDK; owned fd, bounded read; реальные байты и pause/resume на согласованном лабораторном интерфейсе. Нельзя считать Ethernet golden достаточным для utun |
| 5. Discovery/ARP и устойчивость | default route, adapters, resolved binding, ошибки сети | Явный timeout ARP, недоступный интерфейс, смена адреса/VPN, sleep/wake -> диагностируемый Interrupted; никакого продолжения на другом интерфейсе молча |
| 6. Sendqueue и паритет | Npcap batch send и измерения 100..100k pps | Сначала correct single-frame путь. Успех всей очереди подтверждает batch; частичная/неопределённая отправка -> Failed либо доказанный conservative replay, без пропусков. Никакого продвижения cursor на размер неотправленной очереди |

На каждой ОС проверить остановку при полном отсутствии входящего трафика.
Для Npcap использовать nonblocking next_ex/dispatch и собственный дедлайн;
само наличие packet timeout или вызова breakloop не считать доказательством
завершения любого blocked read. Нет тихого fallback на обычный TCP connect.

GO 2B: реальные wire traces трёх ОС, корректные результаты и pause/resume.
Отсутствие Windows-паритета блокирует трёхплатформенную v1, но не офлайн 2A.
После этого этап 3: сессионный elevated runner, IPC authentication/handshake,
durable history/checkpoint ACK и настоящее сканирование из Slint.

## Проверенные источники для будущего net/CI

- [Linux packet(7)](https://www.man7.org/linux/man-pages/man7/packet.7.html):
  AF_PACKET, bind по ifindex, CAP_NET_RAW, PACKET_OUTGOING и усечение frames.
- [Npcap nonblocking mode](https://npcap.com/guide/wpcap/pcap_setnonblock.html):
  next_ex/dispatch возвращают 0 без пакетов; loop в этом режиме может крутиться.
- [Npcap breakloop](https://npcap.com/guide/wpcap/pcap_breakloop.html):
  ограничения wakeup и необходимость учитывать платформу/тип capture handle.
- [cargo-deny build checks](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html):
  allow-build-scripts, executable/archive checks и адресные исключения.

## Самопроверка плана

API/probe/остановка -> задачи 1/2/4; RX hostile input -> 3;
Pause/Resume/identity -> 5; no-C и три CI ОС -> 1/6; источник/route/Npcap/BPF
и реальные pcap явно вынесены в 2B. Долговечность результатов и auth IPC — этап 3.
Тестовые адаптеры не выдаются за реальные сканы; большой этап не скрыт за одной
кнопкой Scan. Публикация, merge и реальные сетевые действия не выполняются при
подготовке этого плана.
