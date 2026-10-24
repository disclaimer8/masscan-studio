# rmasscan: закрытие ревью и подготовка следующего этапа — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** закрыть подтверждённые дефекты достоверности результата и TX-прогресса,
согласовать документы с фактическим кодом и получить проверяемую Linux-базу для Windows.

**Architecture:** сохранить `net → engine → core`: net сообщает измеренные потери,
engine определяет исход и допустимость checkpoint. Core остаётся stateless-парсером;
дедуп остаётся в engine. Slint, runner и новые платформенные адаптеры в этот патч не входят.

**Tech Stack:** существующий Rust workspace, Linux AF_PACKET, fake adapters/ManualClock,
Python wire harness, GitHub Actions. Новые зависимости не нужны.

**Spec:** [порт сканера](../specs/2026-10-23-masscan-rust-port-design.md),
[контракты 2A](2026-10-23-rmasscan-stage2a-engine.md),
[Linux 2B](2026-10-23-rmasscan-stage2b-linux.md).
Общая Studio-спека пока находится вне этой ветки:
`/Users/denyskolomiiets/masscan-studio/docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`.
Её перенос и согласование — задача 1.

**Статус:** план для утверждения. Пользователь разрешил составить план;
реализация замечаний, коммиты, push, merge и публикация этим запросом не разрешены.
Новые контракты ниже — предложения, а не ранее утверждённые требования.

## Проверенная база

- Локально `feat/rmasscan-stage2b-linux`, HEAD `403604b` на момент составления.
  Уже присутствуют merge main, исправление гонки overflow-теста, backoff EINTR
  и исправление проверки исходящих кадров. Не реализовывать их повторно.
- `rmasscan/scripts/wire_suite.py` имеет чужую незакоммиченную правку.
  Перед работой проверить diff и владельца изменения; не перезаписывать и не
  включать чужую правку в свой commit автоматически.
- Опубликованный PR #8 на `df53e6d` имеет зелёный CI трёх ОС. Это не CI локального
  `403604b` и не Windows/macOS raw I/O. Перепроверить HEAD при начале исполнения.
- Предыдущие локальные 298 PASS относятся к старой базе. Сохранённый Linux
  functional suite: 120 PASS; performance suite: 5 PASS/1 FAIL, 38/40 валидных
  захватов. Новый запуск нельзя объявлять успешным по этим старым результатам.
- План Windows от 2026-10-24 сохраняется. Его устаревшая задача 0 заменяется
  приоритетами этого документа после утверждения; Windows не начинать скрыто.

## Global Constraints

- IPv4/TCP; NIC=1, TX=1, RX=1; shard=1/1, retries=0, BlackRock rounds=14.
- Только `Sent` продвигает cursor. `Uncertain` → Failed, без повторной отправки
  и checkpoint. Принятые результаты доступны после ошибки.
- Один вызов адаптера ≤50 мс; Stop ≤1 с; Pause прекращает TX ≤1 с и сохраняет
  RX drain с `wait=3` для приёмки. Не включать drain в обещание остановки TX.
- Seed/index — u64 в Rust; UI получает decimal strings. Не менять wire bytes,
  cookie, shuffle, job identity или формат checkpoint без отдельного основания.
- Unsafe остаётся в net/FFI. Не добавлять C toolchain или новые зависимости.
- Живые прогоны — только существующий согласованный netns/veth-стенд без uplink.
  Не запускать сканирование домашней/рабочей сети и не менять firewall.
- Отдельно отмечать offline tests, CI build, lab wire, physical NIC и UI acceptance.
- Исходники Swift, личная история, установленное приложение и файлы других работ
  сохраняются. Нельзя коммитить весь dirty spikes-worktree одним добавлением каталога.

## Предлагаемые решения для утверждения

| Вопрос | Предложение |
| --- | --- |
| RX drops > 0 | `Failed(RxLoss { kernel_drops })`, без checkpoint; уже принятые результаты остаются |
| Нет достоверной RX-статистики | `Failed(RxStatsUnavailable)`; неизвестное не превращается в ноль |
| Ошибка запроса RX-статистики | `Failed(RxError(...))`; ранее сохранённый ноль не подменяет ошибку |
| Период проверки RX | Не реже раза в 250 мс по часам engine и обязательная финальная проверка |
| Бесконечный WouldBlockUnsent | `EngineOptions::tx_stall_timeout = 10 с` по умолчанию; нулевое значение запрещено |
| Граница TX stall | Время от первой попытки отправки кадра, вернувшей WouldBlockUnsent; сброс только после Sent; throttle-сон между кадрами не считается |
| Приоритет исхода | Существующее правило first failure сохраняется; обнаруженная потеря запрещает успешные Completed/Paused, в том числе при одновременном Stop |
| VLAN и дедуп | VLAN остаётся явно неподдержанным; bounded FIFO dedup остаётся в engine. Полную C-семантику дедупа в этом этапе не обещаем |

Строгая RX-политика консервативна: kernel drops могут включать посторонние кадры.
Это значит «полнота локального приёма не доказана», а не «точно потерян ответ нашей цели».
Ноль kernel drops также не доказывает отсутствие потерь в сети или на удалённом хосте.
Эти правила не заменяют отдельную проверку truncation, capture filters и supported link types.

## Review Focus

1. Потеря появляется только в финальном чтении счётчиков: нельзя успеть выдать
   Completed/CheckpointReady — задача 2.
2. Статистика недоступна или её чтение сбрасывает счётчик: нельзя получить ложный
   ноль, потерять накопленное значение или посчитать его дважды — задача 2.
3. Низкий rate законно задерживает TX; бесконечный backpressure незаконно держит
   один кадр: watchdog различает эти случаи, Stop/Pause остаются быстрыми — задача 3.
4. Cumulative drops/ошибка одновременно с Pause/Stop/ошибкой потребителя:
   единственный терминальный исход, сохранённые результаты, никакого checkpoint — задача 2.
5. Зелёные логи/ZIP относятся к старому или другому дереву: source hash, dirty diff,
   commit и сырые capture связаны однозначно — задачи 1, 4 и 5.

## Задача 1. Свести спецификации и перечень возможностей

**Files:** `docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`
(перенести выбранный файл из spikes-worktree), существующая
`docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`, `rmasscan/README.md`,
`rmasscan/crates/rmasscan-core/tests/selftest_parity.rs`.

**Interfaces:** одна согласованная таблица возможностей с колонками
`capability / слой / реализовано / проверка / ограничение / следующий этап`.
Она описывает продукт и библиотеки отдельно; не вводит фиктивный runtime API.

- [ ] Снять HEAD/status обоих деревьев и прочитать актуальные diff. Выбрать только
  документы этой задачи; подтвердить происхождение переносимой редакции.
- [ ] Внести встроенный rmasscan в решения общей спеки; заменить целевые требования
  argv/paused.conf/console-event на typed engine events. Старые требования оставить
  только в явно историческом описании Swift, без противоречивого нормативного текста.
- [ ] Зафиксировать предложенные выше RX/TX-контракты после утверждения плана.
  Указать: `Completed` означает завершение задания с доступной статистикой без
  наблюдавшихся kernel drops, а не обнаружение всех реально открытых портов сети.
- [ ] Разнести готовность: дедуп есть в engine; VLAN Unsupported; ARP codec есть,
  resolver ещё нет; paused.conf parser есть, пользовательский импорт ещё нет;
  --echo-all вызывается CLI и имеет описанное подмножество; raw I/O только Linux.
- [ ] Уточнить карту selftests: C dedup selftest не портирован буквально; новый
  engine FIFO имеет свои тесты. Не менять статус на «полный C-паритет» по одному
  существованию дедупликации и не перенести её второй раз в core.
- [ ] Проверить относительные ссылки и поиск устаревших утверждений «оба UI»,
  «Qt выбран», «Windows raw PASS», «CI NOT RUN». Исторические отчёты сохранять
  как исторические, текущий статус привязывать к commit/date.
- [ ] Отдельный docs commit после разрешения исполнения; без исходников UI и артефактов.

## Задача 2. Провести RX integrity через границу net → engine

**Files:** `rmasscan/crates/rmasscan-engine/src/{io,events,engine,fake,lib}.rs`,
`rmasscan/crates/rmasscan-net/src/linux/{mod,tests}.rs`,
`rmasscan/crates/rmasscan-net/examples/wire_scan.rs`;
создать `rmasscan/crates/rmasscan-engine/tests/rx_integrity.rs`.

**Interfaces:** добавить в engine `RxHealth { kernel_drops: Option<u64> }` и
обязательный `Rx::health(&mut self, timeout: Duration) -> Result<RxHealth, IoError>`.
Значение cumulative с начала этой попытки, не delta; Some(0) только при успешном
измерении. Добавить `FailReason::RxLoss { kernel_drops: u64 }`, `RxStatsUnavailable`.
`Outcome` дополняется `rx_health: RxHealth`; экспортировать тип из engine.
Существующие `recv`, `Tx`, `open_explicit` сохраняются.

- [ ] RED: fake health Some(0) → Completed; Some(1) → RxLoss; None →
  RxStatsUnavailable; ошибка → RxError. Ни один отказ не выдаёт CheckpointReady,
  `checkpoint()` возвращает None, принятые ранее результаты выдаются перед Finished.
- [ ] RED: drops только при последнем health после RX drain → Failed; те же
  проверки для Pause/Stop. Ошибка ConsumerTooSlow, возникшая раньше, не заменяется
  поздней RxLoss, но доступная последняя статистика сохраняется в Outcome.
- [ ] RED net seam: последовательные delta 2/0/3 дают cumulative 2/2/5;
  ошибка последнего packet_stats не возвращает cached Some(0); Drop не удваивает
  счётчик. Проверить ограничение 50 мс для реализации health.
- [ ] Добавить управляемый health-сценарий в fake adapter. Все реализации Rx
  обновить явно; не вводить default health=Some(0), скрывающий неподдержанный адаптер.
- [ ] Engine проверяет health каждые 250 мс без привязки к числу входящих кадров
  и после выхода из RX-loop, до публикации rx_end/терминального результата.
  Финальный snapshot определяет конец окна наблюдения; затем handle закрывается
  до Finished. На panic сохраняется WorkerPanicked, без попытки обещать полноту.
- [ ] Net читает PACKET_STATISTICS, накапливает сбрасываемые значения и сообщает
  ошибку чтения вызывающему. Согласовать существующие периодические flush/Drop
  с новым методом: один владелец счётчика, без потерянных ошибок и двойного сложения.
- [ ] Обновить сериализацию harness: точная причина ошибки, последнее health,
  ненулевой exit code для отказов. Статистику неизвестного качества писать null.
- [ ] GREEN: `cargo test --locked -p rmasscan-engine --test rx_integrity`;
  на Linux `cargo test --locked -p rmasscan-net --lib`. При ожидаемом отсутствии
  Linux cfg на Mac этот прогон не отмечать как проверку AF_PACKET.
- [ ] Отдельный commit `fix(engine): reject unverified receive completion`.

## Задача 3. Ограничить время отсутствия TX-прогресса

**Files:** `rmasscan/crates/rmasscan-engine/src/{engine,events,fake}.rs`,
создать `rmasscan/crates/rmasscan-engine/tests/tx_stall.rs`.

**Interfaces:** `EngineOptions::tx_stall_timeout: Duration`, default 10 с;
`FailReason::TxStalled { idle_millis: u64 }`. Параметр — runtime policy,
не часть порядка probe и не новое поле checkpoint/job digest.

- [ ] RED: постоянный WouldBlockUnsent → TxStalled после 10 с по ManualClock;
  cursor не продвинут, нет checkpoint, принятые RX-результаты доступны.
- [ ] RED: временный WouldBlockUnsent короче лимита и затем Sent → продолжение;
  следующий кадр получает новое окно. Sent не повторяется и не увеличивает cursor дважды.
- [ ] RED: throttle при rate=1 и более медленном допустимом core rate не включает
  watchdog до попытки отправки. Нулевой tx_stall_timeout отвергается до запуска потоков.
- [ ] RED: Stop/Pause внутри длительного WouldBlock прекращают TX ≤1 с;
  естественный конец, Uncertain и TxError сохраняют существующие приоритеты.
  На границе deadline новый send не начинается; Sent из уже начатого вызова
  учитывается как отправленный, даже если вызов вернулся после границы watchdog.
- [ ] Реализовать elapsed time по тем же монотонным Clock, что и throttle.
  Начало окна — начало первой неудачной попытки кадра; между попытками остаётся
  backoff 1 мс. Проверять watchdog перед очередной попыткой и после WouldBlock.
  Допуск обнаружения — один ограниченный I/O-вызов + backoff + scheduler, не новый
  таймаут на каждый retry. Не использовать число повторов как замену времени.
- [ ] GREEN: `cargo test --locked -p rmasscan-engine --test tx_stall` и
  `cargo test --locked -p rmasscan-engine --test pause_resume`.
- [ ] Отдельный commit `fix(engine): bound persistent transmit backpressure`.

## Задача 4. Проверить границы контракта и повторить Linux-приёмку

**Files:** `rmasscan/crates/rmasscan-engine/tests/lifecycle.rs`,
`rmasscan/crates/rmasscan-net/tests/{linux_io,linux_wire}.rs`,
`rmasscan/scripts/{wire_suite.py,verify-wire.py,wire-lab.sh}`,
`docs/experiments/2026-10-23-rmasscan-stage2b-linux.md` и новый каталог raw evidence.

**Interfaces:** существующие suite rust/perf и JSON verdict; добавить rx_health
в проверки результатов из задачи 2. Не менять INVALID на PASS.

- [ ] Закрепить текущую VLAN-политику тестом через engine и bounded FIFO-повтор
  после eviction. Неподдержанная tagged VLAN не считается реализованной функцией;
  это не повод добавлять второй dedup в core.
- [ ] Сначала согласовать имеющийся dirty diff wire_suite.py, затем проверить
  readiness/drain tcpdump и причину двух неполных capture. Добавить regression
  на потерянный хвост capture; сохранить предыдущие неудачные данные.
- [ ] Проверить независимость C-эталона: manifest/hash/pinned revision, negative
  comparator cases, отсутствие нормализации различающихся SYN. Проверить
  фильтрацию, source tuple, counts и критерии RX completeness обоих сравнителей.
- [ ] На согласованном Linux-стенде заново запустить functional suite и полную
  матрицу 4 rates × 5 repeats × C/Rust. Все 40 capture валидны, полные ожидаемые
  ответы, kernel drops=0, медианы в согласованном ±20%; иначе gate остаётся открытым.
- [ ] В этом же стенде целенаправленно создать RX overflow с маленьким буфером
  и контролируемой нагрузкой. Приёмка: измерено drops>0, итог Failed, checkpoint
  отсутствует. Если overflow не воспроизведён, отметить NOT RUN, не выдавать PASS.
- [ ] Сохранить commit, dirty diff (ожидается пустой для финального прогона),
  хэши бинарников и pcap, версии ОС/ядра/oracle, команды и все итоги.
  fake backpressure/panic tests не называть проверками физического NIC.
- [ ] Полный `cargo test --locked --workspace`, fmt, Clippy с `-D warnings`,
  `cargo deny check bans licenses sources`, Python comparator self-test.
  CI macOS/Ubuntu/Windows относится к exact published HEAD; получить review diff
  engine/net/harness. Не заменять новый CI зелёным run старого commit.
- [ ] Отдельный evidence commit; слияние PR — только отдельное разрешённое действие.

## Задача 5. Зафиксировать интеграционный и дистрибуционный долг

**Files:** создать `docs/experiments/2026-10-24-rmasscan-readiness.md`;
обновить `docs/superpowers/plans/2026-10-24-rmasscan-stage2b-windows.md` после утверждения.
Источники: pinned Studio snapshot, локальный `SNAPSHOT.json`, опубликованные
source/binary ZIP и их manifest; публикацию и UI-исходники эта задача не меняет.

**Interfaces:** readiness table с отдельными итогами `Linux merge readiness`,
`Windows correctness`, `macOS correctness`, `Studio integration`, `distribution`.

- [ ] Проверить vendor hash против закреплённых git objects, а не только самого
  manifest. Указать старую revision и отсутствие актуального engine/net в Studio.
  Обновление vendor и сборку нового preview оставить отдельному интеграционному этапу.
- [ ] Разделить ARP codec/ARP resolver, paused.conf library/import UI,
  offline preview/raw Scan. Qt не нужен: выбран только Slint. Зафиксировать
  незакрытые per-cell interactions, native menu, keyboard/IME и frame timing.
- [ ] Проверить точный source ZIP для уже выданного бинарника: Cargo.lock,
  build scripts, manifests, собственный код, vendor LICENSE/NOTICE и инструкция
  восстановления. Наличие source ZIP не объявлять автоматическим доказательством
  полной лицензионной готовности; его отсутствие также не утверждать без проверки.
- [ ] Записать требуемое решение до следующей поставки: условия для объединённого
  Studio+AGPL engine, вариант лицензирования Slint конкретной версии, notices
  зависимостей. Публичный выпуск не разрешать одним изменением Cargo license.
- [ ] Описать отдельный будущий gate runner: raw socket ownership, объём кода под
  повышенными правами, feasibility privilege-drop на каждой ОС, authenticated IPC,
  lifetime и durable checkpoint ACK. Не считать смерть scanner решённой до
  проверки всей схемы, включая Windows-драйвер и возможные дочерние процессы.
- [ ] В Windows-плане заменить устаревшую задачу 0 ссылкой на закрытые задачи
  этого плана и включить новый Rx::health/TX-stall контракт. Предыдущие команды
  и цифры не выдавать за свежий прогон.
- [ ] Отдельный docs commit. Эта задача создаёт проверяемый перечень долгов,
  но не закрывает Windows/macOS/UI/licensing gates сама по себе.

## Приёмка и дальнейшая очередь

**Готово к отдельному решению о merge Linux-этапа:** утверждены и реализованы
RX/TX-контракты, тесты и новые Linux-прогоны прошли, полная capture matrix валидна,
CI exact HEAD зелёный, замечания независимого review закрыты, статус ограничений
опубликован в документации ветки. Ни один пункт не означает готовность продукта к релизу.

Затем отдельными этапами:

1. **Windows/Npcap:** существующий [план Windows](2026-10-24-rmasscan-stage2b-windows.md),
   реальная Windows 11, TX/RX/health/Stop/pause-resume; Server 2022 — только CI.
2. **macOS BPF:** отдельный план, аппаратная проверка, те же контракты потерь/остановки.
3. **Сетевая интеграция:** discovery/ARP, network identity, sleep/VPN и throughput.
4. **Runner/Studio:** права и IPC, durable checkpoint, хранилище, обновление pinned
   engine, настоящий Scan в Slint, функциональный и UI-паритет.
5. **Поставка:** лицензии, воспроизводимый source/binary bundle, повторная проверка
   ad-hoc подписи Mac. Публичные установщики/подпись — отдельное решение.

Самопроверка плана: задачи 2/3 закрывают подтверждённые дефекты; задача 1 устраняет
расхождения требований; задача 4 проверяет результат на проводе; задача 5 отделяет
незавершённый продукт от Linux-базы. Review Focus 1/2/4 → задача 2, 3 → задача 3,
5 → задачи 1/4/5. Новые параметры явно предложены, исходники при составлении не менялись.
