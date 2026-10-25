# Rust masscan: 2B-Windows / Npcap — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** получить Windows 11 x64 harness с настоящим SYN TX/RX через Npcap,
доказанными Stop и pause/resume; сначала закрыть оставшиеся пункты Linux-приёмки.

**Architecture:** сохранить net → engine → core и публичный
`open_explicit(&AdapterBinding) -> Result<OpenedAdapter, NetError>`.
Новый `net::windows` динамически загружает Npcap и выдаёт отдельные TX/RX handles.
Engine, cookie, порядок probe и checkpoint остаются общими; GUI и elevated runner
не входят в этот этап.

**Tech Stack:** Rust 1.99.1, существующий workspace, Windows API через
`windows-sys = "=0.61.2"` с нужными features, ручные Rust ABI declarations Npcap,
PowerShell для лабораторного запуска; драйвер и DLL Npcap установлены пользователем.

**Spec:** [Rust-порт](../specs/2026-10-23-masscan-rust-port-design.md),
[контракты 2A](2026-10-23-rmasscan-stage2a-engine.md),
[план Linux](2026-10-23-rmasscan-stage2b-linux.md),
[ревью 2B (устарело: дерево `365eb18`)](../../experiments/2026-10-24-rmasscan-stage2b-review.md).
Старые заголовки «реализацию не начинать» в ранних спеках заменены последующими
поручениями пользователя. Этот документ подготовлен по запросу на проверку и план;
в момент написания реализация Windows не начиналась.

## Исходное состояние и порядок

Состояние Linux-базы и её статусы приведены в Задаче 0 и в
[перечне готовности](../../experiments/2026-10-24-rmasscan-readiness.md). Прежние сведения
о `365eb18`, PR #8 и `df53e6d` относились к ревью 2B и устарели; свежим прогоном они не являются.

Порядок: **0 — Linux-база и контракты → 1 — Windows ABI/loader → 2 — TX/RX feasibility
gate → 3 — адаптер → 4 — переносимый harness → 5 — реальный Windows lab**.
Пока нет Windows-машины/драйвера/замкнутого стенда, можно завершать offline-часть,
но приёмка raw I/O остаётся NOT RUN. Это не причина подменять её CI-сборкой.

## Global Constraints

- Windows 11 x86_64 — целевая ОС этого подэтапа. GitHub `windows-2022` — среда
  сборки и offline-тестов; Windows ARM64, x86 и Wi-Fi monitor mode не принимаются
  по результатам x64 Ethernet-теста.
- Runtime остаётся: IPv4/TCP, NIC=1, TX=1, RX=1, shard=1/1, retries=0,
  BlackRock rounds=14; seed ненулевой, u64 в Rust. Source-port single/range сохраняются.
- Source IP/MAC явные. Не вводить проверку обязательного владения source IP
  интерфейсом ОС: это противоречит принятому Linux/C-oracle binding.
- I/O deadline ≤50 мс; Stop ≤1 с; Pause прекращает TX ≤1 с и ждёт RX drain
  `wait` (приёмка с wait=3). Новая попытка resume имеет новый attempt_id.
- Только Sent двигает cursor. Неопределённый результат отправки → Uncertain,
  Failed без checkpoint и без повторной отправки. Нет silent drops в очереди.
- Core/engine/CLI остаются без unsafe; Windows FFI только в private net-модулях
  с SAFETY-комментариями и `deny(unsafe_op_in_unsafe_fn)`.
- Нет статической линковки wpcap.lib/Packet.lib, C/C++, bindgen или Npcap SDK
  в сборке продукта. SDK-заголовки допустимы как источник ABI для ревью.
- Сохраняются AGPL/NOTICE и no-C guard. Nmap внешний, Slint выбран, тема системная.
- Npcap не скачивается и не устанавливается нашим приложением/скриптом.
  Отсутствие DLL не ломает offline/core/--echo. Нет автоматического сканирования.
- Только явно выбранный замкнутый стенд. Без изменений firewall, включения ICS,
  bridge, NAT или перенастройки основной сети пользователя. План не разрешает
  запуск по произвольной домашней/рабочей подсети.

## Review Focus

1. Подложная DLL в cwd/PATH или незагруженная Packet.dll: trusted load должен
   завершиться безопасной диагностикой — задача 1.
2. Указатель pcap недействителен после следующего чтения/закрытия: кадр копируется
   до выхода из FFI, handles не делятся конкурентно — задачи 1/3.
3. Пустой capture, бесконечный поток мусора и потеря адаптера: deadline не
   продлевается, потоки не зависают — задачи 2/3/5.
4. Send зависает или его исход неизвестен: нельзя выдать Sent, checkpoint
   либо оставить отправляющий worker после Stop — задачи 2/3/5.
5. EXE запустился, но драйвер/права/ответы отсутствуют: отчёт разделяет
   build, offline tests, TX, RX и полноту независимого capture — задачи 4/5.

## Карта файлов

- Изменить `rmasscan/crates/rmasscan-net/src/lib.rs`: platform dispatch,
  переносимые ошибки; существующие OpenedAdapter/NetStatsHandle сохраняются.
- Создать `src/windows/{mod,ffi,loader,adapter,tests}.rs` внутри net:
  ABI и DLL ownership; разрешение символов; TX/RX и fake-function-table tests.
- Создать `rmasscan/crates/rmasscan-net/tests/windows_io.rs` и
  `tests/windows_wire.rs`: offline/opt-in live и чтение артефактов.
- Изменить `rmasscan/crates/rmasscan-net/examples/wire_scan.rs`;
  создать `examples/support/{mod,metrics}.rs`: отделить Linux /proc-метрики.
- Создать `rmasscan/scripts/windows-wire-lab.ps1`,
  `rmasscan/scripts/package-windows-wire.ps1` и `rmasscan/docs/windows-wire-lab.md`.
- Изменить workspace/net Cargo manifests, lockfile, deny/no-C guards при
  появлении target-зависимостей; `.github/workflows/rmasscan.yml` для артефакта.

## Задача 0. Linux-база и контракты (перенесена в план ремедиации)

Прежняя Задача 0 (EINTR, outgoing-test, capture, merge main, performance matrix)
заменена. Linux-работа ведётся по
[плану ремедиации](2026-10-24-rmasscan-review-remediation.md), а не здесь.
Команды и цифры из прежней версии этой задачи и из
[ревью 2B](../../experiments/2026-10-24-rmasscan-stage2b-review.md) (дерево `365eb18`)
не являются свежим прогоном и не переносятся на Windows.

Состояние задач плана ремедиации (закрыты задачи 1-5; Linux-код принят на `27e3042`, evidence `8479ff2`):

- Задача 1 (спецификации и перечень возможностей): `66902da`, `cc9df28`, `e5d6326`.
- Задача 2 (RX integrity): `364ee49`.
- Задача 3 (TX stall): `c31ae16`; задачи 2 и 3 прошли review.
- Задача 4 (Linux-приёмка): закрыта, review пройдено после fix round. Код измерен на `27e3042`, evidence `8479ff2`
  (functional 141/0/0, perf 40/40 VALID, переполнение RX даёт `Failed(RxLoss)`); прогон `ee51a19`/`eb8812a`
  заменён. Результаты в [отчёте Linux](../../experiments/2026-10-23-rmasscan-stage2b-linux.md).
  **CI на точном HEAD: NOT RUN** (push не разрешён).
- Задача 5 (долг интеграции и поставки): закрыта, review пройдено после fix round: [перечень готовности](../../experiments/2026-10-24-rmasscan-readiness.md).
- Итоговое review ветки: «с исправлениями»; исправления внесены.

Перед стартом кода Windows: Linux-ветка принята review и имеет зелёный CI на закреплённом
HEAD; этот commit становится базой Windows. Слияние PR остаётся отдельным решением пользователя.

**Контракты, которым обязан удовлетворять Windows-адаптер** (источник:
[спецификация, §0.1](../specs/2026-10-23-cross-platform-qt-rust-design.md)):

- `Rx::health(timeout) -> Result<RxHealth, IoError>` реализован обязательно. `RxHealth.kernel_drops:
  Option<u64>` кумулятивно с начала попытки; `None` значит «измерить нельзя» и не превращается в 0.
  Если Npcap/драйвер не даёт честного счётчика потерь, адаптер обязан вернуть `None`, а не 0.
  **Следствие (спецификация §0.1, «Приоритет»):** `Completed`, `Stopped` и `Paused` возможны
  только при подтверждённом `Some(0)`. С `None` каждый запуск на Windows завершается
  `Failed(RxStatsUnavailable)`, pause/resume пройти не может и GO Windows недостижим. Поэтому
  наличие честного счётчика `Some(n)` проверяется в Задаче 2 как STOP/GO, а не только реализуется в Задаче 3.
- Потеря RX даёт `FailReason::RxLoss { kernel_drops }`, `None` даёт `FailReason::RxStatsUnavailable`,
  ошибка запроса статистики даёт `FailReason::RxError(String)`; все без checkpoint. После неудачного
  запроса `Outcome.rx_health` сбрасывается в `RxHealth { kernel_drops: None }`, прежний `Some(0)` не
  сохраняется. Проверка выполняется по часам engine примерно каждые 250 мс (интервал проверяется после очередного вызова `recv` ≤50 мс
  и самой проверки ≤50 мс, поэтому фактический зазор до ~350 мс) и обязательно в конце, перед исходом.
- TX stall: `EngineOptions::tx_stall_timeout` по умолчанию 10 с, ноль отвергается;
  `WouldBlockUnsent` не продвигает курсор; итог `FailReason::TxStalled { idle_millis }` без checkpoint.
  Адаптер обязан возвращать `WouldBlockUnsent` только когда кадр точно не отправлен.
- Прежние контракты сохраняются: только `Sent` двигает cursor, неопределённый результат даёт
  Uncertain/Failed без повторной отправки, вызов ≤50 мс, Stop ≤1 с.

Для Windows это новые обязательные проверки в задачах 2-5: fake-function-table тесты на `None`
health и на бесконечный `WouldBlockUnsent`; живая проверка потерь на независимом capture.

## Задача 1. Безопасная загрузка Npcap и ABI

**Interfaces:** private `NpcapApi::load() -> Result<Arc<NpcapApi>, NetError>`;
owned `PcapHandle` держит Arc библиотеки до `pcap_close`. Никаких raw handles
или function pointers вне Windows net-модуля. Public `NetError` дополнить
`DriverUnavailable(String)`, `MissingCapability(String)` и `AbiMismatch(String)`;
текст PermissionDenied сделать платформенно нейтральным.

- [ ] Создать red tests: DLL отсутствует, отсутствует обязательный символ,
  неправильная архитектура, API init failure, закрытие после частичного open.
  Fake-loader фиксирует порядок close/unload и не требует Npcap.
- [ ] Получать системный каталог через WinAPI, не доверять переменной окружения.
  Грузить полный путь `System32\Npcap\wpcap.dll` с ограниченным поиском зависимостей:
  `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`.
  Точечное использование LoadLibraryExW/GetProcAddress вместо новой libloading
  зависимости — решение этого плана; требование динамической загрузки сохраняется.
- [ ] Не искать DLL в cwd/PATH/рядом с EXE. Сохранить фактические пути, версии
  и hashes загруженных wpcap/Packet DLL в диагностике; ошибки не запускают installer.
- [ ] Объявить только используемые ABI: pcap open/create/activate/settings,
  findalldevs/freealldevs, next_ex, sendpacket, datalink, geterr, stats,
  lib_version и close. Windows `timeval`/pcap headers проверить по выбранным
  Npcap headers, с size/align/offset assertions; не переносить Unix long вслепую.
- [ ] Обосновать Send/Sync отдельно для immutable function table и owned handle.
  Каждый pcap handle принадлежит одному worker; не добавлять blanket unsafe
  impl Sync ради передачи между потоками. DLL живёт до закрытия обоих handles.
- [ ] Перечень `\Device\NPF_{GUID}` брать из API; поддержать длины и backslash,
  отклонять interior NUL/несуществующий endpoint. Loopback NULL и monitor DLT
  пока дают явный UnsupportedLink, а не интерпретируются как Ethernet.
- [ ] `cargo test --locked -p rmasscan-net` на Windows без установленного Npcap:
  fake tests PASS, отсутствие драйвера — ожидаемая ошибка, offline работает.
  Commit: `feat(net): add owned Npcap loader and Windows ABI boundary`.

## Задача 2. Ранний эксперимент TX/RX и дедлайнов — до полного адаптера

**Files:** `src/windows/ffi.rs`, `tests/windows_io.rs`,
`docs/experiments/2026-10-24-rmasscan-stage2b-windows-spike.md`.

**Interfaces:** испытание вызывает два отдельных owned pcap handles;
пишет длительности каждого open/send/read/close и raw return codes. Передача
одного кадра — синхронная, без sendqueue и без detached timeout thread.

- [ ] Зафиксировать реальную Windows 11 x64, Npcap/driver versions и режим
  Admin-only. Сначала inventory без пакетов; затем утверждённый замкнутый стенд.
- [ ] Проверить nonblocking RX с собственным абсолютным deadline ≤50 мс:
  пустой канал, мусор, unplug, sleep/wake; ошибки открытия и завершение.
- [ ] Отдельно измерить sendpacket в норме, при нагрузке, unplug и отмене.
  `pcap_setnonblock` документирует чтение; он НЕ доказывает bounded TX.
  Успешный open также не доказывает возможность injection.
- [ ] **RX health STOP/GO.** Проверить, даёт ли `pcap_stats` (`ps_drop`, `ps_ifdrop`) на этом
  драйвере честный, кумулятивный с начала попытки, per-handle счётчик потерь, пригодный как
  `Some(n)`. Измерить: значение 0 на чистом прогоне; рост при искусственном переполнении RX (медленный
  читатель, нагрузка) и значение не меньше потерь, измеренных независимым capture; поведение после unplug и при ошибке
  запроса; длительность вызова ≤50 мс. Адаптер вправе сам накапливать сырой счётчик, который не кумулятивен или
  сбрасывается при чтении (так делает Linux: дельты 2/0/3 дают 2/2/5). STOP только если честное кумулятивное
  значение на попытку построить нельзя: сброс вне контроля адаптера, необнаружимое переполнение, счётчик общий для
  нескольких handle или занижение потерь, потому что тогда адаптер вернёт `None`, каждый запуск закончится `RxStatsUnavailable` и
  Windows GO недостижим. Выход: отдельное решение (другой источник счётчика или пересмотр контракта),
  не подмена `None` нулём.
- [ ] Записать p50/p95/max длительности и задержку Stop, а не только факт запуска.
  Если TX способен остаться заблокированным за пределами контракта, STOP для
  интеграции: отдельное решение о cancellable механизме, не ослабление лимита.
  Нельзя обойти проблему оставленным worker, который продолжит отправку позже.
- [ ] GO spike: реальные отправка и приём на Ethernet, отсутствие зависших
  handles, замеры укладываются в контракт на заявленном сочетании драйвер/ОС.
  Это эмпирическая проверка, не универсальная гарантия всех версий Npcap.

## Задача 3. Реализовать Windows AdapterPair

**Interfaces:** `windows::open(&AdapterBinding) -> Result<OpenedAdapter, NetError>`;
существующие `Tx::send`, `Rx::recv` и общий Engine не менять. Windows-модуль
подключается через cfg; macOS продолжает возвращать UnsupportedPlatform.

- [ ] Red fake-API tests: next_ex=0, error, malformed caplen/len/null pointers,
  мусор до deadline, oversized frame, send failure, DLL lifetime и Drop всех
  handles после второго open failure.
- [ ] RX: явно nonblocking, немедленно копировать данные pcap в caller buffer,
  проверять длины до slice/copy; `caplen != len` считать truncation.
  При отсутствии пакета ожидать до 1 мс/остатка deadline; мусор не продлевает вызов.
  Сохранять checksum Verify: нельзя глобально довериться offload ради зелёного теста.
- [ ] TX: sendpacket==0 → Sent; ошибка после вызова с неопределённым исходом
  → Uncertain, без retry. Не выводить WouldBlockUnsent из текста pcap_geterr.
  Предотправочные ошибки валидации → IoError. Проверить ровно один cursor advance.
- [ ] Отсеивать свои TX до дорогого разбора, по возможности в capture filter;
  seam и live-test подтверждают, что валидные SYN-ACK/RST не отфильтрованы.
  Настройки не меняют firewall и не включают promiscuous mode без необходимости.
- [ ] Счётчики NetStats работают на Windows; недоступные показатели — None,
  а не выдуманный ноль. Проверить семантику pcap_stats/reset/wrap для выбранной
  версии, сохранять итог после закрытия handle; Linux counters не регрессируют.
- [ ] Проверить Stop/Pause, Uncertain и panic через общий runtime. No-C guard,
  fmt, Clippy, cargo deny, workspace tests на трёх ОС.
  Commit: `feat(net): implement bounded Windows Npcap adapters`.

## Задача 4. EXE и воспроизводимый пакет для пользователя

**Interfaces:** расширить лабораторный `wire_scan` режимами
`--inventory` (без TX) и `--write-reference-pcap FILE` (без открытия адаптера).
Существующие scan/pause/stop/resume flags сохранить. Метрики ОС возвращают
`Option`, отсутствие /proc на Windows сериализуется как null, не как 0.

- [ ] Red tests: inventory не вызывает send; offline reference не грузит DLL;
  неверный checkpoint отвергается до adapter open; default запуск без явно
  заданных параметров не начинает скан.
- [ ] Выделить /proc-измерения из `wire_scan.rs`; на Windows добавить supported
  handle/process metrics, фиксировать identity commit/hash/OS/driver/ABI/binding.
- [ ] PowerShell wrapper принимает явные параметры лаборатории, запускает EXE
  через массив аргументов, без Invoke-Expression. При нехватке прав выдаёт
  инструкцию, а не меняет UAC/драйвер/службу автоматически.
- [ ] CI собирает release x64 EXE и ZIP: EXE, PowerShell, краткий README,
  SHA256SUMS, LICENSE/NOTICE и source commit. Npcap DLL/installer в ZIP не входят.
  Артефакт — конкретный commit, не плавающее имя latest.
- [ ] Пользователь получает готовый пакет и два этапа: inventory, затем
  явно настроенный wire-run. Результат — архив JSON/pcap/logs с PASS/FAIL/NOT RUN.
  Отправка письма не является автоматическим побочным эффектом сборки.
  Commit: `test(net): package Windows wire harness with diagnostics`.

## Задача 5. Приёмка Windows на проводе

> **Статус 2026-10-25 (этап VM):** выполнено на виртуальном стенде n2, не на физическом NIC. Отчёт:
> [Windows VM acceptance](../../experiments/2026-10-24-rmasscan-windows-vm-acceptance.md); сырые данные
> `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/` (evidence `dd78c4b`, `d2726df`, `c5ee494`, перепроверка `bfe069f`; код `9ecbe32` для A и B, `847e218` для C, `931f69f` для перепроверки).
> Физический NIC: **NOT RUN**. **Каждый отмеченный ниже пункт Задачи 5 выполнен только на VM**; пункты, чья цель - физический NIC, не отмечены. Чекбоксы Задач 1-4 в этом файле не перепроверялись и не менялись.

**Files:** `tests/windows_wire.rs`, `scripts/windows-wire-lab.ps1`,
`docs/experiments/2026-10-24-rmasscan-stage2b-windows.md` и каталог сырых данных.

- [ ] До первого кадра записать топологию: Windows NIC ↔ выделенный Linux peer
  через отдельный кабель/изолированный switch, без uplink/NAT/bridge; либо
  согласованный изолированный virtual switch. Физический NIC обязателен для
  заявления физического паритета. Нет такого стенда — wire NOT RUN.
  *Выполнено на VM (чекбокс не отмечен: цель пункта - физический NIC). Согласованный virtual switch (мост wvb-n2, netns wvp-n2, без uplink/IP/NAT); отчёт, раздел 4. Физического стенда нет: **физический wire NOT RUN**, пункт для физического NIC остаётся открытым.*
- [x] Выбрать явный binding, проверяемый на этом NIC. C-oracle фикстуры для
  такого же binding снять в уже разрешённом Linux namespace-стенде; нельзя
  сравнить разные MAC/IP и скрыть разницу нормализацией SYN-байтов.
  *Эталоны pinned masscan `8e6b3b0` сняты раньше (историческая часть A, `functional/fixtures`) и переиспользованы в `9ecbe32`; binding без нормализации (`functional/fixtures`, отчёт, разделы 3-4).*
- [x] Capture на независимом Linux peer с readiness ACK и строгой completeness;
  результаты сканера отдельно сверять с ожидаемыми Open/Closed и исключениями.
  Подготовка стенда/ARP здесь явная, не новая функция discovery в продукте.
  *capture_schema 3, readiness marker, строгая полнота: 64 сырых прогона, отчёт, раздел 7.*
- [x] Те же 6 классов кейсов Linux, source-port single/range; два повтора.
  Пауза N=0/1/8/15 для 16 probe: pause+resume == continuous == C; scan_id
  постоянный, attempt_id новый. Завершённое задание не возобновляется.
  *`functional-r2`, `9ecbe32`: 29 PASS (evidence `dd78c4b`).*
- [x] Stop при rate=1, тишине, нагрузке, drain и полной очереди; unplug;
  mismatch/corrupt checkpoint; разрешения Admin-only. После terminal outcome
  нет дальнейших SYN, живых workers или leaked handles; ошибки не дают checkpoint.
  *`failure-r1`, `9ecbe32`: 19 PASS; unplug = QMP set_link (TxUncertain); перепроверка исправлений ревью (I1, I2) на `931f69f`: `perm_restricted_scan` exit 5 PASS, флаг 0x800 на EXE из пакета, подложенный файл-не-DLL рядом с EXE не ломает запуск (раздел 11 отчёта; сырого вывода у этой проверки нет).*
- [ ] На целевом NIC снять baseline 100/1k/10k/100k pps, 5 повторов, capture
  drops/полноту ответов/CPU/RSS и задержки. Недостигнутые ±20% записать как
  открытый performance gate 2B-sendqueue; не скрывать их успешным low-rate scan.
  *VM-часть выполнена (чекбокс не отмечен: целевой физический NIC не снят). `perf-r1`, `847e218`: 21 PASS на VM, не на целевом физическом NIC. ±20% gate MET на 100 и 1k, **OPEN** на 10k и 100k (потолок VM около 6.4 kpps) до 2B-sendqueue; снятие на физическом NIC остаётся открытым.*
- [x] Offline verifier читает артефакты на Mac/Linux/Windows без Npcap.
  Не хватает pcap, manifest или валидного capture — FAIL/NOT RUN, никогда PASS.
  *`rmasscan-lab windows-verify`, без Npcap; отсутствие -> NOT RUN, неполный захват -> INVALID (отчёт, раздел 7). Для `.pcap.gz` нужен `gunzip -k`.*
- [ ] Независимое ревью Windows unsafe/lifetimes/timeout и отчёт с точным commit.
  *Отчёт написан (коммиты в разделе 2 отчёта). Итоговое ревью продукта: WITH FIXES (I1 → `7247688`, I2 → `68134b0`); перепроверка CHANGES REQUIRED (R1) → исправлено `3d28ae3`, `931f69f`; проверка закрытия APPROVED; живая перепроверка на `931f69f` PASS (раздел 11 отчёта). CI на точном HEAD **NOT RUN** - пункт остаётся открытым.*
  Commit: `test(net): record Windows wire and resume acceptance`.

## GO и дальнейшая очередь

> Статус 2026-10-25: критерий GO ниже **ещё не выполнен**: Windows VM correctness - **OPEN**; VM-приёмка PASS (части A, B, C и перепроверка на `931f69f`), но «CI зелёный» не выполнено: CI этого HEAD и CI Linux-базы Задачи 0 на её закреплённом HEAD, оба **NOT RUN** (push не разрешён). Физический NIC - отдельный пункт **NOT RUN**, в это GO не входит. Единый список условий: [отчёт](../../experiments/2026-10-24-rmasscan-windows-vm-acceptance.md), разделы 1 и 13.

**GO Windows correctness:** Linux-база Задачи 0 принята (review + CI exact HEAD); CI зелёный; Windows 11 реально
передаёт/принимает; byte parity и pause/resume проходят; Stop ≤1 с; нет ложного
checkpoint/скрытых потерь/утечек. Зафиксированы версии DLL/драйвера и ограничения.
**GO всего 2B** требует также macOS BPF, discovery/ARP, решения source range,
sendqueue/performance и целевой матрицы платформ. Windows correctness не заменяет это.

Далее: **macOS BPF → discovery/ARP и сеть/VPN/sleep → sendqueue/скорость →
сессионный runner + IPC + durable checkpoint ACK → настоящий Scan из Slint**.
Вопрос хранения без C остаётся отдельным решением до этапа 3. Исправление
ad-hoc подписи macOS app проверяется перед GUI-поставкой. Swift пока сохраняется.

## Источники и самопроверка

- [Npcap nonblocking](https://npcap.com/guide/wpcap/pcap_setnonblock.html):
  next_ex/dispatch в nonblocking не ждут пакет; loop может крутиться.
- [Npcap next_ex](https://npcap.com/guide/wpcap/pcap_next_ex.html): pointer
  lifetime и return codes; DLT нельзя предполагать по названию адаптера.
- [Npcap injection](https://npcap.com/guide/wpcap/pcap_inject.html):
  sendpacket возвращает 0 при успехе; open не гарантирует injection и некоторые
  драйверы способны менять link header. Поэтому нужен независимый capture.
- [Npcap developer guide](https://npcap.com/guide/npcap-devguide.html):
  пути DLL, версия, AdminOnly и endpoint names.
- [Microsoft LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw):
  full path и ограничение поиска зависимостей через флаги загрузки.
- Review Focus 1→1; 2→1/3; 3→2/3/5; 4→2/3/5; 5→4/5.
  Публичный API сохранён; новые ошибки/modes определены в соответствующих задачах.
  Linux known gaps вынесены до Windows, а реальные испытания отделены от CI.
