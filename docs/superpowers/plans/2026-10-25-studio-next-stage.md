# Masscan Studio: от принятого движка к настоящему скану из приложения — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** закрыть три замечания независимой приёмки и получить инженерную сборку Slint, которая через отдельный Rust runner выполняет настоящий скан на изолированном стенде, сохраняет результаты, делает Pause/Resume и корректно переживает ошибки.

**Architecture:** непривилегированный Slint UI → Rust application controller + SQLite → аутентифицированный локальный IPC → отдельный Rust runner → существующие `rmasscan-core/engine/net`. Алгоритмы сканера не переписываются. macOS BPF и автоматический выбор сетевого маршрута — отдельное направление, параллельное интеграции UI.

**Tech Stack:** Rust 1.99.1, выбранный Slint 1.18.1, SQLite, Unix domain socket / Windows named pipe, существующие Linux AF_PACKET и Windows Npcap. Исходники приложения и тесты — Rust; shell/PowerShell только для системной интеграции.

**Spec:** [перенос Studio, редакция 8](../specs/2026-10-23-cross-platform-qt-rust-design.md), [Rust-порт](../specs/2026-10-23-masscan-rust-port-design.md), [готовность](../../experiments/2026-10-24-rmasscan-readiness.md).

**Основание ревью:** `/Users/denyskolomiiets/masscan-studio-reviews/2026-10-25-7ffa155/REVIEW.md`; там сохранены Rust-патч воспроизведений, мутации и логи. Ниже все три находки изложены самостоятельно.

**Статус:** план, не отчёт о выполнении. Этим поручением создаётся только документ. Реализация, установка runner и новые сетевые прогоны сейчас не выполняются. Merge/push/публикация не являются автоматическими шагами плана.

## Проверенная база

- Проверенный код: `7ffa155460801b533e0f72e766ced8a5465bceeb`. Он вошёл в main через `2cc2bec19ae2b5810a0104f95d6bf3dd6cf4e3bd`; деревья совпадают.
- Локальный `feat/rmasscan-stage2b-windows` уже на `982332f`: последующий коммит меняет документы, не устраняет три находки.
- CI точного 7ffa155 зелёный: macOS, Ubuntu, Windows, пакет Windows, language guard. Независимый чистый Mac-прогон: 849 passed / 0 failed / 8 ignored.
- Сохранённые Windows A/B/C повторно проверены: 29/19/21 PASS. Это старые сетевые прогоны, не fresh acceptance нового кода.
- На home-pc и госте стоят бинарники `931f69f`; хеши совпали с отчётом. После исправлений стенд должен получить новую явно закреплённую сборку.
- UI находится отдельно: `/Users/denyskolomiiets/masscan-studio/cross-platform`, worktree с незакоммиченными файлами. Там Slint-прототип и старый vendor `e195df3`, без настоящего Scan. Не смешивать его состояние с main.
- macOS raw I/O отсутствует. ARP codec есть, автоматического определения маршрута/next-hop для продуктового сканирования нет. `AdapterBinding` сейчас задаёт один интерфейс, source IPv4/MAC и next-hop MAC.

## Результаты и границы этапа

| Результат | Что пользователь получает | Что это доказывает |
|---|---|---|
| A. Исправленная приёмка | Три закрытых дефекта, отрицательные тесты, точные версии стенда | Достоверность новых лабораторных прогонов |
| B. Первый настоящий Scan из Slint | Start, результаты, Stop, Pause, закрытие/открытие приложения, Resume и история на Windows/Linux-стенде | Интеграцию UI → runner → engine → SQLite |
| C. macOS и обычная сеть | BPF, проверяемое определение binding, реальные платформенные прогоны | Возможность перехода от лабораторной сборки к приложению на трёх ОС |

**B — промежуточная инженерная сборка, не публичная v1 и не отмена требования трёх ОС.** В B реальные сканы ограничены заранее проверенным лабораторным профилем binding и разрешёнными целями. В обычном интерфейсе не появляется требование вручную вводить MAC-адреса: до готовности C произвольная сеть не поддерживается и явно отклоняется.

Полный DNS/Nmap/export, физический Windows NIC, оптимизация sendqueue и публичные установщики — следующие отдельные задачи. Их отсутствие не мешает доказать B; они остаются обязательным долгом до объявления полного паритета v1. Импорт Swift окончательно отменён пользователем 2026-10-26 и в дальнейшие работы не входит. Не показывать демонстрационные действия как работающие функции.

## Global Constraints

- UI без root/administrator; пароль принимает только системный механизм. Один runner на сеанс, один активный скан; Lock доступен в idle, выход отзывает сеанс.
- Никакой постоянной службы, скрытой установки драйверов, изменения firewall, произвольного CLI и автоматического начала сканирования.
- Runner не пишет SQLite/экспорт и не запускает Nmap. Engine встроен в runner; отдельного внешнего masscan и парсинга stdout в целевом пути нет.
- Модель угроз — §5.3 спеки. Peer/process identity и сеанс проверяются; токен не передаётся в argv/env. Не обещать защиту от внедрения вредоносного кода с правами владельца UI.
- Авторизация ≤180 с, handshake ≤10 с, кадр команды ≤131072 байт. Несовместимая версия протокола, чужой session/attempt и неверный кадр отклоняются до запуска.
- Сохраняются лимиты задания: 1–4096 целей, targets <65536 байт UTF-8, TCP-порты 1–65535, rate 1–10 000 000, default 22,80,443 и rate 100, wait=3. Runtime: IPv4/TCP, NIC=1, shard=1/1, retries=0, BlackRock rounds=14.
- u64 остаётся в Rust. Seed/index — decimal TEXT в SQLite и строки на границе Slint. Проверять отдельно представление и допустимость индекса для конкретного задания.
- SQLite WAL + synchronous=FULL, commit каждые 250 мс или 1000 результатов. Paused/Resume доступны только после транзакционного сохранения результатов и checkpoint и ACK.
- UI delivery: 50 мс или 1000 изменений, максимум 4 MiB сериализованных событий. Progress можно объединять; результаты и lifecycle нельзя молча отбрасывать. Контрольные сообщения не ждут опустошения очереди результатов.
- Stop прекращает TX в пределах согласованного 1 с; ожидание RX drain и сохранение отдельно отражены в состоянии. Измерять на каждой ОС, не считать быстрый fake доказательством дедлайна Npcap/BPF. Forced termination, ошибка записи или потери RX никогда не выдаются за Completed/Paused.
- Сохраняются engine RX-health/TX-stall и типизированные причины ошибок. Не уменьшать их строгость ради зелёного UI.
- Не переносить в продукт `rmasscan-lab`, fixture/flood/forging API. `rmasscan-net` в продуктовом runner подключается без feature `lab`.
- Не править старые доказательства и их verdict. Новая приёмка — новый каталог, commit, хеши, сырые логи и capture.

## Review Focus

1. Потеря управляющей/lock-сессии при работающем скане: новый запуск запрещён, свой текущий запуск останавливается, чужие ресурсы не затрагиваются — задачи 1 и 6.
2. Смена имени suite или каталогов не скрывает неразобранную утечку на eno1 — задача 2.
3. Capture INVALID/unknown или отказ Stop не превращается в принятую медиану — задача 3.
4. Смерть процесса между записью checkpoint и ACK, заполненный диск и поздние события старой попытки не создают ложный Resume — задачи 5–7.
5. Старая UI-копия core, неверный binding или изменившаяся сеть не запускают другое задание под видом исходного — задачи 4, 6 и 9.

## Порядок и ответственность

```
1 → 2 → 3 → A: повторная приёмка стенда
4 → 5 → 6 → 7 → 8 → B: настоящий Scan из Slint
                 9 → C: macOS + сетевой preflight
```

Офлайн-задачи 4–7 могут идти параллельно исправлению стенда. Любая новая raw-приёмка ждёт закрытия P1. Задача 9 может разрабатываться параллельно UI; её аппаратная проверка также ждёт исправленного стенда и явной разрешённой цели.

Рабочие ветки создавать от свежего main в отдельных worktree. Общие интерфейсы protocol/store фиксировать до параллельной реализации. Не редактировать один файл несколькими исполнителями. Каждый блок заканчивается своим ревью; общий runtime не переписывается ради удобства стенда.

## 1. Потеря блокировки должна останавливать Windows-suite

**Files:** `rmasscan/crates/rmasscan-lab/src/windows_suite.rs`, `windows_suite_tests.rs`; при необходимости отдельный `suite_lock.rs` для владельца блокировки.

**Contract:** `LockGuard` должен не только освобождать ресурс в Drop, но и сообщать потерю владения. Предлагаемый API: `ensure_held(&mut self) -> Result<(), LockLost>`. Проверка вызывается перед удалёнными мутациями/raw-start и во время ожидания. Удалённые операции привязаны к идентификатору владельца; поздняя команда потерявшего блокировку процесса не может запускать или чистить ресурсы нового владельца.

- [ ] Перенести диагностический Rust-тест из отчёта, поменять ожидаемое неправильное поведение на требуемое: lock SSH отвечает LOCKED, завершается 255; итог не Ok(0), последующих raw-runner вызовов 0. Получить RED.
- [ ] Добавить отдельные тесты потери lock до запуска, во время активной попытки, во время cleanup; проверить сохранение доказательств и отсутствие воздействий на второй экземпляр.
- [ ] Реализовать наблюдение lock-сессии и остановку своей активной работы. Одна проверка `try_wait()` в начале недостаточна: закрыть гонку между проверкой и исполнением удалённой команды через проверку владельца на удалённой стороне.
- [ ] Не выполнять глобальную очистку без подтверждённого владения. При невозможности достоверно завершить удалённую работу — ABORT с сохранением `.abort-uncopied`, дальнейших запусков нет.
- [ ] GREEN: `cargo test --locked -p rmasscan-lab --lib windows_suite`; отдельно реальные локальные SIGINT/SIGTERM и timeout-тесты без SSH к стенду.
- [ ] Ревью гонок владения; только затем отдельный fix commit после разрешения исполнения.

## 2. Проверять незавершённые доказательства во всём стенде

**Files:** те же `windows_suite.rs`, `windows_suite_tests.rs`; `verify.rs` и его тесты только при необходимости переиспользовать существующую проверку safety.

**Contract:** обнаружение `.abort-uncopied` идёт по всему `~/winvm/t4-ev`, а очистка остаётся ограниченной принадлежащими запуску объектами. `sweep_remote` возвращает все неразобранные каталоги, а не только каталоги переданного `suite`.

- [ ] RED: `old-suite` содержит keep marker и непустой eno1.pcap, запрашивается `new-suite`: итог isolation refusal (существующий exit 13), raw-start=0.
- [ ] RED: старый каталог с пустым/неполным/нечитаемым capture сохраняется и блокирует старт как непроверенный; успешный полностью собранный старый прогон не блокирует новый.
- [ ] Разделить обнаружение, проверку и удаление. Не следовать symlink вне корня, не удалять неразобранный каталог, не «исправлять» его verdict.
- [ ] Документировать восстановление: скопировать и проверить хеши, разобрать safety-причину, сохранить результат решения; смена имени или автоматическое удаление marker не являются восстановлением.
- [ ] GREEN: `cargo test --locked -p rmasscan-lab --lib windows_suite` и проверка `verify` для safety-trip в active/discarded/aborted evidence.
- [ ] Отдельное ревью и fix commit.

## 3. Валидировать Stop-часть Linux performance и повторить приёмку

**Files:** `rmasscan/crates/rmasscan-lab/src/wire_suite.rs`, `wire_suite_tests.rs`, `rmasscan/crates/rmasscan-net/tests/linux_wire.rs`; новый отчёт в `docs/experiments/2026-10-25-acceptance-fixes.md`.

**Contract:** основной throughput и Stop-leg имеют отдельные verdict. `stop.capture_valid != true`, неизвестные обязательные поля, неправильный исход/rc и отсутствие фактической остановки не дают принятого Stop-leg. Невалидные Stop-leg не входят в Stop-медиану и не позволяют объявить полной всю приёмку.

- [ ] RED: копия матрицы из 40 ячеек, все `stop.capture_valid=false`; приёмка должна отвергнуть её. Повторить для null/отсутствия поля, отказа процесса и неверного `stopped_early`.
- [ ] Разобрать results.json типизированно/через serde_json; не искать подстроку `"valid":false`. Закрепить позитивную матрицу и раздельный отчёт throughput/Stop.
- [ ] GREEN: focused `wire_suite` tests и `linux_wire` на синтетических матрицах. Проверить корректный частичный результат при прерывании.
- [ ] Чистый checkout: fmt, clippy `-D warnings`, workspace tests, language guard; CI точного commit на трёх ОС. Повторное независимое ревью задач 1–3.
- [ ] После закрытия P1: новая сборка по commit, deploy manifest и сверка SHA-256 на Mac/home-pc/госте. Записать версии driver/NIC и clock preflight.
- [ ] Linux/minipc: smoke, затем полные 40 perf-ячеек (C/Rust × 4 rate × 5 повторов) с валидными Stop-leg. Если capture не справляется с rate, оставить INVALID и объяснить; не нормализовать к PASS.
- [ ] Windows/n2: целевые проверки потери lock и предыдущего aborted suite; затем A/B на одной новой сборке. Если меняются счётчики/формат perf verdict — C также повторить. Старые A/B/C не переименовывать в новый commit.

**Выход A:** три дефекта закрыты регрессионными тестами и ревью; свежие live-результаты имеют измеренный scope. Windows VM не объявляется физическим NIC, gate 10k/100k не закрывается зелёной сборкой.

## 4. Вернуть Slint в актуальную ветку без второго экземпляра движка

**Files:** новый `studio/Cargo.toml`, `studio/Cargo.lock`, `studio/crates/studio-ui/{Cargo.toml,build.rs,src/main.rs,ui/main.slint}`, `studio/xtask/`; `.github/workflows/studio.yml`; README.

**Input:** выбранные исходники старого `cross-platform/spikes/slint-table`, UI-модель и настройки. Прототип находится вне main и должен быть инвентаризирован перед переносом.

- [ ] Записать source path и SHA-256 переносимых файлов. Сохранить системную тему, светлую/тёмную тему, таблицу и выбранные взаимодействия; не переносить target/, артефакты, старый vendor, инструменты с интерпретаторами.
- [ ] Создать отдельный Cargo workspace `studio/`, использующий `../rmasscan/crates/*` через относительные path dependencies внутри одного репозитория. Никаких абсолютных зависимостей на соседние worktree.
- [ ] Старый `scan-engine` адаптировать к актуальным `ReadyPlan`, `Engine::start/resume`, `EngineHandle`, `Event`, `Outcome`, `Checkpoint`. Не называть существующий offline prepare настоящим Scan.
- [ ] Удалить product-зависимость от fake-masscan; сохранить synthetic mode только как явно помеченную тестовую конфигурацию.
- [ ] Проверить независимость build graph: scanner workspace сохраняет свои `no_c_in_build` и cargo-deny; `studio` не добавляется в его members. Root language guard остаётся общим, без исключения для приложения.
- [ ] Build/test UI на трёх ОС; отдельный запуск окна. В headless Linux CI сборка не считается интерактивной приёмкой.

**Выход:** воспроизводимый UI из main-совместимого дерева, актуальное ядро, прежний дизайн; сетевой Scan пока не включён.

## 5. Протокол и хранилище до подключения raw I/O

**Files:** `studio/crates/studio-protocol/src/{lib,codec}.rs`, `studio/crates/studio-store/src/{lib,schema,writer,recovery}.rs`, тесты `protocol_contract.rs`, `durability.rs`, `recovery.rs`.

**Предлагаемые новые интерфейсы, не существующий API engine:**

- `Envelope<T> { protocol_version, session_id, scan_id, attempt_id, sequence, payload: T }`.
- Handshake: `Hello { protocol_version, build_id, session_id, capabilities }`; совместимость и identity проверяются до допуска Command.
- `Command`: `Start(JobSnapshot)`, `Resume { job: JobSnapshot, checkpoint: CheckpointRecord }`, `Pause`, `Stop`, `AckCheckpoint { checkpoint_id, committed_sequence }`, `CloseSession`. `CheckpointRecord` содержит точные байты engine checkpoint, его формат, идентификаторы задания/попытки и digest; не индекс без контекста.
- `RunnerEvent`: `Started`, `Results`, `Progress`, `CheckpointPending`, `Finished`, `Failure`. IPC не сериализует приватные engine-типы напрямую; номера версий и enum payload контролируются протоколом.
- `JobSnapshot`: нормализованные compact ranges, exclusions, seed/rate/wait, runtime-параметры, binding, engine/protocol versions и digest. Он неизменяем после Start.
- `Store::open(path)`, `append_batch(attempt_id, sequence, rows)`, `commit_checkpoint(snapshot, checkpoint, through_sequence) -> CommitReceipt`, `recover()`.
- `CommitReceipt` выдаётся только после commit; повтор batch/ACK идемпотентен. Result key включает scan и endpoint, а attempt/sequence сохраняют происхождение.

- [ ] Сначала зафиксировать wire schema, лимит 131072 байт для каждого кадра и разбиение больших batches; не раскрывать /0 в список адресов.
- [ ] RED/GREEN: malformed/oversized/truncated frame, неверная версия, старый attempt, повтор sequence, u64-граничные значения. Состояние чужого задания не меняется.
- [ ] SQLite: исходный кандидат — `rusqlite` без bundled/buildtime_bindgen, с закреплением версии и проверенной внешней SQLite. Проверить загрузку/версию на каждой ОС до реализации store; зависимости SQLite не должны попадать в runner или scanner workspace. Не включать bundled C и не ослаблять scanner bans как обход проблемы сборки.
- [ ] Создать jobs/attempts/results/checkpoints/schema-version; WAL+FULL; batch 250 мс/1000; canonical decimal TEXT для u64. На Unix каталог 0700, БД/WAL/SHM 0600; на Windows ACL владельца.
- [ ] RED/GREEN: смерть до commit, после commit до ACK, повтор после restart, заполненный диск, повреждённая/новее ожидаемой schema. До commit Resume недоступен; после commit checkpoint восстанавливается без root-файла.
- [ ] OS-backed single-instance lock на канонический data directory до открытия store и runner; тест crash release. Активные незавершённые попытки при восстановлении становятся Interrupted.
- [ ] Проверки: `cargo test --locked -p studio-protocol -p studio-store` из `studio/`; отдельные kill/crash integration tests.

SQLite — уже выбранное хранилище, не предложение заменить его JSON. Выбор способа поставки внешней библиотеки документируется вместе с проверенными путями/версиями. [Документация rusqlite](https://github.com/rusqlite/rusqlite) подтверждает различие системной линковки и bundled-компиляции; успешная сборка одной ОС не переносится на остальные.

## 6. Сессионный runner и транспорт

**Files:** `studio/crates/studio-runner/src/{main,session,engine_bridge}.rs`, `studio/crates/studio-platform/src/{lib,unix,windows}.rs`, `studio/crates/studio-app/src/{session,controller}.rs`; тесты `session_auth.rs`, `runner_lifecycle.rs`, `engine_bridge.rs`.

**Interfaces:** `RunnerClient::connect(launch, identity)`, `send(Command)`, `next_event()`; `SessionController` владеет соединением и attempt state. Runner преобразует JobSnapshot в ReadyPlan, проверяет его заново и использует существующие `Engine::start/resume`, `CancelHandle`, `recv_event_timeout`, `checkpoint`, `outcome`, `join`.

- [ ] Сначала непривилегированный runner + настоящий engine с FakeAdapter: Start/Results/Stop/Pause, только одна попытка, итог после всех результатов, неизвестная команда отзывает сеанс.
- [ ] Авторизация по ОС: Unix socket 0700 + peer/process identity; Windows named pipe DACL + PID/удерживаемые process handles, remote pipe forbidden. Не использовать argv/env-secret и не доверять одному числовому PID.
- [ ] Linux pkexec, Windows runas и macOS osascript подключаются только после проверенного bootstrap. Таймаут/отмена возвращают понятное состояние; пароль приложение не читает.
- [ ] Runner из admin-owned каталога и проверяемые зависимости. Сборка в пользовательском target/ не считается доверенной установкой. Разовая установка — отдельная явная команда с manifest/hash, без daemon/service.
- [ ] Повышенный runner не содержит UI/SQLite/Nmap/lab API. Default features не включают `rmasscan-net/lab`.
- [ ] RED/GREEN: подмена endpoint, старый runner другой версии, отмена UAC, другой UID/SID, PID reuse, обрыв IPC, смерть UI/runner, переполнение канала. Late события не применяются к новой попытке.
- [ ] Управление Pause/Stop и отслеживание disconnect работают независимо от очереди Results. Ошибка сохранения в непривилегированном процессе останавливает engine и даёт неполный исход.
- [ ] Windows/Linux raw включается только после задачи A и валидированного лабораторного binding. macOS в этой точке явно Unsupported, без скрытого внешнего masscan.
- [ ] Проверки: `cargo test --locked -p studio-runner -p studio-platform -p studio-app`; отдельный bootstrap-тест на каждой ОС без отправки пакетов.

## 7. Подключить настоящий цикл к UI и долговечный Resume

**Files:** `studio/crates/studio-ui/src/{main,model,actions}.rs`, `ui/main.slint`; `studio/crates/studio-app/src/{controller,delivery}.rs`; тесты `scan_flow.rs`, `backpressure.rs`, `checkpoint_ack.rs`.

**UI states:** Idle → Authorizing → Starting → Scanning → Pausing/Saving → Paused; Stop → Stopping → Stopped. Completed, Failed, Interrupted — отдельные исходы. Paused выставляется только по CommitReceipt; Finished(Paused) engine сам по себе недостаточен.

- [ ] Подключить кнопки Start/Stop/Pause/Resume к controller; прогресс и строки из RunnerEvent. Synthetic режим не смешивается с реальными результатами.
- [ ] При CheckpointReady сначала получить/проверить точный Checkpoint engine, дописать все предшествующие результаты, commit, затем ACK. Повторить тот же сценарий после перезапуска приложения и новой авторизации.
- [ ] Resume сохраняет scan_id, seed и эффективный job, создаёт новый attempt_id. Изменение digest, binding, версии или неподходящий индекс блокирует resume до открытия адаптера.
- [ ] Медленный UI читает данные из store пакетами/диапазонами. FIFO событий ограничен 4 MiB; Progress объединяется, результаты не теряются. При невозможности записи — явный Fail/Interrupted, без бесконечной памяти.
- [ ] Неактивные DNS/Nmap-действия не показывают fixture как реальный ответ. История доступна после restart; удаление активного скана и Lock во время него запрещены.
- [ ] Системная тема остаётся default. Проверить сортировку IP/портов, множественный выбор, контекстное меню, клавиатуру и фильтр на 100k записей по методике §8, отдельно от сетевого pps.
- [ ] RED/GREEN: двойной Start, Stop во время авторизации, закрытие во время запуска, старые события после нового scan, disk-full перед ACK, disconnect после ACK.

## 8. Приёмка первого настоящего приложения

**Files:** `studio/xtask/`, `.github/workflows/studio.yml`, новый отчёт `docs/experiments/2026-10-25-studio-real-scan.md` и отдельный каталог evidence.

- [ ] Единая команда сборки из `studio/`: `cargo xtask build`; она собирает UI и runner и записывает source commit, dirty state, dependency lock и SHA-256 каждого бинарника.
- [ ] На Windows/n2 и Linux-стенде проверить из UI известные open/closed/silent порты: результаты совпали с внешним свидетелем, Stop работает, Pause/закрытие/повторный запуск/Resume продолжают то же задание.
- [ ] После убийства UI/runner пакеты прекращаются; история восстанавливается честно, Resume не появляется из несохранённого checkpoint. Проверить отдельно смерть процесса и разрыв IPC; для forced death runner подтвердить предел 2 с из спеки внешним capture, а не только завершением PID.
- [ ] Проверить один сеанс авторизации на несколько последовательных сканов и повторную авторизацию после смерти runner. UI остаётся непривилегированным.
- [ ] У каждого результата приёмки — конкретные UI/runner/engine hashes, ОС/NIC/driver, capture и итог. Наличие EXE или открывшееся окно не является Scan PASS.
- [ ] Для Linux без доступной desktop-сессии зафиксировать UI-interaction NOT RUN; Xvfb/compile не выдавать за проверку на пользовательском рабочем столе.
- [ ] Mac preview собирается и запускает UI/offline flow. Для .app подпись проверяется после окончательной упаковки и фактического запуска; пока нет BPF, его сетевой Scan не объявляется готовым.

**Выход B:** Windows/Linux инженерная сборка с настоящим лабораторным Scan, историей и Pause/Resume. Полный parity/release gate остаётся открытым до следующей задачи и завершения продуктовых функций.

## 9. Параллельное направление: macOS и сетевой preflight

**Files:** будущие `rmasscan/crates/rmasscan-net/src/macos/{mod,bpf}.rs`, изменения dispatch в `rmasscan-net/src/lib.rs`; продуктовый `studio-platform/src/network/`; отдельный подробный план `2026-10-25-macos-bpf-and-binding.md` до реализации этого направления.

- [ ] Зафиксировать BPF boundary без C-компиляции и без изменения контракта AdapterPair. Отдельные тесты record alignment, truncation, link type, stats, deadline, close и permission errors.
- [ ] На Mac подтвердить реальные TX/RX, kernel-drop semantics, Stop/Pause/Resume. Пока неизвестны счётчики — RxStatsUnavailable, не подставной ноль.
- [ ] Сетевой preflight определяет интерфейс, source IPv4/MAC, маршрут и next-hop. Проверять его до каждой попытки; смена сети/VPN блокирует автоматический resume.
- [ ] Не считать один next-hop MAC достаточным для произвольного множества on-link хостов. Поддержку нескольких next-hop спроектировать отдельно либо явно отказать неподдержанному job до отправки; без молчаливого пропуска целей.
- [ ] Не прятать unsupported link/VLAN/IPv6 и отсутствие разрешений за «пустым сканом».
- [ ] После аппаратной приёмки подключить Mac runner к тому же UI/store/protocol; повторить сценарий задачи 8. Объявлять три ОС только по трём фактическим результатам.

## Очередь после B/C

1. Реальные DNS и Nmap без повышения прав, с согласованными лимитами и безопасным XML.
2. Экспорт отфильтрованных результатов, CSV formula protection; ручной Swift-import на Mac с правильной эпохой дат и без изменения оригиналов.
3. Автоматический сетевой binding в пределах принятого сетевого scope, если не закрыт задачей 9; сон/смена сети без автозапуска.
4. Физический Windows NIC и sendqueue/performance отдельно от correctness VM.
5. Полный UI-паритет, оставшиеся 100k-метрики на каждой ОС, упаковка/лицензии и решение о публичной поставке.

## Как принимать работу

На каждую задачу: исходный commit → RED регрессии → минимальное исправление → GREEN → независимое ревью → commit задачи. Числа тестов берутся из нового лога, не из предыдущего отчёта. При найденном регрессе возвращается конкретная задача, а не весь проект к выбору UI-стека.

Первый исполняемый пакет — **задачи 1–3**. Офлайн-перенос UI и protocol/store можно вести отдельно; raw UI-приёмка заблокирована до A. Следующий видимый пользователю результат — **сборка B с настоящим сканированием из окна**, а не ещё один отчёт о лабораторных инструментах.
