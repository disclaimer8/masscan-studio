# Rust masscan: проверенное состояние перед этапом 2

Дата: 2026-10-23. Проверка кода, локальные офлайн-тесты и чтение GitHub CI.
Исходники не менялись, сетевые сканы не запускались, ветки не переключались.

## Зафиксированные версии

| Компонент | Состояние на момент проверки |
| --- | --- |
| Worktree порта | `/Users/denyskolomiiets/masscan-studio-rmasscan`, `feat/rmasscan-port`, чистый HEAD `74765d5bc90cf18edf62ec34f355403a0cfce1b8` |
| GitHub main | `04df2490bc627964907e4e13cb8e61dd8fe176be`, merge PR #1 с этапами 0–1 |
| Дерево `rmasscan/` | `bd3ac5e23b81380e530307f2e3841dae99eca397` одинаково в локальном HEAD порта и remote main |
| Studio | `feat/cross-platform-spikes`, HEAD `b02dd29`, новые файлы пока не закоммичены |
| Ядро внутри Studio | неизменяемый snapshot `e195df3983b51f408264e471a23119af373f2848` |

После встроенного в Studio snapshot изменились главным образом документация,
property-тесты, CI и лицензирование. Diff production `rmasscan-core/src` между
e195df3 и 74765d5 содержит только комментарии, изменения алгоритмов не найдены.
Поэтому срочная замена snapshot не нужна; новый runtime API потребует отдельного
обновления зависимости и миграции адаптера Studio.

## Что уже работает

- Компактные IPv4/port ranges, объединение и исключения, BlackRock и порядок
  transmit, SYN cookie, checksums, формирование TCP SYN, throttle и часы.
- ScanConfig/EffectiveConfig, валидация, echo, импорт подмножества paused.conf.
- CLI: `-sL`, `--echo`, `--echo-all`, `--offline --packet-trace`.
- Golden-фикстуры C, проверки порядка/байтов, property-тесты, карта перенесённых
  selftests. Карта явно различает перенесённое, частичное, этап 2 и отложенное.
- AGPL LICENSE/NOTICE, отдельный workspace без C-компиляции в текущем графе.
- Studio использует реальное ядро для офлайн-подготовки задания, исключений,
  количества целей и первых 32 элементов порядка. Это ещё не сетевой скан.

## Перепроверенные результаты

`cargo test --locked --workspace` на Mac: **172 passed, 0 failed, 1 ignored**.
Пропущен длительный release-бенчмарк. `cargo fmt --all --check` и
`cargo clippy --locked --workspace --all-targets -- -D warnings` прошли.
Логи: `evidence/2026-10-23-rmasscan-next-stage/`.

[CI 39989647414](https://github.com/disclaimer8/masscan-studio/actions/runs/39989647414)
для 74765d5 завершён успешно на `ubuntu-24.04`, `macos-14`, `windows-2022`:
fmt, Clippy, tests, cargo-deny. Фраза README «зелёный CI ещё не закрыт, нужен
push» уже устарела. Это Windows Server runner, не аппаратная проверка Windows 11/Npcap.
Отдельный [CI merge-коммита main 39992231418](https://github.com/disclaimer8/masscan-studio/actions/runs/39992231418)
при повторной проверке также завершился успешно на всех трёх ОС; результат
сохранён в `ci-main.json` отдельно от feature-ветки.

В BENCHMARKS.md записана скорость генерации около 0.96–0.99 от C на minipc.
В этой проверке замер не повторялся. Это офлайн-генерация, не скорость реальной
передачи/приёма. Байтовые тесты SYN включают значения из C-harness; сам harness
не закоммичен. Воспроизводимый захват pcap по сети ещё нужен на этапе 2B.

## Чего ещё нет

В workspace только `rmasscan-core` и `rmasscan-cli`. Нет raw I/O crate, runtime
Engine/Handle, RX parser для недоверенных кадров, receive/dedup, событий скана,
действующей Pause/Resume и владения адаптером. Наличие парсера paused.conf этого
не заменяет. Privileged runner/IPC, durable history и ACK checkpoint в Studio
также пока не реализованы.

## Что исправить до подключения сети

1. `for_each_probe` и Probe пока приватны в CLI. Ошибка callback прекращает
   полезную работу, но `transmit_scan` продолжает обход до конца: нужен реальный
   ранний выход/курсор, особенно для огромных диапазонов и Stop.
2. EffectiveConfig имеет публичные изменяемые поля; `validate` сам не отвергает
   seed 0. Engine должен принимать только проверенную, неизменяемую конфигурацию.
3. `-sL` с retries > 0 документирован как потенциально зависающий. Не использовать
   его для runtime; явная ошибка безопаснее воспроизведения зависания оракула.
4. Проверка «без C» сейчас перечисляет два crate и проверяет текущую платформу.
   Перед добавлением net/engine нужны весь workspace, все targets и контроль
   build scripts; существующий зелёный CI не доказывает будущую защиту.
5. Троттлер и raw read/write должны допускать отмену. Timeout в UI сам по себе
   не прекращает заблокированный системный вызов или сон внутри throttle.

Рекомендация: следующий исполнимый этап — **2A: отменяемый runtime на тестовом
адаптере**, затем **2B: реальный raw I/O и изолированный сетевой паритет**.
План: [2026-10-23-rmasscan-stage2a-engine.md](../superpowers/plans/2026-10-23-rmasscan-stage2a-engine.md).
