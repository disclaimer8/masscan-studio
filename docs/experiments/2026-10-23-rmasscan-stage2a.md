# Rust masscan: этап 2A, статус и приёмка

Дата: 2026-10-23. Ветка `feat/rmasscan-stage2a`, офлайн: без сети, сокетов,
повышенных прав и C. Локальная проверка выполнена на Mac (rustc 1.99.1). Запуск CI
на трёх ОС ещё не выполнялся: push не делался (см. «Что не доказано»).

## Что поставил 2A

- Crate `rmasscan-engine` (`#![forbid(unsafe_code)]`): один TX- и один RX-поток,
  отменяемые Pause/Stop, ограниченные очереди, терминальный `Outcome` отдельно от
  очереди результатов. Отмена проверяется перед каждой отправкой и внутри ожиданий
  throttle; очередь никогда не блокирует производителя.
- Core: `ReadyPlan` (неизменяемый, fallible-конструктор), `ProbeCursor`
  (`current` не продвигает, `advance_sent` подтверждает одну отправку), разбор RX
  для недоверенных байтов, кодек ARP, приватные поля `EffectiveConfig` с getters.
- Checkpoint/resume: версионированный формат, digest идентичности запуска
  (sha2), отказ resume при смене rate/адресов/исключений/портов/источника/версии.
- Fake-адаптер (`rmasscan_engine::fake`): скриптуемые Tx/Rx, ответчик SYN-ACK,
  ручные часы. Тесты не спят по-настоящему там, где важно время.
- Runtime v1 принимает только shard=1/1, NIC=1, retries=0, rounds=14, seed != 0;
  остальное это типизированный `UnsupportedConfig`.

## Свидетельства критериев выхода

`cargo test --locked --workspace`: **282 passed, 0 failed, 1 ignored** (длительный
release-бенчмарк генерации, как на этапе 1). Из них engine 50 (backpressure 6,
bounded_memory 1, identity 9, lifecycle 24, pause_resume 10), core: 135 unit,
`probe_cursor` 11, `receive` 35, `no_c_in_build` 2; golden/property этапа 1 прежние
и проходят. `cargo fmt --all --check`, `cargo clippy --locked --workspace
--all-targets -- -D warnings`, `cargo deny check bans licenses sources`: чисто.

| Критерий | Чем подтверждено |
| --- | --- |
| Побайтный resume | `pause_resume`: пауза в каждом индексе, затем resume даёт кадры, идентичные непрерывному запуску; цепочка pause-resume-pause-resume; пауза до первой отправки, на последнем probe, посреди WouldBlock |
| Нет пропусков | `partial_send_failure_...`, `would_block_unsent_retries_same_frame_...`, `uncertain_send_fails_without_checkpoint_or_retry` |
| Нет ложного CheckpointReady | `only_a_clean_pause_yields_a_checkpoint`, переполнение очереди и Uncertain не дают checkpoint |
| Безопасность границ RX | proptest `arbitrary_bytes_never_panic`, `random_headers_behind_valid_prefix_never_panic`, `every_truncated_arp_prefix_is_an_error`, ручные случаи IHL/длин/фрагментов/чужого cookie. Это property-тесты, а не libFuzzer-запуск |
| Stop <= 1 с | `stop_at_rate_1_interrupts_real_throttle_wait` (реальные часы, rate=1), пустой RX, полная очередь, во время drain; assertions на 1 с |
| Нет зависших потоков | Drop handle в обычном и drain-режиме, `alive_handles() == 0` |
| Нет C в графе | `no_c_in_build` смотрит `cargo tree --locked --workspace --target all -e normal,build,dev`: engine и подграф sha2 (sha2, digest, cpufeatures) входят, `cc` нет; `cargo deny` чист |
| Ограниченная память | `bounded_memory`, ниже |

### Bounded memory на масштабе /0

Тест `rmasscan-engine/tests/bounded_memory.rs`: план 0.0.0.0/0 минус 240.0.0.0/4,
один порт, 4 026 531 840 probe (config требует хотя бы один exclude для >1e9
адресов). Курсор отдаёт 1 000 000 probe, затем `ProbeCursor` с позиции
`range - 2` (O(1), без пролистывания), затем настоящий `Engine` с Tx, который
выбрасывает кадры, и пустым Rx; ждём 1M отправок, Stop.

Измерено: прирост RSS процесса (`ps -o rss=`) около 96 КиБ на курсоре и 80 КиБ на
engine при бюджете 64 МиБ. Материализация диапазона стоила бы десятки ГиБ, даже
бит на probe это ~480 МиБ. Отрицательный контроль: выделение 200 МиБ внутри
теста роняет проверку (`RSS grew 204896 KiB`). Дополнительно проверено, что
Stop прерывает скан до конца диапазона и пустой RX не рождает результатов.

Не измерено: RSS при реальных ответах и заполненной очереди результатов,
стоимость хранения 4096 событий, память UI/Studio, лимиты ОС, пиковое
потребление при долгой работе. Это не замер лимита RSS интерфейса. На Windows
RSS-проверка пропускается (нет `ps`), остаются структурные утверждения о позиции и
диапазоне. Тест быстрый (~0.4 с), не `#[ignore]`.

## CI

`.github/workflows/rmasscan.yml` ранее запускал `cargo test --all`; engine уже
входил в workspace, но шаги переведены на явные `--workspace` (fmt `--all`,
clippy и тесты), чтобы будущие члены не выпали. Два старых crate нигде не
перечислялись. Шаги cargo-deny и `no_c_in_build` покрывают engine с sha2.
**Трёхплатформенный прогон ожидает push.** Локально прошёл только macOS.

## Что 2A явно не закрывает

- Реальный raw I/O: AF_PACKET, BPF, Npcap. Тестовый адаптер не выдаётся за
  реальный; ни один живой скан не запускался и не работает.
- Golden pcap C-oracle (изолированный namespace/veth), ARP по проводу, discovery.
- Привилегированный runner, IPC-аутентификация, durable history и ACK checkpoint,
  подключение настоящего Scan к Studio. Это этапы 2B (пп. 1-6 дорожной карты) и 3.
- Три ОС в CI и аппаратный Windows 11/Npcap (NOT RUN, не PASS).
- Измерения скорости передачи/приёма; BENCHMARKS.md описывает только offline-генерацию.

Вердикт GO 2A по критериям плана: локальные проверки проходят, resume
побайтно совпадает, остановка укладывается в контракт на fake-адаптере. Итоговый
GO требует зелёного CI на трёх ОС после push и fresh review (см. отчёт задачи 6).

## Открытые хвосты (переносятся в 2B)

1. WouldBlock busy-spin: при `WouldBlockUnsent` TX повторяет тот же кадр без
   паузы; на реальном адаптере нужен backoff/ожидание готовности.
2. Throttle pre-sleep check: отмена проверяется перед отправкой и внутри
   ожиданий, но проверка непосредственно перед входом в сон throttle отмечена
   ревью как недоделанная; на реальных часах задержка отмены ограничена только
   шагом сна. Закрыть и покрыть тестом в 2B.
3. Rx transient/fatal: любая ошибка `Rx::recv` сейчас фатальна (`rx_error_fails_the_scan...`);
   реальным адаптерам нужно различие временных и необратимых ошибок.
4. Source MAC на `Reply`: разобранный ответ не несёт MAC источника; он нужен
   для ARP/диагностики и не используется.

## Подготовка обновления snapshot Studio (только план, ничего не копировалось)

Mutable worktree в Studio не копировать до фиксированного commit API; текущий
snapshot ядра в Studio (`e195df3`) остаётся. При обновлении потребуется:

- Миграция на getters: поля `EffectiveConfig` приватны, адаптер Studio читает
  `massip()`, `seed()`, `max_rate()`, `operation()` и т.д.; офлайн-preview тесты
  Studio должны остаться зелёными.
- Зависимость от `rmasscan-engine` (и транзитивно sha2/digest/cpufeatures) с
  фиксированными версиями; проверить `cargo tree` и deny-политику Studio.
- `LICENSE` (AGPL-3.0) и `NOTICE` (атрибуция Robert David Graham) вместе с
  кодом, плюс checksum manifest файлов snapshot и commit/tree-хэш источника.
- Studio `Process` fixture сохраняет явную маркировку: настоящий Scan до этапа 3 не
  подключается.
