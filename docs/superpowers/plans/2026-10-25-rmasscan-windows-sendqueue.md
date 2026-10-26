# Rust masscan: 2B-sendqueue / Windows throughput — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** поднять пропускную способность Windows-адаптера пачечной отправкой через Npcap sendqueue
(`pcap_sendqueue_alloc/queue/transmit/destroy`), сохранив каждый действующий контракт (вызов ≤50 мс,
Stop/Pause ≤1 с, exactly-once `sent`, WouldBlock, RX health, checkpoint), заново снять часть C (те же 20 ячеек)
на запечатанном Windows VM стенде `n2` и честно записать результат: потолок VM, если он останется, это OPEN, а не
скрытая цифра.

**Architecture:** net → engine → core сохраняются, публичный `open_explicit(&AdapterBinding) ->
Result<OpenedAdapter, NetError>` не меняется. Контракт `rmasscan_engine::io::Tx` получает пачечный метод
`send_batch` с реализацией по умолчанию (цикл `send`) и `max_batch()` (по умолчанию 1): Linux и macOS адаптеры
не меняются и ведут себя побайтно так же. Engine берёт из `Throttler` пачку, режет её по `max_batch()` и
подтверждает курсор ровно на число кадров, принятых драйвером. Windows `TxHalf` собирает пачку в один
владеемый `pcap_send_queue` и выполняет один синхронный `pcap_sendqueue_transmit(sync = 0)`; размер пачки
ограничен константой, выбранной спайком так, что один transmit укладывается в бюджет вызова. Лаборатория
(`rmasscan-lab windows-suite`/`windows-verify`) получает проверки, которые не дают выдать одиночную отправку
за sendqueue.

**Tech Stack:** Rust 1.99.1, существующий workspace, `windows-sys = 0.61.2` (только для `sys`), собственные
FFI-объявления Npcap (`src/windows/ffi.rs`), Npcap 1.90 на госте (не поставляется), QEMU Win11 VM на `home-pc`
(стенд `n2`: мост `wvb-n2`, netns `wvp-n2`), minipc (Ubuntu) для Linux-регрессии и как хранитель закреплённого
C-оракула `8e6b3b0`.

**Spec:** [Rust-порт](../specs/2026-10-23-masscan-rust-port-design.md) (§4.5 троттлер строки 273–287, §5.2
строка 378, §5.3 строка 409, §7.6 строка 533, этап 5 строка 612, риск sendqueue строка 706),
[контракты engine §0.1](../specs/2026-10-23-cross-platform-qt-rust-design.md) (строки 77–108),
[план Windows](2026-10-24-rmasscan-stage2b-windows.md), [план Windows VM](2026-10-24-rmasscan-windows-vm-next-stage.md),
[приёмка Windows VM](../../experiments/2026-10-24-rmasscan-windows-vm-acceptance.md) (§6 часть C, §9 ограничения, §12 дефекты CI),
[спайк Npcap](../../experiments/2026-10-24-rmasscan-stage2b-windows-spike.md),
[приёмка macOS](../../experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md) (§9 уроки),
[перечень готовности](../../experiments/2026-10-24-rmasscan-readiness.md) (строка «Windows throughput»),
[Rust-лаборатория](../../../rmasscan/docs/rust-lab.md) (раздел «Deployment for the live Windows rerun»),
[стенд VM](../../../rmasscan/docs/windows-vm-lab.md).

Репозиторий: `$REPO`, ветка `feat/rmasscan-stage2b-sendqueue` от `main` не раньше `baa5cc7` (PR #14 влит);
если к старту влиты исправления лаборатории `01aaf8e..149d09d` (ветка `fix/rmasscan-lab-7ffa155-findings`),
база берётся после них. Репозиторий Rust-only по решению пользователя.

## Исходное состояние и порядок

- Windows-адаптер (`rmasscan-net/src/windows/adapter.rs`, строки 86–106): один синхронный `pcap_sendpacket` на
  кадр, rc 0 → `Sent`, иначе `Uncertain`; `WouldBlockUnsent` не выдаётся. Таблица символов (`ffi.rs`, строки
  262–284) не содержит `pcap_sendqueue_*`. Подставная таблица (`windows/tests/fake.rs`, `symbol_addr`, строки
  497–523) тоже.
- Engine (`rmasscan-engine/src/engine.rs`, `run_tx`, строки 456–562): пачка `Throttler::next_batch_interruptible`
  (до 10 000) отправляется по одному кадру; `halt` проверяется перед каждой отправкой; только `Sent` двигает
  курсор; окно TX-stall от первой неудачной попытки кадра. `ProbeCursor` (`rmasscan-core/src/probe.rs`, строки
  290–369) выдаёт один `current()` и подтверждает один `advance_sent()`.
- Часть C на VM (`perf-r1`, код `847e218`): медианы wire 100.7 / 1006.7 / 6444.6 / 6321.1 pps; gate ±20% MET на
  100 и 1000, OPEN на 10k и 100k; потолок около 6.4 kpps при p50 `pcap_sendpacket` 113–227 мкс (спайк). RX health,
  Stop, pause/resume, linkloss, rxloss, perm — PASS (части A и B). Физический NIC NOT RUN.
- Npcap API (документация Npcap, прочитана 2026-10-25): `struct pcap_send_queue { u_int maxlen; u_int len; char
  *buffer; }`; `pcap_sendqueue_alloc(u_int memsize) -> pcap_send_queue*`; `pcap_sendqueue_queue(queue, const
  pcap_pkthdr*, const u_char*) -> int` (0 ok, −1 «Packet queue is full»); запись в буфере это `pcap_pkthdr` (16 байт
  на Windows, см. `ffi::PcapPkthdr`) + `caplen` байт; `pcap_sendqueue_transmit(p, queue, sync) -> u_int` возвращает
  число отправленных байт, меньше `queue->len` при ошибке (`pcap_geterr`), `sync = 0` шлёт как можно быстрее, `sync
  ≠ 0` выдерживает метки времени в драйвере; реализация `PacketSendPackets` → ioctl `BIOCSENDPACKETSNOSYNC`, вызов
  синхронный. `pcap_sendqueue_destroy(queue)`.
- C-оракул `8e6b3b0` на Windows: sendqueue в `rawsock.c` (спека ссылается на `:261–271`, `:822–830`): очередь
  `pcap_sendqueue_alloc`, `pcap_sendqueue_queue` на кадр, при переполнении и в конце пачки троттлера
  `pcap_sendqueue_transmit(..., 0)` + destroy/alloc. Источник на minipc (`$HOME/rmasscan-oracle/masscan/src/rawsock.c`);
  в этом репозитории C-кода нет. Задача 0 сверяет строки чтением.

Порядок: **0 — база и контракты → 1 — пачечный контракт engine/core (офлайн, все ОС) → 2 — ABI и владение
sendqueue (офлайн, fake) → 3 — спайк на стенде (STOP/GO, выбор размера пачки, семантика частичной отправки) →
4 — `TxHalf` на sendqueue → 5 — harness, suite, verifier → 6 — живая приёмка A/B/C на VM и Linux-регрессия →
7 — отчёт, readiness, CI, GO**. Задачи 1–2 и офлайн-часть 4–5 не ждут стенда; живые части без стенда NOT RUN и
CI-сборкой не подменяются.

## Global Constraints

- **Pure Rust.** Никакого C, C++, Python, Swift ни в репозитории, ни в инструментах и CI; FFI-объявления в стиле
  `libc`/`windows-sys` допустимы (C не компилируется). `unsafe` только в `rmasscan-net`, в уже разрешённых
  модулях `windows::{ffi, handle, loader, process, sys}` и подставной таблице тестов, каждый блок с комментарием
  `SAFETY`; `adapter.rs` остаётся полностью безопасным. Language guard (`scripts/language-guard.sh`) PASS; новые
  файлы evidence только из allowlist (`json pcap txt csv log err sha256 md`, pcap без сжатия). В репозитории Python
  нет ни в каком виде; ad hoc `python3` в своей оболочке агенту не запрещён, но ничего от него не зависит.
- **Контракты не меняются.** Один вызов адаптера ≤50 мс по абсолютному дедлайну: `pcap_sendqueue_transmit`
  синхронен и не отменяем, поэтому пачка ограничена константой `TX_BATCH_FRAMES`, выбранной спайком так, что
  один transmit укладывается во внутренний бюджет (`IO_BUDGET` = 42 мс, запас над срывом планировщика как в
  спайке); превышение считается (`tx_over_budget`) и это FAIL приёмки, не примечание. Stop/Pause ≤1 с: `halt`
  проверяется перед каждой пачкой; пауза на границе пачки. Exactly-once: `sent` равен числу кадров, принятых
  драйвером (тот же стандарт, что rc 0 у `pcap_sendpacket`: доставка не доказывается, её доказывает захват
  пира, верификатор сравнивает `tx_sent` с SYN на проводе). Частичный transmit: префикс до границы записи это
  `Sent`, остаток `Uncertain` → `Failed(TxUncertain)` без checkpoint и без повтора (решение 4; GO спайка
  обязателен, иначе вся пачка `Uncertain`). `WouldBlockUnsent` Windows-адаптер по-прежнему не выдаёт. RX health
  `Some(n)`/`None`/`Err` без изменений; `None` никогда не ноль. Checkpoint только при `Paused`.
- **Живые кадры только на запечатанном стенде `n2`** с теми же шлюзами, что приёмка Windows: гостевой Verify с
  nonce, `record-guest`, полный `vm-lab status` с `raw_run_allowed: true` до и после, захват пира и `eno1`,
  `capture_schema 3`; **0 кадров лаборатории на `eno1`** в каждом прогоне (кадр на `eno1` это FAIL без права
  повтора, suite выходит кодом 13). Отправка только с `\Device\NPF_{C4617223-…}` и только на `198.18.0.2`.
  Npcap не поставляется и не переустанавливается; никаких изменений firewall, маршрутов, DNS, NIC на `home-pc`,
  госте, minipc и Mac.
- **Байтовый паритет SYN с C-оракулом `8e6b3b0`** сохраняется вместе с порядком: sendqueue передаётся в порядке
  постановки, engine ставит кадры в порядке курсора, поэтому порядок кадров на проводе часть контракта и
  проверяется верификатором как раньше (c01–c06, pause-группы). Фикстуры
  `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures` переиспользуются: binding
  тот же, новый захват оракула не нужен.
- **Гигиена агентов (уроки W2 и macOS).** Каждый агент работает в фиксированном приватном `CARGO_TARGET_DIR` по
  роли (`$SCRATCH/target-impl`, `$SCRATCH/target-review`, `$SCRATCH/target-live`), `CARGO_INCREMENTAL=0`; каталоги
  не делятся между ролями и удаляются по окончании роли (диск ограничен). Экспорты прежних коммитов удаляются:
  на `home-pc` остаётся только `~/winvm/build/<текущий sha>`, на госте только `C:\Users\lab\src\rmasscan-<текущий sha>`
  и `C:\Users\lab\t4\wire_scan.exe` текущей сборки, на minipc только текущая сборка `rmasscan-lab`. Живой оператор
  строит оркестратор из чистого клона с `RMASSCAN_LAB_BUILD_COMMIT`. Тесты не зависят от точности `sleep`,
  уникальные имена через `getrandom`, не ждут немедленного освобождения `flock`. Никакой самодельной сложности: ни
  одного механизма, которого не требует контракт (нет адаптивного размера пачки, нет фонового TX-потока, нет
  повторной отправки остатка пачки, нет `sync = 1`).
- **GO только при зелёном CI на точном HEAD** (`ubuntu-24.04`, `macos-14`, `windows-2022`, `language-guard`) и
  после полного `cargo test --locked --workspace` на трёх ОС перед push (Mac, minipc, гость VM).
- Runtime остаётся: IPv4/TCP, NIC=1, TX=1, RX=1, shard=1/1, retries=0, BlackRock rounds=14; seed ненулевой;
  source IP/MAC явные, владение source IP не проверяется. Promiscuous не включается. Discovery/ARP, runner, UI,
  Linux `PACKET_TX_RING`, macOS пачки `write` в этот этап не входят.

## Review Focus

1. **Скрытая буферизация за `Sent`.** Курсор обязан продвигаться только на число кадров, которые драйвер принял в
   этом же вызове; никакая очередь не переживает вызов `send_batch`, Stop/Pause/panic не теряют «отправленные»
   кадры и не отправляют их позже. Проверяется fake-тестами engine и Windows (задачи 1, 4) и живым `stop_*`/
   `pause` (задача 6).
2. **Частичный transmit.** Число байт должно ложиться на границу записи `16 + caplen`; префикс `Sent`, остаток
   `Uncertain`; не на границе — вся пачка `Uncertain`; текст `pcap_geterr` статус не определяет. Спайк доказывает
   границу живым захватом (задача 3), fake-тесты перебирают все исходы (задача 4), `linkloss` части B проверяет путь
   вживую (задача 6).
3. **Бюджет вызова.** `TX_BATCH_FRAMES` выбран измерением (idle, под потоком мусора, при link down), `tx_over_budget`
   считается и в приёмке равен 0; engine режет пачку по `max_batch()` и `MAX_TX_BATCH`; размер очереди в байтах
   не позволяет `pcap_sendqueue_queue` вернуть −1 (задачи 3, 4, 5).
4. **Подмена пачечного пути одиночным.** Любая обёртка `Tx` (`HarnessTx` в `wire_scan`, `GuardTx` в живых
   тестах, `GuardedTx` лаборатории) обязана пробрасывать `send_batch` и `max_batch`; `run.json` несёт
   `identity.tx_mode`/`tx_batch_cap` и `net.tx_batches`; верификатор FAIL-ит ячейку ≥10k pps без единой пачки при
   заявленном sendqueue (задачи 1, 5).
5. **Шлюз доказательств.** Статус стенда до/после, `eno1` 0 кадров, хэши до копирования, INVALID/NOT RUN никогда
   PASS, те же фикстуры и binding без нормализации, `tx_sent` == SYN на проводе, порядок равен фикстуре (задачи 5–7).

## Карта файлов

- Изменить `rmasscan/crates/rmasscan-engine/src/io.rs` (`TxBatch`, `Tx::max_batch`, `Tx::send_batch`),
  `src/engine.rs` (`run_tx` пачками, `MAX_TX_BATCH`), `src/fake.rs` (сценарии пачек), `src/lib.rs` (экспорт),
  `tests/common/mod.rs` (`PauseTx` пробрасывает), новые тесты `tests/tx_batch.rs`.
- Изменить `rmasscan/crates/rmasscan-core/src/probe.rs` (`ProbeCursor::preload`, `advance_sent_n`) и его тесты.
- Изменить `rmasscan/crates/rmasscan-net/src/windows/{ffi,handle,adapter,live}.rs`, `src/windows/tests/{fake,adapter_tests}.rs`,
  `src/windows/tests.rs`, `src/lib.rs` (`NetStats` поля `tx_batches`, `tx_batch_max`, `tx_over_budget`; `TxMode`),
  `examples/wire_scan.rs` (`HarnessTx::send_batch`, `identity.tx_mode`, `tx_batch_cap`, блок `net`),
  `tests/windows_live.rs` (`GuardTx::send_batch`, новые живые тесты), `tests/macos_live.rs` (`GuardTx` пробрасывает).
- Изменить `rmasscan/crates/rmasscan-lab/src/{windows_suite,verify,link}.rs` и их тесты (`verify_perf_tests.rs`,
  `windows_suite_tests.rs`), `rmasscan/docs/rust-lab.md`, `rmasscan/docs/windows-wire-lab.md`.
- Создать `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-baseline.md`,
  `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-spike.md` + `-spike-raw/`,
  `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md` + `-acceptance-raw/{smoke-<sha>,functional-r3,failure-r2,perf-r2,linux-functional-r1,verification}`.
- Изменить `docs/experiments/2026-10-24-rmasscan-readiness.md` (строка «Windows throughput» делится на VM и
  физический NIC), `.github/workflows/rmasscan.yml` (комментарий: sendqueue проверяется fake-тестами, живые
  `#[ignore]`).

## Константы стенда (единые для всех задач)

| Параметр | Значение |
| --- | --- |
| Стенд | `n2`: мост `wvb-n2` без uplink/IP/NAT, netns пира `wvp-n2` (`lab0`), гостевой NIC `Ethernet 2` |
| Binding гостя | `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}`, `198.18.0.1/30`, MAC `52:54:00:04:80:a9` |
| Пир | `198.18.0.2`, MAC `02:57:4c:3d:2e:9b`; listeners `80,443,8000-8007`, «немой» `8099`, остальные RST ядра |
| seed / rate / wait / retries | 1 / 100 / 3 / 0 (часть C: 100, 1000, 10000, 100000; `stop_*` rate 1, wait 10) |
| Часть C | `--plan perf`: `perf.<rate>.r<rep>`, 4 × 5, порты `1-500`, `1-5000`, `1-50000`, `1-65535`, source port 40000, `PERF_RATES`/`PERF_REPS` в `verify.rs` строки 223–224 |
| Gate части C | медиана `steady_pps_wire` по ≥3 Completed PASS ячейкам в ±20% → MET, иначе OPEN, <3 ячеек → NOT RUN (`perf_summary`, `verify.rs` строки 2861–2925); никогда не меняет `overall` |
| Фильтр `eno1` | `net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host 52:54:00:04:80:a9 or ether host 02:57:4c:3d:2e:9b or ether proto 0x88b5` |
| Фикстуры C | `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures` (masscan `8e6b3b0`, бинарь `8afc8ec8…`) |
| Бюджеты | `MAX_IO_TIMEOUT` 50 мс (контракт), `IO_BUDGET` 42 мс (Windows, спайк 2B), порог выбора пачки p99.9 ≤ 21 мс / max ≤ 42 мс |
| Пачка | `TX_BATCH_FRAMES` (предварительно 256; окончательно по спайку, из ряда 16/64/256/1024/4096), байты очереди `TX_BATCH_FRAMES × (16 + MAX_TX_FRAME = 1518)`; engine `MAX_TX_BATCH = 4096` |
| Доступ | `home-pc` (Ubuntu, `sudo -n` без пароля у `a1`), гость `ssh -J home-pc -p 2222 lab@127.0.0.1`, QMP `~/winvm/qmp.sock`, стенд `~/winvm/lab/n2.json` |

## Задача 0. База и контракты sendqueue

**Files:** создать `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-baseline.md`. Кода нет.

**Constraints:** приватный `CARGO_TARGET_DIR` (`target-impl`), `CARGO_INCREMENTAL=0`; ни одного кадра, ни одного
изменения на стендах; чтение minipc и `home-pc` только командами просмотра; Python в репозиторий не попадает.

- [ ] Выписать контракты с номерами строк (проверенные места, не пересказ): `io.rs` (`SendStatus`, `Tx`, `Rx::health`),
  `engine.rs` `run_tx` 456–562 (halt перед отправкой, stall-окно, `Uncertain` → `fail`), `throttle.rs`
  `next_batch_interruptible` 125–132 (0 = «вызвать снова», рост до 10 000, отрезки сна ≤50 мс), `probe.rs`
  `ProbeCursor` 290–369, `windows/adapter.rs` `TxHalf` 74–106 и `IO_BUDGET` 51, `handle.rs` `send_raw` 289–297,
  `ffi.rs` `pcap_api!` 262–284 и `PcapPkthdr` 42–49 (16 байт), `loader.rs` `resolve` 190–203, `wire_scan.rs`
  `HarnessTx` 380–420, `windows_live.rs` `GuardTx` 155–170, `link.rs` `GuardedTx` 160–185, `verify.rs` `perf`
  2456–2600 и `perf_summary` 2861–2925.
- [ ] Записать факты Npcap API из раздела «Исходное состояние» с ссылкой на документацию Npcap (`pcap-win32-ext`,
  `types`, `packet-api`); отметить, что `PacketSendPackets` вызывает ioctl в цикле и возвращает суммарно
  переданные байты, и что доказательство границы записи при частичном возврате будет получено спайком (задача 3),
  а не из документации.
- [ ] Сверить чтением на minipc (`ssh minipc "sed -n 255,275p;820,835p $HOME/rmasscan-oracle/masscan/src/rawsock.c"`,
  дерево оракула `8e6b3b0` не меняется): как C ставит кадр в очередь, когда вызывает transmit (`flush` на конце
  пачки троттлера и при переполнении очереди), размер очереди, `sync = 0`. Записать точные строки. Если minipc
  недоступен, записать NOT RUN и ссылки спеки (`rawsock.c:261–271`, `:822–830`).
- [ ] Снять состояние стендов только чтением: `ssh home-pc 'sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab status
  --run-id n2 --manifest ~/winvm/lab/n2.json --host-only'` (rc и `raw_run_allowed`), `pgrep -af qemu` на `home-pc`
  (VM запущена или нет), `ssh -J home-pc -p 2222 lab@127.0.0.1 'ver'`, версия Npcap из `recheck-931f69f` и baseline
  (ожидается 1.90, Admin-only), `rustc --version` на госте. Записать, что потребуется действие пользователя A
  (разрешение живого окна) и, если VM/стенд не подняты, действия B.
- [ ] Выполнить на Mac: `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`,
  `cargo test --locked --workspace`, `bash scripts/language-guard.sh`; записать rc и строки `test result`.
  Записать базу: `perf-r1` медианы, потолок 6.4 kpps, Windows GO (VM), физический NIC NOT RUN, фикстуры
  переиспользуются (binding совпадает).
  Commit: `docs(net): Windows sendqueue stage baseline and contracts`.

**GREEN:** документ существует, все цифры с командами, три проверки rc 0, language guard PASS, строки C-оракула
записаны или честный NOT RUN.

## Задача 1. Пачечный контракт `Tx` в engine и core (все ОС, офлайн)

**Files:** изменить `rmasscan-engine/src/{io,engine,fake,lib}.rs`, `rmasscan-engine/tests/common/mod.rs`,
`rmasscan-core/src/probe.rs`; создать `rmasscan-engine/tests/tx_batch.rs`; изменить обёртки `Tx`:
`rmasscan-net/examples/wire_scan.rs` (`HarnessTx`), `rmasscan-net/tests/{windows_live,macos_live}.rs` (`GuardTx`,
`GuardPeerTx`), `rmasscan-lab/src/link.rs` (`GuardedTx`).

**Constraints:** core/engine без `unsafe` (`forbid`); поведение при `max_batch() == 1` побайтно равно нынешнему
(тот же порядок кадров, те же вызовы `send`, те же исходы и checkpoint); Linux и macOS адаптеры не трогаются
(используют реализацию по умолчанию); никакой очереди, переживающей вызов; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// rmasscan-engine/src/io.rs
/// Исход пачки: первые `sent` кадров приняты (как `Sent` по одному), остаток описан `rest`.
/// Инвариант: `sent == frames.len()` ⇔ `rest == SendStatus::Sent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxBatch { pub sent: usize, pub rest: SendStatus }
pub trait Tx: Send {
    fn send(&mut self, frame: &[u8], timeout: Duration) -> Result<SendStatus, IoError>;
    /// Сколько кадров адаптер принимает одним `send_batch` (≥1). По умолчанию 1.
    fn max_batch(&self) -> usize { 1 }
    /// Один вызов адаптера на префикс `frames` (≤ `max_batch()`, ≥1), не позже `timeout`.
    /// По умолчанию: цикл `send` до первого исхода, отличного от `Sent`.
    fn send_batch(&mut self, frames: &[&[u8]], timeout: Duration) -> Result<TxBatch, IoError> { /* цикл send */ }
}
// rmasscan-engine/src/engine.rs
pub const MAX_TX_BATCH: usize = 4096;   // верхняя скрепа над max_batch() любого адаптера
// rmasscan-core/src/probe.rs
impl ProbeCursor {
    /// Загружает до `n` ещё не подтверждённых probe (начиная с текущего) и отдаёт их по порядку индексов.
    pub fn preload(&mut self, n: usize) -> &[Probe];
    /// Подтверждает `k` первых загруженных probe (k ≤ загруженным); `position += k`.
    pub fn advance_sent_n(&mut self, k: usize);
}
// FakeAdapter: script_batch(steps: impl IntoIterator<Item = BatchStep>), set_max_batch(n), batch_calls(), batch_sizes()
// enum BatchStep { All, Prefix { sent: usize, rest: SendStatus }, Fail(String) }
```

`run_tx`: внутри цикла по `left` вместо одного `send`: `want = left.min(tx.max_batch().max(1)).min(MAX_TX_BATCH)`;
`probes = cursor.preload(want)`; кадры собираются в `Vec<&[u8]>`; один `send_batch`; `cursor.advance_sent_n(r.sent)`,
`shared.sent += r.sent`, `position`, `left -= r.sent`; `stall_since = None` при `r.sent > 0`; `r.rest`: `Sent` →
продолжить; `WouldBlockUnsent` → как сейчас для первого неотправленного кадра (окно stall с `attempt_start`, сон
1 мс, проверки `halt` до и после); `Uncertain` → `fail(TxUncertain)`; `Err` → `fail(TxError)`. `halt` проверяется
перед каждой пачкой (как перед каждой отправкой сейчас). `ProbeCursor` хранит `VecDeque<Probe>`; `current()` это
фронт, `advance_sent()` == `advance_sent_n(1)`; `position` растёт только в `advance_sent_n`.

Обёртки: `HarnessTx` (`wire_scan.rs`) реализует `max_batch` = внутренний и `send_batch`: если `pause_after ==
Some(sent)` — пауза и `TxBatch { sent: 0, rest: WouldBlockUnsent }` (как сейчас для `send`); иначе режет пачку до
`pause_after − sent` кадров, пробрасывает во внутренний `send_batch`, учитывает `sent`, тайминги (`first/mark/last`
по последнему кадру пачки, `last_idx`), `tid`. `GuardTx` (`windows_live.rs`, `macos_live.rs`): `assert_lab_frame`
на **каждый** кадр пачки до проброса; `uncertain_after`/`panic_at` внутри пачки режут её так же, как `pause_after`.
`GuardedTx` (`link.rs`): проверка каждого кадра, иначе `Err` без отправки всей пачки. `PauseTx` (engine tests):
проброс по тому же правилу.

- [ ] Red `probe.rs` (cfg test): `preload_then_advance_n_matches_single_steps` (индексы и байты кадров равны
  последовательности `current/advance_sent` на том же плане), `preload_is_capped_by_the_range`,
  `advance_n_beyond_loaded_is_rejected_by_debug_assert_and_saturates`, `position_moves_only_in_advance`.
- [ ] Red `tests/tx_batch.rs` (FakeAdapter с `ManualClock`): `max_batch_one_sends_the_same_frames_in_the_same_order`
  (эталон: та же последовательность `sent_frames` и `send_calls`, что у теста lifecycle до изменения),
  `batches_never_exceed_max_batch_or_the_throttle_batch`, `a_full_batch_advances_the_cursor_by_its_size_once`,
  `a_prefix_result_advances_only_the_prefix_and_fails_uncertain_without_checkpoint`,
  `a_prefix_then_would_block_retries_the_first_unsent_frame_and_opens_the_stall_window`,
  `stall_window_resets_after_any_sent_prefix`, `stop_between_batches_sends_nothing_afterwards`,
  `pause_lands_on_a_batch_boundary_and_the_checkpoint_equals_position`,
  `resume_from_a_batched_pause_continues_without_gap_or_duplicate` (сравнение с непрерывным прогоном при
  `max_batch 1` и 8), `a_batch_error_fails_tx_error_and_sends_nothing_more`, `progress_sent_equals_cursor_position`.
- [ ] Red `wire_scan.rs` (модуль тестов): `pause_after_inside_a_batch_cuts_the_batch_exactly_at_n` (внутренний
  fake с `max_batch 8`, `--pause-after 5` → внутренний видит 5 кадров, затем пауза), `harness_forwards_max_batch`.
- [ ] Реализовать io/engine/probe/fake и обёртки; существующие тесты engine (`lifecycle`, `tx_stall`,
  `bounded_memory`, pause/resume) без изменений ожиданий остаются зелёными; `cargo test --locked --workspace` на
  Mac; `cargo check -p rmasscan-net --tests --examples` на Mac собирает обёртки (Windows-обёртки собираются в CI).
  Commit: `feat(engine): batched Tx contract with exact prefix accounting`.

**GREEN:** все тесты engine/core PASS на Mac; fmt/clippy чисты; `max_batch() == 1` путь эквивалентен прежнему
(тест эталона); обёртки пробрасывают `send_batch`/`max_batch`; language guard PASS.

## Задача 2. ABI sendqueue и владеемая очередь (офлайн, fake)

**Files:** изменить `rmasscan-net/src/windows/{ffi,handle}.rs`, `src/windows/tests/fake.rs`, `src/windows/tests.rs`.

**Constraints:** `unsafe` только в `ffi`/`handle`/fake с `SAFETY`; указатели очереди не покидают `handle`; порядок
освобождения: очередь (`pcap_sendqueue_destroy`) раньше `pcap_close` своего handle, оба раньше выгрузки DLL;
символы обязательны (без тихого отката на `pcap_sendpacket`): отсутствие → `MissingCapability` с именем;
приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// ffi.rs
#[repr(C)] pub(crate) struct PcapSendQueue { pub maxlen: c_uint, pub len: c_uint, pub buffer: *mut c_char }
const _: () = assert!(size_of::<PcapSendQueue>() == 16 && align_of::<PcapSendQueue>() == 8);
const _: () = assert!(offset_of!(PcapSendQueue, len) == 4 && offset_of!(PcapSendQueue, buffer) == 8);
pub(crate) const SENDQUEUE_RECORD_HEADER: usize = size_of::<PcapPkthdr>(); // 16
pub(crate) type SendQueueAllocFn = unsafe extern "C" fn(c_uint) -> *mut PcapSendQueue;
pub(crate) type SendQueueQueueFn = unsafe extern "C" fn(*mut PcapSendQueue, *const PcapPkthdr, *const u8) -> c_int;
pub(crate) type SendQueueTransmitFn = unsafe extern "C" fn(*mut PcapT, *mut PcapSendQueue, c_int) -> c_uint;
pub(crate) type SendQueueDestroyFn = unsafe extern "C" fn(*mut PcapSendQueue);
// pcap_api! { ..., sendqueue_alloc = "pcap_sendqueue_alloc", sendqueue_queue = "pcap_sendqueue_queue",
//             sendqueue_transmit = "pcap_sendqueue_transmit", sendqueue_destroy = "pcap_sendqueue_destroy" }
// handle.rs
pub(crate) struct SendQueue { raw: NonNull<PcapSendQueue>, capacity: u32, records: Vec<u32>, api: Arc<NpcapApi> }
impl SendQueue {
    pub(crate) fn alloc(api: &Arc<NpcapApi>, bytes: u32) -> Result<SendQueue, NetError>;  // NULL → System
    pub(crate) fn push(&mut self, frame: &[u8]) -> Result<(), c_int>;   // pkthdr {ts: 0, caplen = len = frame.len()}
    pub(crate) fn queued_bytes(&self) -> u32;  pub(crate) fn record_sizes(&self) -> &[u32];  pub(crate) fn len(&self) -> usize;
    pub(crate) fn clear(&mut self);              // records.clear(); (*raw).len = 0  (публичное поле, единственный писатель pcap_sendqueue_queue)
}
impl PcapHandle { pub(crate) fn transmit_raw(&mut self, q: &mut SendQueue, sync: bool) -> c_uint; }
// Drop for SendQueue: pcap_sendqueue_destroy; unsafe impl Send (как PcapHandle), без Sync.
```

- [ ] Red `tests.rs`: `sendqueue_abi_layout_matches_the_npcap_header` (размеры/смещения, заголовок записи 16 байт),
  `missing_sendqueue_symbol_is_missing_capability_naming_it` (`pcap_sendqueue_transmit` в `missing` →
  `MissingCapability`, текст содержит имя, DLL выгружена), `required_symbols_are_unique_and_prefixed` покрывает
  четыре новых имени, `sendqueue_alloc_null_is_a_system_error`, `sendqueue_push_records_header_plus_frame_and_full_is_minus_one`
  (fake проверяет `len` после каждой записи = Σ(16 + caplen)), `clear_resets_len_and_records`,
  `sendqueue_destroy_precedes_close_and_unload` (журнал: `sendqueue_destroy` < `close:N` < `unload`),
  `transmit_returns_the_scripted_bytes_and_passes_sync_zero`.
- [ ] `fake.rs`: функции `f_sendqueue_alloc/queue/transmit/destroy` с состоянием сценария: `queues:
  Vec<(Box<PcapSendQueue>, Vec<u8>)>` (реальный буфер, `len`/`maxlen` ведутся как в libpcap), `queue_full_at:
  Option<usize>`, `transmit_script: VecDeque<TransmitStep>` (`All`, `Bytes(u32)`, `Boundary(k)` = сумма первых k
  записей, `Straddle(k)` = граница k + 7, `Over` = len + 1), `transmit_calls`, `transmitted: Vec<Vec<Vec<u8>>>`
  (кадры, разобранные из буфера очереди по заголовкам: при `Boundary(k)` в `sent` и `responder` уходят первые k),
  `sync_seen: Vec<c_int>`, журнал `sendqueue_alloc:<bytes>`, `sendqueue_transmit:<n>`, `sendqueue_destroy`.
- [ ] Реализовать `ffi`/`handle`; `cargo test --locked -p rmasscan-net` на Mac (fake-тесты Windows собираются на всех
  ОС под `test`). Commit: `feat(net): Npcap sendqueue ABI and owned send queue`.

**GREEN:** fake-тесты PASS на Mac и Linux; clippy чист; `unsafe` только в разрешённых модулях; language guard PASS.

## Задача 3. Спайк sendqueue на стенде `n2`: STOP/GO, размер пачки, частичный transmit

**Files:** изменить `rmasscan-net/src/windows/live.rs` (новые `#[ignore]` тесты), создать
`docs/experiments/2026-10-25-rmasscan-windows-sendqueue-spike.md`, `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-spike-raw/`
(`runs/<run>/`, `tools/` только `.sh`/`.ps1`, `MANIFEST.sha256`).

**Constraints:** действие пользователя A получено; стенд `n2` `raw_run_allowed: true` до и после каждого прогона
(`status-pre/post.json`); каждый кадр проходит `assert_lab_frame`; захват пира (`sudo -n ip netns exec wvp-n2
rmasscan-lab capture dump ...` или `tcpdump -i lab0 -n -U -s 96 -w peer.pcap`) и `eno1` с фильтром лаборатории в
каждом прогоне, sha256 на `home-pc` до копирования; мусор пира только `rmasscan-lab peer flood` (Rust); link down
только `rmasscan-lab peer linkloss` через QMP (инструмент suite, восстанавливает линк); приватный
`CARGO_TARGET_DIR`; гость собирает тесты из `git archive` коммита; старые экспорты удалены.

**Interfaces:** окружение как у `live.rs` (`RMASSCAN_NPCAP_LAB_DEVICE/_SRC_MAC/_PEER_MAC/_OUT_DIR/_COND`,
опционально `_START_AT/_DOWN_AT/_UP_AT`), плюс `RMASSCAN_NPCAP_SQ_SIZES` (по умолчанию `1,16,64,256,1024,4096`),
`RMASSCAN_NPCAP_SQ_ROUNDS` (по умолчанию 200). CSV длительности каждого transmit (`t_ms,n,bytes_queued,bytes_sent,dur_us`)
и KV-сводка p50/p95/p99.9/max на размер. Тесты используют `SendQueue`/`transmit_raw` задачи 2 напрямую (адаптера ещё нет).

- [ ] **`live_sendqueue_transmit_timing`.** Для каждого n из ряда: 200 transmit по n SYN на `198.18.0.2` (порты по
  кругу `1-65535`), `sync = 0`, пауза между transmit такая, чтобы средняя скорость не превышала 100k pps; записать
  p50/p95/p99.9/max и `bytes_sent == bytes_queued` в каждом вызове; захват пира: число SYN равно Σn (exactly-once
  на проводе, 0 дублей по sha256 кадра). Условия: idle; поток мусора 20k pps от пира (`peer flood --pps 20000
  --size 60 --duration 40`); сравнение n = 1 через очередь против `pcap_sendpacket` (1000 вызовов каждого).
  **Правило выбора `TX_BATCH_FRAMES`:** наибольшее n ряда, у которого в обоих условиях p99.9 ≤ 21 мс и max ≤
  42 мс (`IO_BUDGET`); если даже n = 16 не укладывается — STOP (sendqueue в бюджет контракта на этом стенде не
  входит, отдельное решение, не ослабление лимита). Записать достигнутые pps на размер (Σn / Σdur) как ожидаемый
  потолок VM.
- [ ] **`live_sendqueue_partial_boundary` (GO/STOP для точного учёта префикса).** Очередь из k = 7 корректных SYN,
  затем одна запись, которую драйвер отвергает (кандидаты по очереди: кадр 9000 байт, как в спайке 2B для
  `pcap_sendpacket` «(20)»; запись с `caplen = 0`; `caplen = 20` с `len = 60`), затем m = 5 корректных. Ожидание GO:
  `bytes_sent == Σ_{j<k}(16 + caplen_j)` точно (граница k), пир получил ровно k SYN и ни одного из m, текст
  `pcap_geterr` записан. Повторить 20 раз и при k = 0 и k = 255. STOP (вся пачка `Uncertain` в продукте), если
  `bytes_sent` не на границе, если доходят кадры после отвергнутой записи, или если ни одна запись не отвергается
  (тогда частичный путь живьём невоспроизводим: продукт остаётся на правиле «не на границе → всё Uncertain», а
  точный учёт префикса помечается NOT RUN и в отчёте не заявляется доказанным).
- [ ] **`live_sendqueue_reuse_no_leak`.** 10 000 transmit по 64 кадра через одну очередь с `clear()` между
  вызовами (без destroy/alloc), затем 1 000 с destroy/alloc на каждую пачку; `bytes_sent` всегда полный, рабочее
  множество процесса (`process_sample`) не растёт монотонно (разница < 1 МБ между 10% и 100%), пир насчитал ровно
  Σn. Если `clear()` даёт расхождения — переход на destroy/alloc (как C), записать.
- [ ] **`live_sendqueue_stop_latency`.** 60 раундов: TX-поток шлёт пачки по `TX_BATCH_FRAMES`, RX-поток крутит
  `recv` с дедлайном 42 мс; флаг стоп выставляется в случайный момент; время от флага до выхода TX ≤ один transmit
  (записать max), join обоих ≤ 1 с (ожидание max ≈ 100 мс).
- [ ] **Условие link down (необязательно, если QMP доступен оркестратору).** `peer linkloss --down-after 2.0`:
  во время down записать `bytes_sent`, длительности и rc transmit; ожидание по спайку 2B: «чёрная дыра», все байты
  «отправлены»; если transmit возвращает меньше `len`, проверить границу. Это информация для части B `linkloss`,
  не критерий GO.
- [ ] Отчёт в формате спайка 2B (таблица решений GO/STOP с цифрами, окружение и версии, изоляция на каждый
  прогон, таблица таймингов, что узнали, рекомендации задаче 4: `TX_BATCH_FRAMES`, семантика частичного transmit,
  `clear()` или destroy/alloc), сырьё с `MANIFEST.sha256` и `eno1.pcap` каждого прогона (0 кадров).
  Commit: `test(net): Npcap sendqueue timing, partial-transmit boundary and stop spike`.

**GREEN:** все пункты измерены с цифрами; решения GO/STOP записаны; `TX_BATCH_FRAMES` выбран правилом; `eno1` 0
кадров во всех прогонах; `MANIFEST.sha256` сходится; стенд после спайка `raw_run_allowed: true`.

## Задача 4. `TxHalf` на sendqueue

**Files:** изменить `rmasscan-net/src/windows/adapter.rs`, `src/windows/tests/adapter_tests.rs`, `src/lib.rs`
(`NetStats`/`Counters`, `TxMode`), `examples/wire_scan.rs` (блок `net`, `identity`), `tests/windows_live.rs`
(живые тесты).

**Constraints:** `adapter.rs` безопасный; никакой очереди, переживающей `send_batch` (после возврата `len == 0`);
`send` одного кадра по-прежнему `pcap_sendpacket` (принятый путь); частичный transmit по решению спайка; `timeout`
не применяется (transmit не отменяем, граница это `TX_BATCH_FRAMES`), но длительность измеряется; приватный
`CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// adapter.rs
pub(crate) const TX_BATCH_FRAMES: usize = /* решение спайка, предварительно 256 */;
pub(crate) const TX_QUEUE_BYTES: u32 = (TX_BATCH_FRAMES * (SENDQUEUE_RECORD_HEADER + MAX_TX_FRAME)) as u32;
/// Что драйвер принял из пачки по числу переданных байт.
pub(crate) enum Accounted { Exact(usize), Straddle }
pub(crate) fn accounted(record_sizes: &[u32], bytes_sent: u32) -> Accounted;  // чистая функция, тесты на границах
impl Tx for TxHalf {
    fn send(..)  // без изменений
    fn max_batch(&self) -> usize { TX_BATCH_FRAMES }
    fn send_batch(&mut self, frames: &[&[u8]], _timeout: Duration) -> Result<TxBatch, IoError>;
}
// lib.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum TxMode { Single, SendQueue { max_batch: usize } }
pub struct OpenedAdapter { pub io: AdapterPair, pub stats: NetStatsHandle, pub tx_mode: TxMode }
// NetStats: + tx_batches: u64 (вызовов transmit), tx_batch_max: u64 (наибольшая пачка), tx_over_budget: u64
//   (вызовов send/send_batch дольше MAX_IO_TIMEOUT = 50 мс по Instant; Linux/macOS: 0, структурно не измеряется — документировать)
```

`send_batch`: 1) `frames.is_empty()` → `IoError`; 2) `frames.len() > TX_BATCH_FRAMES` → `IoError` (нарушение
контракта вызывающего, ничего не отправлено); 3) длина каждого кадра в `MIN_TX_FRAME..=MAX_TX_FRAME` до любой
постановки, иначе `IoError` + `tx_errors`, ничего не отправлено; 4) `frames.len() == 1` → `self.send`; 5) `queue.clear()`,
`push` каждого кадра (−1 → `IoError` «sendqueue refused a frame that fits the allocated queue», `tx_errors`,
`clear`, ничего не отправлено); 6) `t = Instant::now()`, `sent = transmit_raw(queue, false)`, `dur`; `tx_batches += 1`,
`tx_batch_max = max`, `dur > MAX_IO_TIMEOUT` → `tx_over_budget += 1`; 7) `accounted(record_sizes, sent)`:
`Exact(n)` → `tx_sent += n`, `TxBatch { sent: n, rest: Sent }`; `Exact(k < n)` → `tx_sent += k`, `tx_uncertain += n − k`,
`TxBatch { sent: k, rest: Uncertain }` (если спайк дал STOP точному учёту: `tx_uncertain += n`, `TxBatch { sent: 0,
rest: Uncertain }`); `Straddle` или `sent > queued` → `tx_uncertain += n`, `TxBatch { sent: 0, rest: Uncertain }`;
8) `queue.clear()` в любом исходе (и в `Drop`). Текст `pcap_geterr` только в счётчик/лог, не в статус.
`open_with`: очередь выделяется один раз (`SendQueue::alloc(api, TX_QUEUE_BYTES)`) после TX handle и до RX; ошибка
закрывает уже открытое; `OpenedAdapter.tx_mode = SendQueue { max_batch: TX_BATCH_FRAMES }`. Linux/macOS: `TxMode::Single`.

- [ ] Red `adapter_tests.rs` (fake): `accounted_exact_boundaries_and_straddles` (таблица: 0, k, n, k+7, len+1),
  `a_full_transmit_is_sent_exactly_n_and_counts_one_batch`, `a_boundary_partial_is_prefix_sent_and_rest_uncertain_with_counts`
  (или по решению спайка `..._is_all_uncertain`), `a_straddling_partial_is_all_uncertain`,
  `bytes_over_queued_is_all_uncertain`, `one_frame_batches_use_sendpacket_not_the_queue`,
  `a_bad_length_anywhere_in_the_batch_sends_nothing_and_is_an_io_error`, `an_oversized_batch_is_refused_before_queueing`,
  `queue_full_is_an_io_error_and_nothing_was_transmitted`, `queue_is_empty_after_every_outcome`,
  `sendqueue_is_destroyed_before_the_tx_handle_closes`, `transmit_longer_than_fifty_ms_is_counted_over_budget`
  (fake со сном в `f_sendqueue_transmit`), `net_stats_batches_and_max_survive_closing`,
  `engine_scan_through_fake_sendqueue_completes_with_exactly_one_advance_per_sent` (responder на кадры из
  очереди; `sent_frames` равны плану по порядку), `engine_partial_transmit_fails_uncertain_without_checkpoint_or_more_batches`,
  `engine_stop_between_batches_sends_nothing_afterwards`, `pause_resume_through_batches_has_no_gap_or_duplicate`
  (сравнение с `max_batch 1`), `tx_mode_is_sendqueue_with_the_cap`.
- [ ] Реализовать `send_batch`, `accounted`, счётчики, `TxMode`; `wire_scan.rs`: `identity.tx_mode`
  (`"sendqueue"`/`"single"`), `identity.tx_batch_cap`, блок `net` с `tx_batches`, `tx_batch_max`,
  `tx_over_budget`; `--inventory` без изменений (очередь не выделяется).
- [ ] `tests/windows_live.rs` (`#[ignore]`, через `open_explicit` + `Engine`, `GuardTx` на каждый кадр):
  `live_batched_scan_counts_exactly_once_on_the_wire` (65535 портов на 100k pps: `tx_sent` == SYN у пира, 0 дублей,
  `tx_batches > 0`, `tx_over_budget == 0`), `live_batched_stop_is_prompt_and_nothing_is_sent_afterwards`,
  `live_batched_pause_resume_has_no_gap_or_duplicate`, `live_call_latency_under_batches` (максимум на тип вызова
  `send_batch`/`recv`/`health` ≤ 50 мс в KV `max_per_call`, как `macos_live`). Запуск оператором на госте в
  окне задачи 6.
- [ ] fmt, clippy, `cargo deny check bans licenses sources`, `cargo test --locked --workspace` на Mac; Windows-сборка
  подтверждается CI после push и гостевым `cargo test -p rmasscan-net` в задаче 6.
  Commit: `feat(net): batched Windows TX through the Npcap sendqueue`.

**GREEN:** fake-тесты PASS на Mac/Linux (и Windows в CI); `tx_mode` в JSON harness; `unsafe` не добавлен вне
`handle`/`ffi`; language guard PASS.

## Задача 5. Лаборатория: suite, verifier, документы

**Files:** изменить `rmasscan-lab/src/{windows_suite,verify}.rs`, `src/{windows_suite_tests,verify_perf_tests,verify_tests}.rs`,
`rmasscan/docs/rust-lab.md`, `rmasscan/docs/windows-wire-lab.md`.

**Constraints:** `#![forbid(unsafe_code)]`; команды массивами; тесты верификатора на синтетических и мутированных
каталогах без сети; статусы никогда не повышаются; существующие каталоги evidence (`perf-r1` и прочие) обязаны
давать прежние вердикты (регрессия на закоммиченном архиве); приватный `CARGO_TARGET_DIR`.

**Interfaces:** `windows-suite` получает в `manifest.json` поле `tx_mode_expected: "sendqueue"` (значение из
`--tx-mode sendqueue|single`, по умолчанию `sendqueue`; опция добавляется в `WINDOWS_SUITE_OPTIONS`). `windows-verify`
для каждого прогона: (а) `identity.tx_mode` присутствует и равен `tx_mode_expected` манифеста (отсутствие поля в
новом каталоге — FAIL «harness predates sendqueue»; старые каталоги без `tx_mode_expected` в манифесте — без
проверки); (б) `net.tx_over_budget == 0` — иначе FAIL «call budget breached» (safety-класс не нужен, это
behaviour); (в) для ячеек `perf.<rate>` с `rate ≥ 10000` при `tx_mode == "sendqueue"`: `net.tx_batches > 0` и
`net.tx_batch_max ≤ identity.tx_batch_cap`, иначе FAIL «sendqueue claimed but no batch was transmitted»;
(г) `notes.perf` дополняется `tx_batches`, `tx_batch_max`, `tx_batch_cap`, `tx_over_budget`; `perf_summary.rows[].median`
дополняется `tx_batch_max`. Текст заметки `perf_summary` «may stay OPEN until 2B-sendqueue» заменяется на «VM
ceiling with sendqueue is an OPEN finding for the physical NIC stage, never a FAIL» (тест
`summary_notes_name_the_latency_sources_and_the_gate_caveat` обновляется осознанно). Правила `tx_sent` == SYN на
проводе, порядок == фикстура, exactly-once и остальные не меняются.

- [ ] Red `verify_perf_tests.rs`/`verify_tests.rs`: `missing_tx_mode_in_a_sendqueue_directory_is_fail_not_pass`,
  `tx_mode_mismatch_is_fail`, `over_budget_calls_fail_the_run`, `a_fast_cell_without_batches_under_sendqueue_is_fail`,
  `batch_max_above_cap_is_fail`, `legacy_directories_without_tx_mode_expected_are_unchanged` (прогон `windows-verify`
  по `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/perf-r1` и `failure-r1` даёт те же `overall`,
  счётчики и `rate_gate`, что закоммиченные `verdict.json`; тест читает каталоги репозитория, pcap в `perf-r1`
  лежат как `peer.pcap.gz` — тест ограничивается `verdict`-сверкой полей, не требующих pcap, либо помечает
  NOT RUN с причиной; **gzip не распаковывать в репозиторий**), `perf_notes_carry_batch_fields`.
- [ ] Red `windows_suite_tests.rs`: `tx_mode_option_is_validated_and_recorded_in_the_manifest`,
  `options_list_includes_tx_mode` (как `options_for`).
- [ ] Реализовать; `rust-lab.md`: раздел «Part C with sendqueue» (команды `perf-r2`, новые проверки, поля JSON,
  правило GO VM), обновить строку о `2B-sendqueue`; `windows-wire-lab.md`: абзац об адаптере (sendqueue, пачка,
  бюджет, частичный transmit). Commit: `feat(lab): sendqueue evidence fields and verifier rules for part C`.

**GREEN:** `cargo test --locked -p rmasscan-lab` PASS на Mac и Linux; `windows-verify` на закоммиченных каталогах
воспроизводит прежние вердикты; документация обновлена; language guard PASS.

## Задача 6. Живая приёмка на VM: части A, B, C и Linux-регрессия

**Files:** `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance-raw/{smoke-<sha>,functional-r3,failure-r2,perf-r2,linux-functional-r1,verification}`
(каждый каталог suite с `manifest.json`, `fixtures/`, `runs/`, `runs_discarded/`, `deploy/`, `verdict.json`, `README.md`,
`MANIFEST.sha256`).

**Constraints:** выполняет живой оператор в приватном `$SCRATCH/live-sq/target` по процедуре `rust-lab.md`
(«Deployment for the live Windows rerun», шаги 1–9): один закреплённый коммит, сборка из `git archive` на `home-pc`
и на госте (`RMASSCAN_SOURCE_COMMIT`, `RUSTFLAGS='-C target-feature=+crt-static -C link-arg=/DEPENDENTLOADFLAG:0x800'`,
`dumpbin /loadconfig` → `0x800` записан), `deploy-manifest` перезаписан под коммит, `git_dirty=false`; старые
`~/winvm/build/<sha>` и `C:\Users\lab\src\rmasscan-<sha>` удалены; pcap без сжатия; `--rerun` только с записью
причины; никакого `sudo` вне `sudo -n` команд suite; личные пути в текстах → `$HOME`/`$REPO`.

- [ ] **Смоук** `smoke-<sha>`: `--plan functional --only c01_one_addr_port_synack.run1` и `--plan perf --only perf.100.r1`
  (каждый в своём каталоге; overall NOT RUN by design), плюс гостевой `cargo test --locked -p rmasscan-net` и
  `cargo test --locked -p rmasscan-net --test windows_live -- --ignored` с окружением стенда (4 живых теста задачи 4,
  KV `max_per_call` в `verification/`).
- [ ] **Часть A** `functional-r3` (`--plan functional`, 24 прогона → 29 пунктов PASS): байты и порядок SYN равны
  фикстуре без нормализации; pause-группы N=0/1/8/15 равны continuous и C; `refuse_completed` без SYN;
  `identity.tx_mode == "sendqueue"` в каждом `run.json`.
- [ ] **Часть B** `failure-r2` (`--plan failure`, 18 прогонов): `stop_*` 4 PASS (`stop_to_outcome_ms < 1000`, 0 SYN после
  исхода; записать максимум — он теперь включает один transmit), `linkloss` (TxUncertain без checkpoint; при
  частичном transmit — префикс учтён, `tx_uncertain > 0`; записать `bytes_sent`-поведение), `overflow_queue`,
  `rxloss`, `ckpt_*` ×8, `perm_*` ×3 (exit 5 / 5 / 0).
- [ ] **Часть C** `perf-r2` (`--plan perf`, 20 ячеек rep-major): таблица медиан по скоростям (`steady_pps_wire`,
  in-process, CPU, peak WS, join, drain, `tx_batch_max`), `rate_gate` по ячейкам, `tx_over_budget == 0` везде,
  kernel drops; INVALID-ячейки с причиной; gate не ослабляется. Ожидание: MET на 100/1k/10k; 100k — MET или OPEN
  с измеренным потолком VM (честно, как есть).
- [ ] **Linux-регрессия engine** `linux-functional-r1`: на minipc (`sudo -n` оператора) `scripts/wire-lab.sh --suite rust`
  функциональный набор по процедуре Linux-приёмки (`docs/experiments/2026-10-23-rmasscan-stage2b-linux.md`,
  `rust-lab.md`), тот же коммит, бинарь из `git archive`: 141 проверок PASS, `tx_mode == "single"`. Это проверка,
  что пачечный engine не изменил поведения адаптера с `max_batch 1`. macOS: только офлайн (`cargo test --locked
  --workspace` на Mac); живой smoke `macos_live` — необязательное действие пользователя C.
- [ ] `eno1`: 0 кадров лаборатории во **всех** прогонах (суммарно в README каждого каталога); `status-pre/post`
  `raw_run_allowed: true`; `verdict.json` от `windows-verify`; `MANIFEST.sha256` (`shasum -a 256`) на каталог;
  `verification/`: гостевые `clippy`/`cargo test --workspace` логи, Mac и minipc логи, `dumpbin` вывод, KV живых тестов.
  Commit: `test(net): record Windows sendqueue wire, failure and performance acceptance`.

**GREEN:** `windows-verify` overall PASS для `functional-r3` и `failure-r2`; `perf-r2` overall PASS (ячейки PASS,
INVALID честно записаны) с `rate_gate` по скоростям; Linux-регрессия PASS; `eno1` 0 кадров; хэши сходятся;
`tx_over_budget` 0 во всех прогонах.

## Задача 7. Отчёт, readiness, CI и итоговое ревью

**Files:** создать `docs/experiments/2026-10-25-rmasscan-windows-sendqueue-acceptance.md`; изменить
`docs/experiments/2026-10-24-rmasscan-readiness.md`, `.github/workflows/rmasscan.yml` (комментарий),
`docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance.md` (только сноска: throughput см. новый отчёт),
`rmasscan/README.md` (если описывает TX-путь).

**Constraints:** статусы PASS/FAIL/INVALID/NOT RUN/OPEN не повышаются; GO только при зелёном CI на точном HEAD;
VM-потолок остаётся OPEN для физического NIC и не маскируется; Python в репозиторий не попадает.

- [ ] Отчёт по образцу приёмки Windows VM: §1 итог и границы (единый список условий GO «Windows throughput (VM)»),
  §2 коммиты и чистота дерева, §3 хэши (оркестратор, бинарь `home-pc`, `wire_scan.exe`, tar), §4 топология, §5 версии
  (Npcap, `TX_BATCH_FRAMES`, `IO_BUDGET`), §6 результаты A/B/C с таблицей `perf-r2` против `perf-r1` (строка на
  скорость: wire pps до/после, gate до/после, `tx_batch_max`, CPU), спайк и живые тесты, §7 хэширование и полнота,
  §9 ошибки и ограничения (VM e1000e не физический NIC; transmit не отменяем, граница по размеру пачки — измерена,
  не доказана как граница на физическом NIC; частичный transmit доказан/не доказан по спайку; 100k OPEN если так;
  Linux/macOS: `max_batch 1`, живая проверка macOS NOT RUN, если действие C не выполнялось), §10 ревью, §12 CI, §13 заявление.
- [ ] Readiness: строка «Windows throughput» делится на «Windows throughput (VM)» со статусом по критерию GO ниже и
  «Windows throughput (physical NIC)» **NOT RUN/OPEN**; строка «Windows correctness (VM)» получает пометку
  «перепроверена на sendqueue-коде `<sha>`: A/B PASS».
- [ ] Workspace-тесты на трёх ОС перед push (Mac, minipc, гость) с логами в `verification/`; push; CI зелёный на
  точном HEAD; удаление приватных target-каталогов и старых экспортов записано.
- [ ] Итоговое Opus-ревью ветки (engine пачки и учёт, `unsafe`/lifetimes очереди, лаборатория, evidence);
  исправления; живая перепроверка изменённых путей на исправленном коммите (минимум `c01`, `stop_load`, `perf.10000.r1`),
  если менялся `rmasscan-net`/`engine`/`core`; если менялась только лаборатория или документы — пересчёт архива
  исправленным верификатором с неизменными вердиктами.
  Commit: `docs(net): Windows sendqueue acceptance report and readiness`.

**GREEN:** отчёт существует с единым списком условий; readiness обновлён; CI зелёный на HEAD; ревью APPROVED.

## GO и дальнейшая очередь

**GO «Windows throughput (VM)»:** код принят ревью; CI зелёный на точном HEAD на трёх ОС; на запечатанном стенде
`n2` на одном закреплённом коммите части A (29 PASS), B (все пункты PASS) и C (20 ячеек, честные `rate_gate`)
пройдены; `rate_gate` **MET на 100, 1000 и 10000 pps**; 100 000 pps измерен и записан (MET, либо OPEN с потолком
VM и достигнутыми pps); `tx_over_budget` 0 во всех прогонах; Stop ≤1 с (измерено в `stop_*`); байты и порядок
SYN равны C-оракулу; `tx_sent` равен SYN на проводе, дублей нет; `kernel_drops` честный `Some(n)`; нет ложного
checkpoint, утечек handle и потоков; `eno1` 0 кадров; Linux-регрессия PASS; версии и ограничения зафиксированы.
**GO не распространяется** на физический NIC Windows (throughput и correctness на нём остаются NOT RUN/OPEN),
другие версии Npcap, Wi-Fi, macOS/Linux throughput, discovery/ARP, runner/IPC, UI. Потолок VM, оставшийся на
100k, это OPEN-запись для этапа физического NIC, не причина откладывать GO (VM) и не FAIL.

Далее: **физический стенд Windows (NIC, Npcap, тот же suite) → Linux `PACKET_TX_RING`/macOS пачки `write` по
необходимости → discovery/ARP и сеть/VPN/sleep → сессионный runner + IPC + durable checkpoint ACK → настоящий
Scan из Slint**.

## Решения этого плана (с причиной и ценой ошибки)

1. **Пачечный контракт как расширение `Tx` (`send_batch` + `max_batch`, по умолчанию цикл `send`), engine режет
   пачку `Throttler` по `max_batch()` и `MAX_TX_BATCH`, курсор получает `preload/advance_sent_n`.** Причина: Linux и
   macOS адаптеры не меняются и ведут себя побайтно так же; `Sent` означает ровно то, что принял драйвер в этом же
   вызове, скрытой буферизации нет; один код-путь engine. Отвергнуто: буферизация внутри `TxHalf::send` с
   отложенным transmit (нарушает exactly-once, Stop теряет или досылает кадры) и обязательный `send_batch` у всех
   реализаций (большой diff без выгоды). Цена ошибки: обёртка без проброса тихо возвращает одиночный путь —
   закрывается полем `identity.tx_mode`, счётчиком `tx_batches` и правилом верификатора (задача 5).
2. **Размер пачки — константа `TX_BATCH_FRAMES`, выбранная спайком** (наибольшее n из 16/64/256/1024/4096 с
   p99.9 ≤ 21 мс и max ≤ 42 мс idle и под мусором), байты очереди `n × (16 + 1518)`; адаптации во время работы нет —
   скорость задаёт `Throttler` (пачка 1…10 000 как в C), а пачка лишь верхняя граница одного вызова. Причина:
   контракт ≤50 мс держится на границе, которую можно измерить и записать, как `IO_BUDGET` 42 мс; адаптивный
   размер это механизм без требования. Цена ошибки: слишком мало — потолок VM ниже 100k (честный OPEN); слишком
   много — превышение бюджета видно в `tx_over_budget` и это FAIL приёмки, константа пересматривается по данным.
3. **Пейсинг: троттлер без изменений, один transmit на engine-пачку (≤ `TX_BATCH_FRAMES`), `sync = 0`.** Причина:
   паритет с C (`flush` на конце пачки троттлера), метки времени в драйвере (`sync = 1`) это неотменяемое ожидание
   внутри ядра, которое нельзя ограничить бюджетом вызова. Цена ошибки: всплески до `TX_BATCH_FRAMES` кадров на
   низких скоростях (как у C); gate ±20% считается по стационарной скорости и не страдает; если спайк покажет
   нестабильность скорости из-за всплесков, пачка уменьшается, не меняется троттлер.
4. **Частичный transmit: префикс до границы записи это `Sent`, остаток `Uncertain` → `Failed(TxUncertain)`;
   не на границе или больше очереди — вся пачка `Uncertain`; остаток не повторяется.** Причина: `bytes_sent`
   это документированный счёт принятых драйвером байт, граница записи проверяема (`16 + caplen`), и так `tx_sent`
   остаётся точным; повтор остатка требовал бы доказать «точно не отправлено» для первой отвергнутой записи,
   чего документация не даёт, а ошибочный повтор дал бы дубль на проводе. Условие: GO спайка
   `live_sendqueue_partial_boundary`; при STOP вся пачка `Uncertain` (как сегодня rc ≠ 0). Цена ошибки: при
   неверной границе `tx_sent` завысит/занизит счёт — ловится правилом `tx_sent == SYN на проводе` в `linkloss`
   и в любом прогоне с частичным transmit.
5. **Stop/Pause с очередью в полёте: `halt` перед каждой пачкой; transmit не отменяем, поэтому задержка Stop ≤ один
   transmit (≤42 мс по пачке) + отрезок сна троттлера ≤50 мс; пауза на границе пачки, `--pause-after N` харнесса
   режет пачку ровно на N.** Причина: контракт ≤1 с выполняется запасом; точная пауза нужна функциональным
   группам N=0/1/8/15. Цена ошибки: если transmit на стенде длится дольше измеренного, это видно в `stop_*`
   (`stop_to_outcome_ms`) и `tx_over_budget`.
6. **Символы `pcap_sendqueue_*` обязательны (`MissingCapability` при отсутствии), тихого отката на `pcap_sendpacket`
   нет; пачка из одного кадра идёт через `pcap_sendpacket` (принятый путь).** Причина: все Npcap/WinPcap экспортируют
   их, откат скрыл бы деградацию; одиночный путь уже доказан частями A–C. Цена ошибки: экзотическая wpcap без
   sendqueue не откроется — честная ошибка с именем символа.
7. **Очередь выделяется один раз на `TxHalf`, между пачками `len = 0` (публичное поле структуры), destroy в `Drop`
   раньше `pcap_close`; при аномалии в спайке `live_sendqueue_reuse_no_leak` — destroy/alloc на пачку, как C.**
   Причина: без аллокаций на пачку; единственный писатель буфера это `pcap_sendqueue_queue`, читающий только
   `len`/`maxlen`. Цена ошибки: утечка или порча — видна в спайке (рабочее множество, счёт пира).
8. **Часть C: те же 20 ячеек (`--plan perf`, rep-major), новый каталог `perf-r2`, то же правило MET (±20% по
   медиане ≥3 Completed PASS ячеек); GO «throughput (VM)» требует MET на 100/1k/10k и честную запись 100k;
   физический стенд для этого GO не нужен и остаётся отдельной строкой NOT RUN/OPEN.** Причина: сопоставимость с
   `perf-r1` строка в строку; VM e1000e не целевое железо, его потолок не доказательство провала продукта, но и не
   скрывается. Цена ошибки: если пользователь считает 100k обязательным на VM — критерий ужесточается до старта
   части C (открытый вопрос 1), статусы не меняются.
9. **Полные повторы частей A и B на новом коде обязательны, фикстуры C переиспользуются, Linux-регрессия
   функционального набора на minipc обязательна, macOS только офлайн (живой smoke — по желанию пользователя).**
   Причина: изменился engine и TX-путь Windows; доказательства корректности с прежнего пути на новый не переносятся;
   binding не изменился, поэтому оракул не переснимается; Linux проверяет путь `max_batch 1` вживую без
   привилегированных действий пользователя. Цена: около 4 часов стенда VM и ~20 минут minipc.
10. **Доказательства в JSON: `net.tx_batches`, `tx_batch_max`, `tx_over_budget`, `identity.tx_mode`, `tx_batch_cap`;
    верификатор FAIL-ит превышение бюджета и «sendqueue без пачек» на ≥10k.** Причина: иначе выигрыш и бюджет
    нельзя отличить от прежнего пути по evidence. Цена ошибки: три счётчика и два поля; старые каталоги не
    трогаются (правила применяются только при `tx_mode_expected` в манифесте).

## Действия пользователя (точные команды, когда, отмена)

Все команды выполняет пользователь (или живой оператор с явного разрешения пользователя, где отмечено «оператор»).
`$LAB` на Mac это `rmasscan/target/release/rmasscan-lab` ветки; на `home-pc` `~/winvm/lab/bin/rmasscan-lab`
(переустанавливается оператором на коммит приёмки по `rust-lab.md`, шаг 3).

| № | Когда | Команда | Что меняет | Отмена |
| --- | --- | --- | --- | --- |
| A | перед задачей 3 и перед задачей 6 | сообщение «живое окно на стенде n2 разрешено» (команды нет) | разрешает оператору raw-прогоны только на `n2`, только на `198.18.0.2` | сообщение «стоп»: оператор прерывает suite (Ctrl-C, код 130/10/13), стенд остаётся запечатанным |
| B1 (если VM не запущена; оператор) | перед задачей 3 | `ssh home-pc 'cd ~/winvm && nohup ./run.sh >/dev/null 2>&1 &'` затем `ssh -J home-pc -p 2222 lab@127.0.0.1 ver` | запускает QEMU Win11 с `lab.env` (lab NIC подключён холодно) | `ssh -J home-pc -p 2222 lab@127.0.0.1 'shutdown /s /t 0'` |
| B2 (если стенд `n2` не поднят; оператор) | перед задачей 3 | `ssh home-pc 'sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab up --run-id n2 --manifest ~/winvm/lab/n2.json --lab-env ~/winvm/lab.env'`, затем перезапуск VM по B1 (новый TAP требует перезапуска), затем `record-guest` по `windows-vm-lab.md` | мост/TAP/netns `n2` без uplink; `lab.env`; ничего на `eno1`, маршрутах, DNS, firewall | `ssh home-pc 'sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab down --run-id n2 --manifest ~/winvm/lab/n2.json'` |
| C (необязательно) | после задачи 6, живой smoke macOS на `feth` | `sudo $LAB macos-lab up --run-id m1 --manifest $HOME/.rmasscan-lab/macos-m1.json`; `sudo $LAB macos-lab bpf-access --grant --manifest $HOME/.rmasscan-lab/macos-m1.json`; оператор: `cargo test --locked -p rmasscan-net --test macos_live -- --ignored` с `RMASSCAN_BPF_LAB_MANIFEST`/`RMASSCAN_BPF_OUT_DIR`; затем `sudo $LAB macos-lab bpf-access --revoke --manifest ...` | пара `feth4201/4202`, права `/dev/bpf0..15` на сессию | `sudo $LAB macos-lab down --manifest $HOME/.rmasscan-lab/macos-m1.json` (или перезагрузка) |
| D | задача 6, Linux-регрессия | подтвердить, что у оператора на minipc работает `ssh minipc 'sudo -n true'`; иначе выполнить `scripts/wire-lab.sh --suite rust --out <dir>` на minipc самостоятельно по `rust-lab.md` | netns/veth стенда `wire-lab.sh` на время прогона | скрипт удаляет свои netns; `ip netns list \| grep wl-` пуст |
| E | после задачи 7 | слияние PR ветки `feat/rmasscan-stage2b-sendqueue` в `main` после зелёного CI (решение пользователя) | `main` | `git revert -m 1 <merge sha>` |

Постоянных изменений на хостах план не делает: стенд `n2` и `feth` это сессионные объекты с явным `down`; Npcap,
маршруты, DNS, firewall, NIC не меняются.

## Источники и самопроверка

- Документация Npcap (прочитана 2026-10-25 через Context7 `/nmap/npcap`): `pcap-win32-ext` (`pcap_sendqueue_queue`
  0/−1, `pcap_sendqueue_transmit` возвращает отправленные байты, `sync`), `types` (`struct pcap_send_queue`),
  `packet-api` (`PacketSendPackets`, `BIOCSENDPACKETSNOSYNC/SYNC`), `npf-driver` (таблица ioctl).
- Спека порта: §4.5 (троттлер и пачка, строки 273–287), §5.2/5.3 (sendqueue для > 40 kpps, строки 378, 409),
  §7.6 (с/без sendqueue, строка 533), этап 5 (строка 612), риск (строка 706). Контракты engine: cross-platform
  спека §0.1 (строки 77–108).
- Код: `rmasscan-engine/src/{io,engine}.rs`, `rmasscan-core/src/{throttle,probe}.rs`,
  `rmasscan-net/src/windows/{ffi,handle,loader,adapter,live}.rs`, `src/windows/tests/{fake,adapter_tests}.rs`,
  `examples/wire_scan.rs`, `tests/windows_live.rs`, `rmasscan-lab/src/{windows_suite,verify,link,provenance}.rs`,
  `rmasscan/docs/{rust-lab,windows-vm-lab,windows-wire-lab}.md`, `scripts/package-windows-wire.ps1`, `.cargo/config.toml`.
- Evidence: `2026-10-24-rmasscan-windows-vm-acceptance-raw/perf-r1/README.md` (медианы, провенанс, сборка гостя
  `build-guest.ps1`), спайк 2B (`pcap_sendpacket` p50 113–227 мкс, `IO_BUDGET` 42 мс, 60 раундов Stop), приёмка macOS
  §9 (уроки: верхняя граница `send` измеряется, не доказывается; приватные target-каталоги; pcap без сжатия).
- C-оракул `8e6b3b0`: `src/rawsock.c` на minipc (`rawsock_send_packet`/`rawsock_flush`, спека `:261–271`, `:822–830`);
  в этом репозитории C-кода нет, сверка чтением в задаче 0.
- Review Focus 1→1/4/6; 2→3/4/6; 3→3/4/5; 4→1/5; 5→5/6/7. Публичный API сохранён (`open_explicit`,
  `OpenedAdapter` расширен полем `tx_mode`, `NetStats` тремя полями, `Tx` двумя методами с реализацией по
  умолчанию). Все привилегированные и стендовые действия вынесены в таблицу с отменой; живые испытания
  отделены от CI; каждая задача несёт приватный `CARGO_TARGET_DIR` и запрет Python в репозитории.

## Исполнение (2026-10-26)

Тело плана выше не переписано. Решения контролёра в ходе исполнения, изменившие его:

- Ветка: фактическая `feat/rmasscan-windows-sendqueue`, не `feat/rmasscan-stage2b-sendqueue`.
- Задача 4 выполнена до задачи 3 с временными константами (`TX_BATCH_FRAMES` 256, переключатель учёта префикса), пока ждалось разрешение на живое окно; после спайка константы исправлены.
- Спайк: учёт префикса при частичном transmit **STOP** (драйвер возвращает 0 при частично доставленной пачке), поэтому `PREFIX_ACCOUNTING` и ветка префикса удалены: любой `bytes_sent`, не равный объёму очереди, делает всю пачку `Uncertain` (решение 4 в части «GO спайка обязателен, иначе вся пачка»).
- `TX_BATCH_FRAMES` = 64 по правилу ряда 16/64/256/1024/4096 (256 не прошёл устойчиво на двух режимах скорости VM), не 256.
- Опция `--rate-override` и каталог `functional-batched-r1` добавлены в раунде исправлений задачи 5 и сняты: функциональные случаи содержат не больше 16 проб (пачка не формируется), порядок проб masscan зависит от скорости. Пачечный путь проверяется иначе: порядок SYN на проводе равен плану (`ProbeCursor`) в ячейках `perf` (верификатор `bbda664`), плюс `windows_live`.
- Действие C (macOS) снято; B1/B2 не понадобились (стенд был поднят).
