# rmasscan: Windows sendqueue, база и контракты (задача 0)

Дата 2026-10-25. База: ветка `feat/rmasscan-windows-sendqueue`, HEAD `ce37b9c4a9157c08924f70acf3ca98542bc0e08a`
(`main` baa5cc7 + исправления лаборатории). Кода нет; на стендах ничего не менялось, кадров не отправлялось.
Номера строк сняты с чистого `git archive HEAD` (экспорт удалён после проверки), поэтому не зависят от параллельных правок.

## 1. Контракты с номерами строк (HEAD ce37b9c)

| Место | Строки | Что зафиксировано |
| --- | --- | --- |
| `rmasscan-engine/src/io.rs` `SendStatus` | 24-34 | `Sent` двигает курсор; `WouldBlockUnsent` кадр точно не ушёл; `Uncertain` исход неизвестен, `Failed`, без checkpoint и повтора |
| `io.rs` `trait Tx` | 36-38 | единственный метод `send(&mut self, frame, timeout)`; пачечного метода нет |
| `io.rs` `trait Rx` / `health` | 51-58 | `RxHealth.kernel_drops: Option<u64>`, `None` никогда не ноль |
| `engine.rs` `run_tx` | 456-562 | `halted()` перед каждой отправкой и перед пачкой; окно TX-stall от первой неудачной попытки кадра, сброс только после `Sent`; `Sent` -> `cursor.advance_sent()`; `WouldBlockUnsent` -> stall-окно; `Uncertain` -> `shared.fail(TxUncertain)` |
| `rmasscan-core/src/throttle.rs` `next_batch_interruptible` | 125-132 | отменяемый вариант; 0 означает «вызвать снова»; `batch_size` ограничен 10000 (строки 198-199); сон режется на отрезки `MAX_SLEEP_CHUNK_MICROS` = 50 000 (строка 14) |
| `rmasscan-core/src/probe.rs` `ProbeCursor` | 290-369 | `current()` (351) не продвигает, `advance_sent()` (358) подтверждает ровно один кадр |
| `rmasscan-net/src/windows/adapter.rs` `IO_BUDGET` | 51 | 42 мс |
| `adapter.rs` `TxHalf` | 74-106 | один синхронный `pcap_sendpacket` на кадр; rc 0 -> `Sent`, иначе `Uncertain`; длина вне `MIN_TX_FRAME..=MAX_TX_FRAME` -> `IoError` до вызова драйвера |
| `windows/handle.rs` `send_raw` | 289-297 | сырой rc `pcap_sendpacket`; длина > `i32::MAX` -> -1 без вызова |
| `windows/ffi.rs` `PcapPkthdr` | 42-49 | `ts: Timeval`, `caplen: u32`, `len: u32` (16 байт на Windows, по плану) |
| `ffi.rs` таблица `pcap_api!` | 262-284 | `pcap_sendqueue_*` в таблице нет (`sendpacket` на 274, `geterr` на 276) |
| `windows/ffi.rs` `PcapFns::resolve` (макрос) / вызов в `loader.rs` | ffi 229; loader 190-203 | недостающий экспорт даёт `MissingCapability` со списком; таблица обязательных символов `REQUIRED_SYMBOLS` |
| `examples/wire_scan.rs` `HarnessTx` | 381-420 (impl `Tx` на 391) | обёртка, `send` возвращает `WouldBlockUnsent` по сценарию паузы; обязана пробрасывать пачечный метод |
| `tests/windows_live.rs` `GuardTx` | 144-170 (impl на 155) | обёртка живых тестов |
| `rmasscan-lab/src/link.rs` `GuardedTx` | 163-185 (impl на 167) | отказывает кадру вне `injection_allowed`, считает `refused` |
| `rmasscan-lab/src/verify.rs` `PERF_RATES`/`PERF_REPS` | 223-224 | `[100, 1000, 10000, 100000]`, 5 повторов |
| `verify.rs` `perf` / `perf_summary` | 2456 / 2861 | gate строка 2861 и далее; `rate_gate` MET/OPEN, `overall` не меняет |

Отличие от плана: `ffi.rs` `PcapFns::resolve` находится в строках 229+ (макрос), а `loader.rs` 190-203 это его вызов.
`IO_BUDGET` и `MAX_IO_TIMEOUT` (50 мс) см. `adapter.rs` 51 и `engine`/`io` соответственно.

## 2. Факты Npcap API (документация, не измерение)

Источник: документация Npcap (`pcap-win32-ext`, `types`, `packet-api`, `npf-driver`), прочитана 2026-10-25 через Context7 `/nmap/npcap`.
- `struct pcap_send_queue { u_int maxlen; u_int len; char *buffer; }`.
- `pcap_sendqueue_alloc(u_int memsize)`, `pcap_sendqueue_queue(queue, const pcap_pkthdr*, const u_char*)`: 0 успех, -1 «очередь полна»;
  запись в буфере = `pcap_pkthdr` (16 байт) + `caplen` байт.
- `pcap_sendqueue_transmit(p, queue, sync)` возвращает число отправленных байт; меньше `queue->len` при ошибке (`pcap_geterr`).
  `sync = 0` отправляет как можно быстрее; `sync != 0` выдерживает метки времени в драйвере.
- `PacketSendPackets` вызывает ioctl `BIOCSENDPACKETSNOSYNC` (при `sync = 0`), вызов синхронный и не отменяемый,
  возвращает суммарно переданные байты.
- `pcap_sendqueue_destroy(queue)`.
- НЕ доказано документацией: что при частичном возврате число байт ложится на границу записи `16 + caplen`. Это доказывает спайк (задача 3) живым захватом пира; до него вся пачка при частичном возврате считается `Uncertain`.

## 3. Сверка с C-оракулом `8e6b3b0` (прочитано на minipc)

Команды (только чтение, дерево не менялось):
`ssh minipc 'sed -n 255,275p $HOME/rmasscan-oracle/masscan/src/rawsock.c'`, `... sed -n 820,835p ...`, `... sed -n 300,335p ...`,
`... sed -n 450,458p / 484,492p $HOME/rmasscan-oracle/masscan/src/main.c`, `... grep -n -E "sendq|SENDQ" ... rawsock.c`,
`cd $HOME/rmasscan-oracle/masscan && git rev-parse HEAD` -> `8e6b3b0c07a81e8ea61d557c06134a21a6881614`.

Строки `src/rawsock.c`:
- 49: `#define SENDQ_SIZE 65536 * 8` (524 288 байт; без скобок, но при `alloc(SENDQ_SIZE)` раскрывается верно).
- 261-271 `rawsock_flush`: `if (adapter->sendq)`: `sendqueue_transmit(pcap, sendq, 0)` (строка 264, **sync = 0**; результат (число байт) не проверяется), затем `sendqueue_destroy` (268) и `sendqueue_alloc(SENDQ_SIZE)` (269).
- 313-329 WINDOWS PCAP в `rawsock_send_packet`: `hdr.len = hdr.caplen = length` (`hdr.ts` не инициализирован); `sendqueue_queue` (319); при ненулевом коде (очередь полна) -> `rawsock_flush` (321) и повторная постановка того же кадра (322, результат не проверяется); если `flush` -> `rawsock_flush` (325-327); всегда `return 0`.
- 820-826: `adapter->sendq = 0`; только `#if defined(WIN32)` и `is_sendq`: `sendqueue_alloc(SENDQ_SIZE)`. Комментарий 820-821: sendqueue до примерно 300 kpps.
- 538-540: `sendqueue_destroy` при закрытии.
Строки `src/main.c`: 457 `rawsock_flush(adapter)` в конце TX-потока; 490 `rawsock_flush(adapter)` после `stack_flush_packets` в потоке приёма/ответов (перед `pixie_usleep(100)`).

Выводы для порта: C шлёт очередь в порядке постановки; flush при переполнении (524 288 байт) и в конце пачки троттлера; sync = 0; возврат transmit в C игнорируется (порт обязан его использовать для `Sent`/`Uncertain`, это сознательное отличие, а не паритет). Ссылки спеки `rawsock.c:261-271` и `:822-830` подтверждены (822-830 в оракуле: 820-826 плюс хвост функции).

## 4. Состояние стендов (только чтение, 2026-10-25 около 22:00 по часам Mac)

| Проверка | Команда | Результат |
| --- | --- | --- |
| статус стенда | `ssh home-pc 'sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab status --run-id n2 --manifest ~/winvm/lab/n2.json --host-only'` | rc 0; `ok: true`, `state: "up"`, `raw_run_allowed: true`, `host_ok: true`, `isolation_violations: []`; объекты `wvb-n2`, `wvh-n2`, `wvp-n2`, `wvt-n2` «present, owned»; `vm`: `attached: true`, `carrier: true`, `cmdline_ok: true`, `fd_iff: true`, `pid 4009645`; `guest_verify_fresh: true`, `guest_verify_nonce: null` (в режиме `--host-only`) |
| QEMU | `ssh home-pc 'pgrep -af qemu'` | `qemu-system-x86_64 -enable-kvm -machine q35 ... -smp 6 -m 8192`, pid 4009645, совпадает с `vm.pid` |
| гость | `ssh -J home-pc -p 2222 lab@127.0.0.1 ver` | первая попытка: `Connection timed out during banner exchange`; повтор через ~2 мин: `Microsoft Windows [Version 10.0.26300.9711]` |
| Npcap | `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/recheck-931f69f/logs/inv.out`, `.../README.md` строка 12 | Npcap 1.90, `lib_version` «Npcap version 1.90, based on libpcap version 1.10.7 (64-bit time_t)», wpcap.dll 1.10.7.0, Packet.dll/драйвер 5.1.90.1020 (из прошлой записи, на госте в этом проходе не перепроверялось) |
| rustc гостя | не запускался (вне разрешённого перечня чтений) | в записи `recheck-931f69f`: `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |

Вывод: VM запущена, стенд `n2` поднят и запечатан, `raw_run_allowed: true` по host-only статусу. Действия B1/B2 не требуются.
Остаётся действие пользователя A (разрешение живого окна) перед задачей 3 и перед задачей 6. Полный (не host-only) статус с гостевым Verify и nonce снимается живым оператором непосредственно перед каждым прогоном.

## 5. Проверки на Mac (чистый экспорт `git archive HEAD`, `CARGO_TARGET_DIR` приватный, `CARGO_INCREMENTAL=0`)

| Команда | Результат |
| --- | --- |
| `cargo fmt --all --check` | rc 0, пустой вывод |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | завершился `Finished dev profile`, ошибок нет (rc 0) |
| `cargo test --locked --workspace` (первый прогон) | FAIL: `rmasscan-lab --lib` 620 passed, **2 failed**: `dump::tests::sequence::a_complete_capture_is_acknowledged_finalised_and_valid`, `dump::tests::linux_wire_gate::real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate`; сборка шла параллельно с другим агентом (нагрузка); после падения cargo остановился |
| `cargo test --locked -p rmasscan-lab --lib dump::tests` | `25 passed; 0 failed` |
| `cargo test --locked --workspace --no-fail-fast` (повтор) | rc 0; 39 строк `test result`, все `ok`, 0 failed; `rmasscan-lab --lib` 622 passed; прочие крупные: 160 passed (9 ignored), 136 passed, 41 passed, 32 passed |
| `bash scripts/language-guard.sh` | `language guard: PASS (6621 tracked files checked)` (в экспорте проведён `git init && git add -A`, так как скрипту нужен git) |

Замечание: два падения первого прогона не воспроизведены (изолированный и полный повтор зелёные), похоже на нагрузочную гонку в
тестах `dump` лаборатории; к задаче не относятся, но стоит помнить при CI-красном на этих двух именах.

## 6. База результатов (без изменений, из `perf-r1`, код `847e218`)

Источник: `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/perf-r1/README.md`.
Медианы `steady_pps_wire` (5 ячеек на скорость): 100 pps -> 100.7 (MET); 1000 -> 1006.7 (MET); 10000 -> 6444.6 (OPEN); 100000 -> 6321.1 (OPEN).
Потолок около 6.4 kpps при p50 `pcap_sendpacket` 113-227 мкс (спайк 2B, `2026-10-24-rmasscan-stage2b-windows-spike.md`).
Windows GO (VM): части A и B PASS, RX health, Stop, pause/resume, linkloss, rxloss, perm PASS. Физический NIC: NOT RUN.
Фикстуры части C переиспользуются без нового захвата оракула (binding гостя тот же): `docs/experiments/2026-10-24-rmasscan-windows-vm-acceptance-raw/functional/fixtures`.
`peer.pcap` ячеек 10k и 100k в `perf-r1` лежат как `.gz`; сравнение по полям вердикта, распаковка в репозиторий запрещена.

## 7. Что нужно дальше

- Действие пользователя A (живое окно на `n2`, только `198.18.0.2`) до задачи 3.
- Задача 3 доказывает границу записи при частичном transmit и выбирает `TX_BATCH_FRAMES` (ряд 16/64/256/1024/4096).
- Оговорка ветки: план называет ветку `feat/rmasscan-stage2b-sendqueue`, фактическая `feat/rmasscan-windows-sendqueue`.
