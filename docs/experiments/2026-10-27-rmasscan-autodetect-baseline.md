# rmasscan: автоопределение адаптера и шлюза. База и контракты (задача 0)

Дата: 2026-10-27. Ветка `feat/rmasscan-autodetect`, база `cda41ea` (коммит плана). Документ только читает: ни одного кадра,
ни одного `sudo` на Mac, стенды не менялись. Реальные маршруты, MAC и имена хостов сюда не копируются; о реальных
хостах записаны лишь факты «есть/нет». C-источник: чекаут masscan `8e6b3b0` (`$ORACLE_SRC` = `src/` этого чекаута).

## 1. Состояние окружения (только чтение)

| Что | Команда | Результат |
| --- | --- | --- |
| Mac ОС | `sw_vers` | macOS 27.0.1 (сборка 26A434) |
| Rust | `rustc --version` | rustc 1.99.1 (Homebrew) |
| minipc `sudo -n` | `ssh minipc 'sudo -n true'` | rc 0, доступно |
| minipc netns | `ip netns list` | пусто (0 пространств) |
| minipc оракул | `sha256sum ~/rmasscan-oracle/masscan/bin/masscan` | `8afc8ec81f2e051389116908b01a4482b42e020bc48254585b7dcca4b25e2a3e` (ожидалось `8afc8ec8…`, совпало) |
| minipc маршруты | `ip route get 0.0.0.0` (не dump) | `local 0.0.0.0 dev lo src …` (RTN_LOCAL, подтверждено); маршрут по умолчанию с `dev` есть (1 строка) |
| home-pc `sudo -n` | `ssh home-pc 'sudo -n true'` | rc 0, доступно |
| home-pc qemu | `pgrep -af qemu` | процессы есть (VM работает) |
| VM `n2` | `sudo -n rmasscan-lab vm-lab status --run-id n2 --manifest ~/winvm/lab/n2.json --host-only` | rc 1: `state: up`, VM attached, carrier, `cmdline_ok`, `fd_iff` true; объекты `wvb-n2`, `wvh-n2`, `wvp-n2`, `wvt-n2` present, owned; **`host_ok: false`, `ok: false`, `raw_run_allowed: false`**; `isolation_violations`: 4 записи «forwarding must be 0» (три лабораторных линка и глобальный `ip_forward`) |
| Гость Windows | `ssh -J home-pc -p 2222 lab@127.0.0.1 'ver && whoami /groups \| findstr /i "S-1-16-12288"'` | rc 0; Windows 10.0.26300.9711; метка `S-1-16-12288` (High Mandatory Level) присутствует: **elevated** |
| Mac `macos-lab status --run-id m1` | собранный `rmasscan-lab` из этого коммита | rc 3 (ожидаемо): нет манифеста стенда, `feth4201` не существует, `bpf_access: denied`, `raw_run_allowed: false` |
| Mac маршрут по умолчанию | `route -n get default` (оболочка агента) | интерфейс и шлюз есть (оба поля присутствуют); значения не записываются, сверка с задачей 3 |

Вывод: `sudo -n` подтверждён на minipc и home-pc. Но стенд `n2` сейчас НЕ годен для живого прогона:
`raw_run_allowed: false` из-за `forwarding must be 0` (причину не выясняли, хост не менялся). Для задачи 7 (Windows) его надо
привести в порядок до прогона, иначе Windows-кейсы NOT RUN до решения пользователя. VM `n2` при этом поднята и присоединена.

Действия пользователя в задаче 7: A, B, F (по таблице плана). B1/B2 при необходимости делает агент. Каждый `sudo` на Mac
выполняет пользователь голыми командами: chained-строка `up` + `grant` + root-кейс, одно `down` (оно же revoke).

## 2. Базовая проверка (Mac, свой `CARGO_TARGET_DIR`, `CARGO_INCREMENTAL=0`, `SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib`)

| Команда | rc | Итог |
| --- | --- | --- |
| `cargo fmt --all --check` (`rmasscan/`) | 0 | чисто |
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | 0 | чисто |
| `cargo test --locked --workspace --no-fail-fast` | 0 | 39 тестовых бинарников, `1274 passed; 0 failed; 23 ignored` (лаб-lib: 706 passed; core lib 136; net lib 193 + 9 ignored; cli main 15, differential 7; engine: backpressure 6, bounded_memory 1, identity 9, lifecycle 32, pause_resume 10, rx_integrity 11, tx_batch 14, tx_stall 9) |
| `cargo xtask test` (`studio/`) | 0 | `147 passed; 0 failed; 2 ignored` по всем бинарникам |
| `bash scripts/language-guard.sh` | 0 | `language guard: PASS (9705 tracked files checked)` |

Примечание о нестабильности: первый запуск `cargo test --locked --workspace` (без `--no-fail-fast`) дал rc 101: упали два
теста `rmasscan-lab` (`dump::tests::linux_wire_gate::real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate` и
`dump::tests::sequence::a_complete_capture_is_acknowledged_finalised_and_valid`) с причиной «tcpdump did not exit after
SIGINT» (поддельный `fake-tcpdump.sh` под нагрузкой полного прогона). Отдельный прогон `cargo test -p rmasscan-lab --lib dump::`
дал 25 passed, повторный полный прогон 0 failed. Это существующая нестабильность по времени, не связанная с задачей; для
GO нужны зелёные полные прогоны.

База из readiness (`docs/experiments/2026-10-24-rmasscan-readiness.md:83`): «ARP codec / ARP resolver | codec есть в core
текущей ветки; resolver и discovery шлюза нет нигде». Подтверждено кодом: в `rmasscan-core/src/arp.rs` есть только
кодек и `PendingResolve`; в `rmasscan-net` нет ни разрешения шлюза, ни таблицы маршрутов; в `ScanConfig` нет `router_ip`.

## 3. Контракты с номерами строк (проверены чтением)

### 3.1 CLI (`rmasscan/crates/rmasscan-cli`)

- `Cargo.toml`: только `[[bin]] name = "rmasscan" path = "src/main.rs"`, `[lints] workspace = true`; зависимости
  `rmasscan-core`, `clap`; dev: `serde`, `serde_json`. Нет `[lib]`, нет `rmasscan-engine`/`rmasscan-net`/`getrandom`.
- `src/main.rs:31–62` `for_each_probe`: для `--offline --packet-trace` требует `--adapter-ip`, `--adapter-mac`, `--router-mac`,
  `--source-port` (иначе ошибка `--offline --packet-trace needs …`, «stage 1 has no adapter discovery»), строит
  `AdapterBinding { interface_id: adapter_name или "offline", Ethernet, … }`.
- `:111–155` `run(cli, out)`: `to_config()`; `--echo/--echo-all` → `validate(Echo)`; `--list` → `validate(List)`;
  `--offline --packet-trace` → `validate(Scan)`; иначе `Err("stage 1 supports only -sL, --echo/--echo-all and --offline --packet-trace")`.
- `:174` начинается `#[cfg(test)] mod tests` внутри бинарника (юнит-тесты `run_args`); `:305` внутри теста запрет скана без
  `--offline` (`["rmasscan","10.0.0.0/30","-p80","--seed","1"]` → ошибка); `:473–511` тесты
  `packet_trace_requires_adapter_options` и `scan_without_offline_trace_is_rejected`.
- `src/args.rs:64` `pub seed: Option<u64>` («REQUIRED, must be non-zero»); `:121–128` `-e/--interface` с `alias = "adapter"`,
  help «recorded only; no adapter is opened in stage 1»; `:203–206` `--seed` обязателен и ненулевой (`seed == 0` в C значит энтропия,
  `main.c:1640-1641`). Уже есть: `--adapter-ip`, `--adapter-mac`, `--router-mac`, `--source-port` (alias `adapter-port`).
  Нет: `--router-ip`, `--iflist`, `--source-ip`, `--source-mac`. `Cli` derive `Default`.

### 3.2 Core (`rmasscan-core/src`)

- `config.rs:96–119` `ScanConfig`: `targets, excludes, seed, max_rate, retries, shard, resume_index, resume_count,
  blackrock_rounds, wait_secs, adapter_ip, adapter_mac, router_mac, source_port, adapter_name, offline`. `router_ip` отсутствует.
  `Default` на `:121`. Все литералы `ScanConfig { … }` в `rmasscan` и `studio` (18 мест) используют `..Default` (кроме самого
  `impl Default`), поэтому добавление поля не ломает их; студия: `studio-protocol/src/lib.rs:134` с `..Default::default()`.
- `config.rs:379–444` `validate(cfg, op)`: порядок проверок: shard, rounds ≥ 64, retries ≥ 1000, rate, исключения,
  `try_range`; `Echo` возвращается рано; пустые цели/порты; `ExcludeRequired` при `op == Scan`, `count_ipv4s > 1_000_000_000` и пустых
  `cfg.excludes` (`:432–434`); `ZeroSeed` (`cfg.seed == 0`) последним. `EffectiveConfig` геттеры на `:204–220` (`adapter_ip`,
  `adapter_mac`, `router_mac`, `adapter_name`). `echo` на `:592` (adapter на `:631`, router-mac на `:640–642`);
  `read_paused_conf` на `:768` (`adapter|if|interface` на `:848`, `router-mac-ipv4/ipv6` на `:874–878`). `parse_source_port`
  на `:330–348` требует ширину-степень-двойки.
- `probe.rs:61–69` `AdapterBinding { interface_id, link_type, source_ipv4, source_mac, next_hop_mac, source_ports }`;
  `:84–92` `check_source_ports`: `first == 0 || first > last || !width.is_power_of_two()` → ошибка. Ширина 17 ({p, p+16})
  не выражается: **подтверждено**. `:222–273` `ReadyPlan::new`: только `Operation::Scan`, resume 0, shard 1/1, retries 0,
  rounds 14, порты ≤ 65535, непустой диапазон.
- `arp.rs:61–72` `encode_request(my_mac, my_ip, target_ip) -> [u8; 60]` (broadcast назначение, sender = my_mac, target MAC 0);
  `:144–191` `PendingResolve::{new, request_frame, resolved, offer}`: ответ принимается при opcode 2, `target_ip == my_ip`,
  `target_mac == my_mac`, `sender_ip == target_ip`, `sender_mac == eth_src`, не нулевой, не групповой; первый подходящий фиксируется.
  Шапка файла (`:1–10`): отличия от C (строгие длины 6/4, VLAN → ошибка).

### 3.3 Net (`rmasscan-net/src`)

- `lib.rs:121–133` `IfaceReport { name, index, mac, mac_masked, ethernet, up, ipv4 }`; `:232` `NetStatsHandle::new` — `pub(crate)`
  (подтверждено, внешний конструктор невозможен); `:284–307` четыре `open_explicit(&AdapterBinding) -> Result<OpenedAdapter, NetError>`
  (linux/windows/macos/прочие → `UnsupportedPlatform`). `OpenedAdapter { io: AdapterPair, stats: NetStatsHandle, tx_mode }`.
  Шапка `lib.rs:1–22`: `#![deny(unsafe_code)]`, список FFI-модулей: `linux::socket`; `macos::{sys, ifinfo, process}`;
  `windows::{ffi, handle, loader, process, sys}`; `lab_io::imp` (feature `lab`). `mod macos` и `mod windows` собираются и в тестах
  других платформ (`cfg(any(…, test))`). `Cargo.toml` комментарий (`:8–11`) перечисляет тот же список; `[lints.rust] unsafe_op_in_unsafe_fn = "deny"`.
- `allow(unsafe_code)`: `linux/mod.rs:15` (`mod socket`), `macos/mod.rs:18,22,26` (`sys`, `ifinfo`, `process`) и `:33`
  (тестовый `spike`), `windows/mod.rs:15,17,20,23,26,33,37` (`ffi`, `handle`, `loader`, `process`, `sys`, `tests`, `live`).
- `linux/mod.rs:358–393` `verify_binding`: только Ethernet, `valid_ifname`, `if_nametoindex`, `SIOCGIFHWADDR` с `ARPHRD_ETHER`;
  `source_ipv4`/`source_mac` с ОС не сверяются. `:404–420` `open`: TX-сокет protocol 0, RX-сокет `ETH_P_ALL` с bind на ifindex;
  `RxHalf::step` (`:245–296`) отбрасывает только `PACKET_OUTGOING` и чужой ifindex, фильтра по MAC/ethertype нет.
  `linux/socket.rs:74–81` `PACKET_IGNORE_OUTGOING` на RX-сокете; `:213–249` `OsIface` (`if_nametoindex`, `SIOCGIFHWADDR`).
- `macos/ifinfo.rs:190–227` `interfaces() -> Vec<IfaceReport>` + `merge`; `MASKED_MAC = 02:00:00:00:00:00` (`:23`);
  `visible_mac()`/`masked()`; `:242–280` `verify_binding` (Ethernet по `IFT_ETHER`, `link.mac.is_some()` — плейсхолдер считается
  наличием MAC, поэтому явный `--adapter-mac` проходит без прав); `:280–301` `nic_mac`, `nic_mac_masked`, `iface_exists`.
- `macos/adapter.rs:128–143` `own_mac_filter` (BPF: отбросить кадры с нашим source MAC, остальное принять), `drop_all_filter`;
  `:522–545` `check_binding`: Ethernet, source MAC не нулевой и не групповой, `source_mac != next_hop_mac`; `:592–609`
  `configure_rx`: `BIOCSBLEN → BIOCSETIF → BIOCGDLT → BIOCIMMEDIATE → BIOCSSEESENT 0 → BIOCSETF(own_mac_filter)`.
- `windows/adapter.rs:352–374` `check_binding` (те же условия, что macOS); `:425–427` RX-фильтр `not ether src <source MAC>`,
  promisc выключен; `windows/sys.rs:159–213` `adapter_mac_by_guid` (`GetAdaptersAddresses`, `unsafe` с SAFETY, повтор до 4 раз при
  `ERROR_BUFFER_OVERFLOW`); `windows/inventory.rs:12` `npf_guid(name)` для `\Device\NPF_{GUID}`. Новые Windows-вызовы
  (`GetBestRoute2`, `GetIpForwardTable2`) идут в существующий `windows::sys`.

### 3.4 Engine (`rmasscan-engine/src`)

- `io.rs:45–108` `Tx::{send, max_batch, send_batch}` и `Rx::{recv, health}`; `AdapterPair { tx, rx }` на `:111–114`.
- `events.rs:77–93` `Event::{Started, Progress, Results, CheckpointReady, Finished}`; `Outcome { reason, progress, rx_health }`
  (`:~64–70`), `Progress { sent, next_index, received, discarded, duplicates, rate }`, `Reason::{Completed, Stopped, Paused, Failed(FailReason)}`.
- `engine.rs:64–98` `EngineOptions` (по умолчанию `io_timeout = MAX_IO_TIMEOUT` = 50 мс, `engine.rs:37`); `:693–712`
  `Engine::start(plan, io, options)` и **скрытый** `start_with_clock(…)`: `:703` `#[doc(hidden)]`, комментарий «Не часть
  стабильного API» (`:700–702`); `:930–962` `recv_event_timeout`, `outcome`, `progress`, `join`, `join_drain`.
- **Часы**: трейт `Clock` в `rmasscan-core/src/throttle.rs:22–30`: `now_micros(&self) -> u64` (монотонные микросекунды) и
  `sleep_micros(&self, us)` (в проде спит, в тестовых часах двигает время на `us`); `SystemClock` там же; движок берёт
  `Arc<dyn Clock + Send + Sync>` (`engine.rs:323`), `now_micros` на `:520, :556, :617, :655`, `sleep_micros` на `:569`.
- `fake.rs:23` `ManualClock` (стартует на 1_000_000 мкс; `advance`, `advance_micros`, `set_hold`); `:56–70` `impl Clock`:
  `sleep_micros` по умолчанию сразу продвигает время на `us`, в режиме `hold` реально спит 1 мс. **FakeAdapter и часы**: `FakeRx::idle`
  (`:436–440`) на каждом пустом `recv` (шаг `Idle`, пустая очередь) делает `clock.advance(timeout)` и спит 100 мкс; поэтому
  резолвер ARP на `FakeAdapter` с `ManualClock` продвигает время на `timeout` (≤ 50 мс) за каждый пустой `recv`.

### 3.5 Lab

- `wire_suite.rs:219–232` `struct Case` + начало `cases()` (`c01_one_addr_port_synack` …); `:472–545` `recorder`/`stop_recorder`
  (свидетель `capture dump` в пространстве пира, стартовый маркер). `isolation_permits` находится в
  `wire_suite.rs:2122` (проверка JSON `isolation.json`: `uplink|bridge|nat|default_route == false`, `ip_forward == 0`, `ipv6 == "disabled"`,
  `veth_created_inside_scanner_ns_peer_moved_to_peer_ns`, `host_link_list_unchanged`), использована на `:2088`.
- `capture.rs:8–40` `classify(frames, scanner, peer)` (ключи `syn_from_scanner`, `synack_from_peer`, `rst_from_peer`,
  `rst_from_scanner`, `marker`, `other`); `:329–425` `isolation` (пишет `default_route: false`; требует, чтобы
  `ip route get 8.8.8.8` не удавался в обоих пространствах); `:427–455` `check_isolation_snapshot`: ровно `lo` + veth,
  маршрутов ≤ 1 и **ни default, ни gateway**, `ip_forward == 0`. Следствие: стенд `autodetect` (default via пир) без нового
  режима проваливает `check_isolation_snapshot`, `isolation()` («lab has route to external IP») и seal-проверки `wire-lab.sh:174–188`.
- `pcap.rs`: `read_pcap_records` (`:5`), `is_syn` (`:58`), `compare_streams` (`:96`, упорядоченное побайтное сравнение SYN),
  `encode` (`:222`, классический pcap без сжатия).
- `verify.rs:385` `plan_frames(args)`: строит план как `wire_scan` (ключи `--src-ip --src-mac --router-mac --source-port
  --targets --ports --exclude --seed --rate --wait`), `ScanConfig { … ..default }` на `:411`.
- `macos_suite.rs:472–505` `write_hashes`/`copy_verified` (`hashes-before-copy.txt`); `:527–565` `uplink_interlock`,
  `interlock_stats`; `macos_lab.rs:40` `UPLINK_FILTER`.
- `windows_suite.rs:884–922` исполнение раннера (`argv`, `forge`, `restricted`; `forge-argv.json`); `:1781` строка помощи
  (`--fixtures DIR` обязателен; `--plan functional|failure|perf`; кода `autodetect` пока нет); `:2062` манифест (`"exe"`).
  **Вывод гостя**: `:1367–1390` копирует из гостя в каталог прогона `guest-stdout.txt`, `guest-stderr.txt`, `guest-exit.txt`,
  `guest-runner.json`, `guest-nic.json`, `guest-runner.log`, `guest-runner.rc`; `:1392–1400` читает `guest-stdout.txt` (срезав BOM) и
  берёт **последнюю строку, начинающуюся с `{`**, записывая её как `run.json` (`:1400`).
  Следствие для верификатора: stdout автоопределения не должен кончаться JSON-строкой, а гостевой runner пишет `"\n"` при пустом stdout.
- `scripts/wire-lab.sh`: `:42` проверка `--suite` (`oracle|rust|perf`), `:47–56` re-exec через `sudo -n env … "$0"`, `:64–80`
  явный binding (по умолчанию `02:aa:00:00:00:01/02`, `IP_A_LINK=10.200.0.1`, `IP_ADAPTER=10.200.0.100`, порты `80,8080`),
  `:144–172` топология (netns `wl-scan-*`/`wl-peer-*`, `veth-a`/`veth-b`, постоянный neigh на пире, `ethtool tx off`), `:174–190`
  seal (**`fail "$ns has a default route"`**, `route get 8.8.8.8` не должен работать, не более одного маршрута) и вызов
  `capture isolation`. `scripts/windows_wire_run.ps1` (43 строки) пишет `stdout.txt`, `stderr.txt`, `exit.txt`, `nic.json`, `runner.json`.

### 3.6 Studio

- `studio-protocol/src/lib.rs:75–160` `Job::prepare()`: строит `ScanConfig` (`:134`, `..Default::default()`) → `validate(Scan)`
  → `ReadyPlan::new` с явным binding. `studio-runner/src/main.rs:48–79` `raw_adapter`: `Simulation` → `FakeAdapter`; `MacFeth` →
  `open_explicit(plan.binding()).io`. Studio зависит от `rmasscan-net` (`studio/Cargo.toml:23`), но не от `discover`; правок не требуется.

### 3.7 Тесты бинарника и `cfg(test)` (для `OsBackend`)

- `cargo test` собирает `src/main.rs` как тестовую цель с `cfg(test)` (юнит-тесты `:174`). Интеграционные тесты запускают бинарник,
  собранный **без** `cfg(test)` (`env!("CARGO_BIN_EXE_rmasscan")`). Следовательно `os_backend.rs` под `#[cfg(not(test))]` виден
  интеграционным тестам через спавн бинарника, но недостижим из юнит-тестов; поэтому интеграционные тесты обязаны запускать
  только `--iflist` и `--offline`.
- Все текущие спавны бинарника в `rmasscan-cli` (единственный файл `tests/differential.rs`):
  1. `:61` `run_bin(args)` — argv из фикстур C-оракула: `-sL …` (вызов `:90`) и `--echo`/`--echo-all …` (вызов `:135`), содержимое по кейсам фикстур;
  2. `:150` цикл: `["-sL","bogus","-p80","--seed","1"]`, `["--banners","10.0.0.0/24","-p80"]`;
  3. `:165` `["-sL","0.0.0.0/0","-p80","--seed","1"]` (broken pipe, spawn);
  4. `:196` `["--help"]` (`warm_up_exe`, spawn);
  5. `:228` `["-sL","10.0.0.0/30","-p80","--seed","1","--retries","1"]`;
  6. `:248` `["-sL","10.0.0.0/30","-p80","--seed","0"]`;
  7. `:258` `["--help"]`.
  Ни один не касается адаптеров.

## 4. C-оракул (`$ORACLE_SRC`, `8e6b3b0`)

### 4.1 `main-initadapter.c`

- `:44–57` интерфейс: если `--interface` задан, берётся он; иначе безусловно `rawsock_get_default_interface` (**даже при `--offline`
  и при заданных IP/MAC**: `--offline` не пропускает поиск; пропускает только `--interface`). Отказ: `[-] FAIL: could not determine default interface\n` +
  `    [hint] try "--interface ethX"\n` (LOG 0). `:58` `[+] interface = %s` (LOG 1, то есть только с `-v`).
- **Префикс FAIL.** Все FAIL-строки `main-initadapter.c` начинаются с `[-] FAIL:` (`:52, :102, :134, :195, :221, :254`). Но строки
  `main.c` без `[-] `: `FAIL: range too big, need confirmation` (`main.c:1236`, hints `:1237–1238`), `FAIL: failed to detect IP of interface`
  (`main.c:1286`, hint с `--adapter-ip 192.168.100.5` на `:1288–1289`), `main-conf.c` — `FAIL: bad source port specification`
  и другие без `[-] `.
- `:66–81` адаптер открывается ДО MAC/IP (требует привилегий); у rmasscan обнаружение идёт до `open` (отклонение).
- `:90–112` MAC: если `my_mac_count == 0` и MAC нулевой → `rawsock_get_adapter_mac`; всё ещё нулевой → stderr
  `[-] FAIL: failed to detect MAC address of interface: "%s"\n` + ` [hint] try something like "--source-mac 00-11-22-33-44-55"\n`
  (подсказка с одним пробелом). `[+] source-mac = %s` (LOG 1).
- `:122–147` IPv4: `--adapter-ip` (`src.ipv4.first`) или `rawsock_get_adapter_ip`; ноль → `[-] FAIL: failed to detect IP of interface "%s"\n`,
  `    [hint] did you spell the name correctly?\n`, `    [hint] if it has no IP address, manually set with something like "--source-ip 198.51.100.17"\n`.
  `[+] source-ip = %s`.
- `:159–201` маршрутизатор: `--offline` → MAC `66-55-44-33-22-11` принудительно (затирает и значение `--router-mac`), поиска нет (`:160–163`);
  иначе нулевой MAC → `router_ip = --router-ip`, если 0 то `rawsock_get_default_gateway`; при `err == 0` печатает `[+] router-ip = %s`
  (даже `0.0.0.0`) и вызывает `stack_arp_resolve`; затем `[+] router-mac-ipv4 = %s`; нулевой MAC → `[-] FAIL: ARP timed-out resolving MAC address for router %s: "%s"\n` (**печатает
  настроенный `router_ip`, т. е. `0.0.0.0`, если шлюз был найден автоматически**), `    [hint] try "--router-ip 192.0.2.1" to specify different router\n`,
  `    [hint] try "--router-mac 66-55-44-33-22-11" instead to bypass ARP\n`, `    [hint] try "--interface eth0" to change interface\n`.
- IPv6 (`:212–261`) и NDP не переносятся.

### 4.2 Остальное

- `stack-arpv4.c:103–270`: запрос 60 байт (broadcast, sender = my_mac, zero target MAC), отправка сразу, затем повтор на каждой смене секунды
  `time(0)`; `i++ >= 10` → выход: всего **12 запросов за ~11 с**; критерии ответа: ethertype ARP, opcode 2, `ip_dst == my_ip`, `mac_dst == my_mac`,
  `ip_src == target`; сообщения `[+] resolving router … with ARP (may take some time)...` и `[+] arping local router …` (LOG 0); VPN-кладж
  (datalink 12 → MAC `00:00:00:00:00:02`). Строже в Rust: sender MAC == eth src, не нулевой и не групповой.
- `rawsock-getif.c`: macOS (`:54–176`) — `RTM_GET` для `0.0.0.0` с `RTA_DST|RTA_IFP`, чтение до совпадения `rtm_seq` и `rtm_pid`
  (несовпадения печатает `printf` в stdout), имя из `sockaddr_dl`; sockaddr выровнены `ROUNDUP(sa_len)` по `sizeof(int)` = 4;
  Linux (`:298–391`) — dump `RTM_GETROUTE`, только `AF_INET` и `RT_TABLE_MAIN`, маршрут с `RTA_DST` равным 0, берётся **наименьший приоритет** (шлюз 0
  пропускается); Windows (`:416–493`, ядро `:455–485`) — `GetAdaptersInfo`, тип 6 (Ethernet) или 71 (Wi-Fi), у адаптера есть шлюз → имя
  `\Device\NPF_<AdapterName>`; цикл не прерывается, поэтому **побеждает последний** адаптер со шлюзом.
- `rawsock-getroute.c`: macOS (`:109–229`) — тот же `RTM_GET 0.0.0.0` (не dump); при несовпадении имени интерфейса `exit(1)` с
  `ERROR: ROUTE DOESN'T MATCH INTERFACE` / `YOU'LL HAVE TO SET --router-mac MANUALLY` (сравнение по `memcmp` на `sdl_nlen`);
  Linux (`:338–421`) — dump, `main`, `AF_INET`, `RTA_DST == 0`, интерфейс совпал: **побеждает последний** подходящий (даже без `RTA_GATEWAY`, тогда 0);
  Windows (`:444–568`) — первый совпавший адаптер, первый разбираемый адрес `GatewayList`.
- `rawsock-getip.c`: Linux `SIOCGIFADDR`, ошибка → stderr `ERROR:'%s': %s` и 0; Windows первый разбираемый адрес `IpAddressList`;
  macOS/BSD `getifaddrs`, **первый** `AF_INET` по имени. `rawsock-getmac.c`: Linux `SIOCGIFHWADDR` (для `0xfffe` без MAC подставляет `…:01`),
  Windows `Address` при длине 6, macOS/BSD `getifaddrs` + `sockaddr_dl` (на macOS 27 без прав приходит `02:00:00:00:00:00`).
- `rawsock.c:198–225` `rawsock_list_adapters` (`--iflist`): `pcap_findalldevs`, **в stderr**, формат `" %d  %s \t(%s)\n"`, пустой список →
  `ERR:libpcap: no adapters found, are you sure you are root?`. `main-conf.c:2823` `iflist` → `Operation_List_Adapters`.
- `output.c:746–800`: `Discovered open port 80/tcp on 10.0.0.1` = 39 символов, затем `79 - 39 = 40` пробелов, затем `\n` (итого 80 байт),
  `fflush(stdout)`; статус `closed` не печатается без `--show closed`.
- `main.c:1222–1240` `range too big` (>1e9 адресов без `--exclude`) → `exit(1)`; `:1275–1291` `masscan_initialize_adapter`, `exit(1)` при ошибке;
  `:1315–1320` порт источника по умолчанию `40000 + now % 20000`, `first = port`, `last = port + 16`, `range = 16`; `:185–186` `port_mask = last - first`
  (то есть {p, p+16} при маске 16). Подтверждено: `check_source_ports` (`probe.rs:84–92`) не выражает такую ширину 17.
- `main-conf.c`: `:2474–2485` `adapter|if|interface`; `:2486–2488` `adapter-ip|source-ip|source-address|spoof-ip|spoof-address|src-ip`
  (диапазон степени двойки); `:2523–2555` `adapter-port|source-port|src-port` (ровно один диапазон, ширина-степень двойки, иначе `FAIL: …` и `exit(1)`);
  `:2556–2557` `adapter-mac|spoof-mac|source-mac|src-mac`; `:2587–2625` `router-mac|router|dest-mac|destination-mac|dst-mac|target-mac`, `router-mac-ipv4|router-ipv4`,
  `router-mac-ipv6|router-ipv6`; `:2626–2641` `router-ip` (одиночный адрес, иначе `FAIL: bad source IPv4 address: %s=%s` / `hint   addresses look like "19.168.1.23"`).

### 4.3 Таблица «matched / deviate» (решения 1–7 плана)

| № | Что | masscan (C) | rmasscan | Статус |
| --- | --- | --- | --- | --- |
| 1 | Интерфейс | первый с маршрутом по умолчанию (Linux: наименьший priority; Windows: последний со шлюзом; macOS: `RTM_GET 0.0.0.0`) | интерфейс маршрута к целям (первая и последняя unicast-цели совпадают); маршруты по умолчанию dump-ом/таблицей | deviate |
| 2 | Следующий хоп | всегда шлюз по умолчанию (и ARP на него) | `--router-ip` → шлюз маршрута → единственная on-link цель → шлюз по умолчанию интерфейса → отказ с тремя подсказками | deviate (часть веток matched) |
| 3 | Source IP/MAC | первый IPv4, MAC интерфейса; нулевой MAC → отказ с `--source-mac`/`--source-ip` | то же; плейсхолдер Darwin и нулевой MAC отказывают с теми же подсказками; алиасы `--source-ip/--source-mac`; IfType 71 как Ethernet | matched |
| 4 | ARP | 12 запросов за ~11 с, `time(0)` | 10 запросов с шагом 1 с, отказ в 10 с по инжектированным часам; критерии строже | deviate |
| 5 | Привилегии | `rawsock_init_adapter` до MAC/IP | обнаружение, `--iflist`, `--offline` без привилегий; порядок defaults → validate → detect → ARP → open | deviate |
| 6 | Умолчания | seed из энтропии; порт {p, p+16}; `--offline` фиктивный MAC `66-55-44-33-22-11` | seed из `getrandom` (печатается); один порт `40000 + t % 20000`; `--offline` принудительно, без поиска маршрутизатора | deviate (offline matched) |
| 7 | Вывод | `Discovered…` 39+40+`\n`, flush, `[+]` только с `-v`; `--iflist` в stderr | строка побайтно; `[+]` всегда; свой формат `--iflist`; нет строки статуса и Ctrl-C | строка matched, остальное deviate |

## 5. Доказательства чтением

- **ARP-ответ проходит RX-фильтры без изменений.** Linux: RX-сокет `ETH_P_ALL`, отбрасываются только исходящие и чужой ifindex
  (`linux/mod.rs:245–296`). macOS: BPF-фильтр `own_mac_filter` (`macos/adapter.rs:128–141`) отбрасывает только кадры с нашим source MAC; ответ приходит с MAC шлюза, проходит.
  Windows: `not ether src <наш MAC>` (`windows/adapter.rs:425`), ответ с MAC шлюза проходит; promisc выключен, ответ адресован нам unicast.
- **`check_binding` macOS/Windows принимает `next_hop_mac = ff:ff:ff:ff:ff:ff` при unicast `source_mac`**: проверки только `source_mac != 0`,
  `source_mac[0] & 1 == 0`, `source_mac != next_hop_mac` (`macos/adapter.rs:522–545`, `windows/adapter.rs:352–374`); Linux `verify_binding` next hop не проверяет.
- **`NetStatsHandle::new` `pub(crate)`** (`lib.rs:232`): внешний код не может собрать `OpenedAdapter`; шов `open` обязан возвращать `AdapterPair`.
- **`libc` 0.2.191 (в `Cargo.lock`)**: `rtmsg` для Linux отсутствует (есть только `in6_rtmsg`); есть `rtattr`, `RTM_GETROUTE`, `RTA_DST`, `RTA_OIF`, `RTA_GATEWAY`,
  `RTA_PREFSRC`, `RTN_LOCAL`, `if_nameindex`/`if_freenameindex`, `SIOCGIFFLAGS`, `SIOCGIFADDR`, `SIOCGIFHWADDR`; `nlmsghdr`, `sockaddr_nl`, `NETLINK_ROUTE`, `NLM_F_DUMP`
  лежат в `src/new/linux_uapi/linux/netlink.rs` (доступность на `x86_64-unknown-linux-gnu` подтвердит сборка в задаче 3: Linux-цель здесь не собирается). На macOS есть
  `rt_msghdr`, `RTM_GET`, `RTA_DST`, `RTA_GATEWAY`, `RTA_IFP`, `RTF_*`, `PF_ROUTE`, `RTM_VERSION`, `NET_RT_*`.
- **`windows-sys` 0.61.2**: `GetBestRoute2`, `GetIpForwardTable2` (`MIB_IPFORWARD_ROW2/TABLE2`), `GetAdaptersAddresses`, `FreeMibTable`, `IP_ADAPTER_ADDRESSES_LH`
  (`IfType`, `OperStatus`, `FirstGatewayAddress`), `GAA_FLAG_INCLUDE_GATEWAYS`, `IF_TYPE_ETHERNET_CSMACD = 6`, `IF_TYPE_IEEE80211 = 71`, `ERROR_NOT_FOUND = 1168`,
  `ERROR_NETWORK_UNREACHABLE = 1231`, `ERROR_HOST_UNREACHABLE = 1232` — все под features `Win32_NetworkManagement_IpHelper`, `Win32_NetworkManagement_Ndis`,
  `Win32_Networking_WinSock`, `Win32_Foundation`, которые уже включены в `rmasscan-net/Cargo.toml`. Новых features и зависимостей не нужно.

## 6. Семантика маршрутов, на которой строится задача 3

- **Linux.** Не-dump `RTM_GETROUTE` для `0.0.0.0` отвечает `local 0.0.0.0 dev lo` (`RTN_LOCAL`): измерено на minipc (`ip route get 0.0.0.0`).
  Поэтому маршруты по умолчанию берутся dump-ом таблицы main (как и C: `rawsock-getif.c:298–391`, `rawsock-getroute.c:338–421`), а для цели lookup с `RTA_DST`.
  Цели-пробы `0.0.0.0`/`255.255.255.255` не используются (иначе ложные отказы на каноническом `0.0.0.0/0 --exclude 255.255.255.255`).
- **Darwin.** Sockaddr в сообщениях route socket выровнены по 4 байта (`ROUNDUP(sa_len)` с `sizeof(int)`, `rawsock-getif.c:20–23, :46`); каждый `PF_ROUTE`-сокет
  видит все сообщения системы, поэтому ответ надо отбирать по `rtm_seq` и `rtm_pid` (`rawsock-getroute.c:183–196`). Источники XNU (`bsd/net/rtsock.c`) на этом
  хосте недоступны: утверждение о выравнивании и широковещании подтверждено поведением и макросами C-кода, а не чтением XNU; перепроверить в задаче 3 на реальном
  `RTM_GET`/`PF_ROUTE`. Имя интерфейса приходит как `sockaddr_dl` (`sdl_nlen`).
- **Windows.** `GetBestRoute2` для `0.0.0.0` не используется; маршруты по умолчанию берутся из `GetIpForwardTable2` (префикс длины 0). «Нет маршрута» может прийти как
  `ERROR_NOT_FOUND`, `ERROR_NETWORK_UNREACHABLE` или `ERROR_HOST_UNREACHABLE` (коды проверены по `windows-sys`; перечень возвращаемых ошибок — документация Microsoft
  `GetBestRoute2`, здесь не измерялся).
- **Ожидание плана (не выполнялось):** `--offline` preflight на Mac для `m05` (без `--adapter`, цель — адрес этого хоста) обязан отказать как `LocalTarget` через `lo0`.

## 7. Расхождения плана с кодом

1. `capture.rs:329–455` не содержит `isolation_permits` и `default_route`: в диапазоне только `isolation` (`:329`) и `check_isolation_snapshot` (`:427`);
   `isolation_permits` в `wire_suite.rs:2122`, функция `default_route` в `macos_lab.rs:444` (в `capture.rs` лишь ключ JSON `"default_route"` на `:353`).
2. `wire-lab.sh:47–56` покрывает re-exec, проверка `--suite` на `:42`, binding начинается на `:64`, а не `:60`; топология и seal `:144–190` верны.
3. `windows_suite.rs:884–922`: это тело раннера (начало сигнатуры на `:880`), а не обёртка вывода гостя; сам вывод гостя `:1367–1390`, `run.json` `:1392–1400` (как в сообщении координатора).
4. `main.rs:305` — не отдельная функция, а элемент списка внутри теста; `main.rs:174` — начало `#[cfg(test)] mod tests`.
5. Таблица кейсов и описание «ARP в 2.3 readiness»: строка про ARP находится в таблице на `readiness.md:83`.

## 8. Риски и замечания

- Стенд Windows `n2`: `raw_run_allowed: false` (`forwarding must be 0`); перед задачей 7 нужен чистый `vm-lab status`.
- Тесты `dump::` лаб-крейта нестабильны под полной нагрузкой (§2).
- Первое утверждение о XNU (выравнивание/широковещание) не подтверждено чтением исходников XNU (§6).
- Доступность `nlmsghdr`/`sockaddr_nl` из `libc` на Linux-цели не проверена компиляцией (§5).
