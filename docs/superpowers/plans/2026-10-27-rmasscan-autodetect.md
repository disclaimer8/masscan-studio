# rmasscan: живой скан из CLI с автоопределением адаптера и шлюза — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `rmasscan` получает живой скан из командной строки, как masscan: `sudo rmasscan 10.0.0.0/24 -p80,443 --rate 1000`.
Сканер сам определяет адаптер (интерфейс маршрута к целям), его IPv4 и MAC, IPv4 следующего хопа (шлюза) из
таблицы маршрутов и MAC шлюза через ARP-запрос, отправленный и принятый на том же raw-адаптере. Каждую часть можно
задать masscan-совместимыми флагами `--adapter`/`-e`, `--adapter-ip`/`--source-ip`, `--adapter-mac`/`--source-mac`,
`--router-ip`, `--router-mac`, `--source-port`. Работает на Linux (AF_PACKET), Windows (Npcap) и macOS (BPF) через
существующие адаптеры `rmasscan-net` и `rmasscan-engine`. Вывод этапа: строка masscan `Discovered open port N/tcp on IP`
на stdout за швом «приёмник результатов», в который этап 2 (форматы вывода) подключит свои форматы. `--iflist`
добавляется (он дёшев). Живые кадры только на запечатанных стендах: `netns` на minipc, `feth` на Mac, VM `n2` на home-pc.

**Architecture:** продуктовый код меняется в трёх местах. (1) `rmasscan-net` получает безопасный модуль `discover`
(чистая логика выбора адаптера, IP, MAC и следующего хопа над двумя швами `RouteTable` и `Interfaces`), безопасный
переносимый модуль `route_parse` (разбор ответов netlink, `rt_msghdr` и строк `MIB_IPFORWARD_ROW2` над простыми
полями, тестируемый на любой ОС) и по одному FFI-модулю на ОС, читающему состояние ядра в процессе: Linux rtnetlink
(`RTM_GETROUTE` запрос с `RTA_DST` и dump маршрутов по умолчанию) + `if_nameindex`/ioctl, macOS `PF_ROUTE` `RTM_GET` +
существующий `ifinfo` (`getifaddrs`), Windows `GetBestRoute2` + `GetIpForwardTable2` + `GetAdaptersAddresses`; плюс
безопасный модуль `arp_resolve` (синхронный резолвер над `Tx`/`Rx` с кодеком `rmasscan_core::arp` и инжектированными
часами). (2) `rmasscan-cli` становится `[lib]` + `[[bin]]`: библиотека `live.rs` (композиция `defaults → validate → detect
→ ARP на короткоживущем адаптере → ReadyPlan → open → Engine → события → приёмник`) за швом `Backend`, `output.rs` (трейт
`Sink` и интерактивная строка masscan), `args.rs`; бинарник только строит `OsBackend` (модуль `#[cfg(not(test))]`) и зовёт
`run`. Ни один unit-тест не достигает реального бэкенда. (3) `rmasscan-core` получает поле `router_ip` в
`ScanConfig`/`EffectiveConfig`. `open_explicit`, `AdapterBinding`, `ReadyPlan`, контракты engine и Studio не меняются.
Лаборатория получает режим `autodetect` в `capture isolation`, один офлайн-верификатор `autodetect-verify`, команду
`autodetect-suite` (Linux внутри `wire-lab.sh --suite autodetect`, macOS как пользователь в окне гранта плюс один
root-кейс по команде пользователя) и план `--plan autodetect` в `windows-suite`.

**Tech Stack:** Rust 1.99.1, существующий workspace (`clap 4.6.7`, `libc 0.2.191` — для Linux `rtmsg` объявляется
локально `repr(C)`, как уже сделано для других ABI-типов; `windows-sys 0.61.2` с уже включёнными
`Win32_NetworkManagement_IpHelper`/`Ndis`/`Networking_WinSock`, новых features не нужно; `getrandom 0.4.3` уже в
`Cargo.lock` у `rmasscan-lab`), `rmasscan_core::throttle::Clock` и `rmasscan_engine::fake::ManualClock` для
детерминированного времени, `rmasscan-lab` (`wire-lab.sh`, `capture dump|isolation`, `peer`, `macos-lab`, `vm-lab`,
`windows-suite`, `verify-wire`), системные `tcpdump`/`ip`/`ifconfig` только в лаборатории. Без Python, C, Swift.

**Spec:** [спека порта](../specs/2026-10-23-masscan-rust-port-design.md) §4.7 (адаптер, ARP, выбор интерфейса,
строки 320–329), §4.8 (`--offline`, строка 339), таблица Windows (строки 368, 382), §10 (строка 626: строка
`Discovered`); [спека Studio](../specs/2026-10-23-cross-platform-qt-rust-design.md) §0.1 (контракты engine, строки
84–115), §0.2 (строка «ARP: только кодек», строка 131); [готовность](../../experiments/2026-10-24-rmasscan-readiness.md)
(раздел 2.3 «ARP codec / ARP resolver», раздел 6 «сетевая интеграция (discovery/ARP, network identity)»);
[приёмка macOS BPF](../../experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md) §9; [приёмка Studio feth](../../experiments/2026-10-26-studio-mac-feth-raw-acceptance.md)
§9 (маскирование MAC, слепой `netstat`, mDNS хоста, незамеченный диалог); [Linux-приёмка](../../experiments/2026-10-23-rmasscan-stage2b-linux.md)
§0 (minipc: `sudo -n` без пароля, `wire-lab.sh` перезапускает себя через него); [приёмка Windows VM](../../experiments/2026-10-24-rmasscan-windows-vm-acceptance.md)
(строки 113–114: Npcap Admin-only, ssh-сессия гостя elevated), [доступ к VM](../../experiments/2026-10-24-windows-vm-access.md)
(management NIC гостя это QEMU user-mode NAT `10.0.2.15`); [README rmasscan](../../../rmasscan/README.md) («Отличия от
masscan»); [BENCHMARKS](../../../rmasscan/BENCHMARKS.md); стенды: [rust-lab.md](../../../rmasscan/docs/rust-lab.md),
[macos-feth-lab.md](../../../rmasscan/docs/macos-feth-lab.md), [windows-vm-lab.md](../../../rmasscan/docs/windows-vm-lab.md),
[windows-wire-lab.md](../../../rmasscan/docs/windows-wire-lab.md); планы-образцы `2026-10-25-rmasscan-windows-sendqueue.md`,
`2026-10-26-studio-mac-feth-raw.md`; pre-flight ревью `.superpowers/sdd/2026-10-27-rmasscan-autodetect/preflight-review.md`
(исправления M1–M6, S1–S13 и minor внесены в эту редакцию).

Репозиторий: `$REPO`, worktree `$REPO` (`masscan-studio-autodetect`), ветка `feat/rmasscan-autodetect` от `main`
`e00e970`. Репозиторий Rust-only. C-оракул `8e6b3b0`: исходники в закреплённом чекауте `$ORACLE_SRC` (на minipc
`$HOME/rmasscan-oracle/masscan`, тот же чекаут есть локально); в этом репозитории C-кода нет.

Решения пользователя (2026-10-27, обязательны): живые окна разрешены на всех трёх стендах (minipc netns через
существующее `sudo -n`; `n2` и VM на home-pc, агент может поднять их через `sudo -n`, если они не подняты; `feth` на
Mac с `up`/`down` пользователя), только `198.18.0.0/24`; `--seed` для живого скана необязателен (случайный и
печатается, как у masscan) и остаётся обязательным для `-sL`/`--echo`; root-кейс на Mac это одна строка Terminal
(`up` + `grant` + `autodetect-suite --root-case` под `sudo`). Для `--offline` план оставляет `--seed` обязательным: это
прочтение решения (оно называет только `-sL` и `--echo`), причина — golden-детерминизм трассы (решение 6).

## Исходное состояние и порядок

- CLI (`rmasscan-cli/src/main.rs:146–154`): ветки `--echo`, `-sL`, `--offline --packet-trace`; всё прочее —
  `Err("stage 1 supports only …")`. `for_each_probe` (`:31–62`) требует `--adapter-ip`, `--adapter-mac`, `--router-mac`,
  `--source-port` и строит `AdapterBinding { interface_id: adapter_name или "offline", … }`. `args.rs`: `--seed` уже
  `Option<u64>` (`:64`), отказ при `None`/0 в `to_config` (`:203–206`); `-e/--interface` с alias `adapter` «только
  записывается» (`:121–128`); `--source-port` с alias `adapter-port`. Нет `--router-ip`, `--iflist`, alias `--source-ip`/
  `--source-mac` (C принимает оба: `main-conf.c:2486`, `:2556–2557`). Crate **bin-only** (`Cargo.toml` без `[lib]`);
  `tests/differential.rs` запускает бинарник. Exit code: 0 или 1 (`main`, `:157–171`), BrokenPipe → 0. Существующие
  unit-тесты `main.rs`, которые после этого этапа дошли бы до ОС: `bad_inputs_are_fatal` (строка `:305`, аргументы
  `rmasscan 10.0.0.0/30 -p80 --seed 1`), `scan_without_offline_trace_is_rejected` (`:497–511`),
  `packet_trace_requires_adapter_options` (`:473–494`) — переписываются в задаче 5 (S9).
- Core: `ScanConfig` (`config.rs:96–119`) без `router_ip`; все литералы `ScanConfig { … }` в rmasscan и `studio-protocol`
  используют `..Default::default()`, добавление поля безопасно. `validate` (`:379–444`) уже содержит интернет-предохранитель
  masscan: `count_ipv4s() > 1e9` без `--exclude` → `ExcludeRequired` (`:430–435`, C `main.c:1232–1239`); `ZeroSeed` для
  List/Scan (`:439–441`), Echo принимает seed 0. `AdapterBinding` (`probe.rs:61–69`): `interface_id`, `link_type`,
  `source_ipv4`, `source_mac`, `next_hop_mac`, `source_ports` (ширина — степень двойки, `check_source_ports`); `ReadyPlan::new`
  (`:222–273`). ARP-кодек `arp.rs`: `encode_request` (`:61–72`, 60 байт, нулевое дополнение, побайтно как
  `stack-arpv4.c:125–160`), `PendingResolve::offer` (`:174–190`: только opcode 2, `target_ip == my_ip`, `target_mac ==
  my_mac`, `sender_ip == target_ip`, sender MAC unicast и равен Ethernet-источнику).
- Net: `open_explicit(&AdapterBinding)` (`lib.rs:284–307`) по ОС; `OpenedAdapter { io, stats, tx_mode }` с публичными
  полями, но `NetStatsHandle::new` `pub(crate)` (`lib.rs:232`) — подделать `OpenedAdapter` снаружи нельзя, поэтому шов
  CLI возвращает `AdapterPair` (M3). `verify_binding` Linux (`linux/mod.rs:358–393`: имя, ifindex, `ARPHRD_ETHER`; source
  IP/MAC с ОС не сверяются), macOS (`macos/ifinfo.rs:242–280`: `IFT_ETHER`, наличие 6-байтового адреса, заполнитель
  `02:00:00:00:00:00` проходит), Windows (`windows/adapter.rs:352–374`); на macOS и Windows `check_binding` требует только
  unicast `source_mac` и `source_mac != next_hop_mac`. RX-фильтры: Linux `ETH_P_ALL` на ifindex плюс
  `PACKET_IGNORE_OUTGOING` (`linux/socket.rs:74–81`), macOS BPF `own_mac_filter` (`macos/adapter.rs:128–143`,
  `:592–609`), Windows `not ether src <source_mac>` (`windows/adapter.rs:425–427`). Следствие: ARP-ответ шлюза (eth src =
  MAC шлюза) проходит в `Rx` на всех трёх ОС без изменений адаптеров. FFI-модули с `#[allow(unsafe_code)]` сегодня:
  `linux::socket`, `macos::{sys, ifinfo, process}`, `windows::{ffi, handle, loader, process, sys}`. Уже есть: `IfaceReport`
  и `macos::ifinfo::interfaces()` (`ifinfo.rs:190–227`, `mac_masked`), Linux `IfaceInfo` (`linux/socket.rs:213–249`:
  `if_nametoindex`, `SIOCGIFHWADDR`), Windows `adapter_mac_by_guid` (`windows/sys.rs:159–213`, `GetAdaptersAddresses`),
  `npf_guid` (`windows/inventory.rs:12`). Нет: маршрутов, списка IPv4 на Linux/Windows, резолвера ARP. `libc 0.2.191`:
  Linux `RTM_GETROUTE`, `RTA_*`, `RTN_*`, `rtattr`, `SIOCGIF*` есть, `rtmsg` нет (объявить локально); macOS `RTM_GET`,
  `RTA_DST`/`RTA_IFP`, `RTAX_*`, `RTF_*`, `rt_msghdr`, `sockaddr_dl` есть. `windows-sys`: `GetBestRoute2`,
  `GetIpForwardTable2`, `MIB_IPFORWARD_ROW2`, `IP_ADAPTER_ADDRESSES_LH`, `IF_TYPE_ETHERNET_CSMACD` (6),
  `IF_TYPE_IEEE80211` (71), `IF_TYPE_SOFTWARE_LOOPBACK` (24), `IfOperStatusUp` под уже включёнными features.
- Engine: `Tx`/`Rx` (`io.rs:45–108`), `Event::{Started, Progress, Results, CheckpointReady, Finished}` (`events.rs:77–93`),
  `EngineOptions::new(scan_id, attempt_id)` (`engine.rs:85`), `Engine::start` (`:693`), `start_with_clock` (`:704`,
  `Arc<dyn rmasscan_core::throttle::Clock + Send + Sync>`), `EngineHandle::{recv_event_timeout, join, outcome}`
  (`:930–962`); `wait` берётся из плана (`:64`). Кадры не-ответы (ARP во время скана) отбрасываются `parse_reply` в
  `discarded` (`:634–650`). `FakeAdapter` публичен: `set_responder`, `sent_frames`, `alive_handles`, `pair`, `reply_to_syn`;
  `ManualClock` публичен (`fake.rs:23`).
- Studio собирает `rmasscan-core/engine/net` из этого же дерева (`studio/Cargo.toml:21–23`); `Job::prepare`
  (`studio-protocol/src/lib.rs:75–160`) строит binding константами и зовёт `open_explicit`. Studio не меняется; API net
  только расширяется.
- C-оракул `8e6b3b0`, что именно делает masscan (`main-initadapter.c`): интерфейс = `rawsock_get_default_interface`
  (Linux `rawsock-getif.c:298–391`: dump `RTM_GETROUTE`, строка с dst 0; macOS `:55–178`: `RTM_GET` на `PF_ROUTE` с
  `RTA_DST|RTA_IFP` для 0.0.0.0; Windows `:416–495`: **последний** адаптер `GetAdaptersInfo` с непустым `GatewayList`,
  Ethernet **или Wi-Fi (IfType 71)**, имя `\Device\NPF_{GUID}`); MAC = `rawsock_get_adapter_mac` (`SIOCGIFHWADDR` /
  `GetAdaptersInfo` / `getifaddrs`, `:97–115`); IP = первый IPv4 интерфейса (`rawsock_get_adapter_ip`, `:126–147`); шлюз =
  `--router-ip`, иначе `rawsock_get_default_gateway(ifname)` — шлюз маршрута по умолчанию **этого** интерфейса (Linux
  `rawsock-getroute.c:338–421` dump, macOS `:110–230` `RTM_GET 0.0.0.0` с проверкой `RTA_IFP`, Windows `:444–570`
  `GatewayList`), без учёта целей; `--offline` → MAC шлюза **принудительно** фиктивный `66-55-44-33-22-11` даже при
  `--router-mac`, поиск маршрутизатора не выполняется (`:159–163`); ARP `stack_arp_resolve` (`stack-arpv4.c:103–262`):
  запрос сразу и затем раз в секунду, после ~11 с таймаут; принимается только opcode 2 с `ip_dst == my_ip`, `mac_dst ==
  my_mac`, `ip_src == your_ipv4`; при таймауте `FAIL: ARP timed-out resolving MAC address for router IF: "IP"` и три
  подсказки: `try "--router-ip 192.0.2.1" to specify different router`, `try "--router-mac 66-55-44-33-22-11" instead to
  bypass ARP`, `try "--interface eth0" to change interface`. Подсказки MAC/IP: `try something like "--source-mac
  00-11-22-33-44-55"`, `if it has no IP address, manually set with something like "--source-ip 198.51.100.17"`. Порт
  источника по умолчанию (`main.c:1315–1320`, `:185–186`): `first = p = 40000 + time % 20000`, `last = p + 16`, маска 16 →
  **два порта {p, p+16}**; у `AdapterBinding` ширина диапазона обязана быть степенью двойки, поэтому это не
  выражается — отклонение (решение 6). `--iflist` (`rawsock.c:199–224`): список `pcap_findalldevs` на stderr. Строка
  результата (`output.c:781–795`): `Discovered open port %u/tcp on %s` (39 символов для `80`/`10.0.0.1`), дополнение
  пробелами до 79 символов (здесь **40** пробелов), `\n`, `fflush`; закрытые порты по умолчанию не печатаются.
- Стенды: Linux `wire-lab.sh` (`:144–190`): `veth-a` в netns сканера с MAC `02:aa:00:00:00:01`, без IPv4 для оракула
  (`IP_A_LINK` пуст в `oracle-fixtures`), пир `veth-b` `02:aa:00:00:00:02` с `10.200.0.2-5/24`, постоянная соседская
  запись `IP_ADAPTER → MAC_A` на пире, **нет маршрута по умолчанию** (seal-проверки `:177`, `:184`), затем `capture
  isolation` (`:189`; `capture.rs:329–455`: отвергает любой маршрут по умолчанию/шлюз (`:447–449`) и работающий `route get
  8.8.8.8` (`:400`), пишет `default_route:false` константой (`:353`)); `sudo -n env` re-exec пробрасывает фиксированный
  список переменных и аргументов (`:47–56`); `case "$SUITE"` знает `oracle|rust|perf`. macOS `m1`: `feth4201`
  (`02:ac:00:00:00:01`, без IPv4) ↔ `feth4202` (`02:ac:00:00:00:02`, `198.18.0.2/30`), постоянная ARP `198.18.0.1 →
  02:ac:00:00:00:01` на `feth4202`; маршрут к `198.18.0.2` на хосте ведёт в `lo0`; `macos-lab status` требует «без inet на
  feth4201» (правило 2); закоммиченные `peer.pcap` Studio не содержат ARP. Windows `n2`: гость `Ethernet 2` =
  `\Device\NPF_{C4617223-…}`, `198.18.0.1/30`, **без шлюза**, management NIC `10.0.2.15` (QEMU user-mode NAT) держит
  маршрут по умолчанию; пир `lab0` `198.18.0.2`, MAC `02:57:4c:3d:2e:9b`; в закоммиченных захватах
  (`2026-10-25-rmasscan-windows-sendqueue-acceptance-raw/functional-r3/runs/c01…/peer.pcap`) пир спрашивает `who-has
  198.18.0.1`, а **ядро гостя отвечает 42-байтовым ARP-ответом с MAC сканера** — ARP ядра на проводе ожидаем; гостевой
  runner `windows_wire_run.ps1` исполняет `{"exe","argv"}` из JSON и пишет `stdout.txt` (при пустом stdout — ровно
  `"\n"`), `stderr.txt`, `exit.txt`; `windows-suite` требует `--fixtures`, манифест с `exe.build` «…wire_scan…» и
  фиксированным binding (`windows_suite.rs:1781`, `:2062`).
- Уроки: Darwin 27 отдаёт `02:00:00:00:00:00` вместо MAC непривилегированному ad-hoc-подписанному процессу; `netstat`
  слеп для потомков таких процессов; доступность route socket в процессе для ad-hoc-процесса на Darwin 27 **не
  проверена** (проверяется в задачах 0 и 3, S10); mDNS хоста на `feth4202` требует фильтра приватности; диалоги и
  подсказки посреди окна остаются незамеченными.

Порядок: **0 — база и контракты (чтение) → 1 — контракт CLI, `[lib]`, `router_ip`, приёмник результатов (офлайн) → 2 —
логика обнаружения над швами (офлайн, все ОС) → 3 — переносимые парсеры и ОС-бэкенды маршрутов и интерфейсов (чтение,
тесты на реальных хостах) → 4 — резолвер ARP (офлайн, FakeAdapter, ManualClock) → 5 — живой путь CLI, `--offline`,
`--iflist` (офлайн end-to-end на fake-бэкенде) → 6 — лаборатория: isolation-режим, suite, план Windows, верификатор,
документы (офлайн) → ревью, заморозка коммита `C` → 7 — живая приёмка на трёх стендах → 8 — отчёт, readiness, README, CI,
итоговое ревью, GO**. Задачи 1–6 не ждут стендов; живая часть без стенда NOT RUN и CI не подменяется.

## Global Constraints

- **Pure Rust.** Никакого C, C++, Python, Swift ни в репозитории, ни в инструментах, ни в CI. Language guard
  (`scripts/language-guard.sh`) PASS, `no_c_in_build` и `cargo deny check bans licenses sources` зелёные. Новые файлы
  evidence только из allowlist (`json pcap txt log err sha256 md`), pcap без сжатия. Agents могут звать `python3` ad hoc
  в своей оболочке; ничего в репозитории от него не зависит.
- **`unsafe`** только внутри FFI-модулей `rmasscan-net` с `#[allow(unsafe_code)]` в своём `mod.rs` и `SAFETY` на каждом
  блоке: существующие `linux::socket`, `macos::{sys, ifinfo, process}`, `windows::{ffi, handle, loader, process, sys}` и
  новые `linux::route` (netlink **и** ioctl интерфейсов — отдельного `linux::ifaces` нет), `macos::route`; Windows-часть
  добавляется в существующий `windows::sys` (новых Windows-модулей с `unsafe` нет). Заголовок `lib.rs` и комментарий в
  `rmasscan-net/Cargo.toml` перечисляют ровно этот список. Разбор ответов ядра живёт в безопасном переносимом
  `route_parse.rs`. `discover.rs`, `arp_resolve.rs`, `rmasscan-cli`, `rmasscan-lab` без `unsafe` (`forbid`). Обнаружение
  читает состояние ОС **в процессе**: Linux — rtnetlink (`RTM_GETROUTE` с `RTA_DST` для цели; dump таблицы main для
  маршрутов по умолчанию) и `if_nameindex` + ioctl (`SIOCGIFFLAGS`, `SIOCGIFHWADDR`, `SIOCGIFADDR`); macOS — `PF_ROUTE`
  `RTM_GET` и `getifaddrs`; Windows — `GetBestRoute2`, `GetIpForwardTable2`, `GetAdaptersAddresses` через существующий
  `windows-sys`. **Никогда не запускать `route`, `netstat`, `ip`, `ifconfig`, `arp`** из продукта: на macOS 27 их вывод
  отфильтрован для ad-hoc-подписанных вызывающих, а spawn хрупок.
- **Ни один unit- или интеграционный тест не достигает реального бэкенда.** `rmasscan_cli::run` принимает `&dyn
  Backend`; все тесты библиотеки используют `FakeBackend`, чей `open` **паникует**; `OsBackend` определён в модуле
  бинарника `src/os_backend.rs`, включённом только `#[cfg(not(test))]`, и `fn main` тоже под `#[cfg(not(test))]` (cargo
  компилирует bin-таргет под `cfg(test)`, иначе сборка тестов не соберётся — N2); бинарник тестов не содержит (все
  прежние unit-тесты переехали в библиотеку). Интеграционные тесты запускают бинарник (он собирается **без**
  `cfg(test)` и содержит `OsBackend`) **только через один помощник** `tests/common/spawn.rs::spawn_readonly(argv)`,
  который паникует, если argv не содержит ни одного из `--iflist`, `--offline`, `-sL`/`--list`, `--echo`/`--echo-all`,
  `--help`/`-V`; `differential.rs` и `detect_readonly.rs` идут через него, а кейс `--banners 10.0.0.0/24 -p80` в
  `differential.rs` заменяется на неизвестный флаг плюс `--offline` (`--nonsense --offline 10.0.0.0/30 -p80 --seed 1`),
  чтобы этап 3 не превратил его в живой скан /24 (N3). Причина: полные тесты GO идут на elevated госте Windows с Npcap
  Admin-only, чей management NIC это QEMU NAT — тест, дошедший до `open_explicit`, послал бы ARP к `10.0.2.2` и SYN в
  реальную сеть через slirp. Гарантия структурная (границы модулей, N2, N3); тест `os_backend_is_absent_under_test`
  (компиляция) и ревью Focus 1 это закрепляют.
- **Живые кадры только на запечатанных стендах:** Linux `netns` на minipc (внутри `wire-lab.sh`), macOS `feth` `m1` (по
  действиям пользователя), Windows VM `n2` на home-pc (агент может поднять VM/стенд через `sudo -n`, решение
  пользователя). Никогда на реальной LAN: ARP к реальному шлюзу это живой кадр в сети пользователя и **запрещён**.
  Чтение таблицы маршрутов и интерфейсов (`--iflist`, `--offline`, тесты бэкендов) на реальных хостах разрешено; агент в
  своей оболочке может читать `route -n get default`/`ip route` для сверки (задачи 0, 3). Лабораторные правила: никаких
  изменений firewall, маршрутов, DNS, NIC на реальных хостах; мост лаборатории без uplink; сканируются только адреса
  `198.18.0.0/24`; пароли не попадают ни в репозиторий, ни в evidence; Npcap не поставляется. **Детекционный preflight**
  перед каждым живым кейсом, который зависит от маршрутизации на хосте с двумя NIC (`w01`, `w06`, `m05`): тот же
  `rmasscan --offline` с теми же целями; живой кейс идёт только если результат preflight **равен ожидаемому обнаружению
  кейса** (`w01`/`w06`: `[+] interface = Ethernet 2`; `m05`: отказ `LocalTarget` «address of this host (route via
  lo0)»), иначе NOT RUN (R1).
- **Автоопределение проверяемо на стендах.** Чего не хватало, меняется **внутри запечатанного пространства имён**:
  только Linux netns сканера получает IPv4 `198.18.0.1/24` на `veth-a`, маршрут по умолчанию `via 198.18.0.2` (пир, в
  той же netns-паре, без uplink) и постоянные соседские записи `198.18.0.2–.5 → 02:aa:00:00:00:02` (чтобы ядро сканера
  не слало собственных ARP-запросов); `capture isolation` получает режим `autodetect` ровно под это (M4), seal-проверки
  `wire-lab.sh` для `--suite autodetect` — тоже. Отмена: удаление netns по окончании (существующий cleanup скрипта).
  Стенды macOS и Windows **не меняются**: там автоопределение проверяется в тех частях, которые стенд допускает,
  остальное через переопределения и отказы (решение 8).
- **Действия пользователя.** Каждый `sudo` на Mac делает пользователь голыми командами Terminal из одной таблицы, число
  минимально: одна chained-строка «`up` + `grant` + root-кейс», одно `down` (оно же revoke). Никакого revoke/grant
  посреди окна. На minipc агенты используют существующее `sudo -n` (Linux-приёмка §0); на home-pc `a1` имеет `sudo -n`
  (`rust-lab.md:158–162`); задача 0 **проверяет** оба (`sudo -n true`), а не предполагает.
- **Правила доказательств:** независимые свидетели (`tcpdump`/`capture dump` на стороне пира и на uplink/`eno1`) и
  вердикты верификатора; INVALID/NOT RUN никогда не повышаются; sha256 до копирования (`hashes-before-copy.txt`), затем
  `MANIFEST.sha256`; pcap без сжатия; личные пути скраблены при записи (`$HOME`, `$REPO`, `$SCRATCH`); **privacy-скан**
  каждого файла evidence перед попаданием в публичный репозиторий: ни hostnames, ни имён учётных записей, ни
  mDNS-идентичностей, ни инвентарей приложений; **полный вывод `--iflist` никогда не сохраняется** — suite проверяет его на
  месте и хранит только строку интерфейса стенда, число строк и sha256 (M6); на macOS свидетель пира с фильтром `not
  (ether src 02:ac:00:00:00:02 and udp port 5353)`, как в приёмке Studio.
- **Гигиена агентов.** Фиксированные приватные `CARGO_TARGET_DIR` по роли (`$SCRATCH/target-impl`, `target-review`,
  `target-live`), `CARGO_INCREMENTAL=0`, каталоги не делятся и удаляются по окончании роли; экспорты `git archive`
  прежних коммитов удаляются (на home-pc только `~/winvm/build/<текущий sha>`, на госте только `C:\Users\lab\src\rmasscan-<sha>`,
  на minipc только текущая сборка); отдельные target-каталоги при сравнении экспортов. Тесты не зависят от точности
  `sleep` (часы инжектируются). Никакой самодельной сложности: ни одного механизма, которого цель не требует (нет
  per-target ARP-таблицы, нет кэша ARP, нет фонового резолвера, нет строки статуса, нет обработчика Ctrl-C и
  `paused.conf`, нет численных индексов адаптеров, нет IPv6/VLAN/туннелей).
- **GO только при зелёном CI на точном HEAD** (`rmasscan`, `Studio`, `language-guard`: `ubuntu-24.04`, `macos-14`,
  `windows-2022`) и после полных тестов на трёх ОС (Mac локально: `cargo test --locked --workspace` в `rmasscan/` и
  `cargo xtask test` в `studio/`; minipc Linux; гость Windows на полном дереве) перед push.
- Runtime остаётся: IPv4/TCP, один адаптер, один следующий хоп, TX=1, RX=1, shard 1/1, retries 0, rounds 14; контракты
  engine §0.1 не меняются; `wire_scan` и Studio не трогаются.

## Review Focus

1. **Ни одного кадра до скана, кроме ARP к одному адресу, и ни одного кадра из тестов.** Единственный кадр до engine
   это 60-байтовый ARP-запрос `encode_request` «who has <next hop>» с broadcast-назначением, отправленный с выбранного
   интерфейса; его цель равна ровно одному адресу, напечатанному в `[+] router-ip`; при `--router-mac`, `--offline`,
   `--iflist`, любом отказе обнаружения и любой ошибке открытия кадров нет. ARP-адаптер открывается отдельно и
   закрывается до открытия адаптера engine. `OsBackend` недостижим под `cargo test` (задачи 1, 4, 5; верификатор 6: число
   и цель ARP-запросов сканера в каждом прогоне, ARP ядра считается отдельно).
2. **Порядок и честность обнаружения.** `defaults (seed, порт) → validate` (включая `ExcludeRequired`) → `detect` (без
   привилегий, без spawn, цели-пробы только unicast) → печать `[+]` → ARP → `ReadyPlan` → `open` → engine. Заполнитель
   `02:00:00:00:00:00` и нулевой MAC никогда не становятся source MAC; отказ называет причину и подсказки masscan
   дословно; `--adapter` с несуществующим, выключенным или не-Ethernet интерфейсом отказывает до открытия; маршруты
   по умолчанию берутся dump-ом/таблицей, не lookup-ом `0.0.0.0` (задачи 2, 3, 5).
3. **Engine, net-адаптеры, Studio не меняются.** `open_explicit`, `AdapterBinding`, `ReadyPlan`, `Tx`/`Rx`, события,
   `wire_scan`, Studio компилируются и тестируются без правок; `[+] finished` печатает `sent` engine, и верификатор
   требует `sent == SYN сканера на проводе` (задачи 4, 5, 7).
4. **Паритет с masscan там, где решено, и явные отклонения.** Строка `Discovered` побайтно (39 + 40 пробелов + `\n` для
   `80`/`10.0.0.1`, flush, только open); `--offline` принудительно с фиктивным MAC шлюза `66-55-44-33-22-11` и без поиска
   маршрутизатора; подсказки отказов дословно (`--source-mac`, `--source-ip`, `--router-ip`, `--router-mac`,
   `--interface`) и алиасы `--source-ip`/`--source-mac` приняты; Windows Wi-Fi (IfType 71) принимается как Ethernet-кадры;
   отклонения (маршрут к целям вместо маршрута по умолчанию, ARP к единственной on-link цели, `--seed` из энтропии, один
   порт источника вместо {p, p+16}, `--iflist` своим форматом, `[+]` всегда) записаны в README «Отличия» и доказаны
   парити-прогоном с C-оракулом на minipc (задачи 1, 5, 6, 7).
5. **Ворота доказательств.** Три стенда, статус до/после, 0 кадров лаборатории на uplink/`eno1`, свидетель пира полный,
   хэши до копирования, INVALID/NOT RUN не повышаются, privacy-скан evidence (iflist в редуцированной форме); изменение
   стенда только внутри netns Linux, с режимом isolation `autodetect` и записанной отменой; preflight перед
   маршрутозависимыми кейсами на хостах с двумя NIC (задачи 6, 7, 8).

## Карта файлов

- Изменить `rmasscan/crates/rmasscan-core/src/config.rs` (`router_ip` в `ScanConfig`/`EffectiveConfig`, `echo`,
  `read_paused_conf`), его тесты.
- Создать `rmasscan/crates/rmasscan-net/src/discover.rs` (+ `discover_tests.rs`), `src/route_parse.rs` (+ тесты,
  безопасный, переносимый), `src/arp_resolve.rs` (+ `arp_resolve_tests.rs`), `src/linux/route.rs`, `src/macos/route.rs`;
  изменить `src/lib.rs` (заголовок с перечнем `unsafe`-модулей; экспорт `discover`, `arp_resolve`, `os_route_table()`,
  `os_interfaces()`), `src/linux/mod.rs`, `src/macos/mod.rs`, `src/macos/ifinfo.rs` (`interfaces()` → `Iface`),
  `src/windows/mod.rs`, `src/windows/sys.rs` (`adapters()`, `best_route()`, `forward_table()`), `Cargo.toml` (комментарий о
  модулях с `unsafe`; новых зависимостей нет).
- Изменить `rmasscan/crates/rmasscan-cli/Cargo.toml` (`[lib]` + `[[bin]]`, зависимости `rmasscan-engine`, `rmasscan-net`,
  `getrandom`), `src/args.rs` (`--router-ip`, `--iflist`, алиасы `--source-ip`/`--source-mac`, тексты help), `src/main.rs`
  (тонкий бинарник, `#[cfg(not(test))] fn main`), `tests/differential.rs` (через `spawn_readonly`, кейс `--banners`
  заменён); создать `src/lib.rs` (`pub mod args; pub mod live; pub mod output; pub fn run`), `src/live.rs` (задача 1:
  минимальный `Backend`; задача 5: полный), `src/output.rs`, `src/os_backend.rs` (`#[cfg(not(test))]`),
  `tests/common/spawn.rs` (`spawn_readonly`), `tests/live_fake.rs`, `tests/detect_readonly.rs`.
- Создать `rmasscan/crates/rmasscan-lab/src/autodetect_suite.rs` (+ `autodetect_suite_tests.rs`),
  `src/autodetect_verify.rs` (+ `autodetect_verify_tests.rs`); изменить `src/{lib,main}.rs` (подкоманды),
  `src/capture.rs` (+ `tests/capture.rs`: режим isolation `autodetect`), `src/windows_suite.rs` (+ `windows_suite_tests.rs`:
  `--plan autodetect`, `--fixtures` необязателен для него, `exe.build` и binding по плану), `src/verify.rs` (делегирование
  плана `autodetect`), `scripts/wire-lab.sh` (`--suite autodetect`: стенд, seal, re-exec, `--rmasscan`),
  `rmasscan/docs/rust-lab.md`, `rmasscan/docs/macos-feth-lab.md`, `rmasscan/docs/windows-vm-lab.md`.
- Изменить `rmasscan/README.md` («Команды», «Отличия от masscan», «Ограничения», «Статус»),
  `docs/experiments/2026-10-24-rmasscan-readiness.md` (строка ARP/discovery в 2.3 и новая строка таблицы 1),
  `docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md` §0.2 (строка ARP), `.github/workflows/rmasscan.yml`
  (комментарий: живые autodetect-прогоны вне CI).
- Создать `docs/experiments/2026-10-27-rmasscan-autodetect-baseline.md`,
  `docs/experiments/2026-10-27-rmasscan-autodetect-acceptance.md`,
  `docs/experiments/2026-10-27-rmasscan-autodetect-acceptance-raw/{linux-r1,windows-r1,macos-r1,macos-root-r1,verification,README.md,MANIFEST.sha256}`.

## Константы (единые для всех задач)

| Параметр | Значение |
| --- | --- |
| ARP | `ARP_INTERVAL` 1 с, `ARP_TIMEOUT` 10 с по инжектированным часам: запросы в t = 0, 1, …, 9 с (ровно 10), отказ в 10 с; `recv` с дедлайном `MAX_IO_TIMEOUT` 50 мс; ARP-binding: `next_hop_mac = ff:ff:ff:ff:ff:ff`, `source_ports` плана; «ARP сканера» в верификаторе = ARP-запрос с eth src = source MAC ровно 60 байт с нулевым дополнением (любой target IP), затем проверка target = `router-ip` и байтов `encode_request`; «ARP ОС» = 42-байтовые запросы и кадры opcode 2 с MAC сканера |
| Тексты отказов | строки C как есть: `[-] FAIL: …` и строки `    [hint] …`/` [hint] …` дословно, без обёртки `rmasscan: error:`; exit 1 |
| Фиктивный MAC шлюза `--offline` | `66-55-44-33-22-11`, принудительно (и при `--router-mac`), поиска маршрутизатора нет (C `main-initadapter.c:159–163`) |
| Значения по умолчанию | порт источника: один порт `40000 + unix_time % 20000` (C: {p, p+16}, отклонение, решение 6); seed живого скана: 64 бита `getrandom`, ≠ 0, печатается; rate 100, wait 10 |
| Цели-пробы обнаружения | первый и последний **unicast**-адрес итогового набора: пропускаются `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/3` (в т. ч. `255.255.255.255`); если unicast-адресов нет — отказ `NoUnicastTargets` |
| Строка результата | `Discovered open port {port}/tcp on {ip}` + пробелы до 79 символов + `\n` (для `80`/`10.0.0.1`: 39 + 40 + 1 = 80 байт), flush на строку; только open; пустой stdout допустим (нет open-портов или отказ; гостевой runner пишет `"\n"`, верификатор считает это пустым) |
| Строки stderr обнаружения | `[+] interface = NAME (detected: route to IP \| given)`, `[+] source-mac = xx-xx-xx-xx-xx-xx (detected \| given)`, `[+] source-ip = A.B.C.D (detected \| given)`, `[+] router-ip = A.B.C.D (route gateway \| on-link target \| interface default gateway \| given) \| none (offline)`, `[+] router-mac = … (arp: N requests, T ms \| given \| offline)`, `[+] seed = N (given \| entropy)`, `[+] source-port = N[-M] (given \| time)`, `[+] finished: Completed\|Stopped\|Failed(…), sent N, replies N, open N` |
| Стенд Linux `autodetect` | netns `wl-scan-*`/`wl-peer-*`, `veth-a` `02:aa:00:00:00:01` **`198.18.0.1/24`**, `veth-b` `02:aa:00:00:00:02` `198.18.0.2-5/24`, `default via 198.18.0.2 dev veth-a` в netns сканера, постоянные neigh в netns сканера `198.18.0.2-5 → 02:aa:00:00:00:02` на `veth-a`, постоянный neigh `198.18.0.1 → 02:aa:00:00:00:01` на пире, responder: 80 и 8080 открыты, остальные RST; переменные задаёт сам `wire-lab.sh --suite autodetect` (без новых env в re-exec) |
| Стенд macOS `m1` | без изменений: `feth4201` `02:ac:00:00:00:01` без IPv4, `feth4202` `02:ac:00:00:00:02` `198.18.0.2/30`, слушатели `8000-8007` (`peer listen`), uplink-фильтр `macos_lab::UPLINK_FILTER`, свидетель пира с фильтром приватности |
| Стенд Windows `n2` | без изменений: `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}` = `Ethernet 2`, `198.18.0.1/30`, MAC `52:54:00:04:80:a9`, без шлюза; пир `198.18.0.2` `02:57:4c:3d:2e:9b`, слушатели `80,443,8000-8007`, `eno1`-фильтр как в приёмке Windows; ARP-ответы ядра гостя на `who-has 198.18.0.1` ожидаемы (42 байта, считаются как `os_arp`) |
| Общие аргументы кейсов | `--seed 1 --rate 100 --wait 3` (где не сказано иное); порты Linux `80,81,8080`, Windows `80,443,8000-8007,8099`, macOS `8000-8007,9000-9003` |
| Кейсы Linux | `l01_auto` (`198.18.0.2`, без флагов адаптера), `l02_auto_multi` (`198.18.0.2-198.18.0.5`), `l03_adapter` (`--adapter veth-a`), `l04_adapter_ip` (`--adapter-ip 198.18.0.1`), `l05_adapter_mac` (`--adapter-mac 02-aa-00-00-00-01`), `l06_router_ip` (`--router-ip 198.18.0.3`), `l07_router_mac` (`--router-mac 02-aa-00-00-00-02`), `l08_source_port` (`--source-port 50000-50015`), `l09_arp_timeout` (`--router-ip 198.18.0.9`), `l10_no_such_adapter` (`--adapter nosuch0`), `l11_parity` (оракул и rmasscan, `198.18.0.2-198.18.0.5 -p80,8080 --source-port 40000`, без флагов адаптера), `l12_iflist` (оба `--iflist`: проверка на месте, хранится редуцированная форма) |
| Кейсы Windows | `w01_auto` (после preflight), `w02_adapter_npf`, `w03_adapter_friendly` (`--adapter "Ethernet 2"`), `w04_router_mac`, `w05_arp_timeout` (`--router-ip 198.18.0.3`), `w06_multi_no_gateway` (`198.18.0.2-198.18.0.3`, после preflight: отказ), `w07_iflist`, `w08a_restricted_iflist` (ограниченный токен: `--iflist` rc 0), `w08b_restricted_scan` (ограниченный токен: отказ rc 1 любого вида, 0 кадров); на Windows файлы прогона называются `guest-stdout.txt`/`guest-stderr.txt`/`guest-exit.txt`, `run.json` не строится |
| Preflight (`w01`, `w06`, `m05`) | `rmasscan --offline` с теми же целями на том же хосте перед живым кейсом; результат обязан **равняться ожидаемому обнаружению кейса**: `w01`/`w06` → `[+] interface = Ethernet 2`; `m05` → отказ `LocalTarget` (route via `lo0`); иначе кейс NOT RUN |
| Кейсы macOS (пользователь, грант) | `m01_user_masked` (`--adapter feth4201 --adapter-ip 198.18.0.1 --router-ip 198.18.0.2`: отказ «os-masked»), `m02_user_explicit` (+ `--adapter-mac 02-ac-00-00-00-01`: ARP, скан), `m03_user_router_mac`, `m04_user_arp_timeout` (`--router-ip 198.18.0.3`), `m05_user_no_adapter` (после preflight; без `--adapter`: отказ «address of this host»), `m06_user_no_ip` (без `--adapter-ip`: отказ «no IP address»), `m07_user_iflist` |
| Кейсы macOS (root, действие B) | `m10_root_auto_mac` (`--adapter feth4201 --adapter-ip 198.18.0.1 --router-ip 198.18.0.2`: MAC определён, ARP, скан), `m11_root_iflist` (строка `feth4201` с настоящим MAC) |
| Ожидания отказов | exit 1, 0 кадров сканера на проводе (ARP-таймаут: ровно 10 запросов с шагом 1 ± 0.3 с, 0 SYN), stderr с `FAIL:` и подсказками masscan |
| Каталог прогона | `runs/<tag>/{argv.json, expect.json, stdout.txt, stderr.txt, exit.txt (Windows: guest-stdout.txt, guest-stderr.txt, guest-exit.txt), detected.json, peer.pcap, capture.json\|peer.err, status-pre.json, status-post.json (mac/win), uplink.pcap+uplink.err (mac) \| isolation.json (linux), preflight.txt (w01, w06, m05), hashes-before-copy.txt}`; iflist-кейсы: `iflist.json` `{rc, lines, sha256, stand_line}` вместо вывода и без `stdout.txt`/`guest-stdout.txt` (на Windows редукция делается на home-pc в рабочем каталоге до записи каталога прогона); `l11_parity` дополнительно `oracle/{stdout,stderr,exit}.txt`, `oracle.pcap` |
| Доступ | minipc `ssh minipc`, `sudo -n` (проверить); home-pc `a1` `sudo -n` (проверить); гость `ssh -J home-pc -p 2222 lab@127.0.0.1` (elevated, Npcap Admin-only); Mac: действия пользователя |

## Задача 0. База и контракты (чтение, без кода)

**Files:** создать `docs/experiments/2026-10-27-rmasscan-autodetect-baseline.md`.

**Constraints:** приватный `CARGO_TARGET_DIR` (`target-impl`), `CARGO_INCREMENTAL=0`; ни одного кадра, ни одного
`sudo` на Mac; стенды только читаются; никаких команд, меняющих хосты; чтение маршрутов реальных хостов только в
оболочке агента и без копирования вывода в evidence.

- [ ] Выписать контракты с номерами строк (проверенные места, не пересказ): CLI `main.rs:31–62`, `:111–155`, `:305`,
  `:473–511`, `args.rs:64`, `:121–128`, `:203–206`, `Cargo.toml` (bin-only); core `config.rs:96–119`, `:379–444`,
  `probe.rs:61–69`, `:222–273`, `arp.rs:61–72`, `:144–191`; net `lib.rs:121–133`, `:232`, `:284–307`, `linux/mod.rs:358–393`,
  `:404–420`, `linux/socket.rs:74–81`, `:213–249`, `macos/ifinfo.rs:190–227`, `:242–280`, `macos/adapter.rs:128–143`,
  `:522–545`, `:592–609`, `windows/adapter.rs:352–374`, `:425–427`, `windows/sys.rs:159–213`, `windows/inventory.rs:12`,
  `mod.rs` трёх ОС (`allow(unsafe_code)`); engine `io.rs:45–108`, `events.rs:77–93`, `engine.rs:64–98`, `:693–712`,
  `:930–962`, `fake.rs:23`; lab `wire_suite.rs:219–232`, `:472–545`, `capture.rs:8–40`, `:329–455` (`check_isolation_snapshot`,
  `isolation_permits`, `default_route`), `pcap.rs` (`read_pcap_records`, `is_syn`, `compare_streams`, `encode`),
  `verify.rs:385` (`plan_frames`, ключи `wire_scan`), `macos_suite.rs:472–505`, `:527–565`, `windows_suite.rs:884–922`,
  `:1781`, `:2062`, `scripts/wire-lab.sh:47–56`, `:60–80`, `:144–190`, `scripts/windows_wire_run.ps1`; Studio
  `studio-protocol/src/lib.rs:75–160`, `studio-runner/src/main.rs:48–79`.
- [ ] Записать поведение C-оракула чтением `$ORACLE_SRC` (локальный чекаут `8e6b3b0`; на minipc `$HOME/rmasscan-oracle/masscan/src`):
  `main-initadapter.c` (интерфейс, MAC, IP, маршрутизатор, `--offline` принудительный MAC, тексты FAIL и подсказок
  дословно), `stack-arpv4.c:103–262`, `rawsock-getif.c` по ОС (Windows `:455–485`: **последний** адаптер со шлюзом, Ethernet
  или Wi-Fi 71), `rawsock-getroute.c` по ОС, `rawsock-getip.c`, `rawsock-getmac.c`, `rawsock.c:199–224`, `output.c:748–800`
  (дополнение: 39 символов + 40 пробелов для `80`/`10.0.0.1`), `main.c:1228–1239`, `:1275–1292`, `:1315–1320` и `:185–186`
  (порты {p, p+16}), `main-conf.c:2474–2500`, `:2486`, `:2556–2557`, `:2587–2641`, `:2820–2830`. Записать таблицу
  «matched / deviate» (решения 1–7) и подтвердить, что `check_source_ports` не выражает {p, p+16}.
- [ ] Доказать чтением, что ARP-ответ проходит RX-фильтры трёх адаптеров без изменений и что `check_binding`
  macOS/Windows принимает `next_hop_mac = ff:ff:ff:ff:ff:ff` при unicast `source_mac`; что `NetStatsHandle::new` `pub(crate)`
  (шов `open` возвращает `AdapterPair`); что `libc` не содержит `rtmsg` для Linux; что в `windows-sys` нужные API под уже
  включёнными features.
- [ ] Семантика маршрутов, на которой строится задача 3: Linux — не-dump `RTM_GETROUTE` для `0.0.0.0` отвечает `local
  0.0.0.0 dev lo` (`RTN_LOCAL`), поэтому маршруты по умолчанию берутся dump-ом; Darwin — sockaddr в сообщениях route socket
  выровнены по 4 байта, каждый `PF_ROUTE`-сокет видит все сообщения (фильтр по `rtm_seq`/`rtm_pid`); Windows — `GetBestRoute2`
  для `0.0.0.0` не используется (маршруты по умолчанию из `GetIpForwardTable2`), «нет маршрута» может прийти как
  `ERROR_NOT_FOUND`/`ERROR_NETWORK_UNREACHABLE`/`ERROR_HOST_UNREACHABLE`. Записать с ссылками на исходники C/XNU/документацию.
- [ ] Снять состояние только чтением: `ssh minipc 'sudo -n true && ip netns list && sha256sum ~/rmasscan-oracle/masscan/bin/masscan'`
  (ожидается `8afc8ec8…`), `ssh home-pc 'sudo -n true; pgrep -af qemu; sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab status --run-id n2 --manifest ~/winvm/lab/n2.json --host-only'`,
  `ssh -J home-pc -p 2222 lab@127.0.0.1 'ver && whoami /groups | findstr /i "S-1-16-12288"'` (elevated), на Mac `"$LAB"
  macos-lab status --run-id m1` (ожидаемо rc 3), `sw_vers`, `rustc --version`; на Mac в оболочке агента `route -n get
  default` (только интерфейс и шлюз, в baseline записывается лишь факт «есть/нет» — S10, сверка с задачей 3). Записать,
  какие действия пользователя потребуются в задаче 7 (A, B, F) и что B1/B2 при необходимости сделает агент.
- [ ] Дополнения по re-check r1 (§4): (1) C FAIL-строки несут префикс `[-] ` (`main-initadapter.c:52`, `:102`, `:134`,
  `:195`), подсказки дословны — записать форму rmasscan (решение 7: `[-] FAIL:` + подсказки печатаются как есть); (2) C
  `--offline` всё равно ищет интерфейс по умолчанию, если нет `--interface` (`:44–57`) — в таблицу matched/deviate как
  отклонение «герметичный offline»; (3) часы: `Clock` это `now_micros`/`sleep_micros` (`throttle.rs:22–30`),
  `FakeAdapter::with_clock` продвигает `ManualClock` на таймаут `recv` при простое (`fake.rs:436–441`),
  `Engine::start_with_clock` помечен `#[doc(hidden)]` «не часть стабильного API» (`engine.rs:700–711`) — продукт его
  использует (решение 4); (4) cargo собирает bin-таргет под `cfg(test)` (`rmasscan-cli/Cargo.toml:8` без `test = false`),
  а бинарник для интеграционных тестов — без `cfg(test)`; (5) `windows-suite` всегда переносит гостевые
  `stdout.txt`/`stderr.txt`/`exit.txt` в каталог прогона как `guest-*.txt` (`windows_suite.rs:1367–1390`) и строит
  `run.json` из JSON-строки stdout (`:1392–1400`); (6) ожидаемый preflight `m05` это отказ `LocalTarget` через `lo0`, не
  NIC стенда.
- [ ] На Mac: `cargo fmt --all --check`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo test
  --locked --workspace` в `rmasscan/`, `cargo xtask test` в `studio/`, `bash scripts/language-guard.sh`; записать rc и
  строки `test result`. Записать базу: readiness «ARP: только кодек, resolver и discovery шлюза нет нигде».
  Commit: `docs(cli): autodetect stage baseline and contracts`.

**GREEN:** документ существует, все цифры с командами, проверки rc 0, language guard PASS, таблица паритета C заполнена
по строкам, `sudo -n` на minipc и home-pc подтверждён или честно записан как недоступный (тогда соответствующий стенд
NOT RUN до решения пользователя), семантика маршрутов трёх ОС записана.

## Задача 1. Контракт CLI: `[lib]`, `--router-ip`, `--iflist`, алиасы, seed по операции, приёмник результатов (офлайн)

**Files:** изменить `rmasscan-core/src/config.rs` и тесты, `rmasscan-cli/Cargo.toml`, `src/args.rs`, `src/main.rs`,
`tests/differential.rs`; создать `src/lib.rs`, `src/output.rs`, `src/live.rs` (минимальный `Backend`, N1),
`src/os_backend.rs` (заглушка, `#[cfg(not(test))]`), `tests/common/spawn.rs` (N3).

**Constraints:** `#![forbid(unsafe_code)]`; golden-тесты `-sL`/`--echo`/`--packet-trace` остаются побайтно зелёными;
бинарник тестов не содержит и `fn main` под `#[cfg(not(test))]` (N2); все spawn-ы бинарника в интеграционных тестах
через `spawn_readonly` (N3); `live::Backend` в этой задаче минимален и не зависит от задач 2 и 4 (N1);
`--seed` обязателен и ≠ 0 для `-sL`, `--echo`, `--offline` (решение по операции **до** `validate`, чтобы `--echo` без
seed не печатал `seed = 0`), необязателен только для живого скана (задача 5 подставляет энтропию до `validate`);
`--iflist` взаимоисключает `-sL`/`--echo`/`--packet-trace`/`--offline` **и** позиционные цели/`--range`; существующие
тесты `unsupported_option_errors` (уже покрывают `--banners`, `-oX`) не меняются; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// rmasscan-core/src/config.rs
pub struct ScanConfig { /* … */ pub router_ip: Option<u32>, /* … */ }      // main-conf.c:2626–2641, один адрес
impl EffectiveConfig { pub fn router_ip(&self) -> Option<u32>; }
// echo: строка `router-ip = A.B.C.D` только при Some, в позиции masscan_echo_nic (main-conf.c:376–378) после
// adapter-mac; read_paused_conf принимает ключ `router-ip`.

// rmasscan-cli/Cargo.toml: [lib] path = "src/lib.rs" (name rmasscan_cli) + [[bin]] name = "rmasscan" path = "src/main.rs"
// rmasscan-cli/src/lib.rs
#![forbid(unsafe_code)]
pub mod args; pub mod live; pub mod output;
pub fn run(cli: &args::Cli, backend: &dyn live::Backend, out: &mut dyn Write, log: &mut dyn Write) -> Result<(), String>;
// rmasscan-cli/src/live.rs (в этой задаче): минимальный шов, который задача 5 расширяет методами routes/interfaces/open/…
pub trait Backend { fn entropy64(&self) -> u64; fn unix_time(&self) -> u64; }
// run: --iflist и живой скан пока → Err("not yet available in this build") (задача 5 заменяет); -sL/--echo/--offline как прежде.
// rmasscan-cli/src/os_backend.rs (бинарник, #[cfg(not(test))]): pub struct OsBackend; impl Backend (getrandom, SystemTime).
// rmasscan-cli/src/main.rs: #[cfg(not(test))] mod os_backend; #[cfg(not(test))] fn main() { … rmasscan_cli::run(&cli, &OsBackend, …) }
// rmasscan-cli/tests/common/spawn.rs: pub fn spawn_readonly(argv: &[&str]) -> Output — паникует, если argv не содержит
//   --iflist | --offline | -sL | --list | --echo | --echo-all | --help | -V; единственный путь к CARGO_BIN_EXE_rmasscan в тестах.
// rmasscan-cli/src/args.rs
#[arg(long = "router-ip", value_name = "IP")] pub router_ip: Option<String>,   // один IPv4
#[arg(long = "iflist", conflicts_with_all = ["targets","range","list","echo","echo_all","packet_trace","offline"])] pub iflist: bool,
#[arg(long = "adapter-ip", alias = "source-ip", …)]   // C main-conf.c:2486
#[arg(long = "adapter-mac", alias = "source-mac", …)] // C main-conf.c:2556
// --seed остаётся Option<u64>; to_config больше не отказывает при None (cfg.seed = 0); Some(0) по-прежнему ошибка.
pub enum SeedPolicy { Required, Entropy }           // Required: -sL, --echo, --offline; Entropy: живой скан
pub fn seed_policy(cli: &Cli) -> SeedPolicy;
// run (lib.rs): при Required и cli.seed == None → Err("--seed is required and must be non-zero …") ДО validate.

// rmasscan-cli/src/output.rs
pub trait Sink { fn report(&mut self, reply: &Reply) -> Result<(), String>; fn finish(&mut self) -> Result<(), String>; }
/// masscan output.c:781–795: `Discovered open port N/tcp on IP`, дополнение пробелами до 79, `\n`, flush на строку;
/// Closed не печатается (is_show_closed = 0). Приёмник этапа 2 реализует тот же трейт.
pub struct Interactive<W: Write> { /* … */ }
pub fn discovered_line(ip: Ipv4Addr, port: u16) -> String;   // чистая функция, тест на длину 80 и байты
```

- [ ] Red `config.rs`: `router_ip_round_trips_through_echo_and_paused_conf`, `echo_without_router_ip_is_unchanged`
  (golden `echo/*.conf` как прежде), `validate_keeps_router_ip`.
- [ ] Red `args.rs`/`lib.rs`: `router_ip_accepts_one_address_and_rejects_ranges`, `iflist_conflicts_with_operations_and_targets`,
  `source_ip_and_source_mac_aliases_set_the_adapter_fields`, `seed_policy_by_operation` (таблица), `echo_without_seed_errors_before_printing`
  (вывод пуст, ошибка содержит `--seed`), `list_without_seed_errors` — все на тест-локальном fake минимального `Backend`.
- [ ] Red `tests/common/spawn.rs`: `spawn_helper_refuses_argv_that_could_transmit` (`["10.0.0.0/24","-p80"]` → паника;
  `["--offline", …]` → запуск); `differential.rs` переведён на помощник, кейс `--banners 10.0.0.0/24 -p80` заменён на
  `--nonsense --offline 10.0.0.0/30 -p80 --seed 1` (ожидание: ошибка clap).
- [ ] Red `output.rs`: `discovered_line_matches_masscan_byte_for_byte` (`"Discovered open port 80/tcp on 10.0.0.1"` + 40
  пробелов + `\n`, длина 80; второй вектор `443`/`198.18.0.2` → 42 + 37 + 1), `closed_replies_are_not_printed`,
  `each_line_is_flushed` (writer-счётчик flush), `broken_pipe_exits_zero` (как `io_fail`).
- [ ] Перенести код и unit-тесты `main.rs` в `lib.rs` без изменения поведения golden-веток; `main.rs` = `#[cfg(not(test))]`
  модуль `os_backend` + `#[cfg(not(test))] fn main` (разбор argv + `run`); `cargo test --locked --workspace` (в т. ч. сборка
  bin-таргета под `cfg(test)`); `tests/differential.rs` зелёный через `spawn_readonly`.
  Commit: `feat(cli): library crate, --router-ip, --iflist, source aliases and the Discovered sink`.

**GREEN:** все тесты core/cli PASS на Mac; golden побайтно; `--echo`/`-sL` без seed отказывают до вывода; clippy/fmt
чисты; language guard PASS.

## Задача 2. Логика обнаружения над швами (`rmasscan-net::discover`, офлайн, все ОС)

**Files:** создать `rmasscan-net/src/discover.rs`, `src/discover_tests.rs`; изменить `src/lib.rs` (экспорт).

**Constraints:** модуль безопасный (без `allow(unsafe_code)`), не зависит от ОС, не делает системных вызовов: всё через
`RouteTable` и `Interfaces`; тесты на синтетических таблицах покрывают каждую ветвь и каждый текст отказа; никакой
per-target таблицы (одна пара «интерфейс, следующий хоп» на скан); маршруты по умолчанию только через `default_routes`
(lookup `0.0.0.0` не используется нигде); приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// rmasscan-net/src/discover.rs
pub struct Route { pub ifindex: u32, pub ifname: String, pub gateway: Option<Ipv4Addr>,
                   /// назначение это адрес самого хоста: Linux RTN_LOCAL; macOS RTF_LOCAL или ifp lo0;
                   /// Windows флаг Loopback, или IfType 24 (software loopback), или dst равен unicast-адресу адаптера
                   pub local: bool }
pub struct Iface { pub name: String, pub index: u32, pub device_id: String /* Linux/macOS: name; Windows: \Device\NPF_{GUID} */,
                   pub description: Option<String> /* Windows FriendlyName */, pub mac: Option<[u8; 6]>, pub mac_masked: bool,
                   /// Ethernet-кадры: Linux ARPHRD_ETHER, macOS IFT_ETHER, Windows IfType 6 или 71 (Wi-Fi, Npcap даёт DLT_EN10MB)
                   pub ethernet: bool, pub up: bool, pub ipv4: Vec<Ipv4Addr> }
pub trait RouteTable {
    /// Маршрут к одному unicast-адресу (Linux RTM_GETROUTE+RTA_DST, macOS RTM_GET, Windows GetBestRoute2); None = нет маршрута
    /// (Linux unreachable/blackhole/prohibit; Windows ERROR_NOT_FOUND/NETWORK_UNREACHABLE/HOST_UNREACHABLE; macOS ESRCH).
    fn lookup(&self, dst: Ipv4Addr) -> Result<Option<Route>, NetError>;
    /// Все маршруты по умолчанию в порядке предпочтения ядра (Linux dump таблицы main, dst_len 0, по priority;
    /// macOS RTM_GET 0.0.0.0 (один); Windows GetIpForwardTable2, prefix 0, по Metric).
    fn default_routes(&self) -> Result<Vec<Route>, NetError>;
}
pub trait Interfaces { fn list(&self) -> Result<Vec<Iface>, NetError>; }
#[derive(Default)] pub struct Overrides { pub adapter: Option<String>, pub adapter_ip: Option<Ipv4Addr>,
    pub adapter_mac: Option<[u8; 6]>, pub router_ip: Option<Ipv4Addr>, pub router_mac: Option<[u8; 6]> }
pub struct Targets { pub first: Ipv4Addr, pub last: Ipv4Addr, pub single: bool }
/// first/last unicast-адреса итогового MassIp: пропуск 0/8, 127/8, 224/3 (и 255.255.255.255); None, если unicast нет.
pub fn probe_targets(massip: &MassIp) -> Option<Targets>;
pub enum Source { Given, Detected }
pub enum NextHopWhy { Given, RouteGateway, OnLinkTarget, InterfaceDefaultGateway }
pub enum NextHop { Mac([u8; 6], Source), Resolve { ip: Ipv4Addr, why: NextHopWhy } }
pub struct Detected { pub iface: Iface, pub iface_source: Source, pub source_ipv4: (Ipv4Addr, Source),
                      pub source_mac: ([u8; 6], Source), pub next_hop: NextHop }
#[derive(thiserror::Error)] pub enum DetectError {
    NoUnicastTargets,
    NoRoute(Ipv4Addr),                    // "FAIL: could not determine default interface\n    [hint] try \"--interface ethX\""
    LocalTarget { ip, ifname },           // "FAIL: TARGET is an address of this host (route via IFNAME)\n    [hint] try \"--interface ethX\" and \"--router-ip 192.0.2.1\""
    SplitRoutes { first: (Ipv4Addr, String), last: (Ipv4Addr, String) },   // + "[hint] try \"--interface ethX\""
    NoSuchAdapter(String),                // "[hint] did you spell the name correctly?"
    NotUsable { name, reason: &'static str /* "not Ethernet" | "down" */ },
    NoIpv4(String),                       // "FAIL: failed to detect IP of interface \"X\"\n    [hint] did you spell the name correctly?\n    [hint] if it has no IP address, manually set with something like \"--source-ip 198.51.100.17\""
    MacMasked(String),                    // "FAIL: MAC of interface \"X\" is os-masked (Darwin hides MACs from unprivileged processes)\n    [hint] run as root, or try something like \"--source-mac 00-11-22-33-44-55\""
    NoMac(String),                        // "FAIL: failed to detect MAC address of interface: \"X\"\n [hint] try something like \"--source-mac 00-11-22-33-44-55\""
    NoGateway { ifname },                 // on-link, несколько целей, нет шлюза по умолчанию на интерфейсе: три подсказки masscan
    Os(#[from] NetError) }
pub fn detect(t: &Targets, ov: &Overrides, routes: &dyn RouteTable, ifaces: &dyn Interfaces) -> Result<Detected, DetectError>;
/// Для --offline: интерфейс/IP/MAC по тем же правилам, следующий хоп НЕ ищется (C main-initadapter.c:159–163).
pub fn detect_offline(t: &Targets, ov: &Overrides, routes: &dyn RouteTable, ifaces: &dyn Interfaces) -> Result<Detected, DetectError>;
pub fn iflist_text(ifaces: &[Iface], defaults: &[Route]) -> String;   // одна строка на интерфейс + строки `default via … dev …`
```

Правила `detect` (решения 1–3):

- **Интерфейс.** `ov.adapter` → интерфейс с таким `name`, `device_id` или `description` (без учёта регистра для
  `device_id`/`description`), иначе `NoSuchAdapter`. Без `--adapter`: `routes.lookup(t.first)`; `None` → `NoRoute`;
  `local` → `LocalTarget`; если `!t.single`, `routes.lookup(t.last)` обязан дать тот же `ifindex` и тот же `gateway`,
  иначе `SplitRoutes`. Интерфейс обязан быть `ethernet` и `up`, иначе `NotUsable`.
- **IPv4.** `ov.adapter_ip`, иначе первый адрес `iface.ipv4` в порядке ОС (как `rawsock_get_adapter_ip`), иначе `NoIpv4`.
- **MAC.** `ov.adapter_mac`, иначе `iface.mac`; `mac_masked` → `MacMasked`; `None` или нулевой или групповой → `NoMac`.
  Заполнитель никогда не возвращается.
- **Следующий хоп** (только `detect`). `ov.router_mac` → `Mac(given)` (ARP не нужен; `router_ip` тогда только
  печатается). Иначе IP: `ov.router_ip` → `Resolve{Given}`; иначе маршрут к `t.first` (при `--adapter` тот же lookup;
  интерфейс маршрута обязан совпадать с выбранным, иначе `LocalTarget`/`SplitRoutes` по смыслу): `gateway: Some(g)` →
  `Resolve{g, RouteGateway}`; on-link и `t.single` → `Resolve{t.first, OnLinkTarget}`; on-link и несколько целей →
  первый из `routes.default_routes()` с тем же `ifindex` и `gateway: Some(g)` → `Resolve{g, InterfaceDefaultGateway}`
  (паритет masscan: через маршрутизатор), иначе `NoGateway`.

- [ ] Red `discover_tests.rs` на синтетических `RouteTable`/`Interfaces`: `probe_targets_skip_zero_loopback_multicast_and_broadcast`
  (`0.0.0.0/0` минус `255.255.255.255` → first `1.0.0.0`, last `223.255.255.255`; только `127.0.0.0/8` → `None`),
  `route_to_target_picks_its_interface_not_the_default`, `default_route_is_used_when_the_target_is_remote`,
  `local_target_is_refused_with_the_interface_hint`, `targets_on_two_interfaces_are_refused`,
  `explicit_adapter_by_name_device_id_and_friendly_name`, `unknown_adapter_is_refused_before_anything_else`,
  `non_ethernet_or_down_interface_is_refused`, `wifi_iftype_counts_as_ethernet`, `first_ipv4_in_os_order_is_the_source`,
  `no_ipv4_names_the_source_ip_hint`, `masked_mac_is_refused_never_substituted`, `zero_or_multicast_mac_is_refused`,
  `router_mac_override_skips_resolution_entirely`, `router_ip_override_is_resolved`, `gateway_route_resolves_the_gateway`,
  `on_link_single_target_resolves_the_target_itself`, `on_link_many_targets_resolve_the_interface_default_gateway_from_the_dump`,
  `on_link_many_targets_without_gateway_carry_three_hints`, `explicit_adapter_with_a_local_route_still_needs_router_ip`
  (сценарий Mac feth), `detect_offline_never_consults_routes_for_the_next_hop` (fake `default_routes` паникует),
  `iflist_text_marks_masked_macs_and_lists_ipv4s_and_defaults`, `every_detect_error_text_contains_its_masscan_hint` (таблица).
- [ ] Реализовать; `cargo test --locked -p rmasscan-net` на Mac (модуль платформенно-нейтрален).
  Commit: `feat(net): adapter, source and next-hop detection over route and interface seams`.

**GREEN:** тесты PASS на Mac/Linux/Windows (CI); clippy чист; `unsafe` не добавлен; language guard PASS.

## Задача 3. Переносимые парсеры и ОС-бэкенды маршрутов и интерфейсов (Linux, macOS, Windows)

**Files:** создать `rmasscan-net/src/route_parse.rs` (+ тесты), `src/linux/route.rs`, `src/macos/route.rs`; изменить
`src/linux/mod.rs`, `src/macos/mod.rs`, `src/macos/ifinfo.rs`, `src/windows/mod.rs`, `src/windows/sys.rs`, `src/lib.rs`
(заголовок, экспорт), `Cargo.toml` (комментарий); создать `rmasscan-cli/tests/detect_readonly.rs` (используется
задачей 5).

**Constraints:** `unsafe` только в `linux::route`, `macos::route`, `windows::sys` с `SAFETY` на каждом блоке; никаких
процессов; никаких записей в ядро (только запросы); все вызовы без привилегий; буферы с явными границами; разбор
байтов ядра в безопасном переносимом `route_parse.rs` (тесты компилируются и идут на любой ОС); ОС-тесты на реальных
хостах только читают; на хостах, где маршрут по умолчанию известен (dev Mac, minipc, гость), ожидания строгие через
`RMASSCAN_EXPECT_DEFAULT_ROUTE=1`, без переменной (CI) — терпимые; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// rmasscan-net/src/lib.rs
pub use discover::{Detected, DetectError, Iface, Interfaces, NextHop, Overrides, Route, RouteTable, Targets, detect, detect_offline, iflist_text, probe_targets};
pub fn os_route_table() -> Result<Box<dyn RouteTable>, NetError>;   // Linux/macOS/Windows; иначе UnsupportedPlatform
pub fn os_interfaces() -> Result<Box<dyn Interfaces>, NetError>;
// route_parse.rs (safe, portable):
pub(crate) struct NlRoute { pub kind: u8 /* rtm_type */, pub dst_len: u8, pub table: u32, pub oif: Option<u32>,
                            pub gateway: Option<Ipv4Addr>, pub priority: u32 }
pub(crate) fn parse_netlink_routes(buf: &[u8]) -> Result<Vec<NlRoute>, String>;     // nlmsghdr + rtmsg(local repr(C)) + rtattr; NLMSG_ERROR → Err
pub(crate) fn parse_rt_reply(buf: &[u8], seq: i32, pid: i32) -> Result<Option<RtReply>, String>;  // Darwin: sockaddr ROUNDUP 4; чужие seq/pid → None
pub(crate) struct RtReply { pub flags: i32, pub ifp: Option<String>, pub ifindex: u32, pub gateway_in: Option<Ipv4Addr>, pub gateway_is_link: bool }
pub(crate) struct Fwd { pub ifindex: u32, pub prefix_len: u8, pub next_hop: Ipv4Addr, pub metric: u32, pub loopback: bool }
pub(crate) fn route_from_best(row: &Fwd, dst: Ipv4Addr, ifaces: &[Iface]) -> Route;   // local по правилу Route::local
pub(crate) fn defaults_from_table(rows: &[Fwd], ifaces: &[Iface]) -> Vec<Route>;      // prefix 0, по metric
// linux/route.rs: lookup = RTM_GETROUTE (NLM_F_REQUEST, rtmsg{AF_INET, dst_len 32}, RTA_DST) → parse_netlink_routes →
//   RTN_LOCAL → local; RTN_UNREACHABLE/BLACKHOLE/PROHIBIT или без RTA_OIF → None; default_routes = RTM_GETROUTE NLM_F_DUMP,
//   dst_len 0, таблица main, сортировка по priority. Интерфейсы: if_nameindex + SIOCGIFFLAGS/SIOCGIFHWADDR/SIOCGIFADDR.
// macos/route.rs: socket(PF_ROUTE, SOCK_RAW, AF_INET); rt_msghdr{RTM_GET, rtm_addrs RTA_DST|RTA_IFP, seq, pid} + sockaddr_in;
//   read в цикле до совпадения seq/pid (parse_rt_reply); RTAX_IFP → ifname; RTAX_GATEWAY sockaddr_in → gateway,
//   sockaddr_dl → on-link; RTF_LOCAL или ifp lo0 → local; ESRCH/ENETUNREACH → None; default_routes = RTM_GET 0.0.0.0.
//   Интерфейсы: ifinfo::interfaces() → Iface.
// windows/sys.rs: adapters() (GetAdaptersAddresses AF_INET: FirstUnicastAddress → ipv4, IfIndex, IfType 6|71 → ethernet,
//   24 → loopback, OperStatus Up, FriendlyName, PhysicalAddress; device_id "\\Device\\NPF_" + AdapterName);
//   best_route(dst) (GetBestRoute2; ERROR_NOT_FOUND/NETWORK_UNREACHABLE/HOST_UNREACHABLE → None) → route_from_best;
//   forward_table() (GetIpForwardTable2 AF_INET) → defaults_from_table.
```

- [ ] Red `route_parse.rs` (на любой ОС): `netlink_reply_with_oif_gateway_prefsrc_is_parsed`, `netlink_local_and_unreachable_kinds_are_kept`,
  `netlink_error_message_is_err`, `netlink_dump_keeps_only_dst_len_zero_sorted_by_priority`, `rt_reply_sockaddrs_are_rounded_to_four_bytes`,
  `rt_reply_with_foreign_seq_or_pid_is_skipped`, `rt_reply_gateway_sockaddr_dl_means_on_link`, `rt_reply_rtf_local_or_lo0_is_local`,
  `fwd_row_loopback_flag_or_iftype_24_or_own_unicast_is_local`, `fwd_rows_prefix_zero_sorted_by_metric`.
- [ ] Red `rmasscan-cli/tests/detect_readonly.rs` (на всех ОС, без `#[ignore]`, только чтение, через `os_route_table`/
  `os_interfaces`): `loopback_address_routes_locally` (`lookup(127.0.0.1)` → `Some(Route{local: true})` на всех ОС, Windows по
  любому из трёх признаков), `default_routes_never_panic_and_are_strict_where_expected` (без переменной: `Ok(_)`; с
  `RMASSCAN_EXPECT_DEFAULT_ROUTE=1`: непустой, первый с `gateway: Some` и `local: false` — это и есть проверка route
  socket на Darwin 27 из ad-hoc-подписанного теста, S10), `interfaces_list_is_nonempty_and_loopback_is_not_ethernet`,
  `every_ethernet_interface_has_a_six_byte_or_masked_mac`, `remote_lookup_matches_offline_detection` (если `lookup(8.8.8.8)`
  даёт маршрут: `detect` без переопределений выбирает тот же интерфейс или даёт `NoIpv4`/`MacMasked`/`NotUsable` (маршрут по
  умолчанию через VPN-туннель, N4); с переменной маршрут обязателен). Строгий режим на Mac предполагает, что маршрут по
  умолчанию не идёт через VPN `utun` (иначе шлюз link-level и тест честно падает — запускать без VPN или записать).
  Выводы тестов в evidence не копируются (privacy).
- [ ] Реализовать; `cargo test --locked -p rmasscan-net` и `-p rmasscan-cli` на Mac (с переменной), minipc, госте (с
  переменной) и в CI (без). Задача 0 сверила `route -n get default` из оболочки агента с результатом теста на Mac.
  Commit: `feat(net): in-process route and interface lookups on Linux, macOS and Windows`.

**GREEN:** парсер-тесты PASS на трёх ОС; read-only тесты PASS на Mac, minipc, госте (строго) и в CI (терпимо); `unsafe`
только в перечисленных модулях с `SAFETY`; заголовок `lib.rs` и `Cargo.toml` обновлены; clippy чист; language guard
PASS; `cargo deny` зелёный (новых crates нет).

## Задача 4. Резолвер ARP над `Tx`/`Rx` (офлайн, FakeAdapter, ManualClock)

**Files:** создать `rmasscan-net/src/arp_resolve.rs` (+ `src/arp_resolve_tests.rs`); изменить `src/lib.rs`.

**Constraints:** модуль безопасный; единственный передаваемый кадр — `encode_request(my_mac, my_ip, target)` (60 байт);
принимаются только кадры, которые `PendingResolve::offer` считает ответом (gratuitous/unsolicited/чужие игнорируются);
время только через инжектированные часы `rmasscan_core::throttle::Clock` (тесты с `ManualClock`, запросы считаются
точно); `send` с `WouldBlockUnsent` → повтор на следующем тике, `Uncertain` или `Err` → отказ без повторов; `recv` всегда с
дедлайном ≤ `MAX_IO_TIMEOUT`; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// rmasscan-net/src/arp_resolve.rs
pub const ARP_INTERVAL: Duration = Duration::from_secs(1);
pub const ARP_TIMEOUT: Duration = Duration::from_secs(10);
pub struct ArpPolicy { pub interval: Duration, pub timeout: Duration }   // Default = константы
pub enum NextHopKind { Router, Target }                                  // текст отказа: "router" | "next hop (target)"
pub struct ArpReport { pub mac: [u8; 6], pub requests_sent: u32, pub elapsed: Duration }
#[derive(thiserror::Error)] pub enum ArpResolveError {
    /// "FAIL: ARP timed-out resolving MAC address for router IFNAME: \"A.B.C.D\"" (или "… for next hop (target) …")
    /// + "    [hint] try \"--router-ip 192.0.2.1\" to specify different router" + "    [hint] try \"--router-mac 66-55-44-33-22-11\" instead to bypass ARP"
    /// + "    [hint] try \"--interface eth0\" to change interface"
    Timeout { ifname: String, target: Ipv4Addr, kind: NextHopKind, requests_sent: u32 },
    Io(IoError), Uncertain }
/// Broadcast next hop для короткоживущего адаптера фазы ARP (check_binding macOS/Windows требует unicast source ≠ next hop).
pub fn arp_binding(device_id: &str, source_ipv4: Ipv4Addr, source_mac: [u8; 6], source_ports: (u16, u16)) -> AdapterBinding;
pub fn resolve_next_hop(io: &mut AdapterPair, ifname: &str, my_mac: [u8; 6], my_ip: Ipv4Addr, target: Ipv4Addr,
                        kind: NextHopKind, policy: &ArpPolicy, clock: &dyn Clock) -> Result<ArpReport, ArpResolveError>;
```

Цикл: `t0 = clock.now()`, `next_send = t0`; пока `clock.now() − t0 < timeout`: если `now >= next_send` — `tx.send(frame,
MAX_IO_TIMEOUT)` (`Sent` → `requests_sent += 1`, `next_send += interval`; `WouldBlockUnsent` → `clock.sleep(1 мс)`, тот же
счёт); `rx.recv(buf, min(MAX_IO_TIMEOUT, next_send − now))`; `Some(n)` → `pending.offer(&buf[..n])` → `Some(mac)` → `Ok`.
По истечении — `Timeout`. `rx.health` не вызывается (потери в фазе ARP не влияют на результат скана).

- [ ] Red `arp_resolve_tests.rs` на `FakeAdapter` + `ManualClock` (ответчик `set_responder` отвечает `encode_reply` на
  запрос к нужному IP): `reply_resolves_after_one_request_and_counts_it`, `no_reply_times_out_with_exactly_ten_requests`
  (часы продвигаются на 1 с за тик; `requests_sent == 10`, `elapsed == 10 s`), `request_bytes_equal_the_core_encoder_and_go_to_broadcast`,
  `gratuitous_and_unsolicited_arp_are_ignored`, `reply_from_another_ip_or_to_another_mac_is_ignored`,
  `multicast_sender_mac_is_ignored`, `would_block_retries_without_double_counting`, `uncertain_send_fails_without_retry`,
  `io_error_fails`, `only_the_target_ip_is_ever_requested` (журнал кадров fake: все кадры ARP, все к одному IP),
  `arp_binding_uses_the_broadcast_next_hop`, `timeout_text_names_router_or_target_and_three_hints`.
- [ ] Реализовать; `cargo test --locked -p rmasscan-net`. Commit: `feat(net): synchronous ARP next-hop resolver over Tx/Rx`.

**GREEN:** тесты PASS на трёх ОС (CI), детерминированы (без `sleep` реального времени); `unsafe` не добавлен; clippy
чист; language guard PASS.

## Задача 5. Живой путь CLI, `--offline` с обнаружением, `--iflist` (офлайн end-to-end на fake-бэкенде)

**Files:** изменить `rmasscan-cli/src/live.rs` (расширение минимального `Backend` задачи 1 до полного), `src/os_backend.rs`,
`src/lib.rs`, `src/main.rs`, `src/args.rs` (тексты help), `tests/detect_readonly.rs`, `rmasscan/README.md` («Команды»,
«Отличия от masscan», «Ограничения»); создать `tests/live_fake.rs`.

**Constraints:** `#![forbid(unsafe_code)]`; порядок строго `defaults (seed по политике, порт) → validate → detect →
печать `[+]` → ARP (если нужно) → ReadyPlan → open → Engine → события → Sink → join`; обнаружение и `--iflist` не требуют
привилегий и ничего не открывают; `--offline` зовёт `detect_offline` (следующий хоп не ищется), MAC шлюза всегда
`66-55-44-33-22-11` (даже при `--router-mac`, как C), не открывает адаптер и не шлёт ARP; при явных `--adapter-ip`,
`--adapter-mac` и `--source-port` в `--offline` ОС не опрашивается вовсе (прежние golden-тесты герметичны; `--router-mac`
там игнорируется в пользу фиктивного, как C); ARP-адаптер закрывается (`drop`) до `open` адаптера скана; Ctrl-C не
перехватывается (поведение ОС по умолчанию, `paused.conf` не пишется — записано в README); exit code 0 при
`Completed`/`Stopped`, 1 иначе; отказы обнаружения/ARP печатаются на stderr как есть в форме C (`[-] FAIL: …` плюс
строки подсказок), без обёртки `rmasscan: error:` (она остаётся для прочих ошибок); **`OsBackend` только в
`src/os_backend.rs` под `#[cfg(not(test))]`, `fn main` под `#[cfg(not(test))]`**; `Engine::start_with_clock`
(`#[doc(hidden)]`) используется продуктом осознанно (решение 4); тесты `live_fake.rs` используют `wait_secs = 0` (иначе
каждый fake-скан ждёт 10 с); бинарник в `detect_readonly.rs` только через `spawn_readonly`; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// rmasscan-cli/src/live.rs
pub trait Backend {
    fn routes(&self) -> Result<Box<dyn RouteTable>, NetError>;
    fn interfaces(&self) -> Result<Box<dyn Interfaces>, NetError>;
    fn open(&self, binding: &AdapterBinding) -> Result<AdapterPair, NetError>;   // OsBackend: open_explicit(..).map(|a| a.io)
    fn entropy64(&self) -> u64;              // OsBackend: getrandom; ≠ 0
    fn unix_time(&self) -> u64;              // источник порта 40000 + t % 20000
    fn arp_policy(&self) -> ArpPolicy;       // OsBackend: Default
    fn clock(&self) -> Arc<dyn Clock + Send + Sync>;   // OsBackend: SystemClock; тесты: ManualClock (ARP и engine)
}
pub struct Prepared { pub eff: EffectiveConfig, pub detected: Detected, pub binding: AdapterBinding, pub seed: (u64, Source),
                      pub source_ports: ((u16, u16), Source) }
/// defaults → validate(Scan) → probe_targets → detect|detect_offline; ничего не открывает.
pub fn prepare(cfg: &ScanConfig, seed: SeedPolicy, backend: &dyn Backend, offline: bool) -> Result<Prepared, String>;
pub fn print_detection(p: &Prepared, log: &mut dyn Write) -> Result<(), String>;      // строки `[+] …` из таблицы констант
pub fn run_live(cfg: &ScanConfig, backend: &dyn Backend, sink: &mut dyn Sink, log: &mut dyn Write) -> Result<Outcome, String>;
pub fn run_offline(cfg: &ScanConfig, backend: &dyn Backend, packet_trace: bool, out: &mut dyn Write, log: &mut dyn Write) -> Result<(), String>;
pub fn iflist(backend: &dyn Backend, out: &mut dyn Write) -> Result<(), String>;
// src/os_backend.rs (бинарник, #[cfg(not(test))]): pub struct OsBackend; impl Backend — единственное место с rmasscan_net::open_explicit.
// src/main.rs: #[cfg(not(test))] mod os_backend; fn main() { … rmasscan_cli::run(&cli, &OsBackend, &mut out, &mut err) … }
```

`run_live`: `prepare` → `print_detection` → если `NextHop::Resolve{ip, why}`: `backend.open(arp_binding(..))` →
`resolve_next_hop(.., kind по why, policy, clock)` → `drop(pair)` → `[+] router-mac = … (arp: N requests, T ms)`;
`ReadyPlan::new(eff, binding)`; `backend.open(&binding)` (ошибка `PermissionDenied` → текст с подсказкой по ОС: root /
Administrator и Npcap / `/dev/bpf*`); `Engine::start_with_clock(plan, pair, EngineOptions::new(scan_id, attempt_id),
backend.clock())` (идентификаторы из `entropy64`); цикл `recv_event_timeout(250 мс)`: `Results` → `sink.report` на каждый
`Reply`; `Finished` → выход из цикла; `join()` → `Outcome`; `sink.finish()`; `[+] finished: …, sent N` из
`Outcome.progress.sent`; `Failed(reason)` → `Err`. `lib.rs::run`: `--iflist` → `iflist`; `--offline` → `run_offline` (с
`--packet-trace` печатает трассу как прежде; без него только строки `[+]`); иначе живой скан с `Interactive(stdout)`.

- [ ] Red `tests/live_fake.rs` (`FakeBackend`: синтетические таблицы задачи 2, `FakeAdapter` с ответчиком ARP +
  `reply_to_syn`, `ManualClock`, фиксированные энтропия/время, `open` паникует при `panic_on_open`):
  `live_scan_detects_resolves_and_prints_discovered_lines` (порядок строк stderr по таблице констант, stdout = ожидаемые
  строки по 80 байт, exit 0, журнал кадров fake: ровно 1 ARP до первого SYN, все SYN с `dst = resolved mac`, `src ip/mac`
  из обнаружения, `[+] finished … sent N` равен числу SYN), `router_mac_override_sends_no_arp`,
  `arp_timeout_sends_no_syn_and_fails_with_hints` (часы на 10 с), `detection_failure_opens_nothing` (`panic_on_open`),
  `permission_denied_on_open_names_the_os_hint_and_sends_nothing`, `arp_adapter_is_closed_before_the_scan_adapter_opens`
  (журнал open/drop), `seed_defaults_to_entropy_and_is_printed`, `source_port_defaults_to_time_formula`,
  `internet_wide_range_without_exclude_is_refused_before_detection` (`0.0.0.0/0 -p80`: `ExcludeRequired`, fake-таблицы не
  вызывались), `internet_wide_range_with_the_canonical_exclude_probes_unicast_targets` (`0.0.0.0/0 -p80 --exclude
  255.255.255.255`: lookup для `1.0.0.0` и `223.255.255.255`), `offline_uses_the_fake_router_mac_even_with_router_mac_and_no_next_hop_lookup`,
  `offline_with_explicit_ip_mac_and_port_never_queries_the_os` (fake-таблицы паникуют), `offline_packet_trace_golden_unchanged`
  (прежний `TRACE` набор), `iflist_prints_interfaces_and_default_routes`, `stopped_outcome_exits_zero`,
  `failed_outcome_exits_one_with_reason`, `os_backend_is_absent_under_test` (компиляция: `rmasscan_cli` не экспортирует
  `OsBackend`; бинарник под `cfg(test)` не содержит модуля).
- [ ] Переписать существующие unit-тесты бинарника (S9): `bad_inputs_are_fatal` — убрать строку `rmasscan 10.0.0.0/30 -p80
  --seed 1` (теперь живой скан; покрыт `live_fake`); `scan_without_offline_trace_is_rejected` → удалить (поведение
  изменено осознанно), оставить проверку `--packet-trace` без `--offline` и `-sL --echo` конфликтов;
  `packet_trace_requires_adapter_options` → `packet_trace_fills_missing_values_from_the_backend` (fake-бэкенд) и
  `packet_trace_without_adapter_ip_on_an_interface_without_ipv4_names_the_source_ip_hint`.
- [ ] `tests/detect_readonly.rs` (задача 3) дополняется запуском **бинарника** через `spawn_readonly` только с `--iflist`
  (rc 0, непустой вывод) и `--offline 8.8.8.8 -p80 --seed 1` (rc 0 со строками `[+]` или rc 1 с одним из
  `NoRoute`/`NoIpv4`/`MacMasked`/`NotUsable`); вывод в evidence не копируется.
- [ ] README: «Команды» (примеры `--iflist`, `--offline`, `sudo rmasscan …`), «Отличия от masscan» (строки 34–40 нынешнего
  README): удалить «обычный скан без `--offline --packet-trace` не поддержан» и «`--offline --packet-trace` требует
  `--adapter-ip`, …»; переписать пункт `--seed` («обязателен для `-sL`, `--echo`, `--offline`; для живого скана берётся
  из энтропии и печатается; 0 запрещён»); добавить: интерфейс по маршруту к целям (masscan: маршрут по умолчанию);
  единственная on-link цель → ARP к цели (masscan: к маршрутизатору); порт источника по умолчанию один (masscan: два,
  {p, p+16}); `--iflist` свой формат на stdout; строки `[+]` печатаются всегда (masscan только с `-v`); Ctrl-C без
  `paused.conf`; `--adapter` на Windows по `\Device\NPF_{GUID}` или имени, числовых индексов нет; Wi-Fi принимается;
  явный не-Ethernet `--adapter` отказывает (masscan проверяет тип только при автовыборе); туннели/DLT_NULL/VLAN/IPv6 не
  поддержаны; ARP-таймаут 10 с (masscan ≈ 11 с); `--offline` с явными IP, MAC и портом не опрашивает ОС (masscan и в
  offline ищет интерфейс по умолчанию без `--interface`).
  Commit: `feat(cli): live scan with adapter and gateway auto-detection; --offline detects read-only`.

**GREEN:** все тесты CLI PASS на трёх ОС (CI) без единого открытия адаптера (`panic_on_open` ни разу не сработал);
golden прежние; `cargo build -p rmasscan-cli` на Windows (CI) собирает бинарник с net; README согласован; language guard
PASS; `cargo deny` зелёный (`getrandom` уже в lock).

## Задача 6. Лаборатория: isolation `autodetect`, `autodetect-suite`, `windows-suite --plan autodetect`, `autodetect-verify`, документы

**Files:** изменить `rmasscan-lab/src/capture.rs` (+ `tests/capture.rs`); создать `src/autodetect_suite.rs`,
`autodetect_suite_tests.rs`, `autodetect_verify.rs`, `autodetect_verify_tests.rs`; изменить `src/{lib,main}.rs`,
`src/windows_suite.rs` (+ `windows_suite_tests.rs`), `src/verify.rs` (+ тесты), `scripts/wire-lab.sh`,
`rmasscan/docs/{rust-lab,macos-feth-lab,windows-vm-lab}.md`.

**Constraints:** `#![forbid(unsafe_code)]`; команды массивами по абсолютным путям; suite никогда не зовёт `sudo` сам
(Linux: её запускает `wire-lab.sh`, уже под `sudo -n`; macOS: пользовательский режим в окне гранта, `--root-case`
запускает сам пользователь через `sudo`); верификатор без сети и процессов, статусы не повышаются; прежние верификаторы,
режим isolation по умолчанию и закоммиченные каталоги evidence не меняют вердиктов; `*.gz` в каталоге → отказ
безопасности; личные пути скраблены; полный `--iflist` никогда не записывается; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```text
rmasscan-lab capture isolation --mode autodetect …     # M4: NS_A ровно {198.18.0.0/24 dev veth-a, default via 198.18.0.2 dev veth-a},
    # route get 8.8.8.8 → via 198.18.0.2 dev veth-a, neigh 198.18.0.2-5 permanent на veth-a; NS_B без маршрута по умолчанию,
    # ip_forward=0 в обоих; default_route записывается правдиво ({"scanner_ns": "via 198.18.0.2 dev veth-a", "peer_ns": false});
    # check_isolation_snapshot/isolation_permits получают параметр mode; режим по умолчанию байт в байт прежний.
rmasscan-lab autodetect-suite linux --out DIR --work DIR --ns-a NS --ns-b NS --iface-a IF --iface-b IF --mac-a MAC --mac-b MAC
    --rmasscan PATH --oracle PATH --conf-masked 0|1 [--only TAG ...]          # вызывается из wire-lab.sh --suite autodetect
rmasscan-lab autodetect-suite macos --out DIR --rmasscan PATH --lab PATH_TO_SELF [--run-id m1] [--only TAG ...] [--root-case]
    # без --root-case: euid != 0 обязателен, кейсы m01–m07, ворота как у macos-suite (status-pre/post, alf, leftovers incl. rmasscan,
    # pair-quiet), peer listen 8000-8007, свидетели tcpdump пира (фильтр приватности) и uplink (UPLINK_FILTER), interlock 13,
    # preflight --offline перед m05; с --root-case: euid == 0 обязателен, только m10–m11, свидетели от root, в конце chown -R на $SUDO_USER
rmasscan-lab windows-suite --plan autodetect --guest-exe 'C:\Users\lab\t4\rmasscan.exe' ...   # кейсы w01–w08b через тот же
    # гостевой runner (argv.json → windows_wire_run.ps1; w08a/w08b через windows_wire_runas.cmd); --fixtures для этого плана не требуется;
    # manifest: exe.build "Rust static CRT rmasscan CLI from code_commit", binding по кейсу из expect.json; preflight --offline перед w01/w06;
    # план autodetect НЕ строит run.json из JSON-строки stdout (:1392–1400; у rmasscan её нет) и переносит гостевые файлы как
    # guest-stdout.txt / guest-stderr.txt / guest-exit.txt; для w07 и w08a гостевой stdout.txt забирается в РАБОЧИЙ каталог
    # на home-pc, редуцируется там в iflist.json, и в каталог прогона пишется только iflist.json (guest-stdout.txt не создаётся) — R2
rmasscan-lab autodetect-verify --dir DIR [--out DIR/verdict.json]          # rc 0 PASS, 1 FAIL, 2 INVALID/NOT RUN
```

`wire-lab.sh --suite autodetect`: `case "$SUITE"` и usage получают `autodetect`; стенд задаётся внутри скрипта для этого
suite (`IP_A_LINK=198.18.0.1`, `PEER_IPS` /24, `DEFAULT_VIA=198.18.0.2`, neigh в NS_A — без новых переменных окружения в
`sudo -n env` re-exec); `--rmasscan PATH` добавляется в разбор аргументов и в `REEXEC`; seal-проверки для этого suite: в
NS_A ровно два маршрута (`198.18.0.0/24 dev veth-a`, `default via 198.18.0.2 dev veth-a`), `ip route get 8.8.8.8` → `via
198.18.0.2 dev veth-a`, в NS_B маршрута по умолчанию нет, `ip_forward=0` в обоих, список линков хоста не изменился;
`capture isolation --mode autodetect`; остальное как прежде (responder 80/8080, `capture dump` свидетель, маскирование
`/etc/masscan`). Отмена: cleanup скрипта удаляет оба netns (существующий trap).

Верификатор (каждая проверка именована и покрыта тестом; строки `[+]` разбираются в `detected.json`; план SYN
восстанавливается через небольшой адаптер `plan_args_from(argv.json, detected.json)` → ключи `wire_scan`
(`--iface`, `--src-ip`, `--src-mac`, `--router-mac`, `--targets`, `--ports`, `--exclude`, `--seed`, `--source-port`) → `plan_frames`):

- `safety`: pcap без сжатия; uplink/eno1 0 кадров (macOS/Windows), `isolation.json` режима `autodetect` ok (Linux);
  `status-pre/post` `raw_run_allowed: true` (macOS/Windows); хэши сходятся; privacy: в `stdout.txt`/`stderr.txt`/`*.json`
  нет строк вне allowlist (адреса `198.18.0.0/24`, MAC стендов, имена `veth-a`, `feth420x`, `Ethernet 2`, NPF GUID стенда,
  `lo0`/`lo`); любой другой hostname/имя → INVALID с указанием файла; `iflist.json` вместо вывода `--iflist`.
- `detection`: строки `[+]` присутствуют и равны `expect.json` кейса (интерфейс, IP, MAC, `router-ip` и причина, источник
  `given|detected`); для отказов `exit.txt` = 1 (Windows: `guest-exit.txt`), stderr (`guest-stderr.txt`) содержит `[-] FAIL:`
  и ожидаемую подсказку; `preflight.txt` (где требуется) **равен ожидаемому обнаружению кейса**: `w01`/`w06` — `[+]
  interface = Ethernet 2`, `m05` — отказ `LocalTarget` «address of this host (route via lo0)» (R1).
- `arp`: **ARP сканера** = ARP-запрос (opcode 1) с eth src = source MAC длиной **ровно 60 байт с нулевым дополнением**
  (N5); для каждого такого кадра требуется target = `router-ip` и побайтное равенство `encode_request(source_mac,
  source_ip, router_ip)`, иначе FAIL (`an_arp_request_to_another_ip_is_fail`); их число: 1 (ответ пришёл; при потере ответа
  ≤ 10 с шагом 1 с — заметка) или ровно 10 с шагом 1 ± 0.3 с (таймаут); при `--router-mac` 0; ARP-ответ пира (opcode 2,
  sender = `router-ip`) после первого запроса при успехе; первый запрос раньше первого SYN. **ARP ОС** = 42-байтовые
  запросы с MAC сканера и кадры opcode 2 с MAC сканера (ядро гостя Windows отвечает на `who-has 198.18.0.1`); считается
  отдельно в `os_arp` и никогда не считается кадром сканера; на Linux `os_arp.requests` обязан быть 0 (neigh постоянные),
  иначе INVALID стенда.
- `wire`: все SYN сканера с eth src = source MAC, eth dst = `router-mac`, ip src = source IP, sport в диапазоне
  `source-port`; порядок и множество SYN равны плану (`ProbeCursor`, seed из `[+] seed`); exactly-once; `[+] finished …
  sent N` равен числу SYN сканера; при отказах 0 SYN; RST ядра сканера (Linux, `rst_from_scanner`) допускаются и считаются.
- `results`: каждая строка `stdout.txt` (Windows: `guest-stdout.txt`) ровно 80 байт по формуле (пустой файл или ровно `"\n"` = пусто); множество
  `Discovered` равно множеству портов с SYN-ACK пира в окне прогона (полный захват), иначе FAIL; закрытых портов нет.
- `parity` (`l11_parity`): байты ARP-запроса оракула == байты запроса rmasscan; упорядоченные SYN равны (`compare_streams`);
  множества строк `Discovered` равны; оба `exit` 0.
- `iflist` (`l12`, `m07`, `m11`, `w07`, `w08a`): `iflist.json` `{rc: 0, lines ≥ 2, sha256, stand_line}` и **отсутствие**
  `stdout.txt`/`guest-stdout.txt` в каталоге (иначе INVALID); `stand_line` содержит
  имя NIC стенда и ожидаемый MAC (`m11`, `w07`) или `os-masked` (`m07`) или MAC `02:aa:00:00:00:01` (`l12`); для оракула только
  `{rc, lines, sha256}`.
- `--root-case` каталог (macOS): те же правила; `detected.json` должен нести `source-mac … (detected)`.

- [ ] Red `tests/capture.rs`: `autodetect_mode_accepts_the_default_route_via_the_peer_and_the_permanent_neighbours`,
  `autodetect_mode_refuses_a_default_route_in_the_peer_namespace`, `autodetect_mode_refuses_a_third_route_or_a_host_link`,
  `autodetect_mode_records_default_route_truthfully`, `legacy_mode_is_byte_identical` (снимки прежних тестов).
- [ ] Red `autodetect_verify_tests.rs`: генератор синтетического каталога (строки `[+]`, `argv.json`, `expect.json`, `peer.pcap`
  из `rmasscan_core::arp::{encode_request, encode_reply}` + SYN по плану через `ReadyPlan`/`ProbeCursor` + SYN-ACK/RST пира,
  `uplink.pcap` пустой, статусы, хэши) и `a_consistent_linux_run_is_pass`, `a_consistent_macos_run_is_pass`,
  `a_consistent_windows_run_with_guest_kernel_arp_reply_is_pass`; мутации: `an_arp_request_to_another_ip_is_fail`,
  `a_42_byte_kernel_arp_request_is_os_arp_not_scanner_arp_and_invalid_on_linux`, `a_guest_arp_reply_under_router_mac_is_os_arp_and_pass`,
  `two_scanner_requests_before_a_reply_is_noted_not_fail`, `a_syn_before_the_arp_reply_is_fail`, `a_syn_to_the_wrong_mac_is_fail`,
  `router_mac_override_with_a_scanner_arp_is_fail`, `timeout_case_with_nine_or_eleven_requests_is_fail`,
  `timeout_case_with_a_syn_is_fail`, `refusal_case_with_any_scanner_frame_is_fail`, `sent_count_not_equal_syn_is_fail`,
  `a_discovered_line_without_a_synack_is_fail`, `a_synack_without_a_discovered_line_is_fail`, `a_line_not_80_bytes_is_fail`,
  `guest_newline_only_stdout_is_empty`, `parity_arp_bytes_differ_is_fail`, `parity_syn_order_differs_is_fail`,
  `a_lab_frame_on_the_uplink_is_fail`, `a_gzipped_capture_is_refused`, `a_changed_hash_is_invalid`, `a_hostname_in_stderr_is_invalid`,
  `a_full_iflist_dump_in_the_run_is_invalid` (`stdout.txt` и `guest-stdout.txt`), `iflist_json_without_the_stand_line_is_fail`,
  `missing_preflight_is_not_run`, `preflight_not_equal_to_the_expected_detection_is_not_run` (w01 с чужим интерфейсом; m05 с
  `[+] interface` вместо `LocalTarget`), `a_60_byte_scanner_request_to_another_ip_is_fail`, `windows_run_reads_guest_named_files`,
  `missing_root_case_is_not_run_never_pass`, `verdict_never_upgrades`, `plan_args_from_argv_and_detected_matches_wire_scan_keys`.
- [ ] Red `autodetect_suite_tests.rs` (без процессов): таблицы кейсов трёх ОС (`argv` и ожидания) сериализуются в
  `argv.json`/`expect.json`; `linux_cases_never_name_an_address_outside_198_18_0_0_24`, `macos_user_cases_all_carry_adapter_feth4201_or_expect_a_refusal`,
  `root_case_requires_euid_zero_and_user_cases_refuse_root`, `windows_plan_uses_rmasscan_exe_argv_not_wire_scan`,
  `leftover_patterns_cover_rmasscan`, `privacy_filter_is_applied_to_the_peer_witness_on_macos`,
  `iflist_cases_store_only_the_redacted_form`, `preflight_expectation_is_the_stand_nic_for_w01_w06_and_local_target_for_m05`.
- [ ] Red `windows_suite_tests.rs`: `plan_autodetect_lists_w01_to_w08b` (w08a `--iflist`, w08b скан — два запуска runner под
  ограниченным токеном), `autodetect_runs_carry_expect_json`, `options_list_accepts_plan_autodetect`,
  `fixtures_are_optional_only_for_plan_autodetect`, `manifest_build_and_binding_follow_the_plan`,
  `autodetect_plan_skips_the_run_json_line_and_keeps_guest_names`, `iflist_runs_reduce_guest_stdout_in_the_work_dir_before_the_run_dir_is_written`
  (в каталоге прогона только `iflist.json`, `guest-stdout.txt` отсутствует); `verify_tests.rs`: `windows_verify_delegates_autodetect_runs`,
  `legacy_directories_are_unchanged` (закоммиченные `perf-r1`, `functional-r3` дают прежние вердикты).
- [ ] Реализовать; `cargo test --locked -p rmasscan-lab` на Mac и Linux; `bash -n scripts/wire-lab.sh`; документы:
  `rust-lab.md` (раздел «Autodetect suite»: команды Linux/Windows, каталог прогона, коды, `RMASSCAN_EXPECT_DEFAULT_ROUTE`),
  `macos-feth-lab.md` (раздел «Autodetect window»: пользовательский режим, `--root-case`, отмена), `windows-vm-lab.md`
  (абзац: `rmasscan.exe` на госте собирается как `wire_scan.exe`, план `autodetect`, ARP-ответы ядра гостя ожидаемы).
  Commit: `feat(lab): autodetect isolation mode, suites for Linux, macOS and Windows and the offline autodetect-verify`.

**GREEN:** тесты лаборатории PASS на Mac и Linux; прежние верификаторы и режим isolation воспроизводят закоммиченные
вердикты; clippy чист; language guard PASS; документы обновлены.

**Ревью перед окном (после задач 1–6):** свежее ревью ветки (только чтение) по Review Focus 1–5; исправления; повтор
офлайн-тестов на трёх ОС (Mac, minipc, гость — на госте с подтверждением, что ни один тест не открыл адаптер: `cargo
test` под elevated-сессией с Npcap Admin-only); заморозка коммита `C` (`git rev-parse HEAD` записывается в задаче 7).
Любое изменение после `C` в `rmasscan-cli`, `rmasscan-net`, `rmasscan-core`, `rmasscan-engine` требует повторения окон;
изменения только `rmasscan-lab`/docs — пересчёта архива исправленным верификатором с неизменными вердиктами.

## Задача 7. Живая приёмка: Linux (minipc, с паритетом C), Windows VM `n2`, macOS `feth` `m1`

**Files:** `docs/experiments/2026-10-27-rmasscan-autodetect-acceptance-raw/{linux-r1,windows-r1,macos-r1,macos-root-r1,verification,README.md,MANIFEST.sha256}`.

**Constraints:** живой оператор в `$SCRATCH/target-live` (`CARGO_INCREMENTAL=0`) на коммите `C`, чистое дерево; сборки
из `git archive` на minipc, home-pc и госте (`RMASSCAN_LAB_BUILD_COMMIT`, гость `RUSTFLAGS='-C target-feature=+crt-static
-C link-arg=/DEPENDENTLOADFLAG:0x800'`, `dumpbin /loadconfig rmasscan.exe` → `0x800` записан); старые экспорты удалены;
`sudo -n` только там, где задача 0 его подтвердила (minipc, home-pc, в т. ч. B1/B2 агентом); на Mac все `sudo` —
действия пользователя B и F (таблица); никакого `--rerun` после FAIL изоляции; privacy-скан каждого файла перед
копированием в репозиторий.

- [ ] **Linux (minipc).** `git archive C` → minipc, сборка `rmasscan-lab` и `rmasscan` (release); `RMASSCAN_LAB_BIN=… bash
  scripts/wire-lab.sh --suite autodetect --oracle $HOME/rmasscan-oracle/masscan/bin/masscan --rmasscan target/release/rmasscan --out OUT`
  (кейсы `l01–l12`); затем `rmasscan-lab autodetect-verify --dir OUT --out OUT/verdict.json`. Ожидание: все кейсы PASS,
  `l11_parity` PASS (ARP-байты, порядок SYN, множество `Discovered`), `l12_iflist` редуцированная форма, `os_arp.requests
  == 0`. Также регрессия прежнего пути: `scripts/wire-lab.sh --suite rust` функциональный набор на том же коммите (141
  PASS, `wire_scan` не менялся).
- [ ] **Windows (home-pc / гость).** B1/B2 агентом при необходимости (`sudo -n`, решение пользователя). По `rust-lab.md`
  «Deployment» (шаги 1–5) с дополнительной сборкой `rmasscan.exe` на госте из того же архива; `windows-suite --plan
  autodetect --suite windows-r1 --guest-exe 'C:\Users\lab\t4\rmasscan.exe' --commit C --repo . --remote-lab …
  --deploy-manifest ./deploy-manifest.json`; `windows-verify --dir` (делегирует `autodetect-verify`). Ожидание: preflight
  `w01`/`w06` называет `Ethernet 2` (иначе NOT RUN, не прогон), `w01–w07` PASS, `w08a` PASS (`--iflist` rc 0, `iflist.json`,
  без `guest-stdout.txt`), `w08b` PASS (скан rc 1, 0 кадров), `eno1` 0 кадров во всех прогонах, `status-pre/post` true,
  ARP-ответы ядра гостя в `os_arp`.
  Гостевой `cargo test --locked --workspace` (офлайн, `RMASSCAN_EXPECT_DEFAULT_ROUTE=1`) в `verification/`.
- [ ] **macOS (Mac, действия пользователя).** Оператор собирает `rmasscan` и `rmasscan-lab` (release, `target-live`),
  офлайн `cargo test --locked --workspace` (`RMASSCAN_EXPECT_DEFAULT_ROUTE=1`) и `cargo xtask test` (логи в `verification/`),
  сообщает пользователю `$LAB`, `$RM`, `$OUT` и просит действие **B** (одна строка: `up` + `grant` + root-кейс). После B:
  оператор проверяет `"$LAB" macos-lab status --run-id m1` (`raw_run_allowed: true`, `bpf_access: granted`) и наличие
  `$OUT/macos-root-r1/runs/m10_root_auto_mac/exit.txt`; запускает как пользователь `"$LAB" autodetect-suite macos --out
  "$OUT/macos-r1" --rmasscan "$RM" --lab "$LAB"` (кейсы `m01–m07`, preflight перед `m05`), затем `autodetect-verify` на обоих
  каталогах. Ожидание: `m01` отказ «os-masked» без кадров (если Darwin не маскирует MAC на этой версии — INVALID с
  заметкой, не PASS), `m02` ARP + 8 `Discovered`, `m03` 0 ARP, `m04` 10 ARP и 0 SYN, `m05` preflight = отказ `LocalTarget` через `lo0` и тот
  же отказ в живом кейсе без кадров, `m06` отказ без кадров, `m07`
  `iflist.json` с `os-masked`; `m10` MAC определён под root, ARP, 8 `Discovered`; `m11` `iflist.json` с настоящим MAC; 0
  кадров лаборатории на uplink в каждом прогоне. Затем действие **F** (`down`); `status` → rc 3, `/dev/bpf0` `0600 root:wheel`.
- [ ] **Evidence:** `shasum -a 256 -c hashes-before-copy.txt` в каждом каталоге; privacy-скан (`grep -E` по hostname Mac,
  именам учётных записей, `_tcp.local`, списку приложений: 0 совпадений; полного `--iflist` нет нигде); копия в
  `…-acceptance-raw/{linux-r1,windows-r1,macos-r1,macos-root-r1}`, повторная проверка хэшей, `MANIFEST.sha256`,
  `README.md` каталога (ворота, rc, вердикты, версии, замечания), `verification/` (логи трёх ОС, `verdict.json`,
  `dumpbin`). Commit: `test(cli): record autodetect acceptance on the Linux, Windows VM and Mac feth stands`.

**GREEN:** `autodetect-verify` overall PASS для `linux-r1` (включая паритет), `windows-r1`, `macos-r1` и `macos-root-r1`;
0 кадров на uplink/`eno1`; статусы стендов true до и после; хэши сходятся до и после копирования; privacy-скан чист;
стенд Mac снят; действия пользователя ровно A, B, F.

## Задача 8. Отчёт, readiness, спека §0.2, CI и итоговое ревью

**Files:** создать `docs/experiments/2026-10-27-rmasscan-autodetect-acceptance.md`; изменить
`docs/experiments/2026-10-24-rmasscan-readiness.md`, `docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md`
(§0.2 строка ARP), `rmasscan/README.md` («Статус», «Ограничения»), `.github/workflows/rmasscan.yml` (комментарий).

**Constraints:** статусы не повышаются; GO только при зелёном CI на точном HEAD и после ревью; Python в репозиторий не
попадает; личных путей и имён нет.

- [ ] Отчёт по образцу приёмок: §1 итог и границы (единый список условий GO), §2 коммиты и чистота дерева, §3 хэши
  (`rmasscan` на трёх ОС, `rmasscan-lab`, оракул `8afc8ec8…`), §4 топология и действия пользователя (сколько `sudo`
  фактически), §5 версии (ОС трёх стендов, Npcap, rustc), §6 результаты по стендам (таблица кейсов: обнаруженные
  значения, число ARP сканера и ОС, SYN, `sent`, `Discovered`; паритет C; preflight), §7 хэширование и полнота, §9 ошибки и
  ограничения (маршрут к единственной цели на одном хосте macOS не проверяем — только отказ и переопределения; MAC под
  root на Darwin доказан одним кейсом; физические NIC NOT RUN; VPN/туннели/VLAN/IPv6 не поддержаны; Ctrl-C без
  `paused.conf`; `--iflist` в evidence только редуцированно; порт источника один против {p, p+16}), §10 ревью, §12 CI, §13 заявление.
- [ ] Readiness: строка 2.3 «ARP codec / ARP resolver» → «кодек, резолвер и обнаружение шлюза: есть, приняты на трёх
  стендах (ссылка)»; таблица 1 получает строку «CLI live scan + autodetect» = **GO (stands)** при критерии ниже,
  «physical NIC» NOT RUN; раздел 6 «сетевая интеграция» обновляется (остаются network identity, sleep/VPN). Спека §0.2:
  строка ARP и строка `--offline --packet-trace`/CLI.
- [ ] README «Статус»/«Ограничения»: живой скан из CLI поддержан на запечатанных стендах; `rmasscan.yml`: комментарий
  «autodetect live suites are user/operator-run on the sealed stands; CI runs read-only detection tests only; no test
  opens an adapter».
- [ ] Workspace-тесты на трёх ОС перед push (логи в `verification/`); push; CI зелёный на точном HEAD (`rmasscan`,
  `Studio`, `language-guard`); удаление приватных target-каталогов и экспортов записано.
- [ ] Итоговое ревью ветки (только чтение): безопасность кадров до скана и в тестах, обнаружение, резолвер, CLI,
  лаборатория, evidence; исправления; если менялись `rmasscan-cli`/`net`/`core`/`engine` — повтор окон минимум `l01`,
  `l11`, `w01`, `m02` (и B/F на Mac) на исправленном коммите; если только `rmasscan-lab`/docs — пересчёт архива
  исправленным верификатором с неизменными вердиктами. Commit: `docs(cli): autodetect acceptance report and readiness`.

**GREEN:** отчёт с единым списком условий; readiness, спека §0.2, README согласованы; CI зелёный на HEAD; ревью APPROVED.

## GO и дальнейшая очередь

**GO «rmasscan live scan + autodetect (sealed stands)»:** код принят ревью; CI зелёный на точном HEAD на трёх ОС; ни
один тест ни на одной ОС не открывает адаптер; на закреплённом коммите `C`: Linux `linux-r1` PASS (автоопределение
интерфейса по маршруту, IPv4, MAC, шлюза on-link и через маршрут по умолчанию из dump-а, ARP, каждое переопределение,
оба отказа без кадров, `os_arp.requests == 0`, паритет с C-оракулом по байтам ARP-запроса, порядку SYN и множеству
`Discovered`); Windows `windows-r1` PASS (preflight назвал `Ethernet 2`, `GetBestRoute2`/`GetIpForwardTable2`/
`GetAdaptersAddresses`, NPF и дружественное имя, ARP к on-link цели, отказ многоцелевого on-link без шлюза, ограниченный
токен без кадров, ARP ядра гостя учтён отдельно, `eno1` 0 кадров); macOS `macos-r1` и `macos-root-r1` PASS (отказ по
маскированию без кадров, MAC под root, ARP, отказы «адрес хоста»/«нет IPv4», uplink 0 кадров); `[+] finished … sent N`
равен числу SYN сканера на проводе; ни одного кадра до скана, кроме 60-байтового ARP к одному адресу; статусы стендов
true до/после; хэши сходятся; privacy-скан чист (iflist редуцирован); действия пользователя ровно A, B, F. **GO не
распространяется** на физические NIC, VPN/туннели (DLT_NULL/RAW), VLAN, IPv6, сон/смену сети во время скана, форматы
вывода (этап 2), баннеры и user-mode TCP (этап 3), Studio.

Далее: **этап 2 — форматы вывода masscan через `Sink` (`-oL`, `-oJ`, `-oG`, `--open-only`/`--show`, строка статуса) →
этап 3 — баннеры и user-mode TCP (RX-путь engine остаётся прежним) → Studio: сетевая идентичность через
`rmasscan_net::discover` → физические NIC**.

## Решения этого плана (с причиной и ценой ошибки)

1. **Интерфейс = интерфейс маршрута к целям (lookup первой и последней unicast-цели обязаны совпасть), не «первый с
   маршрутом по умолчанию», как в masscan; маршруты по умолчанию читаются dump-ом/таблицей, а не lookup-ом `0.0.0.0`.**
   Причина: бриф называет «интерфейс, который маршрутизирует к целям, или маршрут по умолчанию»; для интернет-целей это
   одно и то же, для VPN/второго NIC — верный интерфейс; на Linux не-dump lookup `0.0.0.0` отвечает `local … lo`, а
   цели-пробы `0.0.0.0`/`255.255.255.255` из канонического `0.0.0.0/0 --exclude 255.255.255.255` дали бы ложные отказы —
   поэтому пробы только unicast. Отвергнуто: обход всех целей, per-target binding. Цена ошибки: цели в «середине»
   диапазона на другом интерфейсе не замечены — кадры уйдут через выбранный интерфейс (как у masscan всегда);
   `--adapter` переопределяет; preflight `--offline` перед маршрутозависимыми кейсами на двух-NIC хостах.
2. **Следующий хоп: `--router-ip` → шлюз маршрута к целям → (on-link) единственная цель = сама цель → (on-link,
   несколько целей) шлюз по умолчанию интерфейса (hairpin, как masscan) → отказ с тремя подсказками masscan.** Причина:
   masscan всегда шлёт в маршрутизатор; для одного соседа это бессмысленно и невозможно на стенде без шлюза (Windows
   `n2`); правило дешёвое; многоцелевой on-link сохраняет паритет. Цена ошибки: домашний маршрутизатор без hairpin даёт
   пустой результат, как у masscan; на стендах ветки доказаны `l02`, `w06`.
3. **Source IP = первый IPv4 интерфейса, MAC = MAC интерфейса (паритет `rawsock_get_adapter_ip/mac`); заполнитель Darwin
   и нулевой MAC отказывают с подсказками C дословно (`--source-mac`, `--source-ip`), алиасы `--source-ip`/`--source-mac`
   приняты; Wi-Fi (IfType 71) на Windows принимается как Ethernet-кадры (как C и Npcap DLT_EN10MB).** Цена ошибки:
   пользователь Mac без root обязан передать `--adapter-mac`/`--source-mac` — текст отказа говорит именно это.
4. **ARP: 10 запросов с шагом 1 с, отказ в 10 с (C: ~12 за ~11 с), часы инжектируются; критерии ответа `PendingResolve`
   (строже C); gratuitous/unsolicited игнорируются; отдельный короткоживущий адаптер с broadcast next hop, закрываемый до
   открытия адаптера скана; шов `open` отдаёт `AdapterPair`.** Причина: отдельный open не пускает кадры фазы ARP в engine и
   оставляет binding плана неизменяемым; `NetStatsHandle` нельзя подделать снаружи, а резолверу и engine нужен только
   `AdapterPair`, поэтому доказательство «кадры = SYN» строится на `sent` engine, напечатанном в `[+] finished`, и на
   проводе. Продукт зовёт `Engine::start_with_clock` (`#[doc(hidden)]`, «не часть стабильного API»): это единственный
   способ отдать engine те же часы, что и резолверу, и сделать `live_fake` детерминированным; в `OsBackend` часы —
   `SystemClock`, так что поведение равно `Engine::start`. Отвергнуто: один open с подменой `next_hop_mac`; публичный
   конструктор `OpenedAdapter`. Цена ошибки: второй open стоит миллисекунды; таймаут 10 с против 11 с не влияет на паритет
   (верификатор таймаута считает запросы rmasscan); если `start_with_clock` изменится, это ловит `live_fake`.
5. **Привилегии: обнаружение, `--iflist`, `--offline` без привилегий и без spawn; только `open` нуждается в root/
   Administrator/BPF; порядок «defaults → validate → detect → ARP → open»; ни один тест не достигает реального бэкенда
   (`OsBackend` под `cfg(not(test))`, fake паникует на `open`).** Причина: полные тесты GO идут на elevated госте с
   NAT-NIC — тест с реальным бэкендом послал бы кадры в реальную сеть. Цена ошибки: нет; проверяется компиляцией и
   ревью Focus 1.
6. **Значения по умолчанию: `--seed` из энтропии (печатается) только для живого скана, обязателен для `-sL`/`--echo`/
   `--offline` (решение по операции до `validate`); `--source-port` один порт `40000 + time % 20000` — отклонение от C
   ({p, p+16}, маска 16), потому что `AdapterBinding::source_ports` требует ширину-степень-двойки и ширина 17 не
   выражается без изменения контракта core/engine; `--offline` принудительно с фиктивным MAC шлюза и без поиска
   маршрутизатора (C); при всех явных значениях ОС не опрашивается — отклонение: C в offline всё равно ищет интерфейс по
   умолчанию без `--interface` (`main-initadapter.c:44–57`), rmasscan нет, чтобы golden-тесты оставались герметичными.**
   Причина: заголовочная команда брифа без `--seed`; детерминизм golden; минимальный diff core. Цена ошибки: случайный seed
   невоспроизводим без stderr — печатается всегда; один порт источника против двух не меняет ни один SYN в паритете, где
   `--source-port` задан явно; герметичный offline не влияет ни на один живой путь.
7. **Вывод: строка `Discovered open port N/tcp on IP` побайтно (дополнение до 79, flush, только open) за трейтом `Sink`;
   строки `[+]` на stderr всегда (masscan — с `-v`); отказы обнаружения и ARP печатаются в форме C — `[-] FAIL: …` и строки
   подсказок дословно, без обёртки `rmasscan: error:`; строки статуса нет; Ctrl-C не перехватывается.** Причина: паритет
   stdout проверяется оракулом; тексты отказов сравнимы с C строка в строку; шов для этапа 2; обработчик сигналов и
   `paused.conf` — отдельный механизм. Цена ошибки: пользователь теряет прогресс при Ctrl-C; записано в README.
8. **Стенды: Linux netns получает IPv4 на `veth-a`, маршрут по умолчанию через пира и постоянные neigh на цели (чтобы
   ядро сканера не слало ARP); `capture isolation` получает режим `autodetect`; macOS и Windows не меняются; macOS
   доказывает отказ по маскированию, MAC под root (одна команда пользователя), ARP, отказы и переопределения, но не
   маршрут к цели (на одном хосте цель локальна); Windows доказывает on-link цель без шлюза и отказ многоцелевого
   on-link; верификатор отличает ARP сканера (ARP-запрос с MAC сканера ровно 60 байт с нулевым дополнением, затем
   проверка цели и байтов `encode_request`) от ARP ОС (42-байтовые запросы и кадры opcode 2 с MAC сканера, включая ответы
   ядра гостя Windows на `who-has 198.18.0.1`); preflight `--offline` перед `w01`/`w06`/`m05` обязан равняться ожидаемому
   обнаружению кейса (NIC стенда либо отказ `LocalTarget` через `lo0`); на Windows `--iflist` редуцируется на home-pc до
   записи каталога прогона, `run.json` из JSON-строки не строится.** Причина: только Linux позволяет маршрутизируемый сценарий и паритет с
   C; изменение macOS-стенда нарушило бы правила `macos-lab status`; шлюз на лабораторном NIC гостя нарушил бы Verify.
   Цена ошибки: RST ядра сканера на Linux попадают в захват — верификатор их считает, не отвергает.
9. **Паритет с C-оракулом на minipc: байты ARP-запроса, упорядоченные SYN (`compare_streams`) и множество строк
   `Discovered` в одном стенде с одинаковыми argv без флагов адаптера; `--iflist` проверяется на месте и хранится только
   редуцированно (строка стенда, число строк, sha256) — и у rmasscan, и у оракула.** Причина: C `--iflist` это
   `pcap_findalldevs`, формат чужой; полный список интерфейсов реального хоста это инвентарь (privacy). Цена ошибки:
   отличие в `--iflist` невидимо тестом — записано как осознанное отклонение.
10. **Обнаружение, парсеры и резолвер живут в `rmasscan-net` (безопасные `discover`, `route_parse`, `arp_resolve` + FFI в
    `linux::route`, `macos::route`, `windows::sys`), CLI становится `[lib]` + тонкий бинарник и композирует за швом
    `Backend`; Studio не трогается, но сможет переиспользовать `discover`.** Причина: единственный crate с `unsafe`;
    seam-тесты на fake-таблицах, `FakeAdapter` и `ManualClock` покрывают весь путь офлайн и детерминированно на трёх ОС;
    переносимые парсеры тестируются без ядра. Цена ошибки: публичный API net расширяется (только добавления; Studio
    собирается без правок — проверяет CI `Studio`).
11. **Оставлено как есть из minor-замечаний ревью:** `w08` сохранён как два запуска runner под ограниченным токеном
    (`w08a` `--iflist`, `w08b` скан с ожиданием «отказ rc 1, 0 кадров» без привязки к виду `NetError`) — он проверяет, что
    `--iflist` работает под ограниченным токеном, чего прежние приёмки не показывали; `l12_iflist` сохранён в
    редуцированной форме ради записи `--iflist` оракула в том же стенде.
12. **Минимальный `live::Backend` в задаче 1 (`entropy64`, `unix_time`) с заглушкой `OsBackend`, расширяемый задачей 5
    до полного (`routes`, `interfaces`, `open`, `arp_policy`, `clock`).** Причина: задача 1 обязана компилироваться до
    задач 2 и 4 (N1); минимальный трейт покрывает политику seed. Цена ошибки: один дополнительный diff трейта в задаче 5.

## Действия пользователя (точные команды, когда, отмена)

Все команды выполняет пользователь в Terminal на Mac (не через `!`). Подстановки сообщает оператор перед действием:
`$LAB` (`rmasscan-lab` коммита `C` в `$SCRATCH/target-live/release/`), `$RM` (`rmasscan` там же), `$OUT`
(`$SCRATCH/autodetect-out`). Пароль вводится только в запросе `sudo`. На minipc и home-pc пользовательских действий нет
(существующее `sudo -n`, подтверждённое задачей 0; B1/B2 выполняет агент по решению пользователя).

| № | Когда | Команда | Что меняет | Отмена |
| --- | --- | --- | --- | --- |
| A | перед задачей 7 | сообщение «живые окна на стендах netns (minipc), n2 (home-pc) и feth (Mac) разрешены» (команды нет; решение 2026-10-27 уже выдано, подтверждается датой окна) | разрешает оператору raw-прогоны только на стендах, только на адреса `198.18.0.0/24` | сообщение «стоп»: оператор прерывает (Ctrl-C; suite рушит свидетелей; каталоги остаются для проверки изоляции) |
| B1 (агент, `sudo -n`, только если VM не запущена) | перед Windows-частью задачи 7 | `ssh home-pc 'cd ~/winvm && nohup ./run.sh >/dev/null 2>&1 &'`, затем `ssh -J home-pc -p 2222 lab@127.0.0.1 ver` | запускает QEMU Win11 с `lab.env` | `ssh -J home-pc -p 2222 lab@127.0.0.1 'shutdown /s /t 0'` |
| B2 (агент, `sudo -n`, только если стенд `n2` не поднят) | перед Windows-частью | `ssh home-pc 'sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab up --run-id n2 --manifest ~/winvm/lab/n2.json --lab-env ~/winvm/lab.env'`, перезапуск VM по B1, `record-guest` по `windows-vm-lab.md` | мост/TAP/netns `n2` без uplink | `ssh home-pc 'sudo -n ~/winvm/lab/bin/rmasscan-lab vm-lab down --run-id n2 --manifest ~/winvm/lab/n2.json'` |
| B | задача 7, macOS, после сборки оператора | `sudo "$LAB" macos-lab up --run-id m1 && sudo "$LAB" macos-lab bpf-access --run-id m1 --grant && sudo "$LAB" autodetect-suite macos --root-case --out "$OUT/macos-root-r1" --rmasscan "$RM" --lab "$LAB"` (один запрос пароля; прочитать предупреждение гранта; root-кейс длится ~30 с и печатает вердикт) | создаёт пару `feth4201/4202`, ARP, манифест `/var/run/rmasscan-lab/m1.json`; `/dev/bpf0..15` → `0660 root:staff` на сессию; пишет `$OUT/macos-root-r1` (chown на пользователя в конце) | `sudo "$LAB" macos-lab down --run-id m1` (снимает стенд и ставит `0600 root:wheel`); каталог `$OUT/macos-root-r1` удаляется `rm -r` |
| F | конец задачи 7 на Mac (и после любого повторного окна) | `sudo "$LAB" macos-lab down --run-id m1` | удаляет пару, ARP, манифест; `/dev/bpf*` → `0600 root:wheel` (это и есть revoke) | повторный подъём = действие B |
| G | после задачи 8 | слияние PR ветки `feat/rmasscan-autodetect` в `main` после зелёного CI (решение пользователя) | `main`: живой скан CLI | `git revert -m 1 <merge sha>` |

Повтор B нужен только если после окна изменились `rmasscan-cli`/`net`/`core`/`engine` (новый коммит, новое окно).
Постоянных изменений на хостах план не делает: стенды сессионные с явным `down`; на minipc netns удаляются скриптом;
маршруты, DNS, firewall, реальные NIC не меняются нигде.

## Источники и самопроверка

- Код: `rmasscan-cli/src/{main,args}.rs`, `Cargo.toml`, `tests/differential.rs`; `rmasscan-core/src/{config,probe,arp,receive,packet,throttle}.rs`;
  `rmasscan-engine/src/{io,events,engine,fake}.rs`; `rmasscan-net/src/lib.rs`, `linux/{mod,socket}.rs`,
  `macos/{mod,ifinfo,adapter,sys}.rs`, `windows/{mod,adapter,sys,inventory}.rs`, `examples/wire_scan.rs`,
  `tests/{macos_live,windows_live}.rs`; `rmasscan-lab/src/{wire_suite,macos_suite,macos_lab,windows_suite,vm_lab,verify,
  studio_verify,pcap,capture,peer,provenance,main}.rs`; `scripts/{wire-lab.sh,windows_wire_run.ps1,windows_wire_runas.cmd,
  language-guard.sh}`; `rmasscan/{Cargo.toml,Cargo.lock,deny.toml}`; `.github/workflows/{rmasscan,studio,language-guard}.yml`;
  Studio `studio/Cargo.toml`, `studio-protocol/src/lib.rs`, `studio-runner/src/main.rs`; реестр cargo: `libc 0.2.191`
  (нет `rtmsg`), `windows-sys 0.61.2` (IpHelper под включёнными features).
- C-оракул `8e6b3b0` (`$ORACLE_SRC`): `main-initadapter.c`, `stack-arpv4.c:103–262`, `rawsock.c:199–224`,
  `rawsock-getif.c` (`:55–178`, `:298–391`, `:416–495`), `rawsock-getroute.c` (`:110–230`, `:338–421`, `:444–570`),
  `rawsock-getip.c`, `rawsock-getmac.c`, `output.c:748–800`, `main.c:185–186`, `:736–750`, `:1228–1239`, `:1275–1292`,
  `:1315–1320`, `main-conf.c:2474–2500`, `:2486`, `:2556–2557`, `:2587–2641`, `:2820–2830`.
- Документы: `rmasscan/README.md`, `BENCHMARKS.md`, `docs/{rust-lab,macos-feth-lab,windows-vm-lab,windows-wire-lab}.md`,
  `tests/golden/wire/README.md`; спека порта §4.7–4.8, §10; спека Studio §0.1–0.2; readiness; приёмки macOS BPF §9,
  Studio feth §4, §9; Linux-приёмка §0; приёмка Windows VM (строки 113–114), доступ к VM; планы sendqueue и Studio feth
  (формат, исполнение); pre-flight ревью этого плана (M1–M6, S1–S13, minor — все учтены, отклонений нет; два minor
  приняты как решение 11) и его re-check r1 (R1, R2, N1–N5 и minor — учтены: Global Constraints, задачи 0, 1, 3, 5–7,
  константы, решения 4, 6, 7, 8, 11, 12).
- Review Focus 1→1/4/5/6; 2→2/3/5; 3→4/5/7; 4→1/5/6/7; 5→6/7/8. Публичные API: `open_explicit`, `AdapterBinding`,
  `ReadyPlan`, `Tx`/`Rx`, события engine не меняются; `rmasscan-net` расширяется модулями `discover`, `route_parse`,
  `arp_resolve` и функциями `os_route_table`/`os_interfaces`; `ScanConfig` получает одно поле; `rmasscan-cli` получает
  `[lib]`. Все привилегированные и стендовые действия вынесены в таблицу с отменой; живые испытания отделены от CI и от
  тестов (ни один тест не открывает адаптер); каждая задача несёт приватный `CARGO_TARGET_DIR` и запрет Python в
  репозитории; изменение стенда одно (Linux netns, с режимом isolation) и с отменой.
