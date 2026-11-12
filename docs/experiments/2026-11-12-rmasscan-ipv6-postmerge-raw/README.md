# Живая приёмка IPv6 rmasscan после слияния с main (набор r3): Linux IPv6 и регрессии протоколов, управления сканом, форматов вывода и автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-08-rmasscan-ipv6.md`, задача 7, шаг 7d (решение контроллера Р25). Спека:
`docs/superpowers/specs/2026-11-08-rmasscan-ipv6-design.md`, §6.2–6.3. Прежняя приёмка этапа (набор r2 на `e9eaebeb`, до
слияния) лежит в `docs/experiments/2026-11-08-rmasscan-ipv6-acceptance-raw/` и не менялась. Этот каталог — набор r3 на
коде после слияния `origin/main` в ветку `feat/rmasscan-ipv6`: все шесть окон на одном коде, ни одно не замещено
(`verification/superseded-attempts.txt`). Номер набора продолжает нумерацию этапа: r1 и r2 были наборами задачи 7b.

Все шесть каталогов сняты на одном коммите **C = `0ce2a9e8e9c1fec8e56655cef6b258c0cd0e5a54`** (2026-11-12). HEAD ветки
весь набор r3 стоял на C, рабочая копия чистая.
- C = коммит слияния `ffb8d6c1` (родители `0e0bd100` — ветка после итогового ревью этапа, и `d2a6603f` — `origin/main`)
  плюс один коммит только с тестом (`0ce2a9e8`: план Studio с картой доставки никогда не встречает цель IPv6).
- Что принёс main (PR #54 и #57, интеграция Studio; в `rmasscan/` 25 файлов, +3713/−155): наблюдение маршрутов Linux
  (`linux/route_observation.rs`), ограниченный по времени обмен PF_ROUTE на macOS (`macos/route.rs`, `macos/ifinfo.rs`;
  поиск маршрута IPv6 `rt_get6` после слияния идёт через него), наблюдение адаптеров и маршрутов Windows
  (`windows/sys/observation.rs`; в `windows/sys.rs` оно стоит рядом с кодом IPv6 ветки), карта доставки IPv4 по целям в
  `ReadyPlan` (`destinations`, только у планов Studio), `network_plan.rs`, `neighbours.rs`, усиление политики ARP
  (`arp_resolve.rs`, `InvalidPolicy`), идентичность задания с картой (`identity.rs`), в лаборатории — одно чтение часов в
  `vm-lab record-guest` (`vm_lab.rs`). Процедура окон из-за этого не менялась (`rmasscan/docs/rust-lab.md` слиянием не
  тронут).
- Сборки на minipc и госте сделаны из `git archive` C (полное дерево, на госте затем `git init; git add -A`), на home-pc —
  из `git archive` каталога `rmasscan/`; каждая в свежем нейтральном каталоге со своим каталогом target. Оркестратор и
  верификаторы на Mac собраны из чистой рабочей копии на C.
- Сборки: release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников лежат в `verification/binaries.sha256.txt`. Бинарник продукта `rmasscan` на minipc `541eabd8…` (в r2
  был `479eaffe…`: после r2 в продукт вошли правки итогового ревью этапа и код main).

Вердикты вынесли офлайн-верификаторы `ipv6-verify`, `protocols-verify`, `scan-control-verify`, `output-verify`,
`autodetect-verify`; для Windows `windows-verify` передаёт каталог целиком в `autodetect-verify`. После копии в
репозиторий хэши каждого прогона проверены повторно, и верификатор копии дал тот же `verdict.json` байт в байт
(`verification/rederive-on-committed-copy.txt`).

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-ipv6-r3` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + IPv6 на паре veth (ULA `fd00:198:18::/64`, шлюз — link-local пира, постоянные соседи с обеих сторон), ответчик лаборатории с `--tcp6-ips`, C-оракул masscan 8e6b3b0 | `v01`–`v03` (+ манифест) | **PASS 4/4**, `safety_trips` [] | 19:39:50Z–19:42:01Z | `87902aa705879cb29bf5873bf4751b3e5b0178215e4adf1912637fd53c0a325e` |
| `linux-protocols-r3` | тот же стенд без IPv6, `--suite protocols` (+ `icmp_ratemask=0` в netns пира, ответчик UDP/SCTP) | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 19:42:13Z–19:45:35Z | `abe525f1bab736145bdd79061cd38025ed9efc3c5b5bfe12a660e185a35b950b` |
| `linux-scan-control-r3` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 19:45:53Z–19:48:06Z | `39746e75fc0aba49902390c9ff78f43eb518eb3c46619e165259d9936ff9a2c4` |
| `linux-output-r3` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 19:48:24Z–19:53:40Z | `d93f60540b44e94862da8ff8b9f96188879af6b2f528a8a6cd14a124c59e1565` |
| `linux-autodetect-r3` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 19:53:59Z–19:55:33Z | `9e45233481687cc34344e55615e953a568590ea2035f6a048edf7a4b48fff0a5` |
| `windows-autodetect-r3` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 19:58:53Z–20:29:29Z | `1f7aa5d9eecb7d3557b31bcd68523cfe5bb3b497a419ceedc20c562e9bbb2866` |

Что не запускалось:
- macOS (`m1`): **NOT RUN**. Окно Mac требует `sudo` пользователя; живые цели link-local на macOS тоже не проверены. Поиск
  маршрута IPv6 на macOS после слияния идёт через ограниченный обмен PF_ROUTE main; вживую он не снимался.
- Windows IPv6: **NOT RUN** (решение контроллера Р5): на госте `n2` IPv6 лабораторного NIC выключен исправлением стенда,
  гость не менялся; обнаружение IPv6 на Windows (`GetBestRoute2(AF_INET6)`, рядом с наблюдением main в `windows/sys.rs`)
  покрыто офлайн-тестами и CI.
- Studio: `cargo xtask test` (шаг «Offline contracts» `.github/workflows/studio.yml`: тесты, clippy, fmt) прогнан
  офлайн на Mac (ниже, «verification/»); упаковка `cargo xtask build`, шаги только Linux и только Windows этого
  рабочего процесса и живые окна Studio: **NOT RUN** локально, шлюз — Studio CI на PR.
- Физические NIC: **NOT RUN**.

## Что проверено в `linux-ipv6-r3`

Стенд, argv и проверки те же, что в `linux-ipv6-r2` (подробно — README прежнего каталога сырых данных этапа, раздел «Что
проверено в `linux-ipv6-r2`»): запечатанный стенд autodetect (`wl-scan`/`wl-peer`, `198.18.0.0/24`, без uplink), в котором
`wire-lab.sh --suite ipv6` только на паре veth и `lo` двух netns включает IPv6 без DAD, без RS/RA и без форвардинга; сканер
`fd00:198:18::1/64`, пиры `fd00:198:18::2`–`::5/64`, IPv6-маршрут сканера по умолчанию через link-local пира
`fe80::aa:ff:fe00:2`, постоянные соседи IPv6 с обеих сторон, включая оба link-local. Оракул — закреплённый C masscan
`8e6b3b0` (sha256 `8afc8ec8…`) с argv rmasscan плюс `--adapter-ip fd00:198:18::1` и `--router-mac-ipv6 02-aa-00-00-00-02`.
Всего 286 проверок, как в r2.

- Печать стенда `capture isolation --mode ipv6` (`isolation.json`/`isolation-post.json` каждого кейса): настройки veth
  (`disable_ipv6=0`, `accept_dad=0`, `accept_ra=0`, `router_solicitations=0`, `forwarding=0`, `addr_gen_mode=0`), маршруты
  main-таблицы у сканера ровно `default via fe80::aa:ff:fe00:2`, `fd00:198:18::/64`, `fe80::/64`, у пира два последних;
  постоянные соседи у сканера четыре пира и `fe80::aa:ff:fe00:2`, у пира сканер и `fe80::aa:ff:fe00:1`; ни одного tentative
  адреса (`ipv6-stack.json`).
- `v01_ndp_and_tcp6_syn`: rmasscan сам нашёл интерфейс, источник и шлюз (`[+] interface = veth-a (detected: route to
  [fd00:198:18::2])`, `source-ip = [fd00:198:18::1] (detected)`, `router-ip = [fe80::aa:ff:fe00:2] (interface default
  gateway)`) и разрешил MAC роутера по NDP: в каждом шаге одна NS резолвера (с `fd00:198:18::1` на `ff02::1:ff00:2` для
  `fe80::aa:ff:fe00:2`) до первого зонда, столько же, сколько в `(ndp: 1 requests`, и одна NA пира формы Linux на неё;
  `[+] finished: Completed, sent 8, replies 8, open 4`; SYN по IPv6 побайтно равны плану и SYN оракула.
- `v02_mixed_v4_v6`: один скан обеих семей, ARP 1 who-has и NDP 1 NS на шаг rmasscan, `sent 16, replies 16, open 8`;
  проверки инварианта v4 (Р21) «bytes» и «order: IPv6 takes the low shuffled indices» есть на обоих шагах rmasscan и
  прошли.
- `v03_explicit_router_mac_ipv6`: `[+] router-mac-ipv6 = 02-aa-00-00-00-02 (given)`, ни одной NS сканера.
- Кадры стороны сканера, не являющиеся зондами, все отнесены к названным классам (`unexplained` 0 в каждом из 10 шагов) и
  в своих границах: NS резолвера 1 в шагах rmasscan v01/v02 (граница 10), 0 в v03 и у оракула; who-has 1 в шагах v02;
  `rst_to_syn_ack` у rmasscan 4 (v02 8), у оракула 8 (v02 16); `rst_to_rst` у оракула 4 из 4 (v02 8 из 8), у rmasscan 0.
- Шум ядер (`STAND_NOISE`, граница 0): ни одного кадра ни в одном из 10 шагов (детали проверки `{}` везде).
- Порядок: `notes.reply_order_swaps` во всех 10 шагах `{"pairs": 0, "largest_gap_us": null}`; с документом C записи
  rmasscan «the same records in the same order» во всех пяти документах.
- Отклонения (`notes.deviations`): `ndp-ns-not-rs` (NS у оракула 0, у rmasscan по 1), `oracle-source-given` (0 IPv6-зондов
  оракула не с `fd00:198:18::1`), `ipv6-ttl-not-compared` (v01 16 записей C с TTL, все не равны hop limit; v02 8, из них 1;
  v03 4 из 4), `families-one-interface` (v02: у оракула по 8 зондов каждой семьи на одном линке).
- У каждого шага rmasscan код 0; у каждого шага оракула в stderr `[-] Passed the wait window but still running, forcing
  exit...`. `responder.json` всех 10 шагов: `{"exited_with": null, "killed_by_signal": null, "state_unknown": null,
  "stderr": ""}`.

## Регрессии

- `linux-protocols-r3` повторяет `linux-protocols-r2` тем же стендом, таблицей кейсов и верификатором: `p01`–`p05` PASS,
  419 проверок. Кадры стороны сканера: who-has 1 в каждом шаге не-ARP скана; ICMP 3/3 на ответы UDP 8 в `p02` и 4 в `p05`;
  ICMP 3/2 на ответы SCTP 8 в `p03` и 4 в `p05`; RST на SYN-ACK в `p05` 4 у rmasscan и 8 у оракула; `unexplained` 0.
  Все шесть отклонений с 0 случаев. Порядок: у оракула в `p02` по одной паре записей в обратном порядке внутри окна 50 мкс
  (`oracle-binary` 10 мкс, `oracle-json` 2 мкс), в остальных 14 шагах пар нет; с документом C — `p02` (`json`, `binary`) и
  `p05` (`json`) «те же записи в другом порядке», остальные пять — «в том же порядке».
- `linux-scan-control-r3`, `linux-output-r3` и `linux-autodetect-r3` повторяют каталоги `-r2` (тот же стенд, те же
  таблицы кейсов и верификаторы): `sc01`–`sc06`, `o01`–`o17`, `l01`–`l12`, все PASS, те же числа проверок, что в r2 (359, 759 и 412).
- `windows-autodetect-r3` повторяет `windows-autodetect-r2` (`w01`–`w08b`) на C. Код обнаружения на Windows слиянием
  менялся (наблюдение адаптеров и маршрутов main рядом с кодом IPv6 ветки в `windows/sys.rs`); окно проверяет, что
  путь IPv4 CLI тот же.

## Ворота

- Linux:
  - у каждого кейса `isolation.json`/`isolation-post.json` (режим `ipv6` у `linux-ipv6-r3`, `scan-control` со
    `second_link` у `linux-scan-control-r3`, `autodetect` у трёх других);
  - отмена стенда записана в `teardown.json`: `namespaces_left: 0`, `lab_id` совпадает с `manifest.json`;
  - каждый захват `valid: true` без `invalid_reasons`;
  - wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0` во всех пяти окнах, после каждого `ip netns list` пуст;
  - окна шли на переднем плане ssh (`ssh minipc 'bash <скрипт>'`). Первая строка `SigIgn` логов окон — маска самого
    bash скрипта (`0x4`: bash всегда игнорирует SIGQUIT для себя), вторая — маска потомков (`wire-lab.sh` и всё, что он
    запускает): `0000000000000000`.
- Windows:
  - в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1` home-pc
    0 кадров (каждый `eno1.pcap` — 24 байта, только заголовок файла); каждый захват `valid: true`;
  - preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`;
  - гостевой Verify шёл с nonce и `record-guest`; часы гостя относительно home-pc −0,56 с (preflight, неопределённость
    4,0 с; пределы +5 с и −60 с);
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории home-pc `fdaf2826…`); `manifest.json` и
    `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C,
    `git_dirty: false`, бинарник оркестратора `218ac96b…`; `exe.sha256` равен `rmasscan.exe` гостя (`d8819990…`), и каждый
    `guest-runner.json` называет тот же хэш;
  - перед набором `vm-lab status`: `state: up`, `attached`, `host_ok` (`verification/homepc-n2-status-before-suite.json`;
    `raw_run_allowed` там ещё false, его даёт гостевой Verify каждого прогона);
  - 299 проверок, тот же набор проверок, что у `windows-autodetect-r2`.
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя

Исправление стенда гостя (только выделенная VM `n2`: mDNS, LLMNR и Delivery Optimization выключены; на lab-NIC
`Ethernet 2` выключены IPv6 и NetBIOS; снимок применения —
`docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/verification/guest-stand-applied.txt`, рецепт отката
— `guest-stand-before.txt` там же и на госте `C:\Users\lab\guest-stand-before.txt`) для этого окна **не применялось
заново и не откатывалось, а только проверялось** (pwsh 7, скрипт-файл только для чтения). Значения прочитаны дважды: до
`vm-lab up` (19:48:01Z) и после перезапуска VM для окна (19:58:03Z; `LastBootUpTime` 19:57:33,5Z, затем запуск службы
w32time и `w32tm /resync /force`, после чтения — `Configure` и `record-guest`). Обе записи и сравнение лежат в
`verification/guest-stand-check-r3.txt`: каждая строка `reg` и `nic` обоих чтений равна снимку применения строка в
строку. Только для сведения: служба `DoSvc` читается как `Stopped`, тип запуска `Manual`, как в r2. Исправление на госте
оставлено; когда его откатить, решает пользователь. IPv6 на lab-NIC гостя остаётся выключенным (решение Р5), поэтому
окна Windows IPv6 нет.

Результат: ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r3` нет ни UDP-, ни IPv6-кадра.

## Privacy

`rmasscan-lab privacy-scan` (сборка C на Mac) прогнан по копии каждого каталога, по `verification/` и по всему каталогу
сырых данных (с `README.md`) с `--forbid` для каждого идентифицирующего имени длиной от 4 байт, известного оператору:
1. имя хоста Mac (`hostname`);
2. имя хоста Mac (`LocalHostName`);
3. имя компьютера Mac (`ComputerName`);
4. имя учётной записи Mac;
5. имя хоста minipc;
6. имя хоста home-pc;
7. прежнее имя профиля Windows на home-pc;
8. часть-имя учётной записи Mac;
9. часть-фамилия учётной записи Mac.

Вывод с замаскированными токенами — в `verification/privacy-scan.txt`. Все девять токенов дали **0 совпадений** во всех шести каталогах, в `verification/` и во всём каталоге (rc 0 везде);
положительный контроль (файл с токеном № 5 во временном каталоге) даёт попадание (rc 1).

`privacy-scan` отказывает токену короче 4 байт (rc 2, проверено и записано): учётная запись minipc и home-pc
двухсимвольная (её содержат имена хостов 5 и 6), полное имя хоста гостя двухсимвольное. Имена гостя покрывает проход по
DNS-форме: любое имя в кадре mDNS, LLMNR или NBNS, а также в кадрах ICMPv6, которые несут имена (DNSSL в RA, Node
Information), печатается независимо от токенов; таких кадров нет ни в одном захвате шести каталогов.

Дополнительно:
- `grep -ral` по путям домашних каталогов Mac и Linux (`/Users` и `/home` с косой чертой после), по префиксу домашней
  сети (`192.168` с точкой после), по корню scratch агента и по корню временных каталогов пользователя macOS во всём каталоге — 0 файлов; пути Windows
  с `Users` есть только у учётной записи гостя `lab` (`C:\Users\lab\…`), она разрешена; путь каталога Mac в логах окна
  Windows заменён на `$MACOUT`, путь рабочей копии в логе сборки Mac — на `$REPO`;
- пословный регистрозависимый `grep -ralwE` из `rmasscan/docs/rust-lab.md` по именам хостов и учётных записей всех
  машин, в том числе коротким (двухсимвольные учётная запись minipc и home-pc и имя хоста гостя), плюс mDNS-суффиксы
  `_tcp`/`_udp` + `.local`, с `-a` — два файла, `linux-scan-control-r3/runs/sc04_packet_mods_and_pcap/mods/scanner.pcap`
  (запись 12, считая с 1) и `…/mods/peer.pcap` (запись 36): это один и тот же 66-байтовый SYN-ACK пира в файле `--pcap`
  сканера и в захвате пира, где двухсимвольная учётная запись minipc и home-pc совпала с байтами `61 31` кадра (байты
  37–38: младший байт порта назначения TCP `0xce61` и первый байт номера последовательности `0x31aaf93d`). Просмотрено
  глазами: случайное совпадение в данных кадра, не имя (как велит `rust-lab.md`, записано здесь);
- полного `--iflist` нет нигде, только `iflist.json`.

## Стенды сняты

- netns minipc удалены скриптом (`teardown.json` пяти каталогов: `namespaces_left: 0`); после окон `ip netns list` не
  показывает ни одной `wl-*`.
- `n2`: `vm-lab down` rc 0 (20:29:45Z); `status` показывает `state: down` и все четыре объекта MISSING
  (`verification/homepc-n2-status-after-down.json`); ни одного линка `wv*`, ни одной netns `wvp`, `lab.env` удалён. VM
  продолжает работать без бэкенда lab-NIC, как после прежних окон.

## Версии

- minipc: Linux 7.0.0-38-generic, tcpdump 4.99.6, iproute2 6.19.0; SCTP в ядре не загружен; C-оракул masscan `8e6b3b0`
  (sha256 `8afc8ec8…`), `/etc/masscan` нет.
- home-pc: Linux 7.3.0-10-generic, QEMU 10.2.1, tcpdump 4.99.6.
- Гость: Windows 10.0.26300, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`), pwsh 7.6.10. `rmasscan.exe` собран на
  госте со статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`verification/guest-exits.txt`: `OK … 0800 Dependent Load Flag`).
- Mac (macOS 27.2.1) только оркестрирует `windows-suite` по ssh и запускает офлайн-верификаторы, `privacy-scan` и
  офлайн-тесты. Живых кадров с Mac нет, `sudo` на Mac не использовался.

## verification/

- minipc (свежий `git archive` C в новом нейтральном каталоге, свой каталог target): `cargo test --locked --workspace
  --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **2084 passed, 0 failed**, 14 ignored, 51 строка `^test result:`
  (`minipc-test-ws.log`, `minipc-gate-exits.txt`, `minipc-gate-start.txt`); `cargo clippy --locked --workspace
  --all-targets -- -D warnings` — 0 (`minipc-clippy.log`). Оба под `nice -n 19`: они шли одновременно с окном Windows, ssh
  которого идёт через minipc.
  Сборка окон: `minipc-build*.txt`, `minipc-build.log`, `minipc-exits.txt`. Логи окон: `minipc-linux-*-r3-window.log`
  (каталог, `SigIgn`, хэши бинарников, время, вывод `wire-lab.sh`, вердикт и его sha256).
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута, `n2` снят): `cargo test --locked --workspace
  --no-fail-fast` — **1973 passed, 0 failed**, 35 ignored, 51 строка `^test result:`; clippy `-D warnings` — 0
  (`guest-test-ws.log`, `guest-clippy.log`, `guest-exits.txt`, `guest-build-rmasscan.log`,
  `guest-dumpbin-loadconfig-rmasscan.txt`, `guest-dumpbin-dependents-rmasscan.txt`).
- Mac: сборка оркестратора (`mac-build-lab.log`; путь рабочей копии в нём заменён на `$REPO`); сводка тестов на C
  (`mac-test-ws-summary.txt`: `cargo test --locked --workspace --no-fail-fast` — **2201 passed, 0 failed**, 23 ignored,
  51 строка `^test result:`; clippy 0, `fmt --check` 0, `cargo check` Studio 0, language guard PASS, `git diff
  origin/main..HEAD -- studio rmasscan/Cargo.lock rmasscan/deny.toml` пуст); офлайн-тесты Studio
  (`mac-studio-xtask-test-summary.txt`: `cargo xtask test`, как шаг «Offline contracts» `.github/workflows/studio.yml` —
  тесты, clippy, fmt — rc 0, **484 passed, 0 failed**, 2 ignored, 43 строки `^test result:`).
- Строки `test result` во всех сводках считаны строгим `grep -c '^test result:'` (в r2 нестрогий `grep` засчитал ещё имя
  теста `test result_batches_respect_event_batch_limit` и дал 52 вместо 51).
- Остальное: `windows-autodetect-r3-suite.log`, `windows-autodetect-r3-verify.log`, `homepc-n2-status-*.json`,
  `guest-stand-check-r3.txt`, `privacy-scan.txt`, `hosts-versions.txt`, `binaries.sha256.txt`,
  `superseded-attempts.txt`, `rederive-on-committed-copy.txt` (хэши и повторный вердикт копии в репозитории).

## Отклонения

- `cargo test` шёл с `--no-fail-fast`; экспорт гостя и minipc для тестов без `.git`, перед тестами `git init; git add -A`.
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло после окон Linux; тесты и clippy на minipc шли
  одновременно с ним под `nice -n 19`. Стенды разные: на minipc в это время шли только тесты и ssh-трафик управления окна
  Windows. Сборка и тесты гостя шли до окна Windows, при снятом `n2` (одновременно с окнами Linux).
- На minipc в `/tmp` (tmpfs 7,5 ГБ) одновременно лежал только один экспорт: каталог окон удалён после того, как его
  evidence и логи забраны на Mac, и только потом создан каталог ворот.
- Всё к home-pc и гостю шло через minipc как jump-хост (как в r2).
- Оркестратор на Mac собран из чистой рабочей копии на C с каталогом target вне репозитория (не из `git archive`),
  скопирован в нейтральный каталог и запущен из корня репозитория с `--repo .`; его идентичность — sha256 в
  `verification/binaries.sha256.txt` и в `manifest.json` Windows.
- id набора Windows — `ipv6-windows-autodetect-r3` (по образцу r2); каталог evidence называется `windows-autodetect-r3`.
- Служба w32time на госте после перезапуска была остановлена (тип запуска Manual); оператор её запустил для
  `w32tm /resync`, как в прежних этапах. Это не настройка исправления стенда.
- Все команды на госте шли скриптами pwsh 7 (`-File`), ни одной встроенной строки `-Command`; имена скриптов
  `ipv6-7d-<случайное>-*.ps1` перед копированием проверены как свободные и удалены после окна. Вне pwsh на госте шли
  только команды cmd по ssh: `shutdown /s /t 0` (перезапуск VM для окна), `if exist`, `dir`, `type` и `hostname` (проверка
  имён, чтение файлов, имя гостя для пословного grep privacy).
