# Живая приёмка протоколов IPv4 rmasscan (Linux) и регрессия управления сканом, форматов вывода и автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-08-rmasscan-protocols-ipv4.md`, задача 7, шаг 2. Спека:
`docs/superpowers/specs/2026-11-08-rmasscan-protocols-ipv4-design.md`, §6.2–6.3 и поправки П1–П11. Каталоги этого
README — прогон r4: повтор всех пяти окон после итогового ревью этапа (решения контроллера Р20–Р22), на коде с
правками продукта и ужесточённым верификатором. Прогон r3 (код `0ed6e36`) им замещён, см. ниже и
`verification/superseded-attempts.txt`.

Все пять каталогов сняты на одном коммите **C = `82f048352f72929d5573c6b4d20f758ce13edbf3`** (2026-11-10). HEAD ветки
весь прогон r4 стоял на C, рабочая копия чистая.
- Сборки на minipc, госте и home-pc сделаны из `git archive` этого коммита: на minipc и госте полное дерево (затем
  `git init; git add -A`), на home-pc `rmasscan/`; каждая в свежем нейтральном каталоге со своим каталогом target.
  Оркестратор и верификаторы на Mac собраны из чистой рабочей копии на C.
- Сборки: release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников лежат в `verification/binaries.sha256.txt`.
- C отличается от кода r3 (`0ed6e36`) правками итогового ревью, шесть коммитов:
  - `82e01aa` — ответ ARP принимается, только если его `tpa` — адрес источника скана, как в C (`main.c:829–837`);
  - `ec67b3e` — `-sU`/`-sZ` левее файла `-c` или `--resume` задают префикс его строки `ports =`, как в C
    (`main-conf.c:2663–2674`);
  - `90b3ed5` — `--arp` снимает TCP по умолчанию у `--top-ports`, как в C (`main-conf.c:3609`);
  - `18f2c30` — тесты и комментарии: якорь индекса cookie в векторах C для UDP и SCTP, нестабильный тест паузы
    (упряжь, не продукт), устаревшие комментарии, нейтральный путь в манифесте эталонов;
  - `e43640c` — ужесточение `protocols-verify` (решение Р21, ниже);
  - `82f0483` — `Ended::Signal` лаборатории не мёртвый код для clippy на Windows (найдено сборкой гостя первой
    попытки r4, ниже).
  Бинарник продукта `rmasscan` на minipc `b6725146…` (в r3 `73409675…`: продукт изменился правками ARP, `-c` и
  `--top-ports`).

Вердикты вынесли офлайн-верификаторы `protocols-verify`, `scan-control-verify`, `output-verify`, `autodetect-verify`;
для Windows `windows-verify` передаёт каталог целиком в `autodetect-verify`. После копии в репозиторий хэши каждого
прогона проверены повторно, и верификатор копии дал тот же `verdict.json` байт в байт
(`verification/rederive-on-committed-copy.txt`).

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-protocols-r4` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + `icmp_ratemask=0` в netns пира, ответчик UDP/SCTP лаборатории, C-оракул masscan 8e6b3b0 | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 23:33:57Z–23:37:19Z | `ae05acb5fbb6224ad27ac25adddb7270f108d6705291dfacef1de81c0e3b1a8a` |
| `linux-scan-control-r4` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 23:37:35Z–23:39:48Z | `f97c4ccf4b97c6e91b109470bbc8db97c26378d922490910d2e935116eff587a` |
| `linux-output-r4` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 23:39:48Z–23:45:04Z | `8c00ab691f00aaa80f1e97811c3439309e50bb0d6d075184edbfd53152657a96` |
| `linux-autodetect-r4` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 23:45:04Z–23:46:39Z | `878e41245abc40e528bb6edf6c57ab3779320c2e809653303611713d931e5637` |
| `windows-autodetect-r4` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 23:52:07Z–00:22:26Z (2026-11-11) | `d8f8b6b436fa3d0118583ea02424e07b25112a604cd1d15b58bf7f38b830db5a` |

Что не запускалось:
- macOS (`m1`): **NOT RUN**. Окно Mac требует `sudo` пользователя.
- Studio `cargo xtask test`: **NOT RUN** локально (решение контроллера Р16): `studio/` этим этапом не менялся
  (`git diff` от базы этапа пуст), шлюз — Studio CI на PR, как на прежнем этапе.
- Физические NIC: **NOT RUN**.

## Что проверено в `linux-protocols-r4`

Стенд — запечатанный стенд autodetect (`wl-scan`/`wl-peer`, `198.18.0.0/24`, без uplink) плюс одно изменение
`wire-lab.sh --suite protocols` только в netns пира: `net.ipv4.icmp_ratemask=0` (каждый закрытый UDP-зонд получает
свой ICMP 3/3; записано в `commands.txt`, умирает вместе с netns). Ответчик пира (`capture responder`, лабораторный
код) отвечает на UDP 53/161 по сокету на адрес и порт и на SCTP INIT на самом линке (`INIT-ACK` на 2905, `ABORT`
иначе, в форме Linux); TCP, ICMP Echo и ARP — ядро пира. В ядре minipc SCTP не загружен (`peer-stack.json` каждого
кейса: `sctp_in_kernel: false`), модули не загружались и не выгружались, поэтому p03 и p05 выполнены. Оракул —
закреплённый C masscan `8e6b3b0` (sha256 `8afc8ec8…`) с тем же argv, отдельный прогон на каждый документ.

Все argv кейсов: `198.18.0.2-198.18.0.5 <флаги> [<-oX> <файл>] [--show open,closed] --seed 1 --rate 100 --wait 3
--source-port 40000` (таблица `protocols_verify::CASES`). На каждый документ кейса — прогон rmasscan и прогон оракула,
у каждого свой захват пира (`peer.pcap`) и свой перезапущенный ответчик. Всего 419 проверок.

- `p01_ping` (`--ping`, `-oL`): найдены все четыре пира; Echo Request обоих сканеров побайтно равны плану и между собой;
  у всех Echo Reply код 0.
- `p02_udp_payloads_and_closed` (`-sU -p53,161,500,59999`, `-oJ` и `-oB`): встроенные пейлоады DNS (53), SNMP (161),
  ISAKMP (500) и 0 байт на 59999 побайтно равны плану (`ReadyPlan` продукта) и зондам оракула; UDP 53/161 `open`
  (ответ ответчика), 500/59999 `closed` по ICMP 3/3 ядра пира; по 16 записей в каждом документе.
- `p03_sctp_init_ack_abort` (`-sZ -p2905,2906`, `-oB` и `-oL`): INIT побайтно равны плану и оракулу (CRC-32C); `INIT-ACK`
  на 2905 — `open`, `ABORT` на 2906 — `closed`; записи в том же порядке, что у C.
- `p04_arp_scan` (`--arp`, интерактивный stdout и `-oB` тип 8): четыре 42-байтовых who-has, ни одного ARP к шлюзу,
  `[+] router-mac = ff-ff-ff-ff-ff-ff (given)`; все четыре соседа с MAC пира. Каждый ARP-ответ стенда адресован сканеру
  (`tpa` 198.18.0.1), поэтому новая проверка `tpa` ни одного ответа не отбросила; ответов чужим узлам и gratuitous ARP
  на стенде нет (их отбрасывание покрыто офлайн-тестом). `[+] finished … open 0`: строка считает только открытые
  порты, записи ARP `up` в `open` не входят (решение Р22).
- `p05_mixed_protos` (`-pT:80,U:53,S:2905,I:0`, `-oJ`): одна выборка с записями tcp, udp, sctp и icmp (16 записей).
- У каждого шага rmasscan: код 0, на stderr только строки `[+]` и формы строки статуса,
  `[+] finished: Completed, sent N, replies R, open O` равно зондам и различным ответам на проводе. У каждого шага
  оракула в stderr `[-] Passed the wait window but still running, forcing exit...` (подвала у его файла нет, это
  ожидаемо).
- Кадры стороны сканера, не являющиеся зондами, все отнесены к четырём названным классам (`unexplained` 0 в каждом
  шаге) и не превышают своих границ (`notes.scanner_frames`, с `at_most`): next-hop who-has 1 в каждом шаге не-ARP
  скана (граница 10 у rmasscan, 12 у C); RST на SYN-ACK в `p05` 4 у rmasscan (граница 4: только ядро netns сканера)
  и 8 у оракула (новая граница 8 = 4 кадра SYN-ACK + 4 различных SYN-ACK: ядро на каждый кадр и собственный
  `tcp_send_RST` C после его дедупликации, `main.c:1067–1068`, `:1095`; повторов SYN-ACK на стенде не было, поэтому
  граница совпала с прежней 2 × 4); ICMP 3/3 на UDP-ответы 8 в `p02` и 4 в `p05`, ICMP 3/2 на SCTP-ответы 8 в `p03`
  и 4 в `p05` (по одному на ответ).
- Порядок записей. Каждый документ держит записи ответов своего провода поле в поле и в порядке ответов; пару ответов,
  снятых на линке пира не дальше 50 мкс друг от друга (промежуток по захвату, округлён до микросекунды; ровно 50 мкс
  внутри), документ может записать в любом порядке (`REPLY_REORDER_WINDOW_US`; до итогового ревью окно было 1 мс).
  В r4 ни один из 16 шагов такой пары не записал в другом порядке: `notes.reply_order_swaps` везде
  `{"pairs": 0, "largest_gap_us": null}`. При этом окну было что пропустить: в 13 шагах из 16 на линке пира есть
  соседние ответы не дальше 50 мкс друг от друга, всего 32 таких пары, ближайшие 4 мкс. С документом C записи
  rmasscan сравниваются как мультимножество (`notes.record_order_vs_c`): `p02` (`json`, `binary`) и `p05` (`json`) — те
  же записи в другом порядке (стенд ответил на пачку зондов в другом порядке, чем в прогоне оракула), остальные пять
  документов — те же записи в том же порядке. Зонды на захватах r4: соседние зонды пачки не дальше 0,27 мс друг от
  друга, вся пачка до 0,88 мс, пачки не ближе 8,6 мс.
- Отклонения от C (решения контроллера, не дефекты) названы в `notes.deviations` кейса, у каждого своя проверка
  провода: `udp-checksum-ffff` (R12) — 0 пар зондов, равных по этому правилу (суммы 0 на проводе не было);
  `icmp-echo-code-0` и `rx-checksum-verify` (R11) — 0 ответов с кодом не 0 и 0 ответов с неверной суммой;
  `non-tcp-dedup` — 0 повторённых записей UDP и SCTP у C; `sctp-tcp-fallthrough` — 0 ответов SCTP с флагами чанка
  SYN-ACK или RST; `arp-mac-ethernet-source` — 0 ARP-ответов с источником Ethernet, отличным от адреса отправителя.
  Значит, стенд не мог задействовать эти пути: живое окно показывает, что они не изменили сравнение, но не
  упражняет дедупликацию повторов, отбрасывание кода Echo, отличного от 0, и отбрасывание неверных сумм у rmasscan.
- `responder.json` всех 16 шагов: `{"exited_with": null, "killed_by_signal": null, "state_unknown": null, "stderr": ""}`
  — ответчик работал, когда сканер закончил. `peer-stack.json` всех пяти кейсов: `icmp_ratemask` 0,
  `icmp_echo_ignore_all` 0, `sctp_in_kernel` false.

## Регрессии

- `linux-scan-control-r4`, `linux-output-r4` и `linux-autodetect-r4` повторяют на C каталоги `-r4` приёмки управления
  сканом (`2026-11-08-rmasscan-scan-control-acceptance-raw`) тем же стендом, теми же таблицами кейсов и
  верификаторами: `sc01`–`sc06`, `o01`–`o17`, `l01`–`l12`, все PASS, те же числа проверок (359, 759 и 412).
- `windows-autodetect-r4` повторяет `windows-autodetect-r4` прежнего этапа (`w01`–`w08b`) на C.

## Ворота

- Linux:
  - у каждого кейса `isolation.json`/`isolation-post.json` (режим `scan-control` у `linux-scan-control-r4` со
    `second_link`, режим `autodetect` у трёх других);
  - отмена стенда записана в `teardown.json`: `namespaces_left: 0`, `lab_id` совпадает с `manifest.json`;
  - каждый захват `valid: true` без `invalid_reasons`;
  - wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0` во всех четырёх окнах;
  - сборка, окна и тесты шли на переднем плане ssh (`ssh minipc 'bash <скрипт>'`). Строка `SigIgn` в
    `minipc-build-sigign.txt` (`0x4`) и первая строка `SigIgn` логов окон — маска самого bash скрипта: bash всегда
    игнорирует SIGQUIT для себя и возвращает его своим потомкам; вторая строка логов окон и `minipc-sigign-check.txt`
    показывают маску потомков (`wire-lab.sh` и всё, что он запускает): `0000000000000000`. В r3 записывалась маска
    потомка.
- Windows:
  - в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1` home-pc
    0 кадров (каждый `eno1.pcap` — 24 байта, только заголовок файла); каждый захват `valid: true`;
  - preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`;
  - гостевой Verify шёл с nonce и `record-guest`; часы гостя относительно home-pc −0,10 с (preflight);
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории `0b16bdc5…68cd1`); `manifest.json`
    и `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C,
    `git_dirty: false`; `exe.sha256` равен `rmasscan.exe` гостя (`88c7bfa4…`).
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя

Исправление стенда гостя прежнего этапа (только выделенная VM `n2`: mDNS, LLMNR и Delivery Optimization выключены;
на lab-NIC `Ethernet 2` выключены IPv6 и NetBIOS; снимок применения —
`docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/verification/guest-stand-applied.txt`, рецепт отката
— `guest-stand-before.txt` там же и на госте `C:\Users\lab\guest-stand-before.txt`) для этого окна **не применялось
заново и не откатывалось, а только проверялось** (pwsh 7, скрипт-файл только для чтения). Значения прочитаны дважды:
до `vm-lab up` (23:47:35Z) и после перезапуска VM для окна (23:51:36Z; `LastBootUpTime` 23:50:46Z, затем запуск службы
w32time, `w32tm /resync /force`, `Configure`, `record-guest`). Обе записи и сравнение лежат в
`verification/guest-stand-check-r4.txt`: каждая строка `reg` и `nic` обоих чтений равна снимку применения строка в
строку. Только для сведения: служба `DoSvc` читается как `Stopped`, тип запуска `Manual`, как в r3. Исправление на
госте оставлено; когда его откатить, решает пользователь.

Результат: ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r4` нет ни UDP-, ни IPv6-кадра. `privacy-scan` не нашёл ни одного кадра mDNS, LLMNR или NBNS ни в одном захвате пяти каталогов.

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

Вывод с замаскированными токенами — в `verification/privacy-scan.txt`. Все девять токенов дали **0 совпадений** во
всех пяти каталогах, в `verification/` и во всём каталоге (rc 0 везде).

`privacy-scan` отказывает токену короче 4 байт (rc 2, проверено и записано): учётная запись minipc и home-pc
двухсимвольная (её содержат имена хостов 5 и 6), полное имя хоста гостя двухсимвольное. Имена гостя покрывает проход
по DNS-форме: любое имя в кадре mDNS, LLMNR или NBNS печатается независимо от токенов; таких кадров нет ни в одном
захвате пяти каталогов.

Дополнительно:
- `grep -ral` по путям домашних каталогов Mac и Linux (`/Users` и `/home` с косой чертой после) и по префиксу домашней
  сети (`192.168` с точкой после) во всём каталоге — 0 файлов; пути Windows с `Users` есть только у учётной записи
  гостя `lab` (`C:\Users\lab\…`), она разрешена;
- пословный регистрозависимый `grep -ralwE` из `rmasscan/docs/rust-lab.md` по именам хостов и учётных записей всех
  машин, в том числе коротким (двухсимвольные учётная запись minipc и home-pc и имя хоста гостя), плюс mDNS-суффиксы
  `_tcp`/`_udp` + `.local`, с `-a` — 0 файлов (в r3 было одно случайное совпадение в байтах заголовка записи pcap);
- полного `--iflist` нет нигде, только `iflist.json`.

## Стенды сняты

- netns minipc удалены скриптом (`teardown.json` четырёх каталогов: `namespaces_left: 0`); после окон `ip netns list`
  не показывает ни одной `wl-*`.
- `n2`: `vm-lab down` rc 0 (00:22:38Z); `status` показывает `state: down` и все четыре объекта MISSING
  (`verification/homepc-n2-status-after-down.json`); ни одного линка `wv*`, ни одной netns `wvp`, `lab.env` удалён.
  VM продолжает работать без бэкенда lab-NIC, как после прежних окон.

## Версии

- minipc: Linux 7.0.0-38-generic, tcpdump 4.99.6; SCTP в ядре не загружен; C-оракул masscan `8e6b3b0` (sha256
  `8afc8ec8…`), `/etc/masscan` нет.
- home-pc: Linux 7.3.0-10-generic, QEMU 10.2.1, tcpdump 4.99.6.
- Гость: Windows 10.0.26300, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`). `rmasscan.exe` собран на госте со
  статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`verification/guest-exits.txt`: `OK … 0800 Dependent Load Flag`).
- Mac (macOS 27.2) только оркестрирует `windows-suite` по ssh и запускает офлайн-верификаторы и `privacy-scan`. Живых
  кадров с Mac нет, `sudo` на Mac не использовался.

## verification/

- minipc: `cargo test --locked --workspace --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **1836 passed, 0 failed**, 14 ignored, 51 строка `test result`
  (`minipc-test-ws.log`, `minipc-test-ws-exit.txt`). `cargo clippy --locked --workspace --all-targets -- -D warnings` —
  0 (`minipc-clippy.log`). Оба под `nice -n 19`: они шли одновременно с окном Windows, ssh которого идёт
  через minipc. Сборка: `minipc-build*.txt`, `minipc-build.log`, `minipc-exits.txt`, `minipc-versions.txt`,
  `minipc-sigign-check.txt`. Логи окон: `minipc-linux-*-r4-window.log` (каталог, `SigIgn`, хэши бинарников, время,
  вывод `wire-lab.sh`, вердикт и его sha256).
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута, n2 снят): `cargo test --locked --workspace
  --no-fail-fast` — **1731 passed, 0 failed**, 34 ignored, 51 строка `test result`; clippy `-D warnings` — 0
  (`guest-test-ws.log`, `guest-clippy.log`, `guest-exits.txt`, `guest-build-rmasscan.log`,
  `guest-dumpbin-loadconfig-rmasscan.txt`).
- Mac: сборка оркестратора (`mac-build-lab.log`; путь рабочей копии в нём заменён на `$REPO`) и сводка тестов на C
  (`mac-test-ws-summary.txt`: `cargo test --locked --workspace --no-fail-fast` — **1964 passed, 0 failed**, 23 ignored,
  51 строка `test result`; clippy 0; строки `Running` с укороченными путями target).
- Остальное: `windows-autodetect-r4-suite.log`, `windows-autodetect-r4-verify.log`, `homepc-n2-status-*.json`,
  `guest-stand-check-r4.txt`, `privacy-scan.txt`, `hosts-versions.txt`, `binaries.sha256.txt`,
  `superseded-attempts.txt` (r3, первая попытка r4, r1 и r2), `rederive-on-committed-copy.txt` (хэши и повторный
  вердикт копии в репозитории).

## Что было до этих каталогов (замещённые попытки)

Подробности, хэши и повторные вердикты — `verification/superseded-attempts.txt`.
- **r3 на `0ed6e36`** (закоммичен в `63c88b9`, этим коммитом из каталога убран; история git его хранит). Все пять окон
  PASS (`linux-protocols-r3` 6/6 `57fbf950…`, `linux-scan-control-r3` 7/7 `6ccc5b14…`, `linux-output-r3` 18/18
  `0aedd55c…`, `linux-autodetect-r3` 13/13 `42e44370…`, `windows-autodetect-r3` 10/10 `ebbb0b0b…`). Замещён правками
  итогового ревью: правка приёма ARP меняет поведение приёма, поэтому все окна повторены. Верификатор C даёт каталогам r3
  тот же итог: `linux-protocols-r3` PASS 6/6 (единственная переставленная пара r3, шаг `json` кейса `p05`, —
  `largest_gap_us` 6, внутри нового окна), четыре остальных вердикта байт в байт прежние.
- **Первая попытка r4 на `e43640c`** (не закоммичена). Четыре окна Linux PASS (6/6, 7/7, 18/18, 13/13). Остановлена
  сборкой гостя: `cargo clippy -D warnings` на Windows нашёл мёртвый вариант `Ended::Signal` лаборатории; исправлено в
  `82f0483`, и все пять окон повторены на нём. Тесты гостя той попытки упали из-за ошибки оператора (значение
  `RMASSCAN_LAB_BUILD_COMMIT` с лишним `;`), не из-за кода; на C — 0 отказов.
- **r1 на `68ffcf3`** и **r2 на `5661a6e`** (окно протоколов задачи 7b, не закоммичены): FAIL из-за сравнения порядка
  записей с C и INVALID из-за гонки двух CPU в 5 мкс; привели к сравнению с C как мультимножеству и к окну порядка
  (тогда 1 мс, теперь 50 мкс).

## Отклонения

- `cargo test` шёл с `--no-fail-fast`; экспорт гостя и minipc без `.git`, перед тестами `git init; git add -A`.
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло после окон Linux; тесты и clippy на minipc
  шли одновременно с ним под `nice -n 19`. Стенды разные: на minipc в это время шли только тесты и ssh-трафик
  управления окна Windows.
- Архивы `git archive` (полное дерево для minipc и гостя, `rmasscan/` для home-pc) переданы на home-pc и гостя по
  домашней сети напрямую (тот же хост, тот же ключ), на minipc — обычным `ssh minipc`; хэш архива для гостя сверен
  (`verification/guest-exits.txt`, `tar sha256`, равен `git archive` C на Mac). Сборка, тесты и все живые окна Linux
  шли обычным `ssh minipc`, `windows-suite` — обычным `ssh home-pc` (через minipc); сборка на home-pc, сборка и тесты
  гостя и подготовка стенда n2 (`vm-lab up`, перезапуск VM, `Configure`, `record-guest`) — по домашней сети напрямую.
- Оркестратор на Mac собран из чистой рабочей копии на C с уже существующим каталогом target вне репозитория (не из
  `git archive`), скопирован в нейтральный каталог и запущен из корня репозитория с `--repo .`; его идентичность —
  sha256 в `verification/binaries.sha256.txt` и в `manifest.json` Windows.
- Служба w32time на госте после перезапуска была остановлена (тип запуска Manual); оператор её запустил для
  `w32tm /resync`, как в прежних этапах. Это не настройка исправления стенда.
