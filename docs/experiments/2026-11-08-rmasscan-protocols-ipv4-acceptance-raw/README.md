# Живая приёмка протоколов IPv4 rmasscan (Linux) и регрессия управления сканом, форматов вывода и автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-08-rmasscan-protocols-ipv4.md`, задача 7, шаг 2 (решение контроллера Р15: 7b — живые
окна и их сырые данные). Спека: `docs/superpowers/specs/2026-11-08-rmasscan-protocols-ipv4-design.md`, §6.2–6.3.

Все пять каталогов сняты на одном коммите **C = `0ed6e36a8a52c624b1422e008977b7b26b25797d`** (2026-11-10). HEAD ветки
весь прогон r3 стоял на C, рабочая копия чистая.
- Сборки на minipc, госте и home-pc сделаны из `git archive` этого коммита: на minipc и госте полное дерево (затем
  `git init; git add -A`), на home-pc `rmasscan/`; каждая в свежем нейтральном каталоге со своим каталогом target.
  Оркестратор и верификаторы на Mac собраны из чистой рабочей копии на C.
- Сборки: release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников лежат в `verification/binaries.sha256.txt`.
- Код продукта этой задачей не менялся: бинарник `rmasscan` на minipc `73409675…` одинаков во всех трёх попытках
  (r1, r2, r3). C отличается от начала задачи (`bac7a38`) только лабораторией (`rmasscan-lab`), три коммита:
  - `68ffcf3` — ужесточение до первого окна: границы числа кадров названных классов стороны сканера, `responder.json`
    шага (ответчик, умерший посреди шага, назван в вердикте), имя проверки `(non-tcp-dedup applied)` только там, где
    отклонение применяется;
  - `5661a6e` — записи rmasscan сравниваются с записями C как мультимножество (порядок каждого документа по-прежнему
    судится по его собственному проводу); причина — попытка r1, см. ниже;
  - `0ed6e36` — ответы, снятые на линке пира в пределах 1 мс друг от друга, документ может записать в любом порядке;
    причина — попытка r2, см. ниже.

Вердикты вынесли офлайн-верификаторы `protocols-verify`, `scan-control-verify`, `output-verify`, `autodetect-verify`;
для Windows `windows-verify` передаёт каталог целиком в `autodetect-verify`. После копии в репозиторий хэши каждого
прогона проверены повторно, и верификатор копии дал тот же `verdict.json` байт в байт
(`verification/rederive-on-committed-copy.txt`).

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-protocols-r3` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + `icmp_ratemask=0` в netns пира, ответчик UDP/SCTP лаборатории, C-оракул masscan 8e6b3b0 | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 20:05:14Z–20:08:36Z | `57fbf95084ef11767a7bf8ec52e6270b2259308612ad829d0fc5a349630014e0` |
| `linux-scan-control-r3` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 20:08:50Z–20:11:03Z | `6ccc5b147a32aea4a64a295f98f0023d3663cc5765f682e6cff6f5559d24d025` |
| `linux-output-r3` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 20:11:03Z–20:16:18Z | `0aedd55cf947de73439ba65d4bafa065eb9b22b8a36574e526ba232b6ca23fb7` |
| `linux-autodetect-r3` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 20:16:18Z–20:17:52Z | `42e443704a86f0fc872d2abce81458d65f50fdf8aeefbe81faa9b4173710e66c` |
| `windows-autodetect-r3` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 20:18:27Z–20:52:14Z | `ebbb0b0b1f9a81ada84a1213040167b68ec80ed53f3ff57d9289c6a2c4606454` |

Что не запускалось:
- macOS (`m1`): **NOT RUN**. Окно Mac требует `sudo` пользователя.
- Studio `cargo xtask test`: **NOT RUN** локально (решение контроллера Р16): `studio/` этим этапом не менялся
  (`git diff` от базы этапа пуст), шлюз — Studio CI на PR, как на прежнем этапе.
- Физические NIC: **NOT RUN**.

## Что проверено в `linux-protocols-r3`

Стенд — запечатанный стенд autodetect (`wl-scan`/`wl-peer`, `198.18.0.0/24`, без uplink) плюс одно изменение
`wire-lab.sh --suite protocols` только в netns пира: `net.ipv4.icmp_ratemask=0` (каждый закрытый UDP-зонд получает
свой ICMP 3/3; записано в `commands.txt`, умирает вместе с netns). Ответчик пира (`capture responder`, лабораторный
код) отвечает на UDP 53/161 по сокету на адрес и порт и на SCTP INIT на самом линке (`INIT-ACK` на 2905, `ABORT`
иначе, в форме Linux); TCP, ICMP Echo и ARP — ядро пира. В ядре minipc SCTP не загружен (`peer-stack.json` каждого
кейса: `sctp_in_kernel: false`), модули не загружались и не выгружались, поэтому p03 и p05 выполнены. Оракул —
закреплённый C masscan `8e6b3b0` (sha256 `8afc8ec8…`) с тем же argv, отдельный прогон на каждый документ.

Все argv кейсов: `198.18.0.2-198.18.0.5 <флаги> [<-oX> <файл>] [--show open,closed] --seed 1 --rate 100 --wait 3
--source-port 40000` (таблица `protocols_verify::CASES`). На каждый документ кейса — прогон rmasscan и прогон оракула,
у каждого свой захват пира (`peer.pcap`) и свой перезапущенный ответчик.

- `p01_ping` (`--ping`, `-oL`): найдены все четыре пира; Echo Request обоих сканеров побайтно равны плану и между собой;
  у всех Echo Reply код 0.
- `p02_udp_payloads_and_closed` (`-sU -p53,161,500,59999`, `-oJ` и `-oB`): встроенные пейлоады DNS (53), SNMP (161),
  ISAKMP (500) и 0 байт на 59999 побайтно равны плану (`ReadyPlan` продукта) и зондам оракула; UDP 53/161 `open`
  (ответ ответчика), 500/59999 `closed` по ICMP 3/3 ядра пира; по 16 записей в каждом документе.
- `p03_sctp_init_ack_abort` (`-sZ -p2905,2906`, `-oB` и `-oL`): INIT побайтно равны плану и оракулу (CRC-32C); `INIT-ACK`
  на 2905 — `open`, `ABORT` на 2906 — `closed`; записи в том же порядке, что у C.
- `p04_arp_scan` (`--arp`, интерактивный stdout и `-oB` тип 8): четыре 42-байтовых who-has, ни одного ARP к шлюзу,
  `[+] router-mac = ff-ff-ff-ff-ff-ff (given)`; все четыре соседа с MAC пира.
- `p05_mixed_protos` (`-pT:80,U:53,S:2905,I:0`, `-oJ`): одна выборка с записями tcp, udp, sctp и icmp (16 записей).
- У каждого шага rmasscan: код 0, на stderr только строки `[+]` и формы строки статуса,
  `[+] finished: Completed, sent N, replies R, open O` равно зондам и различным ответам на проводе. У каждого шага
  оракула в stderr `[-] Passed the wait window but still running, forcing exit...` (подвала у его файла нет, это
  ожидаемо).
- Кадры стороны сканера, не являющиеся зондами, все отнесены к четырём названным классам (`unexplained` 0 в каждом
  шаге) и не превышают своих границ (`notes.scanner_frames`, с `at_most`): next-hop who-has 1 в каждом шаге не-ARP
  скана (граница 10 у rmasscan, 12 у C); RST на SYN-ACK в `p05` 4 у rmasscan (граница 4: только ядро netns сканера)
  и 8 у оракула (граница 8: ядро плюс собственный `tcp_send_RST` C, `main.c:1095`); ICMP 3/3 на UDP-ответы 8 в `p02`
  и 4 в `p05`, ICMP 3/2 на SCTP-ответы 8 в `p03` и 4 в `p05` (по одному на ответ).
- Порядок записей. Каждый документ держит записи ответов своего провода поле в поле и в порядке ответов; пары
  ответов, снятых на линке пира ближе 1 мс друг к другу, могут идти в любом порядке (`REPLY_REORDER_WINDOW`,
  `notes.reply_order_swaps`). В r3 такая пара одна: шаг `json` кейса `p05` записал SYN-ACK 198.18.0.3:80 раньше
  INIT-ACK 198.18.0.5:2905, которое линк пира отправил на 7 мкс раньше (INIT-ACK шлёт поток ответчика, SYN-ACK — ядро
  пира, разные CPU); во всех остальных 15 шагах — 0. С документом C записи rmasscan сравниваются как мультимножество
  (`notes.record_order_vs_c`): `p02` (`json`, `binary`) и `p05` (`json`) — те же записи в другом порядке (стенд ответил
  на пачку зондов в другом порядке, чем в прогоне оракула), остальные пять документов — те же записи в том же порядке.
- Отклонения от C (решения контроллера, не дефекты) названы в `notes.deviations` кейса, у каждого своя проверка
  провода: `udp-checksum-ffff` (R12) — 0 пар зондов, равных по этому правилу (суммы 0 на проводе не было);
  `icmp-echo-code-0` и `rx-checksum-verify` (R11) — 0 ответов с кодом не 0 и 0 ответов с неверной суммой;
  `non-tcp-dedup` — 0 повторённых записей UDP и SCTP у C; `sctp-tcp-fallthrough` — 0 ответов SCTP с флагами чанка
  SYN-ACK или RST; `arp-mac-ethernet-source` — 0 ARP-ответов с источником Ethernet, отличным от адреса отправителя.
  Значит, стенд не мог задействовать эти пути: живое окно показывает, что они не изменили сравнение, но не
  упражняет дедупликацию повторов, отбрасывание кода Echo, отличного от 0, и отбрасывание неверных сумм у rmasscan.
- `responder.json` всех 16 шагов: ответчик работал, когда сканер закончил, его stderr пуст. `peer-stack.json` всех
  пяти кейсов: `icmp_ratemask` 0, `icmp_echo_ignore_all` 0, `sctp_in_kernel` false.

## Регрессии

- `linux-scan-control-r3`, `linux-output-r3` и `linux-autodetect-r3` повторяют на C этого этапа каталоги `-r4` приёмки
  управления сканом (`2026-11-08-rmasscan-scan-control-acceptance-raw`) тем же стендом, теми же таблицами кейсов и
  верификаторами: `sc01`–`sc06`, `o01`–`o17`, `l01`–`l12`, все PASS. Продукт rmasscan этим этапом изменился (UDP,
  ICMP Echo, SCTP, ARP, ICMP 3/3 для TCP), прежнее поведение TCP-скана, вывода и автоопределения на стенде то же.
- `windows-autodetect-r3` повторяет `windows-autodetect-r4` прежнего этапа (`w01`–`w08b`) на C этого этапа.

## Ворота

- Linux:
  - у каждого кейса `isolation.json`/`isolation-post.json` (режим `scan-control` у `linux-scan-control-r3` со
    `second_link`, режим `autodetect` у трёх других);
  - отмена стенда записана в `teardown.json`: `namespaces_left: 0`, `lab_id` совпадает с `manifest.json`;
  - каждый захват `valid: true` без `invalid_reasons`;
  - wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0` во всех четырёх окнах;
  - удалённая оболочка всех окон и тестов на переднем плане ssh (`SigIgn: 0000000000000000`).
- Windows:
  - в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1` home-pc
    0 кадров (каждый `eno1.pcap` — 24 байта, только заголовок файла); каждый захват `valid: true`;
  - preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`;
  - гостевой Verify шёл с nonce и `record-guest`; часы гостя относительно home-pc +0,12 с (preflight);
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории `1e9a6a32…d5e3`); `manifest.json`
    и `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C,
    `git_dirty: false`; `exe.sha256` равен `rmasscan.exe` гостя (`e79bc90a…`).
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя

Исправление стенда гостя прежнего этапа (только выделенная VM `n2`: mDNS, LLMNR и Delivery Optimization выключены;
на lab-NIC `Ethernet 2` выключены IPv6 и NetBIOS; снимок применения —
`docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/verification/guest-stand-applied.txt`, рецепт отката
— `guest-stand-before.txt` там же и на госте `C:\Users\lab\guest-stand-before.txt`) для этого окна **не применялось
заново и не откатывалось, а только проверялось** (pwsh 7, скрипт-файл только для чтения). Значения прочитаны дважды:
до `vm-lab up` (19:56:17Z) и после перезапуска VM для окна (20:18:07Z; `LastBootUpTime` 20:17:21Z, затем запуск службы
w32time, `w32tm /resync /force`, `Configure`, `record-guest`). Обе записи и сравнение лежат в
`verification/guest-stand-check-r3.txt`: каждая строка `reg` и `nic` обоих чтений байт в байт равна снимку
применения. Только для сведения: служба `DoSvc` читается как `Stopped`, тип запуска `Manual`, как в r4 прежнего
этапа. Исправление на госте оставлено; когда его откатить, решает пользователь.

Результат: ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r3` нет ни UDP-, ни IPv6-кадра. `privacy-scan` не
нашёл ни одного кадра mDNS, LLMNR или NBNS ни в одном захвате пяти каталогов.

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
  машин, в том числе коротким, плюс mDNS-суффиксы `_tcp`/`_udp` + `.local`, с `-a` — один файл,
  `linux-output-r3/runs/o12_nostatus/peer.pcap`: совпадение двухсимвольной учётной записи minipc/home-pc на байте
  2711 (0xa97) — это поле микросекунд заголовка записи pcap (`23 61 31 03`), не данные кадра и не имя; просмотрено
  глазами, как велит `rust-lab.md`;
- полного `--iflist` нет нигде, только `iflist.json`.

## Стенды сняты

- netns minipc удалены скриптом (`teardown.json` четырёх каталогов: `namespaces_left: 0`); после окон `ip netns list`
  не показывает ни одной `wl-*`.
- `n2`: `vm-lab down` rc 0 (20:52:33Z); `status` показывает `state: down` и все четыре объекта MISSING
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

- minipc: `cargo test --locked --workspace --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **1830 passed, 0 failed**, 14 ignored, 51 строка `test result`
  (`minipc-test-ws.log`, `minipc-test-ws-exit.txt`). `cargo clippy --locked --workspace --all-targets -- -D warnings` —
  0 (`minipc-clippy.log`). Оба под `nice -n 19`: они шли одновременно с окном Windows, ssh которого идёт
  через minipc. Сборка: `minipc-build*.txt`, `minipc-build.log`, `minipc-exits.txt`, `minipc-versions.txt`. Логи окон:
  `minipc-linux-*-r3-window.log` (каталог, `SigIgn`, хэши бинарников, время, вывод `wire-lab.sh`, вердикт и его sha256).
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута, n2 снят): `cargo test --locked --workspace
  --no-fail-fast` — **1726 passed, 0 failed**, 34 ignored, 51 строка `test result`; clippy `-D warnings` — 0
  (`guest-test-ws.log`, `guest-clippy.log`, `guest-exits.txt`, `guest-build-rmasscan.log`,
  `guest-dumpbin-loadconfig-rmasscan.txt`).
- Mac: только сборка оркестратора (`mac-build-lab.log`; путь рабочей копии в нём заменён на `$REPO`).
- Остальное: `windows-autodetect-r3-suite.log`, `windows-autodetect-r3-verify.log`, `homepc-n2-status-*.json`,
  `guest-stand-check-r3.txt`, `privacy-scan.txt`, `hosts-versions.txt`, `binaries.sha256.txt`,
  `superseded-attempts.txt` (попытки r1 и r2), `rederive-on-committed-copy.txt` (хэши и повторный вердикт копии в
  репозитории).

## Что было до этих каталогов (замещённые попытки)

Обе попытки не закоммичены; их каталоги во время задачи лежали в нейтральном каталоге оператора на Mac и при уборке
удалены. Подробности, хэши и повторный вердикт верификатором C — `verification/superseded-attempts.txt`.
Код продукта во всех трёх попытках один и тот же (`rmasscan` minipc `73409675…`); менялась только лаборатория.
- **r1 на `68ffcf3`.** `linux-protocols-r1`: FAIL 2 (`p02`, `p05`), PASS 4; verdict `75545d3f…`. Остальные окна по
  правилу остановки не запускались. Единственная проваленная проверка — сравнение документа rmasscan с документом C
  «в том же порядке». Каждый документ при этом держал записи ответов своего провода в порядке ответов, зонды обоих
  прогонов побайтно равны и в одном порядке. Причина: оба сканера шлют на `--rate 100` по нескольку зондов подряд, и
  внутри такой пачки ответчик (поток на каждый UDP-сокет и на SCTP-линк) и ядро пира отвечают в порядке, который
  меняется от прогона к прогону. Сравнение по порядку сравнивало хронометраж стенда, а не сканеры. Исправлено в
  `5661a6e`: с документом C записи rmasscan сравниваются как мультимножество, порядок каждого документа судится по его
  собственному проводу. Верификатор C даёт каталогу r1 PASS 6/6.
- **r2 на `5661a6e`.** `linux-protocols-r2`: INVALID 1 (`p05`), PASS 5; verdict `01bc9772…`. Остальные окна по правилу
  остановки не запускались. Единственная проваленная проверка — шаг `oracle-json` кейса `p05`: оракул записал SYN-ACK
  198.18.0.3:80 раньше INIT-ACK 198.18.0.5:2905, которое на захвате линка пира на 5 мкс раньше. Причина: свидетель
  пишет линк пира, а не сокет сканера; INIT-ACK шлёт поток ответчика, SYN-ACK — ядро пира, на разных CPU, и два кадра
  в микросекундах друг от друга доходят до сокета сканера в любом порядке. Исправлено в `0ed6e36`: пары ответов,
  снятых ближе 1 мс друг к другу, документ может записать в любом порядке (`REPLY_REORDER_WINDOW`, счётчик
  `reply_order_swaps` в заметках); записи разных слотов отправки местами меняться по-прежнему не могут (на
  захватах r3 зонды каждого шага шли либо пачкой, в пределах около 0,25 мс друг от друга, либо не ближе 8,4 мс). Верификатор C
  даёт каталогу r2 PASS 6/6 (`p05` `oracle-json`: одна такая пара).
- **r3 на `0ed6e36` (C)** — каталоги этого коммита. Та же картина встретилась в r3 у rmasscan (`p05` `json`, 7 мкс) и
  принята по тому же правилу.

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
  `git archive`) и запущен из нейтрального каталога; его идентичность — sha256 в `verification/binaries.sha256.txt` и
  в `manifest.json` Windows.
- Служба w32time на госте после перезапуска была остановлена (тип запуска Manual); оператор её запустил для
  `w32tm /resync`, как в прежних этапах. Это не настройка исправления стенда.
