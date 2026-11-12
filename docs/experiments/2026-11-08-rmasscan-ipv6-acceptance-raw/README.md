# Живая приёмка IPv6 rmasscan (Linux) и регрессия протоколов, управления сканом, форматов вывода и автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-08-rmasscan-ipv6.md`, задача 7, шаг 7b (решение контроллера Р4). Спека:
`docs/superpowers/specs/2026-11-08-rmasscan-ipv6-design.md`, §6.2–6.3. Каталоги этого README — набор r2: все шесть окон
на одном коде. Набор r1 остановлен первым же окном (`linux-ipv6-r1`, INVALID) и замещён, см. ниже и
`verification/superseded-attempts.txt`.

Все шесть каталогов сняты на одном коммите **C = `e9eaebeb0fe2024bdde29961892e122cd93ab901`** (2026-11-12). HEAD ветки
весь набор r2 стоял на C, рабочая копия чистая.
- Сборки на minipc и госте сделаны из `git archive` этого коммита (полное дерево, на госте затем `git init; git add -A`),
  на home-pc — из `git archive` каталога `rmasscan/`; каждая в свежем нейтральном каталоге со своим каталогом target.
  Оркестратор и верификаторы на Mac собраны из чистой рабочей копии на C.
- Сборки: release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников лежат в `verification/binaries.sha256.txt`.
- C отличается от кода начала шага (`cbcffe72`, CI зелёный на трёх ОС) тремя правками лаборатории (продукт не менялся:
  бинарник `rmasscan` на minipc `479eaffe…` и в r1, и в r2):
  - `1abae2aa` — стенд IPv6: оба link-local адреса (`fe80::aa:ff:fe00:2` у сканера, `fe80::aa:ff:fe00:1` у пира) —
    постоянные соседи, печать стенда их требует;
  - `f346a66b` — названный класс кадров `rst_to_rst`: собственный RST C на RST стенда (закрытый порт), только на шаге
    оракула;
  - `e9eaebeb` — в `-oJ` C TTL записи IPv6 может быть любым 32-битным числом (названо в имени проверки и в правиле
    отклонения `ipv6-ttl-not-compared`); TTL в документах rmasscan остаётся байтом.

Вердикты вынесли офлайн-верификаторы `ipv6-verify`, `protocols-verify`, `scan-control-verify`, `output-verify`,
`autodetect-verify`; для Windows `windows-verify` передаёт каталог целиком в `autodetect-verify`. После копии в
репозиторий хэши каждого прогона проверены повторно, и верификатор копии дал тот же `verdict.json` байт в байт
(`verification/rederive-on-committed-copy.txt`).

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-ipv6-r2` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + IPv6 на паре veth (ULA `fd00:198:18::/64`, шлюз — link-local пира, постоянные соседи с обеих сторон), ответчик лаборатории с `--tcp6-ips`, C-оракул masscan 8e6b3b0 | `v01`–`v03` (+ манифест) | **PASS 4/4**, `safety_trips` [] | 08:03:15Z–08:05:25Z | `2d9e05c79df46a20323c31552179af0f25a5dc51dc0a04ab8f0cc618e8c60847` |
| `linux-protocols-r2` | тот же стенд без IPv6, `--suite protocols` (+ `icmp_ratemask=0` в netns пира, ответчик UDP/SCTP) | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 08:05:43Z–08:09:05Z | `3146bbf191996e8a6db4427cba54f1ea8bf1faa37fe387bd16f09fb35676cf7e` |
| `linux-scan-control-r2` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 08:09:30Z–08:11:43Z | `1695d5cb6a56afaa5342a959e220f8fa5a3c9a5d66c9368247cd1b285cc4ff1d` |
| `linux-output-r2` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 08:11:56Z–08:17:11Z | `b215ab08d6514f9e7627b38e9954a313496fb8dac0c19992f2e4abe179366e8a` |
| `linux-autodetect-r2` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 08:17:37Z–08:19:12Z | `4bd47b92928998ab702e0f9f6188cfed4ac6a5c1131605ba1afdfe8da1fdb0d7` |
| `windows-autodetect-r2` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 08:25:24Z–08:56:22Z | `bc26c06efa84a86dd08443aa5289ec39331d512c283609f8979d91a3aeaa5a06` |

Что не запускалось:
- macOS (`m1`): **NOT RUN**. Окно Mac требует `sudo` пользователя; живые цели link-local на macOS тоже не проверены.
- Windows IPv6: **NOT RUN** (решение контроллера Р5): на госте `n2` IPv6 лабораторного NIC выключен исправлением стенда,
  гость не менялся; обнаружение IPv6 на Windows (`GetBestRoute2(AF_INET6)`) покрыто офлайн-тестами и CI.
- Studio `cargo xtask test`: **NOT RUN** локально (решение контроллера Р16 прежнего этапа): `studio/` этим этапом не
  менялся (`git diff` от базы этапа `fdd18b37` пуст), шлюз — Studio CI на PR.
- Физические NIC: **NOT RUN**.

## Что проверено в `linux-ipv6-r2`

Стенд — запечатанный стенд autodetect (`wl-scan`/`wl-peer`, `198.18.0.0/24`, без uplink), в котором
`wire-lab.sh --suite ipv6` только для этого набора и только на паре veth и `lo` двух netns включает IPv6 (строки
`disable_ipv6=1` для всех наборов те же и идут первыми): без DAD (`accept_dad=0`, адреса `nodad`), без RS/RA
(`accept_ra=0`, `router_solicitations=0`), без форвардинга, link-local по EUI-64. Сканер `fd00:198:18::1/64`, пиры
`fd00:198:18::2`–`::5/64`; IPv6-маршрут сканера по умолчанию через link-local пира `fe80::aa:ff:fe00:2`; постоянные
соседи IPv6 с обеих сторон: у сканера четыре адреса пиров и link-local пира, у пира адрес сканера и link-local
сканера (link-local — правка `1abae2aa` после r1). Затем ожидание 3 с. Печать `capture isolation --mode ipv6`
(`isolation.json` и `isolation-post.json` каждого кейса) подтверждает ровно это: настройки veth, адреса (ни одного
tentative), маршруты main-таблицы (у сканера ровно `default via fe80::aa:ff:fe00:2`, `fd00:198:18::/64`, `fe80::/64`;
у пира два последних; ядро 7.0 других маршрутов в main не показало), постоянных соседей и `ip -6 route get 2001:db8::1`
(у сканера через пира, у пира — нет маршрута). Ответчик лаборатории слушает TCP 80 и 8080 и на каждом IPv6-адресе пира
(`--tcp6-ips`); закрытые порты получают RST ядра пира; на NS отвечает ядро пира.

Оракул — закреплённый C masscan `8e6b3b0` (sha256 `8afc8ec8…`) с argv rmasscan плюс `--adapter-ip fd00:198:18::1` (C
не берёт ULA источником, `rawsock-getip6.c:68-71`) и `--router-mac-ipv6 02-aa-00-00-00-02` (C ищет роутер RS/RA, пир
Linux RA не шлёт; решение Р11). Цели IPv6 в скобках (`[a]-[b]`, обе программы принимают). Argv всех кейсов:
`<цели> -p80,81 [-oX <файл>] --show open,closed --seed 1 --rate 100 --wait 3 --source-port 40000`. На каждый документ
кейса — прогон rmasscan и прогон оракула, у каждого свой захват пира и свой перезапущенный ответчик. Всего 286
проверок.

- `v01_ndp_and_tcp6_syn` (`[fd00:198:18::2]-[fd00:198:18::5]`, `-oJ` и `-oB`): rmasscan сам нашёл интерфейс, источник
  и шлюз (`[+] interface = veth-a (detected: route to [fd00:198:18::2])`, `source-ip = [fd00:198:18::1] (detected)`,
  `router-ip = [fe80::aa:ff:fe00:2] (interface default gateway)`) и разрешил MAC роутера по NDP: на проводе ровно одна
  NS резолвера (с `fd00:198:18::1` на `ff02::1:ff00:2`, цель `fe80::aa:ff:fe00:2`, 86 байт) до первого зонда, столько
  же, сколько в `(ndp: 1 requests`; на неё ровно одна NA пира в форме Linux (флаги S|O, TLLA). Восемь SYN по IPv6
  (78 байт) побайтно равны плану продукта и SYN оракула; записи `-oJ`/`-oB` (типы 10 и 11) равны ответам своего провода
  и записям C (без TTL IPv6, см. отклонения).
- `v02_mixed_v4_v6` (`198.18.0.2-198.18.0.5,[fd00:198:18::2]-[fd00:198:18::5]`, `-oB` и `-oL`): один скан обеих
  семей, один интерфейс и две строки источника (Р17), ARP (1 who-has) и NDP (1 NS). Инвариант v4 (Р21): каждый
  IPv4-зонд побайтно — зонд плана только IPv4 того же адреса и порта, ни один не потерян; IPv6 занимает нижние
  перемешанные индексы (`shuffle((i + rate) mod range) < range_ipv6`, main.c:258–260, 325–331), IPv4-зонд на позиции
  i — цель плана только IPv4 с индексом `x - range_ipv6`. Записи `-oB` четырёх типов (6, 7, 10, 11) и `-oL`.
- `v03_explicit_router_mac_ipv6` (как v01 плюс `--router-mac-ipv6 02-aa-00-00-00-02`, `-oJ`): ни одной NS сканера на
  проводе, `[+] router-mac-ipv6 = 02-aa-00-00-00-02 (given)`, каждый IPv6-зонд на заданный MAC.
- У каждого шага rmasscan: код 0, на stderr только строки `[+]` и формы строки статуса, `[+] finished: Completed,
  sent N, replies R, open O` равно зондам и различным ответам на проводе. У каждого шага оракула в stderr
  `[-] Passed the wait window but still running, forcing exit...` (подвала у его файла нет, это ожидаемо, как на стенде
  протоколов).
- Кадры стороны сканера, не являющиеся зондами, все отнесены к названным классам (`unexplained` 0 в каждом из 10 шагов)
  и не превышают своих границ (`notes.scanner_frames`, с `at_most`): NS резолвера 1 в каждом шаге rmasscan v01/v02
  (граница 10 = `NDP_TIMEOUT / NDP_INTERVAL`), 0 в v03 и у оракула; who-has 1 в шагах v02 (границы 10 и 12); RST на
  SYN-ACK — ядро сканера по одному на SYN-ACK у rmasscan (4, в v02 8), у оракула ещё собственный RST C на каждый
  различный SYN-ACK (8 из 8, в v02 16 из 16); новый класс `rst_to_rst` — собственный RST C на RST закрытого порта, у
  оракула 4 из 4 (v02 8 из 8), у rmasscan 0 из 0; NA на NS пира — 0 (пир не спрашивал).
- Шум ядер (`STAND_NOISE`: MLD, RS, RA, NS DAD, NS пира о сканере, NS ядра сканера о пире; граница 0) — ни одного кадра
  ни в одном шаге: ожидания 3 с хватило, чтобы отчёты MLD о новых группах закончились до первого захвата; ядра не
  слали NS (все соседи постоянные). В r1 именно здесь были кадры NUD для выученных link-local, см. ниже.
- Порядок записей: в каждом из 10 шагов `notes.reply_order_swaps` = `{"pairs": 0, "largest_gap_us": null}`; с документом
  C записи rmasscan совпали как мультимножество и в том же порядке во всех пяти документах (`notes.record_order_vs_c`).
- Отклонения от C (решения контроллера, не дефекты), у каждого своя проверка на стороне оракула, `notes.deviations`:
  `ndp-ns-not-rs` (Р11; NS у оракула 0, у rmasscan по 1), `oracle-source-given` (0 IPv6-зондов оракула не с
  `fd00:198:18::1`), `ipv6-ttl-not-compared` (C пишет как TTL записи IPv6 устаревшее значение: в `-oJ` 32-битное число,
  в `-oB` младший байт; в v01 16 записей C с TTL, все не равны hop limit; в v02 8, из них 1 не равна; в v03 4 из 4),
  `families-one-interface` (Р17; v02: у оракула оба семейства на одном линке стенда, по 8 зондов). TTL записей IPv6
  у rmasscan — hop limit ответа (64), проверен по своему проводу.
- `responder.json` всех 10 шагов: `{"exited_with": null, "killed_by_signal": null, "state_unknown": null, "stderr": ""}`.
  `ipv6-stack.json` всех трёх кейсов: настройки стенда, ни одного tentative/dadfailed адреса.

## Регрессии

- `linux-protocols-r2` повторяет на C каталог `linux-protocols-r4` приёмки протоколов IPv4
  (`2026-11-08-rmasscan-protocols-ipv4-acceptance-raw`) тем же стендом, той же таблицей кейсов и тем же верификатором:
  `p01`–`p05` PASS, 419 проверок, как в r4. Его верификатор на этом этапе стал общим кодом с IPv6 (`pair_verify.rs`,
  решение Р22); это окно показывает рефакторинг на живых данных: `protocols-verify` базы этапа (`fdd18b37`, до
  рефакторинга, собран из `git archive` в свежем каталоге) выносит этому каталогу тот же `verdict.json` байт в байт
  (`3146bbf1…`), а закоммиченный вердикт r4 протоколов (`ae05acb5…`) байт в байт выносят и верификатор `cbcffe72`, и
  верификатор C. Кадры стороны сканера как в r4 (who-has 1 в каждом шаге не-ARP скана; ICMP 3/3 на UDP-ответы 8 в
  `p02` и 4 в `p05`; ICMP 3/2 на SCTP-ответы 8 в `p03` и 4 в `p05`; RST на SYN-ACK в `p05` 4 у rmasscan и 8 у оракула;
  `unexplained` 0), все шесть отклонений с 0 случаев, `responder.json` всех 16 шагов — ответчик работал. Порядок: в
  `p05` у оракула одна пара записей в обратном порядке внутри окна 50 мкс (`largest_gap_us` 6), в остальных 15 шагах
  пар нет; с документом C — `p02` (`json`, `binary`) и `p05` (`json`) «те же записи в другом порядке», остальные пять
  — «в том же порядке».
- `linux-scan-control-r2`, `linux-output-r2` и `linux-autodetect-r2` повторяют на C каталоги `-r4` (тот же стенд, те же
  таблицы кейсов и верификаторы): `sc01`–`sc06`, `o01`–`o17`, `l01`–`l12`, все PASS, те же числа проверок (359, 759 и
  412).
- `windows-autodetect-r2` повторяет `windows-autodetect-r4` прежнего этапа (`w01`–`w08b`) на C. Код обнаружения на
  Windows этим этапом менялся (задача 5: `GetBestRoute2` для IPv6, адреса `AF_INET6`); окно проверяет, что IPv4-путь
  тот же.

## Ворота

- Linux:
  - у каждого кейса `isolation.json`/`isolation-post.json` (режим `ipv6` у `linux-ipv6-r2`, `scan-control` со
    `second_link` у `linux-scan-control-r2`, `autodetect` у трёх других);
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
  - гостевой Verify шёл с nonce и `record-guest`; часы гостя относительно home-pc −0,20 с (preflight);
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории `70e9c667…`); `manifest.json` и
    `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C,
    `git_dirty: false`; `exe.sha256` равен `rmasscan.exe` гостя (`42f7379a…`);
  - перед набором `vm-lab status`: `state: up`, `attached`, `host_ok` (`verification/homepc-n2-status-before-suite.json`).
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя

Исправление стенда гостя прежнего этапа (только выделенная VM `n2`: mDNS, LLMNR и Delivery Optimization выключены; на
lab-NIC `Ethernet 2` выключены IPv6 и NetBIOS; снимок применения —
`docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/verification/guest-stand-applied.txt`, рецепт отката
— `guest-stand-before.txt` там же и на госте `C:\Users\lab\guest-stand-before.txt`) для этого окна **не применялось
заново и не откатывалось, а только проверялось** (pwsh 7, скрипт-файл только для чтения). Значения прочитаны дважды: до
`vm-lab up` (08:17:18Z) и после перезапуска VM для окна (08:24:23Z; `LastBootUpTime` 08:23:36Z, затем запуск службы
w32time и `w32tm /resync /force`, после чтения — `Configure` и `record-guest`). Обе записи и сравнение лежат в
`verification/guest-stand-check-r2.txt`: каждая строка `reg` и `nic` обоих чтений равна снимку применения строка в
строку. Только для сведения: служба `DoSvc` читается как `Stopped`, тип запуска `Manual`, как в r3 и r4 прежнего этапа.
Исправление на госте оставлено; когда его откатить, решает пользователь. IPv6 на lab-NIC гостя остаётся выключенным
(решение Р5), поэтому окна Windows IPv6 нет.

Результат: ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r2` нет ни UDP-, ни IPv6-кадра.

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

Вывод с замаскированными токенами — в `verification/privacy-scan.txt`. Все девять токенов дали **0 совпадений** во всех шести каталогах, в `verification/` и во всём каталоге (rc 0 везде).

`privacy-scan` отказывает токену короче 4 байт (rc 2, проверено и записано): учётная запись minipc и home-pc
двухсимвольная (её содержат имена хостов 5 и 6), полное имя хоста гостя двухсимвольное. Имена гостя покрывает проход по
DNS-форме: любое имя в кадре mDNS, LLMNR или NBNS печатается независимо от токенов; таких кадров нет ни в одном захвате шести каталогов. С этого этапа тот же
проход печатает и имена из кадров ICMPv6, которые их несут (DNSSL в RA, Node Information); таких кадров нет.

Дополнительно:
- `grep -ral` по путям домашних каталогов Mac и Linux (`/Users` и `/home` с косой чертой после), по префиксу домашней
  сети (`192.168` с точкой после) и по корню scratch агента во всём каталоге — 0 файлов; пути Windows с `Users` есть
  только у учётной записи гостя `lab` (`C:\Users\lab\…`), она разрешена;
- пословный регистрозависимый `grep -ralwE` из `rmasscan/docs/rust-lab.md` по именам хостов и учётных записей всех
  машин, в том числе коротким (двухсимвольные учётная запись minipc и home-pc и имя хоста гостя), плюс mDNS-суффиксы
  `_tcp`/`_udp` + `.local`, с `-a` — один файл, `linux-output-r2/runs/o03_ndjson/peer.pcap`: двухсимвольная учётная
  запись minipc и home-pc совпала с байтами `61 31` номера последовательности TCP (запись 15 файла, считая с 1:
  58-байтовый SYN, байты 38–39 кадра, seq `0x61319152`) и номера подтверждения ответа на него (запись 16: RST-ACK
  пира, байты 42–43 кадра, ack `0x61319153`). Просмотрено глазами: случайное совпадение в данных кадра, не имя (как
  велит `rust-lab.md`, записано здесь);
- полного `--iflist` нет нигде, только `iflist.json`.

## Стенды сняты

- netns minipc удалены скриптом (`teardown.json` пяти каталогов: `namespaces_left: 0`); после окон `ip netns list` не
  показывает ни одной `wl-*`.
- `n2`: `vm-lab down` rc 0 (08:57:10Z); `status` показывает `state: down` и все четыре объекта MISSING
  (`verification/homepc-n2-status-after-down.json`); ни одного линка `wv*`, ни одной netns `wvp`, `lab.env` удалён. VM
  продолжает работать без бэкенда lab-NIC, как после прежних окон.

## Версии

- minipc: Linux 7.0.0-38-generic, tcpdump 4.99.6, iproute2 6.19.0; SCTP в ядре не загружен; C-оракул masscan `8e6b3b0`
  (sha256 `8afc8ec8…`), `/etc/masscan` нет.
- home-pc: Linux 7.3.0-10-generic, QEMU 10.2.1, tcpdump 4.99.6.
- Гость: Windows 10.0.26300, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`), pwsh 7.6.10. `rmasscan.exe` собран на госте
  со статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`verification/guest-exits.txt`: `OK … 0800 Dependent Load Flag`).
- Mac (macOS 27.2) только оркестрирует `windows-suite` по ssh и запускает офлайн-верификаторы и `privacy-scan`. Живых
  кадров с Mac нет, `sudo` на Mac не использовался.

## verification/

- minipc (свежий `git archive` C в новом нейтральном каталоге, свой каталог target): `cargo test --locked --workspace
  --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **2016 passed, 0 failed**, 14 ignored, 52 строки `test result`
  (`minipc-test-ws.log`, `minipc-gate-exits.txt`, `minipc-gate-start.txt`); `cargo clippy --locked --workspace
  --all-targets -- -D warnings` — 0 (`minipc-clippy.log`). Оба под `nice -n 19`: они шли одновременно с окном Windows,
  ssh которого идёт через minipc. Первая попытка тестов упала до тестов на компоновке (см. «Отклонения»). Сборка окон:
  `minipc-build*.txt`, `minipc-build.log`, `minipc-exits.txt`. Логи окон: `minipc-linux-*-r2-window.log` (каталог,
  `SigIgn`, хэши бинарников, время, вывод `wire-lab.sh`, вердикт и его sha256).
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута, `n2` снят): `cargo test --locked --workspace
  --no-fail-fast` — **1911 passed, 0 failed**, 34 ignored, 52 строки `test result`; clippy `-D warnings` — 0
  (`guest-test-ws.log`, `guest-clippy.log`, `guest-exits.txt`, `guest-build-rmasscan.log`,
  `guest-dumpbin-loadconfig-rmasscan.txt`, `guest-dumpbin-dependents-rmasscan.txt`).
- Mac: сборка оркестратора (`mac-build-lab.log`; путь рабочей копии в нём заменён на `$REPO`) и сводка тестов на C
  (`mac-test-ws-summary.txt`: `cargo test --locked --workspace --no-fail-fast` — **2144 passed, 0 failed**, 23 ignored,
  52 строки `test result`; clippy 0, `fmt --check` 0, `cargo check` Studio 0, language guard PASS).
- Остальное: `windows-autodetect-r2-suite.log`, `windows-autodetect-r2-verify.log`, `homepc-n2-status-*.json`,
  `guest-stand-check-r2.txt`, `privacy-scan.txt`, `hosts-versions.txt`, `binaries.sha256.txt`,
  `superseded-attempts.txt` (r1 и первая попытка тестов на minipc), `rederive-on-committed-copy.txt` (хэши и повторный
  вердикт копии в репозитории).

## Что было до этих каталогов (замещённые попытки)

Подробности, хэши и повторный вердикт — `verification/superseded-attempts.txt`.
- **r1 на `cbcffe72`** (не закоммичен). Шло только окно `linux-ipv6-r1` (правило остановки): INVALID 3 из 3 кейсов
  (`aed5cf52…`), все проверки шагов rmasscan прошли. Три причины, все — лаборатория или стенд, не продукт:
  1. собственный RST C на RST закрытого порта (main.c:1048–1101: C сбрасывает каждый первый ответ, SYN-ACK и RST) не
     был назван классом — «unexplained» на каждом шаге оракула; правка `f346a66b` (класс `rst_to_rst`);
  2. TTL записи IPv6 в `-oJ` C — устаревшее 32-битное значение (`"ttl": %u` от `ip_ttl`, который C задаёт только для
     IPv4; живые 320995840 и 2497958912), разборщик ждал байт — документ оракула «не разобран»; правка `e9eaebeb`
     (названное правило в имени проверки);
  3. выученные ядрами link-local соседи (после окна: `fe80::aa:ff:fe00:2` REACHABLE у сканера, `fe80::aa:ff:fe00:1` у
     пира) — NUD-пробы (unicast NS) попали в шаги `v03`; правка стенда `1abae2aa` (оба link-local — постоянные соседи,
     печать их требует).
  Каждая правка — свой коммит с офлайн-тестом в живой форме (RED ровно той проверкой, что упала вживую, затем GREEN).
  Верификатор C выносит r1: `v01`, `v02` PASS, `v03` INVALID только из-за шума NUD (причина 3), `a688a9f4…`.

## Отклонения

- `cargo test` шёл с `--no-fail-fast`; экспорт гостя и minipc для тестов без `.git`, перед тестами `git init; git add -A`.
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло после окон Linux; тесты и clippy на minipc шли
  одновременно с ним под `nice -n 19`. Стенды разные: на minipc в это время шли только тесты и ssh-трафик управления окна
  Windows. Сборка и тесты гостя шли до окна Windows, при снятом `n2`.
- Первая попытка тестов на minipc (до тестов, на компоновке) упала: компоновщик получил SIGBUS, потому что `/tmp`
  (tmpfs 7,5 ГБ) был занят на 80 % моими каталогами экспорта. Каталоги r1 и сборки окон удалены (их evidence забраны),
  тесты повторены в новом свежем каталоге — результат выше. Это среда, не код.
- Mac был вне домашней сети: всё к home-pc и гостю шло через minipc (jump-хост), к minipc — обычным `ssh minipc`.
- Оркестратор на Mac собран из чистой рабочей копии на C с уже существующим каталогом target вне репозитория (не из
  `git archive`), скопирован в нейтральный каталог и запущен из корня репозитория с `--repo .`; его идентичность —
  sha256 в `verification/binaries.sha256.txt` и в `manifest.json` Windows.
- id набора Windows — `ipv6-windows-autodetect-r2`: на home-pc в `~/winvm/t4-ev` уже лежал пустой каталог прежнего этапа
  с именем `windows-autodetect-r2`, новый id его не трогает. Каталог evidence называется `windows-autodetect-r2`.
- Служба w32time на госте после перезапуска была остановлена (тип запуска Manual); оператор её запустил для
  `w32tm /resync`, как в прежних этапах. Это не настройка исправления стенда.

