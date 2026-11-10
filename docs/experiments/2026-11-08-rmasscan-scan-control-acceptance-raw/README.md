# Живая приёмка управления сканом rmasscan (Linux) и регрессия форматов вывода и автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-08-rmasscan-scan-control.md`, задача 8, шаг 2. Спека:
`docs/superpowers/specs/2026-11-08-rmasscan-scan-control-design.md`, §6.2–6.3.

Все четыре каталога сняты на одном коммите **C = `e52793b71ddec6ae5a11de0dc99f8c9ebf4605af`** (2026-11-10).
- Каждая сборка сделана из `git archive` этого коммита: на minipc и госте полное дерево, на home-pc и Mac `rmasscan/`.
- Сборки: release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников лежат в `verification/binaries.sha256.txt`.
- Код продукта на C тот же, что на `1e38fca`: бинарник `rmasscan` на minipc совпал байт в байт (`bd9ea841…`).

Вердикты вынесли офлайн-верификаторы `scan-control-verify`, `output-verify`, `autodetect-verify`. Для Windows это
`windows-verify`, который передаёт каталог autodetect целиком в `autodetect-verify`. После копии в репозиторий хэши
каждого прогона проверены повторно, и верификатор копии дал тот же вердикт байт в байт.

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-scan-control-r3` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + вторая пара veth (`veth-a2`/`veth-b2`), C-оракул masscan 8e6b3b0 | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 08:10:32Z–08:12:46Z | `9b3de02582df1226189c489b5b8966574ef82984921e7ca79b7a41b77d80927a` |
| `linux-output-r3` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 08:12:48Z–08:18:03Z | `121b59c7827c9d50efc1c76df11eef350b5c4470e6a032ef6fb15c231a421f8c` |
| `linux-autodetect-r3` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 08:18:05Z–08:19:40Z | `cc1b9fef49cfb69e4aab59ba9db2d68b2532783e5f62dc12da67a60ba39ef6be` |
| `windows-autodetect-r3` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 08:15:16Z–08:45:20Z | `228a0b92e56842bdfdb985d5eb153df440a01644251fe4e19e781f978d799616` |

Что не запускалось:
- macOS (`m1`): **NOT RUN**. Окно Mac требует `sudo` пользователя.
- Физические NIC: **NOT RUN**.
- Живой Ctrl-C на Windows: **NOT RUN**, консольное событие по ssh не доставить (спека §6.2). Обработчик покрыт
  юнит-тестами, живые прерывания сняты на Linux (`sc02`, `sc05`, `sc06`, `o14`–`o16`).

## Что проверено

- `linux-scan-control-r3`, живой паритет управления сканом:
  - `sc01`: `--shard 1/2` и `2/2` с одним `--seed` вместе шлют ровно 12 SYN без пересечений. Их находки вместе равны
    находкам одиночного прогона C, а порядок SYN оракула — это два шарда вперемешку.
  - `sc02`: SIGINT через 3 с, затем строка `saving resume file to: paused.conf` до первого тика ожидания. `paused.conf`
    на диске меньше чем через секунду. Фаза `--wait 2` принимает поздний ответ: netem 1000 мс на `veth-b` пира, ставится
    и снимается suite, факт записан в `netem.json`. `--resume` шлёт ровно остаток плана (точное мультимножество) и
    дописывает `-oJ`.
  - `sc03`: `--retries 2` шлёт каждый зонд `(2+1)^2 = 9` раз (108 SYN), мультимножество равно оракулу.
  - `sc04`: `--ttl 42 --tcp-sackok --tcp-wscale 7` на каждом SYN; `--badsum` (неверная L4-сумма при верной IPv4); файл
    `--pcap` сканера.
  - `sc05`: `--infinite` даёт больше одного полного прохода, затем SIGINT, код 0, без `paused.conf`.
  - `sc06`: `--adapter[0]` на `veth-a` и `--adapter[1]` на `veth-a2`; точное разбиение плана по чётным и нечётным
    индексам. Ответы второго адаптера вернулись по второму линку, по одному различному ответу на SYN: повторы SYN-ACK
    пира к адресу `198.18.0.6`, который не назначен ни одному интерфейсу, — это тот же ответ, ядро их не обрывает RST.
    Ни одного непрошеного кадра. Пауза и `--resume` без потерь, дубли ограничены. На resume обе строки
    `source-port` — `(given)`.
- `linux-output-r3` и `linux-autodetect-r3` — повтор приёмок `2026-11-06-rmasscan-output-acceptance-raw` на C этого
  этапа.
  - Первое прерывание теперь — пауза Р4, как в C (`main.c:1136-1139`, `main-conf.c:399-403`): stderr `o14`–`o16` несёт
    `waiting several seconds to exit...`, стирание из 70 пробелов, `saving resume file to: paused.conf`, тики ожидания и
    `[+] finished: Paused`.
  - `output-verify` на C принимает этот поток. Путь `Stopped` не тронут, закоммиченные каталоги прежнего этапа дают
    прежние вердикты.
- `windows-autodetect-r3` — повтор `windows-autodetect-r2` прежнего этапа на C этого этапа.

## Ворота

- Linux:
  - у каждого прогона `isolation.json`/`isolation-post.json` (режим `scan-control` у `linux-scan-control-r3` с
    `second_link`, режим `autodetect` у двух других);
  - отмена стенда записана в `teardown.json`: `namespaces_left: 0`, `lab_id` совпадает с `manifest.json`;
  - wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0`;
  - удалённая оболочка всех окон и тестов на переднем плане ssh (`SigIgn: 0000000000000000`).
- Windows:
  - в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1` home-pc
    0 кадров;
  - preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`;
  - гостевой Verify шёл с nonce и `record-guest`;
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории `f20a6b4a…e9b249`); `manifest.json`
    и `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C,
    `git_dirty: false`.
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя перед окном (только выделенная VM `n2`)

В `windows-autodetect-r2` (на `1e38fca`, не закоммичен) захват `w03` нёс mDNS-объявления гостевой ОС на lab-NIC
(служба Delivery Optimization, DNS-SD-тип `_dosvc` в домене `.local`) с именем хоста гостя. Перед этим окном на госте сделано следующее
(pwsh 7, скриптом-файлом):
1. Записаны текущие значения: `verification/guest-stand-before.txt`; это и есть рецепт отката.
2. Применены настройки (снимок сразу после применения: `verification/guest-stand-applied.txt`):
   - `EnableMDNS = 0` (`Dnscache\Parameters`);
   - `EnableMulticast = 0` (политика `DNSClient`, LLMNR);
   - `DODownloadMode = 99` (политика Delivery Optimization);
   - на lab-NIC `Ethernet 2` (MAC `52-54-00-04-80-A9`) **только**: снят биндинг `ms_tcpip6` и выключен NetBIOS over
     TCP/IP (`NetbiosOptions = 2`).
3. Затем гость перезагружен: `vm-lab up`, затем `shutdown /s /t 0`, затем `run.sh` с `lab.env`. `LastBootUpTime`
   08:13:19Z, `Dnscache` стартовал 08:13:24Z, оба после применения в 08:12:50Z.
4. Затем `w32tm /resync /force`, `Configure`, `record-guest`.
5. Снова записаны значения: `verification/guest-stand-after.txt`.

До и после:

| Настройка | До | После |
| --- | --- | --- |
| `EnableMDNS` | нет значения (по умолчанию вкл.) | 0 |
| `EnableMulticast` (LLMNR) | нет значения (по умолчанию вкл.) | 0 |
| `DODownloadMode` | нет значения | 99 |
| lab-NIC `ms_tcpip6` | True, адрес `fe80::…/64` | False, только `198.18.0.1/30` |
| lab-NIC NetBIOS (`NetbiosOptions`/`TcpipNetbiosOptions`) | 0 (по DHCP) | 2 (выкл.) |
| управляющий NIC `Ethernet` | `ms_tcpip6` True, NetBIOS 0 | без изменений |

Результат: ни в одном `peer.pcap` прогонов `windows-autodetect-r3` нет ни UDP-, ни IPv6-кадра. `privacy-scan` не нашёл
ни одного кадра mDNS, LLMNR или NBNS.

## Privacy

`rmasscan-lab privacy-scan` прогнан по копии каждого каталога и `verification/` с `--forbid`:
- имя учётной записи Mac и имя хоста Mac;
- имена хостов minipc и home-pc;
- полное имя хоста гостя;
- часть-имя учётной записи Mac.

Вывод с замаскированными токенами — в `verification/privacy-scan.txt`.

**Идентифицирующие токены** (1–4 и 6) дали **0 совпадений** во всех четырёх каталогах и в `verification/`. Ни в одном
захвате нет кадров mDNS, LLMNR или NBNS.

Полное имя хоста гостя — **двухсимвольное**. Это проверено по шести источникам на госте: `COMPUTERNAME`,
`Dns.GetHostName`, `Win32_ComputerSystem` Name и DNSHostName, Tcpip `Hostname`/`NV Hostname`, `ActiveComputerName`.
Длину 2 подтверждает и метка имени в mDNS-кадре незакоммиченной попытки r2. Такое имя никого не идентифицирует.

У токена «двухсимвольное имя хоста гостя» 3 совпадения. Все три просмотрены вручную и оказались случайными байтами,
имени в них нет:

| Каталог | Кадры mDNS/LLMNR/NBNS | Токены 1–4, 6 | Двухсимвольное имя гостя | rc |
| --- | --- | --- | --- | --- |
| `linux-scan-control-r3` | 0 | 0 | 1: байты `77 2d` в заголовке записи pcap (поле наносекунд метки времени кадров 381–383 `sc05_infinite_interrupt/run/peer.pcap`); гость к стенду Linux не подключён | 1 |
| `linux-output-r3` | 0 | 0 | 0 | 0 |
| `linux-autodetect-r3` | 0 | 0 | 0 | 0 |
| `windows-autodetect-r3` | 0 | 0 | 0 | 0 |
| `verification/` | 0 | 0 | 2: те же два символа внутри имени крейта `linux-raw-sys` (`minipc-clippy.log`, `minipc-test-ws.log`) | 1 |

Почему так получилось: `privacy-scan` сравнивает токен без учёта регистра как подстроку, в тексте и в сырых байтах
захвата, включая заголовки записей. Двухсимвольный токен поэтому совпадает с посторонними байтами; rc 1 у двух строк
таблицы — только из-за этих трёх совпадений.

Пословный регистрозависимый `grep -ralwE` из `rmasscan/docs/rust-lab.md` даёт 0 совпадений по всем четырём каталогам и
`verification/`. Он шёл по именам хостов и учётных записей всех машин, в том числе коротким, плюс mDNS-суффиксы `_tcp`/`_udp` + `.local`,
с `-a`.

Пути вида `C:\Users\lab\…` относятся к учётной записи гостя `lab`, она разрешена. Полного `--iflist` нет нигде, только
`iflist.json`.

## Стенды сняты

- netns minipc удалены скриптом (`teardown.json` трёх каталогов).
- `n2`: `vm-lab down` rc 0; `status` показывает `state: down` и все четыре объекта MISSING
  (`verification/homepc-n2-status-after-down.json`); ни одного линка `wv*`, ни одной netns `wvp`, `lab.env` удалён.

## Версии

- minipc: Linux 7.0.0-38-generic, tcpdump 4.99.6.
- home-pc: Linux 7.3.0-10-generic, QEMU 10.2.1.
- Гость: Windows 10.0.26300, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`). `rmasscan.exe` собран на госте со
  статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`verification/guest-exits.txt`: `OK … 0800 Dependent Load Flag`).
- Mac только оркестрирует `windows-suite` по ssh и запускает офлайн-верификаторы и `privacy-scan`. Живых кадров с Mac
  нет, `sudo` на Mac не использовался.

## verification/

- minipc: `cargo test --locked --workspace --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **1695 passed,
  0 failed**, 14 ignored (`minipc-test-ws.log`, `minipc-test-ws-exit.txt`). `cargo clippy --locked --workspace
  --all-targets -- -D warnings` — 0. Логи окон: `minipc-linux-*-r3-window.log`.
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута): `cargo test --locked --workspace --no-fail-fast` —
  **1591 passed, 0 failed**, 34 ignored; clippy `-D warnings` — 0 (`guest-test-ws.log`, `guest-clippy.log`,
  `guest-exits.txt`).
- Тест fake-бэкенда `multi_adapter_paused_conf_round_trips_and_resumes` (сделан детерминированным в `b76a945`) прошёл
  на обоих хостах.
- Mac: только сборка оркестратора (`mac-build-lab.log`).
- Остальное: `windows-autodetect-r3-suite.log`, `windows-autodetect-r3-verify.log`, `homepc-n2-status-*.json`,
  `guest-stand-{before,applied,after}.txt`, `privacy-scan.txt`, `hosts-versions.txt`, `binaries.sha256.txt`.

## Что было до этих каталогов (не закоммичено)

Обе попытки хранятся вне репозитория, в нейтральных каталогах оператора на Mac.
- **r1 на `fd73de9`.** `linux-scan-control-r1`: PASS 6, FAIL 1 (`sc06_dual_veth`), остальные окна по правилу остановки
  не запускались. Причин две:
  - проверка верификатора «ответы на SYN второго адаптера вернулись по второму линку» требовала ровно один ответ на
    SYN. Но `198.18.0.6` не назначен ни одному интерфейсу, ядро сканера не обрывает SYN-ACK RST-ом, и пир повторяет
    SYN-ACK через ~1, 3 и 7 с (14 ответов на 6 SYN);
  - на resume строка `source-port[1]` говорила `(time)`, хотя порт унаследован от заданного `adapter-port`.

  Исправлено в `1e38fca`: различные ответы с дедупликацией повторов, проверка непрошеных кадров, происхождение
  унаследованного порта.
- **r2 на `1e38fca`.** `linux-scan-control-r2` PASS 7/7, `windows-autodetect-r3` (той попытки) PASS 10/10, но
  `linux-output-r2` дал FAIL: INVALID в `o14`–`o16`. Верификатор регрессии вывода ещё не знал новый поток первого Ctrl-C
  (Р4: пауза и `saving resume file`, `Paused`). `linux-autodetect-r3` по правилу остановки не запускался. Кроме того,
  захват `w03` той попытки нёс гостевые mDNS-кадры с именем хоста гостя: текстовый шаблон mDNS-суффикса их не находит,
  имена в DNS закодированы метками с длиной. Исправлено в `e52793b`: `output-verify` принимает поток паузы,
  подкоманда `privacy-scan` декодирует mDNS/LLMNR/NBNS. Стенд гостя исправлен, см. выше.

## Отклонения

- `cargo test` шёл с `--no-fail-fast`.
- Гость: экспорт без `.git`, поэтому перед тестами сделан `git init; git add -A`.
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло одновременно с окнами Linux на minipc. Стенды
  разные; через minipc шёл только ssh-трафик управления.
- Сборка, тесты и экспорт на minipc и home-pc (08:00–08:12Z) шли по домашней сети напрямую (тот же хост, тот же ключ).
  Обратный ssh-туннель minipc через hetzner в это время висел: старая сессия на hetzner держала порт 2201, туннель
  ушёл в перезапуск. Он восстановился сам, и все живые окна и `windows-suite` шли обычными `ssh minipc` / `ssh home-pc`.
- Пустой удалённый каталог r2 `~/winvm/t4-ev/windows-autodetect-r3` (без файлов и без маркера) удалён перед стартом,
  чтобы id `windows-autodetect-r3` начинался с чистого места.
