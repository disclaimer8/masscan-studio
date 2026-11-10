# Живая приёмка управления сканом rmasscan (Linux) и регрессия форматов вывода и автоопределения (Linux, Windows VM)

План: `docs/superpowers/plans/2026-11-08-rmasscan-scan-control.md`, задача 8, шаг 2. Спека:
`docs/superpowers/specs/2026-11-08-rmasscan-scan-control-design.md`, §6.2–6.3.

Все четыре каталога сняты на одном коммите **C = `11a2235eaabd0abcff3fe90ab0b6953032ce4a48`** (2026-11-10), итоговом коде
этапа. HEAD ветки весь прогон стоял на C.
- Сборки на minipc, госте и home-pc сделаны из `git archive` этого коммита: на minipc и госте полное дерево, на home-pc
  `rmasscan/`. Оркестратор и верификаторы на Mac собраны из чистой рабочей копии на C (HEAD = C, `git status` пуст), как
  в шаге 5 раздела «Deployment» `rmasscan/docs/rust-lab.md`.
- Сборки: release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников лежат в `verification/binaries.sha256.txt`.
- Код продукта изменился после r3 (`e52793b`): волна исправлений итогового ревью `14200c5` (`--wait forever`,
  предупреждение `--shard` без `--seed`, отсчёт ожидания от конца передачи, `ndjson-status` из файлов, порог длины токена
  `privacy-scan`) и коммит документации и комментария `11a2235`. Бинарник `rmasscan` на minipc теперь `3a169c27…`
  (на `e52793b` был `bd9ea841…`).

Вердикты вынесли офлайн-верификаторы `scan-control-verify`, `output-verify`, `autodetect-verify`. Для Windows это
`windows-verify`, который передаёт каталог autodetect целиком в `autodetect-verify`. После копии в репозиторий хэши
каждого прогона проверены повторно, и верификатор копии дал тот же вердикт байт в байт.

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-scan-control-r4` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + вторая пара veth (`veth-a2`/`veth-b2`), C-оракул masscan 8e6b3b0 | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 10:58:21Z–11:00:34Z | `6993ae1f0cf73286f04a39f229e4122f6f06d723a3ca9962ce14472a781cb66d` |
| `linux-output-r4` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 11:00:35Z–11:05:53Z | `5272b145798f93a10c3c8ad6a0f00c4a5a68d5a9c1b748e23290396599d7774f` |
| `linux-autodetect-r4` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 11:05:55Z–11:07:32Z | `6fb4b0a2ccefecc5d008df0aaba6083cabb79524c4104769d19536ad90699342` |
| `windows-autodetect-r4` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 10:58:41Z–11:28:49Z | `a167b5a1ee951856acdd121f4ab3013c3d4b39f09874bd77458e21bc868f5464` |

Что не запускалось:
- macOS (`m1`): **NOT RUN**. Окно Mac требует `sudo` пользователя.
- Физические NIC: **NOT RUN**.
- Живой Ctrl-C на Windows: **NOT RUN**, консольное событие по ssh не доставить (спека §6.2). Обработчик покрыт
  юнит-тестами, живые прерывания сняты на Linux (`sc02`, `sc05`, `sc06`, `o14`–`o16`).

## Что проверено

- `linux-scan-control-r4`, живой паритет управления сканом:
  - `sc01`: `--shard 1/2` и `2/2` с одним `--seed` вместе шлют ровно 12 SYN без пересечений. Их находки вместе равны
    находкам одиночного прогона C, а порядок SYN оракула — это два шарда вперемешку.
  - `sc02`: SIGINT через 3 с, затем строка `saving resume file to: paused.conf` до первого тика ожидания. `paused.conf`
    на диске через 0,2 с после сигнала. Тики `waiting N-secs` считают от `--wait 2` вниз. Фаза ожидания принимает
    поздний ответ: netem 1000 мс на `veth-b` пира, ставится и снимается suite, факт записан в `netem.json`. `--resume`
    шлёт ровно остаток плана (59 из 80, точное мультимножество) и дописывает `-oJ`.
  - `sc03`: `--retries 2` шлёт каждый зонд `(2+1)^2 = 9` раз (108 SYN), мультимножество равно оракулу.
  - `sc04`: `--ttl 42 --tcp-sackok --tcp-wscale 7` на каждом SYN; `--badsum` (неверная L4-сумма при верной IPv4); файл
    `--pcap` сканера.
  - `sc05`: `--infinite` даёт больше одного полного прохода (218 SYN, 18 проходов), затем SIGINT, код 0, без
    `paused.conf`.
  - `sc06`: `--adapter[0]` на `veth-a` и `--adapter[1]` на `veth-a2`; точное разбиение плана по чётным и нечётным
    индексам. Ответы второго адаптера вернулись по второму линку, по одному различному ответу на SYN: повторы SYN-ACK
    пира к адресу `198.18.0.6`, который не назначен ни одному интерфейсу, — это тот же ответ, ядро их не обрывает RST.
    Ни одного непрошеного кадра. Пауза и `--resume` без потерь, дубли ограничены. На resume обе строки
    `source-port` — `(given)`.
- `linux-output-r4` и `linux-autodetect-r4` — повтор приёмок `2026-11-06-rmasscan-output-acceptance-raw` на C этого
  этапа.
  - Первое прерывание — пауза Р4, как в C (`main.c:1136-1139`, `main-conf.c:399-403`): stderr `o14`–`o16` несёт
    `waiting several seconds to exit...`, стирание из 70 пробелов, `saving resume file to: paused.conf`, тики ожидания и
    `[+] finished: Paused`.
  - `output-verify` принимает этот поток. Путь `Stopped` не тронут, закоммиченные каталоги прежнего этапа дают
    прежние вердикты.
- `windows-autodetect-r4` — повтор `windows-autodetect-r2` прежнего этапа на C этого этапа.

## Ворота

- Linux:
  - у каждого прогона `isolation.json`/`isolation-post.json` (режим `scan-control` у `linux-scan-control-r4` с
    `second_link`, режим `autodetect` у двух других);
  - отмена стенда записана в `teardown.json`: `namespaces_left: 0`, `lab_id` совпадает с `manifest.json`;
  - каждый захват `valid: true` без `invalid_reasons`;
  - wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0`;
  - удалённая оболочка всех окон и тестов на переднем плане ssh (`SigIgn: 0000000000000000`).
- Windows:
  - в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1` home-pc
    0 кадров; каждый захват `valid: true`;
  - preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`;
  - гостевой Verify шёл с nonce и `record-guest`; часы гостя относительно home-pc −0,22 с (preflight);
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории `e0385a8d…2ee9e6`); `manifest.json`
    и `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C,
    `git_dirty: false`; `exe.sha256` равен `rmasscan.exe` гостя (`ef5121a3…`).
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя (только выделенная VM `n2`)

В `windows-autodetect-r2` (на `1e38fca`, не закоммичен) захват `w03` нёс mDNS-объявления гостевой ОС на lab-NIC
(служба Delivery Optimization, DNS-SD-тип `_dosvc` в домене `.local`) с именем хоста гостя. Исправление стенда гостя
сделано перед окном r3 на `e52793b` и с тех пор не снималось. Его записи r3 лежат здесь же как запись состояния стенда
и рецепт отката:
- `verification/guest-stand-before.txt` — значения до исправления (рецепт отката; копия лежит на госте в
  `C:\Users\lab\guest-stand-before.txt`);
- `verification/guest-stand-applied.txt` — снимок сразу после применения (2026-11-10 08:12:50Z);
- `verification/guest-stand-after.txt` — снимок после перезагрузки гостя в r3.

| Настройка | До | После |
| --- | --- | --- |
| `EnableMDNS` (`Dnscache\Parameters`) | нет значения (по умолчанию вкл.) | 0 |
| `EnableMulticast` (LLMNR, политика `DNSClient`) | нет значения (по умолчанию вкл.) | 0 |
| `DODownloadMode` (политика Delivery Optimization) | нет значения | 99 |
| lab-NIC `Ethernet 2` (MAC `52-54-00-04-80-A9`) `ms_tcpip6` | True, адрес `fe80::…/64` | False, только `198.18.0.1/30` |
| lab-NIC NetBIOS (`NetbiosOptions`/`TcpipNetbiosOptions`) | 0 (по DHCP) | 2 (выкл.) |
| управляющий NIC `Ethernet` | `ms_tcpip6` True, NetBIOS 0 | без изменений |

Для r4 исправление **не применялось заново, а только проверялось** (pwsh 7, скриптом-файлом, `-Phase record`).
Значения прочитаны дважды: до `vm-lab up` (10:46:17Z) и после перезапуска VM для окна (10:57:51Z; `LastBootUpTime`
10:57:12Z, затем `w32tm /resync /force`, `Configure`, `record-guest`). Обе записи и сравнение лежат в
`verification/guest-stand-check-r4.txt`: каждая строка `reg` и `nic` обоих чтений байт в байт равна
`guest-stand-applied.txt`, поэтому ничего не переприменялось. Только для сведения: служба `DoSvc` читается как
`Stopped`, тип запуска `Manual` (в r3 `Automatic`); это не настройка исправления, оператор её не трогал. Исправление на
госте оставлено; когда его откатить, решает пользователь.

Результат: ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r4` нет ни UDP-, ни IPv6-кадра. `privacy-scan` не
нашёл ни одного кадра mDNS, LLMNR или NBNS.

## Privacy

`rmasscan-lab privacy-scan` (сборка C на Mac) прогнан по копии каждого каталога и `verification/` с `--forbid` для
каждого идентифицирующего имени длиной от 4 байт, известного оператору:
1. имя учётной записи Mac;
2. имя хоста Mac (`LocalHostName`, оно же `hostname -s`);
3. имя компьютера Mac (`ComputerName`);
4. имя хоста minipc;
5. имя хоста home-pc;
6. часть-имя учётной записи Mac;
7. часть-фамилия учётной записи Mac;
8. прежнее имя профиля Windows на home-pc.

Вывод с замаскированными токенами — в `verification/privacy-scan.txt`. Все восемь токенов дали **0 совпадений** во
всех четырёх каталогах, в `verification/` и в `README.md` (rc 0 везде).

На C `privacy-scan` отказывает токену короче 4 байт (rc 2) и в захватах сравнивает только данные кадров, без
заголовков записей pcap. Поэтому полное имя хоста гостя, **двухсимвольное** (проверено в r3 по шести источникам на
госте), токеном быть не может. Его покрывает проход по DNS-форме `privacy-scan`: любое имя в кадре mDNS, LLMNR или NBNS
печатается независимо от токенов. Таких кадров нет ни в одном захвате четырёх каталогов. Учётная запись minipc и home-pc
тоже двухсимвольная; её покрывают имена хостов 4 и 5, которые её содержат.

Дополнительно:
- `grep` по пути домашних каталогов Mac (`/Users` с косой чертой после него) во всём дереве — 0 совпадений; пути Windows с
  `Users` есть только у учётной записи гостя `lab` (`C:\Users\lab\…`), она разрешена;
- пословный регистрозависимый `grep -ralwE` из `rmasscan/docs/rust-lab.md` по именам хостов и учётных записей всех
  машин, в том числе коротким, плюс mDNS-суффиксы `_tcp`/`_udp` + `.local`, с `-a` — 0 файлов;
- полного `--iflist` нет нигде, только `iflist.json`.

## Стенды сняты

- netns minipc удалены скриптом (`teardown.json` трёх каталогов).
- `n2`: `vm-lab down` rc 0 (11:29:02Z); `status` показывает `state: down` и все четыре объекта MISSING
  (`verification/homepc-n2-status-after-down.json`); ни одного линка `wv*`, ни одной netns `wvp`, `lab.env` удалён.
  VM продолжает работать без бэкенда lab-NIC, как после прежних окон.

## Версии

- minipc: Linux 7.0.0-38-generic, tcpdump 4.99.6.
- home-pc: Linux 7.3.0-10-generic, QEMU 10.2.1.
- Гость: Windows 10.0.26300, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`). `rmasscan.exe` собран на госте со
  статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`verification/guest-exits.txt`: `OK … 0800 Dependent Load Flag`).
- Mac только оркестрирует `windows-suite` по ssh и запускает офлайн-верификаторы и `privacy-scan`. Живых кадров с Mac
  нет, `sudo` на Mac не использовался.

## verification/

- minipc: `cargo test --locked --workspace --no-fail-fast` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` — **1702 passed,
  0 failed**, 14 ignored, 48 тестовых бинарников (`minipc-test-ws.log`, `minipc-test-ws-exit.txt`). `cargo clippy
  --locked --workspace --all-targets -- -D warnings` — 0. Логи окон: `minipc-linux-*-r4-window.log`.
- Гость (сессия elevated, Npcap Admin-only, строгий флаг маршрута, n2 снят): `cargo test --locked --workspace
  --no-fail-fast` — **1598 passed, 0 failed**, 34 ignored, 48 тестовых бинарников; clippy `-D warnings` — 0
  (`guest-test-ws.log`, `guest-clippy.log`, `guest-exits.txt`).
- Тест fake-бэкенда `multi_adapter_paused_conf_round_trips_and_resumes` прошёл на обоих хостах.
- Mac: только сборка оркестратора (`mac-build-lab.log`; путь рабочей копии в нём заменён на `$REPO`).
- Остальное: `windows-autodetect-r4-suite.log`, `windows-autodetect-r4-verify.log`, `homepc-n2-status-*.json`,
  `guest-stand-check-r4.txt`, `guest-stand-{before,applied,after}.txt` (r3, см. выше), `privacy-scan.txt`,
  `hosts-versions.txt`, `binaries.sha256.txt`.

## Что было до этих каталогов (замещённые попытки)

r1 и r2 хранятся вне репозитория, в нейтральных каталогах оператора на Mac; r3 — в истории git.
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
- **r3 на `e52793b`.** Все четыре окна PASS: `linux-scan-control-r3` 7/7, `linux-output-r3` 18/18,
  `linux-autodetect-r3` 13/13, `windows-autodetect-r3` 10/10; закоммичены в `7773eb3`. Замещены этим r4, потому что
  волна исправлений итогового ревью (`14200c5`) изменила stderr: предупреждение `--shard` без `--seed` и отсчёт ожидания
  от конца передачи. Каталоги r3 и их `verification/` доступны в истории git на `7773eb3`.

## Отклонения

- `cargo test` шёл с `--no-fail-fast`.
- Гость: экспорт без `.git`, поэтому перед тестами сделан `git init; git add -A` (то же на minipc).
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло одновременно с окнами Linux на minipc. Стенды
  разные; через minipc шёл только ssh-трафик управления.
- Архивы `git archive` (полное дерево для minipc и гостя, `rmasscan/` для home-pc) переданы на minipc и home-pc по
  домашней сети напрямую (тот же хост, тот же ключ), хэш архива для гостя сверен (`verification/guest-exits.txt`,
  `tar sha256`). Сборки, тесты, все живые окна и `windows-suite` шли обычными `ssh minipc` / `ssh home-pc`.
- Оркестратор на Mac собран из чистой рабочей копии на C с уже существующим каталогом target вне репозитория, а не из
  `git archive`; пересобраны четыре крейта rmasscan (`mac-build-lab.log`). Его идентичность — sha256 в
  `verification/binaries.sha256.txt` и в `manifest.json` Windows.
- Файлы `verification/guest-stand-{before,applied,after}.txt` сняты в r3 и оставлены без изменений: исправление стенда,
  которое они описывают, действует и в r4.
