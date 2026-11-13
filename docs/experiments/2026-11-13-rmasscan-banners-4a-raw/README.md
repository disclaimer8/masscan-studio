# Живая приёмка подэтапа 4a rmasscan (записи баннеров и UDP-баннеры): окно `banners` на стенде Linux, регрессии IPv6, протоколов, управления сканом, вывода и автоопределения (Linux, Windows VM), фаззинг UDP-парсеров

План: `docs/superpowers/plans/2026-11-13-rmasscan-banners-4a.md`, задача 7. Спека: `docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md`
(Р14, Р15, §7; изменения по итогам — §10). Справка C: `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-output-udp.md`
(B0–B10, C3.2). Отчёт: `docs/experiments/2026-11-13-rmasscan-banners-4a-acceptance.md`. Набор r1 — первый набор подэтапа;
ни одна попытка не замещена.

Все каталоги сняты на одном коммите **C = `39ba251ebfb020c1ff0b8b558c06169467b259d1`** (2026-11-13). Хосты называются по
ролям: хост стенда Linux (netns `wl-scan`/`wl-peer`, C-оракул), хост VM (QEMU-гость Windows 11, стенд `n2`), гость Windows, Mac
(оркестратор окна Windows, офлайн-верификаторы, фаззер, `privacy-scan`).
- Хост стенда Linux и гость: полное дерево из `git archive C` (sha256 архива `7bb508a3…` на обоих хостах; гость затем
  `git init; git add -A`); хост VM: `rmasscan/` из того же архива; Mac: чистая рабочая копия на C. Release,
  `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Хэши бинарников: `verification/binaries.sha256.txt`.

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-banners-r1` | хост стенда Linux, стенд протоколов (`icmp_ratemask=0` в netns пира), ответчик сценариев `--udp-answer banners`, C-оракул masscan 8e6b3b0 | `b01_banners`, `b02_rawudp` (+ манифест) | **PASS 3/3**, `safety_trips` [] | 19:26:52Z–19:28:34Z | `920c1d58c4fef4c3e46240e01b6bd621ff55bf815de46954bbf2551de6273607` |
| `linux-ipv6-r1` | тот же стенд + IPv6 на паре veth, `--suite ipv6` | `v01`–`v03` (+ манифест) | **PASS 4/4**, `safety_trips` [] | 19:30:02Z–19:32:12Z | `8edd87fa5d6c8b6810c113e0d37acb78694595ac8493d47f5feeddf92f7b4a80` |
| `linux-protocols-r1` | тот же стенд, `--suite protocols` | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 19:32:12Z–19:35:34Z | `a1d52ae409b9a8b52a6fe0fa748449cf1d96feac051d9d7ab944ead7f4bd60ba` |
| `linux-scan-control-r1` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 19:35:34Z–19:37:47Z | `d52b3f389dc39f59d99b9e624cbc5ffa3c4a2015fd18fa2871437a2e5581e2ad` |
| `linux-output-r1` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 19:37:47Z–19:43:02Z | `241c6a8004263565975916ac3057e1df144464392a8a88a82e4f11242e4e2768` |
| `linux-autodetect-r1` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 19:43:02Z–19:44:37Z | `beb5b48ae589f4e30ee6c261f991db1c50603eb647b698899bcf0b5882111840` |
| `windows-autodetect-r1` | хост VM, гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 19:49:32Z–20:19:29Z | `c4d9396bd617eca6320de8ff3f0422303fcec3e193b55830500e2cd7df37f2f6` |

Числа проверок: banners 228, ipv6 286, protocols 419, scan-control 359, output 759, autodetect 412 (последние пять — как в
r3 прошлого этапа), Windows 299 (как в r3). Вердикты вынесли офлайн-верификаторы; верификатор Mac на C дал те же `verdict.json`
байт в байт, что верификатор хоста стенда, и тот же на копии в репозитории (`verification/rederive-on-committed-copy.txt`).

## Окно `banners` (`linux-banners-r1`)

Таблица кейсов, argv и правила — `rmasscan/crates/rmasscan-lab/src/banners_verify.rs` и раздел «Banners suite»
`rmasscan/docs/rust-lab.md`. Argv: `198.18.0.2-198.18.0.5 -sU -p53,123,137,161,500,1900,5683,11211,16464 <--banners|--rawudp>
<-oB output.bin|-oL output.txt> --seed 1 --rate 100 --wait 3 --source-port 40000 --retries 0`, на документ шаг rmasscan и шаг
оракула, у каждого свой захват пира (`peer.pcap`) и перезапущенный ответчик. 36 сценариев (9 портов × 4 адреса пира) описаны в
`notes.scenarios` вердикта; ответы — эталоны C `rmasscan/tests/golden/udp-banners/cases/*.bin` с идентификатором зонда.

- Статусы и баннеры rmasscan равны C как мультимножество поле в поле без времени во всех четырёх документах (`b01`: 36
  статусов и 52 баннера в документе; `b02`: 36 и 60).
- Объявленное отличие `udp-raw-past-datagram` (C1.1, Р2): 16 сырых баннеров C на 11211 и 1900 в кейсе сравнены по наличию и в
  `-oB` по длине; у каждого из 8 таких баннеров `-oB` оракула длина его датаграммы.
- Каждый баннер идёт за статусом своего ответа с тем же временем; приложения баннеров 36 ответов равны объявленным; в `-oB`
  rmasscan сырой баннер равен датаграмме (28 в `b01`, 36 в `b02`).
- Зонды 36 на шаг, побайтно равны плану и зондам оракула; стенд ответил на каждый ровно одним ответом сценария; `responder.json`
  чистые; `peer-stack.json` стенда.
- rmasscan: код 0, `[+] finished: Completed, sent 36, replies 36, open 36`, ни `ConsumerTooSlow`, ни переполнения очереди.
  Оракул: `[-] Passed the wait window but still running, forcing exit...` на каждом шаге, файл без подвала.

## Фаззинг (`fuzz-udp-r1/`)

`rmasscan-lab fuzz udp` (Р15; `rmasscan/crates/rmasscan-lab/src/fuzz.rs`, раздел «Fuzzing the UDP banner parsers»
`rmasscan/docs/rust-lab.md`), сборка C на Mac, восемь процессов параллельно под `nice -n 19`, по 3700 с на порт:
19:29:43Z–20:31:23Z (`command.txt`, `exits.txt`: все восемь с кодом 0). Корпус: 198 эталонов C задач 4–5, 32 ответа сценариев
стенда, 256 датаграмм ответов из восьми `peer.pcap` окна `linux-banners-r1`.

| Порт | Входов | До текста парсера | Падения | > 100 мс | Инварианты | RSS КиБ: первый → 10 с → конец |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| 53 | 8 628 950 636 | 1 739 210 197 | 0 | 0 | 0 | 6640 → 8000 → 8048 |
| 123 | 7 872 963 127 | 5 503 884 511 | 0 | 0 | 0 | 6656 → 7408 → 7568 |
| 137 | 8 070 700 903 | 1 473 509 884 | 0 | 0 | 0 | 6528 → 7344 → 7424 |
| 161 | 4 968 573 431 | 1 544 967 039 | 0 | 0 | 0 | 6480 → 7136 → 7152 |
| 500 | 7 120 337 360 | 3 692 586 271 | 0 | 0 | 0 | 6512 → 7328 → 7376 |
| 5683 | 6 204 199 992 | 4 113 225 470 | 0 | 0 | 0 | 6512 → 7440 → 7440 |
| 11211 | 3 326 438 094 | 1 604 184 402 | 0 | 0 | 0 | 6608 → 7440 → 7472 |
| 16464 | 4 694 826 196 | 530 636 513 | 0 | 0 | 0 | 6640 → 7712 → 7744 |

Итого 50 886 989 739 входов без находок (`findings` пуст во всех отчётах, `clean: true`). Худший однократный замер `handle_udp`
46 мс (порт 53), среднее 71–741 нс на вход.


## Ворота

- Linux:
  - у каждого кейса `isolation.json`/`isolation-post.json` (режим `ipv6` у `linux-ipv6-r1`, `scan-control` со
    `second_link` у `linux-scan-control-r1`, `autodetect` у четырёх других);
  - отмена стенда в `teardown.json`: `namespaces_left: 0`, `lab_id` совпадает с `manifest.json`;
  - каждый захват `valid: true`;
  - wire-lab: `own_pids=0 stray_processes=0 namespaces_left=0` во всех шести окнах, после каждого `ip netns list` пуст;
  - окна шли на переднем плане ssh (`bash <скрипт окна>`); первая строка `SigIgn` логов окон — маска самого bash скрипта
    (`0x4`), вторая — маска потомков (`0000000000000000`).
- Windows:
  - в каждом из 9 прогонов `raw_run_allowed: true` и в `status-pre.json`, и в `status-post.json`; на `eno1` хоста VM 0 кадров
    (каждый `eno1.pcap` — 24 байта, только заголовок файла); каждый захват `valid: true`;
  - preflight `w01` и `w06`: `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)`;
  - гостевой Verify шёл с nonce и `record-guest`; часы гостя относительно хоста VM +0,45 с (preflight, неопределённость 3,2 с;
    пределы +5 с и −60 с);
  - деплой: `deploy/deploy-manifest.json` (коммит C, бинарник лаборатории хоста VM `84099c8a…`); `manifest.json` и
    `deploy/preflight-*.json`: `code_commit`, `orchestrator.build_commit` и `orchestrator.git_commit` равны C, `git_dirty: false`,
    бинарник оркестратора `3c52d906…`; `exe.sha256` равен `rmasscan.exe` гостя (`ff7ca27f…`), и каждый `guest-runner.json`
    называет тот же хэш;
  - перед набором `vm-lab status`: `state: up`, `attached`, `host_ok` (`verification/vm-host-n2-status-before-suite.json`;
    `raw_run_allowed` там ещё false, его даёт гостевой Verify каждого прогона); после `vm-lab down` (20:19:57Z, rc 0) все
    четыре объекта MISSING (`verification/vm-host-n2-status-after-down.json`), ни одного линка `wv*`, ни одной netns `wvp`,
    `lab.env` удалён. VM продолжает работать без бэкенда lab-NIC, как после прежних окон.
- Хэши: `hashes-before-copy.txt` каждого прогона сходятся до копии и после неё.

## Стенд Windows: исправление гостя

Исправление стенда гостя (только выделенная VM `n2`: mDNS, LLMNR и Delivery Optimization выключены; на lab-NIC `Ethernet 2`
выключены IPv6 и NetBIOS; снимок применения — `docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/verification/
guest-stand-applied.txt`) для этого окна не применялось заново и не откатывалось, а только читалось (pwsh 7, скрипт-файл только
для чтения). Оба чтения и сравнение — `verification/guest-stand-check-r1.txt`. Чтение 1 — до `vm-lab up` (19:35:20Z; первая попытка 19:35:00Z не прочитала реестр, см. файл), чтение 2 — после
перезапуска VM для окна (19:47:50Z, `LastBootUpTime` 19:47:19Z). Каждая строка `reg` и `nic` обоих чтений равна снимку применения.
Исправление на госте оставлено; когда его откатить, решает пользователь. Ни в одном из 9 `peer.pcap` прогонов
`windows-autodetect-r1` нет ни UDP-, ни IPv6-кадра.

## Privacy

`rmasscan-lab privacy-scan` (сборка C на Mac) прогнан по каждому каталогу, по `fuzz-udp-r1/`, по `verification/` и по всему
каталогу сырых данных (с `README.md`) с `--forbid` для каждого идентифицирующего имени длиной от 4 байт, известного оператору:
1. имя хоста Mac (`hostname`, `LocalHostName` — одно имя без учёта регистра);
2. имя компьютера Mac (`ComputerName`);
3. имя учётной записи Mac;
4. имя хоста стенда Linux;
5. имя хоста VM;
6. часть-имя учётной записи Mac;
7. часть-фамилия учётной записи Mac;
8. прежнее имя профиля Windows на хосте VM.

Вывод с замаскированными токенами — в `verification/privacy-scan.txt`. Все восемь токенов дали **0 совпадений** в каждом из
семи каталогов окон, в `fuzz-udp-r1/`, в `verification/` и во всём каталоге (rc 0 везде); положительный контроль (файл с
токеном № 4 во временном каталоге) даёт попадание (rc 1). Кадры NBNS окна `banners` (зонды NBSTAT сканера и ответы ответчика
на 137) `privacy-scan` считает отдельно как собственные кадры стенда: 64 в `linux-banners-r1` (8 шагов × 4 зонда и 4 ответа),
0 в остальных; это точное сравнение байтов с встроенным зондом и ответами сценария между MAC и адресами стенда (И5 спеки),
любой другой кадр NBNS был бы попаданием. Других кадров mDNS, LLMNR или NBNS и кадров ICMPv6 с именами ни в одном захвате нет.

`privacy-scan` отказывает токену короче 4 байт: учётные записи хоста стенда и хоста VM двухсимвольные, имя хоста гостя
трёхсимвольное. Их покрывает пословный регистрозависимый `grep -ralwE` (рецепт из `rmasscan/docs/rust-lab.md`) по именам хостов и
учётных записей всех машин, в том числе коротким, плюс `_tcp`/`_udp` + `.local`, с `-a` по всем файлам, pcap тоже: **0 файлов**.

Дополнительно `grep -ral` по путям домашних каталогов Mac и Linux (`/Users` и `/home` с косой чертой после), по префиксу домашней
сети (`192.168` с точкой после), по корню scratch агента и корню временных каталогов пользователя macOS во всём каталоге — 0
файлов. Имена хостов в именах файлов `verification/` заменены ролями (`linux-stand-*`, `vm-host-*`); полного `--iflist` нет
нигде, только `iflist.json`. Два старых строковых значения самого репозитория в evidence остаются как есть: имя файла
`pcap-hashes-on-home-pc.txt`, которое задаёт `windows-suite` (код лаборатории и прежние каталоги Windows), и причина `#[ignore]`
теста `offline_generation_meets_80pct_of_oracle` (`rmasscan-core/tests/offline_gen.rs:36`), которую печатают логи тестов; оба
уже в публичном коде, переименование изменило бы хэшируемые прогоны и вывод тестов.


## Версии

- Хост стенда Linux: Linux 7.0.0-38-generic, tcpdump 4.99.6, iproute2 6.19.0; SCTP в ядре не загружен; C-оракул masscan
  `8e6b3b0` (sha256 `8afc8ec8…`), `/etc/masscan` нет.
- Хост VM: Linux 7.3.0-10-generic, QEMU 10.2.1, tcpdump 4.99.6.
- Гость: Windows 10.0.26300, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`), pwsh 7.6.10.
- Mac (macOS 27.2): оркестратор `windows-suite` по ssh, офлайн-верификаторы, `privacy-scan`, фаззер, офлайн-тесты. Живых
  кадров с Mac нет, `sudo` на Mac не использовался.

## verification/

- `binaries.sha256.txt`; `mac-test-ws-summary.txt` (Mac: 2349 passed, 0 failed, 23 ignored, 55 строк; clippy, fmt, language
  guard, `cargo check` Studio), `mac-build-lab.log`; `tdd-red-lab.txt`, `tdd-green-lab.txt` (RED задачи 7 против заглушек и
  GREEN); `precheck-c-eth-apps.txt` (вывод C обвязки эталонов на 36 ответах сценариев в кадре Ethernet + IPv4, с `--rawudp` и
  без: приложение и длина каждого баннера).
- Хост стенда Linux: `linux-stand-build.log`, `linux-stand-build-start.txt`, `linux-stand-logs/linux-*-r1-window.log` (каталог, `SigIgn`,
  хэши бинарников, время, вывод `wire-lab.sh`, вердикт и его sha256), `linux-stand-test-ws.log` и `linux-stand-clippy.log`
  (`RMASSCAN_EXPECT_DEFAULT_ROUTE=1`, 2232 passed, 0 failed, 14 ignored, 55 строк; clippy 0), `linux-stand-gate-exits.txt`,
  `linux-stand-gate-start.txt`, `linux-stand-test-ws-attempt1-quota.log` (первая попытка ворот, `Disk quota exceeded`).
- Гость: `guest/build-exits.txt`, `guest/build-rmasscan-<C>.log`, `guest/dumpbin-*-<C>.txt`, `guest/test-exits.txt`,
  `guest/test-ws-<C>.log` (2121 passed, 0 failed, 35 ignored, 55 строк), `guest/clippy-<C>.log` (0).
- Хост VM и окно Windows: `vm-host-n2-status-before-suite.json`, `vm-host-n2-status-after-down.json`,
  `windows-autodetect-r1-suite.log`, `windows-autodetect-r1-verify.log`, `guest-stand-check-r1.txt`.
- `privacy-scan.txt`, `rederive-on-committed-copy.txt`, `hosts-versions.txt`.

Имена хостов в путях журналов заменены на роли; `$R` — каталог экспорта на хосте стенда, `$HOME` — домашний каталог хоста,
`$OUT`/`$MACOUT` — каталоги вывода. Пути гостя с `C:\Users\lab\` — учётная запись гостя `lab`, она разрешена.

## Отклонения

См. раздел 9 отчёта: квота `/tmp` на хосте стенда и перезапуск ворот без отладочной информации; повторный запуск фаззера после
отказа разбора опций; переименование функции скрипта чтения стенда гостя; двойной `record-guest`; повтор `w32tm /resync`;
оркестратор Windows из отдельной чистой рабочей копии на C.
