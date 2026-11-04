# rmasscan: живой скан CLI с автоопределением адаптера и шлюза, приёмка на трёх запечатанных стендах (итоговый отчёт этапа)

Дата: 2026-11-04. Ветка `feat/rmasscan-autodetect`, база `origin/main` `85b08f7` (без rebase: он осиротил бы закреплённый
коммит). Документ фиксирует измеренное и открытое. Статусы: PASS / FAIL / INVALID / NOT RUN / OPEN / PENDING, никогда не
повышаются. «GO» здесь не статус таблицы. GO «rmasscan live scan + autodetect (sealed stands)» по критерию плана
**ожидает** итогового ревью ветки и зелёного CI на точном HEAD (разделы 1, 10, 12, 13). Сырые данные:
[`2026-10-27-rmasscan-autodetect-acceptance-raw/`](2026-10-27-rmasscan-autodetect-acceptance-raw/) (корневой
[README](2026-10-27-rmasscan-autodetect-acceptance-raw/README.md) и `MANIFEST.sha256`; у каждого из `linux-r1`,
`windows-r1`, `macos-r1`, `macos-root-r1` свои `manifest.json`, `verdict.json` и `runs/<tag>/`; логи офлайн-прогонов и
окон лежат в `verification/`). План: `docs/superpowers/plans/2026-10-27-rmasscan-autodetect.md`. Родственные документы:
[baseline](2026-10-27-rmasscan-autodetect-baseline.md), [перечень готовности](2026-10-24-rmasscan-readiness.md), образец
формата: [приёмка Windows sendqueue](2026-10-25-rmasscan-windows-sendqueue-acceptance.md).

## 1. Итог и границы

**rmasscan live scan + autodetect (sealed stands): GO (stands) ещё не объявлен.** Живые условия критерия выполнены на
закреплённом коммите **C = `6c87e94`**: Linux `linux-r1` PASS 13/13 (включая паритет с C-оракулом), Windows VM
`windows-r1` PASS 10/10, Mac `feth` `macos-r1` PASS 8/8 и `macos-root-r1` PASS 3/3. Ожидают два пункта: итоговое ревью
ветки (**PENDING**, раздел 10) и зелёный CI на точном HEAD (**PENDING**, раздел 12). Физические NIC: **NOT RUN**, в это
GO не входят.

Что принимается. Без флага операции `rmasscan` сканирует (IPv4, TCP SYN): читает таблицу маршрутов и интерфейсы ОС в
процессе (Linux rtnetlink и ioctl, macOS `PF_ROUTE` и `getifaddrs`, Windows `GetBestRoute2`, `GetIpForwardTable2`,
`GetAdaptersAddresses`; без привилегий и без запуска `route`, `ip`, `netstat`, `arp`), печатает строки `[+]`, разрешает
MAC следующего хопа 60-байтовыми ARP-запросами к одному адресу и только затем открывает адаптер engine. Engine,
адаптеры `rmasscan-net` (`open_explicit`, `Tx`/`Rx`) и Studio не менялись (раздел 2).

Единый список условий (один и тот же в разделах 1 и 13 и в строке таблицы готовности):

| Условие GO | Статус | Где |
| --- | --- | --- |
| Linux `linux-r1` на C: интерфейс по маршруту к цели, IPv4 и MAC интерфейса, следующий хоп on-link (`l01`) и шлюз по умолчанию интерфейса из dump-а (`l02`, `l11`), ARP, каждое переопределение (`l03`–`l08`), оба отказа без кадров (`l09`, `l10`), `os_arp.requests == 0` | **PASS** 13/13, `safety_trips` [] | раздел 6 |
| Паритет с C-оракулом masscan `8e6b3b0` (`l11_parity`, одинаковые argv без флагов адаптера) | **PASS**: ARP-запрос побайтно равен, 8 SYN равны и идут в том же порядке (`compare_streams`), `Discovered` 8 = 8 | раздел 6 |
| Windows `windows-r1` на C: preflight назвал `Ethernet 2` (`w01`, `w06`); NPF-имя и дружественное имя; ARP к on-link цели; отказ многоцелевого on-link без шлюза; ограниченный токен: `--iflist` работает, скан отказывает без кадров; ARP ядра гостя учтён отдельно | **PASS** 10/10 | раздел 6 |
| macOS `macos-r1` (пользователь в окне гранта BPF) и `macos-root-r1` (root): отказ по маскированию MAC без кадров, MAC под root, ARP, отказы «адрес этого хоста» (после preflight) и «нет IPv4» | **PASS** 8/8 и 3/3 | раздел 6 |
| `[+] finished … sent N` равен числу SYN сканера на проводе | **PASS** в 16 из 16 сканов с исходом `Completed` | раздел 6 |
| Ни одного кадра сканера до скана, кроме 60-байтового ARP-запроса к одному адресу `[+] router-ip`; без кадров при `--router-mac`, `--iflist`, отказе обнаружения и ошибке открытия | **PASS**: 13 прогонов с одним запросом до ответа и 3 прогона ровно с 10 запросами до таймаута, цель каждого запроса равна напечатанному `router-ip`, байты равны `encode_request`; 42-байтовых запросов с MAC сканера 0 в 30 из 30 прогонов; 0 ARP при `--router-mac` (3 прогона), 0 кадров в 6 отказах и 5 прогонах `--iflist` | разделы 6, 7 |
| Ни один тест ни на одной ОС не открывает адаптер | по построению: `OsBackend` есть только вне `cfg(test)`, бинарник в тестах запускается только через `spawn_readonly`; тест `os_backend_is_absent_under_test` прошёл на трёх ОС (раздел 12); подтверждение итоговым ревью (Focus 1) **PENDING** | разделы 10, 12 |
| 0 кадров лаборатории на uplink | **PASS**: `en0` Mac 0 кадров в 9 из 9 прогонов, `eno1` home-pc 0 в 9 из 9; у стенда Linux uplink нет (netns без внешних линков, `isolation.json`) | раздел 4 |
| Статусы стендов true до и после | **PASS**: `raw_run_allowed: true` в 18 `status-pre.json` и 18 `status-post.json` (Windows, macOS); Linux: `isolation.json` и `isolation-post.json` режима `autodetect` в 12 из 12 прогонов, отмена стенда записана (`teardown.json`, `namespaces_left: 0`) | раздел 4 |
| Хэши сходятся | **PASS**: 495 записей `hashes-before-copy.txt` в 30 прогонах и `MANIFEST.sha256` 566 из 566 (`shasum -a 256 -c` при написании отчёта) | раздел 7 |
| Privacy-скан чист, `--iflist` редуцирован | **PASS**: проверка верификатора в 34 из 34 мест, `grep` при копировании 0 совпадений; полного вывода `--iflist` нет нигде (6 файлов `iflist.json`) | раздел 7 |
| Действия пользователя ровно A, B, F | выполнены A, B, F; отклонение записано: root-кейс шёл отдельной строкой `sudo` (три строки за окно вместо двух), грант BPF окна `b7e397a` оставался открытым около 10 ч | раздел 4 |
| Ручные прогоны рабочей области на трёх ОС на C | **PASS** (это не CI): Mac 1553 passed / 0 failed, minipc 1428 / 0, гость 1328 / 0; Studio `cargo xtask test` 168 passed, 3 failed (те же три теста падают на чистом `85b08f7`) | раздел 12 |
| Итоговое ревью ветки | **PENDING** | раздел 10 |
| CI на точном HEAD (`rmasscan`, `Studio`, `language-guard`), зелёный | **PENDING** | раздел 12 |
| Физические NIC | **NOT RUN**, вне этого GO | раздел 13 |

Это измерение на трёх запечатанных стендах. Слои, которые отчёт **не** закрывает:

| Слой | Статус | Почему |
| --- | --- | --- |
| Физический NIC (Linux, Windows, macOS) | **NOT RUN** | veth, виртуальный e1000e и `feth`; физических стендов нет |
| VPN и туннели (`DLT_NULL`/RAW), VLAN, IPv6 | не поддержаны | решение плана: интерфейс туннеля не Ethernet, скан не начинается |
| Шлюз маршрута к цели за маршрутизатором (`router-ip … (route gateway)`) | **NOT RUN** вживую | на всех трёх стендах цели on-link; ветка покрыта офлайн-тестами (`discover_tests`, `live_fake`) |
| Маршрут к единственной цели на macOS | не проверяем на одном хосте | на одном Mac цель является адресом самого хоста; проверены отказ (`m05`) и переопределения |
| Сон и смена сети во время скана | **NOT RUN** | не входило в этап |
| Форматы вывода masscan (`-oL`, `-oJ`, `-oG`, `--open-only`/`--show`, строка статуса) | **OPEN** | этап 2 |
| Баннеры, user-mode TCP | **OPEN** | этап 3 |
| Studio (сетевая идентичность через `rmasscan_net::discover`) | **OPEN** | Studio не трогалась |

Стенды: minipc (Ubuntu 26.04.1, ядро 7.0.0-38), netns и veth; home-pc (ядро 7.3.0-10, QEMU 10.2.1) и гость Windows
10.0.26300.9818 с Npcap в режиме Admin-only, стенд `n2`; Mac (macOS 27.2), пара `feth` `m1`. Результат относится именно к
этим связкам.

## 2. Закреплённые коммиты и чистота дерева

| Часть | Коммит | Чистота и привязка |
| --- | --- | --- |
| Код под всеми живыми окнами (C) | `6c87e942ea0ae349a62bd3ce507a1620233c575f` (2026-11-04) | сборки из `git archive C` на Mac, minipc, home-pc и госте (README evidence); `windows-r1/manifest.json`: `code_commit` = C, `orchestrator.build_commit` = C, `git_dirty: false`; `deploy/deploy-manifest.json`: `commit` = C; пути дерева офлайн-прогонов (`verification/minipc-*.log`, `verification/guest-*.log`) и сборки `rmasscan.exe` (`verification/guest-build-rmasscan-dumpbin.txt`) несут C, `verification/mac-exits.txt` начинается с C. В `manifest.json` Linux и macOS поля коммита нет: привязка через хэши бинарников (раздел 3) |
| Evidence | `00110f9` (`test(cli): record autodetect acceptance on the Linux, Windows VM and Mac feth stands`) | `git diff --name-only 6c87e94 00110f9` содержит только `docs/experiments/2026-10-27-rmasscan-autodetect-acceptance-raw/` |
| База | `origin/main` `85b08f7` | без rebase |
| HEAD | раздел 12 (точный SHA вносит контролёр после push) | |

Ход ветки от `85b08f7` (`git log --oneline 85b08f7..00110f9`, 30 коммитов):

| Группа | Коммиты |
| --- | --- |
| План и baseline | `76d6680`, `ecb4b21` (план r2), `ee85b87`, `27d8ce2`, `50ebaa8` |
| CLI: crate-библиотека, `--router-ip`, `--iflist`, алиасы `--source-ip`/`--source-mac`, `Sink` строки `Discovered` | `0d3cd63` |
| `vm-lab`: forwarding стенда `n2` | `686e411`, `162234f` |
| Обнаружение адаптера, source и следующего хопа (`discover`) | `ff72354`, `822c28f` |
| Маршруты и интерфейсы ОС в процессе (`route_parse`, `linux::route`, `macos::route`, `windows::sys`) | `a516551`, `b6073aa` |
| ARP-резолвер следующего хопа (`arp_resolve`) | `5be9ad8` |
| Живой скан CLI; `--offline` с обнаружением только чтением | `af00931`, `c9aedca` |
| Лаборатория (6a–6d): режим isolation `autodetect`, `wire-lab.sh --suite autodetect`, `autodetect-verify`, `autodetect-suite` для Linux, macOS и Windows | `0f2f136`, `66a7cb5`, `89989ef`, `19ead2f`, `9d1d335`, `b815da8`, `3af9971`, `8afbd98` |
| Исправления по ревью до окон | `9b44a28` (PF1: явные нулевые source IP и router MAC значат «не задан», как в masscan), `76bf074` (LF1: ворота видят каждый чужой кадр, состояние Linux после прогона судится, листинг оракула читается из stderr), `82a3607` (PF2: отказ split-route с `--adapter` даёт подсказки маршрутизатора), `9496cd7` (LF1: запись отмены Linux привязана к своей лаборатории, строка стенда оракула сохраняется) — первый C |
| Исправления по живым окнам | `b7e397a` (PF3: широковещательный маршрут Windows on-link, а не адрес хоста) — второй C; `6c87e94` (PF4: цель macOS, которая является адресом этого хоста, локальна) — финальный C |
| Evidence | `00110f9` |

Что менялось на ветке до C (`git diff --shortstat 85b08f7 6c87e94`): `rmasscan-net` 16 файлов (новые `discover`,
`route_parse`, `arp_resolve`, `linux/route.rs`, `macos/route.rs`, чтение адаптеров и маршрутов в `windows/sys.rs`,
экспорт в `lib.rs`; `macos/adapter.rs` и `windows/adapter.rs` не менялись, в `linux/mod.rs` добавлено только объявление
модуля `route`, в `linux/socket.rs` только видимость `ifreq_for`), `rmasscan-cli` 12,
`rmasscan-lab` 18, `rmasscan-core` один файл (`config.rs`: `router_ip`, `echo`, `read_paused_conf`),
`rmasscan/scripts/wire-lab.sh`, документы `rmasscan/docs/` и `rmasscan/README.md`. `rmasscan-engine`, `studio/` и
`.github/` не менялись. После C до evidence-коммита не менялось ничего, кроме каталога evidence; коммит этого отчёта меняет
только документы и комментарий workflow, поэтому продуктовый код HEAD равен C.

## 3. Хэши и происхождение

| Объект | Значение | Где |
| --- | --- | --- |
| `rmasscan`, Mac (macOS), 1375136 байт | `e788409b2ae110b07dcb174311c8b0f3b838c20aaf15f05278a017c8a80c2812` | `macos-r1/manifest.json`, `macos-root-r1/manifest.json` (`rmasscan`) |
| `rmasscan`, minipc (Linux x86_64), 1555232 байт | `930d695f1aa6cea1efca550cd5f01e0ea61b1827909c9573c6099dd9bcee9632` | `linux-r1/manifest.json` (`rmasscan`) |
| `rmasscan.exe`, гость (статический CRT, Dependent Load Flag 0x800), 1183232 байт | `e8a9c967a07a761a44a140ce26080fe0b0bb3ce0cd329c7400569a8fee1cc268` | `windows-r1/manifest.json` (`exe`), `meta.json` и `guest-runner.json` каждого прогона, `verification/guest-build-rmasscan-dumpbin.txt` |
| `rmasscan-lab`, Mac (suite macOS, оркестратор Windows, верификатор), 4277472 байт | `1639f5913460745792aaaf31ab28e96a2e45b6759761c4c983db35ca952ddc9f` | `macos-*/manifest.json` (`lab`), `windows-r1/manifest.json` (`orchestrator`: `build_commit` = C, `git_dirty: false`) |
| `rmasscan-lab`, minipc, 4737176 байт | `165d484d3283fbd70e7b922501d62e53d240bcda544f11a90c64e8c02f584b66` | `linux-r1/manifest.json` (`lab`), `linux-r1/env.json` (`harness`) |
| `rmasscan-lab`, home-pc, 4737208 байт | `aa56760515355a0d92638eaec083b7e1761a9257a10a34da547a41e12b11918d` | `windows-r1/deploy/deploy-manifest.json` (`commit` = C) |
| `wire_scan`, minipc (регрессия прежнего пути) | `94073c5e9f198f9cd981d48a3114dc95726d0b45afdb98f41f656927b86275ee` | `verification/minipc-rust-regress-results.json` |
| C-оракул masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614`, исходный закреплённый бинарь (не копия с патчем `--offline`), 2106920 байт | `8afc8ec81f2e051389116908b01a4482b42e020bc48254585b7dcca4b25e2a3e` | `linux-r1/manifest.json` (`oracle`), `linux-r1/env.json` (`oracle`, `git_tree_clean: true`), `verification/minipc-rust-regress-results.json` |
| `wire-lab.sh` / `lab-process-group.sh` (minipc) | `e03ebc8e…6229839` / `c33ee0b7…628e78a` | `linux-r1/env.json` (`harness`) |
| tar `git archive C` на госте | `84fc39d5…968a874558` | `verification/guest-exits.txt` |
| Гостевые скрипты лаборатории (`windows-vm-lab.ps1` `71cd2d14…`, `windows_wire_*.ps1`, `*.cmd`) | по файлу | `windows-r1/deploy/preflight-*.json` (`guest_scripts`) |

Вердикты вынес офлайн `rmasscan-lab autodetect-verify` той же сборки C (для Windows `windows-verify`, который передаёт
каталог `autodetect-verify`). При написании отчёта `autodetect-verify` бинаря `1639f591…` повторно запущен на копии каждого из
четырёх закоммиченных каталогов: каждый новый `verdict.json` побайтно равен закоммиченному (`overall`, `totals`, вердикт,
`notes` и детали каждой проверки каждого прогона).

## 4. Топология и действия пользователя

### 4.1. Linux (minipc)

- netns `wl-scan-*` и `wl-peer-*`; veth создан внутри netns сканера, пир перенесён в netns пира; мост, uplink и NAT нет,
  `ip_forward` 0, IPv6 выключен, список линков хоста не изменился (`isolation.json`).
- Сканер: `veth-a` `02:aa:00:00:00:01` `198.18.0.1/24`, `default via 198.18.0.2 dev veth-a` только в netns сканера, постоянные
  соседи `198.18.0.2–.5 → 02:aa:00:00:00:02` (ядро сканера само ARP не шлёт). Пир: `veth-b` `02:aa:00:00:00:02`,
  `198.18.0.2–.5/24`, постоянный сосед `198.18.0.1`; `ip route get 8.8.8.8` из пира не работает. Responder: 80 и 8080
  открыты, остальные порты отвечают RST. `ethtool -K … tx off` на обоих veth (`commands.txt`).
- Стенд меняется только внутри netns (режим `capture isolation --mode autodetect`). Отмена: `wire-lab.sh` удалил оба netns,
  `teardown.json` `namespaces_left: 0`, его `lab_id` равен `lab_id` манифеста; `stray_processes=0`
  (`verification/minipc-linux-window.log`).
- Окно: 2026-11-04 08:08:00Z–08:09:35Z (suite и verify), затем регрессия `--suite rust` до 08:13:11Z.

### 4.2. Windows (home-pc, гость QEMU, стенд `n2`)

- Мост `wvb-n2` без uplink, netns пира `wvp-n2`. Гостевой NIC `Ethernet 2`
  (`\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}`), `198.18.0.1/30`, MAC `52:54:00:04:80:a9`, без шлюза; пир
  `198.18.0.2` `02:57:4c:3d:2e:9b`, слушатели `80,443,8000-8007`, «немой» `8099`. У гостя второй NIC (управление через
  QEMU NAT) со шлюзом по умолчанию, поэтому `w01` и `w06` шли только после preflight.
- `vm-lab status` до и после каждого прогона: `host_ok`, `raw_run_allowed: true`, `isolation_violations` пусто; глобальный
  `ip_forward` home-pc равен 1 при forwarding 0 на всех линках лаборатории (так `vm-lab` допускает с `686e411`). Часы
  гостя: +0.61 с относительно home-pc при пределе +5 с (`deploy/preflight-*.json`).
- `eno1` снимается на каждом прогоне: 0 кадров, 0 «received by filter» (`eno1.err`). Окно: 08:13:39Z–08:49:58Z.

### 4.3. macOS (Mac, стенд `m1`)

- `feth4201` (сканер) `02:ac:00:00:00:01` без IPv4; `feth4202` (пир) `02:ac:00:00:00:02` `198.18.0.2/30`, постоянный ARP
  `198.18.0.1 → 02:ac:00:00:00:01`; слушатели `8000-8007`; стенд не менялся (решение 8 плана). Uplink `en0` снимается
  фильтром `uplink_filter` манифеста: 0 кадров в 9 из 9 прогонов (`uplink.pcap` по 24 байта, только заголовок). Свидетель
  пира `capture dump` на `feth4202`, публикуемый фильтр `not (ether src 02:ac:00:00:00:02 and udp port 5353)`.
- VPN Mac (маршрут по умолчанию через `utun`) на время окон выключил пользователь: с ним строгий офлайн-тест маршрута не
  проходит, а захват uplink на `en0` не увидел бы кадр, ушедший в туннель.
- Окно: `macos-r1` 08:30:37Z–08:31:24Z, `macos-root-r1` сразу после. После F: `macos-lab status` rc 3,
  `bpf_access: denied`, `raw_run_allowed: false`, `/dev/bpf*` `0600 root:wheel` (`verification/macos-status-after-F.json`,
  `verification/macos-bpf-after-F.txt`).

### 4.4. Действия пользователя

| Действие | Кто и когда | Факт |
| --- | --- | --- |
| A | пользователь, 2026-11-03 18:47 CET | разрешил живые окна на трёх стендах, только `198.18.0.0/24` |
| B1/B2 | оператор, существующее `sudo -n` на home-pc, по решению пользователя | манифест `n2` устарел после перезагрузки хоста: `vm-lab down` и `up`, перезапуск VM, Configure гостя и `record-guest`; после окна `n2` снят (`vm-lab down`) |
| B | пользователь, Terminal на Mac, в каждом окне macOS | подъём стенда и грант BPF; root-кейс отдельной строкой `sudo` после пользовательского режима |
| F | пользователь, в конце каждого окна macOS | `macos-lab down` (это и revoke) |

Сколько `sudo` фактически: три строки `sudo` за окно macOS (подъём и грант, root-кейс, F) против двух по плану (одна
цепочка B с root-кейсом и F). Причина: root-кейс сразу после `up` в окне `b7e397a` остановился на воротах до первого
прогона, а пользовательский режим первым гарантирует, что `m05` идёт на свежем стенде, где маршрут к своему адресу ещё не
закеширован. Окон macOS было три (раздел 8): `b7e397a`, первое окно `6c87e94` (не скопировано: утечка имени учётной
записи) и его повтор, это `macos-r1` и `macos-root-r1`. Каждое окно закончилось F; F окна `b7e397a` пользователь
выполнил только утром следующего дня, и грант BPF (`/dev/bpf*` `0660 root:staff`) оставался открытым около 10 ч. На
minipc и home-pc пользовательских действий нет (существующее `sudo -n`).

## 5. Версии

| Компонент | Значение | Источник |
| --- | --- | --- |
| macOS (Mac) | 27.2 (26B123) | README evidence |
| tcpdump на Mac | 4.99.1 (Apple 161) | README evidence |
| minipc | Ubuntu 26.04.1 LTS, ядро 7.0.0-38-generic, x86_64; iproute2 6.19.0; tcpdump 4.99.6 | `linux-r1/env.json`, README evidence |
| home-pc | ядро 7.3.0-10-generic, QEMU 10.2.1 | README evidence |
| Гость | Windows 10.0.26300.9818 (Windows 11), elevated-сессия | README evidence, `verification/guest-exits.txt` (`elevated=True`) |
| Npcap | режим Admin-only (`AdminOnly=1` в реестре, `verification/guest-exits.txt`); номер версии в этом окне не перечитывался, по baseline 2026-10-24 — 1.90 | README evidence |
| rustc | 1.99.1 (`58cf8f9c3 2026-10-13`) на Mac, minipc, home-pc и госте | README evidence, `verification/minipc-exits.txt`, `verification/guest-exits.txt`, `deploy/deploy-manifest.json` |
| C-оракул | masscan `1.3.9-integration`, `8e6b3b0c07a81e8ea61d557c06134a21a6881614` | `linux-r1/env.json`, `l11_parity/oracle/stderr.txt` |
| Сборка `rmasscan.exe` | release, статический CRT, `/DEPENDENTLOADFLAG:0x800` (`0800 Dependent Load Flag`) | `verification/guest-build-rmasscan-dumpbin.txt` |

## 6. Результаты по стендам

Источники чисел: обнаруженные значения — `detected.json` (разбор `stderr.txt`/`guest-stderr.txt`, верификатор проверяет
равенство); число ARP сканера, ARP ОС и RST ядра сканера — `verdict.json` (`notes.scanner_arp_requests`, `notes.os_arp`,
`notes.rst_from_scanner`); SYN на проводе и `sent` — проверка «`[+] finished reports sent equal to the scanner SYNs on the
wire`» (`printed N, wire N`); `Discovered` — строки `stdout.txt`/`guest-stdout.txt`. При написании отчёта SYN сканера,
60- и 42-байтовые ARP-запросы с MAC сканера, ARP-ответы с MAC сканера и цели ARP пересчитаны независимо (`tcpdump -r` по
`peer.pcap` каждого прогона): совпали с вердиктами во всех 30 прогонах.

Обозначения: `route` = `detected: route to 198.18.0.2`, `det` = `detected`, `given` = значение флага; «—» = строки нет
(отказ до неё). Общие аргументы: `--seed 1 --rate 100 --wait 3`.

### 6.1. Linux: `linux-r1` — overall **PASS**, 13 PASS (FAIL 0, INVALID 0, NOT RUN 0)

Порты `-p80,81,8080`, цель `198.18.0.2`, если не сказано иное.

| Кейс | Отличие argv | interface | source-mac / source-ip | router-ip (причина) | router-mac | ARP сканера → цель | ARP ОС (запр. / отв.) | SYN / `sent` | `Discovered` | exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `l01_auto` | без флагов адаптера | `veth-a` route | det / det | `198.18.0.2` (on-link target) | `02-aa-00-00-00-02` (arp: 1) | 1 → `.2` | 0 / 0 | 3 / 3 | 2: 80, 8080 | 0 |
| `l02_auto_multi` | `198.18.0.2-198.18.0.5` | `veth-a` route | det / det | `198.18.0.2` (interface default gateway) | arp: 1 | 1 → `.2` | 0 / 0 | 12 / 12 | 8: {80, 8080} × `.2–.5` | 0 |
| `l03_adapter` | `--adapter veth-a` | `veth-a` given | det / det | `.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 0 | 3 / 3 | 2 | 0 |
| `l04_adapter_ip` | `--adapter-ip 198.18.0.1` | route | det / given | `.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 0 | 3 / 3 | 2 | 0 |
| `l05_adapter_mac` | `--adapter-mac 02-aa-00-00-00-01` | route | given / det | `.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 0 | 3 / 3 | 2 | 0 |
| `l06_router_ip` | `--router-ip 198.18.0.3` | route | det / det | `198.18.0.3` (given) | `02-aa-00-00-00-02` (arp: 1) | 1 → `.3` | 0 / 0 | 3 / 3 | 2 | 0 |
| `l07_router_mac` | `--router-mac 02-aa-00-00-00-02` | route | det / det | — | given | 0 | 0 / 0 | 3 / 3 | 2 | 0 |
| `l08_source_port` | `--source-port 50000-50015` | route | det / det | `.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 0 | 3 / 3 | 2 | 0 |
| `l09_arp_timeout` | `--router-ip 198.18.0.9` | route | det / det | `198.18.0.9` (given) | — (отказ) | 10 → `.9`, шаги 0.999–1.001 с | 0 / 0 | 0 / — | 0 | 1 |
| `l10_no_such_adapter` | `--adapter nosuch0` | — (отказ до строк `[+]`) | — | — | — | 0 | 0 / 0 | 0 / — | 0 | 1 |
| `l11_parity` | `198.18.0.2-198.18.0.5 -p80,8080 --source-port 40000` | `veth-a` route | det / det | `198.18.0.2` (interface default gateway) | arp: 1 | 1 → `.2` | 0 / 0 | 8 / 8 | 8: {80, 8080} × `.2–.5` | 0 |
| `l12_iflist` | `--iflist` | строка стенда `veth-a index=2 mac=02-aa-00-00-00-01 ipv4=198.18.0.1 up ethernet` (3 строки) | | | | 0 | 0 / 0 | 0 | — | 0 |

Во всех сканах source-mac `02-aa-00-00-00-01`, source-ip `198.18.0.1`; порт источника по умолчанию один, `(time)`
(59681–59718), заданный печатается `(given)`, и каждый SYN идёт с порта из `[+] source-port`. `replies` в `[+] finished`
равен `sent` (SYN-ACK открытых портов и RST пира на закрытый 81, где он сканируется). RST ядра сканера на SYN-ACK пира
(ядро не знает соединения): 2 в каждом скане одной цели, 8 в `l02` и `l11`; верификатор их считает, а не отвергает
(решение 8 плана). Отказы в форме C, дословно:

```text
l09: [-] FAIL: ARP timed-out resolving MAC address for router veth-a: "198.18.0.9"
         [hint] try "--router-ip 192.0.2.1" to specify different router
         [hint] try "--router-mac 66-55-44-33-22-11" instead to bypass ARP
         [hint] try "--interface eth0" to change interface
l10: [-] FAIL: no such interface "nosuch0"
         [hint] did you spell the name correctly?
```

**Паритет `l11_parity` с C-оракулом** (одинаковые argv в одном стенде, без флагов адаптера; оракул exit 0): ARP-запрос
оракула равен запросу rmasscan побайтно (`ffffffffffff02aa00000001 0806 … c6120001 … c6120002`, 60 байт с нулевым
дополнением); 8 SYN оракула равны 8 SYN rmasscan по байтам и порядку (`compare_streams`); множество `Discovered` 8 = 8
(верификатор), а `stdout.txt` обоих при сравнении `cmp` совпал побайтно, включая порядок строк. `oracle.pcap` полон
(40 кадров, маркеры 3 + 3). `l12_iflist`: `--iflist` оракула rc 0, 8 строк, строка стенда в форме masscan
` 0  veth-a \t(No description available)`; полный вывод обоих не хранится.

### 6.2. Windows: `windows-r1` — overall **PASS**, 10 PASS (FAIL 0, INVALID 0, NOT RUN 0)

Порты `-p80,443,8000-8007,8099`, цель `198.18.0.2`, если не сказано иное. Во всех сканах source-mac
`52-54-00-04-80-a9` (det), source-ip `198.18.0.1` (det), router-mac `02-57-4c-3d-2e-9b`.

| Кейс | Отличие argv | Preflight | interface | router-ip (причина) | router-mac | ARP сканера → цель | ARP ОС (запр. / отв.) | SYN / `sent` | `Discovered` | exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `w01_auto` | без флагов адаптера | rc 0, `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)` | `Ethernet 2` route | `198.18.0.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 1 | 11 / 11 | 10: 80, 443, 8000–8007 | 0 |
| `w02_adapter_npf` | `--adapter \Device\NPF_{C4617223-…}` | | `Ethernet 2` given | `.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 1 | 11 / 11 | 10 | 0 |
| `w03_adapter_friendly` | `--adapter "Ethernet 2"` | | `Ethernet 2` given | `.2` (on-link target) | arp: 1 | 1 → `.2` | 0 / 1 | 11 / 11 | 10 | 0 |
| `w04_router_mac` | `--router-mac 02-57-4c-3d-2e-9b` | | route | — | given | 0 | 0 / 1 | 11 / 11 | 10 | 0 |
| `w05_arp_timeout` | `--router-ip 198.18.0.3` | | route | `198.18.0.3` (given) | — (отказ) | 10 → `.3`, шаги 1.000 с | 0 / 0 | 0 / — | 0 | 1 |
| `w06_multi_no_gateway` | `198.18.0.2-198.18.0.3` | rc 0, `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)` | — (отказ до строк `[+]`) | — | — | 0 | 0 / 0 | 0 / — | 0 | 1 |
| `w07_iflist` | `--iflist` | | строка стенда `Ethernet 2 index=14 mac=52-54-00-04-80-a9 ipv4=198.18.0.1 up ethernet id=\Device\NPF_{C4617223-…} desc=Ethernet 2` (4 строки) | | | 0 | 0 / 0 | 0 | — | 0 |
| `w08a_restricted_iflist` | `--iflist`, ограниченный токен | | та же строка, 4 строки, тот же sha256 `586a9097…`, что у `w07` | | | 0 | 0 / 0 | 0 | — | 0 |
| `w08b_restricted_scan` | как `w01`, ограниченный токен | | `Ethernet 2` route | `.2` (on-link target) | — (ошибка открытия) | 0 | 0 / 0 | 0 / — | 0 | 1 |

`sent 11, replies 10, open 10`: «немой» `8099` не отвечает. ARP ОС: на каждый скан с ответами пира ядро гостя один раз
отвечает пиру на `who-has 198.18.0.1` (42 байта, учтено как `os_arp.replies`); 42-байтовых запросов с MAC сканера нет.
Preflight `--offline` для `w01` и `w06` напечатал `router-ip = none (offline)` и `router-mac = 66-55-44-33-22-11
(offline)`, его результат равен ожидаемому обнаружению кейса (проверка верификатора). Отказы:

```text
w05:  [-] FAIL: ARP timed-out resolving MAC address for router Ethernet 2: "198.18.0.3"
          (те же три подсказки masscan, что у l09)
w06:  [-] FAIL: no default gateway on interface "Ethernet 2" for several on-link targets
          (те же три подсказки masscan)
w08b: [+] interface, source-mac, source-ip, router-ip напечатаны, затем
      rmasscan: error: cannot open adapter "Ethernet 2": permission denied (raw packet access needs elevated privileges):
      no Npcap device named "\\Device\\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}": only loopback is visible: Npcap may be
      installed in Administrators-only mode and this process lacks rights (1 devices enumerated)
          [hint] run as Administrator; Npcap must be installed (Admin-only mode needs an elevated prompt)
```

`w06` показывает, что многоцелевой on-link без шлюза на интерфейсе стенда отказывает, а не уходит через шлюз второго NIC
гостя. `w08b`: обнаружение работает без привилегий, отказ приходит при открытии ARP-адаптера (план принимает «отказ rc 1
любого вида, 0 кадров»); это ошибка открытия, а не отказ обнаружения, поэтому форма `rmasscan: error:`, а не `[-] FAIL:`.
Гостевой runner при пустом stdout пишет `"\n"` (1 байт), верификатор считает это пустым выводом.

### 6.3. macOS: `macos-r1` (пользователь, грант BPF) — **PASS** 8/8; `macos-root-r1` (root) — **PASS** 3/3

Порты `-p8000-8007,9000-9003`, цель `198.18.0.2`. В `m01`–`m04`, `m06`, `m10` заданы `--adapter feth4201`, `--router-ip
198.18.0.2` (кроме `m04`) и, кроме `m06`, `--adapter-ip 198.18.0.1`.

| Кейс | Отличие argv | interface | source-mac / source-ip | router-ip | router-mac | ARP сканера → цель | ARP ОС | SYN / `sent` | `Discovered` | exit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `m01_user_masked` | без `--adapter-mac` | — (отказ «os-masked» до строк `[+]`) | — | — | — | 0 | 0 / 0 | 0 / — | 0 | 1 |
| `m02_user_explicit` | `+ --adapter-mac 02-ac-00-00-00-01` | `feth4201` given | given / given | `198.18.0.2` (given) | `02-ac-00-00-00-02` (arp: 1) | 1 → `.2` | 0 / 0 | 12 / 12 | 8: 8000–8007 | 0 |
| `m03_user_router_mac` | `+ --adapter-mac`, `--router-mac 02-ac-00-00-00-02` | given | given / given | given | given | 0 | 0 / 0 | 12 / 12 | 8 | 0 |
| `m04_user_arp_timeout` | `+ --adapter-mac`, `--router-ip 198.18.0.3` | given | given / given | `198.18.0.3` (given) | — (отказ) | 10 → `.3`, шаги 1.000–1.001 с | 0 / 0 | 0 / — | 0 | 1 |
| `m05_user_no_adapter` | без флагов адаптера; preflight rc 1, тот же отказ | — (отказ `LocalTarget`) | — | — | — | 0 | 0 / 0 | 0 / — | 0 | 1 |
| `m06_user_no_ip` | `--adapter-mac`, без `--adapter-ip` | — (отказ «no IP» до строк `[+]`) | — | — | — | 0 | 0 / 0 | 0 / — | 0 | 1 |
| `m07_user_iflist` | `--iflist` | строка стенда `feth4201 index=35 mac=masked ipv4=- up ethernet` (30 строк) | | | | 0 | 0 / 0 | 0 | — | 0 |
| `m10_root_auto_mac` (root) | как `m01`, без `--adapter-mac` | `feth4201` given | **det** / given | `198.18.0.2` (given) | `02-ac-00-00-00-02` (arp: 1) | 1 → `.2` | 0 / 0 | 12 / 12 | 8: 8000–8007 | 0 |
| `m11_root_iflist` (root) | `--iflist` | строка стенда `feth4201 index=35 mac=02-ac-00-00-00-01 ipv4=- up ethernet` (30 строк) | | | | 0 | 0 / 0 | 0 | — | 0 |

`replies` 10 / 9 / 9 в `m02` / `m03` / `m10`: 8 SYN-ACK и 2 или 1 RST от 4 закрытых `9000-9003` (Darwin ограничивает RST;
см. [приёмку macOS BPF](2026-10-25-rmasscan-macos-bpf-acceptance.md), раздел 9). Без root `getifaddrs` отдаёт заполнитель
`02:00:00:00:00:00` (`m07`: `mac=masked`), и `m01` отказывает, не делая его source MAC; под root тот же argv определяет
настоящий MAC (`m10`, `m11`). Отказы:

```text
m01: [-] FAIL: MAC of interface "feth4201" is os-masked (Darwin hides MACs from unprivileged processes)
         [hint] run as root, or try something like "--source-mac 00-11-22-33-44-55"
m04: [-] FAIL: ARP timed-out resolving MAC address for router feth4201: "198.18.0.3"
         (те же три подсказки masscan, что у l09)
m05: [-] FAIL: 198.18.0.2 is an address of this host (route via lo0)
         [hint] try "--interface ethX" and "--router-ip 192.0.2.1"
m06: [-] FAIL: failed to detect IP of interface "feth4201"
         [hint] did you spell the name correctly?
         [hint] if it has no IP address, manually set with something like "--source-ip 198.51.100.17"
```

Preflight `m05` (`--offline` с теми же целями) дал rc 1 и тот же отказ `LocalTarget`; результат равен ожидаемому
обнаружению кейса.

### 6.4. Сводка

| Счётчик | Linux | Windows | macOS (оба каталога) |
| --- | --- | --- | --- |
| Сканов `Completed`, `sent` = SYN на проводе | 9 из 9 (3 / 12 / 8 SYN) | 4 из 4 (11 SYN) | 3 из 3 (12 SYN) |
| Прогонов с ARP до ответа (по 1 запросу) | 8 | 3 | 2 |
| ARP-таймаутов (ровно 10 запросов, 1 ± 0.3 с, 0 SYN) | 1 (`l09`) | 1 (`w05`) | 1 (`m04`) |
| `--router-mac`: 0 ARP | 1 (`l07`) | 1 (`w04`) | 1 (`m03`) |
| Отказов без кадров | 1 (`l10`) | 2 (`w06`, `w08b`) | 3 (`m01`, `m05`, `m06`) |
| `--iflist` без кадров, `iflist.json` | 1 (+ оракул) | 2 (`w07`, `w08a`) | 2 (`m07`, `m11`) |
| 42-байтовых ARP-запросов с MAC сканера | 0 | 0 | 0 |
| ARP-ответов ядра с MAC сканера | 0 | 4 (по 1 в `w01`–`w04`) | 0 |
| Кадров с MAC вне пары стенда в захвате пира | 0 | 0 | 0 |

Каждая строка `stdout` ровно 80 байт (`Discovered open port N/tcp on IP`, дополнение до 79, `\n`), дублей нет, и
`Discovered` равны ровно тем портам, на которые пир ответил SYN-ACK в окне прогона (25 проверок).

## 7. Хэширование и полнота

- Каждый прогон хэширован в рабочем каталоге до копирования (`hashes-before-copy.txt`; на Windows pcap хэшированы на home-pc
  до копирования, `pcap-hashes-on-home-pc.txt` в 9 прогонах). При написании отчёта `shasum -a 256 -c` по всем 30 файлам
  `hashes-before-copy.txt`: 495 записей OK, расхождений 0. `MANIFEST.sha256` корня: 566 из 566 OK (567 файлов в каталоге,
  включая сам манифест).
- Захваты полные: 30 `peer.pcap` и `oracle.pcap` разобраны целиком, `capture.json` каждого `valid: true`, число кадров в
  файле равно записанному, у каждого прогона три стартовых маркера до и три конечных после всех кадров сканера; потери
  ядра на свидетелях 0 (31 `capture.json`/`oracle-capture.json`, на Windows и у свидетеля `eno1`). На macOS фильтр
  приватности свидетеля проверен верификатором: оставленные кадры равны `peer.pcap`, оставленные плюс отброшенные равны
  нефильтрованному захвату (9 прогонов).
- Pcap без сжатия: 49 файлов (`peer` 30, `oracle` 1, `uplink` 9, `eno1` 9), `.gz` нет, наибольший 4504 байт
  (`windows-r1/runs/w03_adapter_friendly/peer.pcap`); всего каталог 3.1 МБ. Расширения только из allowlist (`json pcap txt
  log err sha256 md`).
- Отброшенных и прерванных прогонов в каталогах нет (`discarded`, `aborted` пусты во всех четырёх `verdict.json`).
- Privacy: проверка верификатора «every text file holds only allowlisted names, addresses and paths» PASS в 34 местах (30
  прогонов, 4 манифеста); при копировании `grep -ralwE` по именам хостов и учётных записей Mac, minipc, home-pc и гостя,
  `_tcp.local`, `_udp.local` дал 0 совпадений (README evidence). Полный вывод `--iflist` не хранится нигде: 6 файлов
  `iflist.json` (`{rc, lines, sha256, stand_line}`), у кейсов `--iflist` нет `stdout.txt`/`guest-stdout.txt`, у оракула нет
  `oracle/stdout.txt` и `oracle/stderr.txt` в `l12`.
- Пути в логах `verification/` заменены на `$HOME`, `$SCRATCH`, `<user>`, `<mac>`, `<minipc>`, `<home-pc>`, `<guest>`;
  файлы каталогов прогонов после копирования не редактировались (README evidence). Каталоги macOS сняты из нейтрального
  `/private/tmp/rmasscan-ad.*` (раздел 8).

## 8. Исторический сбор: окна до C

Окна шли трижды; первые два раза нашли дефекты продукта, и их исправления сменили C. Эти каталоги не закоммичены; их
описание — README evidence.

1. **C = `9496cd7`.** Linux PASS 13/13 и регрессия 145 PASS. Windows: первая попытка NOT RUN на предварительной проверке
   (часы гостя ушли на +6.2 с вперёд: служба времени не стартовала после перезапуска VM; после `w32tm /resync` −0.7 с);
   вторая попытка: `w01`–`w05`, `w07`, `w08a`, `w08b` PASS, **`w06` NOT RUN**: Windows отдаёт широковещательный адрес /30
   (`198.18.0.3`) маршрутом с флагом MIB Loopback, и rmasscan называл его адресом этого хоста. Исправлено `b7e397a` (PF3).
2. **C = `b7e397a`.** macOS: `m01`–`m04`, `m06`, `m07` PASS, **`m05` NOT RUN**: свой адрес Mac `198.18.0.2` (на
   `feth4202`) Darwin отдаёт маршрутом подсети без `RTF_LOCAL`, пока хост сам не послал на него пакет, и rmasscan не узнавал
   свой адрес. Исправлено `6c87e94` (PF4). Root-кейс `m10`/`m11` PASS 3/3; его первая попытка сразу после `up` остановилась на
   воротах до первого прогона (вывод не сохранился). F этого окна выполнена утром следующего дня (раздел 4.4).
3. **C = `6c87e94`.** Первое окно macOS писало `--out` в scratch-каталог, путь которого содержит имя учётной записи; оно
   попало в `capture.json` (`tcpdump_argv`, путь `-w` в `.work`). Privacy-скан это поймал, каталоги не копировались; окно
   повторено из нейтрального каталога `/private/tmp/rmasscan-ad.*`: это `macos-r1` и `macos-root-r1`. Linux и Windows на этом C
   прогнаны один раз (`linux-r1`, `windows-r1`).

Ни один из этих результатов не повышен и не заменяет закоммиченные каталоги: все вердикты отчёта относятся к C = `6c87e94`.

## 9. Ошибки и ограничения

- **Физические NIC: NOT RUN** на всех трёх ОС. veth, виртуальный e1000e и `feth` не заменяют физическую приёмку.
- **Маршрут к единственной цели на macOS не проверяем на одном хосте.** Цель стенда `m1` (`198.18.0.2`) является адресом
  самого Mac; автоопределение маршрута даёт только отказ `LocalTarget` (`m05`). На macOS доказаны маскирование и отказ,
  переопределения, ARP и MAC под root; маршрут к цели и шлюз доказаны на Linux и Windows.
- **MAC под root на Darwin доказан одним кейсом** (`m10`; `m11` показывает его же в `--iflist`).
- **Шлюз маршрута к цели (`route gateway`) вживую не проверен**: на стендах все цели on-link. Ветка покрыта офлайн
  (`discover_tests`, `live_fake`). Вживую следующий хоп доказан как сама цель (`on-link target`), шлюз по умолчанию
  интерфейса (Linux `l02`, `l11`), заданный `--router-ip` и отказ без шлюза (Windows `w06`).
- **Шлюз по умолчанию интерфейса на Windows и macOS вживую не проверен**: у `Ethernet 2` и `feth4201` шлюза нет (стенды не
  меняются, решение 8 плана); на Windows проверен только отказ `w06`.
- **VPN и туннели (`DLT_NULL`/RAW), VLAN, IPv6 не поддержаны.** На время окон macOS пользователь выключал VPN (раздел 4.3).
- **Ctrl-C не перехватывается**, `paused.conf` не пишется: прогресс теряется (README «Отличия от masscan»).
- **`--iflist` в evidence только в редуцированной форме** (строка стенда, число строк, sha256), и у rmasscan, и у оракула;
  отличие формата от masscan (`pcap_findalldevs` в stderr) тестом не видно и записано как осознанное отклонение.
- **Порт источника по умолчанию один** (`40000 + time % 20000`), у masscan два ({p, p+16}); в паритете `l11` порт задан
  явно, поэтому на SYN это не влияет.
- **ARP-таймаут 10 с**: 10 запросов с шагом 1 с (C: около 12 за около 11 с); измерено на трёх стендах (шаги 0.999–1.001 с).
- **RST ядра сканера на Linux** (2 или 8 на прогон) попадают в захват; верификатор их считает, не отвергает.
- **ARP ОС на Windows**: ядро гостя отвечает на `who-has 198.18.0.1` пира (1 кадр в `w01`–`w04`), учтено отдельно от ARP
  сканера.
- **Текст ошибки открытия на Windows** (`w08b`) печатает имя устройства экранированным (`\\Device\\NPF_{…}`) и в форме
  `rmasscan: error:`: это ошибка открытия, а не отказ обнаружения; верификатор нормализует имя.
- **Отложено на итоговое ревью** (журнал контролёра): нет проверки unicast у `--router-ip`, и единственная широковещательная
  on-link цель ARP-ит сама себя (M3; кадры всё равно идут только к напечатанному адресу, как у C); macOS `RTM_GET 0.0.0.0`
  видит только основной маршрут по умолчанию (M7); склейка PF3/PF4 с ОС не закреплена отдельным тестом; suite macOS скрабит
  только `$HOME`, а не имя учётной записи везде (оператору: `--out` только в нейтральном пути).
- **Studio `cargo xtask test` на Mac: 3 failed** (`feth_acceptance::tests::a_clean_window_writes_every_file_of_the_contract_in_order`,
  `guard_window_keeps_witnesses_until_restoration`, `pause_stage_uses_shared_history_without_changing_standard_mode`); те же
  три падают на чистом worktree `origin/main` `85b08f7`: существующий дефект Studio, не этой ветки (Studio ветка не
  меняет).
- **Один прогон на кейс**, один Mac, одна версия каждой ОС; сон и смена сети во время скана **NOT RUN**.
- **Окна до C** (раздел 8): часы гостя, два дефекта продукта, утечка имени учётной записи в первом окне `6c87e94`; грант BPF
  окна `b7e397a` открыт около 10 ч.
- Python в репозиторий не попал: числа этого отчёта извлечены `jq`, `tcpdump -r` и `shasum` в оболочке, вне репозитория.

## 10. Ревью

Файлы ревью лежат в `.superpowers/` (в gitignore), поэтому вердикты пересказаны здесь.

- **Ревью продукта до окон (Focus 1–4)**: важное I1 — явные нулевые source IP и router MAC считались заданными (в masscan 0
  значит «не задан»); исправлено PF1 `9b44a28`; плюс минорные. Позднее `82a3607` (PF2) дал отказу split-route с `--adapter`
  подсказки маршрутизатора.
- **Ревью лаборатории до окон (Focus 5)**: критичное C1 — ворота не видели кадры с MAC вне пары стенда; важные I1 — листинг
  `--iflist` оракула читался не из stderr, I2 — экранированное имя устройства в отказе `w08b`, I3 — состояние стенда Linux
  после прогона не судилось. Исправлено LF1 `76bf074`; его повторное ревью нашло непривязанную к лаборатории запись отмены
  Linux, исправлено `9496cd7`.
- **Живые окна нашли два дефекта продукта**: PF3 (`b7e397a`, Windows) и PF4 (`6c87e94`, macOS), раздел 8.
- Все исправления прошли ревью задачи и повторное ревью.
- **Отложенные минорные** для триажа итогового ревью (журнал контролёра): продукт M3 и M7 (раздел 9), минорные 4–5 PF1,
  лаборатория M2, M3, M7, M8, минорные 5, 6, 9 задачи 6d, LF1 M4 (шум вывода тестов), склейка PF3/PF4 без закрепляющего
  теста, скраб имени учётной записи в suite macOS.
- **Итоговое ревью ветки** (только чтение: безопасность кадров до скана и в тестах, обнаружение, резолвер, CLI, лаборатория,
  evidence): **PENDING**.

## 11. Перепроверка после итогового ревью

По плану: если ревью изменит `rmasscan-cli`, `rmasscan-net`, `rmasscan-core` или `rmasscan-engine`, повторяются окна
минимум `l01`, `l11`, `w01`, `m02` (и B/F на Mac) на исправленном коммите; если только `rmasscan-lab` или документы —
архив пересчитывается исправленным верификатором с неизменными вердиктами.

Итоговое ревью продуктовый код приняло. Его находки касались только лаборатории и документов, поэтому окна не
повторялись: исправление одно, коммит `fix(lab): evidence scrubs the out path and account name, the verifier flags
them, aborted attempts stay visible` (следующий за `435279f`), только `rmasscan-lab` и документы.

- **Privacy-ворота.** Первое окно macOS на `6c87e94` (раздел 8, п. 3) писало `--out` в scratch, путь которого несёт
  имя учётной записи через дефис (`/private/tmp/claude-501/-Users-<учётная запись>/…`); `autodetect-verify` дал ему
  PASS 8/8, утечку нашёл только grep оператора. Теперь каждый suite (Linux, macOS пользовательский и root, Windows)
  одним общим помощником `capture::Scrubber` пишет во всё, что попадает в evidence, свой `--out` как `$OUT`, рабочий
  каталог как `$WORK` (macOS, Windows: `$OUT/.work`) и учётную запись (`$SUDO_USER`, если задан и не `root`, иначе
  `$USER`) как `$USER`. Верификатор в любом текстовом файле находит ещё `-Users-ИМЯ`, `-home-ИМЯ`, `claude-<цифры>` и
  `/var/folders/` (в том числе `/private/var/folders/`): INVALID с именем файла. Синтетический прогон с путём того
  окна в `capture.json` раньше был PASS, теперь INVALID. Нейтральные пути (`/private/tmp/rmasscan-ad.6qCSaM/…` в
  `macos-r1` и `macos-root-r1`) и `$OUT`, `$WORK`, `$HOME`, `$USER` проходят.
- **Прерванные попытки.** Каждая запись `runs_aborted/` теперь в `aborted` вердикта (тег, кейс, вид, файлы). Кейс с
  попыткой не бывает PASS: прогон рядом с ней INVALID, без прогона NOT RUN; запись, которая не `<плановый
  тег>.<run id>`, делает каталог INVALID. Все три suite отказывают (NOT RUN, до любого изменения) кейсу, у которого в
  `--out` есть `runs/<tag>` или `runs_aborted/<tag>.*`.
- **Документы.** `rust-lab.md` и `macos-feth-lab.md`: `--out` и бинарники в нейтральном каталоге
  (`mktemp -d /private/tmp/rmasscan-ad.XXXXXX`), что пишет suite и что ловит верификатор; `README.md`, «Ограничения»:
  маршруты по умолчанию Linux через nexthop-объект или multipath и macOS только основной маршрут (`--router-ip`).

Перепроверка архива: `autodetect-verify`, собранный из этого коммита, на четырёх закоммиченных каталогах (и
`windows-verify` на `windows-r1`) дал вердикты, **байт в байт равные** закоммиченным `verdict.json`; ни один файл
evidence не менялся (`MANIFEST.sha256`: 566 файлов сходятся). Вердикты не изменились:

| Каталог | Вердикт | sha256 `verdict.json` (закоммиченный = пересчитанный) |
| --- | --- | --- |
| `linux-r1` | PASS 13/13, rc 0 | `64c9e6aabad7207e6487c847cc33a7fdaaa903939cd00a41332184f643e49e8a` |
| `windows-r1` | PASS 10/10, rc 0 (оба верификатора) | `94b72583ced9e921f046d62979c4344aefc903aab66f5746bd2b99e2eae7fa38` |
| `macos-r1` | PASS 8/8, rc 0 | `e3dafaf7779aefd1f16cbc2df80efae68592ad949f5911a6f7935a5e3b0afa63` |
| `macos-root-r1` | PASS 3/3, rc 0 | `26ff9103dbfc121c0ab18ec924cf9115799bba395dbead12ce51738f7addbfcb` |

## 12. CI

CI: заполняется после push на точном HEAD

Workflow на HEAD: `rmasscan` (`ubuntu-24.04`, `macos-14`, `windows-2025` и `windows-x64 wire lab package`), `Studio`
(`macos-14`, `ubuntu-24.04`, `windows-2025`), `language-guard`. План называл `windows-2022`: раннер сменён на `windows-2025`
на `main` в `053f718` (#38), до базы ветки. CI собирает и гоняет только офлайн-тесты; живые прогоны автоопределения в CI
не идут, ни один тест не открывает адаптер (комментарий в `.github/workflows/rmasscan.yml`).

Ручные прогоны на C перед окнами (это не CI; логи в `verification/`):

| ОС | Коммит | Итог | Лог |
| --- | --- | --- | --- |
| macOS (Mac) | C | `cargo fmt --all --check` rc 0, clippy `-D warnings` rc 0; `cargo test --locked --workspace --all-targets` с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` и без VPN: 1553 passed, 0 failed, 23 ignored; language guard PASS | `mac-exits.txt`, `mac-test-ws-strict.log`, `mac-clippy.log`, `mac-langguard.log` |
| Linux (minipc) | C | clippy rc 0; `cargo test` рабочей области: 1428 passed, 0 failed, 14 ignored | `minipc-exits.txt`, `minipc-test-ws.log`, `minipc-clippy.log` |
| Windows (гость `n2`) | C | elevated-сессия, Npcap `AdminOnly=1`, строгий флаг маршрута; clippy rc 0; полное дерево: 1328 passed, 0 failed, 34 ignored | `guest-exits.txt`, `guest-test-ws.log`, `guest-clippy.log` |
| Studio (Mac) | C | `cargo xtask test`: 168 passed, 3 failed, 2 ignored (три `feth_acceptance`, те же на чистом `85b08f7`, раздел 9) | `mac-xtask-test.log` |

Тест `os_backend_is_absent_under_test` (`rmasscan-cli/tests/live_fake.rs`) прошёл во всех трёх журналах рабочей области.
Регрессия прежнего пути на minipc на C: `wire-lab.sh --suite rust` (`wire_scan`) rc 0, **145 PASS**
(`verification/minipc-rust-regress-results.json`; план называл 141, набор вырос до 145 ещё 2026-10-25).

## 13. Заявление о готовности

**GO «rmasscan live scan + autodetect (sealed stands)» ещё не объявлен.** Он ожидает двух пунктов единого списка из
раздела 1: итогового ревью ветки (раздел 10) и зелёного CI на точном HEAD (раздел 12). Остальные условия выполнены на коде
C = `6c87e94` (продуктовый код HEAD не отличается):

- Linux `linux-r1` PASS 13/13: интерфейс по маршруту, IPv4, MAC, следующий хоп on-link и шлюз по умолчанию интерфейса из
  dump-а, ARP, каждое переопределение, оба отказа без кадров, `os_arp.requests == 0`; паритет с C-оракулом по байтам
  ARP-запроса, порядку SYN и множеству `Discovered`.
- Windows `windows-r1` PASS 10/10: preflight назвал `Ethernet 2`, NPF и дружественное имя, ARP к on-link цели, отказ
  многоцелевого on-link без шлюза, ограниченный токен без кадров, ARP ядра гостя учтён отдельно, `eno1` 0 кадров.
- macOS `macos-r1` PASS 8/8 и `macos-root-r1` PASS 3/3: отказ по маскированию без кадров, MAC под root, ARP, отказы «адрес
  хоста» и «нет IPv4», uplink 0 кадров.
- `[+] finished … sent N` равен SYN сканера на проводе в 16 из 16 сканов; ни одного кадра до скана, кроме 60-байтового ARP к
  одному адресу; статусы стендов true до и после; хэши сходятся; privacy-скан чист (`--iflist` редуцирован); действия
  пользователя A, B, F (отклонение в разделе 4.4); ручные прогоны рабочей области на трёх ОС пройдены; ни один тест не
  открывает адаптер по построению (`os_backend_is_absent_under_test` на трёх ОС; подтверждение — итоговое ревью, Focus 1).

Это заявление **не** распространяется на:

| Область | Статус |
| --- | --- |
| Физические NIC (Linux, Windows, macOS) | **NOT RUN** |
| VPN и туннели (`DLT_NULL`/RAW), VLAN, IPv6 | не поддержаны |
| Сон и смена сети во время скана | **NOT RUN** |
| Форматы вывода masscan (этап 2) | **OPEN** |
| Баннеры и user-mode TCP (этап 3) | **OPEN** |
| Studio | **OPEN** |

Стенд никогда не заменяет физическую приёмку.
