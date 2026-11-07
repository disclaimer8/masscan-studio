# rmasscan: форматы вывода masscan, `--readscan`, строка статуса и Ctrl-C, приёмка (итоговый отчёт этапа)

Дата: 2026-11-06. Ветка `feat/rmasscan-output-formats` (черновой PR #50), база `438e58b` (слияние PR #49). Документ
фиксирует измеренное и открытое. Статусы: PASS / FAIL / INVALID / NOT RUN / OPEN / PENDING, никогда не повышаются. «GO»
здесь не статус таблицы. GO «rmasscan output formats (offline parity + Linux stand)» по критерию спеки (§6.4)
выполнен: итоговое ревью ветки одобрено после одной волны правок (раздел 12), CI зелёный на последнем коммите с
кодом `9907de0` (раздел 9). Сырые данные:
[`2026-11-06-rmasscan-output-acceptance-raw/`](2026-11-06-rmasscan-output-acceptance-raw/) (корневой
[README](2026-11-06-rmasscan-output-acceptance-raw/README.md) и `MANIFEST.sha256`; у каждого из `linux-output-r1`,
`linux-autodetect-r2`, `windows-autodetect-r2` свои `manifest.json`, `verdict.json` и `runs/<tag>/`; логи офлайн-прогонов
лежат в `verification/`). Спека: [design](../superpowers/specs/2026-11-06-rmasscan-output-formats-design.md) (решения
Р1–Р19, проверки §6, отличия §8), справка по байтам C:
[c-reference](../superpowers/specs/2026-11-06-rmasscan-output-formats-c-reference.md). Родственные документы:
[приёмка автоопределения](2026-10-27-rmasscan-autodetect-acceptance.md) (образец формата),
[перечень готовности](2026-10-24-rmasscan-readiness.md), [эталоны форматов](../../rmasscan/tests/golden/formats/README.md).

## 1. Итог и границы

**rmasscan output formats (offline parity + Linux stand): GO (stands).** Живые окна сняты на коде **C = `2b0e92c`**, CI
и итоговое ревью — на последнем коммите с кодом `9907de0`:

| Условие | Статус | Где |
| --- | --- | --- |
| Офлайн-паритет с C `8e6b3b0`: 74 случая `--readscan` (каждый формат с `--show open,closed` и без, `-oX --webxml`, два фильтра) совпадают с эталоном C побайтно после маски только полей «часы в момент записи»; тест `formats_golden.rs` не пропускает ни одного случая (`SKIPS` пуст) | **PASS** на Linux (эталоны сняты там); те же ожидаемые байты на macOS и Windows по Р12, прогон в CI | раздел 6.1 |
| Живой паритет Linux `linux-output-r1`: `o01`–`o11` с C-оракулом (записи и заголовок равны), `o12` и `o14`–`o16` только rmasscan (решение контролёра), `o13` без оракула по замыслу (C отправил бы кадры), раздел 6.2; `o17` оба сканера читают оба `-oB` | **PASS** 18/18 (17 прогонов и манифест), `safety_trips` [] | раздел 6.2 |
| Регрессия автоопределения на коде этапа: Linux `linux-autodetect-r2`, Windows VM `windows-autodetect-r2`; живой stderr теперь несёт строку статуса, верификаторы разбирают её по грамматике | **PASS** 13/13 и 10/10 | раздел 6.3 |
| CI на `2b0e92c`: `rmasscan` (macos-15, ubuntu-24.04, windows-2025, пакет windows-x64 wire lab) | **PASS** | раздел 9 |
| Итоговое ревью ветки (два ревьюера: код продукта; лаборатория, CI и документы) и повторное ревью правок; CI на `9907de0` (`rmasscan`, `Studio`, `language-guard`) | **PASS**: ревью APPROVED после правок раздела 12, CI зелёный | разделы 9, 12 |

Что принимается. К живому скану PR #49 добавлены: восемь файловых форматов (`-oL`, `-oJ`, `-oD`, `-oG`, `-oX`, `-oB`,
`-oH`, `-oU`) и `--output-format none`, опции вокруг вывода (`--output-format`, `--output-filename`, `--append-output`,
`--output-flush`, `--open`, `--show`, `--noshow`, `--interactive`, `--stylesheet`, `--webxml`, `--status`, `--nostatus`,
`--ndjson-status`), `--readscan` (чтение файлов `-oB` и вывод любым форматом), строка статуса masscan на stderr и Ctrl-C
(Р18: первое нажатие останавливает скан и дописывает файл с подвалом, второе выходит с кодом 1). Файл вывода
открывается до ARP и до engine (Р8). Engine, ядро и Studio не менялись.

Критерий живого паритета (поправка к спеке §6.2, решение контролёра по итогам первого окна, раздел 8): множество записей
(время маскировано, порядок нормализован) и заголовок rmasscan равны C; **подвал оракула может отсутствовать**, если в
его stderr есть `[-] Passed the wait window but still running, forcing exit...` (`main.c:1489–1496`: поток приёма C на
тихом линке не возвращается, скан не заканчивается, `output_destroy` не вызывается). Подвал rmasscan обязан равняться
подвалу своего формата, построенному из его же записей. Побайтный паритет подвалов с C доказан офлайн 74 эталонами.
Гипотеза о причине forced exit не проверялась отдельным экспериментом: известны наблюдение (строка в stderr у всех 11
сравниваемых прогонов, `notes.oracle_forced_exit: true`) и путь в коде C.

Не входит в GO: macOS живой (NOT RUN), живой Ctrl-C на Windows (NOT RUN), физические NIC (NOT RUN), баннеры, redis,
certs, ротация (не цели этапа).

## 2. Закреплённые коммиты и чистота дерева

| Часть | Коммит | Чистота и привязка |
| --- | --- | --- |
| Код под живыми окнами (C) | `2b0e92ce7af3d0ba5ae68af881de22a0e99a3590` (2026-11-06) | сборки из `git archive C` на minipc и госте (полное дерево), home-pc и Mac (`rmasscan/`); release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, rustc 1.99.1 (README evidence, `verification/binaries.sha256.txt`) |
| Evidence | `86f384f` (`test(cli): record output-format acceptance on the Linux stand and the autodetect regression on Linux and the Windows VM`) | только `docs/experiments/2026-11-06-rmasscan-output-acceptance-raw/` |
| База | `438e58b` (PR #49) | без rebase |
| Последний коммит с кодом | `9907de0` (раздел 9); следующий коммит меняет только статусы в документах (этот отчёт, readiness, README) | |

Ход ветки от `438e58b` (`git log --oneline 438e58b..86f384f`, 14 коммитов):

| Группа | Коммиты |
| --- | --- |
| Спека и план | `317f1a4`, `0e4a939` |
| Записи, форматтеры list/json/ndjson/hostonly/xml/binary и конвейер вывода | `a439a39` |
| grepable и unicornscan, имена сервисов хоста (Р10) | `d872625` |
| Чтение `-oB` для `--readscan` | `9b4cb64` |
| Опции вывода, `--readscan`, файловый вывод живого скана | `bfb1e8d` |
| Строка статуса masscan на stderr | `da95b93` |
| Ctrl-C (Р18) | `25c973c` |
| Мёртвый stderr не оставляет файл без подвала | `28ab7ba` |
| Эталоны C для всех форматов через `--readscan` | `a15cda7` |
| CI: macOS-задачи с retired `macos-14` на `macos-15` | `fbc1b96` |
| Лаборатория: `output-suite`, `output-verify` (первая версия) | `8ad37b5` |
| Лаборатория: верификатор ждёт forced exit оракула, судит подвал rmasscan; clippy и тесты для Windows | `2b0e92c` |
| Evidence | `86f384f` |

После C до evidence-коммита не менялось ничего, кроме каталога evidence; коммит этого отчёта меняет только документы,
поэтому продуктовый код на нём равен C. Исправления после итогового ревью меняют продуктовый код после C; почему
живые вердикты на C для них остаются в силе, сказано в разделе 12. Файл `.github/workflows/rmasscan.yml` этим этапом
правился один раз, в `fbc1b96`; новых тестовых шагов этап не добавил (новые тесты идут через существующие
`cargo test`).

## 3. Хэши и происхождение

Хэши вердиктов пересчитаны при написании отчёта (`shasum -a 256` по трём `verdict.json` закоммиченной копии) и равны
хэшам README evidence:

| Каталог | sha256 `verdict.json` |
| --- | --- |
| `linux-output-r1` | `8752b7d60cbec6bbabf68895e8352293f886bc5da2241be63deb184f471b8b96` |
| `linux-autodetect-r2` | `e546d9a310db98f558906288d4c7570cd6ca3d5920e3aab049a7dc08ee1f88aa` |
| `windows-autodetect-r2` | `d70bd9ace70fded615d7cbf0752541329f89f22ab68c1e03125cc04593617874` |

| Объект | sha256 | Где |
| --- | --- | --- |
| `rmasscan`, minipc (Linux x86_64) | `41d92bb8443c2714d94e441fca45e0dd6055d813108ad83de4fbb9010d1adcbf` | `verification/binaries.sha256.txt` |
| `rmasscan-lab`, minipc | `d145c90c5720b5ba0b2b76145a653189002ec53b2ff8688c6437dc7cfe9eb438` | там же |
| `rmasscan.exe`, гость (статический CRT, Dependent Load Flag 0x800) | `dde1d277e5ba32d6dcac7015fd1d60de18a02478a14508d033993fc4abeccc57` | там же, `verification/guest-exits.txt` |
| `rmasscan-lab`, home-pc | `8bf8c06b527eba9e0088976a9d84298b5b06c84153b6bca0a164f963e0fbbae7` | там же, `windows-autodetect-r2/deploy/deploy-manifest.json` |
| `rmasscan-lab`, Mac (оркестратор `windows-suite`, `windows-verify`) | `266b0b21046f7bb6ef2580824034d6dc26cbe59627cc6bce083c44dd4e4952bf` | там же |
| C-оракул masscan `8e6b3b0c07a81e8ea61d557c06134a21a6881614` | хэш бинаря в `manifest.json` каждого каталога и в `rmasscan/tests/golden/formats/manifest.json` (тот же билд) | `linux-*/manifest.json` |

Вердикты вынесли офлайн `rmasscan-lab output-verify` (Linux output) и `autodetect-verify` (`windows-verify` для Windows
передаёт ему каталог целиком). После копии в репозиторий хэши каждого прогона проверены повторно и верификатор копии
дал тот же вердикт байт в байт (README evidence). `MANIFEST.sha256` корня содержит 715 строк.

## 4. Стенды и действия пользователя

- **Linux (minipc)**: netns `wl-scan-*` и `wl-peer-*`, veth, стенд autodetect (маршрут по умолчанию через `198.18.0.2`
  только внутри netns сканера, постоянные соседи; uplink, мост и NAT нет). Отмена записана (`teardown.json`,
  `namespaces_left: 0`, `lab_id` равен манифесту), `own_pids=0 stray_processes=0`. Окна: `linux-output-r1`
  21:17:25Z–21:22:32Z, `linux-autodetect-r2` 21:22:48Z–21:24:23Z. C-оракул masscan `8e6b3b0` запускается на том же
  стенде.
- **Windows (home-pc, гость QEMU, стенд `n2`)**: мост/TAP/netns без uplink, Npcap в режиме Admin-only. В каждом из 9
  прогонов `raw_run_allowed: true` в `status-pre.json` и `status-post.json`, на `eno1` 0 кадров. Окно 21:22:30Z–21:53:23Z.
  Оркестратор на Mac, ssh через minipc как jump-хост; шёл одновременно с окнами Linux, стенды разные.
- **macOS (`m1`)**: **NOT RUN**. Код ниже CLI не менялся, окно Mac требует `sudo` пользователя. Mac только оркестрирует
  `windows-suite`; `sudo` на Mac не использовался.
- **Действия пользователя**: ни одного. `n2` поднимал и снимал оператор через существующий `sudo -n` на home-pc
  (`vm-lab down` rc 0, `status`: `state: down`, все объекты MISSING, `verification/homepc-n2-status-after-down.json`).

## 5. Версии

| Компонент | Значение | Источник |
| --- | --- | --- |
| minipc | Linux 7.0.0-38-generic, tcpdump 4.99.6 | README evidence, `verification/minipc-versions.txt` |
| home-pc | Linux 7.3.0-10-generic, QEMU 10.2.1 | README evidence |
| Гость | Windows 10.0.26300.9818, elevated-сессия, Npcap 1.90 в режиме Admin-only (`AdminOnly=1`) | README evidence, `verification/guest-exits.txt` |
| Mac (оркестратор) | macOS 27.2 (26B123) | `verification/hosts-versions.txt` |
| rustc | 1.99.1 (`58cf8f9c3 2026-10-13`) на всех хостах | README evidence |
| C-оракул | masscan `1.3.9-integration`, `8e6b3b0c07a81e8ea61d557c06134a21a6881614` | `linux-output-r1/manifest.json` |

## 6. Результаты

### 6.1. Офлайн-паритет с C: 74 случая

Эталоны (`rmasscan/tests/golden/formats/`, `manifest.json`, число случаев пересчитано: **74**) сняты C `8e6b3b0`
(`--readscan` каждого входа во все форматы; сеть отключена `unshare -n`, каждый случай прогнан дважды и дал одно и то же
после маски). Тест `crates/rmasscan-cli/tests/formats_golden.rs` прогоняет каждый случай через `rmasscan_cli::run` на
трёх ОС в CI. Входы: `basic` (8 записей), `edge` (порты 0, 65535, 47001, TTL 0 и 255, флаги 0, 0x04, 0x12, 0x14, 0xFF,
адреса `0.0.0.1` и `255.255.255.255`), `empty` (заголовок и подвал), `many` (70 000 записей, сравнивается по
`masked_sha256`). Маскируются только поля, которые C берёт из часов в момент записи: XML `start`, `finished time`,
`timestr`, `elapsed`; grepable `# Masscan done at`. Каждая маска попадает ровно в одну строку непустого вывода; остальные
байты сравниваются точно. Отличий от C в этих случаях нет. Записано поведение C: на пустом входе все форматы, `-oB`
включая, оставляют файл в 0 байт; без `-p` заголовок grepable не перечисляет порты; XML `down=` считает только
показанные записи. Имена сервисов эталон берёт из `services.txt` (`getent services`), а читатель файла services хоста
(Р10) проверяется отдельно в `output::services`.

### 6.2. Linux: `linux-output-r1` — overall **PASS**, 18 PASS (FAIL 0, INVALID 0, NOT RUN 0)

Цели `198.18.0.2-198.18.0.5`, порты `-p80,443,8080` (80 и 8080 открыты, 443 закрыт), общие аргументы
`--seed 1 --rate 100 --wait 3`. Во всех сканах `[+] finished: Completed, sent 12, replies 12, open 8`, `sent` равен
числу SYN на проводе, SYN равны плану argv и идут в том же порядке.

| Кейс | Отличие argv | Сравнение | exit |
| --- | --- | --- | --- |
| `o01_list` | `-oL output.txt --show open,closed` | с оракулом | 0 |
| `o02_json` | `-oJ` | с оракулом | 0 |
| `o03_ndjson` | `-oD` | с оракулом | 0 |
| `o04_grepable` | `-oG` | с оракулом | 0 |
| `o05_xml` | `-oX` | с оракулом | 0 |
| `o06_binary` | `-oB output.bin` | с оракулом | 0 |
| `o07_hostonly` | `-oH` | с оракулом | 0 |
| `o08_unicornscan` | `-oU` | с оракулом | 0 |
| `o09_json_default_show` | `-oJ` без `--show` (только open) | с оракулом | 0 |
| `o10_list_stdout` | `-oL -` | с оракулом | 0 |
| `o11_interactive` | `-oL output.txt --interactive` | с оракулом | 0 |
| `o12_nostatus` | `-oJ --nostatus` | **только rmasscan** (решение контролёра) | 0 |
| `o13_open_fail` | `-oL /nonexistent-rmasscan-dir/x` | **только rmasscan** (без оракула по замыслу) | 1 |
| `o14_interrupt_json` | `-p1-1000 --rate 20 -oJ`, SIGINT через 2 с | **только rmasscan** (решение контролёра) | 0 |
| `o15_interrupt_xml` | то же, `-oX` | **только rmasscan** (решение контролёра) | 0 |
| `o16_interrupt_binary` | то же, `-oB` | **только rmasscan** (решение контролёра) | 0 |
| `o17_readscan` | `--readscan` обоих `-oB` из `o06` | оба сканера, списки равны байт в байт | 0 |

Что проверено в каждом сравнении (`o01`–`o11`): оба файла разобраны как корректные документы своего формата;
записи rmasscan равны записям оракула после маски времени (порядок нормализован) и равны ответам стенда (12 из 12
или 8 из 8) и ответам на проводе; дублей нет; время записей, заголовка и подвала лежит в окне захвата; stdout пуст
при `-o…`; stderr разбирается в строки `[+]` и строку статуса (каждый фрагмент перед `\r` проверен по грамматике,
`o01`: 12 тиков и одно стирание 77 пробелами прямо перед `[+] finished`); заголовок rmasscan равен заголовку оракула
после маски часов; подвал rmasscan равен подвалу, построенному из его же записей.

Отдельные заметки.

- **`o01`–`o11`: `oracle_forced_exit: true`.** В stderr оракула каждого из 11 прогонов есть
  `[-] Passed the wait window but still running, forcing exit...`, подвала в его файлах нет. По критерию из раздела 1
  это ожидаемо; без этой строки отсутствие подвала было бы INVALID.
- **Только rmasscan по решению контролёра: `o12` и `o14`–`o16`.** Для `o12` у C нет эквивалента: C 8e6b3b0 с
  `--nostatus` и `--wait` больше 0 висит до второго Ctrl-C (`main.c:1150`), не дойдя до принудительного выхода. Первая итерация цикла ожидания проверяет окно ожидания
  (`main.c:1490–1491`) и принудительный выход (`main.c:1494–1496`), пока `--wait` ещё не прошёл, и сразу ждёт поток
  передачи (`main.c:1530`); тот крутится до `is_rx_done` (`main.c:470`), а выставить его могли бы только вторая
  итерация, которой нет, и ветка статуса (`main.c:1518`), которую `--nostatus` пропускает. rmasscan заканчивает скан
  и печатает `N milliseconds elapsed` (`o12`: `3132 milliseconds elapsed`, скан ждал 3 с). Это дефект C, которого у
  rmasscan нет. `o14`–`o16` (прерывание) у C не имеют аналога: у него Ctrl-C запускает фазу ожидания и `paused.conf`
  (Р18).
- **`o13_open_fail`**: без оракула по замыслу, а не по решению: C открывает файл в потоке приёма, уже после старта
  передачи, и отправил бы кадры (Р8), а кейс меряет их отсутствие. `out: could not open file for writing`, затем
  `/nonexistent-rmasscan-dir/x: No such file or directory (os error 2)`, exit 1; в захвате peer 0 кадров сканера (ни
  ARP, ни SYN), только маркеры свидетеля.
- **`o14`–`o16`**: SIGINT через 2.0 с (`interrupt.json`), rmasscan вышел сам (`killed: false`), exit 0,
  `[+] finished: Stopped, sent 41|42|42`, `sent` равен SYN на проводе, строка Ctrl-C ровно одна, файлы JSON, XML и
  binary целые, их записи — подмножество ответов на проводе.
- **`o17_readscan`**: ни одного кадра сканера и оракула во время `--readscan`; stderr — по одной строке
  `[+] --readscan FILE` на вход, без строки статуса.

### 6.3. Регрессия автоопределения

Повтор приёмки [`2026-10-27-rmasscan-autodetect-acceptance-raw`](2026-10-27-rmasscan-autodetect-acceptance-raw/) на коде
этого этапа. Живой stderr CLI теперь несёт строку статуса; верификатор autodetect читает его так, как показывает
терминал (спека §6.3): фрагменты перед `\r` есть в каждом скане, дошедшем до `[+] finished` (Linux `l01`–`l08`, `l11` —
по 13 `\r`; Windows `w01`–`w04` — 20–21), и каждый разобран по грамматике, а не пропущен.

| Каталог | Кейсы | Вердикт |
| --- | --- | --- |
| `linux-autodetect-r2` | `l01_auto`, `l02_auto_multi`, `l03_adapter`, `l04_adapter_ip`, `l05_adapter_mac`, `l06_router_ip`, `l07_router_mac`, `l08_source_port`, `l09_arp_timeout`, `l10_no_such_adapter`, `l11_parity`, `l12_iflist` (+ манифест) | **PASS 13/13**, `safety_trips` [], включая паритет `l11` с оракулом |
| `windows-autodetect-r2` | `w01_auto`, `w02_adapter_npf`, `w03_adapter_friendly`, `w04_router_mac`, `w05_arp_timeout`, `w06_multi_no_gateway`, `w07_iflist`, `w08a_restricted_iflist`, `w08b_restricted_scan` (+ манифест) | **PASS 10/10**, `safety_trips` []; preflight `w01` и `w06` назвал `[+] interface = Ethernet 2 (detected: route to 198.18.0.2)` |

### 6.4. Ручные прогоны рабочей области на C

| ОС | Итог | Лог |
| --- | --- | --- |
| Linux (minipc), с `RMASSCAN_EXPECT_DEFAULT_ROUTE=1` | `cargo test --locked --workspace --no-fail-fast`: 1528 passed, 0 failed, 14 ignored; clippy `-D warnings` rc 0 | `minipc-test-ws.log`, `minipc-test-ws-exit.txt`, `minipc-clippy.log` |
| Windows (гость `n2`, elevated, Npcap Admin-only) | 1428 passed, 0 failed, 34 ignored; clippy rc 0 | `guest-test-ws.log`, `guest-clippy.log`, `guest-exits.txt` |
| macOS (Mac) | `cargo test --locked --workspace` при написании отчёта на HEAD этого коммита (продуктовый код равен C): 1656 passed, 0 failed, 23 ignored; clippy `-D warnings` и `cargo fmt --check` чисты; language guard PASS. Лога в evidence нет (в нём только сборка оркестратора, `mac-build-lab.log`) | |

## 7. Хэширование и полнота

- Каждый прогон хэширован до копирования (`hashes-before-copy.txt`) и перепроверен после; `hashes-before-copy.txt` не
  охватывает `verification/`.
- Захваты полные: у каждого прогона `capture.json` `valid: true`, число кадров в файле равно записанному, три
  стартовых маркера до и три конечных после всех кадров сканера; то же для `oracle-capture.json`. Pcap без сжатия.
- Privacy: проверка верификатора «every text and binary file holds only allowlisted names, addresses and paths» PASS;
  `grep -ralwE` по именам хостов и учётных записей Mac, minipc, home-pc и гостя и по mDNS-суффиксам по всем файлам трёх
  каталогов и `verification/` — 0 совпадений. Пути `C:\Users\lab\…` относятся к учётной записи гостя `lab`, она
  разрешена. Полного `--iflist` нет нигде, только `iflist.json`.
- Отброшенных и прерванных прогонов в каталогах нет (`discarded`, `aborted` пусты).

## 8. Отклонения и история окон

- **Первая живая попытка на `8ad37b5` (заменена).** Окно `linux-output-r1` прошло чисто (`SUITE_RC=0`), но
  `output-verify` дал overall FAIL: PASS 9, INVALID 9. Причина — forced exit оракула: верификатор `8ad37b5` требовал от
  оракула целый подвал. Тогда же нашлись два дефекта тестов (clippy `check_out` вне macOS и тест `output_suite` на
  путях Windows). Всё исправлено в `2b0e92c`; evidence той попытки в репозиторий не копировалось (снято на прежнем
  бинарнике лаборатории, не является доказательством для C). Поправка критерия живого паритета (раздел 1) — решение
  контролёра по итогам этой попытки.
- **minipc, первая попытка тестов на C**: `minipc-test-ws-attempt1-background.log` — 1526 passed, 2 failed
  (`dump::tests::linux_wire_gate::real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate` и
  `dump::tests::sequence::a_complete_capture_is_acknowledged_finalised_and_valid`, «tcpdump did not exit after SIGINT»);
  код выхода 101 записан в `minipc-exits.txt`. Причина: скрипт запущен фоном (`nohup … &`) из неинтерактивного bash,
  который выставил SIGINT в SIG_IGN; поддельный `tcpdump` на `sh` унаследовал это и не может поставить `trap` на SIGINT.
  Повтор на переднем плане ssh-сессии: 0 failed. В `verification/` сохранено значение `SigIgn` только переднего плана
  (`0000000000000004`, `minipc-test-ws-exit.txt`); значение фоновой попытки (README evidence называет `…07`) отдельным
  файлом не сохранено, лог попытки хранится. Живые окна по той же причине шли на переднем плане.
- `cargo test` шёл с `--no-fail-fast`, чтобы в логе были все тестовые бинарники.
- Гость: экспорт без `.git`, поэтому перед тестами `git init; git add -A`, как в прежних гостевых прогонах (без индекса
  тест `rust_only::the_tracked_tree_has_no_interpreted_programs` не находит себя на путях с `\`).
- Окно Windows шло одновременно с окнами Linux (раздел 4).

## 9. CI

CI на `2b0e92c` (прогон `rmasscan` `42291016820`, черновой PR #50):

| Workflow | Прогон | Задачи |
| --- | --- | --- |
| `rmasscan` | `42291016820` | `macos-15`: success; `ubuntu-24.04`: success; `windows-2025`: success; `windows-x64 wire lab package`: success |

Задачи macOS перенесены с `macos-14` на `macos-15` в `fbc1b96`: GitHub вывел образ `macos-14` из обращения
(2026-11-02). CI на evidence-коммите `86f384f` запустил только `language-guard` (`42301944790`: success): workflow
`rmasscan` отфильтрован по путям, коммит меняет лишь `docs/experiments/…-raw/`.

| Коммит | Workflow | Статус |
| --- | --- | --- |
| `2b0e92c` | `rmasscan` | success (выше) |
| `86f384f` | `language-guard` | success (`42301944790`) |
| `7c9b378` | `rmasscan` | failure: `windows-2025`, clippy `dead_code` (константа FIFO-теста без `#[cfg(unix)]`), исправлено в `9907de0` |
| `9907de0` | `rmasscan` | success (`42357661620`: `macos-15`, `ubuntu-24.04`, `windows-2025`, `windows-x64 wire lab package`) |
| `9907de0` | `Studio` | success (`42357661615`: `application` на `macos-15`, `ubuntu-24.04`, `windows-2025`) |
| `9907de0` | `language-guard` | success (`42357661619`) |

CI собирает и гоняет только офлайн-тесты; живые прогоны не идут.

## 10. Не выполнено и ограничения

| Область | Статус |
| --- | --- |
| macOS живой прогон (окно `m1`, регрессия autodetect и вывод) | **NOT RUN**: код ниже CLI не менялся, окно требует `sudo` пользователя |
| Живой Ctrl-C на Windows | **NOT RUN**: консольное событие по ssh не доставить; обработчик покрыт юнит-тестами, живое прерывание снято на Linux (`o14`–`o16`) |
| Физические NIC (Linux, Windows, macOS) | **NOT RUN** |
| Живой паритет подвалов с C | не измерен вживую (C не заканчивает живой скан на стенде, раздел 1); доказан офлайн 74 эталонами |
| Живой паритет `--nostatus` и прерывания с C | нет: у C нет конечного исхода на этих кейсах (раздел 6.2) |
| Итоговое ревью ветки; CI на последнем коммите с кодом | **PASS** (разделы 9, 12) |
| Баннеры, redis, certs, ротация, UDP/SCTP/ICMP-записи, IPv6-записи | не цели этапа (Р1, Р13) |

Отличия от C, которые войдут в README, перечислены в `rmasscan/README.md` («Отличия от masscan»), источники — спека §8
и решения Р1–Р19. Studio и engine этим этапом не менялись.

## 11. Заявление о готовности

**GO «rmasscan output formats (offline parity + Linux stand)»:** выполнено на коде C = `2b0e92c`
(офлайн-паритет 74/74, `linux-output-r1` PASS 18/18, регрессия Linux 13/13 и Windows VM 10/10, CI `rmasscan` на C зелёный).
Условия выполнены: итоговое ревью ветки APPROVED (после правок раздела 12) и зелёный CI (`rmasscan`, `Studio`,
`language-guard`) на последнем коммите с кодом `9907de0` (раздел 9). Заявление не распространяется на строки раздела 10 со статусами NOT RUN и OPEN.
Стенд никогда не заменяет физическую приёмку.

## 12. Исправления после итогового ревью

Итоговое ревью ветки нашло одну важную и несколько мелких правок; они внесены отдельными коммитами поверх `a554e1d`.

- **`--nostatus` с форматом в stdout.** С `-oJ -`, `-oL -`, `-oX -`, `-oB -` и любым другим файловым форматом в `-`
  строка `N milliseconds elapsed` больше не дописывается в stdout после документа. C закрывает stdout вместе с файлом
  `-` (`output.c:216`, `fclose` на `output.c:268`) до `printf` на `main.c:1551`, поэтому его stdout содержит только
  формат. С настоящим файлом или без файлового формата строка остаётся. Тест
  `live_fake::nostatus_with_stdout_format_keeps_stdout_pure`.
- **Обрыв канала у файла.** Тихий выход с кодом 0 на EPIPE остался только для stdout (`| head`). Файл по имени (FIFO
  или `/dev/fd/N`, читатель которого ушёл) получает обычную ошибку `write failed: …`: скан останавливается,
  `[+] finished` печатается, код 1. Тесты `output::tests::only_a_broken_stdout_exits_quietly` и
  `output::pipeline::tests::a_dead_fifo_reader_is_a_write_error` (FIFO, только Unix).
- Оба исправления меняют поведение только на путях, которых живое окно не касалось: `o12_nostatus` пишет в файл
  (`-oJ output.txt`), а цели-FIFO в наборе нет. Живые вердикты на `2b0e92c` (раздел 6.2) для них остаются в силе, новые
  пути закреплены тестами fake-бэкенда и юнит-тестами.
- Лаборатория: в тестах privacy вымышленные имя хоста (`printer-7.local`, `printer-7`) и учётная запись (`alice`)
  вместо настоящих (вердикты тестов те же); ожидание выхода
  rmasscan после SIGINT в `output-suite` учитывает остановку оператора, как и ожидание до сигнала. Строки и логика
  `output_verify.rs` и `autodetect_verify.rs` не менялись: `output-verify` и `autodetect-verify` новой сборки на копии
  трёх закоммиченных каталогов дали `verdict.json`, байт в байт равные закоммиченным (хэши раздела 3).
- Документы: README (оба сообщения Р13, короткий файл `--readscan`, строка времени при `--nostatus`, причина
  зависания C с `--nostatus`), `rust-lab.md`, разделы 1, 2, 6.2 и 8 этого отчёта, поправка к §6.2 спеки.

Повторное ревью правок подтвердило все пункты и нашло одну новую важную ошибку: константа FIFO-теста без
`#[cfg(unix)]` давала `dead_code` в clippy на Windows (CI `windows-2025` упал на `7c9b378`). Исправлено в `9907de0` вместе
с уточнением: C с `--nostatus` висит при `--wait` больше 0 и до второго Ctrl-C (`main.c:1150`). CI на `9907de0` зелёный
(раздел 9). Ручной прогон `cargo test --locked --workspace` на `9907de0` на отдельном Linux-хосте (Ubuntu 26.04, полное
дерево из `git archive`): 1533 passed, 0 failed, 14 ignored; лога в evidence нет.
