# rmasscan: управление сканом (`--shard`, `--retries`, пауза и `paused.conf`, `--resume`, `--infinite`, `-c`/`-iL`, несколько адаптеров, `--pcap`, поля пакета), приёмка (итоговый отчёт этапа)

Дата: 2026-11-10. Ветка `feat/rmasscan-scan-control`, база `83ea225` (`git merge-base origin/main HEAD`), 35 коммитов до
`28c956e`. Документ фиксирует измеренное и открытое. Статусы: PASS / FAIL / INVALID / NOT RUN / OPEN / PENDING, никогда
не повышаются. Сырые данные:
[`2026-11-08-rmasscan-scan-control-acceptance-raw/`](2026-11-08-rmasscan-scan-control-acceptance-raw/) (корневой
[README](2026-11-08-rmasscan-scan-control-acceptance-raw/README.md) и `MANIFEST.sha256`; у каждого из четырёх каталогов
свои `manifest.json`, `verdict.json` и `runs/<tag>/`; логи сборок, тестов, `privacy-scan` и состояния стенда гостя лежат
в `verification/`). Спека: [design](../superpowers/specs/2026-11-08-rmasscan-scan-control-design.md) (решения Р1–Р9, отличия
от C в §8). План: [plan](../superpowers/plans/2026-11-08-rmasscan-scan-control.md), задача 8. Родственные документы:
[приёмка форматов вывода](2026-11-06-rmasscan-output-acceptance.md) (образец формата),
[перечень готовности](2026-10-24-rmasscan-readiness.md).

## 1. Итог и границы

- Все четыре живых окна сняты на итоговом коде этапа C = `11a2235` (прогон r4), после волны исправлений итогового ревью.
- Живая приёмка управления сканом на Linux: `linux-scan-control-r4` **PASS 7/7** (манифест и кейсы `sc01`–`sc06`).
- Регрессия форматов вывода на Linux: `linux-output-r4` **PASS 18/18**; регрессия автоопределения: `linux-autodetect-r4`
  **PASS 13/13** на Linux и `windows-autodetect-r4` **PASS 10/10** на Windows VM.
- Во всех четырёх окнах `safety_trips` пуст.
- NOT RUN: живое окно macOS этого этапа (нужен `sudo` пользователя), физические NIC всех ОС, живой Ctrl-C на Windows
  (консольное событие по ssh не доставить, спека §6.2).
- Тесты Studio (offline) этого этапа идут в CI PR. Studio CI: заполняется при PR.
- Стенд никогда не заменяет физическую приёмку.

## 2. Закреплённые коммиты и чистота дерева

| Часть | Коммит | Привязка |
| --- | --- | --- |
| Код под живыми окнами (C) | `11a2235eaabd0abcff3fe90ab0b6953032ce4a48` (2026-11-10) | minipc и гость: полное дерево из `git archive C`; home-pc: `rmasscan/` из `git archive C`; Mac (оркестратор и верификаторы): чистая рабочая копия на C. Release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, rustc 1.99.1 (`58cf8f9c3 2026-10-13`). HEAD ветки весь прогон стоял на C |
| Код продукта | `14200c5`, затем `11a2235` | `14200c5`: волна исправлений итогового ревью (`--wait forever`, предупреждение `--shard` без `--seed`, отсчёт ожидания от конца передачи, `ndjson-status` из файлов); `11a2235`: комментарий в `live.rs` и документация. Бинарник `rmasscan` на minipc `3a169c27…` |
| Тест-фикс | `b76a945` | только тест: многоадаптерный сценарий паузы и возобновления сделан детерминированным |
| Лаборатория | `e52793b`, `14200c5` | `e52793b`: `output-verify` принимает новый поток первого Ctrl-C (Р4), подкоманда `privacy-scan`; `14200c5`: `privacy-scan` отказывает токену короче 4 байт и в захватах сравнивает только данные кадров |
| Evidence | `28c956e` (`test(cli): record scan-control acceptance r4 at the final code on the Linux stand and the Windows VM`) | только `docs/experiments/2026-11-08-rmasscan-scan-control-acceptance-raw/` (876 файлов, `MANIFEST.sha256` на 875 записей); каталоги r3 этим коммитом удалены, они есть в истории на `7773eb3` |
| База | `83ea225` | без rebase |

Windows: `manifest.json` и `deploy/preflight-*.json` несут `code_commit`, `orchestrator.build_commit` и
`orchestrator.git_commit`, все равные `11a2235`, `git_dirty: false`.

## 3. Результаты четырёх окон (все на C = `11a2235`)

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-scan-control-r4` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + вторая пара veth (`veth-a2`/`veth-b2`), C-оракул masscan 8e6b3b0 | `sc01`–`sc06` (+ манифест) | **PASS 7/7** | 10:58:21Z–11:00:34Z | `6993ae1f0cf73286f04a39f229e4122f6f06d723a3ca9962ce14472a781cb66d` |
| `linux-output-r4` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18** | 11:00:35Z–11:05:53Z | `5272b145798f93a10c3c8ad6a0f00c4a5a68d5a9c1b748e23290396599d7774f` |
| `linux-autodetect-r4` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13** | 11:05:55Z–11:07:32Z | `6fb4b0a2ccefecc5d008df0aaba6083cabb79524c4104769d19536ad90699342` |
| `windows-autodetect-r4` | home-pc, QEMU-гость Windows 11, стенд `n2`, Npcap Admin-only, исправленный стенд гостя (раздел 6) | `w01`–`w08b` (+ манифест) | **PASS 10/10** | 10:58:41Z–11:28:49Z | `a167b5a1ee951856acdd121f4ab3013c3d4b39f09874bd77458e21bc868f5464` |

Вердикты вынесли офлайн-верификаторы `scan-control-verify`, `output-verify`, `autodetect-verify`; для Windows
`windows-verify` передаёт каталог целиком в `autodetect-verify`. После копии в репозиторий хэши каждого прогона
проверены повторно (`hashes-before-copy.txt`), и верификатор копии дал тот же вердикт байт в байт.

### 3.1. Что проверено в `linux-scan-control-r4`

- `sc01`: `--shard 1/2` и `2/2` с одним `--seed` вместе шлют ровно 12 SYN без пересечений; находки равны находкам
  одиночного прогона C; порядок SYN оракула это два шарда вперемешку (12 из 12).
- `sc02`: SIGINT через 3 с, строка `saving resume file to: paused.conf` до первого тика ожидания, `paused.conf` на диске
  через 0,2 с после сигнала; тики `waiting N-secs` считают от `--wait 2` вниз. Фаза ожидания принимает поздний ответ
  (netem 1000 мс на `veth-b` пира, ставится и снимается suite, факт в `netem.json`). `--resume` шлёт ровно остаток плана
  (59 из 80, точное мультимножество) и дописывает `-oJ`.
- `sc03`: `--retries 2` шлёт каждый зонд `(2+1)^2 = 9` раз (108 SYN), мультимножество равно оракулу.
- `sc04`: `--ttl 42 --tcp-sackok --tcp-wscale 7` на каждом SYN; `--badsum` (неверная L4-сумма при верной IPv4); файл
  `--pcap` сканера.
- `sc05`: `--infinite` даёт больше одного полного прохода (218 SYN, 18 проходов), затем SIGINT, код 0, без `paused.conf`.
- `sc06`: `--adapter[0]` на `veth-a`, `--adapter[1]` на `veth-a2`, точное разбиение плана по чётным и нечётным индексам;
  ответы второго адаптера вернулись по второму линку, по одному различному ответу на SYN (повторы SYN-ACK пира к
  `198.18.0.6`, не назначенному ни одному интерфейсу, это тот же ответ); непрошеных кадров нет; пауза и `--resume` без
  потерь, дубли ограничены; на resume обе строки `source-port` это `(given)`.

### 3.2. Регрессии

- `linux-output-r4` и `linux-autodetect-r4` повторяют приёмки `2026-11-06-rmasscan-output-acceptance-raw` на C этого
  этапа. Первое прерывание теперь пауза Р4, как в C (`main.c:1136-1139`, `main-conf.c:399-403`): stderr `o14`–`o16`
  несёт `waiting several seconds to exit...`, стирание из 70 пробелов, `saving resume file to: paused.conf`, тики ожидания
  и `[+] finished: Paused`. `output-verify` на C принимает этот поток; путь `Stopped` не тронут, закоммиченные каталоги
  прежних этапов дают прежние вердикты.
- `windows-autodetect-r4` повторяет `windows-autodetect-r2` прежнего этапа.

## 4. Тесты и сборки на C

| Хост | Результат |
| --- | --- |
| minipc (Linux 7.0.0-38-generic, tcpdump 4.99.6) | `RMASSCAN_EXPECT_DEFAULT_ROUTE=1 cargo test --locked --workspace --no-fail-fast`: **1702 passed, 0 failed**, 14 ignored; `cargo clippy --locked --workspace --all-targets -- -D warnings`: 0 |
| гость (Windows 10.0.26300, elevated, Npcap 1.90 Admin-only) | тот же тест: **1598 passed, 0 failed**, 34 ignored; clippy 0; `rmasscan.exe` со статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`0800 Dependent Load Flag` OK) |
| home-pc (Linux 7.3.0-10-generic, QEMU 10.2.1) | `rmasscan-lab`, `deploy-manifest` для C |
| Mac | только сборка оркестратора и офлайн-верификаторов; `sudo` не использовался |

Тест `multi_adapter_paused_conf_round_trips_and_resumes` (детерминирован с `b76a945`) прошёл на обоих хостах.
sha256 бинарников: `verification/binaries.sha256.txt` (lab home-pc `e0385a8d…`, minipc `c73587a4…`, Mac `074457e3…`,
`rmasscan` minipc `3a169c27…`, `rmasscan.exe` гостя `ef5121a3…`).

## 5. CI

На `11a2235` (C), зелёный: `rmasscan` run **42801284719** (ubuntu-24.04, macos-15, windows-2025, windows-x64 wire lab
package), `language-guard` run **42801284890**. Ранее: `14200c5` зелёный (`rmasscan` 42800478832, `language-guard`
42800479228); `e52793b` зелёный (`rmasscan` 42778534214, `language-guard` 42778534451); `fd73de9` зелёный (`rmasscan`
42743046815, `language-guard` 42743046787); на `1e38fca` `rmasscan` на macos-15 упал на нестабильном тесте
`multi_adapter_paused_conf_round_trips_and_resumes` (тайминг, продукт не менялся), исправлено в `b76a945`, CI на
`b76a945` зелёный (`rmasscan` 42772313158, `language-guard` 42772313439).

Studio CI: заполняется при PR. Тесты Studio (offline) идут в Studio CI PR; на этом стенде `cargo xtask test` не гонялся.

## 6. Стенд Windows: исправление гостя (только выделенная VM `n2`) и обязательный `privacy-scan`

В неподтверждённой попытке r2 захват `w03` нёс mDNS-объявления гостевой ОС (служба Delivery Optimization) с именем
хоста гостя. Перед окном r3 на госте сделано (pwsh 7, скриптом-файлом; рецепт отката `verification/guest-stand-before.txt`,
копия лежит и на госте):

| Настройка | До | После |
| --- | --- | --- |
| `EnableMDNS` (`Dnscache\Parameters`) | нет значения (по умолчанию вкл.) | 0 |
| `EnableMulticast` (LLMNR, политика `DNSClient`) | нет значения | 0 |
| `DODownloadMode` (политика Delivery Optimization) | нет значения | 99 |
| lab-NIC `Ethernet 2` `ms_tcpip6` | True (`fe80::…/64`) | False (только `198.18.0.1/30`) |
| lab-NIC NetBIOS (`NetbiosOptions`) | 0 | 2 |
| управляющий NIC `Ethernet` | `ms_tcpip6` True, NetBIOS 0 | без изменений |

Применено в r3 в 08:12:50Z, затем настоящая перезагрузка, `w32tm /resync`, `Configure`, `record-guest`
(`verification/guest-stand-{before,applied,after}.txt`). Для r4 исправление не переприменялось, а проверялось: значения
прочитаны до `vm-lab up` (10:46:17Z) и после перезапуска VM для окна (10:57:51Z, `LastBootUpTime` 10:57:12Z). Каждая
строка настроек обоих чтений байт в байт равна снимку `guest-stand-applied.txt` (`verification/guest-stand-check-r4.txt`).
Только для сведения: служба `DoSvc` читается как `Stopped`, тип запуска `Manual`; это не настройка исправления. Результат:
ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r4` нет UDP- или IPv6-кадра, `privacy-scan` не нашёл ни одного
кадра mDNS, LLMNR или NBNS. Настройки остаются применёнными на госте; когда их откатить, решает пользователь.

Обязательный шаг `rmasscan-lab privacy-scan --dir --forbid` (декодирует имена в mDNS/LLMNR/NBNS, ищет токены в тексте и
в данных кадров захвата): текстовый шаблон mDNS-суффикса не находит имена в формате DNS (метки с длиной), поэтому r2 не
поймал бы `w03` без него. На C он отказывает токену короче 4 байт и не сравнивает заголовки записей pcap. Токены r4 —
каждое идентифицирующее имя от 4 байт, известное оператору: учётная запись Mac, её части имя и фамилия, имя хоста и имя
компьютера Mac, имена хостов minipc и home-pc, прежнее имя профиля Windows на home-pc. Все дали 0 совпадений во всех
четырёх каталогах, в `verification/` и во всём дереве (rc 0). Полное имя хоста гостя двухсимвольное и токеном быть не
может; его покрывает проход по DNS-форме, а кадров mDNS, LLMNR или NBNS нет ни в одном захвате. Пословный
регистрозависимый `grep -ralwE` из `rmasscan/docs/rust-lab.md` (все имена, в том числе короткие) даёт 0 файлов.
Вывод: `verification/privacy-scan.txt`.

## 7. Попытки, замещённые этим отчётом

- **r1 на `fd73de9`** (не закоммичена, лежит вне репозитория): `linux-scan-control-r1` FAIL (PASS 6, FAIL 1
  `sc06_dual_veth`; verdict `aac52af3…`), остальные окна не запускались (правило остановки). Причины: верификатор считал
  ответы на SYN второго адаптера 1:1, а пир повторял SYN-ACK (адрес `198.18.0.6` никому не назначен, RST не приходит),
  14 ответов на 6 SYN; на resume строка `source-port[1]` говорила `(time)`, хотя порт унаследован от заданного.
  Исправлено в `1e38fca`.
- **r2 на `1e38fca`** (не закоммичена, лежит вне репозитория): `linux-scan-control-r2` PASS 7/7 (`fa35a8a4…`),
  `windows-autodetect-r3` PASS 10/10 (`2353f5bb…`), но `linux-output-r2` FAIL (INVALID в `o14`–`o16`, `69d97ec9…`):
  верификатор вывода не знал новый поток первого Ctrl-C; `linux-autodetect-r3` не запускался. Захват `w03` нёс гостевые
  mDNS-кадры (раздел 6). Исправлено в `e52793b`.
- **r3 на `e52793b`** (закоммичена в `7773eb3`, удалена из дерева коммитом `28c956e`, доступна в истории git): все четыре
  окна PASS: `linux-scan-control-r3` 7/7 (`9b3de025…`), `linux-output-r3` 18/18 (`121b59c7…`), `linux-autodetect-r3` 13/13
  (`cc1b9fef…`), `windows-autodetect-r3` 10/10 (`228a0b92…`). Замещена, потому что волна исправлений итогового ревью
  (`14200c5`) изменила stderr: предупреждение `--shard` без `--seed` и отсчёт ожидания от конца передачи.

## 8. Отклонения

- `cargo test` шёл с `--no-fail-fast`; экспорт гостя и minipc без `.git`, перед тестами `git init; git add -A`.
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло одновременно с окнами Linux, как в прежних этапах;
  через minipc шёл только ssh-трафик управления.
- Архивы `git archive` переданы на minipc и home-pc по домашней сети напрямую (тот же хост, тот же ключ), хэш архива для
  гостя сверен. Сборки, тесты, все живые окна и `windows-suite` шли обычными `ssh minipc` и `ssh home-pc`.
- Оркестратор на Mac собран из чистой рабочей копии на C с уже существующим каталогом target вне репозитория, а не из
  `git archive`; идентичность — его sha256 в `verification/binaries.sha256.txt` и в `manifest.json` Windows.

## 9. Не выполнено и ограничения

| Область | Статус |
| --- | --- |
| macOS живой прогон этапа (окно `m1`) | **NOT RUN**: требует `sudo` пользователя |
| Физические NIC (Linux, Windows, macOS) | **NOT RUN** |
| Живой Ctrl-C на Windows | **NOT RUN**: консольное событие по ssh не доставить; обработчик покрыт юнит-тестами, живые прерывания сняты на Linux (`sc02`, `sc05`, `sc06`, `o14`–`o16`) |
| Второй адаптер на Windows и macOS | не снимался вживую; покрыт тестами с fake-бэкендом |
| Studio offline-тесты этапа | идут в Studio CI PR (**PENDING**, см. раздел 5) |
| Баннеры, redis, certs, ротация, IPv6, VLAN, туннели | не цели этапа |

Отличия от C, вошедшие в README, перечислены в `rmasscan/README.md` («Отличия от masscan»); источники: спека §8 и решения
Р1–Р9. Studio этим этапом не менялась.
