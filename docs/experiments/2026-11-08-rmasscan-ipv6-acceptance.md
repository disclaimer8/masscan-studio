# rmasscan: IPv6 (TCP SYN поверх IPv6, NDP, смешанный скан IPv4 и IPv6, записи IPv6 в выводе и `--readscan`), приёмка (итоговый отчёт этапа)

Дата: 2026-11-12 (r2; окна 2026-11-12 08:03Z – 08:56Z; после слияния с main набор r3 на `0ce2a9e8`, окна 19:39Z – 20:29Z,
раздел 11). Ветка `feat/rmasscan-ipv6`, база `fdd18b37` (слияние PR #55, протоколы IPv4;
`git merge-base main HEAD`). Документ фиксирует измеренное и открытое. Статусы: PASS / FAIL / INVALID / NOT RUN / OPEN / PENDING,
никогда не повышаются. Сырые данные:
[`2026-11-08-rmasscan-ipv6-acceptance-raw/`](2026-11-08-rmasscan-ipv6-acceptance-raw/) (корневой
[README](2026-11-08-rmasscan-ipv6-acceptance-raw/README.md) и `MANIFEST.sha256`; у каждого из шести каталогов свои
`manifest.json`, `verdict.json` и `runs/<tag>/`; логи сборок, тестов, `privacy-scan` и состояния стенда гостя лежат в
`verification/`). Спека: [design](../superpowers/specs/2026-11-08-rmasscan-ipv6-design.md) (решения Р1–Р5, отличия от C в §8,
поправки по итогам реализации в §9). План: [plan](../superpowers/plans/2026-11-08-rmasscan-ipv6.md), задача 7. Родственные
документы: [приёмка протоколов IPv4](2026-11-08-rmasscan-protocols-ipv4-acceptance.md) (образец формата),
[перечень готовности](2026-10-24-rmasscan-readiness.md).

## 1. Итог и границы

- **После слияния с main (r3, раздел 11).** PR #58 конфликтовал с main (интеграция Studio, PR #54 и #57, меняла тот же код
  обнаружения). Ветка слила `origin/main` `d2a6603f` (коммит слияния `ffb8d6c1` плюс коммит только с тестом), и все шесть окон
  прогнаны заново на C r3 = `0ce2a9e8`: IPv6 **PASS 4/4**, протоколы **PASS 6/6**, управление сканом **PASS 7/7**, вывод
  **PASS 18/18**, автоопределение Linux **PASS 13/13** и Windows VM **PASS 10/10**, `safety_trips` пуст, ни одной замещённой
  попытки; сырые данные [`2026-11-12-rmasscan-ipv6-postmerge-raw/`](2026-11-12-rmasscan-ipv6-postmerge-raw/). Разделы 1–10
  ниже описывают набор r2 на `e9eaebeb` (до правок итогового ревью и до слияния) и не переписаны.
- Все шесть живых окон набора r2 сняты на одном коде C = `e9eaebeb`. Набор r1 на `cbcffe72` остановлен первым же окном
  (`linux-ipv6-r1`, INVALID 3 из 3) и замещён; три причины и три правки лаборатории в разделе 5, продукт между r1 и r2 не менялся.
- Живая приёмка IPv6 на Linux: `linux-ipv6-r2` **PASS 4/4** (манифест и кейсы `v01`–`v03`: автоопределение и NDP с TCP SYN по
  IPv6, смешанный скан IPv4 и IPv6, явный `--router-mac-ipv6`; 286 проверок); оракул — закреплённый C masscan `8e6b3b0`.
- Регрессии на Linux: протоколы `linux-protocols-r2` **PASS 6/6** (419 проверок), управление сканом `linux-scan-control-r2`
  **PASS 7/7** (359), вывод `linux-output-r2` **PASS 18/18** (759), автоопределение `linux-autodetect-r2` **PASS 13/13**
  (412); на Windows VM `windows-autodetect-r2` **PASS 10/10**.
- Во всех шести окнах `safety_trips` пуст.
- Офлайн-паритет вывода: 119 эталонов C (94 прежних воспроизведены без изменений, 25 новых сняты через оракул `8e6b3b0` на
  записях IPv6 типов 10 и 11 и на `--readscan` с фильтром по адресу IPv6).
- NOT RUN: Windows IPv6 (решение этапа, П14 спеки: на lab-NIC гостя `n2` IPv6 выключен исправлением стенда, гость не менялся), живое окно
  macOS (`m1`, нужен `sudo` пользователя) и цели link-local на macOS, физические NIC всех ОС, тесты Studio этого этапа локально
  (`studio/` этим этапом не менялся, `git diff fdd18b37 f089b071 -- studio` пуст, шлюз это Studio CI PR). Studio CI:
  заполняется при PR.
- Стенд никогда не заменяет физическую приёмку. IPv6 вживую снят только на Linux; окно Windows это регрессия автоопределения
  IPv4 (`w01`–`w08b`) на новом коде.
- Что живые окна не упражняли, см. раздел 6.

## 2. Закреплённые коммиты и чистота дерева

| Часть | Коммит | Привязка |
| --- | --- | --- |
| Код под живыми окнами (C) | `e9eaebeb0fe2024bdde29961892e122cd93ab901` (2026-11-12) | minipc и гость: полное дерево из `git archive C`, на госте затем `git init; git add -A`; home-pc: `rmasscan/` из `git archive C`; Mac (оркестратор и верификаторы): чистая рабочая копия на C. Release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, rustc 1.99.1 (`58cf8f9c3 2026-10-13`). HEAD ветки весь набор r2 стоял на C, рабочая копия чистая |
| Код продукта | `68c0e2e4` … `c1e76779` (задачи 1–6 и их правки): диапазоны IPv6 и `ipv6address_fmt`, смешанная индексация, TCP SYN поверх IPv6, NDP, записи 10 и 11, обнаружение IPv6 на трёх ОС | не менялся с `c1e76779` до `e9eaebeb`: `git diff --stat c1e76779 e9eaebeb -- rmasscan/crates ':!rmasscan/crates/rmasscan-lab'` пуст; **после окон продукт менялся**: правило подтверждения 1e9 в `validate` (`eba1492b`, затем `9dbbfd69`: исключение IPv6 подтверждает только переполнение от целей IPv6, R24) и отказ плана при MAC следующего хопа IPv6, равном MAC источника (`6d6b235a`, `ReadyPlan::new_cli`); ни одно живое окно эти пути не упражняет, их покрывают только офлайн-тесты (Mac на `f171465e`: 2153 прошли, 0 упали; minipc и гость прогнаны на `e9eaebeb`, до этих изменений);  бинарник `rmasscan` на minipc `479eaffe…` и в r1 (на `cbcffe72`), и в r2 |
| Лаборатория | `06227c14`, `0f48dfac`, `cbcffe72` (задача 7a: набор `ipv6`, `ipv6-verify`, общий `pair_verify.rs` для протоколов и IPv6); `1abae2aa`, `f346a66b`, `e9eaebeb` (правки задачи окон 7b, раздел 5) | `wire-lab.sh --suite ipv6`, `ipv6-suite`, `ipv6-verify`, `privacy-scan` (имена из кадров ICMPv6) |
| Evidence | `f089b071` (`test(cli): record IPv6 acceptance r2 at C on the Linux stand and the Windows VM`) | только `docs/experiments/2026-11-08-rmasscan-ipv6-acceptance-raw/` (в каталоге 1169 файлов, `MANIFEST.sha256` на 1168 записей; `shasum -a 256 -c --quiet MANIFEST.sha256` даёт rc 0) |
| Код под окнами r3 (после слияния с main) | `0ce2a9e8e9c1fec8e56655cef6b258c0cd0e5a54` (2026-11-12) | коммит слияния `ffb8d6c1` (родители `0e0bd100` и `origin/main` `d2a6603f`) плюс коммит только с тестом `0ce2a9e8`; сборки так же, как для r2; HEAD ветки весь набор r3 стоял на нём, рабочая копия чистая (раздел 11) |
| Evidence r3 | `f05e93df` | только `docs/experiments/2026-11-12-rmasscan-ipv6-postmerge-raw/` (1170 файлов, `MANIFEST.sha256` на 1169 записей, `shasum -a 256 -c --quiet MANIFEST.sha256` даёт rc 0) |
| База | `fdd18b37` | без rebase; от базы до `f089b071` 19 коммитов (`git rev-list --count fdd18b37..f089b071`), первый из них `6685610e` (документ и план этапа) |

Windows: `manifest.json` и `deploy/preflight-*.json` несут `code_commit`, `orchestrator.build_commit` и
`orchestrator.git_commit`, все равные C, `git_dirty: false`.

## 3. Результаты шести окон (все на C = `e9eaebeb`)

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-ipv6-r2` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + IPv6 на паре veth (ULA `fd00:198:18::/64`, шлюз link-local пира, постоянные соседи с обеих сторон), ответчик лаборатории с `--tcp6-ips`, C-оракул masscan 8e6b3b0 | `v01`–`v03` (+ манифест) | **PASS 4/4** | 08:03:15Z–08:05:25Z | `2d9e05c79df46a20323c31552179af0f25a5dc51dc0a04ab8f0cc618e8c60847` |
| `linux-protocols-r2` | тот же стенд без IPv6, `--suite protocols` (+ `icmp_ratemask=0` в netns пира, ответчик UDP и SCTP) | `p01`–`p05` (+ манифест) | **PASS 6/6** | 08:05:43Z–08:09:05Z | `3146bbf191996e8a6db4427cba54f1ea8bf1faa37fe387bd16f09fb35676cf7e` |
| `linux-scan-control-r2` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7** | 08:09:30Z–08:11:43Z | `1695d5cb6a56afaa5342a959e220f8fa5a3c9a5d66c9368247cd1b285cc4ff1d` |
| `linux-output-r2` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18** | 08:11:56Z–08:17:11Z | `b215ab08d6514f9e7627b38e9954a313496fb8dac0c19992f2e4abe179366e8a` |
| `linux-autodetect-r2` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13** | 08:17:37Z–08:19:12Z | `4bd47b92928998ab702e0f9f6188cfed4ac6a5c1131605ba1afdfe8da1fdb0d7` |
| `windows-autodetect-r2` | home-pc, QEMU-гость Windows 11, стенд `n2`, Npcap Admin-only, исправленный стенд гостя (раздел 8) | `w01`–`w08b` (+ манифест) | **PASS 10/10** | 08:25:24Z–08:56:22Z | `bc26c06efa84a86dd08443aa5289ec39331d512c283609f8979d91a3aeaa5a06` |

Хэши этой таблицы пересчитаны `shasum -a 256 <каталог>/verdict.json` в каталоге сырых данных и равны корневому README
сырых данных. Вердикты вынесли офлайн-верификаторы `ipv6-verify`, `protocols-verify`, `scan-control-verify`, `output-verify`,
`autodetect-verify`; для Windows `windows-verify` передаёт каталог целиком в `autodetect-verify`. После копии в репозиторий хэши
каждого прогона проверены повторно, и верификатор копии дал тот же `verdict.json` байт в байт
(`verification/rederive-on-committed-copy.txt`). Для этого отчёта `ipv6-verify` и `protocols-verify` из отладочной сборки
HEAD ветки на Mac перевыпустили вердикты `linux-ipv6-r2` и `linux-protocols-r2` ещё раз: оба хэша равны таблице. Числа проверок
регрессионных верификаторов те же, что на прежнем этапе: протоколы 419, управление сканом 359, вывод 759, автоопределение 412;
у IPv6 286, у Windows 299.

### 3.1. Что проверено в `linux-ipv6-r2`

Стенд: запечатанный стенд autodetect (`wl-scan`/`wl-peer`, `198.18.0.0/24`, без uplink), в котором `wire-lab.sh --suite ipv6`
только для этого набора и только на паре veth и `lo` двух netns включает IPv6 (строки `disable_ipv6=1` для всех наборов те же
и идут первыми): без DAD (`accept_dad=0`, адреса `nodad`), без RS/RA (`accept_ra=0`, `router_solicitations=0`), без
форвардинга, link-local по EUI-64. Сканер `fd00:198:18::1/64`, пиры `fd00:198:18::2`–`::5/64`; IPv6-маршрут сканера по умолчанию
через link-local пира `fe80::aa:ff:fe00:2`; постоянные соседи IPv6 с обеих сторон (в том числе оба link-local, правка
`1abae2aa`); ожидание 3 с. Печать `capture isolation --mode ipv6` (`isolation.json` и `isolation-post.json` каждого кейса)
подтверждает ровно это: настройки veth, адреса (ни одного tentative), маршруты main-таблицы (у сканера ровно
`default via fe80::aa:ff:fe00:2`, `fd00:198:18::/64`, `fe80::/64`; у пира два последних; ядро 7.0 других маршрутов в main не
показало), постоянных соседей и `ip -6 route get 2001:db8::1`. Ответчик лаборатории слушает TCP 80 и 8080 и на каждом
IPv6-адресе пира (`--tcp6-ips`); закрытые порты получают RST ядра пира; на NS отвечает ядро пира.

Оракул — закреплённый C masscan `8e6b3b0` с argv rmasscan плюс `--adapter-ip fd00:198:18::1` (C не берёт ULA источником,
`rawsock-getip6.c:68–71`) и `--router-mac-ipv6 02-aa-00-00-00-02` (C ищет роутер RS/RA, пир Linux RA не шлёт). Цели IPv6 в
скобках (`[a]-[b]`, обе программы принимают). Argv всех кейсов: `<цели> -p80,81 [-oX <файл>] --show open,closed --seed 1 --rate 100
--wait 3 --source-port 40000`. На каждый документ кейса прогон rmasscan и прогон оракула, у каждого свой захват пира и свой
перезапущенный ответчик.

- `v01_ndp_and_tcp6_syn` (`[fd00:198:18::2]-[fd00:198:18::5]`, `-oJ` и `-oB`): rmasscan сам нашёл интерфейс, источник и шлюз
  (`[+] interface = veth-a (detected: route to [fd00:198:18::2])`, `source-ip = [fd00:198:18::1] (detected)`, `router-ip =
  [fe80::aa:ff:fe00:2] (interface default gateway)`) и разрешил MAC роутера по NDP: на проводе ровно одна NS резолвера (с
  `fd00:198:18::1` на `ff02::1:ff00:2`, цель `fe80::aa:ff:fe00:2`, 86 байт) до первого зонда, столько же, сколько в `(ndp: 1
  requests`; на неё ровно одна NA пира в форме Linux (флаги S|O, TLLA). Восемь SYN по IPv6 (78 байт) побайтно равны плану
  продукта и SYN оракула; записи `-oJ` и `-oB` (типы 10 и 11) равны ответам своего провода и записям C (кроме TTL IPv6, ниже).
- `v02_mixed_v4_v6` (`198.18.0.2-198.18.0.5,[fd00:198:18::2]-[fd00:198:18::5]`, `-oB` и `-oL`): один скан обеих семей, один
  интерфейс и две строки источника (П7), ARP (1 who-has) и NDP (1 NS). Инвариант v4 (П14): каждый IPv4-зонд побайтно равен
  зонду плана только IPv4 того же адреса и порта, ни один не потерян; IPv6 занимает нижние перемешанные индексы
  (`shuffle((i + rate) mod range) < range_ipv6`, `main.c:258–260`, `:325–331`), IPv4-зонд на позиции i равен цели плана
  только IPv4 с индексом `x − range_ipv6`. Записи `-oB` четырёх типов (6, 7, 10, 11) и `-oL`.
- `v03_explicit_router_mac_ipv6` (как v01 плюс `--router-mac-ipv6 02-aa-00-00-00-02`, `-oJ`): ни одной NS сканера на проводе,
  `[+] router-mac-ipv6 = 02-aa-00-00-00-02 (given)`, каждый IPv6-зонд на заданный MAC.
- У каждого шага rmasscan: код 0, на stderr только строки `[+]` и формы строки статуса, `[+] finished: Completed, sent N,
  replies R, open O` равно зондам и различным ответам на проводе. У каждого шага оракула в stderr `[-] Passed the wait window
  but still running, forcing exit...`, подвала у его файла нет, это ожидаемо, как на стенде протоколов.
- Кадры стороны сканера, не являющиеся зондами, все отнесены к названным классам (`unexplained` 0 в каждом из 10 шагов) и не
  превышают границ (`notes.scanner_frames`): NS резолвера 1 в каждом шаге rmasscan `v01` и `v02` (граница 10 =
  `NDP_TIMEOUT / NDP_INTERVAL`), 0 в `v03` и у оракула; who-has 1 в шагах `v02` (границы 10 и 12); RST на SYN-ACK: ядро
  сканера по одному на SYN-ACK у rmasscan (4, в `v02` 8), у оракула ещё собственный RST C на каждый различный SYN-ACK (8 из 8,
  в `v02` 16 из 16); новый класс `rst_to_rst` (раздел 5) у оракула 4 из 4 (`v02` 8 из 8), у rmasscan 0 из 0; NA на NS пира 0
  (пир не спрашивал).
- Шум ядер (`STAND_NOISE`: MLD, RS, RA, NS DAD, NS пира о сканере, NS ядра сканера о пире; граница 0): ни одного кадра ни в одном
  шаге. Ожидания 3 с хватило, чтобы отчёты MLD о новых группах кончились до первого захвата; ядра не слали NS, потому что все
  соседи постоянные. В r1 именно здесь были кадры NUD для выученных link-local (раздел 5).
- Порядок записей: в каждом из 10 шагов `notes.reply_order_swaps` = `{"pairs": 0, "largest_gap_us": null}`; записи rmasscan
  совпали с документом C как мультимножество и в том же порядке во всех пяти документах (`notes.record_order_vs_c`).
- Отклонения от C (решения контролёра, не дефекты), у каждого своя проверка на стороне оракула, `notes.deviations`:
  `ndp-ns-not-rs` (П5; NS у оракула 0, у rmasscan по 1), `oracle-source-given` (0 IPv6-зондов оракула не с
  `fd00:198:18::1`), `ipv6-ttl-not-compared` (в `v01` 16 записей C с TTL, все не равны hop limit; в `v02` 8, из них 1 не равна;
  в `v03` 4 из 4), `families-one-interface` (П7; `v02`: у оракула оба семейства на одном линке стенда, по 8 зондов). TTL записей
  IPv6 у rmasscan это hop limit ответа (64), он проверен по своему проводу.
- `responder.json` всех 10 шагов: `{"exited_with": null, "killed_by_signal": null, "state_unknown": null, "stderr": ""}`.
  `ipv6-stack.json` всех трёх кейсов: настройки стенда, ни одного tentative и dadfailed адреса.

### 3.2. Регрессии

- `linux-protocols-r2` повторяет на C каталог `linux-protocols-r4` приёмки протоколов IPv4 (тот же стенд, та же таблица кейсов,
  тот же верификатор): `p01`–`p05` PASS, 419 проверок. Верификатор протоколов на этом этапе стал общим кодом с IPv6
  (`pair_verify.rs`, П14); окно показывает рефакторинг на живых данных, а перекрёстная проверка в разделе 5 даёт
  независимое свидетельство, что вердикты не изменились. Порядок: в `p05` у оракула одна пара записей в обратном порядке внутри
  окна 50 мкс (`largest_gap_us` 6), в остальных 15 шагах пар нет.
- `linux-scan-control-r2`, `linux-output-r2` и `linux-autodetect-r2` повторяют на C каталоги `-r4` (тот же стенд, те же таблицы
  кейсов и верификаторы): все PASS с теми же числами проверок.
- `windows-autodetect-r2` повторяет `windows-autodetect-r4` прежнего этапа на C. Код обнаружения на Windows этим этапом менялся
  (задача 5: `GetBestRoute2(AF_INET6)`, адреса `AF_INET6`); окно проверяет, что путь IPv4 тот же. Живого IPv6 на Windows нет
  (раздел 10).

## 4. Тесты и сборки на C

| Хост | Результат |
| --- | --- |
| minipc (Linux 7.0.0-38-generic, tcpdump 4.99.6, iproute2 6.19.0) | `RMASSCAN_EXPECT_DEFAULT_ROUTE=1 cargo test --locked --workspace --no-fail-fast`: **2016 passed, 0 failed**, 14 ignored, 51 строка `^test result:`; `cargo clippy --locked --workspace --all-targets -- -D warnings`: 0. Оба под `nice -n 19`: шли одновременно с окном Windows, ssh которого идёт через minipc. Первая попытка тестов упала до тестов на компоновке (раздел 9) |
| гость (Windows 10.0.26300, elevated, Npcap 1.90 Admin-only) | тот же тест: **1911 passed, 0 failed**, 34 ignored, 51 строка; clippy 0; `rmasscan.exe` со статическим CRT и `/DEPENDENTLOADFLAG:0x800` (`0800 Dependent Load Flag` OK) |
| home-pc (Linux 7.3.0-10-generic, QEMU 10.2.1) | `rmasscan-lab`, `deploy-manifest` для C |
| Mac (macOS 27.2) | `cargo test --locked --workspace --no-fail-fast` на C: **2144 passed, 0 failed**, 23 ignored, 51 строка (`verification/mac-test-ws-summary.txt`); clippy 0; `cargo fmt --check` 0; `cargo check --locked` в `studio/` 0. `sudo` не использовался; живых кадров с Mac нет |

**Число строк `test result`: 51, не 52.** В сырых данных (`mac-test-ws-summary.txt`, `minipc-gate-exits.txt`, `guest-test-ws.log`,
README) стоит «52 строки». Это число по нестрогому `grep -c 'test result'`: оно ловит ещё имя теста
`test result_batches_respect_event_batch_limit ... ok` (строка 933 лога minipc, строка 931 лога гостя). Настоящих строк
`^test result:` по 51 на каждом хосте (`grep -c '^test result:'` по `minipc-test-ws.log` и `guest-test-ws.log` и по сводке Mac), суммы
passed и failed верны (2144/0, 2016/0, 1911/0). Каталог сырых данных хэширован (`MANIFEST.sha256`) и не правится, поэтому «52»
остаётся там как есть. На прежнем этапе та же ошибка на единицу (51 вместо 50).

sha256 бинарников: `verification/binaries.sha256.txt` (lab minipc `6586c0b2…`, `rmasscan` minipc `479eaffe…`, lab home-pc
`70e9c667…`, `rmasscan.exe` гостя `42f7379a…`, lab Mac `707d5bbf…`, оракул `8afc8ec8…`).

## 5. r1 INVALID, три правки лаборатории и перекрёстная проверка рефакторинга

Набор r1 (на `cbcffe72`, CI зелёный на трёх ОС; факты и хэши в `verification/superseded-attempts.txt`) остановило правило
остановки на первом же окне: `linux-ipv6-r1` дало INVALID 3 из 3 кейсов (`v01`, `v02`, `v03`), PASS у манифеста, вердикт
`aed5cf52…`. Собственные проверки rmasscan прошли; шаг rmasscan `v03` `json` получил INVALID только от шума стенда (причина 3). Три причины, ни одна не продуктовая:

1. **Собственный RST C на RST закрытого порта** (`f346a66b`, класс `rst_to_rst`). C сбрасывает каждый различный ответ, прошедший
   cookie и дедупликацию, и RST стенда тоже, и SYN-ACK (`main.c:1048–1101`: `TCP_IS_SYNACK || TCP_IS_RST`, затем
   `tcp_send_RST`), кадром своего шаблона (78 байт по IPv6, окно 1200, опция MSS). Класс `rst_to_syn_ack` называл только половину
   SYN-ACK, и каждый шаг оракула давал «unexplained» (`v01` 4, `v02` 8, `v03` 4). Правка называет новый класс: кадр с адреса
   сканера с флагами TCP ровно `0x04` и seq, равным ack RST стенда, не больше одного на различный RST стенда на шаге оракула
   (вживую 4 из 4, `v02` 8 из 8), у rmasscan 0 (тот же кадр там FAIL). Только оракул; верификатор протоколов не тронут (на его
   стенде нет закрытого порта TCP). *Почему это не прячет продуктовый дефект:* класс не ослабляет проверку rmasscan и не
   разрешает оракулу ничего вне формы кадра C.
2. **32-битный TTL записи IPv6 в `-oJ` C** (`e9eaebeb`, `IPV6_DOC_RULE`). C печатает `"ttl": %u` от `ip_ttl`, который он задаёт
   только для IPv4 (`proto-preprocess.c:127`; `out-json.c:51`), поэтому у записи IPv6 стоит устаревшее 32-битное число (вживую
   320995840 и 2497958912); `-oB` хранит младший байт (`out-binary.c:135`). Разборщик ждал байт и называл документ оракула
   «не разобранным» (`v01`, `v03`, шаг `oracle-json`). Правка разбирает документы оракула с TTL до `u32` для записей IPv6 (названо
   в имени проверки «an IPv6 record's ttl may be any 32-bit value … ipv6-ttl-not-compared» и в `notes.deviations`); TTL в документе
   rmasscan остаётся байтом, большее значение это его FAIL, значение с C не сравнивается. *Почему это не прячет продуктовый
   дефект:* правило касается только документов оракула, и продукт пишет настоящий hop limit, который проверен по своему проводу.
3. **Выученные link-local соседи на стенде** (`1abae2aa`). После окна `topology-after` показал `fe80::aa:ff:fe00:2` REACHABLE у
   сканера и `fe80::aa:ff:fe00:1` REACHABLE у пира: ядро сканера выучивает роутера, когда `ip -6 route get` пробует маршрут по
   умолчанию, и NUD позже слал unicast NS внутри шагов `v03`. Правка: оба link-local адреса постоянные соседи, а печать стенда
   (`check_ipv6_side`) их требует (стенд без них отказывает до первого кадра). *Почему это не прячет продуктовый дефект:* правка
   ужесточает печать стенда и убирает шум ядер, который шёл в `STAND_NOISE` (граница 0); NDP rmasscan по-прежнему видна на
   проводе (число NS равно числу в строке `ndp:`).

Каждая правка это отдельный коммит с офлайн-тестом в живой форме, RED ровно той проверкой, что упала вживую, затем GREEN
(RED `f346a66b` ревью воспроизвело; RED `1abae2aa` и `e9eaebeb` по git не проверяются: тест `e9eaebeb` зовёт `parse_doc_of`,
которой нет у его родителя, значит RED шёл на другой версии теста; r1 в репозиторий не закоммичен). Верификатор C выносит r1: `v01`, `v02` PASS, `v03` INVALID только из-за шума NUD (причина 3),
вердикт `a688a9f4…`. Бинарник продукта в r1 и r2 один (`479eaffe…`): вся разница между r1 и r2 лабораторная.

**Перекрёстная проверка рефакторинга протоколов (П14).** Задача 7a вынесла общий код протоколов и IPv6 в `pair_verify.rs` с
требованием, чтобы вердикты протоколов остались байт в байт. Проверка на базе этапа `fdd18b37` (до рефакторинга) из чистого
`git archive` в отдельном каталоге:

```
git archive fdd18b37 | tar -x -C $S/src
cd $S/src/rmasscan && CARGO_TARGET_DIR=$S/tgt cargo build --locked --release -p rmasscan-lab
$S/tgt/release/rmasscan-lab protocols-verify --dir <копия linux-protocols-r2> --out $S/out/linux-protocols-r2.json
$S/tgt/release/rmasscan-lab protocols-verify --dir <копия 2026-11-08-rmasscan-protocols-ipv4-acceptance-raw/linux-protocols-r4> --out $S/out/linux-protocols-r4.json
```

`rmasscan-lab` базы `fdd18b37` (сборка на Mac, sha256 `13c523609ea1782ffd38f5c0828694a4981ac62316d69a47ad8315f1458339ce`) выносит
`linux-protocols-r2` вердикт `3146bbf191996e8a6db4427cba54f1ea8bf1faa37fe387bd16f09fb35676cf7e` (равен закоммиченному `verdict.json`,
PASS 6/6) и закоммиченному `linux-protocols-r4` приёмки протоколов вердикт `ae05acb5fbb6224ad27ac25adddb7270f108d6705291dfacef1de81c0e3b1a8a`
(равен его `verdict.json`, пересчитан `shasum`, PASS 6/6). То же дают верификаторы `cbcffe72` и C. Эта проверка выполнена в задаче 7b
вне `verification/` (там записан только повторный вердикт верификатором C), поэтому команды и хэш бинарника записаны здесь.

## 6. Что живое окно не упражняло

Отклонения rmasscan от C, названные в верификаторе, живьём сработали так, как показано в разделе 3.1; всё остальное из списка
названных отличий README (§8, блок «IPv6») стенд не упражнял и доказывается офлайн-тестами, векторами C и сверкой с кодом и
бинарником C (`--echo`, `-sL`, `--readscan`).

- Ответ rmasscan на NS пира во время скана (NA): `NA на NS пира` 0, пир ни разу не спрашивал; кодек и поведение NA (RFC 4861
  §7.1, hop limit 255, `payload_length` 32, NS от `::` без ответа) покрыты офлайн-тестами.
- Нарушения RFC 4861 во входящих NS и NA (hop limit не 255, code не 0, неверная сумма, чужой адрес назначения), кадры NDP с
  заголовками расширения, Hop-by-Hop и Fragment во входящих кадрах TCP, `--badsum` по IPv6, `DLT_NULL`: стенд таких кадров не
  шлёт и не использует.
- Возобновление (`--resume`) заданий с IPv6, паузу с `paused.conf` для IPv6: точный остаток потока доказан тестами, живого окна
  нет.
- `--readscan` с записями IPv6: офлайн (эталоны C и тесты); живой только чтение собственных `-oB` окон.
- Отказ смешанного скана, у которого семейства идут через разные интерфейсы (П7), `NoGateway6`, macOS с VPN: офлайн-тесты.
- Цели link-local и адрес источника link-local, цели за маршрутизатором: на стенде все цели on-link (хоп IPv6 это link-local
  роутер интерфейса по умолчанию), шлюз маршрута к цели за маршрутизатором вживую не снят.
- Окно порядка в 50 мкс: в r2 ни один документ rmasscan не записал пару в обратном порядке (у оракула одна пара в `p05`,
  6 мкс).
- Пир SCTP это ответчик лаборатории, а не стек ядра (как в приёмке протоколов).
- Явные `--router-ip` IPv6 (`router-ip = [..] (given)`) и `--adapter-ip` IPv6 у rmasscan: оракулу `--adapter-ip` дан, а rmasscan
  определяет источник сам; заданный явно адрес IPv6 вживую у rmasscan не снимался.

## 7. CI

Зелёный CI на точном HEAD ветки и Studio CI PR: **PENDING**, заполняется при PR. Итоговое ревью ветки: заполняет контролёр при
слиянии. Известно сейчас:

- На C `e9eaebeb`: `rmasscan` 43179515165 success (все ОС), `language-guard` 43179514999 success.
- На коммите evidence `f089b071`: `language-guard` 43253741014 success. Рабочий процесс `rmasscan` на нём не запускался: фильтр
  путей `.github/workflows/rmasscan.yml:17–25` (`rmasscan/**` и сам файл), а `f089b071` менял только `docs/experiments/`
  (`git diff --name-only e9eaebeb f089b071 | grep -v '^docs/experiments/'` пусто). Код на `f089b071` равен коду C.
- «Ещё раз на итоговом HEAD» (повтор полных ворот) локально не выполнялся: код тот же, различаются только документы. Документы
  этой задачи лежат под `rmasscan/` и запустят `rmasscan` при PR.

## 8. Стенд Windows: исправление гостя и обязательный `privacy-scan`

Исправление стенда гостя прежнего этапа (только выделенная VM `n2`: mDNS, LLMNR и Delivery Optimization выключены; на lab-NIC
выключены IPv6 и NetBIOS; снимок применения и рецепт отката лежат в
`2026-11-08-rmasscan-scan-control-acceptance-raw/verification/`) для этого окна не применялось заново и не откатывалось, а только
проверялось (pwsh 7, скрипт-файл только для чтения). Значения прочитаны дважды: до `vm-lab up` (08:17:18Z) и после перезапуска VM для
окна (08:24:23Z, `LastBootUpTime` 08:23:36Z). Каждая строка `reg` и `nic` обоих чтений равна снимку применения строка в строку
(`verification/guest-stand-check-r2.txt`). IPv6 на lab-NIC гостя остаётся выключенным (П14), поэтому окна Windows IPv6 нет.
Результат: ни в одном из 9 `peer.pcap` прогонов `windows-autodetect-r2` нет ни UDP-, ни IPv6-кадра; `privacy-scan` не нашёл ни
одного кадра mDNS, LLMNR или NBNS ни в одном захвате шести каталогов. Настройки остаются применёнными на госте; когда их откатить,
решает пользователь.

`rmasscan-lab privacy-scan --dir --forbid` (сборка C на Mac) прогнан по копии каждого каталога, по `verification/` и по всему
каталогу сырых данных (с `README.md`) с девятью токенами, каждый длиной от 4 байт: имя хоста Mac (`hostname`, `LocalHostName`,
`ComputerName`), имя учётной записи Mac и две её части, имена хостов minipc и home-pc, прежнее имя профиля Windows на home-pc. Все
девять дали **0 совпадений** во всех шести каталогах, в `verification/` и во всём каталоге (rc 0). Токен короче 4 байт
`privacy-scan` отказывает (rc 2, проверено и записано): учётные записи minipc и home-pc и полное имя хоста гостя двухсимвольные,
имена гостя покрывает проход по DNS-форме, который с этого этапа печатает и имена из кадров ICMPv6, которые их несут (DNSSL в RA,
Node Information); таких кадров нет. Положительный контроль (файл с токеном № 5) даёт попадание. Дополнительно `grep -ral` по
путям домашних каталогов и префиксу домашней сети во всём каталоге: 0 файлов; пословный `grep -ralwE` из `rmasscan/docs/rust-lab.md`
по всем именам, в том числе коротким: один файл, `linux-output-r2/runs/o03_ndjson/peer.pcap`, где двухсимвольная учётная запись
совпала с байтами `61 31` номера последовательности TCP (случайное совпадение в данных кадра, просмотрено глазами и записано в
README сырых данных). Вывод: `verification/privacy-scan.txt`. Файлы этого отчёта и остальные документы этой задачи прошли `privacy-scan` с теми же ролями токенов, кроме № 7
(прежнее имя профиля Windows на home-pc не удалось прочитать, взято нынешнее): 0 совпадений, rc 0; положительный контроль даёт попадание.

## 9. Отклонения

- `cargo test` шёл с `--no-fail-fast`; экспорт гостя и minipc без `.git`, перед тестами `git init; git add -A`.
- Окно Windows (оркестратор на Mac, ssh через minipc как jump-хост) шло после окон Linux; тесты и clippy на minipc шли
  одновременно с ним под `nice -n 19`. Стенды разные: на minipc в это время шли только тесты и ssh-трафик управления окна
  Windows. Сборка и тесты гостя шли до окна Windows, при снятом `n2`. Mac был вне домашней сети: всё к home-pc и гостю шло через
  minipc (jump-хост).
- Первая попытка тестов на minipc упала до тестов на компоновке: компоновщик получил SIGBUS (`ld terminated with signal 7`),
  потому что `/tmp` (tmpfs 7,5 ГБ) был занят на 80 % каталогами экспорта оператора. Каталоги r1 и сборки окон удалены (их evidence
  забраны), тесты повторены в новом каталоге с отдельным target (результат в разделе 4). Это среда, не код.
- Оркестратор на Mac собран из чистой рабочей копии на C с уже существующим каталогом target вне репозитория (не из `git archive`);
  идентичность это его sha256 в `verification/binaries.sha256.txt` и в `manifest.json` Windows.
- id набора Windows `ipv6-windows-autodetect-r2`: на home-pc в `~/winvm/t4-ev` уже лежал пустой каталог прежнего этапа с именем
  `windows-autodetect-r2`, новый id его не трогает. Каталог evidence называется `windows-autodetect-r2`.
- Служба w32time на госте после перезапуска была остановлена (тип запуска Manual); оператор её запустил для `w32tm /resync`, как в
  прежних этапах. Это не настройка исправления стенда.
- Одна команда на госте шла встроенной строкой: `pwsh -Command Get-FileHash` (только чтение хэша, ничего не менялось), хотя
  правило для гостя это только `-File` со скриптом. Остальные команды на госте шли скриптами. В README сырых данных этого нет
  (только в записях хода задачи 7b); сырые данные не правились.
- Число «52 строки `test result`» в сырых данных неверно, строк 51 (раздел 4).
- Часть фактов r1 в репозитории не лежит: r1 не закоммичен (описан в `superseded-attempts.txt`), а RED-прогоны правок `1abae2aa` и
  `e9eaebeb` проверить по git нельзя (раздел 5).
- Перекрёстная проверка рефакторинга протоколов (П14) выполнена вне `verification/` (раздел 5).

## 10. Не выполнено и ограничения

| Область | Статус |
| --- | --- |
| Windows IPv6 вживую | **NOT RUN**: IPv6 lab-NIC гостя выключен исправлением стенда (П14), гость без согласия пользователя не меняется; обнаружение IPv6 на Windows покрыто офлайн-тестами и CI |
| macOS живой прогон этапа (окно `m1`) и цели link-local на macOS | **NOT RUN**: требует `sudo` пользователя; link-local цели на macOS не проверены вовсе; после слияния с main поиск маршрута IPv6 на macOS (`rt_get6`) идёт через ограниченный обмен PF_ROUTE main, вживую он тоже не снимался (раздел 11) |
| Физические NIC (Linux, Windows, macOS) | **NOT RUN** |
| Продукт после окон: правило 1e9 в `validate` и проверка MAC хопа IPv6 в плане | живыми окнами **не упражнялись**: r2 шёл на `e9eaebeb`, до `eba1492b` и `6d6b235a`; r3 шёл на `0ce2a9e8`, где этот код есть, но ни одно окно его не упражняет (нет скана больше 1e9 адресов, MAC хопа IPv6 не равен MAC источника); покрыты офлайн-тестами `ipv6_exclude_confirms_only_an_overflow_the_ipv6_targets_cause` и `cli_plan_refuses_an_ipv6_next_hop_mac_equal_to_the_source_mac`; Mac 2153/0 на `f171465e`, на `0ce2a9e8` Mac 2201/0, minipc 2084/0 и гость 1973/0 |
| Studio `cargo xtask test` этого этапа | r2: **NOT RUN** локально (`studio/` не менялся); r3: шаг «Offline contracts» `studio.yml` прогнан на Mac на `0ce2a9e8`, rc 0, 484/0 (раздел 11); упаковка `cargo xtask build` и шаги только Linux и только Windows: **NOT RUN** локально; Studio CI: заполняется при PR |
| IPv6 за маршрутизатором, `--resume` IPv6 и ответ NA вживую | не снимались (раздел 6), покрыты офлайн-тестами |
| Не-TCP протоколы по IPv6 (UDP, SCTP, ICMP Echo, ARP-скан), баннеры, VLAN, туннели | не цели этапа; UDP, SCTP, `I:` и `--arp` с целью IPv6 отказывают (README, блок «IPv6») |

Отличия от C, вошедшие в README, перечислены в `rmasscan/README.md` («Отличия от masscan», блок «IPv6»); источники: спека §8 и её
раздел «§9 Изменения по итогам реализации» (П1–П14). Studio этим этапом не менялась.

## 11. После слияния с main (r3)

PR #58 конфликтовал с main: после базы этапа `fdd18b37` в main вошла интеграция Studio (PR #54 и #57, Codex), которая
меняла тот же код обнаружения rmasscan. Ветка слила `origin/main` без rebase (решение Р25), и весь набор окон прогнан ещё раз
на результате слияния. Сырые данные набора r3 лежат в отдельном каталоге
[`2026-11-12-rmasscan-ipv6-postmerge-raw/`](2026-11-12-rmasscan-ipv6-postmerge-raw/) (корневой
[README](2026-11-12-rmasscan-ipv6-postmerge-raw/README.md), `MANIFEST.sha256`, `verification/`); каталог r2
`2026-11-08-rmasscan-ipv6-acceptance-raw/` хэширован и не менялся.

**Коммиты.**

| Часть | Коммит | Что это |
| --- | --- | --- |
| Код под окнами r3 (C) | `0ce2a9e8e9c1fec8e56655cef6b258c0cd0e5a54` (2026-11-12) | коммит слияния `ffb8d6c1` (родители `0e0bd100`, ветка после итогового ревью этапа, и `d2a6603f`, `origin/main`) плюс один коммит только с тестом (`0ce2a9e8`: план Studio с картой доставки никогда не встречает цель IPv6). minipc и гость: полное дерево из `git archive C`; home-pc: `rmasscan/` из `git archive C`; Mac: чистая рабочая копия на C. Release, `CARGO_INCREMENTAL=0`, `RMASSCAN_LAB_BUILD_COMMIT=C`, rustc 1.99.1. HEAD ветки весь набор r3 стоял на C, рабочая копия чистая |
| Evidence r3 | `f05e93df` | только `docs/experiments/2026-11-12-rmasscan-ipv6-postmerge-raw/` (1170 файлов, `MANIFEST.sha256` на 1169 записей, `shasum -a 256 -c --quiet` даёт rc 0) |

**Что принёс main** (в `rmasscan/` 25 файлов, +3713/−155; как разрешены 11 конфликтных мест, сказано в сообщении
коммита слияния `ffb8d6c1`): наблюдение маршрутов Linux (`linux/route_observation.rs`); на macOS ограниченный по времени обмен PF_ROUTE
(`macos/route.rs`, `macos/ifinfo.rs`), через который после слияния идёт и поиск маршрута IPv6 `rt_get6` (один срок 1 с на весь
обмен, другой текст ошибки); наблюдение адаптеров и маршрутов Windows (`windows/sys/observation.rs`; в `windows/sys.rs` оно стоит
рядом с кодом IPv6 ветки); карта доставки IPv4 по целям в `ReadyPlan` (`destinations`, только у планов Studio: в
`ProbeCursor::load_one` карта касается только кадров IPv4, кадр IPv6 несёт `next_hop_mac_ipv6`); `network_plan.rs`,
`neighbours.rs`, усиление политики ARP (`arp_resolve.rs`, `InvalidPolicy`), идентичность задания с картой (`identity.rs`); в
лаборатории одно чтение часов в `vm-lab record-guest` (`vm_lab.rs`). `rmasscan/docs/rust-lab.md` слиянием не тронут, процедура
окон та же, что в r2. Бинарник продукта на minipc `541eabd8…` (в r2 `479eaffe…`: с тех пор в продукт вошли правки итогового
ревью этапа и код main). `studio/` равен main: `git diff origin/main..HEAD -- studio rmasscan/Cargo.lock rmasscan/deny.toml`
пуст.

**Шесть окон, все на C.**

| Каталог | Стенд | Кейсы | Вердикт | Окно (UTC) | sha256 `verdict.json` |
| --- | --- | --- | --- | --- | --- |
| `linux-ipv6-r3` | minipc, netns `wl-scan`/`wl-peer`, стенд autodetect + IPv6 на паре veth (ULA `fd00:198:18::/64`, шлюз — link-local пира, постоянные соседи с обеих сторон), ответчик лаборатории с `--tcp6-ips`, C-оракул masscan 8e6b3b0 | `v01`–`v03` (+ манифест) | **PASS 4/4**, `safety_trips` [] | 19:39:50Z–19:42:01Z | `87902aa705879cb29bf5873bf4751b3e5b0178215e4adf1912637fd53c0a325e` |
| `linux-protocols-r3` | тот же стенд без IPv6, `--suite protocols` (+ `icmp_ratemask=0` в netns пира, ответчик UDP/SCTP) | `p01`–`p05` (+ манифест) | **PASS 6/6**, `safety_trips` [] | 19:42:13Z–19:45:35Z | `abe525f1bab736145bdd79061cd38025ed9efc3c5b5bfe12a660e185a35b950b` |
| `linux-scan-control-r3` | тот же стенд, `--suite scan-control` (вторая пара veth) | `sc01`–`sc06` (+ манифест) | **PASS 7/7**, `safety_trips` [] | 19:45:53Z–19:48:06Z | `39746e75fc0aba49902390c9ff78f43eb518eb3c46619e165259d9936ff9a2c4` |
| `linux-output-r3` | тот же стенд, `--suite output` | `o01`–`o17` (+ манифест) | **PASS 18/18**, `safety_trips` [] | 19:48:24Z–19:53:40Z | `d93f60540b44e94862da8ff8b9f96188879af6b2f528a8a6cd14a124c59e1565` |
| `linux-autodetect-r3` | тот же стенд, `--suite autodetect` | `l01`–`l12` (+ манифест) | **PASS 13/13**, `safety_trips` [] | 19:53:59Z–19:55:33Z | `9e45233481687cc34344e55615e953a568590ea2035f6a048edf7a4b48fff0a5` |
| `windows-autodetect-r3` | home-pc, QEMU-гость Windows 11, стенд `n2` (мост/TAP/netns без uplink), Npcap Admin-only, исправленный стенд гостя (только прочитан, ниже) | `w01`–`w08b` (+ манифест) | **PASS 10/10**, `safety_trips` [] | 19:58:53Z–20:29:29Z | `1f7aa5d9eecb7d3557b31bcd68523cfe5bb3b497a419ceedc20c562e9bbb2866` |

Хэши пересчитаны `shasum -a 256 <каталог>/verdict.json` в каталоге сырых данных r3 и равны его README; верификатор Mac на C
выносит копии в репозитории те же `verdict.json` байт в байт (`verification/rederive-on-committed-copy.txt`). Числа проверок
те же, что в r2: IPv6 286, протоколы 419, управление сканом 359, вывод 759, автоопределение 412, Windows 299. Живые
формы IPv6 те же, что в разделе 3.1: в шагах rmasscan `v01` и `v02` одна NS резолвера (`ndp: 1 requests`) и одна NA пира на
неё, в `v03` ни одной NS; шум ядер 0 кадров в каждом из 10 шагов; `unexplained` 0; `reply_order_swaps` 0 во всех шагах IPv6;
отклонения сработали так же (`ipv6-ttl-not-compared`: 16, 1 из 8 и 4 из 4). Протоколы: у оракула в `p02` по одной паре
записей в обратном порядке внутри окна 50 мкс (10 и 2 мкс), у rmasscan пар нет.

Стенд гостя: исправление прежнего этапа не применялось заново и не откатывалось, а только прочитано дважды скриптом pwsh 7 (до
`vm-lab up`, 19:48:01Z, и после перезапуска VM для окна, 19:58:03Z); каждая строка `reg` и `nic` обоих чтений равна снимку
применения (`verification/guest-stand-check-r3.txt`). В 9 `peer.pcap` окна Windows нет ни UDP-, ни IPv6-кадра; на `eno1` 0 кадров
в каждом прогоне. Privacy: `privacy-scan` с теми же девятью ролями токенов, что в разделе 8, дал 0 совпадений в каждом из шести
каталогов, в `verification/` и во всём каталоге; пословный `grep` из `rust-lab.md` нашёл только случайные байты `61 31` одного
SYN-ACK пира в `linux-scan-control-r3/runs/sc04_packet_mods_and_pcap/mods/` (`scanner.pcap` и `peer.pcap`; младший байт порта
назначения и первый байт номера последовательности), это записано в README сырых данных r3 (`verification/privacy-scan.txt`).

**Ворота на C.**

| Хост | Результат |
| --- | --- |
| Mac (macOS 27.2.1) | `cargo test --locked --workspace --no-fail-fast`: **2201 passed, 0 failed**, 23 ignored, 51 строка `^test result:` (`verification/mac-test-ws-summary.txt`); clippy 0; `cargo fmt --check` 0; `cargo check --locked` в `studio/` 0; `scripts/language-guard.sh` PASS (14551 файлов); Studio `cargo xtask test` (шаг «Offline contracts» `studio.yml`: тесты, clippy, fmt; SQLite из brew, как в задании macOS) rc 0: **484 passed, 0 failed**, 2 ignored, 43 строки (`verification/mac-studio-xtask-test-summary.txt`) |
| minipc (Linux 7.0.0-38-generic) | `RMASSCAN_EXPECT_DEFAULT_ROUTE=1 cargo test --locked --workspace --no-fail-fast`: **2084 passed, 0 failed**, 14 ignored, 51 строка; `cargo clippy --locked --workspace --all-targets -- -D warnings`: 0. Оба под `nice -n 19` в свежем экспорте C со своим target (шли одновременно с окном Windows, ssh которого идёт через minipc); каталог окон удалён до этого, в `/tmp` (tmpfs) одновременно лежал один экспорт |
| гость (Windows 10.0.26300, elevated, Npcap Admin-only, `n2` снят) | `RMASSCAN_EXPECT_DEFAULT_ROUTE=1 cargo test --locked --workspace --no-fail-fast`: **1973 passed, 0 failed**, 35 ignored, 51 строка; clippy 0; `rmasscan.exe` (`d8819990…`) со статическим CRT и `0800 Dependent Load Flag` |
| home-pc (Linux 7.3.0-10-generic) | `rmasscan-lab` C (`fdaf2826…`) и `deploy-manifest` для C |

Строки `test result` считаны строгим `grep -c '^test result:'`.

**Не запускалось в r3.** macOS живой (`m1`), в том числе цели link-local и поиск маршрута IPv6 через обмен PF_ROUTE main
вживую: **NOT RUN** (нужен `sudo` пользователя). Windows IPv6: **NOT RUN** (П14; lab-NIC гостя без IPv6). Studio: упаковка
`cargo xtask build`, шаги только Linux и только Windows `studio.yml` и живые окна Studio: **NOT RUN** локально. Физические NIC:
**NOT RUN**. Правило подтверждения 1e9 и проверка MAC хопа IPv6 вошли в код под окнами r3, но ни одно окно их не упражняет
(раздел 10).

**Замещённые попытки r3:** нет. Каждое окно прошло с первого прогона (`verification/superseded-attempts.txt`).

CI: **PENDING**, заполняется при PR.
