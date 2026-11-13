# rmasscan: перечень готовности и долга интеграции/поставки

Дата: 2026-10-24. Документ только фиксирует проверенное и открытое. Он ничего не
закрывает: ни Windows, ни macOS, ни Studio, ни лицензионный gate. Исходники,
Cargo license-поля, релизы и spikes-дерево этой задачей не менялись.

Состояние: строка «CLI IPv6» добавлена 2026-11-12 на ветке `feat/rmasscan-ipv6` (код `e9eaebeb`, evidence `f089b071`, [отчёт](2026-11-08-rmasscan-ipv6-acceptance.md)), обновлена 2026-11-12 повтором r3 после слияния `origin/main` в ветку (код `0ce2a9e8`, evidence `f05e93df`, [отчёт](2026-11-08-rmasscan-ipv6-acceptance.md), раздел 11), строка «CLI protocols IPv4» добавлена 2026-11-10 на ветке `feat/rmasscan-protocols-ipv4`, обновлена 2026-11-11 повтором r4 после итогового ревью ветки (код `82f0483`, evidence `1ddb975`; прежде код `0ed6e36`, evidence `63c88b9`, [отчёт](2026-11-08-rmasscan-protocols-ipv4-acceptance.md)) и после слияния PR #55 (коммит слияния `fdd18b37`), строка «CLI scan control» обновлена после слияния PR #53 (SHA после переписывания истории); строки «CLI live scan + autodetect» таблицы 1, строка ARP раздела 2.3 и раздел 6 обновлены 2026-11-04 на ветке `feat/rmasscan-autodetect` (код `6c87e94`, evidence `00110f9`, [отчёт](2026-10-27-rmasscan-autodetect-acceptance.md)); строки «Studio raw (Mac feth)» и «Studio raw (Windows/Linux, physical NIC)» и таблица раздела 5 обновлены 2026-10-26 на ветке `feat/studio-mac-feth-raw` (код окна `6b1deb5`, прежнее окно `05ab27f`, [отчёт](2026-10-26-studio-mac-feth-raw-acceptance.md)); строки Windows throughput обновлены 2026-10-26 на ветке `feat/rmasscan-windows-sendqueue` (код `628fcad`, evidence `84c581b`). Исходная редакция (2026-10-24) — ветка `feat/rmasscan-stage2b-linux`, база `e5d6326`. Строки Windows обновлены 2026-10-25 на ветке
`feat/rmasscan-stage2b-windows` (код `f64495c`, документы `044dc00` и позже). Строки macOS обновлены 2026-10-25 на ветке `feat/rmasscan-stage2c-macos-bpf` (код `717e45c`, evidence `0c6e3fb`); остальные строки не менялись. Источник перечня возможностей по слоям —
[спецификация, §0.2](../superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md);
здесь он не дублируется. Контракты RX integrity/TX stall — там же, §0.1.

## 1. Итоги по направлениям

| Направление | Статус | Доказательство | Точный блокирующий gate |
| --- | --- | --- | --- |
| Linux merge readiness | **GO, слито** в `main` (PR #9, коммит слияния `2cc2bec`, CI зелёный) | Код и контракты: `364ee49`, `c31ae16`; приёмка Linux измерена на коммите кода `27e3042`, evidence `8479ff2`, [раздел отчёта](2026-10-23-rmasscan-stage2b-linux.md); review Задач 1-5 и итоговое review ветки пройдены (замечания закрыты) | Закрыто: CI зелёный на `7ffa155` и `2cc2bec`, merge выполнен 2026-10-25 по решению пользователя. Физический NIC: **NOT RUN** (отдельная строка) |
| Windows correctness (VM) | **GO (VM)** (VM-приёмка PASS; CI зелёный на `7ffa155` и на коммите слияния `2cc2bec`, PR #9) | Приёмка на виртуальной Windows 11 + Npcap 1.90 (Admin-only), запечатанный стенд n2: часть A 29 PASS, часть B 19 PASS (коды `9ecbe32`), часть C 21 PASS (`847e218`); перепроверка исправлений итогового ревью на `931f69f`, 4 прогона PASS (`perm_restricted_scan` exit 5, флаг поиска DLL 0x800 на EXE из пакета, подложенный файл-не-DLL рядом с EXE не ломает запуск; каталоги overall NOT RUN by design; раздел 11 отчёта). Полные A, B и C на бинаре `931f69f` не перезапускались (**NOT RUN**); **перепроверена на sendqueue-коде `628fcad`: A/B PASS** (29 и 19; [отчёт sendqueue](2026-10-25-rmasscan-windows-sendqueue-acceptance.md), раздел 6). Отчёт [Windows VM acceptance](2026-10-24-rmasscan-windows-vm-acceptance.md), сырые данные [raw](2026-10-24-rmasscan-windows-vm-acceptance-raw/) (evidence `dd78c4b`, `d2726df`, `c5ee494`, перепроверка `bfe069f`). План: [Windows](../superpowers/plans/2026-10-24-rmasscan-stage2b-windows.md) | Для GO (VM) всё выполнено, CI на точном HEAD **PASS** (Linux-база `31a729f` вошла в `2cc2bec`; отдельно на `31a729f` CI не запускался). Остаётся: физический NIC не доказан (**NOT RUN**), вне этого GO: Windows correctness в целом требует и его; VM не заменяет физическую приёмку |
| Windows throughput (VM) | **GO (VM)** (критерий плана sendqueue: MET на 100/1k/10k, 100k OPEN — потолок VM; CI зелёный на `b939cde`, итоговое ревью APPROVED) | Часть C `perf-r2` на sendqueue-коде `628fcad`, пачка `TX_BATCH_FRAMES` 64: PASS 21/21; gate ±20% **MET** на 100, 1k и 10k pps (100.5 / 1006.8 / 9964.9, было 10k **OPEN** 6444.6); **100k pps OPEN** (медиана 22532.8 pps, ячейки 16.8k-29.5k, потолок VM; было 6321.1); порядок SYN на проводе равен плану в 20 из 20 ячеек, `tx_over_budget` 0, kernel drops 0; `windows_live` 4/4; части A/B PASS (29 и 19). [Отчёт](2026-10-25-rmasscan-windows-sendqueue-acceptance.md), [спайк](2026-10-25-rmasscan-windows-sendqueue-spike.md) | Зелёный CI на точном HEAD (**PENDING**). Итоговое ревью ветки APPROVED (0/0/11), ручные прогоны рабочей области на трёх ОС пройдены. 100k на VM остаётся OPEN; измерение VM не есть физическая скорость |
| Windows throughput (physical NIC) | **NOT RUN / OPEN** | Физического Windows-стенда нет; все данные сняты на виртуальном e1000e. Потолок VM с sendqueue не заменяет замер на железе | Замер на целевом (физическом) NIC: корректность и пропускная способность, граница пачки 64 на нём не проверена, частичный transmit там не изучен |
| macOS correctness (feth) | **GO (feth): P1–P3 исправлены (PR #14, влит в main), архив пересчитан исправленным верификатором с неизменёнными вердиктами (`2026-10-25`: [reverify-6968272](2026-10-25-rmasscan-macos-bpf-acceptance-raw/reverify-6968272/README.md), все три каталога без изменений), CI зелёный: проверки PR #14 на `116ec1b` зелёные, прогон main `40232921797` на `baa5cc7` прошёл на macos-14, windows-2022, ubuntu-24.04 и в пакете windows-x64 wire lab. Критерий `linkloss` изменён пользователем 2026-10-25 (поправка в плане, раздел «GO и дальнейшая очередь»); это смена критерия, не повышение статуса.** (A и C PASS, B 17 PASS + linkloss INVALID, класс отказа линка OPEN до физического NIC) | Приёмка на паре `feth4201`/`feth4202`, macOS 27.0.1, Apple M4 Pro, запечатанный стенд `m1`: часть A 29 PASS, часть C 21 PASS (медианы 100.4 / 1014.0 / 10212.6 / 93808.6 pps, rate gate MET на всех четырёх), часть B 17 PASS и 1 INVALID (`linkloss`: сканер завершился `Completed` без отказа TX/линка при падении линка на стороне пира, предварительное правило) плюс прерванная попытка `linkloss`, хранимая только для изоляции; код `717e45c`, верификатор `2989ace`, evidence `0c6e3fb`; 0 кадров лаборатории на `en0` в 60 захватах, 0 чужих SYN, `raw_run_allowed` true везде. Отчёт [macOS BPF acceptance](2026-10-25-rmasscan-macos-bpf-acceptance.md), [spike](2026-10-25-rmasscan-macos-bpf-spike.md), [raw](2026-10-25-rmasscan-macos-bpf-acceptance-raw/) | Единый список: (1) CI: закрыто, PR #14 влит; проверки PR на `116ec1b` зелёные, прогон main `40232921797` на `baa5cc7` зелёный на macos-14, windows-2022, ubuntu-24.04 и в пакете windows-x64 wire lab (прогоны `40198055873` и `40222680150` относились к более ранним SHA); (2) итоговое ревью ветки проведено (CHANGES REQUIRED: 0 критичных, 3 важных, 8 минорных), исправления внесены серией final-fix, узкое повторное ревью серии **APPROVED**; (3) `macos_live` (6 живых тестов адаптера) выполнены в окне гранта: **PASS** 6 из 6, 0 кадров лаборатории на uplink, максимум на вызов recv 143 мкс / send 55 мкс / health 85 мкс / idle recv 34.1 мс (измерено на `feth`, не доказанная граница при нехватке mbuf), результаты в разделе 6 отчёта; живая перепроверка `c01` и `perm_denied_scan` итоговое ревью признало ненужной (поведение продукта не менялось), **NOT RUN**; (4) ручные прогоны на трёх ОС на `3e3886e`: Linux 1002/0, Windows 931/0, Mac 1122/0 и 23 ignored, clippy чисто везде; (5) `linkloss` остаётся INVALID и GO для «macOS correctness (feth)» не блокирует, класс отказа линка переносится как **OPEN** на этап физического NIC, статус не повышен; (6) физический NIC вне этого GO |
| macOS physical NIC correctness (USB/Thunderbolt Ethernet) | **NOT RUN** | Все данные сняты на паре `feth` (копирование в ядре); физического стенда нет. Риск блокировки `write()` (XNU `bpfwrite` игнорирует `ioflag`, mbuf выделяется с `MBUF_WAITOK`) относится к любому интерфейсу, включая `feth`, при нехватке mbuf; на `feth` не наблюдался (206 000 записей, максимум 70.3 мкс), верхней границы нет — **OPEN**; Stop ≤1 с измерен, не гарантирован; `bs_drop` — нижняя граница, потери ниже BPF не видны; sleep/wake **NOT RUN**; macOS 14 **NOT RUN** | Физический Ethernet-адаптер на Mac, те же контракты потерь/остановки/дедлайна, замер блокировки `write()` |
| macOS throughput (физический NIC) | **OPEN** | На `feth` медианы 100.4 / 1014.0 / 10212.6 / 93808.6 pps, gate ±20% MET; это копирование в ядре, не скорость физического NIC | Замер на физическом NIC (USB/Thunderbolt Ethernet) |
| CLI live scan + autodetect | **GO (stands)** (итоговое ревью ветки APPROVED; CI зелёный на `d634146`, PR #49) | Живой скан CLI (IPv4, TCP SYN) с автоопределением интерфейса, source IP/MAC и следующего хопа и ARP-резолвером, код `6c87e94`, evidence `00110f9`: Linux netns `linux-r1` PASS 13/13 (паритет с C-оракулом: байты ARP-запроса, порядок SYN, множество `Discovered`), Windows VM `n2` `windows-r1` PASS 10/10, Mac `feth` `macos-r1` PASS 8/8 и `macos-root-r1` PASS 3/3; `sent` равен SYN на проводе в 16 из 16 сканов; до скана только 60-байтовый ARP к напечатанному `router-ip`; 0 кадров лаборатории на `en0` и `eno1`; ручные прогоны рабочей области на трёх ОС на `6c87e94` пройдены. [Отчёт](2026-10-27-rmasscan-autodetect-acceptance.md), [raw](2026-10-27-rmasscan-autodetect-acceptance-raw/) | Итоговое ревью ветки APPROVED и зелёный CI на точном HEAD (`rmasscan`, `Studio`, `language-guard`). Вне этого GO: физические NIC, VPN/туннели, VLAN, IPv6, сон и смена сети во время скана, форматы вывода (этап 2), баннеры и user-mode TCP (этап 3), Studio |
| CLI live scan + autodetect (physical NIC) | **NOT RUN** | Все живые окна сняты на запечатанных стендах: veth (Linux), виртуальный e1000e (Windows VM), `feth` (Mac); физического стенда нет | Приёмка живого скана CLI на физическом NIC каждой ОС |
| CLI output formats (`-oL -oJ -oD -oG -oX -oB -oH -oU`, `--readscan`, строка статуса, Ctrl-C) | **GO (stands)** (итоговое ревью ветки APPROVED; CI зелёный на `9907de0`, PR #50) | Код живых окон `2b0e92c`, evidence `86f384f`, последний коммит с кодом `9907de0` (PR #50): офлайн-паритет с C `8e6b3b0` на 74 эталонах `--readscan` (байты равны после маски только часов в момент записи); Linux netns `linux-output-r1` PASS 18/18 (`o01`–`o11` с C-оракулом: записи и заголовок равны, подвал оракула отсутствует ожидаемо — C не заканчивает живой скан на стенде, `oracle_forced_exit`; подвал rmasscan равен подвалу своего формата; `o12` `--nostatus`, `o13` отказ открытия файла без кадров и `o14`–`o16` SIGINT только rmasscan, `o17` `--readscan` обоих сканеров), регрессия autodetect Linux 13/13 и Windows VM 10/10; CI `rmasscan` на `2b0e92c` зелёный (macos-15, ubuntu-24.04, windows-2025, windows-x64 wire lab). [Отчёт](2026-11-06-rmasscan-output-acceptance.md), [raw](2026-11-06-rmasscan-output-acceptance-raw/) | Итоговое ревью ветки и зелёный CI на точном HEAD (**PENDING**). macOS живой и живой Ctrl-C на Windows: **NOT RUN**; физические NIC: **NOT RUN**. Redis, certs, ротация, баннеры не входят |
| CLI scan control (`--shard`, `--retries`, пауза Ctrl-C и `paused.conf`, `--resume`, `--infinite`, `-c`/`-iL`, `--adapter[0..7]`, `--pcap`, `--ttl`, `--badsum`, `--tcp-*`) | **GO (stands)**, слито в `main` (PR #53, коммит слияния `f0d9b5c`; проверки PR `rmasscan`, Studio и `language-guard` зелёные) | Код `8059eac`, evidence `6509a8c` (ветка `feat/rmasscan-scan-control`; SHA после переписывания истории 2026-11-10, прежние `11a2235` и `28c956e`, карта в `../history-rewrite-2026-11-sha-map.txt`): Linux netns `linux-scan-control-r4` PASS 7/7 (`sc01`–`sc06`: шарды и `--retries` равны C-оракулу, пауза и `--resume` с точным остатком, `--infinite`, два адаптера на второй паре veth), регрессия вывода Linux 18/18 и автоопределения Linux 13/13, Windows VM 10/10; тесты minipc 1702/0 и гость 1598/0; CI `rmasscan` 42801284719 и `language-guard` 42801284890 на коде этапа зелёные. [Отчёт](2026-11-08-rmasscan-scan-control-acceptance.md), [raw](2026-11-08-rmasscan-scan-control-acceptance-raw/) | Итоговое ревью ветки проведено (волна исправлений `776db92`), слияние выполнено. macOS живой и живой Ctrl-C на Windows: **NOT RUN**; физические NIC: **NOT RUN** |
| CLI protocols IPv4 (UDP, ICMP Echo, SCTP INIT, ARP, префиксы `-p` `T:`/`U:`/`S:`/`I:`/`O:`, `--top-ports`, файлы нагрузок) | **GO (stands)**, слито в `main` (PR #55, коммит слияния `fdd18b37`, 2026-11-11; проверки PR зелёные) | Код `82f0483`, evidence `1ddb975` (ветка `feat/rmasscan-protocols-ipv4`, повтор r4 после итогового ревью): Linux netns `linux-protocols-r4` PASS 6/6 (`p01`–`p05`: `--ping`, `-sU` с ICMP 3/3, `-sZ`, `--arp`, смесь; зонды побайтно равны C-оракулу, записи равны C как мультимножество, порядок документа судится по его проводу с окном 50 мкс), регрессии управления сканом Linux 7/7, вывода Linux 18/18, автоопределения Linux 13/13 и Windows VM 10/10; 94 эталона C для вывода; тесты Mac 1964/0, minipc 1836/0 и гость 1731/0. [Отчёт](2026-11-08-rmasscan-protocols-ipv4-acceptance.md), [raw](2026-11-08-rmasscan-protocols-ipv4-acceptance-raw/) | Закрыто: слияние выполнено (PR #55, `fdd18b37`), проверки PR зелёные. macOS живой и физические NIC: **NOT RUN**; протоколы вживую на Windows не снимались. Пир SCTP это ответчик лаборатории; отклонения от C (дедупликация повторов, код Echo, неверные суммы, нулевая сумма UDP) вживую не сработали ни разу; порядок записей внутри пачки отправки вердикт требует, кроме пар ответов не дальше 50 мкс друг от друга (отчёт, раздел 5) |
| CLI IPv6 (TCP SYN over IPv6, NDP, mixed v4/v6) | **GO (stands)**, conditional on CI on the exact HEAD and Studio CI PR (фиксирует контролёр при слиянии) | Код `0ce2a9e8`, evidence `f05e93df` (набор r3 после слияния `origin/main` `d2a6603f` в ветку `feat/rmasscan-ipv6`: коммит слияния `ffb8d6c1` плюс коммит только с тестом; база `fdd18b37`; main принёс наблюдение маршрутов и адаптеров на трёх ОС, ограниченный обмен PF_ROUTE на macOS и карту доставки IPv4 у планов Studio; в коде под окнами есть и правки итогового ревью: правило подтверждения 1e9 в `validate` (`9dbbfd69`, R24) и проверка MAC следующего хопа IPv6 в `ReadyPlan::new_cli` (`6d6b235a`), ни одно живое окно их не упражняет; прежний набор r2: код `e9eaebeb`, evidence `f089b071`, те же вердикты): Linux netns `linux-ipv6-r3` PASS 4/4 (`v01`–`v03`: автоопределение интерфейса, источника и шлюза IPv6, NDP к роутеру стенда, 8 SYN по IPv6 побайтно равны плану и C-оракулу, смешанный скан IPv4 и IPv6 с инвариантом v4, `--router-mac-ipv6` без NS; записи типов 10 и 11), регрессии протоколов Linux 6/6, управления сканом Linux 7/7, вывода Linux 18/18, автоопределения Linux 13/13 и Windows VM 10/10; 119 эталонов C для вывода (25 с IPv6); тесты на `0ce2a9e8`: Mac 2201/0, minipc 2084/0 и гость 1973/0, офлайн-тесты Studio на Mac 484/0. [Отчёт](2026-11-08-rmasscan-ipv6-acceptance.md) (раздел 11), [raw r3](2026-11-12-rmasscan-ipv6-postmerge-raw/), [raw r2](2026-11-08-rmasscan-ipv6-acceptance-raw/) | Итоговое ревью ветки (правки до `0e0bd100`) и ревью слияния пройдены; зелёный CI на точном HEAD и Studio CI PR: **PENDING**. Windows IPv6 вживую: **NOT RUN** (IPv6 lab-NIC гостя выключен исправлением стенда, решение этапа); macOS живой (в том числе поиск маршрута IPv6 через обмен PF_ROUTE main), цели link-local на macOS и физические NIC: **NOT RUN**. IPv6 принят только на Linux netns; не-TCP протоколы по IPv6 отказывают (README, блок «IPv6»); NA на NS пира, нарушения RFC 4861, `--resume` IPv6 и цели за маршрутизатором вживую не снимались (отчёт, раздел 6); «52 строки `test result`» в сырых данных r2 это 51 (отчёт, раздел 4) |
| Studio raw (Mac feth) | **GO (feth)**, conditional on CI on the exact HEAD (фиксирует контролёр при слиянии) and the final review (APPROVED на финальном коде) | [Отчёт](2026-10-26-studio-mac-feth-raw-acceptance.md), раздел 1 | Закрыть условия отчёта (§10, §12); resume после перезапуска Studio на raw, sleep/VPN, release-сборка, физический NIC: **NOT RUN** |
| Studio raw (Windows/Linux, physical NIC) | **NOT RUN / OPEN** | Шлюз `raw_profile_enabled` ложен вне macOS; raw на Windows/Linux в Studio не включался | Отдельная приёмка по ОС и на физическом NIC |
| Studio integration (прочее: актуальный engine в vendor, UI-паритет) | **OPEN** (pinned engine устарел) | Раздел 2 | Обновить vendor до актуального engine/net; UI-паритет |
| Distribution | **OPEN** | Раздел 4 | Решение по лицензиям (раздел 4.3); воспроизводимый source/binary bundle; повторная проверка ad-hoc подписи Mac |

Слои, которые никогда не смешиваются: offline-тесты, CI-сборка, lab wire (netns/veth),
физический NIC, UI-приёмка. Физический NIC не проверен нигде (ни Linux, ни Windows).

### 1.1. Linux: что именно измерено

Результаты ниже относятся к чистому коммиту кода `27e3042` (`rmasscan/` не менялся до HEAD
этой записи, кроме теста `tx_stall.rs`); evidence-коммит `8479ff2`. Review Задачи 4 пройдено после fix round;
прогон на `ee51a19`/`eb8812a` заменён (superseded) и не является текущим результатом. Подробности и сырые данные:
[отчёт Linux, раздел «Fix round 1: повторный прогон на `27e3042`»](2026-10-23-rmasscan-stage2b-linux.md),
[сырые данные](2026-10-24-rmasscan-linux-acceptance-raw/round1-27e3042/).

- Functional: 141 pass / 0 fail / 0 skip.
- Performance: 40 из 40 точек VALID; Rust `rx_health` `kernel_drops` = 0 в 20 из 20 прогонов; медианы Rust/C по
  скоростям 100/1000/10000/100000 pps: 1.016/1.000/1.000/1.004.
- Воспроизведённое переполнение RX даёт `Failed(RxLoss { kernel_drops: 173 })`, rc 3, без checkpoint.
- CI: зелёный на голове PR #9 `7ffa155` и на коммите слияния `2cc2bec`, в который вошла Linux-база (`31a729f`);
  отдельно на `31a729f` CI не запускался. PR #8 (`df53e6d`) закрыт как слитый вместе с PR #9.
- Не проверено: физический NIC, >100k pps, Windows, macOS, UI.

## 2. Studio: закреплённый snapshot

Источники (read-only): `cross-platform/vendor/rmasscan-core/SNAPSHOT.json` в spikes-дереве
Studio (`feat/cross-platform-spikes`, грязное, чужая работа) и опубликованные pre-release
`engine-preview-2026-10-23`, `process-preview-2026-10-23`, `ui-preview-2026-10-23`.

### 2.1. Хэши vendor против закреплённых git-объектов

Проверка шла против git-объектов `e195df3983b51f408264e471a23119af373f2848` (коммит
`test(core): proptest for permutation invariants and parser robustness`, предок текущего HEAD),
а не только против manifest:

- 11 файлов `src/*.rs`: SHA-256 `git show <rev>:rmasscan/crates/rmasscan-core/<file>` совпал с
  SNAPSHOT.json и с файлами рабочего vendor-каталога: MATCH 11/11. Те же 11 файлов в source ZIP
  engine-preview совпали с git-объектами.
- `LICENSE` (`0d96a4ff68ad…`): совпал с `rmasscan/LICENSE` текущего HEAD; в vendor он заявлен как
  взятый из C-upstream (`8e6b3b0`). Объект upstream в этом клоне недоступен, поэтому происхождение
  от upstream по самому upstream-объекту здесь **не** проверено; проверен только факт совпадения с
  `rmasscan/LICENSE`.
- `Cargo.toml` vendor (`51fc03a3f832…`) намеренно отличается от workspace-манифеста в git
  (`bd38287d7a5f…`): автономный манифест, заявлено в SNAPSHOT.json. Его содержимое сверено только
  с manifest, не с git-объектом.

### 2.2. Что в snapshot отсутствует

Закреплённая ревизия `e195df3` содержит из rmasscan только `rmasscan-core` и `rmasscan-cli`. В ней нет
`rmasscan-engine`, `rmasscan-net`, `arp`/`probe` модулей core (vendor `lib.rs` перечисляет 10 модулей без
них), RX health, TX-stall watchdog, Linux AF_PACKET. От текущей ветки её отделяют 45 коммитов; в
`rmasscan-core` изменились 16 коммитов (+1426/−43 строк в `src/` по 9 файлам). Актуального engine/net в
Studio нет. Обновление vendor и сборку нового preview оставить отдельному интеграционному этапу
(этой задачей не выполняется).

### 2.3. Разделение возможностей (не объявлять одно другим)

| Пара | Состояние |
| --- | --- |
| ARP codec / ARP resolver | кодек, резолвер и обнаружение шлюза: есть, приняты на трёх стендах ([отчёт](2026-10-27-rmasscan-autodetect-acceptance.md)); кодек в core, резолвер (`arp_resolve`) и обнаружение (`discover`) в `rmasscan-net`, используются CLI; в pinned snapshot Studio их нет; физические NIC **NOT RUN** |
| `paused.conf` library / import UI | парсер в core (библиотека); пользовательского import UI нет |
| offline preview / raw Scan | Studio-preview готовит задание, исключения, число целей и первые 32 элемента порядка без пакетов; сетевого Scan нет. Release-текст engine-preview: «No real scan packets» |
| fake-masscan process | синтетический helper с фикстурами документационного диапазона; не Rust-engine |

### 2.4. UI: незакрытые взаимодействия (Slint, Qt не нужен)

Выбран только Slint; Qt/CXX-Qt исключены. Не закрыты и не доказаны: per-cell interactions таблицы,
native menu, keyboard и IME, frame timing. Release `ui-preview` сам помечает общий A1/A2 как
INCONCLUSIVE; Windows-запуск не проверен (Wine не засчитывается), Ubuntu 26.04 Wayland benchmark неполный.

## 3. Windows и macOS

### 3.1. Windows

- Физического Windows-хоста с Npcap нет. (Запись ранней редакции «ISO ещё нет, Mido вернул HTTP 404» устарела: VM Windows 11 Pro
  на home-pc (Ubuntu, QEMU/KVM) создана, Npcap 1.90 установлен, wire-приёмка на VM выполнена, см. строки таблицы и
  [отчёт](2026-10-24-rmasscan-windows-vm-acceptance.md).) NIC виртуальный, поэтому физический паритет остаётся **NOT RUN**.
- План Windows обновлён: [Задача 0](../superpowers/plans/2026-10-24-rmasscan-stage2b-windows.md) теперь
  ссылается на закрытые задачи [плана ремедиации](../superpowers/plans/2026-10-24-rmasscan-review-remediation.md)
  и включает контракты, которым должен удовлетворять адаптер. Предыдущие команды и цифры не являются
  свежим прогоном.
- Windows CI-сборка (`windows-2022`) и offline-тесты не доказывают raw I/O.

### 3.2. macOS

BPF-адаптер реализован (этап 2C); живая приёмка выполнена на запечатанной паре `feth4201`/`feth4202` (macOS 27.0.1, один Mac): части A и C PASS, часть B с одним INVALID (`linkloss`), см. [отчёт](2026-10-25-rmasscan-macos-bpf-acceptance.md). `feth` это копирование в ядре, не физический NIC: физический Ethernet-адаптер (USB/Thunderbolt), throughput на нём, блокировка `write()` (риск не привязан к физическому NIC: `MBUF_WAITOK` на любом интерфейсе, на `feth` не наблюдалась, границы нет), sleep/wake и macOS 14 остаются **NOT RUN**/**OPEN**; CI не выполняет живых macOS-тестов; `macos_live` выполнены вручную в окне гранта: 6 из 6 PASS (результаты в разделе 6 отчёта приёмки). Ad-hoc подпись
Mac-приложения проверяется повторно перед GUI-поставкой.

## 4. Поставка и лицензии

Лицензионной готовности этот раздел не утверждает и юридического вывода не делает. Cargo license-поля
не менялись.

### 4.1. Опубликованные pre-release (GitHub `disclaimer8/masscan-studio`, isPrerelease=true)

Все три: tag указывает на базу `b02dd2968563bd4af952748272f2d7bb92568281`; исходники — несохранённое
состояние, авторитетен приложенный source ZIP (сказано в release-тексте и manifest).

| Релиз | Source ZIP SHA-256 | Что внутри |
| --- | --- | --- |
| engine | `defaf777e485…` | 53 файла; Studio-код, `Cargo.lock`, `scripts/`, `vendor/rmasscan-core` (src + LICENSE + SNAPSHOT.json + автономный Cargo.toml), docs |
| process | `df4812cb385a…` | 31 файл, без engine |
| ui | `59e39cae264b…` | 24 файла, без engine |

Содержимое просмотрено списком (`unzip -l`) и чтением файлов; ничего из архивов не запускалось.

### 4.2. Проверка source ZIP против требований

| Требование | engine | process / ui |
| --- | --- | --- |
| `Cargo.lock` | есть (`1303de69b88e…`, slint 1.18.1) | есть; хэш совпал с manifest |
| build scripts | `build.rs`, `scripts/build-release-preview.sh`, `xtask` есть | есть |
| manifests | `Cargo.toml` всех crate есть | есть |
| собственный код Studio | есть | есть |
| хэши исходников в manifest | **нет** (в engine `build-manifest.json` нет `source_sha256`) | есть; 31/31 и 24/24 совпали, лишних файлов нет |
| vendor LICENSE | есть (AGPL-3.0 text, = `ENGINE-LICENSE.txt` в Windows ZIP) | не применимо (engine не включён) |
| vendor NOTICE (MIT-часть `util-checksum.c`) | отдельного NOTICE **нет**; MIT-атрибуция есть только комментарием в `checksum.rs` | не применимо |
| инструкция восстановления | `README.md` и `PLATFORM-VERIFICATION.md` описывают сборку на Rust 1.99.1 по lockfile; отдельной пошаговой инструкции «восстановить именно этот бинарник» нет | то же |
| исходники зависимостей (crates) | не приложены (только lockfile) | то же |
| бинарник связан с исходником | `Masscan-Studio-Preview.exe` `efa36ef7de64…` и `fake-masscan.exe` `51378584f71f…` из Windows ZIP совпали с `ui_sha256`/`fixture_sha256` manifest; **пересборка из ZIP не выполнялась**, воспроизводимость не доказана | process: хэши EXE совпали с manifest |

Наличие source ZIP не считается доказательством полной лицензионной готовности; его частичная полнота
также не утверждается за пределами таблицы. Не проверено: полнота notices зависимостей (561 запись в
lockfile engine), соответствие ZIP бинарнику побайтно.

Дополнительные факты: crate `scan-engine` объявляет `license = "AGPL-3.0-only"`, остальные Studio crates
(`scan-core`, `scan-process`, `spike-data`, `slint-table`, `xtask`) поля license не имеют. Это зафиксировано
как наблюдение, не как исправляемый дефект в рамках задачи. Process и ui релизы не содержат файлов лицензий
в Windows ZIP (в engine ZIP есть `ENGINE-LICENSE.txt`).

### 4.3. Решения, которые нужны до следующей поставки (OPEN)

1. Условия для объединённого Studio + AGPL engine (в одном исполняемом файле/процессе против отдельного
   процесса): кто лицензиат, что публикуется, какой исходник сопровождает бинарник.
2. Вариант лицензирования Slint для точной версии из `Cargo.lock` Studio (в проверенных lock-файлах —
   `slint 1.18.1`). Условия этой версии в рамках задачи не проверены (кэш crates недоступен).
3. Notices зависимостей: инструмент/процедура, содержимое для бинарной поставки.
4. Полнота и воспроизводимость source ZIP для уже выданного бинарника (хэши исходников, vendor NOTICE,
   исходники зависимостей или инструкция их получения, пересборка и сравнение).
5. Публичный выпуск и подпись не разрешаются изменением Cargo license-поля; отдельное решение пользователя.

AGPL-3.0 для порта принят пользователем; Nmap остаётся внешним инструментом.

## 5. Будущий gate: runner

Состояние: **OPEN, не решено, не реализовано.** Требования описаны в
[спецификации, §5–6](../superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md). Закрытие gate
требует проверки всей схемы целиком по каждой ОС:

- владение raw socket / handle: какой процесс его открывает и кому передаёт;
- объём кода под повышенными правами, измеримо;
- feasibility privilege-drop на каждой ОС (Linux capabilities, macOS BPF-устройства, Windows с драйвером Npcap);
- аутентифицированный IPC и смена версии;
- lifetime: поведение при смерти scanner и при смерти runner; смерть scanner не считается решённой, пока
  не проверена вся схема, включая Windows-драйвер и возможные дочерние процессы;
- durable checkpoint ACK: checkpoint принят хранилищем до подтверждения пользователю.

Ни один из пунктов выше не заявлен как решённый по всем ОС. Обновление 2026-10-26 (Studio raw, Mac feth; отчёт [здесь](2026-10-26-studio-mac-feth-raw-acceptance.md)), по строкам:

| Пункт | Статус | Основание |
| --- | --- | --- |
| bootstrap macOS (сессия, hash-pin) | **PASS** | runner бандла = установленный `cf22b148…` (код `6b1deb5`, со сторожем сети PR #28), Authorize принят в окне `session-6b1deb5-r2` (диалоги окон `50d717e` и `6b1deb5` остались без ответа, NOT RUN), Lock показал «Runner session closed». Выход root-runner после Lock в этом окне `ps` не фиксировался; cleanup подтверждён прежними пробами авторизации (`studio/VERIFICATION.md`) |
| durable checkpoint ACK вживую на raw (Mac feth) | **PASS** | `s2_pause`: «Checkpoint committed by Studio», `next_index` 7, Resume без пропусков и дублей |
| raw Start/Pause/Resume/Stop через Studio на `feth` | **PASS** (GO (feth) условно, см. строку «Studio raw (Mac feth)») | `studio-verify` PASS 7/7 на финальном коде `6b1deb5` (`session-6b1deb5-r2`), 0 кадров на uplink; прежнее окно `05ab27f` на runner `e369e29d…` это история |
| смерть scanner/runner, объём кода под повышенными правами, privilege-drop по ОС | **OPEN** | не измерялось этим окном |
| raw на Windows/Linux в Studio | **NOT RUN / OPEN** | шлюз закрыт вне macOS; bootstrap Windows/Linux принят отдельными этапами, см. `studio/VERIFICATION.md` |

## 6. Что этот документ не закрывает

Windows на физическом NIC, Windows throughput (physical NIC; Windows throughput (VM): GO (VM)), macOS на физическом NIC и его throughput, UI и licensing gates остаются открытыми (Windows correctness (VM): GO (VM); macOS correctness (feth): GO (feth): P1–P3 исправлены (PR #14 влит), архив пересчитан исправленным верификатором с неизменёнными вердиктами, CI зелёный (main `baa5cc7`, прогон `40232921797`), критерий `linkloss` изменён пользователем 2026-10-25; см. таблицу). Живой скан CLI с автоопределением: GO (stands) (итоговое ревью APPROVED, CI зелёный на `d634146`), на физическом NIC **NOT RUN**, см. строку «CLI live scan + autodetect». Очередь дальше: Windows/Npcap физический стенд (sendqueue на VM реализован, см. отчёт), macOS физический NIC, сетевая
интеграция (network identity, sleep/VPN; discovery и ARP для CLI приняты на стендах, см. [отчёт](2026-10-27-rmasscan-autodetect-acceptance.md)), runner/Studio (Studio raw на Mac feth: GO (feth) условно, см. строку в таблице; Windows/Linux и физический NIC открыты), поставка.
