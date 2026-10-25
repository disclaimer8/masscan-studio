# rmasscan: приёмка Windows на виртуальной машине (2B-Windows, итоговый отчёт этапа VM)

Дата: 2026-10-25. Ветка `feat/rmasscan-stage2b-windows`. Документ фиксирует измеренное и открытое. Статусы: PASS / FAIL /
INVALID / NOT RUN / OPEN / NOT STARTED, никогда не повышаются. «GO» здесь не статус таблицы: GO по критерию плана для Windows VM
correctness **объявлен** после зелёного CI на `main` `2cc2bec` (раздел 13). Сырые данные:
[`2026-10-24-rmasscan-windows-vm-acceptance-raw/`](2026-10-24-rmasscan-windows-vm-acceptance-raw/) (корневой
[README](2026-10-24-rmasscan-windows-vm-acceptance-raw/README.md); у каталогов Rust-харнесса свой `README.md`, `verdict.json` и
`MANIFEST.sha256`, у перепроверки они лежат в `perm/` и `func/`; исторические `functional/`, `functional-r1-smoke/` и
`verification/` покрыты корневым `MANIFEST.sha256`). Родственные отчёты: [baseline](2026-10-24-rmasscan-windows-baseline.md),
[spike Npcap](2026-10-24-rmasscan-stage2b-windows-spike.md), [перечень готовности](2026-10-24-rmasscan-readiness.md).

## 1. Итог и границы

**Windows VM correctness: GO (VM).** VM-приёмка PASS (части A, B, C и перепроверка на `931f69f`), CI зелёный на голове PR #9
`7ffa155` и на коммите слияния `2cc2bec` в `main` (раздел 12). Физический NIC — отдельный пункт **NOT RUN** и в это GO не входит.

Единый список условий (один и тот же в разделах 1 и 13, в таблице готовности и в обоих планах):

| Условие GO | Статус | Где |
| --- | --- | --- |
| Части A, B, C на запечатанном стенде n2 | **PASS** (29 / 19 / 21), на бинарях до исправлений | раздел 6 |
| Перепроверка исправлений итогового ревью, `931f69f` | **PASS**, 4 прогона (каталоги overall NOT RUN by design) | раздел 11 |
| Ревью: W1, N4c, лаборатория, продукт (проверка закрытия) | **APPROVED** | раздел 10 |
| CI на точном HEAD, зелёный | **PASS**: PR #9 на `7ffa155` (10 из 10 проверок, события push и pull_request), `main` на `2cc2bec` | раздел 12 |
| Linux-база Задачи 0: review + CI | review пройдено; CI ровно на `31a729f` не запускался, но база целиком вошла в `2cc2bec`, CI которого зелёный | readiness, строка Linux |
| Физический NIC | **NOT RUN**, вне этого GO | раздел 13 |

Это измерение на одном запечатанном стенде. Слои, которые отчёт **не** закрывает:

| Слой | Статус | Почему |
| --- | --- | --- |
| Физический NIC (Windows) | **NOT RUN** | Все данные сняты на виртуальном e1000e; физического стенда нет. VM не заменяет физическую приёмку |
| Пропускная способность (Windows) | **OPEN** | ±20% gate открыт на 10k и 100k pps; потолок VM около 6.4 kpps при одном `pcap_sendpacket` на кадр; закрывается после 2B-sendqueue и замера на целевом (физическом) NIC |
| macOS BPF | **NOT STARTED** | Плана и кода адаптера нет |
| Runner / IPC / durable checkpoint ACK | **OPEN** | Не входило в этап |
| UI (настоящий Scan в Slint) | **OPEN** | Не входило в этап |
| Дистрибуция (ZIP, подпись, лицензии) | **OPEN** | Не входило в этап. В частях A–C `wire_scan.exe` собран на госте из `git archive`, без ZIP; в перепроверке (раздел 11) EXE взят из ZIP, собранного `scripts/package-windows-wire.ps1` на `931f69f`. Воспроизводимость «source → тот же EXE», подпись и лицензии — **NOT RUN** / OPEN |

Стенд: QEMU Win11 Pro, виртуальная Intel 82574L (e1000e), Npcap 1.90, режим Admin-only. Результат относится именно к этой
связке (spike: «не универсальная гарантия для других версий Npcap, физических NIC»).

## 2. Закреплённые коммиты и чистота дерева

| Часть | Код (commit) | Evidence (commit) | Чистота |
| --- | --- | --- | --- |
| A `functional-r2`, B `failure-r1`, смоук | `9ecbe32f82aac77d15575c855dfaa4c10c101ab4` | `dd78c4b` (+ `d2726df`, заметки воспроизводимости по ревью W1) | `git_dirty=false` в `manifest.json` оркестратора |
| C `perf-r1`, смоук | `847e218bbd69c6151d781078df7bf03b00716cf7` | `c5ee494` | `git_dirty=false` |
| Перепроверка `recheck-931f69f` (`perm/`, `func/`) | `931f69fd1eaa0affd160d047b39855843c8cb152` | `bfe069f` | `git_dirty=false` в `manifest.json` оркестратора |
| Историческая A `functional/` | `1a446c594d86db52fbfa9a07962dc8cc1b662ca9` | `b672a35` и пересверки до `e9be82a` | см. раздел 8 |

Проверено чтением `manifest.json` каждого каталога: `code_commit` и `orchestrator.git_dirty=false` (functional-r2, failure-r1,
perf-r1, оба смоука и обе части перепроверки). Продуктовый код между `847e218` и `931f69f` менялся (исправления итогового ревью,
раздел 10); доказательства частей A, B и C к исправленному коду **не** относятся (раздел 9). Сырые логи, добавленные к перепроверке:
`recheck-931f69f/logs/` (README каталога).

## 3. Хэши и происхождение

| Объект | Части A и B (`9ecbe32`) | Часть C (`847e218`) | Где |
| --- | --- | --- | --- |
| Оркестратор `rmasscan-lab` (Mac) | `5270672c5d74…fd0a5` | `cfb589a6d79f…5f0de` (собран дважды, побайтно совпал) | `manifest.json` → `orchestrator`; README |
| Бинарь на home-pc | `2ad4d789280a…1544b`, 3127648 байт | `4dfd4e6f4da6…178e9`, 3201824 байт | README каталога |
| Deploy manifest (значение, записанное в прогоне) | `a4d070d3d60a…95a7d` | `7b599b100264…361ae` | `deploy/deploy-manifest.json` |
| Гостевой `wire_scan.exe` | `362632ce1743…34c90`, 629760 байт | `cb44c91eb471…32802` | `run.json` → `identity.binary_sha256` в каждом прогоне |
| tar исходников (`git archive --format=tar <commit> rmasscan`) | `a406a16884dc…b93d2` | `d652a07b4752…1cca0` | README, «Reproducibility notes» |
| Эталоны C | pinned masscan `8e6b3b0c07a8…` (дерево чистое, оригинальный бинарь, не `--offline`-копия), бинарь `8afc8ec81f2e…e2a3e` | те же `functional/fixtures` | `manifest.json` → `oracle`; `functional/fixtures/manifest.json` |

Перепроверка (`recheck-931f69f`, код `931f69fd1eaa`; значения из `recheck-931f69f/README.md`, там же полные):

| Объект | Значение |
| --- | --- |
| Оркестратор `rmasscan-lab` (Mac, чистый клон) | `a854f049a875f1e464aa3dffac3c52e125e25a285aa0211db00bcfb9068c985d` |
| Бинарь на home-pc, 3278664 байт | `be5d88a29fb14181195a9cf1ab9422f6dc1d3848d41c89b0767a3dee427df0ee` |
| Deploy manifest (запись прогона; сохранённая копия после очистки `74211b54…`) | `6303cd69e5d15bbb1b7a161c9f433f18dfbfbbb9ab28703b1764543d5ab714e8` |
| tar исходников (`git archive --format=tar 931f69f rmasscan`) | `2f810908da699c759b891f063ec3d92f60ca886aae92fac22144fc80716f1f01` |
| ZIP `rmasscan-wire-windows-x64-931f69fd1eaa.zip` (`scripts/package-windows-wire.ps1`) | `f96d86b1e58691c0c64b3552214977c5be5cbef8b2b3d1faf996325daa576cb5` |
| Гостевой `wire_scan.exe` из ZIP, один sha во всех 4 `run.json` | `02d67866b94e9f8b0f76ddabca0d7fd6cf3c451ee9785442b59c9b57d5be6915` |

Полные 64-символьные значения приведены в README каталогов. Замечание о deploy manifest: сохранённая копия прошла очистку
(исходный домашний каталог заменён на `$HOME`, одно вхождение), поэтому её собственный sha256 другой (`ad34159b…` для A/B, `0264d579…` для C).
Запись из прогона воспроизводится обратной подстановкой `$HOME` -> исходный каталог, точная команда в README каталога (ревью W1, M1). Гостевой `build-guest.ps1` и логирующий прокладочный `scp`-shim приведены в README с sha256
(ревью W1, M3, M4). Ограничение M4: JSON-артефакты хэшируются только после передачи через `scp`-shim; независимо от передачи до копирования
хэшируются лишь pcap (`pcap-hashes-on-home-pc.txt`). Каждый `run.json` содержит тот же sha `wire_scan.exe` и `source_commit`.

## 4. Топология

Стенд `n2` (одинаков во всех прогонах; `functional-r2/manifest.json`, README):

- Мост `wvb-n2` без uplink, без IP, без NAT и без forwarding; netns пира `wvp-n2`, интерфейс `lab0`.
- Гостевой NIC `Ethernet 2`, binding `\Device\NPF_{C4617223-A264-44F4-BDC8-0EA27F02CC40}`, 198.18.0.1/30, MAC `52:54:00:04:80:a9`.
- Пир 198.18.0.2, MAC `02:57:4c:3d:2e:9b`. Управляющий NAT-NIC не открывался; сканы идут только в 198.18.0.2.
- seed 1, rate 100 и wait 3 (кроме части C и отдельных случаев части B: `stop_*` идут с rate 1 и wait 10), retries 0, shard 1/1.
- `eno1` (внешний интерфейс home-pc) снимается на каждом прогоне. Результат: **0 кадров лаборатории во всех 64 прогонах частей A–C и
  смоуков и в 4 прогонах перепроверки (итого 68 закоммиченных сырых прогонов Rust-харнесса)**. Счёт по каталогам `runs/`:
  1 (smoke-rust-9ecbe32) + 24 (functional-r2) + 18 (failure-r1) + 1 (smoke-perf-847e218) + 20 (perf-r1) = 64, плюс 3 (`perm`) + 1 (`func`) = 68.
  Проверено: у всех `capture.json` поле `eno1.pcap.frames` равно 0 (для 64 прогонов A–C проверено при написании отчёта; 4 прогона
  перепроверки сверены независимым ревью), у всех `eno1.pcap` размер 24 байта (только заголовок).

## 5. Версии

Источник: `functional-r2/runs/c01_one_addr_port_synack.run1/run.json` (`identity`, `npcap`); те же значения в остальных каталогах.

| Компонент | Значение |
| --- | --- |
| Windows | 10.0.26300 x64 (Windows 11 Pro); baseline снят на 26300.9457, после отложенного обновления 26300.9711 ([baseline](2026-10-24-rmasscan-windows-baseline.md)) |
| `wpcap.dll` | 1.10.7.0, sha256 `332f81cc1671…96a9f` |
| `Packet.dll` | 5.1.90.1020, sha256 `6f9116d9747d…658c2` |
| Драйвер Npcap | 5.1.90.1020 |
| `lib_version` | `Npcap version 1.90, based on libpcap version 1.10.7 (64-bit time_t)` |
| Режим прав | Admin-only (реестр `AdminOnly=1`, [baseline](2026-10-24-rmasscan-windows-baseline.md), раздел установки). Не-elevated токен видит только `NPF_Loopback`; `perm_restricted_*` согласуются с этим |
| Процесс | `elevated=true`, `restricted_token=false` во всех прогонах, включая `perm_restricted_*`; для ограниченных запусков этот самоотчёт ненадёжен (раздел 11), ни один вердикт на нём не основан |

## 6. Результаты по частям

Счётчики из `verdict.json` (`totals`), проверены чтением.

### Часть A: `functional-r2` — overall **PASS**, 29 PASS (FAIL 0, INVALID 0, NOT RUN 0)

24 прогона + 4 группы pause/resume + manifest = 29. Нет INVALID, нет discarded, нет `--rerun`. Покрытие:

- Шесть функциональных классов (`c01` SYN-ACK, `c02` RST, `c03` несколько портов, `c04` exclude, `c05` source-port single,
  `c06` source-port range), каждый два повтора; байты SYN и порядок равны эталону C без нормализации.
- Полнота Open/Closed: «reply union equals listener truth without duplicates».
- Отклонение чужих ответов: `x01_foreign_replies.run1/run2`.
- Pause на N=0/1/8/15 для 16 probe (`group_pause_resume_N0/N1/N8/N15`): pause+resume равны continuous Rust и эталону C по байтам и
  порядку, ни один probe не потерян и не добавлен на шве; scan identity постоянная, attempt свежий.
- `refuse_completed`: завершённое задание не возобновляется (checkpoint отвергнут до открытия адаптера, ни одного SYN в проводе).

### Часть B: `failure-r1` — overall **PASS**, 19 PASS (18 прогонов + manifest)

| Прогон | Исход | Подтверждено |
| --- | --- | --- |
| `stop_silent`, `stop_load`, `stop_drain`, `stop_fullqueue` | Stopped, без checkpoint | `stop_to_outcome_ms` 27.97 / 11.686 / 3.108 / 39.991, все ≪ 1000 мс; workers завершены; после terminal outcome 0 SYN |
| `linkloss` | `TxUncertain`, exit 3 | гостевой разрыв линка через QMP `set_link` (down, затем up), uncertain TX не повторён, checkpoint нет, связь восстановлена. Это закрывает пункт spike «unplug NOT RUN» для VM |
| `overflow_queue` | `ConsumerTooSlow`, exit 3 | частичный результат, без checkpoint |
| `ckpt_*` (8 вариантов: corrupt checksum / next_index, empty, future engine / format, truncated, wrong ports / seed) | отказ до открытия адаптера | например `wrong_seed` → `JobMismatch`; ни один SYN не ушёл в провод |
| `rxloss` | `Failed(RxLoss { kernel_drops: 67804 })`, exit 3 | реальное переполнение, без checkpoint; **kernel_drops — нижняя граница** (область очереди NPF); значение совпало во всех трёх чтениях |
| `perm_restricted_scan` / `perm_restricted_inventory` / `perm_elevated_control` | exit 2 / exit 5 / exit 0 | файлы `guest-exit.txt` |

Замечание к `perm_restricted_scan`: exit 2 здесь — это то, что код делал на коммите `9ecbe32`; итоговое ревью нашло, что должен быть exit 5
(`PermissionDenied`); исправлено в `7247688` и подтверждено живой перепроверкой на `931f69f` (разделы 10 и 11).

### Часть C: `perf-r1` — overall **PASS**, 21 PASS (manifest + 20 ячеек)

Без rerun, без discarded, без RxLoss, kernel drops 0 во всех 20 ячейках. Медианы по 5 Completed PASS ячейкам на скорость
(`perf-r1/README.md`, `perf_summary`):

| rate pps | pass | rx_loss | wire pps | in-process pps | CPU user ms | CPU kernel ms | peak WS, байт | join ms | drain s | kernel drops | rate_gate |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 100 | 5 | 0 | 100.7 | 100.6 | 31 | 437 | 9736192 | 0.122 | 3.04 | 0 | MET |
| 1000 | 5 | 0 | 1006.7 | 1006.9 | 78 | 765 | 9986048 | 0.171 | 3.05 | 0 | MET |
| 10000 | 5 | 0 | 6444.6 | 6444.7 | 234 | 4906 | 12427264 | 0.148 | 3.08 | 0 | OPEN |
| 100000 | 5 | 0 | 6321.1 | 6321.1 | 375 | 6281 | 13897728 | 0.139 | 3.10 | 0 | OPEN |

Вывод: ±20% gate **MET** на 100 и 1000 pps, **OPEN** на 10k и 100k. Это измерение VM, не провал: сканер упирается примерно в 6.4 kpps при
одном `pcap_sendpacket` на кадр. Gate остаётся OPEN до 2B-sendqueue и последующего замера на физическом NIC и не меняет общий вердикт корректности. Диапазон wire pps по
ячейкам: 100 pps 100.3–100.8; 1k 1005.8–1007.8; 10k 6269.9–6551.3; 100k 6175.4–6351.5.

Латентности: задержка Stop берётся из `stop_*` прогонов части B (таблица выше); латентность одиночных вызовов Npcap — из
[spike](2026-10-24-rmasscan-stage2b-windows-spike.md) (`pcap_sendpacket` p50 113–227 мкс, максимум 22 598 мкс; RX-вызов с абсолютным
дедлайном 50 мс: все 1096 измеренных таймаутов вернулись позже 50 мс, перерасход до 7.1 мс; поэтому внутренний бюджет вызова ≤42 мс, решение контролёра; Stop в spike: join потоков максимум 53.4 мс). В части C отдельной ноги Stop нет
(`join ms` и `drain s` — это завершение, не отдельное измерение Stop).

Смоуки: `smoke-rust-9ecbe32` (1 прогон, PASS; overall NOT RUN by design, 27 запланированных не исполнены) и `smoke-perf-847e218`
(1 ячейка `perf.100.r1`, PASS; overall NOT RUN by design, 19 ячеек не исполнены). Это не приёмка.

Большие pcap (части B и C) хранятся как `peer.pcap.gz` (`gzip -9n`, без потерь); исходные sha256 и размеры — в
`pcap-hashes-on-home-pc.txt`. Перед повторной проверкой: `gunzip -k` на рабочей копии.

## 7. Хэширование и полнота захвата

Каждый pcap хэшируется на home-pc до копирования (`pcap-hashes-on-home-pc.txt`); все 64 сырых прогона (и 4 прогона перепроверки) прошли шлюз raw-run
(`capture_schema 3`: nonce, хэши, код выхода Verify, `raw_run_allowed=true`). Непрошедшие или недоснятые прогоны сохраняются, а не
удаляются; в этих каталогах таких нет (`runs_discarded` пуст).

## 8. Историческая часть A: `functional/`

`capture_schema 1`, без доказательства гостевого шлюза по каждому прогону (прогоны сняты до цепочки nonce). Вердикт её проверяльщика:
overall PASS, 29 PASS. **Заменена `functional-r2` и сохранена только для истории**; доказательством приёмки служит `functional-r2`. В
каталоге есть один discarded INVALID-прогон `x01_foreign_replies.run1` (tcpdump получил 96 кадров, записал 94; повторён без правок кода,
PASS). Единственный прогон `functional-r1-smoke/` — INVALID (`capture_schema` 1 < 2, см. корневой README), overall NOT RUN
(INVALID 1 / NOT RUN 27 / PASS 1); в приёмку не входит.

## 9. Ошибки и ограничения

- **Три отказа `scp` в W1 (NOT RUN).** «command output collection exceeded deadline», exit 2, отказ до любого удалённого изменения; только
  при параллельных ssh-сессиях к home-pc. Следов в evidence не оставили. Причина: два ProxyJump-хопа, вспомогательные `ssh -W` держат stderr
  `scp` после его выхода. Исправлено `478d0a3` (общее окно дренажа пайпа ≤5 с в пределах дедлайна), тест закреплён в `6ed388b`.
- **W2: перезапись бинаря оркестратора.** Общий каталог сборки был перезаписан другим агентом в 02:16:34 (сборка без
  `RMASSCAN_LAB_BUILD_COMMIT`), пересобран в 02:18:27. Часть C стартовала в 02:18:24 с приватной копии (sha `cfb589a6…`, идентична
  исходной). Во всех manifest и preflight смоука и perf-r1 один и тот же sha и `build_commit=847e218`; ничего не отброшено. Ошибка
  контролёра, раскрыта в README каталога. Перезапуск одной проверки смоука в 02:18 на перезаписанном бинаре есть только в журнале
  оператора W2 (в `.superpowers/`, вне репозитория), в README его нет.
- **Доказательства A, B и C сняты на бинарях до исправлений.** Гостевые `wire_scan.exe` собраны из `9ecbe32` (A, B) и `847e218` (C).
  Между `847e218` и `931f69f` изменены продукт и его сборка (`git log 847e218..931f69f -- rmasscan/crates/rmasscan-net`, плюс
  `rmasscan/.cargo/config.toml` и `scripts/package-windows-wire.ps1`): отображение отказа при Admin-only и видимом одном loopback
  в `PermissionDenied`, exit 5 (I1, `7247688`); флаг загрузки DLL `/DEPENDENTLOADFLAG:0x800` в `.cargo/config.toml` и скрипте
  упаковки (I2, `68134b0`); безопасное копирование errbuf (N1, `3d28ae3`); порядок проверки происхождения до любого экспорта,
  `unsafe fn resolve`, ограниченное чтение errbuf (M1, M2, M9, `0eadfcd`); телеметрия токена (M8, `20cba3c`); тест-двойник (M4, `23bd9bd`); документация и
  штамп CI (`010b042`). Engine и core не менялись (`git diff 847e218 f64495c` не трогает их пути). На исправленном EXE из пакета
  (`931f69f`) повторены **только 4 прогона**: `perm` ×3 и `c01`. Полные наборы A, B и C на исправленном бинаре **не** перезапускались
  (**NOT RUN**); Stop, pause/resume, RxLoss, linkloss, отказы checkpoint и часть C на нём не проверены. По замыслу нормальный путь
  сканирования не изменён; изменены отказ при нехватке прав (I1), отказ для непроверенного модуля Npcap (M1), поиск статических DLL
  при запуске (I2, флаг в `.cargo/config.toml` и скрипте упаковки), телеметрия токена (M8) и чтение errbuf (M9, N1).
- **pcap в `.pcap.gz`**: перед повторной проверкой `gunzip -k` (раздел 6).
- **`kernel_drops` — нижняя граница.** Это счётчик очереди NPF; потери ниже NPF (между NIC и NPF) им не видны. В spike (прогон r06)
  счёт NPF занизил потерю на 137 028 кадров, потерянных ниже NPF.
- **Область очереди NPF**; один сканирующий NIC, IPv4/TCP.
- **Только VM.** Виртуальный e1000e и QEMU/TAP/bridge; поведение на физическом NIC, Wi-Fi, других версиях Npcap не проверено.
- **Нет сырых логов у части проверок перепроверки.** Результат флага `0x800`, запусков с подложенными файлами, создания ZIP и
  `SHA256SUMS`, проверки остатков на госте есть только в описании оператора (README перепроверки), сырой вывод не сохранён.
  Сохранены сырые логи остальных проверок (`recheck-931f69f/logs/`) и тексты скриптов.
- **Замечание к подложенным файлам.** Контрольный и подложенные запуски — `wire_scan.exe --help`: ответ BadArgs, exit 2 (у EXE нет
  `--help`). Запись `dumpbin /imports` для EXE из пакета не сохранена, поэтому «пустой» проход формально не исключён (замечание
  проверки закрытия, C1). Падение `0xc000012f` до исправления наблюдалось на другой сборке (dev, динамический CRT, `7247688`) и в
  evidence не записано.
- **Расхождение в справочном README стенда.** `$HOME/winvm/README` на home-pc (вне репозитория) называет Npcap «not admin-only»; реестр после
  переустановки (`AdminOnly=1`) и exit 2 у `perm_restricted_scan` согласуются с Admin-only. Не проверено повторно в этом отчёте.

## 10. Ревью

Файлы лежат в `.superpowers/` (в gitignore), поэтому вердикты пересказаны здесь, ссылок нет.

- **Покомпонентные ревью.** N1 baseline (`task-1-review`): NEEDS FIXES → fix round 2, APPROVED (`task-1-rereview-r2`). N2 изолированный
  switch (`task-2-review`): NEEDS FIXES → APPROVED на одном условии (заменить копию скрипта на home-pc; `task-2-rereview-r2`). Ревью задач детального плана Windows (загрузчик, spike, адаптер, пакет; `task-1…4-review` плана stage2b-windows): все одобрены после своих раундов. N4a харнесс части A (`task-4a-review`): APPROVED при условиях → после
  трёх раундов APPROVED (`task-4a-rereview-r3`). Ревью лаборатории Linux (`lab-review-linux`) и Windows (`lab-review-windows`): CHANGES
  REQUIRED → Windows APPROVED + GO на staged-прогон n2 (`lab-rereview-windows-r2`), Linux APPROVED (`lab-rereview-linux-r3`).
- **Ревью evidence W1** (`review-W1.md`): **APPROVED**, критичных 0, важных 0, минорных 5; «W1 evidence acceptable for N5 report: yes».
  M1, M3, M4 исправлены в `d2726df`; M5 закреплён тестом в `6ed388b`; M2 (чтение `.pcap.gz` проверяльщиком) отложено, `gunzip -k` задокументирован.
- **Ревью N4c** (`n4c-review.md`): Needs fixes (I1: проверка «ровно один раз» при потере захвата давала FAIL вместо INVALID; M1–M6).
  **Перепроверка** (`n4c-rereview-r1.md`): APPROVED, I1 и M1–M6 исправлены; N1 (устаревшие пункты в `rust-lab.md`) исправлен в `847e218`.
- **Итоговое ревью ветки, продукт** (`final-review-product.md`): **WITH FIXES**, критичных 0, важных 2, минорных 10 (код `cfg(windows)` не
  компилировался на Mac). **I1**: Admin-only без прав и при видимом только loopback давал `InterfaceMismatch` (exit 2) вместо
  `PermissionDenied` (exit 5); виден в evidence `perm_restricted_scan`. **I2**: статический импорт `version.dll` / `iphlpapi.dll`
  не из KnownDLLs, риск подмены DLL рядом с EXE; комментарий в `loader.rs` был неверен.
- **Итоговое ревью ветки, лаборатория** (`final-review-lab.md`): **WITH FIXES**, критичных 0, важных 2, минорных 7. **I-1**: нарушение
  безопасности (кадр на eno1 / чужой SYN) вместе с INVALID превращалось в отбрасываемый INVALID и повтор, итог PASS. **I-2**: eno1 при
  прерванном raw-прогоне не проверялся. Перепроверки: `n4-final-lab-rereview.md` — CHANGES REQUIRED (1 важное, 8 минорных); `n4-final-lab-rereview-r2.md` —
  **APPROVED**, «безопасно для следующего live-прогона», с минорами R2-1…R2-4 (N5 PARTIAL); R2-1 исправлен в `b82dc46`, R2-2…R2-4 в `ec864c9`.
- **Статус исправлений.** Лаборатория: I-1, I-2, M-1, M-3, M-4, M-5 исправлены; M-2, M-6 частично; M-7 отложен (коммиты
  `699ea02`…`9ce40d6`, `92630c3`, `85f73d4`, `b82dc46`, `ec864c9`). Продукт: I1 — `7247688`, I2 — `68134b0` (`/DEPENDENTLOADFLAG:0x800`),
  M1/M2/M9 — `0eadfcd`, M4 — `23bd9bd`, M5/M7/M8 — `20cba3c`, M6/M10 — `010b042`; M3 отложен.
- **Перепроверка продукта** (`final-review-product-rereview.md`, `847e218..66a5da4`): **CHANGES REQUIRED**, критичных 0, важных 1 (R1:
  флаг на EXE из пакета не доказан и не охраняется), минорных 3 (N1–N3). Исправлено в `3d28ae3` (`check-dll-search-flag.ps1`, шаг в
  CI-workflow; сам CI не запускался) и `931f69f` (manifest требует exit 5). **Проверка закрытия** (`66a5da4..920dd25`): **APPROVED**,
  критичных 0, важных 0, минорных 1 (C1: в следующей перепроверке записать `dumpbin /imports` EXE из пакета). Живое подтверждение — раздел 11.
- Ограничение ревью: доказательства частей A, B и C относятся к коду до этих исправлений (`9ecbe32`, `847e218`); см. раздел 9.

## 11. Перепроверка после исправлений итогового ревью

Живая перепроверка на том же стенде n2, коммит кода `931f69f`, сырые данные:
[`recheck-931f69f/`](2026-10-24-rmasscan-windows-vm-acceptance-raw/recheck-931f69f/). Те же правила, что и в частях A-C:
проверка стенда перед каждым прогоном, capture_schema 3, отправка только на 198.18.0.2, захват на eno1.

- **Сборка.** `wire_scan.exe` собран скриптом упаковки `scripts/package-windows-wire.ps1` из `git archive` коммита. В README
  каталога записаны sha архива исходников, ZIP и EXE (раздел 3), а также полные тексты гостевых скриптов (`guest-scripts/`).
- **I1, права.** `perm_restricted_scan` (`perm/`) отклонён под ограниченным токеном: guest exit **5**, `PermissionDenied` с
  подсказкой про режим Administrators-only, адаптер не открыт, `tx_sent` = 0, SYN сканера в захвате нет. Вердикт прогона
  **PASS**. Manifest этого suite содержит `perm_restricted_refusal: PermissionDenied`, поэтому проверяльщик принимает только
  exit 5, а не прежний `InterfaceMismatch` (exit 2). `perm_restricted_inventory` даёт exit 5, `perm_elevated_control` даёт exit 0,
  оба **PASS**.
- **I2, поиск DLL.**
  - `check-dll-search-flag.ps1` на собранном пакетом EXE: Dependent Load Flag `0x800`. Тот же скрипт добавлен в CI-workflow (`3d28ae3`); CI не запускался.
  - Подложенные рядом с EXE файлы-не-DLL `version.dll` и `iphlpapi.dll` запуск не ломают: ответ и код выхода те же, что у
    контрольного запуска без них (оба запуска — `wire_scan.exe --help`, BadArgs, exit 2). Сырого вывода нет, только описание оператора.
    Падение `0xc000012f` до исправления наблюдалось на другой сборке (dev, динамический CRT) и в evidence не записано.
  - Пакеты при этой проверке не отправлялись.
- **M1, реальная загрузка Npcap.** Повышенный `--inventory` (без отправки): exit 0, `wpcap.dll` 1.10.7.0 и `Packet.dll`
  5.1.90.1020 из `C:\Windows\System32\Npcap`.
- **Функциональный прогон.** `c01_one_addr_port_synack.run1` (`func/`) **PASS**, SYN побайтно равен эталону C.
- **Блокировка suite.** Второй `--cleanup` во время прогона отклонён за 3 с с сообщением о занятой блокировке. Работающий
  прогон не пострадал.
- **eno1.** 0 кадров стенда во всех 4 прогонах.
- **Результат каталогов.** `perm/`: PASS 4 / NOT RUN 15; `func/`: PASS 2 / NOT RUN 27; оба каталога overall **NOT RUN by design**
  (запущены только выбранные прогоны), `windows-verify` exit 2. Это не приёмка каталога целиком, как и смоуки в разделе 6.
- **Сырые логи.** Для блокировки suite, повышенного `--inventory`, гостевых clippy/test и строк раздела 12 сохранены сырые выводы
  (`recheck-931f69f/logs/`). Для флага `0x800`, подложенных файлов, ZIP и `SHA256SUMS`, остатков на госте сырого вывода нет
  (раздел 9).
- **Windows-сборка рабочей области.** На `931f69f` тесты `rmasscan-lab` не компилировались под Windows: unix-only
  помощники в `tests/rust_only.rs`, 6 тестов с unix-допущениями. Исправлено в `9b5cf3e` и `920dd25`, только `#[cfg(unix)]`
  у тестов, продуктовый код не менялся. Повторный прогон на госте на `920dd25` по git-инициализированной копии дерева, как
  в CI: `cargo clippy --locked --workspace --all-targets -- -D warnings` завершён `Finished` без ошибок, у
  `cargo test --locked --workspace --all-targets` все строки `test result` с `0 failed` (код выхода в логе не записан; rc 0 — со
  слов контролёра). Это замена Windows CI, а не CI.
- **Известное ограничение.** Под `runas /trustlevel:0x20000` процесс сам сообщает `elevated: true, restricted_token: false`.
  Отказ при этом верный: Admin-only Npcap не пускает токен с deny-only группой Administrators. Эти флаги — только
  телеметрия, ни один вердикт на них не опирается.

## 12. CI

CI на точном HEAD: **PASS**. PR #9 (`feat/rmasscan-stage2b-windows` → `main`) на голове `7ffa155`: 10 из 10 проверок в событиях
push и pull_request (rmasscan на ubuntu-24.04, macos-14 и windows-2022, пакет windows-x64 с проверкой флага поиска DLL, language
guard). PR слит merge-коммитом `2cc2bec`, sha веток, на которые ссылаются доказательства, сохранены. На `2cc2bec` в `main` CI тоже
зелёный. Linux-база (`31a729f`) вошла в этот HEAD; отдельно ровно на `31a729f` CI не запускался.

До зелёного прогона CI нашёл шесть дефектов, которые ручные прогоны пропустили. Все они в тестах или в настройках git, не в продукте:
- доказательства в `docs/experiments` на Windows-раннере извлекались с CRLF, и хэши расходились. Теперь `docs/experiments/** -text`,
  атрибут закреплён тестом (`e9a1517`);
- пять тестов зависели от тайминга или порядка выполнения. Это число чтений за тихий период, удержанные ManualClock в `tx_stall`,
  имя временного каталога по времени, освобождение flock при параллельном fork, параллельное чтение в тесте переполнения
  `rx_integrity` (`e9a1517`, `26045a3`, `5360ca7`, `7ffa155`).

После исправлений все тесты рабочей области 5 раз подряд прошли на Windows-госте (785 passed, 0 failed в каждом прогоне) и 4 раза
на Mac при полной загрузке CPU.

Ручные прогоны на трёх ОС до CI (это не CI). Они нашли две ошибки сборки, невидимые на Mac:
- unix-only помощники в тестах под Windows, исправлено в `9b5cf3e` и `920dd25`;
- тест только для Linux со старым инициализатором `Suite`, исправлено в `f64495c`.

| ОС | Коммит | Что прогнано | Итог | Сырой лог |
| --- | --- | --- | --- | --- |
| macOS (Mac разработчика) | `044dc00` (дерево чистое) | fmt, clippy `-D warnings`, `cargo test --workspace` (включает тест `no_c_in_build`), `cargo deny check bans licenses sources`, language guard | fmt, clippy, test, deny, guard: rc 0 | `logs/mac-check-044dc00.log` |
| Linux (minipc, Ubuntu) | `f64495c` | language guard (GNU grep 3.12), clippy `-D warnings`, `cargo test --workspace --no-fail-fast` | rc 0, 880 passed / 0 failed / 14 ignored. `cargo deny` там не установлен (**NOT RUN** на Linux); `cargo fmt` на minipc не запускался (**NOT RUN**) | `logs/minipc-check-f64495c.log` |
| Windows 11 (гость n2) | `920dd25` | clippy `--all-targets -D warnings`, `cargo test --workspace --all-targets --no-fail-fast` по git-копии дерева | clippy завершён без ошибок, все строки `test result` с `0 failed` (`f64495c` меняет только тест для Linux, на госте не прогонялся) | `logs/guest-clippy-920dd25.log`, `logs/guest-test-920dd25.log` |

Логи лежат в `recheck-931f69f/logs/` (README каталога перечисляет их). В логах гостя нет отдельной строки с кодом выхода.

## 13. Заявление о готовности

**GO для Windows VM correctness объявлен: GO (VM).** Выполнены все условия критерия плана stage2b-windows (раздел «GO и дальнейшая
очередь»), включая «CI зелёный» на точном HEAD (`7ffa155`, коммит слияния `2cc2bec`, раздел 12). Условия частей A–C выполнены на
бинарях до исправлений, раздел 9. Единый список условий приведён в таблице раздела 1. Что сделано и где доказано:

- Части A (29 PASS), B (19 PASS) и C (21 PASS) на запечатанном стенде n2, коды `9ecbe32` и `847e218` (раздел 6). Это бинари до
  исправлений ревью (раздел 9).
- Живая перепроверка исправлений итогового ревью на `931f69f`, 4 прогона PASS (раздел 11); полные A, B и C на исправленном бинаре **NOT RUN**.
- Ревью W1 и N4c одобрены; лабораторное ревью одобрено после двух перепроверок; продуктовая перепроверка CHANGES REQUIRED (R1) → исправлено →
  проверка закрытия APPROVED (раздел 10).
- CI зелёный на точном HEAD (`7ffa155`, слияние `2cc2bec`); до него сборка и тесты на трёх ОС прошли вручную (раздел 12).

Windows correctness в целом (не VM) дополнительно требует физического NIC (**NOT RUN**); поэтому строка таблицы готовности перечисляет оба gate.
Это заявление **не** распространяется на:

| Область | Статус |
| --- | --- |
| Физический NIC | **NOT RUN** |
| Пропускная способность (±20% на 10k и 100k, потолок VM около 6.4 kpps) | **OPEN**: 2B-sendqueue, затем замер на физическом NIC |
| macOS BPF | **NOT STARTED** |
| Runner / IPC | **OPEN** |
| UI | **OPEN** |
| Дистрибуция | **OPEN** |

VM никогда не заменяет физическую приёмку.
