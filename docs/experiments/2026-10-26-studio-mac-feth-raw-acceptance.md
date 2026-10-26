# Studio: приёмка raw-сканирования Mac feth через Studio (итоговый отчёт этапа)

Дата: 2026-10-26. Ветка `feat/studio-mac-feth-raw`, база `main` `0bb9767`. План: `docs/superpowers/plans/2026-10-26-studio-mac-feth-raw.md`.
Документ фиксирует измеренное и открытое. Статусы: PASS / FAIL / INVALID / NOT RUN / OPEN / PENDING никогда не повышаются.
Сырые данные: [`2026-10-26-studio-mac-feth-raw-acceptance-raw/`](2026-10-26-studio-mac-feth-raw-acceptance-raw/) (корневой
[README](2026-10-26-studio-mac-feth-raw-acceptance-raw/README.md), `MANIFEST.sha256`, `session-05ab27f/`, `session-05ab27f-r2/`,
`verification/`). Родственные документы: [baseline](2026-10-26-studio-mac-feth-raw-baseline.md),
[приёмка macOS BPF (engine)](2026-10-25-rmasscan-macos-bpf-acceptance.md), [перечень готовности](2026-10-24-rmasscan-readiness.md),
[`studio/VERIFICATION.md`](../../studio/VERIFICATION.md).

## 1. Итог и границы

**Studio raw (Mac feth): GO (feth), conditional on §12 CI and §10 review.** Условное слово: оно не становится безусловным, пока
контролёр не запишет в §12 зелёный CI на точном HEAD и в §10 вердикт APPROVED итогового ревью. Сейчас оба пункта **PENDING**.

Измерено: одна авторизованная сессия Studio (`studio-ui --smoke-feth`, путь тех же `Action::*`, `Client::authorize` и истории SQLite,
что и клики) на запечатанной паре `feth4201`/`feth4202`, три кейса, **PASS 7/7** независимого верификатора `studio-verify`, 0 кадров
лаборатории на uplink `en0`, 1046 кадров у независимого свидетеля на пире. Первая попытка окна **NOT RUN** (диалог Authorize остался
без ответа), вторая **PASS**; обе записаны, первая не скрыта и не засчитана.

Единый список условий GO «Studio raw (Mac feth)» (один и тот же в §1, §13 и в таблице готовности):

| Условие GO | Статус | Где |
| --- | --- | --- |
| Сессия `session-05ab27f-r2` на замороженном `C` `05ab27f`: `studio-verify` overall | **PASS** 7/7 (safety, chronicle, history, s1_full, s2_pause, s3_stop, wire) | §6 |
| Попытка 1 `session-05ab27f` | **NOT RUN** (rc 10; Authorize без ответа, сканов нет); не повышена | §6, §9 |
| Изоляция: кадры лаборатории на `en0` | **0** в обоих окнах (uplink-pcap пуст, exit 0, drop 0) | §4, §6 |
| Стенд до и после: `raw_run_allowed: true`, `bpf_access: granted` до окна | **PASS** (`status-pre/post` в r2); после `down`: rc 3 «no stand recorded», `feth4201` нет, `/dev/bpf0`,`/dev/bpf1` `crw------- root wheel` | §4 |
| Хэши: бандл чистый, runner бандла = установленный, хэши файлов до и после копирования | **PASS** | §3, §7 |
| Ручной проход UI (действие E) | **NOT RUN** (пользователь пропустил) | §6 |
| Офлайн-тесты на Mac на `C`: Studio, rmasscan | **PASS** 121/0 и 1268/0 | §12 |
| Офлайн-тесты Linux (minipc) и Windows (гость) на `C` | **PASS** 1147/0 и 1077/0 (clippy rc 0 на обоих, guard PASS на Linux) | §12 |
| Итоговое ревью ветки | **CHANGES** (исправлено в раунде исправлений); узкое повторное ревью **PENDING** | §10 |
| CI на точном HEAD (`rmasscan`, `Studio`, `language-guard`; ubuntu-24.04, macos-14, windows-2022) | **PENDING** | §12 |

Это GO не распространяется на (границы, статусы не повышены):

| Область | Статус |
| --- | --- |
| Физический NIC, USB/Thunderbolt Ethernet | **NOT RUN** |
| Windows и Linux raw в Studio (шлюз закрыт: `raw_profile_enabled` ложна вне macOS) | **NOT RUN / OPEN** |
| Resume после перезапуска Studio на raw (действие E не делалось) | **NOT RUN** |
| Sleep/wake, VPN | **NOT RUN** |
| Скорости выше 300 pps и класс дефекта, видимый только на перф-скоростях или при >1 цели | **OPEN** (engine принят отдельно, этап не ловит) |
| Другая версия macOS, другой Mac | **NOT RUN** |
| Release-сборка (окно прошло на debug) | **NOT RUN** |

## 2. Закреплённые коммиты и чистота дерева

- Замороженный коммит `C` = `05ab27fb631da440539344cf8c600308149d4671`. Код `C` идентичен `3113a85`; `C` добавляет только закоммиченный план,
  поэтому манифест бандла чист (`dirty: false`, `source_commit` = `C`). Первая сборка на `3113a85` дала `dirty: true` (план и `.superpowers/`
  не были закоммичены); окно на ней не шло.
- Бандл `studio/dist/build-1793039025527`, профиль **debug**, aarch64.
- Коммиты ветки от `0bb9767` до `C` (12): `8cac448` (шлюз по профилю), `9ffa4d9` (baseline), `dd4cfe6` (`studio-verify`), `d56d271`
  (`--smoke-feth`), `5df4c19`, `1b13b0d`, `a678af6`, `e2ea52f`, `bd9ee39` (оркестратор), `bef9c80`, `3113a85`, `05ab27f` (план).
- Коммит evidence: `092fd64` `test(studio): record Mac feth raw acceptance through Studio`. HEAD отчёта указан в §12 после коммита контролёром.
- Код движка (`rmasscan/` кроме `rmasscan-lab` и `docs/macos-feth-lab.md`) в ветке не менялся.

## 3. Хэши и происхождение

| Что | sha256 |
| --- | --- |
| `studio-ui` (бандл) | `eff51e58117f2cc7b6ed3690d3874a512a1ad4091db98a29339df14a921daa86` |
| `studio-runner` бандла = установленный `/Library/PrivilegedHelperTools/MasscanStudio/<sha256>/studio-runner` | `e369e29dff4d89577ec58b87f5f86306312875c185305e00fe70ac23c4a943cb` |
| `rmasscan-lab` (свидетели, верификатор `studio-verify`) | `e0e2f5170218763b51ed22045516a738efbafae4e0a54eaa9570b047d460733b` |
| `bundle-manifest.json` | `59f7c141b6e8299632ab2f89b39112188602c0c0f3c1895023fd1149671eda79` |
| `Cargo.lock` Studio (манифест бандла) | `549df63a6ce9a5e122b656c2bb88f72a366709339c36e098b326fb44db7f3783` |

`provenance.json` обоих окон совпадает с таблицей; `window_sha` в `verdict.json` = `C`. Оркестратор проверил «хэш бандла = установленный» до
запуска UI (чтение `provenance.json`: `installed_runner_sha256` = `runner_sha256`).

## 4. Топология и действия пользователя

Стенд `m1`: `feth4201` (сканер, `02:ac:00:00:00:01`, без IPv4) <-> `feth4202` (пир, `02:ac:00:00:00:02`, `198.18.0.2/30`), манифест
`/var/run/rmasscan-lab/m1.json`. Свидетели: `tcpdump -p -n -U -s 0 -i feth4202 -w peer.pcap` без фильтра и
`tcpdump -p -n -U -s 0 -i en0 -w uplink.pcap '<фильтр лаборатории>'` (uplink `en0`, шлюз `192.168.1.1`, маршрут по умолчанию не менялся).
Пир слушает `8000-8007`; `alf.txt` = `Firewall is disabled. (State = 0)`; на хосте нет слушателей `198.18.0.2` до окна; процессов-остатков нет.
Задание Studio: `targets 198.18.0.2`, source `198.18.0.1`/`02:ac:00:00:00:01`, next hop `02:ac:00:00:00:02`, source port 40000, wait 3 с, retries 0.

Действия пользователя фактически:

| Действие | Сколько раз | Что произошло |
| --- | --- | --- |
| A (разрешение на живое окно) | 1 | выдано (диалог выбора 16:3x) |
| B (install-runner + `up` + `grant`) | **1** | диалог администратора установки runner один раз и **2** запроса `sudo` (up, grant), 20:26 |
| D (диалог Authorize в Studio) | **2** | попытка 1: диалог показан 20:27:13, без ответа; попытка 2: отвечен |
| E (ручной проход UI) | 0 | **NOT RUN**, пользователь пропустил |
| F (`down`, он же revoke BPF) | **1** | 20:49 |

Грант BPF выдан один раз на оба окна и не снимался и не выдавался повторно между попытками. Оркестратор не вызывает `sudo`.

Состояние после F (`verification/status-after-down.json`): `macos-lab status` rc 3 «no stand recorded», `feth4201` отсутствует, `/dev/bpf0` и
`/dev/bpf1` `crw------- root wheel`, остатков процессов нет.

## 5. Версии

| Что | Значение |
| --- | --- |
| macOS | 27.0.1 (26A434), `sw_vers` (`session-*/sw_vers.txt`) |
| Darwin | 27.0.0, `xnu-13432.1.9~1/RELEASE_ARM64_T6041`, arm64 |
| rustc / cargo | 1.99.1 (58cf8f9c3 2026-10-13) / 1.99.1 (5f94df478 2026-08-27), Homebrew |
| SQLite (Homebrew, динамическая линковка) | 3.54.1 2026-10-16 |
| tcpdump | 4.99.1 (Apple version 161), libpcap 1.10.1 |
| `net.inet.tcp.syncookie` / `rst_rlc_enable` / `rst_rlc_bucket_ms` | 1 / 1 / 200 (`sysctl.txt`) |

## 6. Результаты

### Окно, попытка 1: `session-05ab27f` — **NOT RUN**

Оркестратор rc 10, UI rc 1 «Authorization timed out» после 180 с. `studio-verify` rc 2, overall **NOT RUN**
(`verification/session-05ab27f.verdict.json`, `.verify.log`): chronicle «the session ended before any Start», кейсы NOT RUN. Свидетели:
uplink 0 кадров, пир 2 кадра. Причина по журналу службы авторизации: диалог Authorize Studio показан в 20:27:13.451, учётные данные не
отправлялись (пароль пользователя ушёл в диалог действия B в 20:26:21), вызывающая сторона снята в 20:30:13 (-60008). Это не дефект кода.
Попытка не повышена и не повторяется в счёт.

### Окно, попытка 2: `session-05ab27f-r2` — **PASS** 7/7

Оркестратор rc 0; `studio-verify` rc 0: `safety`, `chronicle`, `history`, `s1_full`, `s2_pause`, `s3_stop`, `wire` все PASS (fail 0, invalid 0,
not run 0). Действия сессии по плану: `Authorize, Start:s1_full, Start:s2_pause, Pause, Resume, Start:s3_stop, Stop, Lock`; авторизация ровно один
раз; сетевая проверка (preflight) прошла до первого Start; сессия runner закрыта после Lock.

| Кейс | Задание | Результат | SYN на проводе | Rows в SQLite | Замер |
| --- | --- | --- | --- | --- | --- |
| `s1_full` | `80,443,8000-8007,9000-9009`, 20 probe, rate 100, seed 1 | **PASS**, Completed | 20 = весь план в порядке плана, без дублей | 20, из них 8 open (`8000-8007`), ответ на каждую строку, ответа без строки нет | n/a |
| `s2_pause` | `9000-9031`, 32 probe, rate 4, seed 2, Pause через 1.5 с после Scanning | **PASS**, Scanning > Saving > Paused > Scanning > Completed | 32: ветка 1 = 7, ветка 2 = 25, без пропусков и дублей | 32 | `pause_to_paused_ms` **3090** (порог 5000); `next_index` **7** = число SYN первой ветки; текст ACK «Checkpoint committed by Studio» |
| `s3_stop` | `1-2000`, rate 300, seed 3, Stop через 1.5 с после Scanning | **PASS**, Stopped | 471 из 2000, префикс плана, 0 SYN позже Stopped + 100 мс | 439 | `stop_to_stopped_ms` **50** (порог 1000) |

Остальное `verdict.json`: после ветки Stop в истории `checkpoint_len` 0 и `next_index` null; `chronicle` — UTC и монотонные часы согласованы
(разброс 0.001 с при допуске 0.132 с); история содержит ровно три запланированных скана; вне окон кейсов 0 SYN сканера; каждый одноадресный
кадр сканера это SYN с source port 40000 на `198.18.0.2`.

Изоляция: uplink-pcap 24 байта (пустой), `tcpdump` счёл 0 кадров по фильтру лаборатории, drop 0; пир 1046 кадров, captured = pcap = 1046,
kernel drop 0. `status-pre/post` оба `raw_run_allowed: true`; перед окном `bpf_access: granted`.

### Dry run и отказ ворот до стенда (контрольные, не доказательство)

- `dryrun-05ab27f`: rc 0, UI rc 1 «Authorization failed», нет диалога и процессов; `studio-verify` на нём **NOT RUN** rc 2
  (`verification/dryrun-05ab27f.summary.txt`, `.verify.log`). INVALID по host-listeners ожидаем: dry run не записывает слушателей хоста.
- `gate-05ab27f`: до подъёма стенда оркестратор отказал: **NOT RUN** rc 2, напечатал действие B; кадров нет
  (`verification/gate-refusal-05ab27f.summary.txt`).

### Ручной проход UI (действие E)

**NOT RUN**: пользователь пропустил. Автоматическая сессия проходит тот же код, что и клики, но ручной проход глазами не записан.

## 7. Хэширование и полнота

- `shasum -a 256 -c hashes-before-copy.txt` в каталоге окна до копирования: 0 несовпадений (в репозитории для `session-05ab27f` ожидаемо отсутствует только удержанный `peer.pcap`) в `session-05ab27f` (29 файлов) и
  `session-05ab27f-r2` (29 файлов); то же на копии в репозитории после копирования.
- **Приватность.** `session-05ab27f/peer.pcap` (попытка 1) не включён в репозиторий: его 2 кадра это только собственные mDNS-объявления
  и запросы хоста на `feth4202` (имя хоста и названия домашних устройств), кадров лаборатории и сканера в нём нет. Его sha256
  (`deb24aca7105d58c252162d00f9628b6ce16d7e39c4da2642d70e04143891559`) остаётся строкой в `session-05ab27f/hashes-before-copy.txt`
  как запись о захвате; файл никогда не входил в опубликованный коммит. Попытка 1 **NOT RUN** независимо от этого файла. Шаг процедуры на
  будущее: просматривать `tcpdump -r peer.pcap 'not tcp'` до копирования.
- `data/` (SQLite и lock) в репозиторий **не** копируется (`sqlite3` вне allowlist guard); история представлена `history.json` (снят кодом
  Studio через `studio-store` после выхода UI) и `data.sha256` (хэш файла SQLite после дампа). `window.json` хранит
  `data_sha256_before_dump`; два хэша различаются по построению. Оригиналы остаются в `$SCRATCH` до коммита отчёта.
- `MANIFEST.sha256` (73 строки) покрывает все файлы каталога, кроме самого себя; `shasum -a 256 -c MANIFEST.sha256` даёт 0 несовпадений.
  `verdict.json` r2 лежит в каталоге окна и не входит в `hashes-before-copy.txt` (написан после); он в MANIFEST.
- Личные пути скраблены при записи (`$HOME`, `$REPO`, `$SCRATCH`); в обоих каталогах окна личных путей нет. Логи тестов и сводки в
  `verification/` скраблены при копировании (имя хоста заменено на `$HOSTNAME`); журналы тестов сокращены до строк `Running`,
  `Finished`, `test result`.
- Расширения только `json pcap txt log err sha256 md png`; pcap без сжатия; `bash scripts/language-guard.sh` PASS на добавленных файлах.

## 8. Исторический сбор

Не применимо: окно единственное (две попытки), старые окна не собирались. Предыдущие приёмки: engine на `feth`
([приёмка macOS BPF](2026-10-25-rmasscan-macos-bpf-acceptance.md)), не пересчитывались.

## 9. Ошибки и ограничения

1. **Грант BPF на окно.** Пока действует грант (от B до F, около 23 минут обеих попыток), `/dev/bpf*` открыты для группы `staff`: любой
   процесс staff на этом Mac мог бы открыть BPF и писать в любой интерфейс. Грант нужен независимым свидетелям `tcpdump`, не root-runner.
   Защита этим этапом не доказывается; доказательство изоляции это uplink-захват (0 кадров). После `down` права `0600 root:wheel` (§4).
2. **`feth` не физический NIC.** Пара копирует кадры в ядре; поведение USB/Thunderbolt Ethernet, блокировки `write()` и потерь ниже BPF
   не проверено. **NOT RUN**.
3. **Один Mac и одна версия macOS** (27.0.1, arm64, M-серия); другие версии, macOS 14 в частности, живьём **NOT RUN** (CI на macos-14
   гоняет только офлайн-тесты).
4. **Resume после перезапуска Studio на raw: NOT RUN** (действие E не делалось). Путь доказан на Simulation, а raw-дельта (повторное
   открытие адаптера на Resume) покрыта `s2_pause` внутри одной сессии; дефект именно в связке «новая сессия + сохранённый checkpoint»
   остаётся **OPEN**.
5. **Sleep/wake и VPN: NOT RUN.**
6. **Диалог Authorize может остаться незамеченным все 180 с** (попытка 1: показан в 20:27:13, снят в 20:30:13). Записано как наблюдение,
   поведение не менялось; подробности в §6.
7. **Бандл debug-профиля.** Окно шло на debug-сборке (`build-1793039025527`); release-сборка в живом окне **NOT RUN**.
   Тайминги (`pause_to_paused_ms`, `stop_to_stopped_ms`) относятся к debug.
8. **Граница GO по скоростям.** Скорости 4, 100 и 300 pps на одной цели `198.18.0.2`; перф-скорости и несколько целей этим этапом не
   ловятся (приёмка engine отдельно). **OPEN**.
9. **Формулировки `studio-verify` (код не менялся, замечание на потом).** При отсутствующем Start сообщение «the Start action of the case is in the
   chronicle» выражает ожидание, а не находку (должно читаться «is not»); при `ui_rc` 1 сообщение «INVALID: the UI exited with code 0» выражает
   ожидание. Вердикты (NOT RUN, INVALID) верны. Вторая строка: «window.json has no INVALID mark» в попытке 1 при непустом `invalid_marks`
   читается так же вывернуто. Отдельная правка.
10. **Устаревший текст xtask.** `studio/xtask/src/runner_setup.rs` по-прежнему печатает «raw gate remains closed» после пробы авторизации,
    а `runner_setup_windows.rs` «Raw scanning remains disabled»; для macOS первая строка теперь неточна. Код не менялся этим этапом.
11. **Попытка 1 в архиве.** Хранится как свидетельство NOT RUN, а не как повтор, скрывающий отказ.

## 10. Ревью

| Задача | Ревью | Итог |
| --- | --- | --- |
| 1 шлюз по профилю (`8cac448`, `5df4c19`) | Opus | замечаний по небезопасному пути нет; I1 (CI Studio не запускался) закрыт PR #29; I2 исправлен; 5 минорных |
| 2 `--smoke-feth` (`d56d271`, `1b13b0d`) | Opus | замечаний безопасности нет; мутанты и пути отказа закрыты раундом 1 |
| 4 `studio-verify` (`dd4cfe6`…`bef9c80`) | Opus, перепроверка | C1, C2, I1–I4, I6 исправлены; I5 (до Start) исправлен раундом 2 |
| 3 оркестратор (`bd9ee39`, `3113a85`) | Opus | безопасность и контракт подтверждены; I1–I4 исправлены раундом 1 |
| 0 baseline (`9ffa4d9`) | без отдельного ревью | факты проверены механически; закрывается итоговым ревью |
| Итоговое ревью ветки (Opus), `0bb9767..c7db0c5` | **CHANGES**: 0 критичных, 2 важных, 13 минорных | I1 приватность (peer.pcap попытки 1, исправлено до push), I2 запись слушателей хоста (исправляется в lab/xtask/docs без нового окна); см. раунд исправлений |
| Узкое повторное ревью после раунда исправлений | **PENDING** | пишет контролёр; GO условный до **APPROVED** |

## 11. Перепроверка после исправлений

Не было: после заморозки `C` код не менялся; окно шло на `C`. Если итоговое ревью потребует правки `studio-runner`, `studio-protocol`,
`studio-platform` или `rmasscan-*`, окно повторяется (B, D, F) минимум для `s1_full` и `s2_pause` на исправленном коммите; при правках
только `studio-ui`/xtask/lab/docs архив пересчитывается исправленным верификатором. Раунд исправлений после итогового ревью менял только xtask, lab и документы и пересчитал архив (§10); runner и окно не затронуты.

## 12. CI

**CI на точном HEAD: PENDING.** Запись добавляет контролёр после push.

| Прогон | Коммит | Результат |
| --- | --- | --- |
| Черновой PR #29: Studio (macos-14, ubuntu-24.04, windows-2022), rmasscan (3 ОС + package), language-guard | `5df4c19` | success (журнал контролёра); не точный HEAD |
| `rmasscan`, `Studio`, `language-guard` | `C` `05ab27f` | success (журнал контролёра, `gh run list`); код финального HEAD совпадает с `C` байт в байт, но сам HEAD другой |
| `rmasscan`, `Studio`, `language-guard` | точный финальный HEAD | **PENDING (pending controller)** |

Ручные прогоны рабочей области (не CI), `C` = `05ab27f`:

| ОС | Прогон | Итог |
| --- | --- | --- |
| macOS (Mac разработчика) | `cargo xtask test` в `studio/` (`verification/test-studio-mac-05ab27f.log`) | 121 passed / 0 failed / 2 ignored |
| macOS (Mac разработчика) | `cargo test --locked --workspace` в `rmasscan/` (`verification/test-rmasscan-mac-05ab27f.log`) | 1268 passed / 0 failed / 23 ignored |
| Linux (minipc) | на `C`: guard, clippy, `cargo test --locked --workspace` в `rmasscan/` (`verification/test-rmasscan-linux-05ab27f.log`) | guard PASS, clippy rc 0, **1147 passed / 0 failed** / 14 ignored |
| Windows 11 (гость) | на `C`, полное дерево: clippy, `cargo test --locked --workspace` (`verification/test-rmasscan-windows-05ab27f.log`) | clippy rc 0, **1077 passed / 0 failed** / 34 ignored |

Первый прогон на Windows (57 падений) был ошибкой стенда контролёра: tar не включил `docs/` и `.github/`, которые читают эти тесты; прогон повторён на полном дереве и дал строку выше. Падения первого прогона не относятся к коду.

Живые `feth`-окна в CI не идут (комментарий в `.github/workflows/studio.yml`): CI компилирует и гоняет только офлайн-тесты Studio и
rmasscan. Первая сборка на `3113a85` дала такой же прогон тестов (studio 121/0, rmasscan 1268/0) до заморозки `C`.

## 13. Заявление о готовности

**Статус: GO (feth), conditional on §12 CI and §10 review** — только для «Studio raw (Mac feth)»; остальные статусы не меняются.

- Одна авторизованная сессия Studio на запечатанной паре `feth`, код `C` `05ab27f`, PASS 7/7 (`s1_full`, `s2_pause`, `s3_stop`, safety,
  chronicle, history, wire); 0 кадров лаборатории на `en0`, 1046 кадров у свидетеля на пире (§6).
- Pause: checkpoint до ACK, `next_index` 7, `pause_to_paused_ms` 3090 мс; Stop: 50 мс, 0 SYN после Stopped (§6).
- Попытка 1 NOT RUN (Authorize без ответа), не повышена (§6, §9).
- Стенд и грант сняты: rc 3 «no stand recorded», BPF `0600 root:wheel` (§4).
- Тесты Mac на `C`: Studio 121/0, rmasscan 1268/0. Linux 1147/0 и Windows 1077/0 на `C`: PASS. CI на финальном HEAD и узкое повторное ревью: **PENDING**.

Это заявление **не** распространяется на:

| Область | Статус |
| --- | --- |
| Studio raw (Windows/Linux, physical NIC) | **NOT RUN / OPEN** (шлюз закрыт вне macOS) |
| Физический NIC macOS | **NOT RUN** |
| Resume после перезапуска Studio на raw | **NOT RUN** |
| Ручной проход UI (E) | **NOT RUN** |
| Sleep/wake, VPN | **NOT RUN** |
| Release-сборка, другие версии macOS, другие Mac | **NOT RUN** |
| Перф-скорости, несколько целей | **OPEN** |
| Раздел 5 готовности: остальное в схеме runner (Windows/Linux raw, physical NIC) | **OPEN** |
