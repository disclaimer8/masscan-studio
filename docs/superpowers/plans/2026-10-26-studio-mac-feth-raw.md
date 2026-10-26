# Studio: настоящий raw-скан на стенде `feth` (Mac) и открытие release gate профиля Mac feth — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** провести настоящий raw-скан из Slint Studio на запечатанной паре `feth4201`/`feth4202`: UI → авторизованный
root-runner (установленная hash-адресуемая копия, запуск через системный диалог администратора macOS) → engine
`rmasscan` → BPF-адаптер macOS → `feth4201` → пир `feth4202`; доказать это живой приёмкой с независимым захватом (пир
`feth4202` и uplink `en0`, на `en0` 0 кадров лаборатории), с проверкой результатов по истории Studio (SQLite) и по
проводу; после этого открыть release gate **только для профиля Mac feth** (`studio_protocol`, путь `Backend::MacFeth`
в `studio/crates/studio-runner/src/main.rs`). Raw-профили Windows/Linux и физические NIC остаются закрытыми.

**Architecture:** продуктовый код меняется минимально: (1) булев шлюз `RAW_SCANNING_ENABLED` становится функцией
профиля и платформы `raw_profile_enabled(Backend) -> bool` (compile-time, не настраивается пользователем), истинной
только для `MacFeth` на macOS; (2) runner отказывает профилю `MacFeth`, если он не root, ДО preflight и ДО открытия
адаптера; (3) UI получает автоматизируемый режим `--smoke-feth` (тот же путь, что клики: `Action::Authorize` →
`Action::Start(MacFeth)` → Pause/Resume/Stop → `Action::Lock`), пишущий хронику в JSON; (4) оркестратор живой
приёмки `cargo xtask feth-acceptance` (macOS) ставит ворота стенда, независимых свидетелей `tcpdump` на `feth4202` и
`en0`, listeners пира, запускает упакованный UI в режиме `--smoke-feth`, выгружает историю SQLite в `history.json`,
хэширует и держит interlock uplink; (5) офлайн-верификатор `rmasscan-lab studio-verify` сверяет провод, хронику UI и
историю (exactly-once, порядок по плану, результаты, pause/resume/stop, ACK checkpoint). Stand создаёт и убирает
пользователь (`rmasscan-lab macos-lab`), Studio стенд не создаёт.

**Tech Stack:** Rust 1.99.1, Slint (как в `studio/`), SQLite системный/Homebrew (как в `studio/README.md`),
`rmasscan` текущий `main`, `rmasscan-lab` (`macos-lab`, `peer listen`, `pcap`), системные `/usr/sbin/tcpdump`,
`/usr/libexec/ApplicationFirewall/socketfilterfw`, `/usr/sbin/lsof`, `/bin/ps`. Без Python, C, Swift.

**Spec:** [кроссплатформенная спека](../specs/2026-10-23-cross-platform-qt-rust-design.md) §5 (runner, строки 303–345),
§6 (checkpoint и ACK, строки 462–525), §10.2–10.3 (строка R «runner», строки 682–716);
[приёмка macOS BPF](../../experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md) (§4 топология, §6 части A/B/C и
`macos_live`, §9 уроки, §11 процедура окна); [стенд feth](../../../rmasscan/docs/macos-feth-lab.md);
[готовность](../../experiments/2026-10-24-rmasscan-readiness.md) (строки «Studio integration», раздел 5 «runner»);
`studio/AUTHORIZATION.md` («Fixed macOS feth preflight», «Acceptance still required»), `studio/VERIFICATION.md`
(2026-10-26: подтверждённый elevated session, установленный helper `3b1acf…`, `CheckNetwork ready=false` без манифеста),
`studio/README.md` («Repeatable UI smoke», «macOS and Linux session authorization»).

Репозиторий: `$REPO`, worktree `$REPO`, ветка `feat/studio-mac-feth-raw` от
`main` `0bb9767`. Репозиторий Rust-only.

## Исходное состояние и порядок

- Шлюз: `studio/crates/studio-protocol/src/lib.rs:16` `pub const RAW_SCANNING_ENABLED: bool = false`. Читают его:
  runner `raw_adapter` (`studio-runner/src/main.rs:56–66`: `MacFeth` → шлюз → `check_feth()` = `inspect_mac_feth`
  → `rmasscan_net::open_explicit(plan.binding()).map(|a| a.io)`), контроллер Start (`studio-app/src/lib.rs:616–627`)
  и Resume (`:679–686`), манифесты `prepare-runner` (`xtask/src/runner_setup.rs:56`, `runner_setup_windows.rs:62,86`),
  CI-пробы Linux/Windows (`xtask/src/linux_acceptance.rs:22`, `windows_acceptance.rs:177`), тест
  `incomplete_raw_integration_refuses_before_opening_an_adapter` (`studio-runner/tests/controller.rs:131–156`).
- Неавторизованный raw Start в контроллере сейчас `return Err("Authorize the runner before starting a raw scan")`
  (`lib.rs:623–627`), что через обработчик ошибки шага (`:849–875`) даёт `Update::State(Interrupted, …)` и закрытие
  клиента; шлюзовая ветка (`:619–622`) даёт `State(Failed, …)` и `return Ok(())`.
- Preflight Studio `studio-platform/src/network.rs`: манифест только `/private/var/run/rmasscan-lab/m1.json`
  (`:316`), команды с дедлайном 5 с и лимитом 2 MiB (`:254–305`), `validate` (`:119–251`): манифест `sealed` и
  константы, `feth4201` без inet, `feth4202` = `198.18.0.2/30`, default route как в манифесте, маршруты `198.18.0.1`
  → `feth4202`, `198.18.0.2` → `feth4202`/`lo0`, `8.8.8.8` не через `feth`, таблица маршрутов, мосты, перекрытия
  адресов, постоянная ARP `198.18.0.1 → 02:ac:00:00:00:01` на `feth4202`, forwarding 0; MAC сравниваются строго
  (`iface`, `:94–97`) — заполнитель Darwin `02:00:00:00:00:00` даёт «MAC changed or unavailable». Манифест
  перечитывается после наблюдений (`:374`).
- Стенд `rmasscan-lab macos-lab status` (`macos_lab.rs:561–723`, `:1473–1497`): те же правила 1–7 плюс
  `bpf_nodes`/`bpf_access`, `lab_routes`; заполнитель MAC принимается **только** не-root процессом против
  запечатанного манифеста (`mask_ok`, `:567–569`), root обязан видеть настоящие MAC. `raw_run_allowed` не требует
  `granted`.
- Адаптер macOS (`rmasscan-net/src/macos/adapter.rs:556–575`, `:669–674`): перебор `/dev/bpf0..`, `EACCES` →
  `PermissionDenied` с подсказкой `bpf-access --grant`; root открывает узлы `0600 root:wheel` без гранта.
  Независимые свидетели (`tcpdump` от пользователя) гранта **требуют** (`macos-feth-lab.md`, «Live adapter tests»,
  приёмка macOS §4: грант на сессию, revoke/down в конце).
- Сессия root: `studio-platform/src/macos.rs:117–169` (`osascript … with administrator privileges`, 180 с на
  авторизацию, 10 с на Hello), `Client::authorize` (`studio-app/src/lib.rs:206–219`) пинит hash runner из бандла
  (`file_hash(source)`) и ждёт ровно установленный `/Library/PrivilegedHelperTools/MasscanStudio/<sha256>/studio-runner`.
  Сессия обслуживает последовательные сканы; `Lock` закрывает (`README.md:64–70`). Установленный сейчас helper
  `3b1acf…` относится к прежнему коду: любой коммит, меняющий байты runner, требует новой установки.
- Runner: один активный attempt, `Pause` → engine `Paused` → `Event::Checkpoint` (receipt, дедлайн ACK 10 с после
  записи, `main.rs:24–42`, `:359–384`) → контроллер коммитит FULL (`studio-store/src/lib.rs:287–306`, `:346–352`) →
  `AckCheckpoint` → runner `Finished{Paused, "Checkpoint committed by Studio"}` (`main.rs:299–313`). `Resume` → новый
  attempt → `raw_adapter` открывается заново (`:250`).
- UI smoke: `studio-ui/src/main.rs:293–296`, `:754–963` (`--smoke`, `--smoke-pause`, `--smoke-stop-race`; всегда
  Simulation; дедлайн 25 с; `STUDIO_SCREENSHOT`). Backend в форме: индекс 0 = `MacFeth` («Mac feth · not enabled
  yet», `ui/main.slint:490`), 1 = Simulation.
- История: `studio-store` (`scans`, `results` с PK `(scan,ip,port)`, `discovered_at`, `checkpoint`, `next_index`,
  `sequence`), `Store::open`/`scans`/`rows`/`observations` (`lib.rs:58–154`, `:213–257`), `instance.lock`.
- Лаборатория: `peer listen --open 8000-8007 --ready FILE` на macOS биндит `198.18.0.2` только если адрес на
  `feth4202` (`peer.rs:540–565`); `pcap::read_pcap_records`/`is_syn` (`pcap.rs:5,58`); восстановление порядка plan
  через `ProbeCursor` (`verify.rs:385–452`, `plan_frames`); хэши до копирования (`macos_suite.rs:474–495`).
- Доказанное ранее и не повторяемое здесь: engine на `feth` (A 29 PASS, C 21 PASS, B 17 PASS + linkloss INVALID,
  `macos_live` 6/6, 0 кадров на `en0` в 60 захватах), elevated session с `1b397f…`/`3b1acf…`, `--smoke-pause`.

Порядок: **0 — база и контракты (чтение) → 1 — шлюз по профилю и отказ не-root (офлайн) → 2 — `--smoke-feth`
(офлайн-тесты машины состояний) → 3 — `cargo xtask feth-acceptance` (офлайн-тесты помощников) → 4 —
`rmasscan-lab studio-verify` (офлайн, мутации) → ревью кода, заморозка коммита `C` → 5 — живое окно на стенде
(действия пользователя B–D, затем F) → 6 — отчёт, readiness, CI, итоговое ревью, GO**. Задачи 1–4 не ждут стенда;
живая часть без стенда NOT RUN и CI не подменяется.

## Global Constraints

- **Pure Rust.** Никакого C, C++, Python, Swift ни в репозитории, ни в инструментах, ни в CI; language guard
  (`scripts/language-guard.sh`) PASS; новые файлы evidence только из allowlist (`json pcap txt log err sha256 md png`),
  pcap без сжатия. `unsafe` только там, где уже разрешён (`studio-platform` FFI, `rmasscan-net` FFI-модули); все
  новые crates/модули этого плана `#![forbid(unsafe_code)]`. В репозитории Python нет ни в каком виде; ad hoc
  `python3` в своей оболочке агенту не запрещён, но ничего от него не зависит.
- **Не ломать построенное Codex в `studio/`.** Изменения минимальны и изолированы (перечень в карте файлов); каждый
  существующий studio-тест остаётся зелёным; единственный тест, чьё ожидание меняется осознанно, это
  `incomplete_raw_integration_refuses_before_opening_an_adapter` (на macOS он теперь доказывает отказ **неавторизованному**
  raw Start без диалога и без адаптера; на Linux/Windows прежний текст). Поведение Windows и Linux не меняется: raw там
  закрыт (`raw_profile_enabled` ложна для всего), Authorize/Lock, pipe, pkexec, UAC как были.
- **Живые кадры только на запечатанном стенде `feth`** (`macos-lab status` `raw_run_allowed: true` до и после каждого
  окна), захват uplink `en0` с фильтром лаборатории в **каждом** живом прогоне и **0 кадров лаборатории на `en0`**
  (кадр на `en0` это FAIL без права повтора, оркестратор завершается кодом 13); сканируется только `198.18.0.2`
  (`Job::prepare` это уже требует, `studio-protocol/src/lib.rs:89–93`); никаких изменений default route, DNS, pf,
  firewall, реальных NIC; никакого promiscuous.
- **Действия пользователя.** Каждый `sudo`, диалог администратора macOS (установка runner и Authorize), подъём и снятие
  стенда делает пользователь; команды в таблице «Действия пользователя» это голые команды для Terminal (не через
  `!`, sudo там не спросит пароль); их число минимально: один chained ввод «установить runner + up + grant», один
  диалог Authorize на всю автоматическую сессию, одно `down` (оно же revoke). Никакого revoke/grant посреди окна
  (прогоны с отказом прав в этот план не входят: они доказаны приёмкой engine). Root-runner открывает BPF сам; грант
  нужен **только** независимым свидетелям `tcpdump` и это доказывается чтением кода (задача 0), а не предположением.
- **Автоматизируемая приёмка через UI.** Доказательства не зависят от ручных кликов: режим `--smoke-feth` упакованного
  `studio-ui` проходит тот же код, что клики (`Action::*` контроллера, `Client::authorize`, история SQLite). Один ручной
  проход UI записывается как дополнительное свидетельство (действие E, необязательное) и не заменяет автоматический.
- **Правила доказательств как в приёмке macOS BPF:** независимый захват пира и вердикты верификатора; INVALID/NOT RUN
  никогда не повышаются; sha256 всех файлов до копирования (`hashes-before-copy.txt`), затем `MANIFEST.sha256` на
  каталог; pcap без сжатия; личные пути скраблены (`$HOME`, `$REPO`, `$SCRATCH`) ещё при записи, чтобы хэши не
  пересчитывались.
- **Гигиена агентов.** Каждый агент работает в фиксированном приватном `CARGO_TARGET_DIR` по роли
  (`$SCRATCH/target-impl`, `$SCRATCH/target-review`, `$SCRATCH/target-live`), `CARGO_INCREMENTAL=0`,
  `SQLITE3_LIB_DIR="$(brew --prefix sqlite)/lib"` для `studio/`; каталоги не делятся между ролями и удаляются по
  окончании роли; `studio/dist/` прежних сборок и `$SCRATCH/*-out` прежних окон удаляются. Никакой самодельной
  сложности: ни одного механизма, которого цель не требует (нет нового протокола IPC, нет runtime-переключателя
  шлюза, нет feature-флага сборки, нет демона, нет нового верификатора pcap в Studio: pcap читает `rmasscan-lab`).
- **GO только при зелёном CI на точном HEAD** (workflows `rmasscan`, `Studio`, `language-guard`: `ubuntu-24.04`,
  `macos-14`, `windows-2022`) и после полных тестов на трёх ОС (Mac: `cargo xtask test` в `studio/` и
  `cargo test --locked --workspace` в `rmasscan/`; minipc Linux; гость Windows VM) перед push.
- Runtime остаётся: IPv4/TCP, один адаптер, source `198.18.0.1`/`02:ac:00:00:00:01`, next hop `02:ac:00:00:00:02`,
  source port 40000, wait 3 с, retries 0 (`Job::prepare`). Физические NIC, Windows/Linux raw, discovery/ARP, сон/VPN
  в этот этап не входят.

## Review Focus

1. **Шлюз открыт ровно для одного профиля на одной ОС.** `raw_profile_enabled(Backend::MacFeth)` истинна только при
   `cfg(target_os = "macos")`; `Simulation` и `Archived` всегда ложь; Windows/Linux UI показывают прежний отказ;
   манифесты `prepare-runner` несут список открытых профилей; тест на каждой ОС (задача 1).
2. **Ничего под root до preflight, ничего в сеть до открытия адаптера.** Runner-не-root отказывает `MacFeth` до
   `inspect_mac_feth`; `inspect_mac_feth` строгий (заполнитель MAC не принимается), `open_explicit` только после
   `Ok`; Resume открывает адаптер заново через тот же путь; неавторизованный Start в контроллере = `Failed` без
   диалога и без runner (задачи 1, 4, 5).
3. **Автоматический UI-прогон это тот же код, что клики.** `--smoke-feth` не обходит контроллер, не вызывает runner
   напрямую, не трогает SQLite сам; хроника пишется из `Update`-ов; сравнение хроники с историей и проводом делает
   верификатор, а не UI (задачи 2, 4).
4. **Независимость свидетелей и шлюз доказательств.** `tcpdump` на `feth4202` и `en0` это не продуктовый код; статус
   стенда до/после; хэши до копирования; `history.json` снят из SQLite после выхода UI (не из UI); INVALID/NOT RUN не
   повышаются; порядок SYN на проводе равен плану, восстановленному из задания (задачи 3, 4, 5).
5. **Pause/Resume/Stop и ACK вживую.** Checkpoint в SQLite до `AckCheckpoint`; `Paused` с текстом runner «Checkpoint
   committed by Studio»; `next_index` равен числу SYN первой ветки; вторая ветка без пропусков и дублей; после Stop
   ни одного SYN; `stop_to_stopped_ms` и `pause_to_paused_ms` измерены на уровне Studio (задачи 2, 4, 5).

## Карта файлов

- Изменить `studio/crates/studio-protocol/src/lib.rs` (`raw_profile_enabled`, `RAW_PROFILES`, тесты),
  `studio/crates/studio-runner/src/main.rs` (`raw_adapter`: шлюз по профилю, отказ не-root),
  `studio/crates/studio-app/src/lib.rs` (Start/Resume: шлюз по профилю, неавторизованный raw Start → `Failed`),
  `studio/crates/studio-platform/src/network.rs` (текст ошибки при заполнителе MAC),
  `studio/xtask/src/{runner_setup,runner_setup_windows,linux_acceptance,windows_acceptance}.rs` (манифест
  `raw_profiles`, проверки «закрыто на этой ОС»), `studio/crates/studio-runner/tests/controller.rs` (ожидание по ОС),
  новый тест `studio/crates/studio-runner/tests/raw_profile.rs`.
- Изменить `studio/crates/studio-ui/src/main.rs` (`--smoke-feth`, модуль `smoke_feth`), создать
  `studio/crates/studio-ui/src/smoke_feth.rs` (машина состояний и хроника, офлайн-тесты), `studio/crates/studio-ui/ui/main.slint`
  (подпись профиля).
- Изменить `studio/xtask/src/main.rs` (подкоманда `feth-acceptance`, macOS), `studio/xtask/Cargo.toml`
  (`[target.'cfg(target_os = "macos")'.dependencies] studio-store`), создать `studio/xtask/src/feth_acceptance.rs`.
- Создать `rmasscan/crates/rmasscan-lab/src/studio_verify.rs` и `studio_verify_tests.rs`; изменить
  `rmasscan/crates/rmasscan-lab/src/{lib,main}.rs` (подкоманда `studio-verify`), `rmasscan/docs/macos-feth-lab.md`
  (раздел «Studio acceptance»).
- Создать `docs/experiments/2026-10-26-studio-mac-feth-raw-baseline.md`,
  `docs/experiments/2026-10-26-studio-mac-feth-raw-acceptance.md`,
  `docs/experiments/2026-10-26-studio-mac-feth-raw-acceptance-raw/{session-<sha>/,manual-<sha>/ (если было),verification/,MANIFEST.sha256,README.md}`.
- Изменить `studio/README.md`, `studio/AUTHORIZATION.md`, `studio/VERIFICATION.md`,
  `docs/experiments/2026-10-24-rmasscan-readiness.md` (строка «Studio integration» делится: «Studio raw (Mac feth)»
  и «Studio raw (Windows/Linux, physical NIC)»), `.github/workflows/studio.yml` (только комментарий: живой `feth`
  в CI не идёт).

## Константы (единые для всех задач)

| Параметр | Значение |
| --- | --- |
| Стенд | `m1`: `feth4201` (сканер, `02:ac:00:00:00:01`, без IPv4) ↔ `feth4202` (пир, `02:ac:00:00:00:02`, `198.18.0.2/30`), манифест `/var/run/rmasscan-lab/m1.json` (= `/private/var/run/…`, путь preflight Studio) |
| Задание Studio | `targets 198.18.0.2`, `exclusions ""`, source `198.18.0.1`/`02:ac:00:00:00:01`, next hop `02:ac:00:00:00:02`, source port 40000, wait 3 (`Job::prepare`) |
| Пир | listeners `8000-8007` (`rmasscan-lab peer listen`), 80/443 закрыты (bind без root `EACCES`), тихих портов нет (syncookies), RST закрытых портов ограничены (`rst_rlc`), wildcard-слушатели хоста отвечают на `198.18.0.2` (`netstat -an -p tcp` записывается) |
| Сценарии `--smoke-feth` (одна сессия) | `s1_full`: порты `80,443,8000-8007,9000-9009` (20 probe), rate 100, seed 1 → Completed; `s2_pause`: `9000-9031` (32), rate 4, seed 2, Pause через 1.5 с после `Scanning` → Paused (ACK) → Resume → Completed; `s3_stop`: `1-2000`, rate 300, seed 3, Stop через 1.5 с после `Scanning` → Stopped; затем `Lock` |
| Пороги | `pause_to_paused_ms` ≤ 5000 (wait 3 с + commit + опрос UI 50 мс), `stop_to_stopped_ms` ≤ 1000; дедлайн всего smoke 420 с (авторизация до 180 с + сканы) |
| Фильтр uplink | `net 198.18.0.0/30 or (arp and (host 198.18.0.1 or host 198.18.0.2)) or ether host 02:ac:00:00:00:01 or ether host 02:ac:00:00:00:02 or ether proto 0x88b5` (`macos_lab::UPLINK_FILTER`) |
| Свидетели | `/usr/sbin/tcpdump -p -n -U -s 0 -i feth4202 -w peer.pcap` (без фильтра), `/usr/sbin/tcpdump -p -n -U -s 0 -i <uplink> -w uplink.pcap '<фильтр>'`; uplink берётся из `status-pre.json` → `uplink` |
| Ворота окна | `status-pre.json` (`raw_run_allowed: true`, `bpf_access: granted`), `alf.txt` = `Firewall is disabled. (State = 0)`, `lsof -nP -iTCP@198.18.0.2 -sTCP:LISTEN` пусто, `ps` без `wire_scan|tcpdump .*feth420|peer listen|capture dump|studio-ui|studio-runner`, счётчики пары не двигаются в одном из трёх окон по 1 с |
| Каталог evidence окна | `$OUT = $SCRATCH/feth-raw-out/session-<sha>` (rc 13 при кадре на uplink), копия в `docs/experiments/2026-10-26-studio-mac-feth-raw-acceptance-raw/session-<sha>/` после проверки хэшей |
| Установка runner | `/Library/PrivilegedHelperTools/MasscanStudio/<sha256>/studio-runner`; hash = sha256 байт `Masscan Studio.app/Contents/MacOS/studio-runner` того же бандла, что запускается |
| Бюджеты движка (не меняются) | `MAX_IO_TIMEOUT` 50 мс, macOS `IO_BUDGET` 33 мс, Stop ≤ 1 с (измерено на engine 2.9–34.5 мс) |

## Задача 0. База и контракты (чтение, без кода)

**Files:** создать `docs/experiments/2026-10-26-studio-mac-feth-raw-baseline.md`.

**Constraints:** приватный `CARGO_TARGET_DIR` (`target-impl`), `CARGO_INCREMENTAL=0`; ни одного кадра, ни одного
`sudo`, ни одного диалога; стенд только читается (`macos-lab status` без root, rc 3 «no stand recorded» ожидаем).

- [ ] Выписать контракты с номерами строк (проверенные места, не пересказ): шлюз и его читатели (раздел «Исходное
  состояние»), `raw_adapter` (`main.rs:43–75`), ветки Start/Resume контроллера (`lib.rs:613–719`) и обработчик ошибки
  шага (`:849–875`), `Client::authorize` (`:206–219`), `Authorized::open` (`macos.rs:117–169`), `inspect_mac_feth`
  (`network.rs:309–379`, `validate` `:119–251`), `run_checks` и `mask_ok` (`macos_lab.rs:561–569`), `open_device`
  и `GRANT_HINT` (`adapter.rs:70–71`, `:556–575`), checkpoint/ACK (`main.rs:24–42`, `:299–313`, `:359–384`;
  `store/lib.rs:346–352`, `:359–370`), smoke (`studio-ui/main.rs:293–296`, `:754–963`), `peer listen` на macOS
  (`peer.rs:540–565`), `plan_frames` (`verify.rs:385–452`), `read_pcap_records`/`is_syn` (`pcap.rs:5,58`).
- [ ] Таблица соответствия проверок preflight Studio ↔ `macos-lab status` (по строкам кода): манифест/константы,
  интерфейсы и MAC (Studio строго; lab принимает заполнитель только не-root), default route, маршруты, `lab_routes`
  ↔ source/peer/public route и перекрытия, мосты, перекрытие адресов интерфейсов (у lab только в preflight `up`),
  ARP, forwarding, `bpf_nodes`/`bpf_access` (только lab), повторное чтение манифеста (только Studio). Записать вывод:
  наборы не идентичны, но взаимодополняющие; Studio не переиспользует `rmasscan-lab` (решение 2).
- [ ] Доказать чтением, зачем нужен грант: root-runner открывает `/dev/bpfN` при `0600 root:wheel` (root обходит
  биты режима; `open_device` возвращает `EACCES` только не-root), а `tcpdump` свидетелей запускается от пользователя
  и без гранта не откроет BPF (`macos-feth-lab.md` «Live adapter tests», приёмка macOS §4). Записать: грант на окно =
  одно действие, `down` сам выставляет `0600 root:wheel`.
- [ ] Снять состояние только чтением: `"$BIN" macos-lab status --run-id m1` (ожидаемо rc 3 или 2: стенда нет),
  `ls -l /Library/PrivilegedHelperTools/MasscanStudio/` (установленные версии; `3b1acf…` ожидается), `ls studio/dist`,
  `shasum -a 256` runner в последнем бандле, `sysctl -n net.inet.tcp.syncookie net.inet.tcp.rst_rlc_enable`,
  `sw_vers`, `rustc --version`, `brew --prefix sqlite`; записать, что действия пользователя B–D и F потребуются в
  задаче 5, и что ни одна из установленных версий runner не совпадёт с runner коммита `C`.
- [ ] На Mac: в `studio/` `cargo xtask test` (= test + clippy + fmt), в `rmasscan/` `cargo test --locked --workspace`,
  `bash scripts/language-guard.sh`; записать rc и строки `test result`. Записать базу: приёмка macOS BPF (A/C PASS,
  B 17+1 INVALID), `macos_live` 6/6, elevated session `1b397f…` (Hello/CheckNetwork `ready=false` без манифеста/
  CloseSession), `--smoke-pause` упакованного `.app`.
  Commit: `docs(studio): Mac feth raw stage baseline and contracts`.

**GREEN:** документ существует, все цифры с командами, три проверки rc 0, language guard PASS, таблица соответствия
preflight заполнена по строкам кода, вывод о гранте записан.

## Задача 1. Шлюз по профилю и отказ не-root (офлайн, все ОС)

**Files:** изменить `studio-protocol/src/lib.rs`, `studio-runner/src/main.rs`, `studio-app/src/lib.rs`,
`studio-platform/src/network.rs`, `xtask/src/{runner_setup,runner_setup_windows,linux_acceptance,windows_acceptance}.rs`,
`studio-runner/tests/controller.rs`; создать `studio-runner/tests/raw_profile.rs`.

**Constraints:** compile-time, не настраивается пользователем, без env/флагов; ни одной новой команды IPC; Windows и
Linux ведут себя как прежде (`raw_profile_enabled` там ложна для всех профилей, тексты отказов прежние); `forbid(unsafe_code)`
сохраняется; приватный `CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// studio-protocol/src/lib.rs
/// Release gate per profile and platform. Compile-time; never a user setting.
/// Only the sealed Mac feth stand on macOS is open; Windows/Linux raw profiles and physical NICs stay closed.
pub const fn raw_profile_enabled(backend: Backend) -> bool {
    matches!(backend, Backend::MacFeth) && cfg!(target_os = "macos")
}
/// Profiles open in this build (for manifests and reports): `["MacFeth"]` on macOS, `[]` elsewhere.
pub const RAW_PROFILES: &[&str] = if cfg!(target_os = "macos") { &["MacFeth"] } else { &[] };
// `RAW_SCANNING_ENABLED` удаляется (все читатели переводятся; документы VERIFICATION/AUTHORIZATION обновляются в задаче 6).
```

`raw_adapter` (runner): `Backend::MacFeth` → `if !raw_profile_enabled(job.backend) { Err("Raw scanning is not enabled
for this profile in this Studio build …") }` → `#[cfg(unix)] if Identity::current()?.uid != 0 { Err("The Mac feth
profile needs the authorized root runner; Authorize first") }` → `check_feth()?` → `open_explicit`. Порядок: шлюз, root,
preflight, адаптер; никакой ветки не пропускать.

Контроллер: Start/Resume читают `raw_profile_enabled(job.backend)`; неавторизованный raw Start даёт
`emit(State(Failed, "Authorize the runner before starting a raw scan"))` и `return Ok(())` (как шлюзовая ветка), не
`Err` (иначе `Interrupted` и закрытие клиента). Resume без авторизации остаётся `Err("Raw resume is gated; saved
checkpoint is unchanged")` (checkpoint в БД не трогается, тест это пинит).

`network.rs`: в `iface`, когда наблюдённый `ether` равен `02:00:00:00:00:00`, текст ошибки «{name}: MAC os-masked
(Darwin hides MACs from unprivileged processes); the preflight needs the authorized root runner» вместо «MAC changed or
unavailable»; `validate` по-прежнему `Err` (заполнитель никогда не принимается).

Манифесты `prepare-runner` (macOS/Linux/Windows): поле `raw_enabled` → `raw_profiles: RAW_PROFILES`; CI-пробы Linux и
Windows проверяют `!raw_profile_enabled(Backend::MacFeth)` (на этих ОС) и `RAW_PROFILES.is_empty()`.

- [ ] Red `studio-protocol` (unit): `raw_gate_is_open_only_for_mac_feth_on_macos` (таблица: `MacFeth` = `cfg!(macos)`,
  `Simulation` false, `Archived` false; `RAW_PROFILES` согласован с функцией).
- [ ] Red `tests/raw_profile.rs` (runner `--stdio`, без root, на всех ОС): `unprivileged_runner_fails_mac_feth_before_any_adapter`
  — Hello, `Start(Job::example(MacFeth))` → первое событие попытки `Finished{Failed, detail}` без `Started`; на macOS
  `detail` содержит «authorized root runner», на других ОС «only available on macOS» или «not enabled for this profile»;
  runner живёт и принимает `CloseSession`. `check_network_without_root_refuses_and_names_masking_or_manifest` (macOS):
  `CheckNetwork` → `ready=false`, `detail` содержит «stand manifest» (нет стенда) либо «os-masked» (стенд поднят);
  на Linux/Windows прежний текст «unavailable»/«only available on macOS».
- [ ] Обновить `controller.rs::incomplete_raw_integration_refuses_before_opening_an_adapter`: на macOS ожидать
  `State(Failed, detail)` с «Authorize the runner before starting a raw scan», по-прежнему без `Scanning` и без
  `Interrupted`, и затем успешный Simulation Start в том же контроллере (клиент не закрыт); на других ОС прежнее
  ожидание. Добавить `raw_resume_without_authorization_keeps_the_checkpoint` (macOS): сохранённый Paused MacFeth-скан в
  БД (через `Store::begin`/`apply` синтетически, как в `controller_persists_pause…`), `Action::Resume` → `Interrupted`
  с «Raw resume is gated», checkpoint в БД прежний.
- [ ] Red `network.rs` (cfg test, macOS): `masked_mac_is_refused_with_the_root_hint` на синтетическом `Snapshot` с
  `ether 02:00:00:00:00:00`.
- [ ] Реализовать; `cargo xtask test` на Mac; на minipc и госте VM `cargo xtask test` (там `raw_profile_enabled` ложна,
  тесты ожидают прежние тексты). Commit: `feat(studio): per-profile raw gate open for Mac feth; unprivileged runner refuses raw`.

**GREEN:** все studio-тесты PASS на трёх ОС; на Linux/Windows поведение и тексты прежние; clippy/fmt чисты;
language guard PASS; ни одного открытия адаптера ни в одном тесте.

## Задача 2. `--smoke-feth`: автоматический UI-прогон на профиле Mac feth

**Files:** изменить `studio-ui/src/main.rs`, `studio-ui/ui/main.slint`; создать `studio-ui/src/smoke_feth.rs`.

**Constraints:** тот же путь, что клики (`Action::Authorize/Start/Pause/Resume/Stop/Lock` через `Controller::send`,
состояния из `Controller::poll`); UI не читает SQLite и не вызывает runner напрямую; режим работает только на macOS,
только при заданных `STUDIO_DATA_DIR` и `STUDIO_SMOKE_OUT`, только с `Backend::MacFeth`; при любом неожиданном
состоянии (`Failed`, `Interrupted`, `authorized=false` после `busy`, «Network preflight refused», таймаут фазы) —
`Lock`, запись причины и rc ≠ 0 без следующего скана; существующие smoke-режимы не меняются; приватный
`CARGO_TARGET_DIR`.

**Interfaces:**

```rust
// studio-ui/src/smoke_feth.rs  (#![forbid(unsafe_code)] через crate)
pub struct Plan { pub scans: Vec<ScanCase> }           // s1_full, s2_pause, s3_stop (константы плана)
pub struct ScanCase { pub tag: &'static str, pub job: Job, pub pause_after: Option<Duration>, pub stop_after: Option<Duration> }
pub enum Step { Send(Action), Quit { ok: bool, reason: String }, Wait }
pub struct Driver { /* phase, scan index, timers, chronicle */ }
impl Driver {
    pub fn new(plan: Plan, now: Instant) -> Self;
    /// Один `Update` (или тик таймера) → ноль или больше шагов; `Update` записывается в хронику с `now` и UTC.
    pub fn step(&mut self, update: Option<&Update>, now: Instant, utc: String) -> Vec<Step>;
    pub fn chronicle(&self) -> &Chronicle;
}
#[derive(Serialize)] pub struct Chronicle { schema: u32 /* 1 */, started_utc: String, plan: Vec<CaseRecord>, events: Vec<EventRecord>, actions: Vec<ActionRecord>, result: String }
// EventRecord { utc, mono_ms, kind: "Authorization"|"State"|"Notice"|"Progress"|"Rows"|"History", status, detail, rows }
// ActionRecord { utc, mono_ms, action: "Authorize"|"Start:s1_full"|"Pause"|"Resume"|"Stop"|"Lock" }
// CaseRecord { tag, job (как в Job), scan_id_hex (из Update::History после Start), rows_seen, started_utc, finished_utc,
//              finished_status, paused_next_index (из `SavedScan.next_index` в Update::History при Paused), pause_to_paused_ms, stop_to_stopped_ms }
```

Фазы `Driver`: `Authorize` → ждёт `Authorization{busy:false, authorized:true}` и `Notice("Network preflight passed…")`
(любой другой `Authorization{authorized:false}` или «refused» → `Quit{ok:false}`) → для каждого сценария:
`Start(job)` → `State(Starting)` → `State(Scanning)` (запоминает `t_scanning`) → (`pause_after`: через 1.5 с
`Pause` → `State(Saving)` → `State(Paused)` [фиксирует `pause_to_paused_ms`] → `Resume` → `Scanning` → `Completed`;
`stop_after`: через 1.5 с `Stop` → `State(Stopped)` [фиксирует `stop_to_stopped_ms`]) → терминальное состояние
записано → следующий сценарий → после последнего `Lock` → `Authorization{authorized:false, "Runner session closed"}`
→ `Quit{ok:true}`. `scan_id_hex` берётся из `Update::History(data, selected)` после Start (`selected`). `rows_seen`
считает строки из `Update::Rows`. Таймаут фазы 60 с (кроме авторизации: 200 с); общий дедлайн 420 с.

`main.rs`: флаг `--smoke-feth`; `ui.set_backend_index(0)`; таймер 50 мс вызывает `driver.step` для каждого `Update`
и один раз в тик с `None`; `Step::Send` → `action(&a, &ui, …)`; `Step::Quit` → запись `STUDIO_SMOKE_OUT/smoke.json`
(плюс `STUDIO_SCREENSHOT` как у прочих smoke), `quit_event_loop`, rc по `ok`. Запуск без `STUDIO_DATA_DIR`/`STUDIO_SMOKE_OUT`
или не на macOS → ошибка до создания контроллера. Подпись профиля в `main.slint:490`: «Mac feth · isolated stand
(macOS)»; строка 527 без изменений.

- [ ] Red `smoke_feth.rs` (unit, без UI и без сети): `driver_authorizes_then_runs_the_three_cases_in_order_and_locks`
  (синтетическая последовательность `Update`-ов, проверка `ActionRecord` по порядку и `result == "ok"`),
  `preflight_refused_locks_and_fails_without_start`, `failed_state_during_a_case_quits_without_the_next_case`,
  `pause_is_sent_only_after_scanning_and_after_the_delay`, `stop_latency_is_measured_from_the_action_to_stopped`,
  `phase_timeout_quits_with_reason`, `chronicle_serializes_without_personal_paths` (в хронике нет `/Users/`).
- [ ] Red `main.rs` (unit): `smoke_feth_requires_macos_data_dir_and_out_dir` (чистая функция разбора аргументов/окружения).
- [ ] Реализовать; `cargo xtask test`; на Mac проверить офлайн, что `--smoke-feth` без стенда завершается rc ≠ 0 с
  причиной «Authorize…» (установленного runner для нового бандла нет) и ничего не стартует; на Linux (minipc, Xvfb)
  и госте Windows прежние `--smoke-pause`/`--smoke-stop-race` PASS. Commit: `feat(studio): automated Mac feth UI run (--smoke-feth) with a chronicle`.

**GREEN:** unit-тесты драйвера PASS на всех ОС (модуль платформенно-нейтрален, только запуск режима macOS); прежние
smoke не изменились; clippy/fmt чисты; language guard PASS.

## Задача 3. `cargo xtask feth-acceptance`: оркестратор живого окна (macOS)

**Files:** изменить `studio/xtask/src/main.rs`, `studio/xtask/Cargo.toml`; создать `studio/xtask/src/feth_acceptance.rs`.

**Constraints:** macOS only (`cfg(target_os = "macos")`), никакого `sudo` внутри; команды массивами по абсолютным
путям (`/usr/sbin/tcpdump`, `/usr/libexec/ApplicationFirewall/socketfilterfw`, `/usr/sbin/lsof`, `/bin/ps`,
`/usr/sbin/netstat`, `/usr/sbin/sysctl`, `/sbin/ifconfig`); ни одного кадра от самого оркестратора; свидетели
останавливаются `SIGINT`, затем `wait`; `history.json` читается через `studio_store::Store` **после** выхода UI
(`studio-store` только как macOS-зависимость xtask); пути в выходных файлах скраблены (`$HOME`→`$HOME`, `$REPO`, `$OUT`
относительные); приватный `CARGO_TARGET_DIR`.

**Interfaces:** `cargo xtask feth-acceptance --out DIR --app '/abs/Masscan Studio.app' --lab /abs/rmasscan-lab
[--manual]`. Порядок внутри `DIR` (создаётся пустым, иначе отказ):

1. `gates`: `"$LAB" macos-lab status --run-id m1 > status-pre.json` (rc 0, `raw_run_allowed: true`, `bpf_access ==
   "granted"`, `uplink` непустой и не `feth*`), `alf.txt`, `leftover-listeners.txt` (пусто), `leftover-procs.txt`
   (пусто; шаблон из констант плюс `studio-ui|studio-runner`), `pair-quiet.txt` (счётчики `feth4201`/`feth4202` из
   `netstat -I … -b -d -n` трижды с шагом 1 с; отказ, если двигались во всех трёх окнах), `host-listen-before.txt`
   (`netstat -an -p tcp`), `sysctl.txt` (`net.inet.tcp.syncookie`, `rst_rlc_enable`, `rst_rlc_bucket_ms`),
   `sw_vers.txt`; провал любого → NOT RUN, rc 2, ничего не запущено.
2. `provenance.json`: sha256 `studio-ui`, `studio-runner`, `studio-inspect` из бандла, `manifest.json` бандла
   (копия), hash runner и наличие `/Library/PrivilegedHelperTools/MasscanStudio/<hash>/studio-runner` (только `stat`;
   отсутствие → NOT RUN до запуска UI: «install the runner of this exact bundle first»), `git rev-parse HEAD`,
   `git status --porcelain` (dirty → NOT RUN), sha256 `$LAB`, `--version` лаборатории.
3. `peer listen`: `"$LAB" peer listen --open 8000-8007 --ready DIR/listeners-ready.txt` (stdout/err в
   `listeners.log`), ждать файл готовности ≤ 10 с. Имена всех файлов окна из allowlist language guard
   (`json pcap txt log err sha256 png`).
4. Свидетели: `tcpdump` на `feth4202` → `peer.pcap`/`peer.err`, на `<uplink>` с фильтром → `uplink.pcap`/`uplink.err`;
   2 с, оба живы (`kill -0`), иначе NOT RUN с остановкой уже запущенного.
5. UI: `STUDIO_DATA_DIR=DIR/data STUDIO_SMOKE_OUT=DIR STUDIO_SCREENSHOT=DIR/final.png "<app>/Contents/MacOS/studio-ui"
   --smoke-feth` (без `--manual`); с `--manual` — тот же запуск без `--smoke-feth` и ожидание выхода UI (пользователь
   кликает сам и закрывает окно). stdout/stderr → `ui.log`; `ui_rc.txt`.
6. Остановка: 1 с тишины, `SIGINT` свидетелям, `wait` (rc в `peer.err`/`uplink.err`), `SIGINT` listeners, `wait`;
   `host-listen-after.txt`; `status-post.json` (`raw_run_allowed: true`, иначе INVALID-отметка в `window.json`).
7. `history.json`: `Store::open(DIR/data)` → для каждого скана `scan_id_hex`, `attempt_hex`, `job`, `status`,
   `detail`, `next_index`, `checkpoint_len`, `sequence`, `created_at`, `rows[] {ip, port, open, discovered_at}`;
   `instance.lock` после этого свободен.
8. `window.json`: UTC начала/конца, uplink, pid-ы, версии, `ui_rc`, пороги плана; `data.sha256` (sha256
   `data/history.sqlite3`; наличие `-wal`/`-shm` после выхода UI → отметка «history not closed cleanly» = INVALID);
   `hashes-before-copy.txt` (sha256 каждого файла каталога, кроме самого списка и каталога `data/`: SQLite в
   репозиторий не попадает, его представляют `history.json` и `data.sha256`).
9. Interlock без разбора pcap (xtask pcap не читает): `uplink.err` даёт `N packets captured` с `N == 0` и `0 packets
   dropped by kernel`, а `uplink.pcap` имеет размер ровно 24 байта (только заголовок); любой `captured > 0`,
   `dropped > 0` или размер > 24 → rc 13 и файл `ISOLATION-BREACH.txt`; полный разбор pcap делает верификатор.

Выход: 0 (окно закрыто, хэши записаны), 2 NOT RUN, 10 abort (UI умер/таймаут; каталог сохранён для проверки изоляции),
13 isolation breach. Один `--out` на один запуск.

- [ ] Red `feth_acceptance.rs` (unit, без процессов): `gates_require_granted_sealed_stand_and_a_real_uplink`
  (разбор `status-pre.json`: отсутствие `bpf_access: granted` → NOT RUN с причиной; `uplink: feth…` → NOT RUN),
  `firewall_text_must_be_exact`, `leftover_patterns_cover_studio_binaries`, `pair_quiet_refuses_only_when_every_window_moved`,
  `interlock_reads_tcpdump_statistics` (таблица строк `uplink.err`: `0 packets captured` ok; `1 packets captured` →
  breach; `dropped by kernel 1` → breach; отсутствие строки → unproven/NOT RUN), `paths_are_scrubbed_before_writing`,
  `history_json_lists_rows_in_rowid_order_with_checkpoint_presence` (на временной БД через `studio_store::Store` с
  синтетическими `apply`), `runner_of_the_bundle_must_be_installed_before_the_ui_starts` (логика на `stat`-результате).
- [ ] Реализовать; `cargo xtask test` на Mac; на Linux/Windows xtask собирается без `studio-store` (зависимость только
  macOS) и без новой подкоманды. Commit: `feat(studio): feth-acceptance orchestrator (gates, witnesses, UI run, history dump)`.

**GREEN:** unit-тесты PASS; `cargo xtask test` зелёный на трёх ОС; язык guard PASS; команда без стенда даёт NOT RUN
rc 2 на первом же шаге и ничего не запускает (проверяется запуском на Mac без стенда).

## Задача 4. `rmasscan-lab studio-verify`: офлайн-верификатор окна Studio

**Files:** создать `rmasscan/crates/rmasscan-lab/src/studio_verify.rs`, `studio_verify_tests.rs`; изменить
`rmasscan-lab/src/{lib,main}.rs`, `rmasscan/docs/macos-feth-lab.md`.

**Constraints:** `#![forbid(unsafe_code)]`; без сети, без процессов; читает только каталог окна; статусы никогда не
повышаются; порядок probe восстанавливается из задания с константами binding Studio, зафиксированными в модуле (не
зависимость от `studio-protocol`: верификатор независим от кода под тестом); pcap только без сжатия (`*.gz` в каталоге
→ отказ безопасности, как у `macos-verify`); приватный `CARGO_TARGET_DIR`.

**Interfaces:** `rmasscan-lab studio-verify --dir DIR --out DIR/verdict.json [--manual]`; rc 0 PASS, 1 FAIL,
2 INVALID/NOT RUN. `verdict.json`: `{overall, provenance{verifier_sha256, window_sha, ui_sha256, runner_sha256,
installed_runner_sha256}, isolation{uplink_frames, uplink_captured, uplink_dropped, status_pre, status_post},
cases[]{tag, scan_id, status, checks[]{name, ok, detail}}, totals, notes}`.

Правила (каждая проверка именована и покрыта тестом):

- `safety` (первые, при провале остальное не повышается): все `*.pcap` без сжатия; `uplink.pcap` разобран полностью,
  0 кадров; `uplink.err` `captured == 0`, `dropped by kernel == 0`; `status-pre`/`status-post` `raw_run_allowed: true`,
  `status-pre.bpf_access == granted`; `hashes-before-copy.txt` сходится с файлами каталога (кроме `verdict.json` и каталога `data/`);
  `provenance.json`: hash runner бандла == hash, под которым он установлен (`installed_runner_sha256`), `dirty ==
  false`. Нарушение изоляции → FAIL overall без права повтора; неполный захват (`dropped > 0`, обрыв pcap) → INVALID.
- `chronicle`: `smoke.json` `schema 1`, `result == "ok"` (иначе соответствующий кейс FAIL/INVALID по причине), порядок
  действий равен плану (`Authorize`, `Start:s1_full`, `Start:s2_pause`, `Pause`, `Resume`, `Start:s3_stop`, `Stop`,
  `Lock`), авторизация `authorized=true` ровно один раз, `Notice` «Network preflight passed» до первого Start,
  «Runner session closed» после `Lock`.
- `history`: для каждого кейса скан найден по `scan_id_hex`, `job` равен заданию плана (targets/ports/seed/rate/
  backend `MacFeth`), статус: `s1_full` Completed, `s2_pause` Completed (после Resume) и `detail` не пусто,
  `s3_stop` Stopped; `rows` без дублей по `(ip, port)`, все `ip == 198.18.0.2`; `rows_seen` хроники == число `rows`.
- `wire` (из `peer.pcap`, окно кейса `[t_starting − 1 с, t_finished + 1 с]` по UTC хроники; SYN сканера: src MAC
  `02:ac:00:00:00:01`, `198.18.0.1 → 198.18.0.2`, sport 40000): плановая последовательность портов кейса
  восстанавливается как в `plan_frames` (константы Studio: source `198.18.0.1`, MAC `02:ac:00:00:00:01` /
  `02:ac:00:00:00:02`, sport 40000, wait 3, `adapter_name feth4201`); **exactly-once**: мультимножество портов SYN
  кейса не содержит дублей; **порядок**: последовательность SYN равна префиксу плана (Completed: всему плану;
  Stopped: префиксу длины `sent`); SYN одного кейса не попадают в окно другого; SYN вне окон всех кейсов → FAIL.
- `results`: ответы пира в окне кейса (SYN-ACK → open, RST → closed, `198.18.0.2 → 198.18.0.1`, dport 40000,
  ack == seq SYN + 1 для SYN-ACK): каждая `row` подтверждена ответом на проводе с тем же `open`; каждый SYN-ACK на SYN
  этого кейса имеет `open` row (пропущенный RST допустим, `rst_rlc`); для `s1_full` ровно 8 open rows `8000-8007`
  (listeners лаборатории; `host-listen-before/after` учитываются как в `macos-verify`: LISTEN хоста на `*`/`198.18.0.2`
  тоже open); пост-ответы после `t_finished` (демонтаж listeners) только в `notes.post_run_replies`.
- `pause_resume` (`s2_pause`): хроника `Scanning → Saving → Paused → Scanning → Completed`; `pause_to_paused_ms ≤
  5000`; `Paused.detail == "Checkpoint committed by Studio"`; хроника несёт `paused_next_index = k` (из
  `Update::History` на `Paused`); в `history.json` после Resume `checkpoint_len == 0` и `next_index` null (Started их
  очищает), статус Completed; число SYN до `Starting` второй попытки равно `k`; первая ветка = первые `k` портов
  плана, вторая = остальные, объединение без пропусков и дублей (32 порта `9000-9031`).
- `stop` (`s3_stop`): `stop_to_stopped_ms ≤ 1000`; `0 < SYN < 2000`; последний SYN не позже `t_stopped + 250 мс`
  (гранулярность опроса UI 50 мс + запас), ни одного SYN после; `checkpoint_len == 0`, `next_index` null.
- `--manual`: `smoke.json` не требуется; проверяются только `safety`, `history` (без сверки с планом: статус любой
  терминальный) и `results` (rows ⊆ ответов провода; SYN только `198.18.0.1 → 198.18.0.2`); overall по этим правилам,
  с `notes.manual = true`.

- [ ] Red `studio_verify_tests.rs`: генератор синтетического каталога (хроника, `history.json`, `peer.pcap` с кадрами
  по плану через `rmasscan_core` и `pcap::encode`, `uplink.pcap` пустой, `*.err`, статусы, `provenance`, хэши) и тест
  `a_consistent_window_is_pass`; мутации, каждая со своим ожиданием: `a_lab_frame_on_the_uplink_is_fail`,
  `uplink_kernel_drop_is_invalid`, `a_gzipped_capture_is_refused`, `a_changed_hash_is_invalid`,
  `installed_hash_mismatch_is_invalid`, `a_duplicate_syn_is_fail`, `syn_order_off_the_plan_is_fail`,
  `a_syn_after_stop_is_fail`, `stop_latency_over_a_second_is_fail`, `pause_latency_over_five_seconds_is_fail`,
  `paused_without_the_runner_ack_text_is_fail`, `first_leg_not_equal_next_index_is_fail`, `resume_gap_or_duplicate_is_fail`,
  `a_row_without_a_wire_reply_is_fail`, `a_synack_without_an_open_row_is_fail`, `missing_rst_is_tolerated`,
  `rows_seen_not_equal_history_rows_is_fail`, `manual_mode_skips_the_plan_but_keeps_safety_and_results`,
  `verdict_never_upgrades_invalid_to_pass`. Утилиты: `plan_ports_for_job`, `scan_window`, `parse_tcpdump_stats`
  (тесты на таблице строк).
- [ ] Реализовать; `cargo test --locked -p rmasscan-lab` на Mac и Linux (модуль платформенно-нейтрален);
  `macos-feth-lab.md`: раздел «Studio acceptance» (каталог окна, команда `feth-acceptance`, `studio-verify`,
  правила, коды возврата). Commit: `feat(lab): studio-verify for Studio Mac feth windows`.

**GREEN:** тесты PASS на Mac и Linux; clippy чист; `macos-verify` и прочие верификаторы не тронуты; language guard
PASS; документация обновлена.

**Ревью перед окном (после задач 1–4):** свежее ревью ветки (Opus, только чтение) по Review Focus 1–5; исправления;
повтор офлайн-тестов на трёх ОС; заморозка коммита `C` (`git rev-parse HEAD` записывается в задаче 5). Любое
изменение после `C`, затрагивающее `studio-runner`, `studio-protocol`, `studio-platform`, `rmasscan-*`, меняет байты
runner и требует повторной установки (действие B ещё раз) и повторения окна; изменения только `studio-ui`/`xtask`/
`rmasscan-lab`/docs — повторения окна без установки, если sha256 runner в новом бандле равен установленному
(оркестратор это проверяет в `provenance`).

## Задача 5. Живое окно: установка runner, стенд, автоматическая сессия, ручной проход

**Files:** `docs/experiments/2026-10-26-studio-mac-feth-raw-acceptance-raw/{session-<sha>/, manual-<sha>/ (если было),
verification/, README.md, MANIFEST.sha256}`.

**Constraints:** выполняет живой оператор в `$SCRATCH/target-live` (`CARGO_INCREMENTAL=0`) на коммите `C`, чистое
дерево (`git status --porcelain` пусто, иначе оркестратор NOT RUN); бандл из `cargo xtask build` этого коммита; все
`sudo` и диалоги — пользователь (таблица действий); порядок действий ровно как ниже; `--out` каждому запуску новый;
личные пути нигде; pcap без сжатия; никакого `--rerun`: FAIL по изоляции закрывает окно, NOT RUN/INVALID повторяются
новым каталогом с записью причины.

- [ ] **Сборка и подготовка (оператор, без root):** в `studio/` `cargo xtask build` → `APP=…/dist/build-<stamp>/Masscan
  Studio.app` (manifest `dirty: false`, `source_commit == C`); `cargo xtask prepare-runner "$APP/Contents/MacOS/studio-runner"`
  → `RUNNER_DIR=…/dist/runner-<stamp>` (manifest `raw_profiles: ["MacFeth"]`, sha256 `R`); в `rmasscan/`
  `RMASSCAN_LAB_BUILD_COMMIT=$C cargo build --locked --release -p rmasscan-lab` → `LAB`; офлайн `cargo xtask test`
  и `cargo test --locked --workspace` на том же коммите (логи в `verification/`). Сообщить пользователю `RUNNER_DIR`,
  `LAB`, `APP` и попросить действие **B** (одна строка: установка runner + `up` + `grant`).
- [ ] **Ворота после действия B (оператор):** `"$LAB" macos-lab status --run-id m1` → `raw_run_allowed: true`,
  `bpf_access: granted`; `ls -l /Library/PrivilegedHelperTools/MasscanStudio/$R/studio-runner` (root, 0755);
  `cargo xtask probe-authorization "$APP/Contents/MacOS/studio-runner"` **не** выполняется (лишний диалог): Hello/
  CheckNetwork докажет сама сессия smoke.
- [ ] **Автоматическая сессия:** `cargo xtask feth-acceptance --out "$SCRATCH/feth-raw-out/session-$C" --app "$APP"
  --lab "$LAB"`; при появлении диалога администратора пользователь вводит пароль (действие **D**, один раз); оператор
  ждёт rc; затем `"$LAB" studio-verify --dir … --out …/verdict.json`. Ожидание: rc 0 оркестратора, overall PASS, 0
  кадров на uplink, `s1_full` 8 open rows, `s2_pause` ACK и две ветки без пропусков/дублей, `s3_stop` без SYN после
  Stop. INVALID/NOT RUN → причина в README, повтор с новым `--out` (новый диалог D); FAIL → анализ, исправление, ревью,
  при изменении байтов runner — действие B снова.
- [ ] **Ручной проход UI (действие E, необязательное):** `cargo xtask feth-acceptance --manual --out "$SCRATCH/feth-raw-out/manual-$C"
  --app "$APP" --lab "$LAB"`; пользователь в открывшемся окне: Authorize (диалог) → New scan → профиль Mac feth, цели
  `198.18.0.2`, порты `8000-8007`, rate 100 → Check → Start → дождаться Completed → Lock → закрыть окно; оператор:
  `studio-verify --manual`. Если не выполнялось — NOT RUN в отчёте, на GO не влияет.
- [ ] **Закрытие окна:** попросить действие **F** (`down`); `"$LAB" macos-lab status --run-id m1` → rc 3 «no stand
  recorded» / интерфейсов нет; `ls -l /dev/bpf0` → `0600 root:wheel`.
- [ ] **Evidence:** проверка `shasum -a 256 -c hashes-before-copy.txt` в каждом каталоге окна, копия в
  `docs/experiments/…-acceptance-raw/{session-$C,manual-$C}`, повторная проверка хэшей на копии, `MANIFEST.sha256`
  (`shasum -a 256`), `README.md` каталога (ворота, rc, вердикт, версии, замечания), `verification/` (логи тестов трёх
  ОС, `verdict.json`, `final.png`). Каталог `data/` (SQLite) в репозиторий **не** копируется (`sqlite3` вне allowlist
  guard): его представляют `history.json` и `data.sha256`; оригинал остаётся в `$SCRATCH` до коммита отчёта и
  удаляется вместе с `feth-raw-out`. Commit: `test(studio): record Mac feth raw acceptance through Studio`.

**GREEN:** `studio-verify` overall PASS для `session-<C>`; 0 кадров на uplink; `status-pre/post` true; хэши сходятся
до и после копирования; ручной проход записан или честно NOT RUN; стенд снят, BPF `0600 root:wheel`.

## Задача 6. Отчёт, readiness, документы Studio, CI и итоговое ревью

**Files:** создать `docs/experiments/2026-10-26-studio-mac-feth-raw-acceptance.md`; изменить
`docs/experiments/2026-10-24-rmasscan-readiness.md`, `studio/README.md`, `studio/AUTHORIZATION.md`,
`studio/VERIFICATION.md`, `.github/workflows/studio.yml` (комментарий).

**Constraints:** статусы не повышаются; GO только при зелёном CI на точном HEAD и после ревью; все тексты «not
enabled»/«remains disabled» в документах Studio переписываются точно по новому шлюзу (Mac feth открыт, Windows/Linux
закрыты); Python в репозиторий не попадает.

- [ ] Отчёт по образцу приёмки macOS: §1 итог и границы (единый список условий GO «Studio raw (Mac feth)»), §2 коммиты
  и чистота дерева (`C`, HEAD evidence), §3 хэши (UI, runner бандла = установленный, `rmasscan-lab`, верификатор),
  §4 топология и действия пользователя (сколько диалогов и `sudo` фактически было), §5 версии (macOS, Darwin,
  rustc, SQLite, tcpdump), §6 результаты (таблица кейсов с измеренными `pause_to_paused_ms`, `stop_to_stopped_ms`,
  числами SYN/ответов/rows; ручной проход), §7 хэширование и полнота, §9 ошибки и ограничения (грант на окно и его
  риск; `feth` не физический NIC; один Mac/одна версия macOS; resume после перезапуска Studio на raw NOT RUN, если E
  не делалось; sleep/VPN NOT RUN), §10 ревью, §12 CI, §13 заявление.
- [ ] Readiness: строка «Studio integration» делится на «Studio raw (Mac feth)» = **GO (feth)** при выполнении
  критерия ниже и «Studio raw (Windows/Linux, physical NIC)» = **NOT RUN/OPEN**; раздел 5 «runner» получает строки
  «bootstrap macOS: PASS (сессия, hash-pin, cleanup)», «durable checkpoint ACK вживую на raw: PASS/…», остальное OPEN.
- [ ] `studio/README.md`: «Mac feth» абзац (строки 58–62) переписать: профиль открыт на macOS после приёмки, стенд
  создаёт пользователь, ссылка на отчёт; `AUTHORIZATION.md` «Acceptance still required» и строка 128; `VERIFICATION.md`
  новый раздел «2026-10-26 — Mac feth raw through Studio» с хэшами и ссылкой на evidence; `studio.yml` комментарий
  «live feth window is user-run; see docs/experiments/…».
- [ ] Workspace-тесты на трёх ОС перед push (логи в `verification/`); push; CI зелёный на точном HEAD (`rmasscan`,
  `Studio`, `language-guard`); удаление приватных target-каталогов, `studio/dist/` прежних сборок и `$SCRATCH/feth-raw-out`
  записано.
- [ ] Итоговое ревью ветки (Opus): шлюз и отказы, `--smoke-feth`, оркестратор, верификатор, evidence; исправления;
  если менялись `studio-runner`/`studio-protocol`/`studio-platform`/`rmasscan-*` — повторное окно (действия B, D, F)
  минимум для `s1_full` и `s2_pause` на исправленном коммите; если только `studio-ui`/xtask/lab/docs — пересчёт
  архива исправленным верификатором с неизменными вердиктами, окно не повторяется.
  Commit: `docs(studio): Mac feth raw acceptance report and readiness`.

**GREEN:** отчёт существует с единым списком условий; readiness и документы Studio согласованы с шлюзом; CI зелёный на
HEAD; ревью APPROVED.

## GO и дальнейшая очередь

**GO «Studio raw (Mac feth)»:** код принят ревью; CI зелёный на точном HEAD на трёх ОС; на запечатанном стенде `m1` на
коммите `C` автоматическая сессия `--smoke-feth` через упакованный `.app` и установленный runner того же бандла:
`studio-verify` overall **PASS** (`s1_full`: 20 SYN в порядке плана, 8 open rows `8000-8007`, каждая row подтверждена
проводом; `s2_pause`: `Paused` с ACK runner, checkpoint в SQLite, первая ветка = `next_index` SYN, вторая без пропусков
и дублей, `pause_to_paused_ms ≤ 5000`; `s3_stop`: `stop_to_stopped_ms ≤ 1000`, ни одного SYN после Stop, без
checkpoint); 0 кадров лаборатории на `en0`, `captured 0`/`dropped 0`; `raw_run_allowed: true` до и после; hash runner
бандла равен установленному; хэши сходятся; действия пользователя ровно B, D, F (плюс E по желанию). **GO не
распространяется** на Windows/Linux raw-профили, физические NIC, resume после перезапуска Studio на raw (если E не
выполнялось), сон/VPN/смену сети во время скана, macOS 14, дистрибуцию и лицензии.

Далее: **физические NIC (Windows/Npcap стенд, macOS USB-Ethernet) с теми же suite → Windows/Linux raw-профили Studio
(их шлюз остаётся закрытым до своей приёмки) → discovery/ARP и сетевая идентичность (VPN/sleep) → поставка**.

## Решения этого плана (с причиной и ценой ошибки)

1. **Шлюз становится `raw_profile_enabled(Backend) -> bool`, const fn, истинной только для `MacFeth` на macOS;
   `RAW_SCANNING_ENABLED` удаляется; открывается на ветке, а «открытие релиза» это слияние после GO.** Причина: один
   предикат на профиль и платформу читается в трёх местах и манифестах; Windows/Linux закрыты той же функцией без
   отдельных веток; runtime-переключатель или feature сборки дали бы расхождение байтов между принятым и выпущенным
   runner (hash-pin). Отвергнуто: флип `bool = true` с опорой на `check_feth` вне macOS (контроллер Windows тогда
   просил бы Authorize ради заведомого отказа). Цена ошибки: лишний профиль откроется только явным `matches!` — ревью
   Focus 1 и тест на каждой ОС.
2. **Preflight Studio (`inspect_mac_feth`) и `macos-lab status` остаются отдельными; Studio не зависит от
   `rmasscan-lab`; маскирование Darwin: Studio заполнитель не принимает (runner в сессии всегда root), только текст
   ошибки называет причину.** Причина: разные роли (шлюз перед открытием адаптера под root против ворот стенда до/после
   окна от пользователя), наборы проверок пересекаются, но различаются осознанно (`bpf_access` нужен только
   свидетелям; перечитывание манифеста нужно только Studio); зависимость Studio от лаборатории тянула бы feature `lab`
   в `rmasscan-net` продукта. Цена ошибки: расхождение проверок при изменении стенда — таблица соответствия в
   baseline и обе записи (status pre/post + NetworkChecked в хронике) в каждом окне.
3. **Приёмка это одна авторизованная сессия с тремя кейсами (`s1_full`, `s2_pause`, `s3_stop`), выбранными из
   `macos_live`/`--smoke-pause`, а не часть A/B/C `macos-suite`; верификатор `studio-verify` доказывает exactly-once и
   порядок по плану (`ProbeCursor`), результаты по ответам провода, ACK по тексту runner и SQLite.** Причина: engine
   на `feth` уже принят (A/B/C, `macos_live`); здесь проверяется связка UI → runner → адаптер и история; одна сессия =
   один диалог администратора; `macos-suite` привязан к `wire_scan`/`run.json` и его переделка это лишний механизм.
   Цена ошибки: класс дефекта, видимый только на перф-скоростях или в x01, этим этапом не ловится — записано в §9
   отчёта как граница GO.
4. **Автоматизация через `--smoke-feth` в `studio-ui` (путь кликов), не драйвер поверх IPC runner.** Причина: бриф
   требует доказательств через UI и кросс-проверку с историей; драйвер IPC обошёл бы контроллер, SQLite и ACK.
   Цена ошибки: машина состояний в UI может «подыграть» — она не читает БД и не трогает runner, хронику сверяет
   независимый верификатор с `history.json`, снятым после выхода UI, и с проводом.
5. **Грант BPF на окно нужен свидетелям, не runner; одно chained действие B (install + up + grant), одно D (диалог
   Authorize), одно F (`down`, он же revoke); никакого revoke/grant посреди окна (прогоны отказа прав не входят).**
   Причина: `tcpdump` от пользователя без гранта BPF не откроет; root-runner открывает узлы сам (чтение `open_device`);
   `down` всегда ставит `0600 root:wheel`. Отвергнуто: свидетели под `sudo` (две лишние точки ввода пароля, sudo из
   агента невозможен). Цена ошибки: на время гранта любой staff-процесс может писать в любой интерфейс (риск записан,
   как в приёмке macOS); доказательство изоляции остаётся uplink-захватом.
6. **`history.json` снимает `cargo xtask feth-acceptance` через `studio-store` (зависимость только macOS), pcap
   читает `rmasscan-lab studio-verify`; кросс-workspace зависимостей нет.** Причина: SQLite принадлежит Studio
   (динамическая линковка, Homebrew), pcap и восстановление плана уже есть в лаборатории; второй парсер pcap в Studio
   или rusqlite в лаборатории это самодельная сложность и новый build-риск CI. Цена ошибки: два бинарника в окне вместо
   одного — оба с провенансом и хэшами.
7. **Переустановка runner: один раз на окно на замороженном коммите `C`; повтор только если менялись байты runner;
   проверка «hash бандла == установленный» делает оркестратор до запуска UI.** Причина: hash-pin это модель доверия;
   установка = диалог; порядок «код → ревью → заморозка → окно» сводит число установок к одной (две при исправлении
   runner после ревью). Дополнение после итогового ревью: изменение поведения в `studio-app` (шлюз Start/Resume, порядок записи в хранилище и `AckCheckpoint`, поток `Update`)
   требует нового окна; изменения только текста или диагностики в `studio-app`/`studio-ui` требуют лишь пересчёта архива исправленным верификатором. Цена ошибки: UI-only правка после окна может дать другой байтовый runner при пересборке —
   оркестратор откажет (NOT RUN) и попросит действие B, а не пропустит.
8. **Resume после перезапуска Studio на raw не входит в GO (необязательное E / NOT RUN).** Причина: ещё один диалог
   администратора; путь уже доказан на Simulation (`controller_persists_pause_before_resume_and_survives_restart`), а
   raw-дельта (повторное открытие адаптера на Resume) покрыта `s2_pause` в той же сессии. Цена ошибки: дефект именно
   в связке «новая сессия + сохранённый checkpoint» остаётся OPEN и назван в §9.
9. **Пороги Studio-уровня: `stop_to_stopped_ms ≤ 1000`, `pause_to_paused_ms ≤ 5000`; измеряются от `Action` до
   `Update::State` на таймере UI 50 мс.** Причина: контракт Stop ≤ 1 с на engine измерен 2.9–34.5 мс, запас на IPC,
   FULL-commit и опрос велик; пауза включает wait 3 с. Цена ошибки: ложный FAIL при тормозящем Mac — это FAIL
   измерения, он записывается, порог не ослабляется без решения пользователя.
10. **Evidence коммитится в `docs/experiments/…-acceptance-raw/` (pcap без сжатия, пути скраблены при записи), а не
    остаётся в игнорируемом `studio/verification/`; SQLite представлен `history.json` + `data.sha256`, сам
    `history.sqlite3` не коммитится (расширение вне allowlist guard).** Причина: бриф требует правил приёмки macOS
    (хэши до копирования, независимые захваты в репозитории); объём мал (три кейса, сотни кадров). Цена ошибки:
    история доступна только в выгрузке, а не как БД — выгрузка делается кодом Studio (`studio-store`) и привязана
    хэшем исходного файла.

## Действия пользователя (точные команды, когда, отмена)

Все команды выполняет пользователь в Terminal. Подстановки сообщает оператор перед действием: `$RUNNER_DIR` (каталог
`studio/dist/runner-<stamp>` из `prepare-runner`), `$LAB` (`rmasscan/target/…/release/rmasscan-lab` коммита `C` или его
копия в `$SCRATCH/target-live`), `$R` (sha256 runner из `manifest.json` `$RUNNER_DIR`). Диалоги администратора macOS
открываются сами; пароль вводится только в них.

| № | Когда | Команда | Что меняет | Отмена |
| --- | --- | --- | --- | --- |
| A | перед задачей 5 | сообщение «живое окно на стенде feth разрешено» (команды нет) | разрешает оператору raw-окно только на `feth`, только на `198.18.0.2` | сообщение «стоп»: оператор прерывает (`Ctrl-C`, оркестратор рушит свидетелей и UI, каталог остаётся для проверки изоляции) |
| B | задача 5, после сборки/подготовки | `cd "$REPO/studio" && cargo xtask install-runner "$RUNNER_DIR" && sudo "$LAB" macos-lab up --run-id m1 && sudo "$LAB" macos-lab bpf-access --run-id m1 --grant` (один диалог администратора на установку, один запрос пароля `sudo`; прочитать предупреждение гранта) | устанавливает `/Library/PrivilegedHelperTools/MasscanStudio/$R/studio-runner` (root, без служб); создаёт пару `feth4201/4202`, ARP, манифест `/var/run/rmasscan-lab/m1.json`; `/dev/bpf0..15` → `0660 root:staff` на сессию | `sudo "$LAB" macos-lab down --run-id m1` (снимает стенд и ставит `0600 root:wheel`); установку убирает `sudo rm -r "/Library/PrivilegedHelperTools/MasscanStudio/$R"` (ничего больше не зарегистрировано; выполнять только после `down`) |
| D | задача 5, во время `cargo xtask feth-acceptance` (оператор запускает, окно UI появляется само) | в диалоге «studio-ui wants to make changes» ввести пароль (команды нет); один раз на автоматическую сессию | открывает одну root-сессию runner `$R`; сессия закрывается `Lock` в конце smoke | «Cancel» в диалоге: UI сообщает отказ, ничего не стартует, окно NOT RUN; повтор требует нового диалога |
| E (необязательно) | задача 5, после D | оператор запускает `feth-acceptance --manual`; пользователь в окне: Authorize (диалог, пароль) → New scan → Mac feth, `198.18.0.2`, порты `8000-8007`, rate 100 → Check → Start → Completed → Lock → закрыть окно | вторая root-сессия на ручной проход | закрыть окно до Start: ручной проход NOT RUN, GO не зависит |
| F | конец задачи 5 (и после любого повторного окна) | `sudo "$LAB" macos-lab down --run-id m1` | удаляет пару, ARP, манифест; `/dev/bpf*` → `0600 root:wheel` (это и есть revoke) | повторный подъём = действие B без установки (`sudo … up … && sudo … bpf-access --grant`) |
| G | после задачи 6 | слияние PR ветки `feat/studio-mac-feth-raw` в `main` после зелёного CI (решение пользователя) | `main`: шлюз Mac feth открыт | `git revert -m 1 <merge sha>` |

Повтор B нужен только если после окна изменились байты runner (ревью-исправления в `studio-runner`/`studio-protocol`/
`studio-platform`/`rmasscan-*`): тогда `cargo xtask install-runner "$RUNNER_DIR2"` (новый диалог) и новое окно (D, F).
Прежние версии в `/Library/PrivilegedHelperTools/MasscanStudio/` ничему не мешают и удаляются по желанию пользователя
(`sudo rm -r …/<sha256>`). Постоянных изменений на хосте план не делает: стенд, грант и сессии сессионные; установка
runner — единственный остающийся файл, и он перечислен с отменой.

## Источники и самопроверка

- Код Studio: `studio/crates/studio-protocol/src/lib.rs`, `studio-runner/src/main.rs`, `studio-app/src/lib.rs`,
  `studio-platform/src/{network,macos,unix,audit,trusted}.rs`, `studio-store/src/lib.rs`, `studio-ui/src/main.rs`,
  `studio-ui/ui/main.slint`, `studio/xtask/src/{main,runner_setup,runner_setup_windows,linux_acceptance,windows_acceptance}.rs`,
  тесты `studio-runner/tests/{controller,lifecycle,socket_session}.rs`, `.github/workflows/{studio,rmasscan,language-guard}.yml`,
  `scripts/language-guard.sh`.
- Код engine/net/lab: `rmasscan-net/src/lib.rs`, `src/macos/{adapter,mod,ifinfo}.rs`, `tests/macos_live.rs`,
  `rmasscan-engine/src/{engine,events}.rs`, `rmasscan-lab/src/{macos_lab,macos_suite,macos_verify,verify,pcap,peer,main}.rs`.
- Документы: `studio/{README,AUTHORIZATION,VERIFICATION}.md`, `rmasscan/docs/macos-feth-lab.md`,
  `docs/experiments/2026-10-25-rmasscan-macos-bpf-acceptance.md` (§4, §6, §9, §11), `docs/experiments/2026-10-24-rmasscan-readiness.md`,
  спека `docs/superpowers/specs/2026-10-23-cross-platform-qt-rust-design.md` (§5, §6, §10.2–10.3), планы
  `2026-10-25-rmasscan-windows-sendqueue.md` (формат, исполнение), `2026-10-26-studio-windows-authorization.md`.
- Review Focus 1→1/6; 2→1/4/5; 3→2/4; 4→3/4/5; 5→2/4/5. Публичный API Studio IPC не меняется (`Command`/`Event`
  прежние, `VERSION` прежний); меняются только шлюз (функция вместо константы), порядок отказов runner, текст
  ошибки preflight, новый режим UI, новая подкоманда xtask и новый верификатор лаборатории. Все привилегированные и
  стендовые действия вынесены в таблицу с отменой; живые испытания отделены от CI; каждая задача несёт приватный
  `CARGO_TARGET_DIR` и запрет Python в репозитории.
