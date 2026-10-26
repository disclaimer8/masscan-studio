# Studio Mac feth raw: база и контракты (задача 0, чтение без кода)

Дата: 2026-10-26. Ветка `feat/studio-mac-feth-raw`, база `main` `0bb9767`. План: `docs/superpowers/plans/2026-10-26-studio-mac-feth-raw.md`.
Документ только читает: ни одного кадра, ни одного `sudo`, ни одного диалога, ни одного открытия `/dev/bpf*`, стенд не трогался. Весь
код ниже прочитан на `0bb9767` (чистая выгрузка `git archive HEAD`), номера строк проверены по ней. Сборка и тесты шли из этой выгрузки
в приватном `CARGO_TARGET_DIR` (`$SCRATCH/target-review`, `CARGO_INCREMENTAL=0`, `SQLITE3_LIB_DIR=/opt/homebrew/opt/sqlite/lib`);
выгрузка удалена после снятия данных.

## 1. Окружение

| Что | Значение | Команда |
| --- | --- | --- |
| macOS | 27.0.1 (26A434), Darwin 27.0.0, arm64 (Apple M4 Pro) | `sw_vers`, `uname -a` |
| rustc / cargo | 1.99.1 (58cf8f9c3 2026-10-13) / 1.99.1 (5f94df478 2026-08-27), Homebrew | `rustc --version`, `cargo --version` |
| SQLite | `/opt/homebrew/opt/sqlite` | `brew --prefix sqlite` |
| tcpdump | 4.99.1 (Apple version 161), libpcap 1.10.1; `-rwxr-xr-x root:wheel` (без setuid) | `/usr/sbin/tcpdump --version`, `ls -l /usr/sbin/tcpdump` |
| Пользователь | `denyskolomiiets` uid 501, в группе `staff` | `id` |
| `net.inet.tcp.syncookie` / `rst_rlc_enable` | `1` / `1` | `sysctl -n net.inet.tcp.syncookie net.inet.tcp.rst_rlc_enable` |
| Интерфейсы `ifconfig -l` | `feth4201`/`feth4202` отсутствуют (стенд не поднят) | `ifconfig -l` |
| Каталог стенда | `/var/run/rmasscan-lab/` отсутствует | `ls /var/run/rmasscan-lab` |

Syncookies включены: у закрытого порта Darwin отвечает RST с ограничением `rst_rlc`, тихих портов нет (так же, как в приёмке macOS BPF).

## 2. Состояние стенда и установленных runner (только чтение)

`macos-lab status --run-id m1` (бинарник `rmasscan-lab` из `0bb9767`, запуск без root): **rc 3**, `raw_run_allowed: false`, стенда нет.

| Проверка | ok | Деталь |
| --- | --- | --- |
| manifest | нет | `no stand recorded at /var/run/rmasscan-lab/m1.json` |
| interfaces | нет | `ifconfig feth4201: interface feth4201 does not exist` |
| default_route | нет | `no recorded default route to compare with` |
| routes | да | `8.8.8.8 via en0` |
| lab_routes | нет | `route to 198.18.0.1 goes through Some("en0"), not the pair` |
| arp | нет | `no permanent 198.18.0.1 -> 02:ac:00:00:00:01 entry on feth4202` |
| bridges | да | `no bridge has a feth member` |
| forwarding | да | `net.inet.ip.forwarding = 0` |
| bpf_nodes | да | `/dev/bpf0..15 exist` |

`bpf_access: "denied"` (все существующие узлы `0600`), `uplink: "en0"`, `gateway: "192.168.1.1"`. Это ожидаемое «стенда нет»; живых окон
эта задача не открывает.

Установленные runner (`ls -l /Library/PrivilegedHelperTools/MasscanStudio/`, `shasum -a 256` каждого `studio-runner`):

| Версия (каталог = sha256 файла, совпадение проверено) | Время установки | Размер |
| --- | --- | --- |
| `1b397fccdcd01a9fbd58d5caebd0af574533dbbecae55855a306eb1f16548838` | Oct 26 06:55 | 3587136 |
| `3b1acf74399c2a4e49e43f885e465b82993a8de983f28ef4bf897f1da5f520aa` | Oct 26 07:34 | 3587136 |

Оба `drwxr-xr-x root wheel`, файл `-rwxr-xr-x root wheel`.

Бандлы `.app`: в этой ветке каталога `studio/dist` нет (он в `.gitignore` и не клонируется). Последние локальные бандлы лежат в соседнем
worktree `masscan-studio-app` (ветка `feat/studio-network-guard`, `e5fe45d`): runner в `Masscan Studio.app/Contents/MacOS/studio-runner` у
`build-1793016190148` (12:03), `build-1793015976013` и `build-1793014510832` равен
`d537f3dab0fbee8aa9efcb80505f35bdd3bd8cefe04dcfcba78697e0f9d99a33`; ещё более ранние `9783df32…` и `65f33cbf…`. **Ни один из них не равен
ни `1b397f…`, ни `3b1acf…`.** Вывод для задачи 5: ни одна из установленных версий runner не совпадёт с runner коммита `C` (любой коммит,
меняющий байты runner, а эта ветка меняет `studio-runner/src/main.rs` и зависимости `studio-protocol`/`studio-platform`, даёт новый hash,
а `Client::authorize` ждёт ровно `installed_path(file_hash(source))`, `studio-app/src/lib.rs:207–209`). Поэтому в окне нужна установка
(действие B).

Действия пользователя, которые потребуются в задаче 5 (формулировка плана): **B** одна chained команда «установить runner + `macos-lab up` +
`bpf-access --grant`» (sudo, пароль вводит пользователь в Terminal); **C** подтверждение/проверка поднятого стенда по `status`; **D** один
диалог администратора macOS (Authorize) на всю автоматическую сессию; **F** одно `macos-lab down` (оно же revoke). E (ручной проход UI)
необязателен. Агент не вводит пароль и не вызывает `sudo`.

## 3. Контракты с номерами строк (`0bb9767`)

Пути относительно `studio/crates/` (Studio) и `rmasscan/crates/` (движок и лаборатория).

### 3.1 Шлюз и его читатели

`RAW_SCANNING_ENABLED`: `studio-protocol/src/lib.rs:15–16` (`pub const RAW_SCANNING_ENABLED: bool = false`, комментарий «Release gate, not a
user-configurable escape hatch»). Читатели (grep по дереву на `0bb9767`):

| Читатель | Место |
| --- | --- |
| runner `raw_adapter`, `MacFeth` | `studio-runner/src/main.rs:60` |
| контроллер Start | `studio-app/src/lib.rs:619` |
| контроллер Resume | `studio-app/src/lib.rs:680` |
| манифест `prepare-runner` (macOS/Linux) | `xtask/src/runner_setup.rs:56` (`"raw_enabled"`) |
| манифест/проверка Windows runner | `xtask/src/runner_setup_windows.rs:62` (`"raw_enabled"`), `:86` (отказ, если шлюз открыт) |
| Linux CI-проба | `xtask/src/linux_acceptance.rs:22` (отказ, если шлюз открыт) |
| Windows CI-проба | `xtask/src/windows_acceptance.rs:177` |
| **Windows: поле манифеста `raw_enabled`** (в плане не перечислено) | `xtask/src/windows_acceptance.rs:370` |
| Документы | `studio/AUTHORIZATION.md:128`, `studio/VERIFICATION.md:209` (упоминают флаг, правятся в задаче 6) |

Тест, чьё ожидание меняется: `studio-runner/tests/controller.rs:131–156` (`incomplete_raw_integration_refuses_before_opening_an_adapter`,
ждёт `Failed` с текстом, содержащим «Raw scanning is not enabled»).

### 3.2 `raw_adapter` (`studio-runner/src/main.rs:43–75`)

`raw_adapter(job)` (`:43`) сначала `job.prepare()?` (`:44`), затем `match job.backend` (`:45`): `Archived` → ошибка (`:46`); `Simulation` →
`FakeAdapter` с `reply_to_syn(.., 0x12)` (`:47–55`); `MacFeth` (`:56–65`): `if !RAW_SCANNING_ENABLED` → «Raw scanning is not enabled in
this Studio build…» (`:60–62`), затем `check_feth()?` (`:63`), затем `rmasscan_net::open_explicit(plan.binding())` (`:64`), ошибка
переводится в «BPF access unavailable: … The isolated feth stand and an explicit access grant are required.». `check_feth()` на macOS =
`studio_platform::network::inspect_mac_feth().map(|_| ())` (`:68–71`), на остальных ОС всегда `Err("Mac feth profile is only available on
macOS…")` (`:72–75`). Проверки uid (не root) перед `check_feth` в `raw_adapter` сейчас нет; uid проверяется только на уровне входа:
`--stdio` отказывает root (`:473–479`), `--connect` отказывает UI с uid 0 (`:489–492`) и для root-runner проверяет hash исполняемого файла
(`:493–501`). Отказ не-root для `MacFeth` это изменение задачи 1.

Порядок в `Command::Start|Resume` runner: `job.prepare()` (`:228`), разбор checkpoint (`:229–236`), **`validate_checkpoint` до любого
адаптера** (`:237–249`, плюс «Resume needs a fresh attempt», `:246–248`), только затем `raw_adapter(job)` (`:250`), `Engine::start|resume`
(`:253–257`). Ошибка любого шага → `Event::Finished{Failed, error}` (`:262–270`). `CheckNetwork` (`:171–200`) на macOS вызывает
`inspect_mac_feth_cancellable` в процессе runner (то есть под root в авторизованной сессии) и отвечает `Event::NetworkChecked{ready, detail}`
(`:181–199`); «Isolated feth preflight passed; no packets sent» при успехе.

### 3.3 Контроллер: Start/Resume и обработчик ошибки шага (`studio-app/src/lib.rs`)

| Контракт | Строки |
| --- | --- |
| `Client::authorize` (macOS/Linux): `file_hash(source)`, `installed_path(&hash)`, `Authorized::open(...)`, подсказка «Install this build's runner with cargo xtask prepare-runner first.», `Self::connected`, `handshake(Some(cancelled))` | `:206–219` (атрибут `cfg` на `:206`) |
| `Action::Authorize if !active`: `client.take()`, `Update::Authorization{busy:true}`, `Client::authorize`, при успехе `Update::Authorization{authorized:true, "…checking isolated network…"}` и `Command::CheckNetwork` | `:587–602` |
| `NetworkChecked` в контроллере превращается **только** в `Update::Notice("Network preflight passed|refused: {detail}")`, в БД не пишется и `Update::State` не порождает | `:778–787` |
| `Action::Start`: `job.prepare()?` (`:617`); для `backend != Simulation`: шлюз `!RAW_SCANNING_ENABLED` → `Update::State(Failed, "Raw scanning is not enabled in this build…")` и `return Ok(())` (`:618–622`); неавторизованный клиент → `Err("Authorize the runner before starting a raw scan")` (`:623–627`); Simulation с авторизованной сессией закрывает её (`:628–638`); `db.begin`, `client.start(.., Command::Start(job))`, `Reset`, `State(Starting)` (`:639–658`) | `:616–659` |
| `Action::Resume`: сохранённый Paused и checkpoint (`:660–678`); raw и (`!RAW_SCANNING_ENABLED` или клиент не авторизован) → `Err("Raw resume is gated; saved checkpoint is unchanged")` (`:679–686`); `db.begin(.., true)`, `Command::Resume{job, checkpoint}` (`:700–718`) | `:660–719` |
| Обработчик ошибки шага: `client.take()`, `Update::Authorization{authorized:false, "Runner session closed"}`, `status = Interrupted`, при активном скане `db.interrupt` и перечитанный статус, `Update::State`, `Update::History` | `:849–875` |

Следствие: ошибка шага (`Err`) всегда закрывает клиента и сбрасывает авторизацию (`Interrupted`); ветка `State(Failed)` + `return Ok(())`
этого не делает. Для «неавторизованного raw Start = `Failed` без диалога и без runner» (решение плана) нужна именно вторая форма.

### 3.4 `Authorized::open` (`studio-platform/src/macos.rs:117–169`)

Отмена до начала (`:118–120`); путь обязан быть `installed_path(hash)` (`:121–123`); `trusted::verify(path, hash)` (`:124`); UI не root
(`:125–128`); `Endpoint::create()` (`:129`); команда `/usr/bin/env -i PATH=… LC_ALL=C <runner> --connect <socket> <owner-json>` в
`osascript … with administrator privileges` (`:130–146`); ожидание `accept_trusted` **180 с** с опросом процесса `osascript` (`:147–155`); при
ошибке launcher убивается (`:163–167`). Hello ждёт 10 с в `handshake` (подтверждено планом, в этом файле не читалось).

### 3.5 Preflight Studio `inspect_mac_feth` (`studio-platform/src/network.rs`)

| Элемент | Строки |
| --- | --- |
| `iface(...)` (link/peer/MAC/IPv4) | `:78–117`; MAC сравнивается **строго**: ровно один `ether`, равный ожидаемому, иначе «`{name}: MAC changed or unavailable`» (`:94–97`) |
| `validate(&Snapshot)` | `:119–251` |
| `command(...)`: фиксированные абсолютные пути, `env_clear`, `LC_ALL=C`, дедлайн 5 с, лимит вывода 2 MiB, отмена | `:253–305` |
| `manifest()`: путь только `/private/var/run/rmasscan-lab/m1.json` (`:316`), предки root-owned без group/other-записи, отказ ACL, `O_NOFOLLOW`, ≤64 KiB | `:309–348` |
| `inspect_mac_feth` / `_cancellable`: манифест, 11 команд (`ifconfig` ×3, `route get` ×4, `netstat -rn -f inet`, `arp -an`, `sysctl net.inet.ip.forwarding`), **повторное чтение манифеста** и сравнение байт («Stand changed during preflight»), затем `validate` | `:349–379` |

Открывает ли preflight адаптер: нет (`:307–308`, «No adapter is opened… nothing is modified»). Заполнитель MAC `02:00:00:00:00:00` в Studio не
принимается ни при каких условиях (только текст ошибки меняется в задаче 1).

### 3.6 Лаборатория: `run_checks`, `mask_ok`, `status` (`rmasscan-lab/src/macos_lab.rs`)

`run_checks(h, recorded, stand)` — `:561–723`; `mask_ok` (`:567–569`) истинна только если манифест `sealed`, `scanner_mac`/`peer_mac`
равны константам **и** процесс **не root** (`!h.is_root()`, `:179–181` через `id -u`). `status` — `:1473–1497`: манифест грузится через
`load_stand` (`:1019–1035`: run-id совпадает, токен манифеста равен файлу-маркеру), добавляется проверка `manifest` первой, rc 0 при
`raw_run_allowed`, иначе 3. Константы `:26–40` (`MASKED_MAC`, `SCANNER_IF`…, `BPF_LAST = 15`, `UPLINK_FILTER` `:40`).
`raw_run_allowed` это «все проверки ok» (`Report::ok`, `:538–544`); `bpf_access` в него **не** входит (`bpf_nodes` проверяет только
существование узлов, `:707–716`).

### 3.7 Адаптер macOS: `open_device` и `GRANT_HINT` (`rmasscan-net/src/macos/adapter.rs`)

`GRANT_HINT` — `:70–71` («/dev/bpf* is 0600 root:wheel; run `rmasscan-lab macos-lab bpf-access --grant`»). `open_device` — `:554–575`:
перебор `/dev/bpf0..255`, `EBUSY` пропускается, `EACCES|EPERM` запоминается (`:563`), `ENOENT` конец, при `denied` →
`NetError::PermissionDenied(GRANT_HINT)` (`:568–570`). Сам `open(2)`: `rmasscan-net/src/macos/sys.rs:104–121`
(`O_RDWR|O_NONBLOCK|O_CLOEXEC`). `open(binding)` (`adapter.rs:668–674`): `check_binding`, `ifinfo::verify_binding`, `open_with(SysOpener)`.
`rmasscan_net::open_explicit` на macOS = `macos::open` (`rmasscan-net/src/lib.rs:297–301`).

### 3.8 Checkpoint и ACK

| Контракт | Строки |
| --- | --- |
| Дедлайн ACK 10 с (`CheckpointAck::timeout`, «Checkpoint ACK timeout» / «Checkpoint delivery stalled») | `studio-runner/src/main.rs:24–42` |
| `Pause` → `engine.pause()`; `Stop` → `engine.stop()` или `Finished{Stopped}` до ACK | `:278–298` |
| `AckCheckpoint{through}`: должен совпасть с `pending.sequence`, затем `Finished{Paused, "Checkpoint committed by Studio"}` | `:299–313` |
| Engine `Finished{Paused}`: `Event::Checkpoint{bytes, next_index}` с квитанцией, `a.pending = CheckpointAck{..}`; иначе `Finished{Completed|Stopped|Failed, "{reason:?}"}` | `:359–384` (ветка `else` `:385–399`) |
| Store: `apply_batch` одной FULL-транзакцией | `studio-store/src/lib.rs:283–306` |
| Store: `Event::Checkpoint` → `UPDATE scans SET checkpoint, next_index, status='"Paused"'` после `validate_checkpoint` | `:346–352` |
| Store: `Event::Finished`, Paused без durable checkpoint = ошибка, Failed при Starting с checkpoint → Paused | `:359–370` |

### 3.9 UI smoke и форма backend

`main()` читает `--smoke`, `--smoke-pause`, `--smoke-stop-race` — `studio-ui/src/main.rs:293–296`. Таймер 50 мс — `:754–954`;
конечный автомат `--smoke-pause`: Scanning→Pause→Paused→Resume→Scanning→Stop→Stopped (`:913–926`); `--smoke` ждёт `Completed` (`:927–929`);
выход по `ok` или **25 с** (`:937–939`), снимок `STUDIO_SCREENSHOT` (`:940–950`). Старт: `ui.set_backend_index(1)`, `Job::example(Simulation)`,
для `--smoke-pause` rate 4 и порты `8000-8031` (`:955–963`); провал → «UI smoke did not complete the expected lifecycle» (`:966–968`).
Обновления, на которые сможет опираться хроника: `Update::Reset(_, backend)` (`:825`), `Update::State(status, detail)` (`:904`), `Update::Progress`
(`:866`), `Update::Notice` (`:877`), `Update::Authorization` (`:892`). Индекс backend 0 = `MacFeth` («Mac feth · not enabled yet»),
1 = Simulation: `studio-ui/ui/main.slint:490`.

Замечание для задачи 2: сообщение `NetworkChecked` доходит до UI только как `Update::Notice` (`studio-app/src/lib.rs:778–787`), без
`Update::State`; хроника `NetworkChecked` в `--smoke-feth` должна читаться из текста `Notice` («Network preflight passed|refused: …»).

### 3.10 Лаборатория: пир, восстановление плана, pcap

| Контракт | Строки |
| --- | --- |
| `peer listen --open … --ready FILE` на macOS: биндит только если `198.18.0.2` числится на `feth4202` (`ifconfig feth4202` → `parse_ifconfig`), иначе «refusing to listen: 198.18.0.2 is not on feth4202» | `rmasscan-lab/src/peer.rs:540–565` |
| `plan_frames(args)`: ScanConfig как в `wire_scan`, `validate(.., Scan)`, `ReadyPlan`, `ProbeCursor::new(&plan, 0)`, `preload(256)` + `advance_sent_n` до пустого пакета; порядок = порядок движка | `rmasscan-lab/src/verify.rs:385–451` |
| `read_pcap_records(data)` (классический pcap, LE/BE, µs/ns) и `is_syn(frame)` (IPv4/TCP, не фрагмент, флаги `&0x3f == 2`) | `rmasscan-lab/src/pcap.rs:5` (до `:56`), `:58–69` |
| Хэши до копирования: `write_hashes`, `copy_verified` | `rmasscan-lab/src/macos_suite.rs:472–496` |

## 4. Таблица соответствия: preflight Studio и `macos-lab status`

Наборы проверок **не идентичны, но дополняют друг друга**. Studio проверяет под root перед открытием адаптера и строго; лаборатория
проверяет от обычного пользователя до и после окна и добавляет то, что относится к свидетелям. Studio **не** переиспользует
`rmasscan-lab` (решение 2): иначе в продукт тянулась бы зависимость от лаборатории.

| # | Проверка | Studio (`network.rs`) | Лаборатория (`macos_lab.rs`) | Различие |
| --- | --- | --- | --- | --- |
| 1 | Манифест и константы | `manifest()` `:309–348` (фиксированный путь, root-owner, без ACL, ≤64 KiB), `validate` `:120–132`: `state=sealed`, `scanner_if`, `peer_if`, обе MAC, `source_ip`, `peer_ip` | `load_stand` `:1019–1035` (run-id, токен == маркер), `status` `:1474–1477` (`state=sealed`) | Studio сверяет константы внутри манифеста; лаборатория сверяет токен и маркер, а константы берёт из кода |
| 2 | Интерфейсы и MAC | `iface` `:78–117`, вызовы `:133–134`: `status: active`, `peer`, ровно один `ether` == ожидаемый, у сканера 0 `inet`, у пира 1 (`198.18.0.2`, маска /30) | `feth_ok` `:423–442`, `run_checks` `:577–606`: те же поля; `MASKED_MAC` принимается при `mask_ok` | **MAC**: Studio строго, заполнитель не принимается (runner в сессии всегда root, root видит настоящие MAC); лаборатория принимает заполнитель только не-root против запечатанного манифеста |
| 3 | Default route | `:135–147`: `uplink` не пуст и не `feth*`, `gateway` IPv4; `route get default`: интерфейс и gateway == манифест | `default_route` `:444–448`, `:608–627`: не `feth*`, равен записанному (`recorded_route` `:1058–1063`); без записи ошибка | Эквивалентны |
| 4 | Маршруты | `:156–158` (8.8.8.8 не через `feth*`), `:159–196` (разбор по заголовку `Netif`; default через `feth*` — отказ; строка `feth*` вне пары — отказ; неоднозначный заголовок, усечённая строка, нет заголовка — отказ) | `:629–651` (`route_allowed` `:451–459`, 8.8.8.8 не через `feth*`) | Studio ещё отказывает любой маршрут, перекрывающий /30 вне пары (`:186–192`), лаборатория вынесла это в `lab_routes` |
| 5 | `lab_routes` (source/peer/public route и перекрытия) | `:148–155`: `198.18.0.1` ∈ {feth4202}, `198.18.0.2` ∈ {feth4202, lo0}; перекрытия `:185–192` | `lab_routes` `:466–503`, вызов `:653` | Эквивалентны по смыслу; у Studio они разбросаны по `validate`, у лаборатории отдельная проверка |
| 6 | Мосты | `:203–206`: `member: feth*` в `ifconfig -a` | `:684–695` | Эквивалентны |
| 7 | Перекрытие адресов интерфейсов | `:207–224`: любой `inet` на любом интерфейсе, перекрывающий /30, кроме собственного `198.18.0.2/30` на `feth4202` | **только в `preflight` перед `up`** `:751–766` (в `status` нет) | Studio проверяет всегда, лаборатория только при подъёме |
| 8 | ARP | `:226–246`: ровно одна запись `(198.18.0.1)`, `on feth4202`, `at` == `02:ac:00:00:00:01` (строго), `permanent` | `:655–682`: достаточно одной подходящей; при `mask_ok` допускает `MASKED_MAC` | Studio строже (ровно одна запись, строгий MAC) |
| 9 | Forwarding | `:247–249` (`net.inet.ip.forwarding` == `0`) | `:696–706` | Эквивалентны |
| 10 | `bpf_nodes` / `bpf_access` | нет (root-runner открывает узлы сам; отказ придёт от `open_device`) | `:707–716` (`bpf_nodes`, только существование), `bpf_access` `:507–529` (`granted`/`denied`/`mixed`, поле отчёта) | Только лаборатория; `raw_run_allowed` от `granted` не зависит |
| 11 | Повторное чтение манифеста | `:374–376`: байты манифеста после наблюдений должны совпасть | нет (один `load_stand`) | Только Studio |
| 12 | Токен и маркер стенда | нет | `load_stand` `:1028–1034` | Только лаборатория |
| 13 | Выполнение команд | `command` `:253–305` (абсолютные пути, `env_clear`, дедлайн 5 с, 2 MiB, отмена) | через `Host::sh` (`:57` и далее) | Разные реализации |
| 14 | Кто и когда | под root внутри runner, непосредственно перед `open_explicit`; также по `CheckNetwork` сразу после Authorize | от пользователя, до и после окна (`status-pre/post`) | Разные роли; оба снимка пишутся в каждом окне (status pre/post + NetworkChecked в хронике) |

Вывод: наборы пересекаются в пунктах 1–9, различаются осознанно в 7, 10–12; ни один набор не заменяет другой. Цена расхождения при
изменении стенда: таблица ведётся здесь, а в каждом окне пишутся обе записи.

## 5. Зачем нужен грант BPF (вывод чтением кода)

1. **Root-runner не нуждается в гранте.** `open_node` это обычный `open(2)` с `O_RDWR` на `/dev/bpfN` (`rmasscan-net/src/macos/sys.rs:104–121`).
   Узлы создаются и остаются `0600 root:wheel` (`REVOKED_MODE`, `macos_lab.rs:38`; `revoke_all`, `:1508–1533`, ставит именно это).
   Процесс с euid 0 обходит биты режима, поэтому открытие проходит без смены режима; в коде это подтверждается тем, что сама
   лаборатория открывает `/dev/bpf0..15` под root при `up` (`macos_lab.rs` план `up`: «open /dev/bpf0..15 together as root and close
   them (the kernel creates the missing nodes)») и что состояние «granted» нужно лишь для не-root процессов. Studio-runner в авторизованной
   сессии это root (проверка `me.uid == 0` с проверкой hash, `studio-runner/src/main.rs:493–501`).
2. **Не-root получает `EACCES`.** `open_device` (`adapter.rs:556–575`) собирает `EACCES|EPERM` и возвращает
   `PermissionDenied(GRANT_HINT)`, где подсказка прямо говорит про `0600 root:wheel` и `bpf-access --grant` (`:70–71`). Это же доказано
   живьём в приёмке macOS: `perm_denied_scan` после revoke дал exit 5 `PermissionDenied` при `bpf_access: denied`
   (`2026-10-25-rmasscan-macos-bpf-acceptance.md` §6, часть B).
3. **Свидетели запускаются от пользователя и без гранта слепы.** `tcpdump` это `/usr/sbin/tcpdump`, `-rwxr-xr-x root:wheel`, без setuid
   (`ls -l`), libpcap открывает `/dev/bpfN` от uid пользователя (501, группа `staff`). Приёмка macOS запускала свидетелей от пользователя в
   окне гранта (`…-acceptance.md` §4: «на время сессии пользователь выполнил `macos-lab bpf-access --grant` (`/dev/bpf0..15` в `0660
   root:staff`), затем `--revoke`»; `macos-feth-lab.md` «Live adapter tests», `:165–195`: «run them in a grant window, as you (never
   root)», в воротах «need `bpf_access: granted`»). Сам захват здесь не запускался (открыл бы BPF); вывод опирается на код, права файла
   `tcpdump` и протокол приёмки.
4. **Цена гранта.** `GRANT_WARNING` (`macos_lab.rs:1500`): `0660 root:staff` даёт любому процессу группы `staff` чтение и **инъекцию**
   кадров на любом интерфейсе, включая `en0`, пока не `--revoke`, `down` или перезагрузка. Доказательство изоляции остаётся uplink-захватом
   с 0 кадров лаборатории.
5. **Решение для плана.** Грант на окно = одно действие B (в той же chained команде, что установка runner и `up`), нужен только
   независимым свидетелям (`tcpdump` на `feth4202` и `en0`), а не root-runner. `down` сам ставит `0600 root:wheel` первым шагом, до разбора
   манифеста (`down`, `macos_lab.rs:1717–1729`, `revoke_all` на `:1721`), поэтому отдельный revoke не нужен: действие F одно. Никакого
   revoke/grant посреди окна.

## 6. Тесты и guard на Mac (`0bb9767`, чистая выгрузка)

Команды и результаты (все в приватном `target-review`, без sudo и без BPF).

| Команда | rc | Результат |
| --- | --- | --- |
| `cd studio && cargo xtask test` (= `cargo test --locked --workspace --all-targets --no-fail-fast` + `cargo clippy --locked --workspace --all-targets -- -D warnings` + `cargo fmt --all --check`) | **0** | 35 тестовых бинарников, **76 passed, 0 failed, 2 ignored** (`tests/live.rs`); `controller.rs` 4 passed, `socket_session.rs` 2, `profiles.rs` 1, `history.rs` 2, `volume.rs` 1 (13.32 с), `lifecycle.rs` 1, `studio-runner` unittests `main.rs` 6; clippy `-D warnings` и fmt чисто; wall 1 мин 49 с |
| `cd rmasscan && cargo test --locked --workspace` | **0** (со второго прогона) | 40 строк `test result`, **1212 passed, 0 failed, 23 ignored** (live-тесты `macos_live` и спайк `#[ignore]`, не запускались); wall второго прогона не снят (первый, упавший, шёл 1 мин 11 с) |
| `bash scripts/language-guard.sh` | **0** | `language guard: PASS (9564 tracked files checked)` |

**Честная запись о первом прогоне `rmasscan`.** Первый запуск `cargo test --locked --workspace` дал rc 101: в `rmasscan-lab --lib` упали два теста
(`dump::tests::sequence::a_complete_capture_is_acknowledged_finalised_and_valid` и
`dump::tests::linux_wire_gate::real_witness_metas_over_every_golden_case_pass_the_linux_wire_gate`; 642 passed, 2 failed) с причиной
`"tcpdump did not exit after SIGINT"` из `dump.rs:199` (проверка завершения свидетеля по таймауту). Эти тесты стартовали под сильной
нагрузкой хоста (load average 11 до 15 от параллельных сборок других агентов). Три повторных прогона `cargo test -p rmasscan-lab --lib dump::`
(25 passed каждый) и полный повторный `cargo test --locked --workspace` (rc 0, 1212 passed) прошли. Классификация: **флаки по таймингу при
перегруженном хосте, не дефект ветки**; код не менялся между прогонами. Первый провал не скрывается: при остановке на первом упавшем
бинарнике остальные бинарники (rmasscan-net и далее) в том прогоне не выполнялись, их результаты взяты из полного повторного прогона. Для
CI и для задачи 4 это риск флаки `dump_tests`; в окне 5 хост должен быть спокоен.

## 7. База из прежних приёмок (не повторяется в этом плане)

| Источник | Что установлено |
| --- | --- |
| Приёмка macOS BPF, `2026-10-25-rmasscan-macos-bpf-acceptance.md` §1, §6 | Часть A (functional-r1) **PASS 29/29**; часть C (perf-r1) **PASS 21/21**, rate gate MET на 100/1k/10k/100k (100k: медиана 93808.6 pps); часть B (failure-r1) **17 PASS + 1 INVALID** (`linkloss`, класс отказа линка OPEN, не повышен); 0 кадров лаборатории на `en0` в 60 снятых захватах; `raw_run_allowed: true` в каждом `status-pre/post`; Stop на engine 2.9–34.5 мс |
| `macos_live` (§6 там же, окно гранта, бинарник из `3e3886e`) | **6 из 6 PASS** (`full_scan`, `stop`, `pause_resume`, `rx_loss`, `uncertain`, `latency`), 20.36 с, 0 кадров на uplink; `max_us_idle_recv` 34087; `pause_resume`: ветка 1 Paused sent 4, ветка 2 Completed sent 8, `next_index` 12, без пропусков и дублей |
| Studio elevated session, `studio/VERIFICATION.md:104–120` | Исправление `068a94d`: root-peer аутентифицирован через audit token; установленный helper `1b397f…` (PID 18317) принят как UID 0, Hello выполнен, **CheckNetwork `ready=false` (манифест стенда отсутствовал)**, CloseSession выполнен, процесс и сокет убраны. Это не доказывает raw, изоляцию и приём настроенного `feth`; шлюз оставался закрытым |
| Helper `3b1acf…` (`VERIFICATION.md:122–127`, `:150–156`) | Установлен и сверен (владелец, права, ACL, SHA-256), отдельной elevated-пробы не имел; упакованный unprivileged lifecycle smoke пройден |
| Упакованный `.app`, `--smoke-pause` (`VERIFICATION.md:232–235`) | Start → Scanning → Saving → Paused → Resume → Stopped; `codesign --verify --deep --strict` прошёл; runner рядом повторил `--smoke-pause` с программным рендерингом. Всегда Simulation (`studio-ui/src/main.rs:955–963`) |
| Границы (§3, §9 приёмки macOS) | Физический NIC NOT RUN; блокировка `write()` при нехватке mbuf OPEN; перф-класс дефектов и x01 этим этапом не ловятся (граница GO, §9 отчёта задачи 6) |

## 8. Замечания к последующим задачам

1. **Второй читатель на Windows.** `xtask/src/windows_acceptance.rs:370` тоже читает `RAW_SCANNING_ENABLED` (поле манифеста `raw_enabled`).
   В карте файлов плана указан только `:177`. Задача 1 должна заменить оба места, иначе Windows-сборка не соберётся после удаления константы.
2. **Документы, упоминающие флаг:** `studio/AUTHORIZATION.md:128`, `studio/VERIFICATION.md:209` (задача 6).
3. **`NetworkChecked` виден UI только как `Notice`.** Хроника `--smoke-feth` не должна ждать для него `Update::State`.
4. **Неавторизованный raw Start сейчас идёт через `Err` и закрывает клиента** (`lib.rs:623–627` + `:849–875`: `Interrupted`, «Runner session
   closed»). Требование плана (`Failed`, без диалога и runner, сессия не ломается) означает ветку формы `:619–622` (`State(Failed)` +
   `return Ok(())`), а не `Err`.
5. **Strict MAC под root не проверялся живьём.** Основание: лаборатория под root видит настоящие MAC при `up` (`macos_lab.rs:572`,
   «root verified … at up»), а `macos_live` под не-root видел заполнитель (`mac_check=os-masked`). Для ad-hoc подписанного root-runner
   через `osascript` это ожидается так же, но первое подтверждение будет `NetworkChecked ready=true` в окне 5; если Darwin скроет MAC и от
   него, Start закончится «MAC changed or unavailable» (то есть закроется, а не откроется; это безопасный отказ).
6. **Сегодняшний runner не отказывает не-root перед `check_feth`** (см. 3.2): `MacFeth` под не-root runner дошёл бы до `inspect_mac_feth`.
   Сегодня это недостижимо из-за закрытого шлюза; после открытия шлюза отказ нужен до `inspect_mac_feth` (задача 1).
7. **Стенд сейчас не поднят** (§2), `status` rc 3 ожидаем. Окно 5 невозможно без действий B–D и F пользователя.

## 9. Критерий GREEN этой задачи

Документ существует; все цифры снабжены командами; `cargo xtask test` rc 0, `cargo test --locked --workspace` rc 0 (с записью флаки первого
прогона), `language-guard` PASS; таблица соответствия preflight заполнена по строкам кода (§4); вывод о гранте записан (§5); состояние
стенда и установленных helper снято только чтением (§2).
