# rmasscan: баннеры, подэтап 4c (TLS и X.509) — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development`. Шаги в чекбоксах (`- [ ]`).
> Цикл на каждую задачу: RED (тест) → FAIL → минимальная реализация со ссылкой на C `файл:строка` → PASS → коммит.
> Статус: утверждён пользователем 2026-11-15. Решения раздела «Решения на ревью» приняты; спорные места
> реализации решаются «как правильнее со стороны Rust» (указание пользователя) при неизменном паритете Р1 по
> наблюдаемому поведению.

**Goal:** TLS-баннеры с паритетом masscan `8e6b3b0`: пять ClientHello, разбор TLS-записей и рукопожатий, X.509
(CN/SAN листа), `--capture cert` (base64 DER в записях `X509`/`X509CA`), проверки `--heartbleed`, `--ticketbleed`,
`--vuln poodle|sslv3`, настоящий STARTTLS (FTP/SMTP/POP3 шлют ClientHello и поток разбирает TLS-парсер) и второе
соединение на TLS-порт (`stream->next`, hello TLS 1.3) по модели порта источника C `{p, p+16}` (Р10, решение ниже).

**Architecture:** как в 4b (Р12): парсеры TLS и X.509 — возобновляемые автоматы `feed(&[u8])` в `rmasscan-proto`
(`banner1/tls.rs`, `banner1/x509.rs`), без сокетов и без `unsafe`. Таблица hello становится таблицей потоков
(hello, `SF__close`, `next`, малое окно heartbleed). Реконнект живёт в стеке `rmasscan-proto` (новый TCB в
`SYN_SENT`, SYN с cookie на своём тике); движок только расширяет привязку портов источника под `--banners` (Р10) и
не знает про TLS. CLI добавляет опции проверок и пробрасывает флаги `capture`/`is_*` в `TcpBannerSettings`.

**Tech Stack:** Rust (пин `rmasscan/rust-toolchain.toml`), workspace `rmasscan/`, без новых внешних крейтов и без
изменений `Cargo.lock` (SipHash-2-4 уже есть в ядре: `rmasscan_core::cookie::siphash24`, сверен с векторами C).

**Spec:** [спека этапа](../specs/2026-11-13-rmasscan-banners-design.md) §3 строка 4c, Р1–Р17 (особенно Р1 паритет,
Р3, Р10, Р12, Р13, Р15, Р17), §10 (И1–И7), §11 (И8–И20). Справка
[TLS, X.509, SMB](../specs/2026-11-13-rmasscan-banners-c-reference-tls-smb.md) писалась до 4b: задача 0 сверяет её
TLS-половину с исходниками C так же, как 4b сверял справку TCP, и выпускает справку 4c. Из
[справки TCP 4b](../specs/2026-11-13-rmasscan-banners-c-reference-tcp.md) в 4c указывают: строка `SYN_SENT/TIMEOUT`
таблицы A4, кладжи `SendFirst` (B5), E3.5/B6 (`--hello-string[PORT]` на TLS-портах: FIN после hello и реконнект),
B6/E2.8 (хвост после STARTTLS), список TLS-портов B4. Образец плана — [план 4b](2026-11-13-rmasscan-banners-4b.md),
образец приёмки — [приёмка 4b](../../experiments/2026-11-13-rmasscan-banners-4b-acceptance.md).

**Опора на 4b (вершина `fab13114`, слияние PR #62):** каркас `banner1/` (классификатор, `Banout` без потокового
base64 и без `banout_end`, `HelloTable`, `Banner1Session`, офлайн-драйвер `banner_stream`); `AppProto::Unported`
для SSL3 и SMB (`session.rs:39-56`, `:145-161`, `:232-249`); константа `SSL_HELLO_SENT: bool = false`
(`session.rs:287-289`) — совпадение SSL3 всегда отвергается; `ParseCx::hand_off_starttls` (`session.rs:120-133`)
шлёт ничего, хвост уходит в `unknown`; стек `tcp/` (`Tcb`, таблица, `AppLayer` без кладжей SendFirst —
`tcp/app.rs:150-151` прямо называет их 4c); `SegmentOut.window: Option<u16>` в ядре (`Some(600)` зарезервирован под
heartbleed, план 4b задача 3); `syn_cookie_ipv4/ipv6` (`rmasscan-core/src/cookie.rs:18,46`); флаги `--capture`
разобраны полностью (`ScanConfig.capture {cert, servername, html, heartbleed, ticketbleed}`, cert по умолчанию
включён), в `TcpBannerSettings` доходит только `capture_html` (`banner_settings.rs:51`); формат вывода `certs`
существует (`output/formats.rs:30`); `--heartbleed` сегодня ошибка разбора (`rmasscan-cli/src/lib.rs:566` закрепляет
`is_err`); номера и имена приложений 9/15/16/20/21/22/24 закреплены (`app.rs:17-32`); hello-буферы общие на скан
(`Arc`, `TcbCtl::send_shared`); бюджет баннеров таблицы 512 МиБ и резерв очереди (И9) действуют и на TLS-записи;
`connection_memory_floor()` обязан покрывать новый размер сессии.

## Решения на ревью (подтверждает пользователь/контролёр до задачи 0)

- **Р10 — модель C `{p, p+16}`, узкое прочтение (решение пользователя 2026-11-15).** При `--banners` и порте
  источника по умолчанию (один порт `p`) привязка приёма расширяется до `p..=p+16` через уже существующий
  `legacy_c_17_port_mask`; реконнект берёт следующий порт арифметикой C `_next_IP_port`
  (`src/stack-tcp-core.c:1603-1644`). Порт исходных SYN скана не меняется (один порт — именованное отличие этапа
  управления сканом, не предмет 4c); явный `--source-port` (один или диапазон) уважается как есть, и при ширине 1
  реконнект повторяет поведение C (тот же порт + `ERRMSG`, задача 0 уточняет текст и частоту). Отклонённая
  альтернатива — полная модель C, где и SYN скана идут с портов по хэшу внутри диапазона: это переписывает паритет
  этапа управления сканом и все прежние окна ради одного реконнекта. Решение пишется в журнал и README (Р10).
- **Перенос по наблюдаемому поведению, не по строкам C (решение пользователя: «как правильнее со стороны Rust»).**
  Внутреннее устройство парсеров — идиоматичный Rust: типизированные состояния и поля, проверяемая арифметика,
  явные пределы; построчная транскрипция автомата C не требуется и не делается. Контракт паритета Р1 при этом не
  смягчается: байты на проводе и записи вывода на любом входе сверяются с C эталонами оракула и дифференциальными
  прогонами, а не сходством кода. Где идиоматичная реализация на битом входе наблюдаемо расходится с C, это либо
  чинится до равенства, либо становится именованным отличием E1/E2 справки 4c — решает контролёр по данным
  оракула, молча расходиться нельзя.
- **X.509 — Rust-нативный инкрементный обход DER**, а не перенос автомата C с таблицей `kludge_next` (~130
  состояний, справка TLS/SMB §2.2). Устройство: явный стек кадров «поле + остаток длины» фиксированной глубины,
  типизированный перечень полей сертификата по ходу обхода, длины — проверяемым разбором короткой и длинной
  формы, OID сравнивается по байтам значения с двумя константами (`55 04 03` и `55 1d 11`) без Aho-Corasick.
  Наблюдаемое поведение закрепляется эталонами и дифференциальным фаззингом против C (задача 3): на валидных
  сертификатах — равенство имён; терпимость C к битому DER (`PADDING` глотает хвост, ошибки тегов ведут себя
  по-состоянию) воспроизводится там, где она наблюдаема в выводе, по данным оракула, а не устройством автомата.
- **Хвост STARTTLS в том же сегменте идёт в TLS-парсер** (замена правила 4b E2.8). У C после согласия `state = 0`
  и остаток сегмента разбирает текстовый парсер как новое приветствие (второй `AUTH TLS`/`EHLO`/`CAPA`), а
  следующий сегмент уже TLS — итог C зависит от нарезки. Правило Р13 велело бы взять за эталон C на неразрезанном
  потоке, но тогда ServerHello, приехавший одним сегментом с согласием, никогда не разберётся как TLS. Предложение:
  каждый байт после строки согласия — в TLS-парсер в любой нарезке; отличие от C (класс E2, замена E2.8) пишется в
  справку 4c, README и §12 спеки. Живой сервер после согласия ждёт ClientHello, поэтому на практике хвост пуст.
- **Hello как у C: в Normal статичные, в режимах проверок один на скан** (уточнено задачей 0, справка 4c §A2).
  Обычные hello и hello второго соединения у C — байты шаблонов как есть, с запечённым random; `ssl_hello()` с
  `time(0)` и siphash-отпечатком применяется только к трём шаблонам режимов, один раз на скан. Следствие для
  стенда: в Normal hello сравниваются побайтно; поле random (байты 11..43) прощается только в прогонах режимов.

## Global Constraints

- `#![forbid(unsafe_code)]` в `rmasscan-proto` и `rmasscan-core`; новых внешних крейтов нет; `Cargo.lock` не
  меняется; `deny.toml` без изменений; ни одного файла C/C++/скрипта на запрещённом интерпретаторе
  (`language-guard`, `rust_only.rs`); обвязки C-оракула живут вне репозитория (Р14), каталог оракула не удалять,
  sudo вне документированных скриптов стенда не использовать.
- `rmasscan-proto` без proptest: случайные тесты — на xorshift-циклах крейта, как соседние.
- `studio/` не меняется ни на байт; новое в `rmasscan-engine`/`rmasscan-core` только аддитивно и по умолчанию
  выключено (Р11). Studio: `cargo check --locked` и `cargo xtask test` в отдельном `CARGO_TARGET_DIR`.
- Каждая сборка — со своим `CARGO_TARGET_DIR` вне дерева; `rmasscan/target` не создавать никогда (два ворктри на
  одном target запускают чужой бинарник в интеграционных тестах). Мутационные прогоны — отдельный ворктри и
  `touch` восстановленных файлов. Таргеты ревью удаляются сразу после ревью.
- Фоновые агенты и прогоны: `trap 'trap - EXIT INT TERM; kill 0' EXIT INT TERM` (форма без снятия ловушки крутит
  CPU навсегда); после каждого агента проверка `ps -Ao pid,%cpu,etime,command | awk '$2>80'`.
- После каждой задачи весь workspace собирается и проходит тесты. Без `--banners`/`--heartbleed`/`--ticketbleed`/
  `--vuln` вывод и кадры прежние побайтно.
- Парсеры — тотальные функции: ни паники, ни `unwrap` на данных, ни индексации без проверки, ни цикла без
  продвижения, ни рекурсии без предела (Р1 класс б); у каждого тест «никогда не паникует» и три нарезки (целиком,
  по байту, 8 случайных по seed) с одинаковым итогом (Р13; у TLS/X.509 C сам от нарезки не зависит, справка §7).
- Паритет: детерминированные странности C повторяются; исправляется только класс а–г, каждое исправление — строка
  README со ссылкой на C. Известные кандидаты 4c: `tcp_set_window` C считает сумму по IPv4-псевдозаголовку даже на
  IPv6 (у нас строитель кадров считает верно по семейству — класс г, проверить в задаче 0); мёртвый разбор
  validity с `mktime` (`src/proto-x509.c:994-1017`) не переносится, вывод его C всё равно не печатает.
- Независимое ревью с C-дифференциалом на каждую парсерную задачу (3, 4, 6): ревью внутри харнесса в 4b пропустило
  три Important в задачах 11–13. На каждое изменение верификатора — вопрос в обе стороны: может ли вина стенда или
  оракула записаться как FAIL rmasscan и может ли дефект rmasscan спрятаться за INVALID.
- Кросс-ОС: гейты гоняются на хосте стенда Linux и госте Windows до приёмки, а не только на Mac (тексты ошибок ОС,
  RSS, видимость FIN уже ловили 4b).
- Исполнитель пишет заметки по ходу работы в `.superpowers/sdd/2026-11-13-rmasscan-banners-4c/task-N-notes.md`.
- Доказательства — в нейтральных каталогах `mktemp -d`; хосты только по ролям; перед коммитом доказательств
  `rmasscan-lab privacy-scan --forbid <имена хостов и учёток>`; хэшированные доказательства не редактируются;
  `git add` только явными путями, голого `git stash` нет. Репозиторий публичный.
- Стенды: Linux netns на хосте оракула; Windows-VM стенда на хосте VM — трогать только её и каталог лаборатории
  гостя, никогда соседнюю VM и CI-раннер; после рестарта VM `w32tm /resync`, скрипты Windows — файлами под `pwsh`,
  не инлайн `-Command`; macOS `feth` — sudo пользователя и выключенный VPN.
- Ветка `feat/rmasscan-banners-4c` от `main` (`fab13114`) в ворктри `masscan-studio-4c`. Push/PR/merge 4c
  пользователем не предразрешены: спрашивать отдельно.

## Review Focus

1. **Цепочка сертификатов мелкими сегментами + FIN сервера:** записи `ssl`, `X509`, `X509CA` полны и одинаковы в
   любой нарезке; имена только листа — тесты задач 3 и 4 на векторах `ssl_test_case_3` и живой сценарий задачи 12.
2. **Второе соединение:** на TLS-порт уходят два ClientHello (по умолчанию — с `SF__close`, затем 1.3-hello) с
   портов `p` и следующего по `_next_IP_port`; сервер отвечает только на второе — баннер всё равно записан; при
   явном одном `--source-port` поведение и текст как у C — тесты задач 7 и 10, окно задачи 12.
3. **STARTTLS вживую (SMTP):** после `220` на проводе ClientHello, баннер `ssl` дописан после записи `smtp` в
   порядке B3; отказ `454` — ни hello, ни записи `ssl` — задача 6 и окно.
4. **`--heartbleed`:** против ответчика, возвращающего heartbeat, — запись `vuln` `SSL[HEARTBLEED]`, кадры с окном
   600; против обычного TLS-сервера ложного `vuln` нет — задачи 4, 9, 12.
5. **Огромный сертификат и бесконечные записи:** запись режется на 65 536 (Р5), бюджет таблицы 512 МиБ считает
   потери, скан завершается `Completed` — тесты задач 1, 4 и 10.

---

### Шаг П (до задачи 0): план в репозитории

**Files:**
- Create: `docs/superpowers/plans/2026-11-13-rmasscan-banners-4c.md` (этот план; статус утверждён, решения
  раздела на ревью приняты)

- [ ] **Step 1:** privacy-scan по файлу; **коммит** `docs(rmasscan): banners 4c (TLS/X.509) implementation plan`.

### Задача 0: справка 4c — сверка TLS-справки с исходниками C

Ни одной строки кода. Справка TLS/SMB писалась до 4b; как справка TCP 4b (§F) поправила ранние справки, справка 4c
фиксирует все байты и состояния, на которые опираются задачи 1–14. SMB-половина не сверяется (4d сверит свою).

**Files:**
- Create: `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tls.md`
- Modify: `docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md` (шапка: шестая справка и правило
  главенства для 4c при расхождении со справкой TLS/SMB)

**Interfaces:**
- Produces: справку со структурой справки TCP (A — потоки и hello, B — автомат записей, C — X.509, D — режимы
  проверок и опции, E — отличия: E1 исправления класса а–г, E2 зависимость от нарезки, E3 сохраняемые странности,
  F — поправки к справке TLS/SMB, каждая с `src/файл.c:строка` на пине `8e6b3b0`).

- [ ] **Step 1: hello и потоки.** Пять шаблонов побайтно из исходников (`src/proto-ssl.c`, `src/vulncheck-heartbleed.c`,
  `src/vulncheck-sslv3.c`): длины, списки шифров, расширения; `ssl_hello()` (смещение и ширина полей time и
  siphash, ключ, что именно хэшируется), `ssl_add_cipherspec` (SCSV, правка трёх длин, поведение не на SSLv3);
  регистрация `banner_ssl`/`banner_ssl_12` (флаги, `next`); точный список предустановленных TLS-портов из
  `src/proto-banner1.c` (справка TLS/SMB §1.1 даёт его с «?» — снять все вопросы, сверить с B4 справки TCP: 23);
  переназначение всех портов при `--hello ssl` и режимах проверок (`src/stack-tcp-core.c:500-507,537-588`).
- [ ] **Step 2: стековые механики.** `SYN_SENT`: когда новый TCB шлёт SYN (таймер при создании, значение seq на
  проводе против хранимого `seqno+1`), повтор SYN по тикам, TTL 255; `_next_IP_port` на границах (ширина 1, 2, 17;
  обёртка по портам сдвигает IP; IPv6-ветка «untested»); `ERRMSG` при том же порте — текст, куда, как часто;
  `App_SendFirst` кладжи (`banner_set_sslhello`, `banner_set_small_window`, `SF__close`, `SF__nowait_hello` у
  потоков TLS — есть или нет); малое окно 600: какие кадры его несут; `tcp_set_window` на IPv6 (псевдозаголовок,
  класс г).
- [ ] **Step 3: автомат TLS.** `ssl_parse_record`, `parse_handshake`, `parse_server_hello`, `parse_alert`,
  `parse_heartbeat`, `parse_server_cert` состояние в состояние против справки §1.4–§1.5: каждое расхождение —
  строка §F. Отдельно: момент отправки heartbleed-запроса; условия записей `vuln`/`safe`/`heartbleed`/`ticketbleed`
  дословно; поведение на типе записи с верхним битом, версии не 3, рукопожатии не 2/11; `remaining` на границах
  сегментов; что происходит с хвостом потока после UNKNOWN.
- [ ] **Step 4: X.509 и banout.** Состояния и `kludge_next` — полнота таблицы §2 справки; стек длин (пределы 9 и
  64 КиБ, child-overflow); какие OID реально пишутся; правило «имена только первого сертификата» (`count`);
  `banout_end`: что делает следующий `banout_append_base64` того же протокола (цепочка из 3+ сертификатов — одна
  запись `X509CA` или несколько; как это видит `banner_flush` и форматы вывода); потоковый base64 через границы
  сегментов и через границу сертификатов; `is_capture_subject/issuer` на живом пути и в `--readscan`
  (`src/in-report.c`) — что именно перекодирует C при чтении `-oB` и в какие форматы это видно.
- [ ] **Step 5: опции.** `SET_capture`, `--heartbleed`, `--ticketbleed`, `--vuln` (полный список значений C, включая
  не-TLS: как с ними поступает план — перенос только TLS-значений, остальные код 1 со строкой C или именованное
  отличие), `--sslv3` (`src/main-conf.c:1132-1178,2810-2819,2929-2941`): побочные эффекты каждого (banners on,
  nocapture по умолчанию, hello на все порты), порядок при нескольких опциях сразу, `tcpcon_set_parameter` против
  `tcpcon_set_banner_flags`, эхо `--echo` (что печатает C для этих опций — ничего? проверить), paused.conf.
- [ ] **Step 6:** список E1/E2/E3 для 4c (включая замену E2.8 из «Решений на ревью» и судьбу E3.5);
  **коммит** `docs(rmasscan): banners 4c C reference (TLS/X.509), verified against 8e6b3b0`.

### Задача 1: banout — потоковый base64 и `banout_end`

**Files:**
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/banout.rs`, `rmasscan/crates/rmasscan-proto/src/banner1/session.rs`
  (доступ из `ParseCx`), эталоны при необходимости не трогаются

**Interfaces:**
- Consumes: задача 0 §4 (семантика `banout_end` и записи цепочки).
- Produces: `pub(crate) struct Base64Stream` в `banout.rs` (`state: u8, temp: u32` как `struct BannerBase64`,
  `src/proto-banout.c:376-442`): `Banout::append_base64(&mut self, budget, b64: &mut Base64Stream, app: u16, px: &[u8])`,
  `Banout::finalize_base64(&mut self, budget, b64: &mut Base64Stream, app: u16)` (набивка `=`/`==`),
  `Banout::end(&mut self, app: u16)` с семантикой задачи 0; состояние кодера — одно на сессию (как
  `StreamState` C), лежит в сессии и пробрасывается в `ParseCx`. Все прежние правила действуют: предел записи
  65 536 (Р5), бюджет таблицы с потерей с конца и счётчиком (И9), порядок сброса B3.

- [ ] **Step 1: тесты** `base64_stream_matches_c_selftest_vectors` (векторы `banout_selftest`,
  `src/proto-banout.c:463-540`: `eA==`, `YmM=`, `bW5v`, `c3R1dg==`, `ZmdoaWo=`), `base64_same_in_any_fragmentation`
  (тот же DER кусками 1/2/3/7/случайно — одна строка), `base64_finalize_only_at_end`,
  `ended_record_semantics_match_c` (по задаче 0: цепочка из трёх «сертификатов»), `base64_respects_record_cap_and_budget`
  (65 536 и бюджет таблицы: потеря считается, запись не дописывается), `base64_flush_order_with_text_record`
  (порядок B3 при соседстве с записью короче и длиннее 200 байт).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-proto`; **коммит**
  `feat(rmasscan-proto): streaming base64 and banout_end in Banout (C proto-banout parity)`.

### Задача 2: SipHash-2-4 и строители ClientHello

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/tls_hello.rs`
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/mod.rs`
- Test data: выгрузка оракула вне репозитория → `rmasscan/tests/golden/tcp-banners/` (случаи hello, манифест)

**Interfaces:**
- Consumes: справка 4c §A2; `rmasscan_core::cookie::siphash24` (уже сверен с векторами
  `src/crypto-siphash24.c` — новой реализации хэша нет).
- Produces:
  - `pub(crate) enum TlsHelloKind { Default, Tls13, Heartbeat, Ticketbleed, Sslv3Poodle }`;
    `pub(crate) fn tls_hello(kind: TlsHelloKind, now_secs: u64) -> Vec<u8>`: `Default`/`Tls13` — статичные
    шаблоны байт в байт как C (`now_secs` игнорируется, справка §A2); остальные три — динамизация как
    `ssl_hello()` (`src/proto-ssl.c:1224-1254`): `time` BE в байтах 11..15, дальше младший байт
    `siphash24((i + now) как u32 LE, 0, 0)` для i в 4..32; для `Sslv3Poodle` — плюс `TLS_FALLBACK_SCSV 0x5600`
    в конец списка шифров с правкой трёх длин (`ssl_add_cipherspec_sslv3`, `:1123-1178`).
  - Шаблоны — константы байт в байт как C (198, 287, 225, 361, 72 байта до SCSV; справка §A2).

- [ ] **Step 1: выгрузка оракула.** Расширить офлайн-обвязку 4b (`tcp-oracle`, справка TCP E4 уже собирает
  TLS-юниты для `banner1_create`): печать пяти `banner_ssl.hello` после каждой опции режима при фиксированном
  `time()` (переопределение в обвязке) и шаблонов как есть; в репозиторий — байты, `now`, хэш обвязки и коммит C в
  манифест.
- [ ] **Step 2: тесты** `tls_hellos_match_c_byte_for_byte` (пять видов при том же `now`; Normal — без
  динамизации при любом `now`), `sslv3_scsv_append_fixes_all_lengths`,
  `vuln_hello_random_is_time_and_siphash_u32le` (байты 11..43, ключ {0,0}, вход — `(i + now)` как u32 LE),
  `tls_hello_never_panics`.
- [ ] **Step 3: FAIL** → реализация.
- [ ] **Step 4: PASS** `cargo test -p rmasscan-proto`, privacy-scan по эталонам; **коммит**
  `feat(rmasscan-proto): five TLS ClientHello builders and siphash24 fingerprint (C parity)`.

### Задача 3: парсер X.509

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/x509.rs`
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/mod.rs`
- Test data: `rmasscan/tests/golden/x509/{README.md,manifest.json,cases/*}` (DER из `src/proto-ssl-test.c` и
  вывод оракула), `rmasscan/crates/rmasscan-proto/tests/x509_golden.rs`

**Interfaces:**
- Consumes: задачи 0 §C, 1 (запись имён идёт прямо в `Banout` приложения `ssl`, как у C).
- Produces: `pub(crate) struct X509` — Rust-нативный инкрементный обход DER (решение выше), не транскрипция
  `src/proto-x509.c`: стек кадров `[Frame; MAX_DEPTH]` («какое поле + сколько байт в нём осталось»), типизированный
  `enum Field` по пути `Certificate → TBSCertificate → subject/extension`, разбор тега и длины (короткая форма,
  `0x81`, `0x82`; прочее — ошибка поля) проверяемыми функциями, счётчик сертификата `count`.
  `fn init(&mut self, cert_len: usize, count: u32)` и `fn feed(&mut self, cx: &mut ParseCx<'_>, px: &[u8])` —
  имена листа дописываются в `ssl` каждое с префиксом `", "`, имена цепочки подавляются (`count <= 1`). OID
  сравнивается по байтам значения с `55 04 03` (CN) и `55 1d 11` (SAN) без Aho-Corasick; остальные OID таблицы
  `mib[]` на наблюдаемый вывод не влияют (задача 0 подтверждает). Пределы тотальности явные и свои, но не слабее
  наблюдаемых у C: длина поля, не влезающая в родителя, — ошибка поля (аналог child-overflow `ASN1_push`,
  `src/proto-x509.c:345-351`), глубина стека фиксирована, длина сертификата >64 КиБ не разбирается (потолок C,
  задача 0). Поля validity пропускаются структурно (мёртвый `mktime` C не переносится). Ни одной аллокации на
  байт; состояние — фиксированные массивы; рекурсии нет.

- [ ] **Step 1: эталоны оракула.** Обвязка над `proto-x509.c` (как §7 справки TLS/SMB): `google_cert`,
  `yahoo_cert`, лист и CA из `ssl_test_case_3`, сертификат из `ssl_test_case_1` — вывод C целиком и по байту;
  плюс искажённые варианты (обрыв на каждой границе поля, длина 0x81/0x82, ребёнок длиннее родителя, глубина 10,
  SAN без CN, CN не-ASCII, пустой ввод). В репозиторий — DER и вывод C с provenance в манифесте.
- [ ] **Step 2: тесты** `x509_golden_matches_c` (все случаи, три нарезки), `only_leaf_names_emitted`
  (`count` 2 и 3 не пишут имён), `x509_never_panics` (xorshift: мутации DER и случайные байты с `init` на
  случайных длинах, включая 0 и >64 КиБ; нет цикла без продвижения — `feed` всегда потребляет вход).
- [ ] **Step 3: FAIL** → реализация обхода по полям (комментарии — ссылки на справку 4c §C и `src/proto-x509.c:NNN`
  там, где воспроизводится наблюдаемая терпимость C).
- [ ] **Step 4: PASS** `cargo test -p rmasscan-proto`, privacy-scan по эталонам; независимое ревью с
  C-дифференциалом: мутированные DER против оракула — каждое наблюдаемое расхождение либо закрыто, либо ушло в
  E-список справки 4c решением контролёра; **коммит**
  `feat(rmasscan-proto): X.509 certificate name parser (C proto-x509 parity)`.

### Задача 4: парсер TLS-записей (ServerHello, сертификаты, alert, heartbeat)

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/tls.rs`
- Modify: эталоны `rmasscan/tests/golden/tcp-banners/` (случаи TLS вида `records`),
  `rmasscan/crates/rmasscan-proto/tests/tcp_golden.rs` при необходимости полей манифеста (флаги capture/режима)

**Interfaces:**
- Consumes: задачи 0 §B/§D, 1 (base64 захвата), 3 (`X509`), существующие `Parser`/`ParseCx`/`banner_stream`.
- Produces: `pub(crate) struct Tls` (`impl Parser`) — возобновляемый автомат по справке 4c §B (поведение
  `ssl_parse_record` и подпарсеров, `src/proto-ssl.c:892-1053`, `:522-652`, `:127-339`, `:788-867`, `:668-775`,
  `:370-495`): записи типов
  20/21/22/23/24, рукопожатия 2 и 11, остальные пропускаются; баннер `ssl` (версия, `cipher:0x%x`, имена из
  задачи 3, ` ALERT(0x%02x%02x) `); при `capture_cert` — DER листа в `X509`, цепочки в `X509CA` потоковым base64
  с `end` на сертификате; режимы из настроек (задача 5 пробросит поля, здесь — поля в `ParseCx` или конструкторе,
  как решит задача 0 по `tcpcon_set_banner_flags`): heartbeat-расширение ServerHello → `vuln "SSL[heartbeat] "`,
  heartbleed-отправка на ServerHello — действие `Send` байтами C (`src/proto-ssl.c:583-588`), ответ heartbeat с
  `remaining>=16` → `vuln "SSL[HEARTBLEED] "` и при `capture_heartbleed` base64 в `heartbleed`; ticketbleed по
  длине session-id; poodle по версии и веткам alert → `vuln`/`safe` дословно.
- В этой задаче парсер ещё не подключён к каркасу (`parser_for` и `force_app` на SSL3 трогает задача 5); проверка —
  прямыми тестами парсера на тех же эталонах (конструкция `Tls` и `ParseCx` в тесте).

- [ ] **Step 1: случаи оракула** (вид `records`): `ssl_test_case_1/2/3` целиком (ожидаемые баннеры §5.3 справки:
  `TLS/1.2 cipher:0xc007, *.google.com, …`; case3 с захватом — `X509` 1916 байт base64 и `X509CA` 1808) и без
  захвата; цепочка из трёх сертификатов; ServerHello с heartbeat-расширением 0 и 1; alert fatal 86/40/прочий в
  режиме poodle и без; heartbeat-ответ `remaining` 0/15/16/0x4000 с захватом и без; session-id 16/17/32 в режиме
  ticketbleed; SSLv3 ServerHello в режиме poodle; записи 20/23 игнорируются; тип с верхним битом; версия записи
  не 3; обрыв на каждой границе заголовков; два рукопожатия в одной записи и запись, разрезанная на все сегменты.
- [ ] **Step 2: тесты** `tcp_golden_matches_c` (новые случаи, три нарезки, действия только целиком),
  `heartbleed_probe_sent_once_on_server_hello`, `cert_capture_off_by_flag`, `tls_never_panics` (xorshift-мутации
  векторов §5.3 и случайные потоки с префиксами записей; потребление входа всегда продвигается).
- [ ] **Step 3: FAIL** → реализация.
- [ ] **Step 4: PASS** `cargo test -p rmasscan-proto`, privacy-scan; независимое ревью с C-дифференциалом;
  **коммит** `feat(rmasscan-proto): TLS record parser with X.509 capture and vuln checks (C proto-ssl parity)`.

### Задача 5: каркас — таблица потоков, `AppProto::Tls`, настройки TLS

**Files:**
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/{hello.rs,session.rs,classify.rs,driver.rs}`,
  `rmasscan/crates/rmasscan-proto/src/tcp/app.rs` (класс `Session`: свойства потока),
  `rmasscan/crates/rmasscan-proto/src/lib.rs`
- Test: существующие `hello_table_4b` и тесты сессии обновляются до правил 4c

**Interfaces:**
- Consumes: задачи 2 (`tls_hello`), 4 (`Tls`), 0 §A/§D.
- Produces:
  - `pub struct TlsSettings { pub hellos: [Arc<[u8]>; 5] /* по TlsHelloKind, построены CLI на старте скана */,
    pub mode: TlsMode, pub capture_cert: bool, pub capture_heartbleed: bool, pub capture_ticketbleed: bool }`,
    `pub enum TlsMode { Normal, Heartbleed, Ticketbleed, Poodle }` (точные поля — по задаче 0 §5: что ставит
    каждый режим в `Banner1`); `TcpBannerSettings` получает `pub tls: TlsSettings`.
  - Таблица потоков вместо только hello: `pub(crate) struct StreamDesc { pub hello: Option<Arc<[u8]>>,
    pub close_after_hello: bool, pub next: Option<Arc<[u8]>>, pub small_window: bool, pub is_tls: bool }` —
    `Session::hello()` заменяется/дополняется доступом слоя приложения к дескриптору (здесь дескриптор строится и
    отдаётся сессии; `next` и `close_after_hello` исполняет слой приложения в задаче 7). TLS-порты B4 (23,
    задача 0): hello по режиму (`Default` в Normal), `close_after_hello = true` только у первого потока,
    `next = Tls13`-hello (в режимах проверок `next` — по задаче 0), `is_tls = true`. `--hello ssl` — тот же поток
    на портах 0..65534 вместо сегодняшнего «поток без hello» (`hello.rs:99-114` переписывается); `--hello-string`
    на TLS-порту сохраняет `close_after_hello` и `next` потока (E3.5, `src/stack-tcp-core.c:595-616`).
  - `AppProto::Tls`; `parser_for(Tls)` — парсер задачи 4 с настройками скана; `app_proto_for(SSL3)` → `Tls`.
    SMB остаётся `Unported` (4d).
  - Настоящий `is_sent_sslhello`: константа `SSL_HELLO_SENT` (`session.rs:289`) заменяется состоянием сессии,
    которое ставит слой приложения при отправке TLS-hello (хук в `Session`, задача 7 проводит его через
    `App_SendFirst`; здесь — поле и его установка из дескриптора при `hello()` + метод для слоя). Совпадение SSL3
    классификатором без отправленного hello по-прежнему отвергается (B1.2), с отправленным — поток идёт в `Tls`.

- [ ] **Step 1: тесты** `stream_table_4c` (23 TLS-порта: hello режима, `SF__close`, `next`; SMB и NPSL — NULL;
  прежние «sent» B4 без изменений), `hello_ssl_sends_on_every_port_but_65535`, `hello_string_on_tls_port_keeps_stream_flags`
  (E3.5 на уровне дескриптора: свой hello, но `close_after_hello` и `next` потока TLS), `ssl3_classifier_gate_follows_sent_hello`,
  `tls_stream_records_via_framework` (случаи задачи 4 теперь и без `force_app` на 443), обновлённые
  `hello_table_4b` → правила 4c (список изменённых ожиданий — в заметки задачи).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-proto`; **коммит**
  `feat(rmasscan-proto): TLS streams in the banner framework (hello table, classifier gate, settings)`.

### Задача 6: настоящий STARTTLS

**Files:**
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/{ftp.rs,smtp.rs,pop3.rs,session.rs}`,
  эталоны `tcp-banners` (случаи `declared-4b` согласия STARTTLS становятся `records`)

**Interfaces:**
- Consumes: задачи 4, 5.
- Produces: `ParseCx::hand_off_starttls` по C минус заменённое правило E2.8 (решение на ревью): действие
  `SendShared(hello режима)`, сессия переключает парсер на `Tls` и номер на SSL3, `is_sent_sslhello = true`;
  `rest` того же сегмента и все следующие байты — в TLS-парсер (не в `unknown`, не в текстовый парсер). IMAP4
  недостижим, как у C (`src/proto-imap4.c` закрывает раньше).

- [ ] **Step 1: случаи оракула.** Согласия FTP 234/SMTP 220/POP3 `+OK`, за ними ServerHello+Certificate вектора
  case3: целиком одним сегментом, разрезано на строке согласия, по байту (вывод C в нарезках — свидетельство
  нового E2: наш эталон — правило решения, а не каждая нарезка C); отказы 454/530/`-ERR` без изменений 4b.
- [ ] **Step 2: тесты** `tcp_golden_matches_c` (обновлённые случаи), `starttls_sends_mode_hello_and_parses_tls`,
  `starttls_tail_in_same_segment_is_tls` (правило решения), `starttls_refused_sends_no_hello`,
  переписанный `starttls_success_switches_to_unported_tls` (4b) под новое правило; независимое ревью с
  C-дифференциалом.
- [ ] **Step 3: FAIL** → реализация; **Step 4: PASS**; **коммит**
  `feat(rmasscan-proto): real STARTTLS hand-off to the TLS parser`.

### Задача 7: стек — `SYN_SENT`, реконнект, кладжи SendFirst, малое окно

**Files:**
- Modify: `rmasscan/crates/rmasscan-proto/src/tcp/{tcb.rs,table.rs,app.rs,stack.rs}`,
  `rmasscan/crates/rmasscan-core/src/stack.rs` (`TableParams` — аддитивно),
  `rmasscan/crates/rmasscan-proto/src/banner1/session.rs` (дескриптор потока в сессии)

**Interfaces:**
- Consumes: задачи 0 §2, 5 (`StreamDesc`).
- Produces:
  - `TableParams` получает аддитивно диапазоны источника таблицы: `pub src_ports: (u16, u16)` и локальные
    диапазоны адресов по семействам (форма — по существующим типам плана движка; значение по умолчанию сохраняет
    поведение 4b: ширина 1). Движок заполняет их в задаче 8; здесь — тип, проброс в фабрике и тесты на значениях
    по умолчанию.
  - Автомат: строка `SYN_SENT` справки A4 — на `Timeout` сегмент SYN `0x02` (seq по задаче 0), на `SynAck` —
    как обычное установление; жизнь соединения считается от создания TCB (задача 0). Создание TCB реконнекта в
    таблице: ключ со следующим портом по `_next_IP_port` (включая сдвиг IP при обёртке портов и ветку IPv6),
    `seqno` — `syn_cookie_ipv4/ipv6` ядра на seed таблицы (тот же, что проверяет движок в `parse_reply`), сессия
    строится из `next`-дескриптора (hello 1.3, без `close_after_hello`, без своего `next`). Полная таблица —
    реконнект не создаётся и считается тем же счётчиком, что SYN-ACK сверх предела (И10) — или отдельным, как
    решит задача 0 по поведению C при полном хэше; решение в заметки.
  - `AppLayer` на `Connected`: если у потока есть `next` — запрос реконнекта в таблицу (новый вариант действия
    слоя, `TcbCtl::reconnect()`), как `tcpapi_reconnect` (`src/stack-tcp-app.c:56-63`). На SendFirst: кладжи
    (`src/stack-tcp-app.c:154-195`) — TLS-потоку `session.note_tls_hello_sent()`, режиму heartbleed — флаг малого
    окна TCB; `SF__close` — `close()` сразу после hello. Малое окно: TCB несёт флаг, все его `SegmentOut` после
    установки получают `window: Some(600)` (ядро уже умеет, `tcp_frame.rs:229`); какие именно кадры — задача 0.
  - Ошибка «тот же порт» при ширине 1: счётчик в `StackStats` (аддитивно, например `reconnect_no_port: u64`) —
    CLI печатает её строкой итога в задаче 10, а не на каждое соединение (частота C `ERRMSG` — задача 0; отличие
    в форме именуется в README).

- [ ] **Step 1: тесты** (стенд задач 6/7 подэтапа 4b: `Session`-заглушка и таблица на `ManualClock`):
  `reconnect_creates_syn_sent_tcb_on_next_port`, `reconnect_syn_seq_is_cookie` (движок примет SYN-ACK: cookie на
  seed таблицы, IPv4 и IPv6), `reconnect_syn_resent_on_ticks`, `next_port_wraps_and_advances_ip` (ширина 2 и 17,
  диапазон IP из двух), `reconnect_same_port_counted_not_created_twice` (ширина 1: как C по задаче 0),
  `second_connection_gets_next_hello_without_close`, `sf_close_fin_follows_first_hello`,
  `small_window_on_all_frames_after_send_first`, `reconnect_tcb_dies_by_lifetime_and_finish`,
  `table_full_refuses_reconnect_without_status_loss`, `stack_never_panics_with_reconnects` (xorshift-цикл
  расширен: случайные дескрипторы с `next`).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-proto -p rmasscan-core`, studio `cargo check --locked`;
  **коммит** `feat(rmasscan-proto): SYN_SENT reconnect, SendFirst TLS kludges, heartbleed small window`.

### Задача 8: движок и CLI — модель порта источника Р10 под `--banners`

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/live.rs` и место сборки плана/опций движка (по факту на вершине:
  где `EngineOptions.tcp_stack` получает `TableParams` и где строится `NicBinding`),
  `rmasscan/crates/rmasscan-engine/src/{engine.rs,banners.rs}` только если проброс диапазонов требует поля,
  `rmasscan/README.md`
- Test: `rmasscan/crates/rmasscan-cli/tests/live_fake.rs`, тесты движка приёма

**Interfaces:**
- Consumes: задача 7 (`TableParams` с диапазонами), решение Р10 (узкое прочтение).
- Produces: при `--banners` (и режимах задачи 9, которые включают баннеры) и порте источника по умолчанию
  привязка адаптера получает `source_ports = (p, p + 16)` и `legacy_c_17_port_mask = true`; при явном
  `--source-port`/`adapter-port` — без изменений. Таблица стека получает те же диапазоны портов и локальных
  адресов плана. Без `--banners` план побайтно прежний (все прежние окна не видят разницы). Граница `p + 16`
  у верха u16 — поведение по задаче 0 (что делает C с маской у 65535) или отказ код 1 по Р17; в заметки и README.

- [ ] **Step 1: тесты** `banners_default_source_port_widens_to_17`, `explicit_source_port_never_widened`,
  `no_banners_plan_unchanged` (кадры и привязка побайтно как до задачи), `second_connection_synack_accepted`
  (сквозной на `FakeAdapter`: SYN-ACK на `p`, реконнект-SYN с `p+1`, его SYN-ACK проходит cookie и дедуп, статус
  `open` один), `widening_at_port_top_behaves_as_decided`.
- [ ] **Step 2: FAIL** → реализация; README: строка Р10 (модель, когда включается, граница сверху).
- [ ] **Step 3: PASS** `cargo test -p rmasscan-engine -p rmasscan-cli`, clippy, studio `cargo check --locked` и
  `cargo xtask test`; **коммит**
  `feat(rmasscan): C {p, p+16} source-port pool under --banners for TLS reconnect (Р10)`.

### Задача 9: CLI — опции `--heartbleed`, `--ticketbleed`, `--vuln`, `--sslv3`; настройки TLS

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/config.rs` (поля режима в `ScanConfig`, `apply_core_kv`, echo —
  по задаче 0 §5), `rmasscan/crates/rmasscan-cli/src/{args.rs,conf.rs,lib.rs,banner_settings.rs}`,
  тест `rmasscan-cli/src/lib.rs:566` (`--heartbleed` больше не ошибка) переписывается

**Interfaces:**
- Consumes: задачи 0 §5, 5 (`TlsSettings`/`TlsMode`), 2 (строители).
- Produces: разбор по `EQUALS` (Р17) для `--heartbleed`, `--ticketbleed` и `--vuln <v>` со значениями
  `heartbleed|ticketbleed|poodle|sslv3` (опции-имени `--sslv3` у C нет, справка §E2; прочие значения, включая
  `ntp-monlist`, — фатальный текст C и код 1, именованное отличие); побочные эффекты как у C:
  режим включает `banners`, поток TLS на все порты, умолчания `nocapture` режима (явные `--capture` после него
  побеждают в порядке argv, как `SET_capture`); `tcp_banner_settings` строит пять hello один раз на скан
  (`now_secs` — настенные часы сборки настроек) и заполняет `TlsSettings` из `ScanConfig.capture` и режима.
  Неизвестное значение `--vuln` — код 1 (текст по задаче 0). Конфликт режимов сразу (например `--heartbleed
  --vuln poodle`) — как C по порядку обработки (задача 0 §5).

- [ ] **Step 1: тесты** `heartbleed_enables_banners_and_tls_mode`, `ticketbleed_and_poodle_modes`,
  `sslv3_is_vuln_poodle`, `vuln_bad_value_fails`, `mode_nocapture_defaults_and_explicit_capture_wins`,
  `tls_settings_capture_flags_reach_proto` (cert по умолчанию включён, `--nocapture cert` выключает),
  `tls_modes_in_config_file_and_paused_conf` (тот же разбор через `-c`, round-trip паузы),
  `modes_echo_as_c` (по задаче 0), `hellos_built_once_with_scan_time` (два соединения — один буфер, `Arc` тот же).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-core -p rmasscan-cli -p rmasscan-proto`; **коммит**
  `feat(cli): --heartbleed, --ticketbleed, --vuln poodle|sslv3 and TLS capture plumbing (C parity)`.

### Задача 10: живой скан с TLS на `FakeAdapter`, итоги и README

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/{live.rs,status.rs,lib.rs}`,
  `rmasscan/crates/rmasscan-cli/tests/{live_fake.rs,live_fake_ipv6.rs}`, `rmasscan/README.md`,
  `connection_memory_floor()` в `rmasscan-proto` (новый размер сессии: состояние TLS + X.509)

**Interfaces:**
- Consumes: задачи 5–9.
- Produces: сквозной живой путь без новых опций движка (стек уже включён CLI при `--banners` в 4b): записи
  `ssl`/`X509`/`X509CA`/`vuln`/`safe`/`heartbleed`/`ticketbleed` во всех форматах прежним путём вывода; в итоге
  stderr добавляется строка счётчика реконнекта без порта (задача 7), только ненулевая, форматом как соседние
  строки И18; статус `tcbs` считает и реконнекты (проверить против `src/main.c:984`).

- [ ] **Step 1: сценарные тесты CLI** `live_fake_tls_banner_end_to_end` (443: SYN-ACK; реконнект-SYN следом; на
  первом соединении через 2 с ClientHello 198 байт и FIN за ним по `SF__close`; ответ case3 сегментами → `-oL`:
  `open`, затем `ssl` с именами листа, `X509`, `X509CA` байтами оракула; второе соединение получает 1.3-hello),
  `live_fake_tls_server_first_no_hello` (сервер говорит первым ServerHello — hello не уходит, поток `unknown`,
  B1.2), `live_fake_starttls_smtp_banner` (25: EHLO/STARTTLS/220 → ClientHello → записи `smtp` затем `ssl`),
  `live_fake_heartbleed_vuln_record` (режим из задачи 9: зонд на ServerHello, heartbeat-ответ → `vuln`; кадры с
  окном 600), `live_fake_tls_ipv6_banner`, `live_fake_tls_flushed_at_end_of_wait` (сервер держит соединение:
  баннеры в конце `--wait`, без FIN/RST), `tls_records_in_all_formats` (`-oB/-oJ/-oX/-oG` на том же сценарии),
  `readme_names_connection_memory_cost` обновлён под новый `connection_memory_floor()`.
- [ ] **Step 2: FAIL** → реализация недостающего (ожидаемо мало: итоги и README). README: TLS-порты и hello,
  `--capture cert`, режимы проверок, второе соединение и Р10, STARTTLS и замена E2.8, отличия E1 4c со ссылками
  на C, из «Не перенесено» уходят TLS и `--hello ssl` (остаются SMB 4d и NPSL Р3); `after_help` — пример
  `--banners -p443`.
- [ ] **Step 3: PASS** всё (`cargo test --workspace`, clippy на всех целях, fmt, language-guard); studio
  `cargo check --locked` и `cargo xtask test` без правок; **коммит**
  `feat(rmasscan): TLS banners in live scans (ClientHello pair, cert capture, STARTTLS, vuln modes)`.

### Задача 11: `--readscan` и формат `certs` против C

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/{readscan.rs,output/formats.rs,output/pipeline.rs}` — только в объёме,
  который назовёт сверка шага 1
- Test data: `-oB` с TLS-записями, построенный оракулом C, в существующих эталонах форматов
  (`rmasscan/tests/golden/formats` или сосед по факту), документы C `--readscan` из него

**Interfaces:**
- Consumes: справка 4c §E4 (перекодировка в `src/in-report.c` — мёртвый код, вызов закомментирован; subject/issuer
  при чтении не появляются), задачи 3, 4.

- [ ] **Step 1: сверка.** C `--readscan` на `-oB` с записями `ssl/X509/X509CA/vuln/heartbleed` во все форматы
  (`-oL/-oJ/-oX/-oG`, `certs` в stdout) против rmasscan `--readscan` того же файла. Отдельно: `certs` оборачивает
  в PEM **каждую** запись баннера, не только X509, и печатает в stdout (справка §E4): срез префикса `cert:`,
  72 колонки, `{finished: 1}`; обрезанная на 65 536 запись сертификата при чтении; две записи `X509CA` одного
  соединения (цепочка из трёх, справка §B4) во всех форматах.
- [ ] **Step 2: тесты** по итогам шага 1: `readscan_tls_records_match_c_all_formats`, `certs_format_matches_c`
  (обёртка каждой записи, префикс, финальная строка, stdout против файла).
- [ ] **Step 3: FAIL** → реализация; если расхождений нет — задача закрывается тестами без кода, это фиксируется в
  заметках.
- [ ] **Step 4: PASS** `cargo test -p rmasscan-cli`; **коммит**
  `feat(cli): --readscan and certs output for TLS banner records (C parity)` (или `test(cli): …`, если кода не было).

### Задача 12: стенд — TLS-сценарии, верификатор окна `banners`, фаззер TLS/X.509

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/{banners_suite.rs,banners_verify.rs,capture.rs,fuzz.rs,main.rs}` и их
  тесты, `rmasscan/scripts/wire-lab.sh`, `rmasscan/docs/rust-lab.md`

**Interfaces:**
- Consumes: задача 10 (живой CLI), сценарии и верификатор 4b (задача 15 подэтапа 4b).
- Produces: TLS-сценарии ответчика `capture responder --tcp-answer banners` (потоки из эталонов задач 3/4, не
  настоящий TLS-сервер: детерминированные байты); правила верификатора для TLS; семейства фаззера `tls` и `x509`.

- [ ] **Step 1: сценарии.** На адресах пира, как сценарии 4b: TLS 443 (case3 целиком и сегментами по 200 мс — с
  проверкой на проводе, что сегментов >1, иначе INVALID), цепочка из 3, alert после ServerHello, молчащий
  TLS-порт (hello уходит, ответа нет), heartbeat-ответчик для режима (отдельный argv окна с `--heartbleed`),
  STARTTLS на 25 (согласие + case3), отказ STARTTLS, сервер, отвечающий только второму соединению. Всё на IPv4;
  на IPv6 — 443 и STARTTLS (Р16). Пульс `WIRELAB-BEAT` и argv окна — как в 4b (И14/И15).
- [ ] **Step 2: верификатор.** Записи `ssl/X509/X509CA/vuln/safe` равны C мультимножеством поле в поле без
  времени; на проводе по соединению: hello равно C побайтно (в прогоне `--heartbleed` — с точностью до поля
  random, байты 11..43, справка §A2; остальные байты, длина, порядок сегментов, относительные seq/ack — точно),
  FIN после первого hello, SYN реконнекта со
  следующего порта и его cookie, окно 600 в режиме heartbleed; время hello и RST жизни — допуски 4b. Виды
  отличий окна — только из E-списка справки 4c. Вопрос в обе стороны (Global Constraints): сценарий, где пир не
  доиграл поток, — INVALID, а не FAIL rmasscan; пропавший второй SYN — FAIL, а не INVALID. Тесты на фикстурах:
  PASS, нет второго соединения, чужой hello вне random, нет FIN `SF__close`, окно не 600, обрезанная запись
  сертификата не той длины.
- [ ] **Step 3: фаззер.** Семейства `tls` (через `banner_stream(.., force_app = SSL3)` с режимами по seed) и
  `x509` (DER напрямую в парсер задачи 3 через тестовый вход драйвера; если входа нет — аддитивно
  `#[doc(hidden)]` в `rmasscan-proto`, как `banner_stream`): корпус — эталоны задач 3/4 и захваты окна; инварианты
  прежние (нет паники, <100 мс лучший из трёх, записи ≤65 536, нарезка = целиком (Р13), RSS <64 МиБ).
- [ ] **Step 4: PASS** `cargo test -p rmasscan-lab`, clippy, `rust-lab.md` (TLS-сценарии, правило random, виды
  отличий 4c); **коммит** `feat(rmasscan-lab): TLS banners window scenarios, verifier rules, tls/x509 fuzz families`.

### Задача 13: TLS-кейс на Windows VM и macOS `feth`

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/{peer.rs,vm_lab.rs,verify.rs,macos_suite.rs,macos_verify.rs}` и их
  тесты, `rmasscan/docs/rust-lab.md`

**Interfaces:**
- Consumes: задача 12 (ответчик и сценарии), образец 4b (задача 18 подэтапа 4b, И16).
- Produces: по одному TLS-кейсу в `windows-suite` и `macos-suite`, только rmasscan; эталон — записи и сегменты C
  того же сценария из окна Linux (копия с проверкой хэшей и пересчётом вердикта, как И16). macOS: порт 8443
  вместо 443 по той же причине, что И16 (процесс без root); таблица потоков для 8443 та же TLS. Windows:
  `--adapter-ip` явно, утверждение «Windows не шлёт RST» судится и на втором соединении.

- [ ] **Step 1:** сценарий 443 (case3) на пирах обоих стендов; проверка двух соединений и hello по правилу random.
- [ ] **Step 2: тесты верификаторов** на фикстурах: PASS, пропавший баннер, нет второго SYN, чужой hello.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-lab`; **коммит**
  `feat(rmasscan-lab): TLS banner cases for the Windows VM and macOS feth stands`.

### Задача 14: живые окна, фаззинг и приёмка 4c

**Files:**
- Create: `docs/experiments/2026-11-13-rmasscan-banners-4c-acceptance.md`,
  `docs/experiments/2026-11-13-rmasscan-banners-4c-raw/`
- Modify: `docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md` (§12 «Изменения по итогам 4c»),
  `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md` (поправка), `rmasscan/README.md` (статус)

**Interfaces:**
- Consumes: задачи 12, 13.

- [ ] **Step 1: гейты трёх ОС до окон.** Полный `cargo test --workspace`, clippy `-D warnings`, fmt,
  language-guard на Mac, хосте стенда Linux и госте Windows (Global Constraints); studio
  `cargo check --locked` + `cargo xtask test`; падения разбираются до окон, как в 4b (§4 приёмки 4b).
- [ ] **Step 2: окно `banners` r1** на стенде Linux, C-оракул `8e6b3b0` и rmasscan с одним `--seed`, источник —
  свой адрес (Р9, И11): прежние кейсы 4b без изменений плюс TLS-сценарии задачи 12 (IPv4 и IPv6), отдельный
  прогон `--heartbleed`, C `--readscan` читает `-oB` rmasscan с TLS-баннерами теми же документами (§5 спеки).
- [ ] **Step 3: регрессия** ipv6 4/4, protocols 6/6, scan-control 7/7, output 18/18, autodetect 13/13,
  Windows 10/10 плюс TCP- и TLS-кейсы, macOS `feth` TCP+TLS (или NOT RUN с причиной: sudo пользователя/VPN);
  регрессии идут без `--banners`, поэтому Р10 их не касается — вердикты обязаны повториться.
- [ ] **Step 4: фаззинг** семейств `tls` и `x509` ≥1 ч каждое и повтор 13 семейств 4b на новом коде (Р15; 24 ч —
  критерий 4d), `nice -n 19`, ловушка по Global Constraints, отчёты JSON в доказательства.
- [ ] **Step 5: доказательства и отчёт.** Нейтральный каталог, `MANIFEST.sha256`, privacy-scan, копия в `…-raw/`;
  отчёт приёмки по образцу 4b: код окна и его хэши, результаты по кейсам, отличия от C (E1/E2/E3 справки 4c, в
  том числе замена E2.8 и закрытая E3.5), NOT RUN с причинами, журнал решений строителя с причиной и ценой
  (Р10 узкое прочтение, перенос по поведению и Rust-нативный X.509, хвост STARTTLS, hello один на скан, счётчик
  реконнекта).
- [ ] **Step 6: §12 спеки этапа**: Р10 выполнено (модель и граница), записи И-продолжения по итогам (нумерация
  после И20), статус в README; **коммиты** доказательств и отчёта отдельные. Push/PR — только по слову
  пользователя (предразрешения на 4c нет).

## Критерий готовности подэтапа

- Все задачи 0–14 закоммичены на ветке `feat/rmasscan-banners-4c`, после каждой workspace зелёный; `studio/`
  собирается и проходит свои тесты без правок.
- Окно `banners` с TLS — без FAIL (INVALID только по вине оракула/стенда с разбором в отчёте); регрессии прежних
  окон повторены; NOT RUN названы с причинами.
- Фаззинг `tls`/`x509` ≥1 ч без падений, зависаний >100 мс, расхождений нарезки и роста RSS сверх предела.
- README и §12 спеки называют каждое отличие от C; «Не перенесено» содержит только SMB (4d) и NPSL (Р3).
- Push, PR и слияние — отдельным словом пользователя; финальное ревью ветки — контролёр, как в 4b.
