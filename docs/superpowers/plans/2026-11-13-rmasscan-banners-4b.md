# rmasscan: баннеры, подэтап 4b (TCP-стек и текстовые протоколы) — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development`. Шаги в чекбоксах (`- [ ]`).
> Цикл на каждую задачу: RED (тест) → FAIL → минимальная реализация со ссылкой на C `файл:строка` → PASS → коммит.

**Goal:** `--banners` для TCP-портов, IPv4 и IPv6, с паритетом masscan `8e6b3b0`: собственный стек TCP в пространстве
пользователя, RST без состояния и `--noreset`, учёт кадров стека в `--rate`, каркас баннеров (классификатор, hello по
порту, `--hello*`, `--http-*`) и парсеры HTTP, FTP, SMTP, POP3, IMAP4, SSH, VNC, Telnet, RDP, memcached и Minecraft.

**Architecture:** автомат соединения, таблица с таймерами, каркас и парсеры живут в `rmasscan-proto` как чистые функции
состояния, байтов и часов (Р12). Движок от `rmasscan-proto` не зависит (иначе меняется `studio/Cargo.lock`, решение
задачи 6 подэтапа 4a): типы сегмента и трейт стека лежат в `rmasscan-core`, CLI передаёт реализацию из `rmasscan-proto`
в новое аддитивное поле `EngineOptions`. Движок вызывает стек в `run_rx` до дедупа, гонит его кадры через ограниченную
очередь впереди SYN и в счёт `--rate`, а баннеры соединений отдаёт новым вариантом `Output`.

**Tech Stack:** Rust 1.99.1, workspace `rmasscan/`, без новых внешних крейтов и без новых зависимостей (sha256 в
проверках манифестов — тестовый `Sha256` из `rmasscan-core/tests/common`).

**Spec:** [docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md](../specs/2026-11-13-rmasscan-banners-design.md)
(Р1–Р17, §10 И1–И7 главнее §3–§9) и её справка
[TCP-баннеры 4b](../specs/2026-11-13-rmasscan-banners-c-reference-tcp.md) (разделы A–F — источник всех байтов, состояний,
таймеров и номеров отличий этого плана; план на неё ссылается, а не копирует; в репозиторий её кладёт шаг П). Фон:
справки [TCP-стек](../specs/2026-11-13-rmasscan-banners-c-reference-tcpstack.md) и
[каркас и парсеры](../specs/2026-11-13-rmasscan-banners-c-reference-parsers.md) (где расходятся, права справка 4b, §F).

**Опора на 4a (строки на вершине 4a, сверить после волны правок финального ревью):** `BannerRecord` и
`MAX_BANNER_BYTES` в ядре (`rmasscan-core/src/banner.rs:11-23`, `rmasscan-proto` реэкспортирует); таблица приложений и
нормализаторы (`rmasscan-proto/src/{app.rs,normalize.rs}`); `udp_banner_parser` (`rmasscan-proto/src/udp/mod.rs:108`);
`EngineOptions.banners: Option<BannerOptions>` (`rmasscan-engine/src/engine.rs:75-97`, `banners.rs:26-32`); общая очередь
`Entry::{Reply, Banner}` под одной блокировкой (`engine.rs:223-275`); `recv_output_timeout -> Output::{Event, Banner}`
(`engine.rs:1420`, `banners.rs:39-45`), `Output` без `#[non_exhaustive]` и сопоставляется исчерпывающе в
`rmasscan-cli/src/live.rs:1179-1245` и `rmasscan-engine/tests/udp_banners.rs:235-241`; `Sink::report_reply_banner`
(`rmasscan-cli/src/output/mod.rs:45`, `output/pipeline.rs:333-336`), у `Sink` четыре реализации (`output/pipeline.rs:282`,
`output/mod.rs:160`, `tests/live_fake.rs:1427`, `:2454`); текстовый автомат memcached
(`rmasscan-proto/src/memcached_text.rs:163`). Р11: всё это расширяется только аддитивно.

## Global Constraints

- `#![forbid(unsafe_code)]` в `rmasscan-proto` и `rmasscan-core`; новых внешних крейтов нет; `Cargo.lock` не меняется;
  `deny.toml` без изменений; ни одного файла C, C++ или скрипта на запрещённом интерпретаторе (`language-guard`,
  `rust_only.rs`); обвязки C-оракула живут вне репозитория (Р14).
- `studio/` не меняется ни на байт; `Event`, `Reply`, `Progress`, `FailReason` и существующие методы `EngineHandle` не
  меняются (Р11); новое в `rmasscan-engine` только аддитивно, по умолчанию выключено; у движка нет обычной зависимости
  от `rmasscan-proto`. Studio: `cargo check --locked` и `cargo xtask test` без правок.
- После каждой задачи весь workspace собирается и проходит тесты: новый вариант перечисления и новый обязательный
  метод трейта вводятся вместе со всеми их потребителями и реализациями.
- Без `--banners`/`--rawudp` вывод и кадры прежние, кроме RST без состояния (Р8), который CLI включает, а
  `EngineOptions::new` нет.
- Парсер и автомат стека — тотальные функции: никакого `panic!`, `unwrap` на данных, индексации без проверки, рекурсии
  без предела, цикла без продвижения (Р1 класс б); тест «никогда не паникует» на случайном входе у каждого.
- Паритет: детерминированные странности C повторяются (справка E3); исправляется только класс а–г (справка E1), каждое
  исправление — строка README с ссылкой на C; зависимость C от нарезки решается правилом «как C на неразрезанном
  потоке» (справка E2, Р13). Каждый парсер проверяется в трёх нарезках: целиком, по байту, 8 случайных по seed.
- Байты под NPSL (`src/proto-banner1.c:327-489`) не переносятся (Р3).
- Задачи 9–12 идут строго по очереди: общие `parser_for` и манифест эталонов `tcp-banners`.
- Сборки и тесты на ноутбуке Linux или Mac со своим `CARGO_TARGET_DIR` вне дерева; после задачи `rmasscan/target` нет.
  Субагент, который грузит CPU (фаззер, окна, сборки в фоне), ставит `trap 'kill 0' EXIT INT TERM` и не оставляет
  детей.
- Исполнитель пишет заметки по ходу работы в `.superpowers/sdd/2026-11-13-rmasscan-banners-4b/task-N-notes.md`
  (решения, находки, что проверено), а не в конце.
- Доказательства — в нейтральных каталогах `mktemp -d /private/tmp/rmasscan-…` (на Linux `/tmp/rmasscan-…`), перед
  коммитом `rmasscan-lab privacy-scan` и grep по именам хостов и учёток; в коммитах нет имён хостов, путей учёток и
  адресов LAN (хост оракула называется «хост оракула»). Репозиторий публичный.
- Комментарии к коду — со ссылкой на C `src/файл.c:строка`; языковая политика текстов как в соседних файлах.
- Ветка `feat/rmasscan-banners-4b` от вершины 4a; после слияния 4a — `merge origin/main` (не rebase) и повтор
  затронутых окон.

## Review Focus

1. **Сервер держит соединение, а скан кончается (по умолчанию `--wait` 10 < жизни 30):** все живые соединения
   сбрасываются разом, и их баннеров больше, чем вмещает очередь; пользователь ждёт их в выводе и `Completed`, а не
   `Failed` — тесты `keepalive_banner_flushed_at_end_of_wait` и `finish_flush_larger_than_queue_is_delivered_whole`
   (задача 4).
2. **Скан TCP и UDP вместе (`-p80,U:53 --banners`):** баннер UDP идёт сразу за своим статусом, баннер TCP приходит позже
   и не рвёт эту смежность — тест `mixed_tcp_udp_banners_keep_udp_adjacency` (задача 4).
3. **Повтор и перекрытие сегментов (ретрансмит сервера, потерянный ACK):** байты не попадают в баннер дважды и не
   теряются — тест `retransmitted_and_overlapping_segments_append_once` (задача 6).
4. **Бесконечный поток сервера (телнет-болтун, SSH-тарпит):** запись обрезается на 65 536 байт, память таблицы в
   бюджете, переполнение считается — тест `endless_stream_caps_record_and_budget` (задача 8).
5. **Ctrl-C с живыми соединениями:** пауза останавливает SYN, стек дожёвывает соединения до конца `--wait`, их баннеры
   пишутся, `paused.conf` тот же, что без живых соединений — тест `live_fake_pause_with_live_connections` (задача 14).

---

### Шаг П (до задачи 0): справка и план в репозитории

**Files:**
- Create: `docs/superpowers/specs/2026-11-13-rmasscan-banners-c-reference-tcp.md` (эта справка),
  `docs/superpowers/plans/2026-11-13-rmasscan-banners-4b.md` (этот план)
- Modify: `docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md` (шапка, строки 4-9: пятая справка)

- [ ] **Step 1:** положить оба файла; в шапку спеки этапа после четырёх справок дописать ссылку на справку 4b с
  правилом: «для 4b при расхождении с справками TCP-стека и каркаса главнее справка 4b (её §F)».
- [ ] **Step 2:** privacy-scan по двум файлам; **коммит** `docs(rmasscan): banners 4b C reference (TCP) and plan`.

### Задача 0: бюджет очереди движка в байтах (И7)

Первая продуктовая задача 4b: до неё TCP-баннеры не текут (финальное ревью 4a, «Deferred-item adjudication»).

**Files:**
- Modify: `rmasscan/crates/rmasscan-engine/src/engine.rs` (`EngineOptions` :75-113, `Queue` :240-402, проверки старта
  :1172), `rmasscan/crates/rmasscan-engine/src/lib.rs`, `rmasscan/README.md` (строка под Р5)
- Test: `rmasscan/crates/rmasscan-engine/tests/udp_banners.rs`, `#[cfg(test)]` в `engine.rs`

**Interfaces:**
- Produces: `pub const DEFAULT_RESULT_BYTE_CAPACITY: usize = 64 * 1024 * 1024;`;
  `EngineOptions.result_byte_capacity: usize` (по умолчанию константа; 0 → `StartError::InvalidOptions("result_byte_capacity
  must be > 0")`). Очередь считает байты полезной нагрузки баннеров в ней. Одно правило приёма для любого набора
  (ответ с баннерами здесь, набор баннеров соединения в задаче 4): `fn fits(&self, st: &QState, new_bytes: usize) -> bool`
  = очередь пуста **или** (записей меньше `result_capacity` **и** байты + `new_bytes` ≤ `result_byte_capacity`); набор
  встаёт целиком или не встаёт. Ответ, который не влез, — `false` → `FailReason::ConsumerTooSlow`, как сейчас. Байты
  уменьшаются при выдаче и при пропуске баннера (`Want::Events`) и обнуляются в `close`.

- [ ] **Step 1: тесты** `byte_budget_refuses_reply_whose_banners_overflow` (`result_byte_capacity` 100 KiB, ответы с
  баннером 64 KiB: первый принят, второй даёт `Failed(ConsumerTooSlow)`), `byte_budget_frees_on_pop` (после выдачи
  баннера следующий принят), `empty_queue_accepts_any_banner_set` (бюджет 1 байт, пустая очередь принимает ответ с
  баннером 64 KiB), `replies_only_queue_unchanged_by_byte_budget` (бюджет 1 байт, 4096 ответов без баннеров
  принимаются, 4097-й нет — как раньше), `events_consumer_skipping_banners_releases_bytes`,
  `batch_cut_at_event_batch_limit_with_banners` (ответ с баннером ровно на позиции `event_batch_limit`: полная пачка
  `Results`, затем его баннер, затем следующий ответ — граница, отложенная финальным ревью 4a).
- [ ] **Step 2: FAIL** → реализация; README: под Р5 одна строка «очередь движка ограничена и в записях, и в байтах
  баннеров (64 МиБ); переполнение во время скана — `ConsumerTooSlow`».
- [ ] **Step 3: PASS** `cargo test -p rmasscan-engine`, studio `cargo check --locked`; **коммит**
  `feat(rmasscan-engine): byte budget for queued banners (stage spec И7)`.

### Задача 1: гигиена эталонов и закрепление таблиц

**Files:**
- Create: `rmasscan/crates/rmasscan-core/tests/common/sha256.rs` (тестовый `Sha256`, вынесенный из `common/mod.rs:128`;
  `mod.rs` его реэкспортирует), `rmasscan/crates/rmasscan-core/tests/common/golden.rs` (проверка манифеста рядом с
  ним); `rmasscan-proto/tests/*.rs` подключают оба `#[path]`, как `rmasscan-cli/tests/differential.rs:6-7`
- Modify: `rmasscan/crates/rmasscan-core/tests/common/mod.rs`, `rmasscan/crates/rmasscan-proto/{tests/udp_golden.rs,
  src/app.rs,src/normalize.rs}`, `rmasscan/crates/rmasscan-cli/src/readscan.rs` (тесты)

**Interfaces:**
- Produces: `pub fn check_manifest_hashes(dir: &Path, manifest_text: &str) -> Result<usize, String>` в
  `rmasscan-core/tests/common/golden.rs` (пары имя/сумма из текста манифеста тем же способом, что
  `rmasscan-proto/tests/udp_golden.rs:483-498`, без `serde_json`): число проверенных файлов; ошибка называет файл и обе
  суммы.

- [ ] **Step 1: тесты** `manifest_hashes_match_files` (каждые `input_sha256` и `output_sha256` `udp-banners/manifest.json`
  равны sha256 файла; сегодня 408 из 408); `manifest_check_names_the_tampered_file` (копия каталога во временном
  каталоге, один байт одного `.out` изменён: ошибка называет этот файл и обе суммы); `app_ids_and_names_pinned` (все 37
  `app_id::*` против `src/masscan-app.h:8-49`, `app_name` 0..=36, `app_from_name` для каждого ключа
  `src/masscan-app.c:61-112`, включая TCP-имена `http.server`, `title`, `html`, `pop`, `imap`, `minecraft`, `vnc-info`,
  `rdp`, `telnet`); `normalize_json_string_all_bytes` (0x00..=0xFF по `src/out-json.c:69-97`);
  `banner_port_filter_keeps_pU53` и `ipv6_only_filter_keeps_ipv6_banner` (сторона «оставляет» отличий R5/R14 для
  баннеров в `--readscan`, отложено с задачи 3 подэтапа 4a).
- [ ] **Step 2: FAIL** (там, где падает; `manifest_hashes_match_files` сегодня зелёный, его RED — подмена в
  `manifest_check_names_the_tampered_file`) → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-core -p rmasscan-proto -p rmasscan-cli`; **коммит**
  `test(rmasscan): verify golden manifest hashes, pin app ids and JSON escapes`.

### Задача 2: имена опций как `EQUALS` C по всей таблице и код выхода ошибок разбора

`--banner-types` и синонимы закрывает волна правок 4a; здесь не планируются.

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/args.rs` (`EQUALS_OPTIONS` и `equals_banner_option` :892-923,
  `preprocess_args` :831-890), `rmasscan/crates/rmasscan-cli/src/main.rs` (:21), `rmasscan/README.md`

**Interfaces:**
- Produces: `fn equals_table() -> &'static EqualsTable` (строится один раз из `Cli::command()`: каждое длинное имя и алиас
  clap, кроме скрытых внутренних, чьё имя начинается с `rmasscan-`, под ключом `normalize_key`); `fn equals_option(a:
  &str) -> Result<Option<String>, String>` заменяет `equals_banner_option` и стоит первым в `preprocess_args`, так что
  остальная цепочка (`F_NUMABLE`, `--name[i]`, `-o`) видит каноническое имя; `pub fn clap_exit_code(kind:
  clap::error::ErrorKind) -> u8` (0 для `DisplayHelp`/`DisplayVersion`, иначе 1). Скрытые опции, которые добавит задача
  13, обязаны начинаться с `rmasscan-`.
- Суффикс `[…]` (справка C1): у имени с индексным смыслом индекс идёт в его разбор (сегодня это ключи `nic[i]`;
  `hello-string`, `hello-file`, `http-header`/`http-field` появятся в задаче 13 и до неё — неизвестные опции); у любой
  другой опции закрытое `[…]` отбрасывается, как у `EQUALS` C (`src/main-conf.c:840-841`); незакрытая `[` — код 1 у
  любой опции (Р17 «непарный индекс»). Охрана `name.contains('[')` (`args.rs:916`) уходит.

- [ ] **Step 1: тесты** `equals_table_has_one_option_per_key` (ключи всех имён и алиасов; у ключа ровно один id
  аргумента; единственная группа из двух имён — `nocapture`/`no-capture`, один id, справка C1);
  `equals_rewrites_every_long_option` (для каждого имени L: `--` + L в верхнем регистре с `_` вместо `-` разбирается как
  `--L`); `equals_keeps_value_after_eq_and_colon`; `equals_leaves_array_names_to_indexed_parsers` (`--Adapter-Ip[1]`
  доходит до `indexed_nic_key`); `equals_array_suffix_ignored_like_c` (по всей таблице: для каждой опции без индексного
  смысла `--L[0]=v` и `--L[0] v` разбираются как `--L`; `--banner-types[0] dns-ver` как `--banner-types dns-ver`);
  `unpaired_index_fails` (`--rate[ 100`, `--Adapter-Ip[1 10.0.0.1` — код 1); `equals_then_numable` (`--TCP-MSS 1400` как
  `--tcp-mss 1400`); `clap_errors_exit_1` (неизвестная опция, значение пропущено в конце argv, неверное значение — код 1
  с текстом clap; `--help` — 0).
- [ ] **Step 2: FAIL** → реализация. Код выхода: ошибки clap — 1, как `exit(1)` C для неизвестного имени
  (`src/main-conf.c:3036`); отличия в README: текст clap вместо `CONF: unknown config option`, пропущенное значение
  фатально (C печатает `empty parameter` и продолжает, `:3300-3302`), незакрытая `[` фатальна, `--help` — 0 (C — 1).
- [ ] **Step 3: PASS** `cargo test -p rmasscan-cli` (все прежние тесты argv зелёные); **коммит**
  `feat(cli): C EQUALS option matching for every option, parse errors exit 1`.

### Задача 3: ядро — сегмент TCP, кадры стека, трейт стека

**Files:**
- Create: `rmasscan/crates/rmasscan-core/src/stack.rs` (типы и трейт), `rmasscan/crates/rmasscan-core/src/tcp_frame.rs`
  (разбор сегмента и сборка кадра), `rmasscan/tests/golden/tcp-frames/{README.md,manifest.json,cases/*}`,
  `rmasscan/crates/rmasscan-core/tests/tcp_frames.rs`
- Modify: `rmasscan/crates/rmasscan-core/src/{lib.rs,receive.rs,packet.rs}` (общие помощники разбора
  `locate_ipv4`/`locate_ipv6`/`ipv4_packet` становятся `pub(crate)`; доступ к байтам опций шаблонов)

**Interfaces:**
- Consumes: задача 1 (`check_manifest_hashes`, `rmasscan-core/tests/common/golden.rs`).
- Produces (`rmasscan_core::stack`):
  - `pub enum ConnAddrs { V4 { local: u32, remote: u32 }, V6 { local: u128, remote: u128 } }`;
    `pub struct ConnKey { pub addrs: ConnAddrs, pub local_port: u16, pub remote_port: u16 }` (Copy, Eq, Hash).
  - `pub struct SegmentIn<'a> { pub key: ConnKey, pub seq: u32, pub ack: u32, pub flags: u8, pub ttl: u8, pub payload: &'a [u8] }`
    (`ttl` — TTL IPv4 или hop limit IPv6, Р2/E1.9).
  - `pub struct SegmentOut { pub key: ConnKey, pub seq: u32, pub ack: u32, pub flags: u8, pub payload: Vec<u8>, pub window: Option<u16> }`
    (`window: None` — 1200 шаблона; `Some(600)` только для heartbleed в 4c).
  - `#[derive(Default)] pub struct StackOutput { pub segments: Vec<SegmentOut>, pub banners: Vec<Vec<BannerRecord>> }`
    (баннеры по соединениям: один внутренний `Vec` — записи одного сброса);
    `pub struct StackStats { pub tcbs_created: u64, pub tcbs_live: u64, pub table_full: u64, pub banner_bytes_dropped: u64 }`;
    `pub struct TableParams { pub seed: u64, pub capacity: usize, pub banner_byte_budget: usize }`.
  - `pub trait TcpStack: Send { fn on_tick(&mut self, now_micros: u64, out: &mut StackOutput); fn on_segment(&mut self,
    now_micros: u64, seg: &SegmentIn<'_>, out: &mut StackOutput) -> bool; fn finish(&mut self, max_connections: usize,
    out: &mut StackOutput) -> bool; fn stats(&self) -> StackStats; }` — контракт: сегмент с битами SYN и ACK приходит,
    только если движок проверил его cookie (задача 4); `on_segment` возвращает `true`, если сегмент взяло соединение
    (живое или новое) или он дал RST на FIN без соединения; `finish` уничтожает до `max_connections` живых соединений
    без кадров и отдаёт их баннеры, `true` — остались ещё.
  - `pub trait TcpStackFactory: Send + Sync + std::fmt::Debug { fn new_table(&self, p: TableParams) -> Box<dyn TcpStack>; }`.
- Produces (`rmasscan_core::tcp_frame`):
  - `pub fn tcp_segment<'a>(frame: &'a [u8], link: LinkType, plan: &ReadyPlan) -> Option<SegmentIn<'a>>` — тот же разбор
    канала и IP, что у `parse_reply`, до `is_my_ip`/`is_my_port` и проверки сумм включительно; без фильтра флагов, без
    набора целей и cookie; нагрузка до конца IP-пакета (без набивки Ethernet).
  - `pub struct TcpFrameBuilder`, `pub fn from_plan(plan: &ReadyPlan) -> Self` (шаблоны IPv4 и, при `source_ipv6`, IPv6 с
    теми же опциями, что SYN: `--tcp-mss/--tcp-wscale/--tcp-tsecho/--tcp-sackok`, `--ttl`), `pub fn build(&self, s:
    &SegmentOut) -> Vec<u8>` — справка A6.
  - `pub fn stateless_rst(reply: &Reply, seed: u64) -> Option<SegmentOut>` — только для TCP-ответа с SYN-ACK или RST
    (`tcp_flags` с битами 0x12 полностью или с 0x04); seq = `cookie + 1`, ack 0, флаги 0x04 (справка A7).

- [ ] **Step 1: оракул кадров вне репозитория.** На хосте оракула обвязка над `src/templ-pkt.c` (`tcp_create_packet`)
  по справке E4: шаблоны по умолчанию и с каждой опцией `--tcp-*` и `--ttl`, IPv4 и IPv6, флаги `0x10 0x18 0x19 0x11
  0x04`, нагрузка 0/1/1400 байт, Ethernet. В репозиторий — входы, кадры C, sha256 обвязки и коммит C в `manifest.json`.
- [ ] **Step 2: тесты** `tcp_frame_golden_matches_c` (побайтно; кадры с E1.10 отличаются только суммой IP, и наша верна),
  `manifest_hashes_match_files`, `ipv4_header_checksum_always_right` (вектор E1.10: `0xfffe`), `ethernet_frame_padded_to_60`,
  `ipv6_frame_unpadded_hop_limit_255`, `window_forced_1200_and_options_repeated`, `ip_id_is_them_port_seq`,
  `stateless_rst_fields` (seq `cookie+1`, ack 0, `0x04`; `None` для ICMP-`closed`, UDP, SCTP),
  `tcp_segment_round_trip` (кадр `build` для ACK/данных/FIN/RST, IPv4 и IPv6, разбирается в тот же сегмент),
  `tcp_segment_rejects_foreign_address_port_and_bad_checksum`, `tcp_segment_payload_excludes_padding`,
  `tcp_segment_never_panics` (проптест на кадрах до 1514 байт).
- [ ] **Step 3: FAIL** → реализация по справке A6/A7.
- [ ] **Step 4: PASS** `cargo test -p rmasscan-core`, studio `cargo check --locked`; **коммит**
  `feat(rmasscan-core): TCP segment view, stack frame builder and the stack trait`.

### Задача 4: движок, сторона приёма — стек до дедупа, сброс в конце, `Output::ConnectionBanner`

**Files:**
- Modify: `rmasscan/crates/rmasscan-engine/src/{engine.rs,banners.rs,lib.rs}` (`run_rx` :916-1037, `Shared` :414-450,
  `Queue`), `rmasscan/crates/rmasscan-engine/tests/udp_banners.rs` (:235-241, новый вариант `Output`),
  `rmasscan/crates/rmasscan-cli/src/output/{mod.rs,pipeline.rs}` (трейт `Sink` и реализации `pipeline.rs:282`,
  `mod.rs:160`), `rmasscan/crates/rmasscan-cli/src/live.rs` (ветка `Output::ConnectionBanner` в цикле :1179-1245),
  `rmasscan/crates/rmasscan-cli/tests/live_fake.rs` (реализации `Sink` :1427, :2454)
- Create: `rmasscan/crates/rmasscan-engine/tests/tcp_stack.rs` (двойник стека — сценарный `TcpStack` в тесте)

**Interfaces:**
- Consumes: задачи 0 (`fits`), 3.
- Produces:
  - `pub struct TcpStackOptions { pub factory: Arc<dyn TcpStackFactory>, pub table_capacity: usize, pub banner_byte_budget: usize }`
    (Debug, Clone); `EngineOptions.tcp_stack: Option<TcpStackOptions>` (по умолчанию `None`). Каждый RX-поток получает
    свою таблицу: `TableParams { seed, capacity: max(1024, table_capacity / адаптеров), banner_byte_budget: budget /
    адаптеров }`.
  - `Output::ConnectionBanner(BannerRecord)` — баннер соединения, к предыдущему ответу не привязан, `timestamp` 0.
  - `Sink::report_connection_banner(&mut self, b: BannerRecord) -> Result<(), String>` — обязательный; ставит время
    записи по часам приёмника в момент обработки (`env.wall.unix_time()`, как `global_now` C при сбросе, справка B3);
    реализован у всех четырёх приёмников; цикл событий CLI отдаёт ему `Output::ConnectionBanner`.
  - Очередь: `Queue::push_conn_banners(&self, set: Vec<BannerRecord>) -> bool` (без ожидания, во время скана; набор —
    записи одного соединения, правило `fits` задачи 0, каждая запись — один элемент; `false` → `ConsumerTooSlow`) и
    `Queue::push_conn_banners_waiting(&self, set: Vec<BannerRecord>, keep_going: &dyn Fn() -> bool) -> bool` (для сброса
    в конце: ждёт, пока `fits`, перепроверяя `keep_going` не реже раза в 50 мс; `false` только при остановке).
  - Очередь кадров стека: `pub const STACK_OUT_CAP: usize = 16_383;` (`BUFFER_COUNT - 1`, справка A8), `stack_out` на
    адаптер в `Shared`; RX кладёт, при полной очереди кадр выбрасывается и считается (RX не ждёт, Р7); отправляет задача 5.
  - `pub struct StackSummary { pub stack: StackStats, pub frames_sent: u64, pub frames_dropped: u64 }`;
    `EngineHandle::stack_stats(&self) -> StackSummary` (сумма по RX-потокам; CLI читает его после конца цикла событий и
    до `join`).
- Порядок в `run_rx` на итерацию (справка A1): `on_tick(now)`; для кадра — `parse_reply` (чистая), затем
  `tcp_segment`. Кадр с битами SYN и ACK отдаётся стеку, только если `parse_reply` вернул для него ответ (cookie
  верен; `Open` или, при SYN|ACK|RST, `Closed` — C создаёт TCB и тогда, `src/main.c:971-985`); иначе стек его не
  видит, даже при живом TCB (C `continue`). Остальные сегменты — `on_segment(now, seg)`. Затем прежний путь статуса и
  дедупа. Кадр, который стек взял (`on_segment` вернул `true`), в `Progress.discarded` не считается. Баннеры
  сброса во время скана → `push_conn_banners`.
- Конец RX (естественный, после паузы и `Stop`; не после `Failed`): пока `finish(64, out)` возвращает `true`, наборы
  уходят через `push_conn_banners_waiting(set, || не Stop)`, до публикации `rx_end`. Сброс в конце никогда не
  превращает естественный конец в `Failed`: очередь давит назад, потребитель дочитывает; `Stop` прерывает сброс.

- [ ] **Step 1: тесты движка** (`FakeAdapter` + `ManualClock` + двойник стека): `bad_cookie_synack_changes_neither_stack_nor_status`
  (и при живом TCB у двойника), `stack_sees_duplicate_synack_status_once`, `status_written_when_stack_table_full`
  (двойник не создаёт соединений: запись `open` всё равно в очереди, анти-цель «тихая потеря статуса»),
  `stack_segments_not_counted_as_discarded`, `ticks_follow_engine_clock_on_idle_rx`,
  `finish_flushes_conn_banners_after_wait` (баннеры после последнего `Results`, до `Finished`),
  `finish_flush_larger_than_queue_is_delivered_whole` (живых соединений больше `result_capacity`, байтов больше
  `result_byte_capacity`, потребитель читает медленно: все баннеры доставлены, итог `Completed`),
  `finish_interrupted_by_stop`, `conn_banner_set_is_all_or_nothing`, `conn_banners_count_in_byte_budget`,
  `events_consumer_never_sees_conn_banners`, `stack_queue_overflow_is_counted_not_blocking`, `ipv6_segment_reaches_stack`,
  `keepalive_banner_flushed_at_end_of_wait` (Review Focus 1), `mixed_tcp_udp_banners_keep_udp_adjacency` (Review Focus
  2), `pause_flushes_live_connections_after_wait`; тест CLI `connection_banner_stamped_at_processing`.
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-engine -p rmasscan-cli`, clippy, studio `cargo check --locked`;
  **коммит** `feat(rmasscan-engine): TCP stack hook before dedup, connection banners with end-of-scan back-pressure`.

### Задача 5: движок, сторона передачи — кадры стека впереди SYN, `--rate`, RST без состояния

**Files:**
- Modify: `rmasscan/crates/rmasscan-engine/src/engine.rs` (`run_tx` :697-898, точка RST в `run_rx` после `push_result`)
- Test: `rmasscan/crates/rmasscan-engine/tests/tcp_stack.rs`

**Interfaces:**
- Consumes: задачи 3 (`TcpFrameBuilder`, `stateless_rst`), 4 (`stack_out`, `StackSummary`).
- Produces: `EngineOptions.stateless_rst: bool` (по умолчанию `false`): при `stateless_rst && tcp_stack.is_none()` за
  каждым свежим (прошедшим дедуп) TCP-ответом `stateless_rst(..)` идёт в `stack_out`. TX: после
  `next_batch_interruptible` сначала до `batch` кадров из `stack_out` (каждый в `my_sent` и `frames_sent`, не в
  `shared.sent`: `Progress.sent` — зонды; скорость в строке статуса считает throttle по `my_sent`, как C), остаток пачки
  — SYN (`src/main.c:289-299`). Ошибка отправки кадра стека, как у NA, не валит скан и считается в `frames_dropped`.
  Досылка остатка пачки при паузе (`batch = u64::MAX`, `engine.rs:762-764`) кадры стека не берёт. После конца зондов
  TX под throttle дожёвывает очередь до конца RX при `ndp || tcp_stack.is_some() || stateless_rst`
  (`src/main.c:470-494`).

- [ ] **Step 1: тесты** `stack_frames_go_before_syns_in_the_same_batch`, `stack_frames_count_against_rate` (N кадров
  стека и M зондов на скорости R занимают (N+M)/R с по `ManualClock`), `tx_lingers_for_stack_frames_until_rx_ends`,
  `stateless_rst_for_synack_and_rst_reply` (байты как `stateless_rst`; по одному на свежий ответ; нет для дубля и
  ICMP-`closed`), `stateless_rst_sent_for_synack_in_wait_window`, `pause_burst_does_not_drain_stack_frames`,
  `stack_frame_send_error_counted_not_fatal`, `no_new_frames_without_options` (`EngineOptions::new`: кадры и события
  побайтно прежние).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-engine`, clippy, studio `cargo check --locked` и `cargo xtask test`;
  **коммит** `feat(rmasscan-engine): stack frames ahead of SYNs under --rate, stateless RST`.

### Задача 6: proto — автомат соединения (`stack_incoming_tcp`)

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/tcp/{mod.rs,tcb.rs}`
- Modify: `rmasscan/crates/rmasscan-proto/src/lib.rs`

**Interfaces:**
- Consumes: задача 3 (`ConnKey`, `SegmentOut`).
- Produces (`pub(crate)`):
  - `enum TcpState` (10 состояний справки A4), `enum What { Timeout, SynAck, Rst, Fin, Ack, Data, Close }`,
    `enum AppEvent { Connected, RecvTimeout, RecvPayload, SendSent, Close }` (`APP_SENDING` не доставляется, справка F1),
    `enum TcbResult { Okay, Destroyed }`.
  - `struct Tcb` (поля справки A3, плюс `created_micros: u64`, `deadline_micros: Option<u64>`).
  - `trait App { fn on_event(&mut self, ctl: &mut TcbCtl<'_>, ev: AppEvent, payload: &[u8]); }`;
    `struct TcbCtl<'a>` с методами `send(&mut self, bytes: &[u8]) -> bool` (`tcpapi_send`, отказ вне EST),
    `recv(&mut self)`, `close(&mut self)` (событие `Close` в тот же TCB), `set_timeout(&mut self, secs: u32)` (срок от
    времени события).
  - `fn incoming(tcb: &mut Tcb, app: &mut dyn App, what: What, payload: &[u8], seq: u32, ack: u32, at_micros: u64,
    lifetime_secs: u32, out: &mut Vec<SegmentOut>) -> TcbResult` — `at_micros` — время события: у `Timeout` это
    **запланированный** срок тика, у остальных — `now`. Пролог и таблица справки A4, отправка и подтверждение справки
    A5 (сегменты по 1400, только голова в полёте, частичный ACK вешает, данные в SEND не принимаются, ACK после реакции
    приложения). Жизнь (Р6, `src/stack-tcp-core.c:1970-1980`): у `Timeout` при `at_micros > created_micros +
    lifetime_secs·10⁶` — RST и уничтожение.

- [ ] **Step 1: тесты** `state_table_rows` (табличный: каждая строка справки A4 — кадры с флагами, seq/ack, следующее
  состояние, события приложения), `payload_reaction_precedes_ack` (приложение шлёт на `RecvPayload`: кадр данных
  `0x18`, затем чистый ACK), `only_head_segment_in_flight`, `hello_over_1400_advances_one_segment_per_tick`,
  `fin_behind_hello_leaves_on_next_tick`, `partial_ack_stalls_until_lifetime` (Р1), `old_data_not_acked_future_dropped`,
  `retransmitted_and_overlapping_segments_append_once` (Review Focus 3), `duplicate_fin_acked`, `rst_destroys_silently`,
  `lifetime_uses_scheduled_tick_time` (`Timeout` с `at` = created + 30 с — жив; created + 32 с — RST, seq `seqno_me`, ack
  `seqno_them`, `0x04`), `send_in_wrong_state_refused`, `tcb_never_panics` (проптест: случайные события и номера, очередь
  ограничена).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-proto`; **коммит** `feat(rmasscan-proto): TCP connection automaton (C stack-tcp-core parity)`.

### Задача 7: proto — таблица, таймеры, слой приложения, rstfilter

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/tcp/{table.rs,app.rs,rstfilter.rs,stack.rs}`

**Interfaces:**
- Consumes: задачи 3, 6.
- Produces:
  - `pub(crate) trait Session: Send { fn hello(&self) -> Option<&[u8]>; fn parse(&mut self, px: &[u8], budget: &mut
    ByteBudget, acts: &mut Vec<SessionAction>); fn flush(&mut self, budget: &mut ByteBudget) -> Vec<(u16, Vec<u8>)>; }`
    (`hello() == None` — поток NULL, hello не шлётся никогда; `Some(&[])` — поток с пустым hello, справка B5);
    `pub(crate) enum SessionAction { Send(Vec<u8>), Close }`;
    `pub(crate) trait Sessions: Send + Sync { fn new_session(&self, remote_port: u16) -> Box<dyn Session>; }`;
    `pub(crate) struct ByteBudget { left: usize, dropped: u64 }` (`take(n) -> usize` сколько можно дописать, `give(n)`).
  - `pub(crate) struct AppLayer` (`impl App`, справка B5).
  - `pub(crate) struct RstFilter` — справка A7, 16384 корзин, SipHash `{seed, seed}`, `input[4] = 0` (E1.11);
    `fn is_filtered(&mut self, k: &ConnKey) -> bool`.
  - `pub struct TcpBannerStack` (`impl TcpStack`) и `pub(crate) fn new_stack(sessions: Arc<dyn Sessions>,
    connection_timeout_secs: u32, p: TableParams) -> TcpBannerStack`.
  - `#[doc(hidden)] pub fn connection_memory_floor() -> usize` — `size_of` записи таблицы, TCB и сессии без буферов
    баннеров (для README, задача 14).
- Таблица растёт лениво: записи есть только у живых соединений, по `capacity` ничего не выделяется заранее; полная
  таблица — SYN-ACK без соединения, `table_full += 1`.
- Время (Р6): TCB создаётся на SYN-ACK; `Connected` ставит срок `created + 2 с` (hello, `src/stack-tcp-app.c:76`); каждый
  тик без уничтожения — следующий через 2 с от **запланированного** срока (`src/stack-tcp-core.c:322-327`); тик
  передаётся в `incoming` со своим сроком, поэтому опоздание обработки (до 50 мс) не сдвигает ни сетку, ни проверку
  жизни: по умолчанию RST на тике +32 с, при `connection_timeout` 6 — на +8 с. Целосекундной сетки нет.
- Разбор одного сегмента (справка A2): SYN-ACK (движок уже проверил cookie) → создать TCB или, если он жив, событие
  `SynAck` (EST_RECV игнорирует); иначе по TCB: `Ack`, `Data`, `Fin` (seq + длина), `Rst` по порядку, и остановка на
  `Destroyed` (E1.5); без TCB с FIN и без RST — `RstFilter`, затем RST временного TCB. Записи сброса — `BannerRecord`
  (`timestamp` 0, адрес и порт сервера, `ip_proto` 6, TTL SYN-ACK), по набору на соединение.

- [ ] **Step 1: тесты** (`Session`-заглушка со сценарием): `hello_two_seconds_after_synack_when_server_silent`,
  `server_first_data_suppresses_hello`, `null_stream_never_sends`, `empty_hello_stays_and_ignores_later_data` (Р1, B5),
  `peer_fin_flushes_and_closes` (записи, наш FIN, `LAST_ACK`, уничтожение на ACK), `ticks_every_two_seconds`,
  `lifetime_rst_on_tick_after_timeout_with_late_processing` (часы переходят каждый срок с опозданием 7 мс: RST на тике
  +32 с при 30 и +8 с при 6), `finish_is_incremental_and_complete` (`finish(2)` по два соединения, все записи ровно по
  разу, без кадров), `table_full_counts_and_creates_nothing`, `table_allocates_only_live_connections` (`capacity` 2³⁰
  ничего не выделяет), `fin_without_tcb_rst_until_filter_saturates` (15 RST, затем фильтр), `rst_without_tcb_ignored`,
  `synack_for_live_tcb_is_ignored`, `records_carry_synack_ttl_and_server_address` (IPv4 и IPv6: hop limit),
  `frame_processing_stops_at_destroyed` (E1.5: ACK уничтожает в `LAST_ACK`, FIN того же кадра не даёт кадра на
  255.255.255.255), `byte_budget_truncates_and_counts`, `stack_never_panics` (проптест: случайные сегменты, флаги, номера
  и часы; таблица и очередь ограничены, каждый TCB уничтожается не позже жизни + 2 с).
- [ ] **Step 2: FAIL** → реализация.
- [ ] **Step 3: PASS**; **коммит** `feat(rmasscan-proto): TCP connection table, timers, app layer and rstfilter`.

### Задача 8: proto — каркас баннеров, офлайн-драйвер и эталоны TCP

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/{mod.rs,classify.rs,banout.rs,hello.rs,session.rs,driver.rs}`,
  `rmasscan/crates/rmasscan-proto/tests/tcp_golden.rs`, `rmasscan/tests/golden/tcp-banners/{README.md,manifest.json,cases/*}`
- Modify: `rmasscan/crates/rmasscan-proto/src/lib.rs`

**Interfaces:**
- Consumes: задачи 1 (`check_manifest_hashes`), 3, 7.
- Produces:
  - `pub struct HelloSet { pub http: bool, pub ssl: bool, pub smbv1: bool }`;
    `pub struct TcpBannerSettings { pub hello: HelloSet, pub hello_strings: Vec<(u16, Vec<u8>)>, pub http_request: Vec<u8>, pub capture_html: bool }`
    (`hello_strings` уже раскодированы и в порядке «первый заданный выигрывает», справка C2; `http_request` — готовый
    запрос, задача 10; до неё — запрос по умолчанию, справка C3).
  - `pub fn tcp_stack_factory(s: TcpBannerSettings, connection_timeout_secs: u32) -> Arc<dyn TcpStackFactory>`.
  - Офлайн-драйвер (как `handle_udp` 4a, для `tests/tcp_golden.rs` и `rmasscan-lab fuzz tcp`):
    `#[doc(hidden)] pub fn banner_stream(s: &TcpBannerSettings, port: u16, force_app: Option<u16>, segments: &[&[u8]]) -> StreamResult`,
    `pub struct StreamResult { pub app_proto: Option<u16>, pub records: Vec<(u16, Vec<u8>)>, pub actions: Vec<StreamAction> }`,
    `pub enum StreamAction { Send(Vec<u8>), Close }` — одна сессия порта, сегменты по очереди, затем сброс без бюджета;
    `app_proto` — номер, который выбрал классификатор (как `app_proto` C, до правила 4b для не перенесённых); `force_app`
    запускает парсер этого приложения без классификатора (семейство фаззера).
  - `pub(crate) enum AppProto { Ftp, Smtp, Pop3, Imap4, Ssh, Http, Vnc(u8), Memcached, Telnet, Rdp, Minecraft, Unported }`
    (`Unported` пишет в `unknown`, app 1); `pub(crate) trait Parser: Send { fn parse(&mut self, cx: &mut ParseCx<'_>, px: &[u8]); }`;
    `pub(crate) struct ParseCx<'a> { pub banout: &'a mut Banout, pub budget: &'a mut ByteBudget, pub acts: &'a mut Vec<SessionAction>, pub port: u16, pub capture_html: bool, pub starttls: bool }`;
    `pub(crate) fn parser_for(p: AppProto) -> Box<dyn Parser>` (здесь все, кроме `Unported`, — заглушка `Unported`;
    задачи 9–12 заменяют свою строку).
  - `pub(crate) struct BannerConfig` (неизменяемая конфигурация скана из `TcpBannerSettings`: hello по порту, запрос
    HTTP, `capture_html`) реализует `Sessions`; `pub(crate) struct Banner1Session` реализует `Session`.
  - `pub(crate) struct Banout` — справка B3: порядок C, предел 65 536 на запись (Р5), бюджет таблицы.
- Правила каркаса: классификатор с семантикой smack справки B2; HEUR-повтор с правилами E2.1 и E2.2; `"220 "` на 25/587 →
  SMTP; SSL3 без hello отвергается (B1.2); SMB, всё после STARTTLS и TLS — `Unported` (без hello, справка B6); hello по
  порту — только строки «sent» таблицы B4; `--hello http` — HTTP на портах 0..65534; `--hello ssl` — на портах 0..65534
  поток TLS, в 4b без hello (как NULL: ответ сервера пишется, справка B6), и он побеждает `http` (порядок smbv1, http,
  ssl); `--hello smbv1` в 4b ничего не меняет (hello SMB не шлётся); `--hello-string` после них.
- Вид ожидания у случая эталона (поле `expect` в `manifest.json`): `records` — записи и действия равны C (здесь только
  случаи без перенесённого парсера: нет совпадения, 70 000 байт без совпадения, отвергнутый SSL3 первым);
  `classification` — сравнивается только `app_proto` с выбором C; `declared-4b` — ожидание по правилу 4b (SMB-поток →
  `unknown`), вывод C хранится как свидетельство. Задачи 9–12 добавляют свои случаи `records` и при необходимости
  `declared-4b`.

- [ ] **Step 1: оракул вне репозитория** `tcp-oracle` по справке E4 (как `udp-oracle` 4a: копия исходников пина,
  `fork` + `alarm` 2 с на случай, ASan-сборка рядом): на случай — порт, флаг `--capture html`, поток сервера; печать
  записей banout по порядку, журнала действий и выбранного `app_proto` для целого потока (эталон) и по байту
  (свидетельство E2); выгрузка hello портов B4. Случаи этой задачи: классификатор (каждый шаблон, регистр, лишний
  ведущий байт, `*` с 0x7B и 0xFF, совпадение во втором сегменте, SSL3 первым, SSL3 затем `{"`, SMB), поток без
  совпадения, 70 000 байт без совпадения.
- [ ] **Step 2: тесты** `tcp_golden_matches_c` (каждый случай по своему виду ожидания, целиком, по байту и 8 случайных
  нарезок: записи с порядком и `app_proto`; действия — только для целого), `manifest_hashes_match_files`,
  `classifier_matches_c_table`, `match_in_later_segment_gives_no_unknown_record` (E2.1),
  `ssl3_first_match_makes_stream_unknown` (E2.2), `smtp_220_space_on_25_587_ftp_elsewhere`,
  `smb_classified_stream_is_unknown_in_4b`, `banout_order_matches_c` (прямые дописывания: голова, вставка после головы,
  переезд головы на 200 байтах — правила справки B3; эталон C с HTTP — задача 10), `banout_caps_record_at_65536`,
  `hello_table_4b` (80/8080/8530 — 99 байт C3; 23 — `ff f6`; 3389 — 45 байт; 11211 — `stats\r\n`; 25565 — 19 байт; 443,
  139, 445 и порты NPSL — нет), `hello_http_every_port_but_65535`, `hello_string_first_given_wins`,
  `banner_stream_force_app_skips_classifier`, `endless_stream_caps_record_and_budget` (Review Focus 4),
  `session_never_panics`.
- [ ] **Step 3: FAIL** → реализация.
- [ ] **Step 4: PASS**, privacy-scan по новым эталонам; **коммит**
  `feat(rmasscan-proto): banner framework (classifier, replay, banout, hello table), offline driver, C goldens`.

### Задача 9: парсеры FTP, SMTP, POP3, IMAP4

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/{ftp.rs,smtp.rs,pop3.rs,imap4.rs}`
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/mod.rs` (`parser_for`), эталоны `tcp-banners`

**Interfaces:**
- Consumes: задача 8 (`Parser`, `ParseCx`, `banner_stream`; хэнд-офф STARTTLS — `cx.starttls = true`).

- [ ] **Step 1: случаи оракула** по справке D2–D5 (вид `records`): однострочные и многострочные приветствия, строка без
  кода, TAB/непечатный байт, ответы 530 на `AUTH TLS`, EHLO с STARTTLS и без, 454 на `STARTTLS`, POP3 `-ERR` на CAPA,
  IMAP `* OK`, `*  OK`, `* BYE`; `"220-"` на порту 25 (уходит в FTP); вид `declared-4b`: 234, 220 и `+OK` на STARTTLS
  (дальше `unknown`, hello TLS не шлётся).
- [ ] **Step 2: тесты** `tcp_golden_matches_c` (новые случаи, три нарезки), `ftp_auth_reply_without_final_newline`,
  `smtp_ehlo_then_starttls_whatever_ehlo_said`, `smtp_220_dash_on_25_parsed_as_ftp` (Р1),
  `pop3_capa_minus_stops_without_stls`, `imap4_banner_is_star_ok` (Р1), `starttls_success_switches_to_unported_tls`,
  `text_parsers_never_panic`.
- [ ] **Step 3: FAIL** → реализация побайтно по C; **Step 4: PASS**; **коммит**
  `feat(rmasscan-proto): FTP, SMTP, POP3 and IMAP4 banners`.

### Задача 10: HTTP — запрос и парсер

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/http_request.rs`, `rmasscan/crates/rmasscan-proto/src/banner1/http.rs`
- Modify: `rmasscan/crates/rmasscan-proto/src/{lib.rs,banner1/mod.rs}`, эталоны `tcp-banners`

**Interfaces:**
- Consumes: задача 8.
- Produces: `pub struct HttpRequestOptions { pub method: Option<Vec<u8>>, pub url: Option<Vec<u8>>, pub version:
  Option<Vec<u8>>, pub host: Option<Vec<u8>>, pub user_agent: Option<Vec<u8>>, pub payload: Option<Vec<u8>>, pub headers:
  Vec<(Vec<u8>, Vec<u8>)>, pub cookies: Vec<Vec<u8>> }`; `pub fn http_request(o: &HttpRequestOptions) -> Result<Vec<u8>,
  String>` — справка C3: порядок payload (и `Content-Length`), user-agent, host, method, url, version, заголовки
  заменой, cookie добавлением; построитель повторяет `http_change_requestline`/`http_change_field` побайтно для любого
  значения (CRLF, голый LF, пробелы, пустые значения — как C); ошибка только для больше 16 заголовков или cookie.

- [ ] **Step 1: случаи оракула** — запросы: по умолчанию и каждая опция, сочетания, повтор заголовка с другим
  регистром, заголовок без `:`, значения с CRLF, с голым LF, пустые, с пробелами, пустой метод, URL с пробелом;
  ответы: `HTTP/1.0 302` по байту (`src/proto-banner1.c:714-767`), `Server: gws` (`src/proto-http.c:693-760`), два
  `Server:`, `Server :`, `<title>`, `<TITLE id=x>`, `<titlex>`, заголовок без `<`, `--capture html`, `HTTP/1.1x`,
  `HTTP/1.` + 2000 цифр; порядок записей banout на ответах с заголовком короче и длиннее 200 байт (перенос из задачи 8).
- [ ] **Step 2: тесты** `default_request_is_99_bytes`, `http_request_golden_matches_c` (все запросы оракула побайтно),
  `payload_sets_content_length`, `header_replace_respells_name_in_place`, `user_agent_replace_matches_c` (замена
  68-байтовой строки короткой, справка C3), `bare_lf_value_moves_later_headers_like_c`, `crlf_value_reproduced`,
  `cookies_add_lines`, `more_than_16_headers_refused`, `tcp_golden_matches_c` (HTTP), `banout_order_http_matches_c`,
  `server_values_concatenated`, `title_prefix_match_absorbs_body_without_lt`, `capture_html_full_body`,
  `failed_status_line_split_matches_unsplit` (E2.3), `http_never_panics`.
- [ ] **Step 3: FAIL** → реализация; **Step 4: PASS**; **коммит** `feat(rmasscan-proto): HTTP banner and request builder`.

### Задача 11: парсеры SSH, Telnet, VNC, RDP

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/{ssh.rs,telnet.rs,vnc.rs,rdp.rs}`
- Modify: `rmasscan/crates/rmasscan-proto/src/banner1/mod.rs`, эталоны `tcp-banners`

**Interfaces:**
- Consumes: задача 8 (`Parser`, `ParseCx`, `banner_stream`).
- Produces: строки `parser_for` для `Ssh`, `Telnet`, `Vnc(u8)`, `Rdp`.

- [ ] **Step 1: случаи оракула** по справке D6–D9: SSH ident + KEXINIT + второй пакет, ident с UTF-8 и с NUL,
  ведущая строка до ident; Telnet: векторы `src/proto-tcp-telnet.c:309-347`, SB, IAC IAC; VNC 3.3/3.7/3.8, тип None и
  не None, ошибка с длиной причины больше 255, ServerInit; RDP: векторы `src/proto-tcp-rdp.c:346-361`, TPKT с первым байтом
  не 3 во втором пакете, длина TPKT меньше 4.
- [ ] **Step 2: тесты** `tcp_golden_matches_c` (новые случаи), `ssh_ident_reply_and_kex_blob_per_packet` (21 байт
  `SSH-2.0-OPENSSH_7.9\r\n`, блоб 1248 байт на каждый пакет, Р1), `ssh_error_appends_exactly_one_more_byte` (E2.4),
  `telnet_replies_once_per_option_ascending`, `telnet_invalid_appends_exactly_one_more_byte` (E2.4),
  `vnc_selects_none_even_if_not_offered` (Р1), `vnc_error_reason_length_low_byte` (Р1), `rdp_labels_and_unknown`,
  `rdp_unknown_appends_whole_stream` (E2.5), `binary_parsers_never_panic`.
- [ ] **Step 3: FAIL** → реализация; **Step 4: PASS**; **коммит** `feat(rmasscan-proto): SSH, Telnet, VNC and RDP banners`.

### Задача 12: memcached по TCP и Minecraft

**Files:**
- Create: `rmasscan/crates/rmasscan-proto/src/banner1/{memcached.rs,minecraft.rs}`
- Modify: `rmasscan/crates/rmasscan-proto/src/{memcached_text.rs,banner1/mod.rs}`, эталоны `tcp-banners`

**Interfaces:**
- Consumes: задача 8; `MemcachedText` (`memcached_text.rs:163-177`, общий с UDP).
- Produces: в `MemcachedText` состояние C 1: ключевое слово, начатое в конце сегмента, продолжается в следующем (E2.6);
  для UDP вывод не меняется (новый автомат на датаграмму). Байт за сегментом не читается (E1.4). Строки `parser_for`
  для `Memcached` и `Minecraft`.

- [ ] **Step 1: случаи оракула**: `STAT` с uptime/time/version, неизвестная статистика, `END`, `STAT\n`, `ERROR`;
  JSON Minecraft целиком, с фавиконом, несбалансированный, внутри ответа другого порта (`{"` без якоря).
- [ ] **Step 2: тесты** `tcp_golden_matches_c` (новые случаи), `udp_golden_matches_c` (все прежние случаи UDP без
  изменений), `memcached_split_keyword_kept` (E2.6), `memcached_never_reads_past_segment` (E1.4: эталон по байту у C
  отличается, у нас как целиком), `memcached_tcp_never_closes`, `minecraft_record_is_raw_stream_when_balanced` (E2.7),
  `minecraft_unbalanced_gives_no_record`, `minecraft_closes_when_count_drops`, `minecraft_hijacks_json_on_any_port` (Р1).
- [ ] **Step 3: FAIL** → реализация; **Step 4: PASS**; **коммит** `feat(rmasscan-proto): memcached over TCP and Minecraft banners`.

### Задача 13: CLI — опции `--hello*`, `--connection-timeout`, `--http-*`

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/config.rs` (поля `ScanConfig` :175-202, `apply_core_kv` :1395,
  `echo_with` :835), `rmasscan/crates/rmasscan-cli/src/{args.rs,conf.rs,lib.rs}`, `rmasscan/crates/rmasscan-proto/src/lib.rs`
- Create: `rmasscan/crates/rmasscan-proto/src/base64.rs`, `rmasscan/crates/rmasscan-cli/src/banner_settings.rs`

**Interfaces:**
- Consumes: задачи 2 (`equals_option`, правило суффикса), 8 (`TcpBannerSettings`, `HelloSet`), 10 (`http_request`).
- Produces:
  - `ScanConfig.hello_http`, `.hello_ssl`, `.hello_smbv1: bool`; `.hello_strings: Vec<(u16, String)>` (base64 как дан, в
    порядке argv); `.connection_timeout: u32` (0 — значение C по умолчанию 30); `.http: HttpConfig { method, url, version,
    host, user_agent, payload: Option<String>, headers: Vec<(String, String)>, cookies: Vec<String> }`.
  - `pub fn decode_hello_base64(s: &str) -> Result<Vec<u8>, String>` (`rmasscan_proto::base64`) — вход по определению
    «верный base64» справки C2, иначе ошибка; верный раскодируется побайтно как `src/crypto-base64.c:104-160`.
  - `pub fn tcp_banner_settings(cfg: &ScanConfig) -> Result<TcpBannerSettings, String>` в `banner_settings.rs`:
    раскодирование, «первый заданный выигрывает», `http_request`.
  - Скрытые опции clap `--rmasscan-hello-string`, `--rmasscan-hello-file`, `--rmasscan-http-header` (с префиксом
    `rmasscan-`, задача 2 их не трогает): `preprocess_args` переписывает в них `--hello-string[P] V`, `--hello-file[P] F`
    (`hello-filename`) и любое написание `--http-header`/`--http-field` по `EQUALS`, **до** `equals_option`, передавая
    набранное имя опции: C выбирает форму по `name += 11` от набранного имени (справка C3), так же делает rmasscan.
    То же правило для ключей файла конфигурации.
- Ошибки — код 1 (Р17): без `[P]`, незакрытая `[`, индекс не десятичный или от 65 536, неверный base64 (справка C2),
  `--hello` не `ssl|smbv1|http` (текст C `FAIL: %s: unknown hello type`), файл hello пуст (текст C) или длиннее 12 285
  байт (E1.14), набранное имя `--http-header` короче 11 знаков (E1.7: C читает за именем), ни одной формы заголовка (две
  строки C), больше 16 заголовков или cookie. Любое другое значение `--http-*`, включая CRLF, — как C.

- [ ] **Step 1: тесты** `hello_value_matches_like_c_and_unknown_fails`, `hello_echo_one_line_ssl_smbv1_http`,
  `hello_string_without_index_fails`, `hello_string_unpaired_index_fails`, `hello_string_non_decimal_index_fails`,
  `hello_string_index_65536_fails`, `hello_string_invalid_base64_fails` (пробел, `=` в середине, `QUJD=`, `Q`, байт вне
  алфавита), `hello_string_valid_base64_decodes_like_c` (с `==`, с `=`, без набивки, пустая строка),
  `hello_string_echo_newest_first` (`hello-string[%u] = %s`), `hello_file_becomes_hello_string`,
  `hello_file_over_12285_fails`, `hello_file_empty_fails_with_c_text`, `connection_timeout_and_tcp_timeout_not_echoed`,
  `http_options_echo_in_table_order` (справка C3/C4), `http_header_form_by_typed_name_like_c` (`HTTP_HEADER[X] v` —
  скобка; `httpheader[X] a:b` — двоеточие, заголовок `a`), `http_header_short_spelling_fails` (`--http-field X:v`,
  `--httpheader X:v`), `http_header_neither_form_fails_with_hint`, `http_header_17th_fails`, `http_values_with_crlf_like_c`,
  `capture_html_reaches_settings`, `banner_options_in_config_file` (те же случаи через `-c`),
  `paused_conf_round_trip_of_banner_options`, `decode_hello_base64_matches_c_vectors`.
- [ ] **Step 2: FAIL** → реализация; **Step 3: PASS** `cargo test -p rmasscan-core -p rmasscan-cli -p rmasscan-proto`;
  **коммит** `feat(cli): --hello, --hello-string, --hello-file, --connection-timeout and --http-* (C parity)`.

### Задача 14: CLI — живой скан с TCP-баннерами, README

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/src/{lib.rs,live.rs,status.rs,args.rs}` (отказ 4a `lib.rs:72-90`, опции движка
  `live.rs:1093-1100`), `rmasscan/crates/rmasscan-cli/tests/{live_fake.rs,live_fake_ipv6.rs}` и любой тест, который
  закрепляет отправленные кадры после SYN-ACK или RST-ответа, `rmasscan/README.md`

**Interfaces:**
- Consumes: задачи 4, 5, 7–13 (`tcp_stack_factory`, `tcp_banner_settings`, `stack_stats`, `connection_memory_floor`).
- Produces: CLI ставит `EngineOptions.tcp_stack` при `--banners` (`table_capacity` = max(1024, `rate` × (жизнь + 4)), где
  жизнь — `connection_timeout` или 30 при 0, без верхнего предела; `banner_byte_budget` 512 МиБ) и `stateless_rst =
  !banners && !noreset`.
- Тексты: предупреждение Р9 — одна строка на скан на любой ОС, если `--banners` и хотя бы один адрес источника выбран
  автоопределением, с этими адресами через ` and `: `[-] warning: --banners uses the OS's own address {ips}: its kernel
  resets the banner connections; give --adapter-ip an unused address on the subnet or drop the --source-port traffic in
  the firewall`; итог в stderr после цикла событий (по `stack_stats()` до `join`), только ненулевые: `[-] banners: {n}
  SYN-ACKs got no connection (table full, {cap} entries)`, `[-] banners: {n} stack frames dropped (transmit queue full)`,
  `[-] banners: {n} banner bytes dropped (memory budget {mib} MiB)`.

- [ ] **Step 1: тесты CLI** `tcp_banners_no_longer_refused` (отказ 4a и его тест сняты), `stateless_rst_by_default_off_with_noreset_and_banners`,
  `table_capacity_uses_effective_timeout` (rate 100, по умолчанию → 3400; `--connection-timeout 6` → 1024),
  `banners_warning_once_for_os_owned_source` (IPv4, IPv6, оба — одна строка с двумя адресами; нет при `--adapter-ip` и
  `--adapter-ipv6`; на всех ОС), `stack_summary_only_when_nonzero` (точные тексты), `infinite_status_shows_tcbs` и
  `json_status_tcb_fields_follow_stack_stats` (`tcbs` = `tcbs_created`, `src/main.c:984`, `src/main-status.c:54-67,
  :189-191`), `readme_names_connection_memory_cost` (число в README не меньше `connection_memory_floor()`); сценарный пир
  на `FakeAdapter` с настоящим стеком: `live_fake_http_banner_end_to_end` (SYN-ACK; через 2 с по `ManualClock` `GET` 99
  байт; ответ с `Server` и `<title>` и FIN → `-oL` даёт `open`, затем `http.server`, `title`, `http` байтами C),
  `live_fake_ssh_server_first` (hello не уходит), `live_fake_parser_close_sends_our_fin`, `live_fake_peer_rst_mid_reply_flushes`,
  `live_fake_lifetime_rst_at_timeout` (`--connection-timeout 6`), `live_fake_keepalive_flushed_at_end_of_wait`,
  `live_fake_pause_with_live_connections` (баннеры записаны после `--wait`; `paused.conf` побайтно равен файлу того же
  argv с молчащим пиром; Review Focus 5), `live_fake_ipv6_banner`, `live_fake_udp_banners_unchanged`.
- [ ] **Step 2: FAIL** → реализация. Ожидаемые кадры всех тестов CLI, которые закрепляют отправку после SYN-ACK или
  RST-ответа, — под RST без состояния (Р8); список изменённых тестов — в заметки задачи. README: опции 4b; модель времени
  (Р6) и RST (Р8, `--noreset`); стоимость соединения в памяти; отличия E1 и E2 с ссылками на C; не перенесённые
  протоколы с портами (TLS 4c, SMB 4d, NPSL Р3 — справка B4); предупреждение Р9; итог счётчиков; бюджет 512 МиБ (решение
  вне Р5); `after_help` — пример `--banners -p80`.
- [ ] **Step 3: PASS** всё (`cargo test --workspace`, clippy на всех целях ноутбука, fmt, language-guard); studio
  `cargo check --locked` и `cargo xtask test` без правок; **коммит**
  `feat(rmasscan): --banners for TCP ports (user-mode stack, C parity), stateless RST and --noreset`.

### Задача 15: стенд — TCP-ответчики и верификатор окна `banners`

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/{banners_suite.rs,banners_suite_tests.rs,banners_verify.rs,
  banners_verify_tests.rs,capture.rs,pair_verify.rs,main.rs}`, `rmasscan/scripts/wire-lab.sh`, `rmasscan/docs/rust-lab.md`

**Interfaces:**
- Consumes: задача 14 (CLI `--banners` для TCP).
- Produces: `capture responder --tcp-answer banners` (сокеты ядра пира на адрес и порт, сценарий по адресу назначения);
  `banners_verify::TCP_SCENARIOS` (сценарий → ожидаемые приложения записей, по порядку сброса; общая таблица для
  задачи 18); виды отличий окна — только из справки E1 (`ipv6-ttl`, `ipv4-stack-checksum`, `memcached-tcp-past-segment`,
  `no-frame-from-destroyed-tcb`, `minecraft-unsplit`) и прежний `udp-raw-past-datagram`.

- [ ] **Step 1: стенд TCP (Р9).** `wire-lab.sh --suite banners`: TCP-кейсы и кейс RST без состояния сканируют с
  `--adapter-ip 198.18.0.9` и с IPv6-адреса той же /64, не назначенных в netns сканера (его ядро молчит, `ip_forward=0`);
  в netns пира — постоянные записи соседей для обоих адресов на MAC сканера (отступление от буквы Р9, запись §11 —
  задача 19); UDP-кейсы 4a — прежний argv с `198.18.0.1`. Таблица сценариев покрывает: каждый из 11 парсеров хотя бы
  раз; доставку в 2–3 сегмента с паузой 200 мс в местах, где C от нарезки не зависит (и проверку на проводе, что
  сегментов было больше одного, иначе INVALID); молчащий порт; неизвестный протокол, говорящий первым; HTTP/1.1 без
  закрытия (жизнь); RST сервера посреди ответа; отказ STARTTLS (454/530); `"220-"` на 25. Всё то же на IPv6.
- [ ] **Step 2: верификатор** `banners-verify`: статусы равны C; записи баннеров — мультимножество, поле в поле без
  времени; на проводе по каждому соединению последовательность кадров сканера (флаги, нагрузка, относительные seq/ack)
  равна C, hello в 1,0–3,5 с после SYN-ACK у обоих, RST жизни в пределах `timeout` + 2 ± 2 с; кадр от уничтоженного
  TCB — FAIL. RST без состояния (Р8): у обоих сканеров ровно один RST на свежий SYN-ACK и на RST-ответ, с `--noreset` —
  ни одного; с `--banners --noreset` RST жизни есть у обоих. Отложенное из 4a: M1 — баннер UDP идёт сразу за записью
  статуса своего ответа или баннером того же `(адрес, порт)`, баннеры одного TCP-соединения идут подряд и после его
  `open`; M2 — текст `-oL` rmasscan на 1900 и 11211 равен `normalize_string` датаграммы ответа.
- [ ] **Step 3: тесты на фикстурах** (как соседние `*_verify_tests.rs`): PASS, пропавший баннер, лишний `unknown`, чужой
  hello, кадр после уничтожения, нет RST у rmasscan, RST при `--noreset`, нет RST жизни при `--banners --noreset`,
  несмежный баннер UDP (M1), неверный текст `-oL` (M2).
- [ ] **Step 4: PASS** `cargo test -p rmasscan-lab`, clippy, `rust-lab.md` (окно 4b, сценарии, виды отличий); **коммит**
  `feat(rmasscan-lab): TCP banners window: scenario responders and verifier`.

### Задача 16: стенд — RST без состояния в прежних верификаторах

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/{ipv6_verify.rs,ipv6_verify_tests.rs,protocols_verify.rs,
  protocols_verify_tests.rs}`, верификаторы Windows и macOS (`verify.rs`, `macos_verify.rs` и их тесты), `rmasscan/docs/rust-lab.md`

**Interfaces:**
- Consumes: задачи 5, 14 (RST rmasscan формы справки A7: seq = ack ответа, ack 0, `0x04`, окно 1200, опции шаблона).
- Produces: класс кадров «RST без состояния» у обоих сканеров вместо «только у оракула».

- [ ] **Step 1:** `grep -rn "has no RST path\|resets no SYN-ACK" crates/rmasscan-lab/src` — каждое место
  (`ipv6_verify.rs:825`, `protocols_verify.rs:915` и найденные) переводится на класс обоих сканеров; верификаторы
  Windows и macOS принимают RST rmasscan той же формы; фикстуры: RST rmasscan есть — PASS, нет — FAIL, лишний — FAIL.
- [ ] **Step 2: PASS** `cargo test -p rmasscan-lab`; **коммит** `fix(rmasscan-lab): previous verifiers expect rmasscan's stateless RST (Р8)`.

### Задача 17: фаззер TCP-парсеров и стека

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/{fuzz.rs,main.rs}`, `rmasscan/docs/rust-lab.md`

**Interfaces:**
- Consumes: задачи 3 (трейт `TcpStack`), 8 (`banner_stream`, `force_app`, `tcp_stack_factory`).
- Produces: `rmasscan-lab fuzz tcp --family F --seed N (--duration D | --count N) [--corpus DIR...] [--pcap FILE...] [--out FILE]`;
  семейства `http ftp smtp pop3 imap4 ssh vnc telnet rdp memcached minecraft framework stack`.

- [ ] **Step 1:** вход — поток до 64 КиБ из корпуса (эталоны `tcp-banners`, захваты окна) с мутациями 4a и случайной
  нарезкой на сегменты 1..1460, у парсерных семейств через `banner_stream(.., force_app, ..)`, у `framework` без
  `force_app`; у `stack` — случайные сегменты, флаги, номера и часы через `TcpStack`. Инварианты: нет паники, вход
  быстрее 100 мс (лучший из трёх), записи не длиннее 65 536, **результат нарезки равен результату целиком** (Р13), RSS
  растёт меньше 64 МиБ. Отложенное из 4a: M3 — прогон дольше `WARMUP_INPUTS` (`fuzz.rs:58`) с меньше чем двумя
  замерами RSS пишет «memory not measured» и выходит 2; M4 — `Rng::new` (`fuzz.rs:189-191`) через splitmix64, нулевое
  состояние заменяется.
- [ ] **Step 2: тесты** `fuzz_short_mode_all_tcp_families` (10 с в `cargo test`), `rss_unmeasured_is_reported`,
  `rng_adjacent_seeds_give_different_streams`, `split_invariant_violation_is_a_finding` (подложный парсер, зависящий от
  нарезки, даёт находку).
- [ ] **Step 3: PASS** `cargo test -p rmasscan-lab`; **коммит** `feat(rmasscan-lab): TCP parser and stack fuzzer (Р15), fuzz M3/M4 fixes`.

### Задача 18: TCP-кейсы на Windows VM и macOS `feth`

**Files:**
- Modify: `rmasscan/crates/rmasscan-lab/src/{peer.rs,vm_lab.rs,verify.rs,macos_suite.rs,macos_verify.rs}` и их тесты,
  обёртки Windows-стенда, `rmasscan/docs/rust-lab.md`

**Interfaces:**
- Consumes: задача 15 (`capture responder --tcp-answer banners`, `TCP_SCENARIOS`).
- Produces: кейс `windows-suite` и кейс `macos-suite` (HTTP 80 и SSH 22) с вердиктом по записям.

- [ ] **Step 1:** ответчик сценариев HTTP и SSH на стороне пира стенда; эталон — записи C тех же сценариев из окна
  Linux; на macOS адрес сканера не назначен на `feth` (иначе ядро шлёт RST); на Windows — адрес гостя (проверка C README
  «Windows не шлёт RST»).
- [ ] **Step 2: тесты верификаторов** на фикстурах: PASS, пропавший баннер, чужой hello.
- [ ] **Step 3: PASS** `cargo test -p rmasscan-lab`; **коммит** `feat(rmasscan-lab): TCP banner cases for the Windows VM and macOS feth stands`.

### Задача 19: живые окна, фаззинг и приёмка 4b

**Files:**
- Create: `docs/experiments/2026-11-13-rmasscan-banners-4b-acceptance.md`, `docs/experiments/2026-11-13-rmasscan-banners-4b-raw/`
- Modify: `docs/superpowers/specs/2026-11-13-rmasscan-banners-design.md` (§11 «Изменения по итогам 4b»),
  `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md` (поправка), `rmasscan/README.md` (статус)

**Interfaces:**
- Consumes: задачи 15–18.

- [ ] **Step 1: окно `banners` r1** на стенде Linux, C-оракул `8e6b3b0` и rmasscan с одним `--seed`, источник — свой
  адрес (Р9): TCP IPv4 и IPv6 (`--banners --connection-timeout 6 --wait 12`, документы `-oB` и `-oL`), сброс таблицы в
  конце (`--wait 3` без `--connection-timeout`), `--banners --noreset` (RST жизни уходит), RST без состояния (без
  `--banners`, затем с `--noreset`), UDP `b01`/`b02` 4a с проверками M1/M2; C `--readscan` читает `-oB` rmasscan с
  TCP-баннерами и даёт те же записи (§5).
- [ ] **Step 2: регрессия** ipv6 4/4, protocols 6/6, scan-control 7/7, output 18/18, autodetect 13/13, Windows 10/10 плюс
  TCP-кейс, macOS `feth` TCP-кейс (или NOT RUN с причиной); прежние вердикты с RST rmasscan по Р8.
- [ ] **Step 3: фаззинг** каждого из 13 семейств ≥ 1 ч (`nice -n 19`, параллельно, `trap 'kill 0' EXIT INT TERM`), отчёты
  JSON в доказательства.
- [ ] **Step 4: доказательства** в нейтральном каталоге, `MANIFEST`, privacy-scan, копия в `…-raw/`; отчёт приёмки (по
  образцу 4a): код окна, результаты, отличия от C (E1, E2), NOT RUN; список кандидатов на исправление функциональных
  багов Р1 (IMAP CAPABILITY, рабочий `--hello-timeout`, SSH только строка идентификации, частичный ACK) без
  реализации; журнал решений строителя с причиной и ценой (все решения этого плана, в том числе ёмкость таблицы,
  бюджет 512 МиБ, base64, `--http-*`, суффикс `[…]`, предупреждение Р9, стенд с постоянными соседями).
- [ ] **Step 5: §11 спеки этапа**: Р8 выполнено (верификаторы обновлены, «у rmasscan нет RST» снято); записи-отступления
  — бюджет байтов баннеров таблицы 512 МиБ сверх Р5 (может укоротить записи против C под нагрузкой, счётчик в итоге,
  строка README) и стенд с постоянными записями соседей вместо ответчиков ARP/NDP rmasscan (буква Р9); прочие решения,
  которые спека оставляла строителю; поправка в спеку порта; **коммит** доказательств и отчёта отдельными коммитами.
