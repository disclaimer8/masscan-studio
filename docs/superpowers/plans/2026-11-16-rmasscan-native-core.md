# rmasscan: нативный Rust, фаза 1 — `rmasscan-core`: план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development` (рекомендуется) или `superpowers:executing-plans`.
> Шаги в чекбоксах (`- [ ]`). Цикл задачи: тест (RED) → FAIL → минимальная правка → PASS → ворота → коммит.

**Goal:** `rmasscan-core` без формы C и быстрее на пути отправки зондов, с замером каждого ускорения; кадры, порядок
целей, cookie, суммы, записи и тексты ошибок не меняются ни на байт.

**Architecture:** сначала страховка без правок `src/` (задачи 0–2): дайджесты потоков на неизменённом коде, замороженные
копии старых функций для дифференциальных тестов, цикл `ProbeCursor` в бенчмарке и база замеров на хосте стенда. Потом
горячий путь в порядке выигрыша (BlackRock, курсор, сборщики кадров, SipHash, деления), каждая правка на скорость —
со своими воротами на хосте стенда; затем идиомы без выигрыша (приём, `Builder::fill`, кадры стека, мелочи, разборщики).
Публичный API не меняется: новое только аддитивно или `pub(crate)`.

**Tech Stack:** Rust 1.99.1, edition 2024, workspace `rmasscan/`, крейт `rmasscan-core`; зависимости прежние
(`siphasher` =1.0.4, `thiserror`; dev: `proptest`, `serde`, `serde_json`); тестовый `Sha256` из `tests/common/sha256.rs`.

**Spec:** [docs/superpowers/specs/2026-11-16-rmasscan-native-rust-design.md](../specs/2026-11-16-rmasscan-native-rust-design.md)
(«Ограничения» действуют на все задачи; «Порядок работ», п. 1 — содержание этого плана).

**Опора.** Ветка `refactor/rmasscan-native-core` от `a275ea9e` (по `rmasscan/` равна main `fab13114`). Строки ниже —
на базе. Пути без префикса считаются от `rmasscan/crates/rmasscan-core/`.

## Global Constraints

- **Файлы.** Меняются только `rmasscan/crates/rmasscan-core/**`, `rmasscan/BENCHMARKS.md` и этот план. Никогда:
  `src/config.rs`, `src/stack.rs` (их меняет 4c), `studio/`, `rmasscan/tests/golden/`, `Cargo.lock`, другие крейты.
- **4c.** Перед началом работ и перед каждой задачей, которая трогает `src/cookie.rs` или `src/tcp_frame.rs`:
  ```sh
  git fetch origin
  B=origin/feat/rmasscan-banners-4c; git rev-parse -q --verify "$B" >/dev/null || B=feat/rmasscan-banners-4c
  git diff --stat origin/main..."$B" -- rmasscan/crates/rmasscan-core
  ```
  На момент плана вывод пуст: вершина 4c `d9cd2f30` (ветка есть только локально) ядро не меняет. План 4c меняет в ядре
  `src/stack.rs` (`TableParams`, аддитивно) и `src/config.rs` и использует `cookie::siphash24`, `syn_cookie_ipv4/ipv6`,
  параметр окна в `tcp_frame.rs` (`SegmentOut.window`) и поля `probe::NicBinding`. Файлов, которые меняют и 4c, и этот
  план, нет. Если проверка покажет в ядре файл из списка Files задачи — остановиться и сверить с владельцем 4c.
- **API заморожен.** Сигнатуры существующих `pub`-элементов (функции, поля, варианты, константы, трейты) не меняются;
  новое — аддитивный `pub` или `pub(crate)`. Сохраняются сигнатуры, на которых стоит 4c: `siphash24(data, k0, k1) -> u64`,
  `syn_cookie_ipv4/ipv6`, `TcpFrameBuilder::build`, поля `NicBinding`. Что требует смены сигнатуры — в список фазы 2.
- **Байт в байт.** Ни один эталон не меняется; дайджесты задачи 0 и дифференциальные тесты задачи 1 проходят после
  каждой задачи без правки ожидаемых значений. `tests/probe_cursor.rs` строит ожидаемые кадры из `transmit_scan` и
  `build_syn`, то есть из меняемого кода: смену байтов он не увидит, доказательство — только дайджесты и эталонные копии.
- **Тесты-закрепления.** Тест, который фиксирует поведение базы, проходит и до правки; вместо RED у него проверка
  чувствительности после реализации: названная в шаге временная порча реализации роняет тест, порча откатывается.
- **Без зависимостей и `unsafe`.** Новых крейтов нет, `Cargo.lock` не меняется, `#![forbid(unsafe_code)]` остаётся.
- **Исправления багов C** (те, что ядро повторяет) сюда не входят: отдельная ветка `fix/rmasscan-core-c-bugs` после
  слияния этой (дизайн, «Порядок работ», п. 3). Странности C повторяются как сейчас.
- **Каталоги сборки.** Каждая команда идёт с `CARGO_TARGET_DIR` вне дерева, свой каталог на worktree; `rmasscan/target`
  не появляется никогда:
  ```sh
  export BASE=a275ea9e
  export CARGO_TARGET_DIR=/private/tmp/rmasscan-native-core-target          # на Linux /tmp/…
  export STUDIO_TARGET_DIR=/private/tmp/rmasscan-native-core-studio-target
  export BENCH_HOST=…   # ssh-имя хоста стенда; задаёт исполнитель, в файлы репозитория не пишется
  ```
- **Фоновые процессы в zsh:** `trap 'trap - EXIT INT TERM; kill 0' EXIT INT TERM`, не `trap 'kill 0' …`; после задачи
  `ps -Ao pid,%cpu,etime,command | awk '$2>80'` и остановить только свои процессы.
- **Гигиена публичного репозитория.** Ни локальных путей, ни имён пользователей, хостов и LAN-адресов; хост замеров —
  «хост стенда» и `$BENCH_HOST`. Перед каждым коммитом `git diff --cached | grep -nE '/(Users|home)/[^/ ]+/'` пуст.
- **Коммиты.** `git add` только явные пути из Files задачи; сообщение
  `git commit -m "<type>(rmasscan-core): …" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`.
  Push и PR — только с согласия пользователя. Если main уходит вперёд — `git merge origin/main`, не rebase, затем G-core.

### Ворота (на них ссылаются задачи)

- **G-core** (из `rmasscan/`): `cargo fmt --all --check && cargo clippy --locked -p rmasscan-core --all-targets -- -D
  warnings && cargo test --locked -p rmasscan-core`.
- **G-ws** (для `probe.rs`, `scan.rs`, `packet.rs`, `cookie.rs`, `receive.rs`, `tcp_frame.rs`, `targets.rs`,
  `payloads.rs`): из `rmasscan/` `cargo clippy --locked --workspace --all-targets -- -D warnings && cargo test --locked
  --workspace`; из `studio/` `CARGO_TARGET_DIR=$STUDIO_TARGET_DIR cargo check --locked && CARGO_TARGET_DIR=$STUDIO_TARGET_DIR
  cargo xtask test` (Studio не правится).
- **G-frozen** (перед каждым коммитом, из корня):
  ```sh
  git diff --exit-code $BASE -- rmasscan/Cargo.lock studio rmasscan/tests/golden \
    rmasscan/crates/rmasscan-core/src/config.rs rmasscan/crates/rmasscan-core/src/stack.rs
  git diff --name-only $BASE -- . ':(exclude)rmasscan/crates/rmasscan-core' \
    ':(exclude)rmasscan/BENCHMARKS.md' ':(exclude)docs/superpowers/plans/2026-11-16-rmasscan-native-core.md'  # пусто
  test ! -e rmasscan/target
  git diff $BASE -- rmasscan/crates/rmasscan-core/src | grep -nE '^-[[:space:]]*pub [a-z_]'
  ```
  Каждая удалённая `pub`-строка последнего grep обязана вернуться в том же диффе байт в байт (перенос), иначе это смена
  API.
- **G-mac** (только ранжирует): `for r in 1 2 3; do (cd rmasscan && cargo bench --locked -p rmasscan-core); done`;
  медиана 9 прогонов по каждому циклу; `sink` каждого цикла равен значению задачи 2. Регрессия на Mac не блокирует, но
  записывается и разбирается в ревью.
- **G-bench** (обязательные ворота задачи на скорость), на закоммиченном HEAD:
  ```sh
  git archive HEAD:rmasscan | ssh "$BENCH_HOST" 'rm -rf ~/rmasscan-bench && mkdir ~/rmasscan-bench && tar -x -C ~/rmasscan-bench'
  for run in 1 2 3; do
    ssh "$BENCH_HOST" 'uptime; cd ~/rmasscan-bench && CARGO_TARGET_DIR=~/rmasscan-bench-target ~/.cargo/bin/cargo test \
      --locked --release -p rmasscan-core --test offline_gen -- --ignored --nocapture --test-threads=1'
  done 2>&1 | grep -E 'load average|OFFLINE_'
  ```
  `--test-threads=1` обязателен: два прогона 2^28 параллельно на 4 ядрах портят оба числа. Перед прогоном load average
  ниже 1,0. Медиана трёх по каждой строке (`OFFLINE_GEN`, `OFFLINE_CURSOR`). Проходит, если медиана каждой строки не
  ниже 0,98 предыдущей принятой строки таблицы и не ниже 0,98 базы задачи 2 (шум стенда — «несколько процентов»,
  `BENCHMARKS.md`). «Выигрыш» (задачи 6 и 10) — не меньше 1,02 предыдущей принятой. `sink` равен базе.
- **Запись замера.** Строка в таблицу раздела «Native-Rust phase 1, rmasscan-core» в `BENCHMARKS.md` (задача 2): задача,
  sha замеренного коммита, медианы стенда, медианы Mac, решение. Отдельный коммит
  `docs(rmasscan): record native-core task N on the bench host`. Не прошла — строка с решением «отклонено», правка
  дорабатывается или откатывается `git revert --no-edit <sha>`.

## Review Focus

1. **Ctrl-C посреди пачки упреждения:** `paused.conf` пишет `resume_base()` после любого числа подтверждённых зондов;
   пользователь ждёт ту же точку и тот же хвост, что без упреждения — тест `pause_at_every_k_resumes_the_exact_suffix`
   (задача 5).
2. **Цель IPv6 без адреса источника IPv6 посреди пачки:** скан падает на том же зонде, с той же ошибкой и позицией,
   ничего не пропуская — тест `failure_position_matches_unbatched` (задача 5).
3. **`--infinite` со вторым проходом:** ни одна пара, перемешанная со старым seed, не попадает в новый проход —
   тест `advance_pass_refused_while_lookahead_holds_pairs` (задача 5).
4. **Смесь TCP, UDP с нагрузкой и без, SCTP и ICMP при повторном использовании буферов:** кадр короче предыдущего не
   несёт его хвоста — тест `recycled_buffers_leave_no_stale_tail` (задача 6).
5. **Принятый кадр IPv4 обрезан или с нечётной границей заголовка:** вердикт суммы прежний (слово через `max` читает
   байт на `max`, байты за концом — 0) — тест `ip_header_checksum_edge_cases` (задача 1, держит задачу 7).

---

### Задача 0: страховка — дайджесты потоков, `-sL` и корпусов разборщиков

Только тесты, `src/` не меняется. Значения записываются на неизменённом коде (база) и после этого не правятся.

**Files:**
- Create: `tests/common/digest.rs`, `tests/native_digests.rs`

**Interfaces:**
- Produces (`tests/common/digest.rs`, через `common::Sha256`): `pub struct Digest`; `new()`, `u16/u32/u64(v)` (LE),
  `bytes(&[u8])` (длина u32 LE, затем байты), `text(&str)` (как `bytes`), `target(TargetIp)` (байт 4 или 6, затем u128
  LE), `probe(&Probe)` (`index, ip_me, port_me, ip_them, target, port_them, port_index, seqno, frame` в этом порядке),
  `finish(self) -> String` (hex SHA-256).
- Produces (`tests/native_digests.rs`): `const EXPECTED: &[(&str, &str)]` — ключ `"<сценарий>/<поток>"`, hex.
  `RMASSCAN_PRINT_DIGESTS=1` печатает строки `("ключ", "hex"),` в порядке вычисления и не сверяет; без неё каждый
  вычисленный ключ обязан быть в таблице с тем же значением, лишних ключей в таблице нет.

Потоки сценария: `probes` — `for_each_probe_nic_with_payloads(eff, &nics[0], &PayloadTable::builtin(), …)`; `cursor1` —
`ReadyPlan::new_cli_with_payloads` → `cursor_for_nic(n, None)` для каждого адаптера, `preload(1)` + `advance_sent_n(1)`,
после каждого шага в дайджест `position()` и `resume_base()`; `cursor64` — то же с `preload(64)` +
`advance_sent_n(len)`; `transmit` — кортежи `transmit_scan_flow_v46` (`i, repeats, xxx, target, port`) для каждого
адаптера. В конце потока — текст ошибки (`{:?}` ошибки `for_each…` или `build_error()`) и последняя `position()`. Для
плана с одним адаптером тест ещё сверяет, что записи `cursor1` и `cursor64` равны `probes`.

Умолчания сценариев: цели `198.18.0.0/26`, порты `80,443`, Ethernet, модификаторы по умолчанию, адаптер `10.255.0.1`,
MAC `00:11:22:33:44:55` → `66:55:44:33:22:11`, порт источника `40000`, seed 42, rate 100, retries 0, shard 1/1, 14 раундов.

| сценарий | отличие от умолчаний |
|---|---|
| `tcp_eth`, `tcp_null`, `tcp_raw` | канал Ethernet / Null / Raw |
| `tcp_ttl42`, `tcp_badsum`, `tcp_options` | `ttl 42`; `badsum`; опции MSS 1460 + SACK + wscale 3 + tsecho `0x12345678` |
| `tcp_null_all` | Null + ttl 42 + badsum + все опции |
| `udp_eth`, `udp_raw` | порты `U:53,U:161,U:9999` (нагрузка DNS, SNMP, без записи), ttl 42; Ethernet / Raw |
| `sctp_eth`, `icmp_null`, `arp_eth` | `S:80,S:2905`; `I:0` на Null с ttl 42; `I:2` |
| `mixed_eth` | `80,U:53,S:2905,I:0` |
| `retries2`, `shard_2_3`, `resume` | retries 2; shard 2/3; `resume_index` 37 + `resume_count` 50 |
| `two_nics` | второй адаптер `10.255.0.2`, порт 41000 (`probes` без сверки с курсорами) |
| `src_ports_16`, `src_ips_4` | порты источника 40000–40015; адреса 10.255.0.4–10.255.0.7 и порты 40000–40003 |
| `infinite` | порт 80, `infinite`, retries 1, rate 102; курсоры: проход 0, `advance_pass()`, проход 1, `repeats()` (сверка с `probes` — только проход 0) |
| `v46_eth`, `v46_raw` | цели `198.18.0.0/28,2001:db8::/124`, у адаптера `source_ipv6` и `next_hop_mac_ipv6` |
| `v46_no_src6` | те же цели, адаптер без `source_ipv6`: отказ посреди прохода |
| `bad_oproto`, `bad_icmp` | `80,O:6`; `80,I:1,I:600`; план `ReadyPlan::new_cli_without_port_checks` |
| `studio_map` | `ReadyPlan::with_destinations`, цели `/28`, у каждой свой MAC `02:00:c6:12:00:xx`; только курсоры |

Сценарии с IPv6 — только Ethernet и Raw: первые 4 байта кадра IPv6 на Null — `AF_INET6` хоста (10, 30 или 23), и дайджест,
записанный на Mac, упал бы на Linux и Windows CI.

- [ ] **Step 1: база.** `git diff --stat $BASE -- rmasscan` пуст; проверка 4c (Global Constraints).
- [ ] **Step 2: дайджесты потоков** — `stream_digests_match_base` по таблице сценариев (сборка конфигурации как в
  `probe.rs::tests::eff`, `v6_nic`, `range_nic`, но через публичный API).
- [ ] **Step 3: дайджесты `-sL` и transmit** — `list_and_transmit_digests_match_base`:
  - `list/r{1..5}/s{seed}`, seed ∈ {1, 2, 0xFFFF_FFFF, u64::MAX}: для N в 1..=40 (цели `10.0.0.1`…N подряд, порт 80),
    retries ∈ {0, 2}, shard ∈ {1/1, 2/3}: итог `list_scan_v46` (`Ok` или `{:?}` ошибки, включая `NonTerminating`) и все
    пары `(target, port)`;
  - `transmit/r{1..5}/s{seed}`: те же N, retries ∈ {0, 2}, shard ∈ {1/1, 2/3}, (`nic_count`, `nic_index`) ∈ {(1,0),
    (2,1)}, rate ∈ {1, 7, 40, 100, 1e8} (обе ветки приведения по модулю, включая rate == range): все кортежи;
  - `big/1000`, `big/1000003` (адреса подряд от `10.0.0.0`, порт 80, seed 1, 14 раундов): кортежи transmit и пары `-sL`;
  - `v46/list`, `v46/transmit`: цели `198.18.0.0/28,2001:db8::/126`, порты `80,443`.
- [ ] **Step 4: корпуса разборщиков** — `parser_corpus_digests_match_base`. Вход — детерминированный xorshift64* с
  фиксированным seed в тесте; дайджест на каждые 500 входов (`corpus/<имя>/<k>`):
  - `targets` (5000): 1–8 токенов из {адрес IPv4, `/8`, `/31`, `/33`, диапазон через `-`, `0.0.0.0/31`, `::1`,
    `2001:db8::/120`, диапазон IPv6, `1.2.3`, `300.1.1.1`, `,`, пробел, таб, случайный байт ASCII} →
    `MassIp::add_target_string` (`Ok` + оба списка диапазонов или `{:?}` ошибки) и `range_parse_ipv4`;
  - `ports` (5000): 1–6 токенов из {`80`, `0`, `65535`, `65536`, `1-1024`, `T:80`, `U:53`, `U:`, `S:2905`, `I:0`, `I:2`,
    `O:6`, `I:600`, `,`, `-`, пробел, `x`, случайный байт} → `parse_ports` (итог и диапазоны);
  - `nmap` (2000): 1–10 строк из {`udp 53 "\x00\x01abc"`, `udp 1-3,7 "a\8\9\0\x4"`, `# …`, `source 53`, `udp U:5 "q"`,
    `tcp 80 "x"`, пустая, `udp 53`, незакрытая кавычка, случайная строка} → `PayloadTable::empty()` +
    `load_nmap_payloads_bytes` (итог, затем `ports()` и для каждого `get(port)`: нагрузка, `source_port`, `set_cookie`);
  - `snmp` (5000): нагрузка порта 161 из `PayloadTable::builtin()` с 0–4 случайными заменами байтов и обрезкой до
    случайной длины, seqno случайный → байты после `CookieMutator::Snmp.apply`;
  - `ranges` (2000): `RangeList` из 1–30 `add_range` (иногда `begin > end`), с `sort_and_merge` и без, `exclude` со
    случайным списком (включая исключение от `0.0.0.0`, которое оставляет `{2,1}`) → `as_slice()`, `is_contains` для
    каждого `begin`, `end`, ±1 и 16 случайных, `pick` после `optimize` для всех индексов меньше `count()` (до 4096);
  - `ranges6` (2000): то же для `Range6List` (`add`, `apply_excludes` с 1–300 исключениями, `::` и `ffff:…:ffff` на
    краях, `is_contains`, `pick`);
  - `receive` (4000): каждый кадр сценариев `tcp_eth`, `udp_eth`, `sctp_eth`, `icmp_null`, `arp_eth`, `v46_eth` как
    есть и с переставленными MAC, адресами и портами источника и назначения, затем 0–3 случайные замены байтов и обрезка
    → `{:?}` результатов `parse_reply_with` (обе `ChecksumPolicy`), `tcp_frame::tcp_segment`, `arp::decode`,
    `arp::incoming_request` с планом сценария.
- [ ] **Step 5: запись.** `RMASSCAN_PRINT_DIGESTS=1 cargo test --locked -p rmasscan-core --test native_digests --
  --nocapture` на базе, вывод — в `EXPECTED`; без переменной — PASS.
- [ ] **Step 6:** G-core, G-frozen и `git diff --exit-code $BASE -- rmasscan/crates/rmasscan-core/src`;
  **коммит** `test(rmasscan-core): pin frame, -sL and parser digests before the native refactor`.
- [ ] **Step 7: другая ОС.** Закоммиченный тест на хосте стенда (дерево через `git archive HEAD:rmasscan`, как в
  G-bench; `cargo test --locked -p rmasscan-core --test native_digests`, без `--release`) — PASS. Падение значит, что
  сценарий зависит от ОС: исправить сценарий (не значения), перезаписать на базе и закоммитить исправление.

### Задача 1: страховка — эталонные копии и дифференциальные тесты

Только тесты. Копии — дословно тела на базе; используют из ядра только то, что план не меняет: `blackrock::SBOX`,
`packet::DEFAULT_*_TEMPLATE`, `PacketModifiers`, `TcpHeaderOptions`, `LinkType`, `checksum::{word_sum,
udp_ipv4_checksum, sctp_crc32c}`, `PayloadEntry::with_cookie`. Всё, что план меняет, скопировано.

**Files:**
- Create: `tests/common/reference.rs`, `tests/native_reference.rs`

**Interfaces:**
- Produces (`tests/common/reference.rs`):
  `ref_ip_header_checksum(px: &[u8], offset_ip: usize, max: usize) -> u16` (`src/checksum.rs:8-50`, с `byte`/`be16`);
  `ref_fold(u64) -> u16`, `ref_tcp_ipv4_partial(px, offset_ip, offset_tcp, offset_app) -> u16` (`:56-80`);
  `ref_siphash24(data, k0, k1) -> u64` (`siphasher` + `Hasher::write` + `finish`, `src/cookie.rs:11-15`),
  `ref_syn_cookie_ipv4(..) -> u64`, `ref_syn_cookie_ipv6(..) -> u64` (`:18-63`);
  `RefBlackRock::new(range, seed, rounds)` (таблица `a`, `b` из `try_new`, `src/blackrock.rs:52-89`), `.shuffle(m)`,
  `.unshuffle(m)`, `.domain()` (`:95-107`, `:134-142`, `read`/`encrypt`/`unencrypt` `:144-203`);
  `RefTcpSyn::new(source_mac, router_mac, link, &PacketModifiers)` + `.build_syn(ip_them, port_them, ip_me, port_me,
  seqno) -> Vec<u8>` (`src/packet.rs:87-120`, `:147-203`, `:223-263`);
  `RefIcmpEcho::new(source_mac, router_mac, link, ttl)` + `.build_echo(ip_them, ip_me, seqno, entropy) -> Vec<u8>`
  (`:438-512`, cookie через `ref_syn_cookie_ipv4`); `RefUdp::new(..)` + `.build_udp((ip_them, port_them), (ip_me,
  port_me), seqno, Option<&PayloadEntry>) -> Vec<u8>` (`:524-596`); `RefSctp::new(..)` + `.build_init(..) -> Vec<u8>`
  (`:617-678`).

- [ ] **Step 1: тесты** в `tests/native_reference.rs` (proptest, `FileFailurePersistence::Direct` в
  `tests/proptest-regressions/native_reference.txt`, как `tests/proptest_order.rs:32-41`; файл появляется только при
  падении и коммитится вместе с исправлением):
  - `blackrock_matches_reference` (2048 случаев): range из {1..=64, 1..=2^40, 2^63-1, 290112, 1000003}, seed любой,
    rounds 0..=63, `m < range`: `shuffle`, `unshuffle`, `unshuffle(shuffle(m)) == m`, `domain()` равны эталону;
  - `ip_header_checksum_matches_reference` (8192): буфер 0..=80 случайных байт (в половине случаев байт `offset` вида
    `0x4?`), `offset` 0..=90, `max` 0..=100;
  - `ip_header_checksum_edge_cases` (Review Focus 5): заголовок IHL 5 при `max` = `offset+19`, `offset+1`,
    `offset+20`, `offset+21`; IHL 15 на буфере 30 байт; IHL 0; `offset >= len`; `max` меньше `offset` — всё равно эталону;
  - `tcp_syn_matches_reference` (4096): адреса, порты, seqno случайные × три канала × ttl любой × badsum × каждая опция
    `Some`/`None` (MSS, SACK, wscale, tsecho);
  - `ipv4_probe_builders_match_reference` (4096): ICMP (entropy случайная), UDP с нагрузкой `None`, встроенными записями
    53, 111, 123, 137, 161, 500, 2049, 5683, 11211 и своей записью без мутатора длиной 0..=1472, SCTP;
  - `siphash_and_cookies_match_reference` (4096): данные 0..=64 байт, ключи, обе функции cookie.
- [ ] **Step 2: PASS** на базе: копии верны. G-core, G-frozen (src не менялся); **коммит**
  `test(rmasscan-core): frozen reference copies for differential tests`.

### Задача 2: страховка — цикл курсора в бенчмарке и база замеров

**Files:**
- Modify: `tests/common/offline_gen.rs`, `benches/offline_gen.rs`, `tests/offline_gen.rs`, `rmasscan/BENCHMARKS.md`

**Interfaces:**
- Produces (`tests/common/offline_gen.rs`):
  `pub fn cursor_plan(targets: &str, ports: &str, source_ports: (u16, u16)) -> ReadyPlan` — план CLI (`new_cli`, один
  адаптер Ethernet с адресом и MAC оракула), seed 1, rate 1e8, 14 раундов;
  `pub fn mapped_plan(targets: &str, ports: &str) -> ReadyPlan` — `ReadyPlan::with_destinations`, у каждой цели свой
  одноадресный MAC `02:00:<4 байта адреса>`;
  `pub fn generate_cursor(plan: &ReadyPlan, preload: usize) -> (u64, u64)` — `cursor_for_nic(0, None)`; пока
  `preload(preload)` не пуст: `sink += seqno + frame[24] + frame[53]` (wrapping) по срезу, `advance_sent_n(len)`;
  возвращает (число зондов, sink). Без троттлера (у движка свой).
- Produces: строки бенчмарка `offline_gen run k`, `cursor_1port run k` (`/10` × p80, порт 40000), `cursor_16port run k`
  (`/10` × p80, порты 40000–40015, две cookie на зонд), `cursor_mapped run k` (`10.0.0.0/16` × `1-64`, 65 536 записей
  карты) — у каждой pps и sink; тест `#[ignore] offline_cursor_generation_2_28` (`0.0.0.0/4` × p80, один порт,
  `preload(64)`, печать `OFFLINE_CURSOR packets=… seconds=… pps=… sink=…`, `assert_eq!(n, 1 << 28)`, только release, та
  же проверка CPU, что у `offline_generation_meets_80pct_of_oracle`, порога нет).

- [ ] **Step 1:** `small_cursor_workload_covers_every_target` (обычный `cargo test`): `/24` × p80 — `generate_cursor` с
  `preload` 1 и 64 даёт 256 зондов, все пары (адрес, порт) `/24` и одинаковый sink. FAIL (функции нет) → реализация →
  PASS.
- [ ] **Step 2:** циклы в `benches/offline_gen.rs`, тест 2^28 курсора в `tests/offline_gen.rs`. Короткое имя хоста в
  комментариях этих двух файлов и в тексте `#[ignore = …]` заменить на «bench host».
- [ ] **Step 3: `BENCHMARKS.md`:** в командах и таблице заменить короткое имя хоста на `$BENCH_HOST` / «bench host»
  (роль, без имени); добавить команды G-bench с `--test-threads=1` и раздел «Native-Rust phase 1, rmasscan-core» с
  таблицей `task | commit | bench host OFFLINE_GEN pps | OFFLINE_CURSOR pps | vs base | Mac medians (4 loops) | sinks |
  decision`.
- [ ] **Step 4:** G-core, G-frozen; **коммит** `test(rmasscan-core): ProbeCursor loops in the bench and a 2^28 cursor
  run` (пути выше).
- [ ] **Step 5: база.** G-mac и G-bench на этом коммите (на `src/` базы); строка «2 (base)» в таблицу; **коммит** записи.

### Задача 3: BlackRock — маска раунда

**Files:**
- Modify: `src/blackrock.rs` (`read` :144-158, `encrypt` :161-175, `unencrypt` :178-203, тесты)

**Interfaces:**
- Produces (приватно): `fn round_mask(seed: u64, r: u64) -> u64`, `fn sbox_mix(x: u64) -> u64`; инвариант
  `read(r, R, seed) == sbox_mix(R ^ round_mask(seed, r))` для r в 1..=63:
  ```rust
  // байт n индекса S-box: ((R >> 8n) ^ seed ^ r) & 0xFF после R ^= rot(seed, r)  ==  (x >> 8n) as u8, где
  let rot = seed.wrapping_shl(r as u32) ^ seed.wrapping_shr((64 - r) as u32);
  let mask = rot ^ ((seed ^ r) & 0xFF).wrapping_mul(0x0101_0101_0101_0101);   // x = R ^ mask
  ```
  `sbox_mix` — смешивание `r0 ^ r1 ^ r2<<23 ^ r3<<33` из `read` (:152-157) по байтам `x`. Маска считается на лету в
  каждом раунде `encrypt` и `unencrypt`. Таблицы масок в структуре нет: `BlackRock` остаётся `Copy, PartialEq, Eq,
  Debug` с прежними пятью полями (иначе +512 байт и другой `Debug` у `PlanInner`/`ReadyPlan`).

- [ ] **Step 1: тест** `round_mask_matches_c_read` (юнит): копия старого `read` в модуле тестов; r ∈ 1..=63, seed ∈ {0, 1,
  u64::MAX, 0x0123_4567_89ab_cdef, 1000 случайных}, R случайный → равенство. FAIL (нет `round_mask`).
- [ ] **Step 2:** реализация; **PASS** G-core (там же `blackrock_matches_reference`, `tests/blackrock_golden.rs`,
  `tests/scan_golden.rs`, `tests/proptest_order.rs`, дайджесты).
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): BlackRock round mask computed once per round`.
- [ ] **Step 4:** G-mac, G-bench; запись.

### Задача 4: BlackRock по 8 индексов в `transmit` и `-sL`

Цепочка 14 раундов ждёт каждое деление; 8 независимых индексов с чередованием по раундам прячут задержку.

**Files:**
- Modify: `src/blackrock.rs`, `src/scan.rs` (`TransmitIndices` :151-187, `transmit_index_stream` :225-254,
  `list_scan_v46` :304-350, `transmit_scan_flow_v46` :444-484)

**Interfaces:**
- Produces (`blackrock.rs`): `pub(crate) const SHUFFLE_LANES: usize = 8;`
  `pub(crate) fn shuffle_batch<const K: usize>(&self, m: [u64; K]) -> [u64; K]` — равно `m.map(|x| self.shuffle(x))`:
  первый `encrypt` всех дорожек раунд за раундом (маска раунда одна на пачку), затем cycle-walk каждой дорожки скалярно.
- Produces (`scan.rs`): `pub(crate) struct TransmitIndices` (было приватным) с `pub(crate) fn peek_index(&self) ->
  Option<u64>` (`(i < end).then_some(i)` — ровно `i` следующего `next()`) и `pub(crate) fn end(&self) -> u64`;
  `#[allow(clippy::too_many_arguments)] pub(crate) fn transmit_indices(range, shard, nic_count, nic_index, resume_index,
  resume_count, retries, max_rate) -> TransmitIndices` — тело нынешнего `transmit_index_stream`, который теперь
  возвращает его (pub-сигнатура та же);
  `pub(crate) struct Shuffled<I> { inner: I, blackrock: BlackRock, buf: [(u64, u64); SHUFFLE_LANES], head: usize, len:
  usize }`, `Shuffled::new(inner: I, blackrock: BlackRock) -> Self`,
  `impl<I: Iterator<Item = (u64, u64)>> Iterator for Shuffled<I>` с элементом `(tag, blackrock.shuffle(m))` в порядке
  входа: пустой буфер набирается до 8 пар; полная пачка — `shuffle_batch`, неполная (конец потока) — скалярный `shuffle`;
  `impl Shuffled<TransmitIndices> { pub(crate) fn peek_index(&self) -> Option<u64>; pub(crate) fn end(&self) -> u64 }`
  (`peek_index`: голова буфера, иначе `inner.peek_index()`).
- `transmit_scan_flow_v46` идёт по `Shuffled::new(transmit_indices(..), blackrock)`, `Break` возвращается сразу
  (лишние перемешанные дорожки пропадают, `emit` их не видит); `list_scan_v46` — по `Shuffled` над `(i, i)` из
  `ListIndices`, проверка `NonTerminating` до первого вывода прежняя. `ProbeCursor` в этой задаче не трогается.

- [ ] **Step 1: тесты.** `shuffle_batch_equals_scalar` (юнит `blackrock.rs`): range ∈ {1, 2, 3, 9, 40, 290112, 1000003,
  2^22, 2^63-1}, seed ∈ {1, 2, 0xFFFF_FFFF, u64::MAX}, rounds ∈ {0, 1, 2, 3, 4, 14, 63}, окна из 8 значений
  `(s + k) % range` для s в начале, середине и конце диапазона. `transmit_flow_break_at_every_position` (юнит `scan.rs`): N 1..=40, retries {0,
  2}, shard {1/1, 2/3}, (nic_count, nic_index) {(1,0), (2,1)}: для каждой позиции p полного прогона `Break(p)` на p-м
  вызове → `Ok(Break(p))`, `emit` вызван ровно p+1 раз, префикс равен полному. FAIL (нет `shuffle_batch`).
- [ ] **Step 2:** реализация; **PASS** G-core (дайджесты `list/*`, `transmit/*`, `big/*`, `v46/*` и сценарии задачи 0
  без изменений; `tests/probe_cursor.rs` здесь не доказателен, он строит ожидание из `transmit_scan`), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): shuffle transmit and -sL indices eight at a time`.
- [ ] **Step 4:** G-mac, G-bench (здесь x86 может отличаться от Mac сильнее всего); запись.

### Задача 5: ProbeCursor — конкретный поток с упреждением

**Files:**
- Modify: `src/probe.rs` (`ProbeCursor` :974-997, `cursor_for_nic` :917-971, `refresh_position` :1024-1032,
  `load_one` :1036-1075, `advance_pass` :1098-1150)
- Test: `tests/probe_cursor.rs`, юнит-тесты `probe.rs`

**Interfaces:**
- Consumes: задача 4 — `transmit_indices(..)`, `Shuffled<TransmitIndices>`, `peek_index()`, `end()`.
- Produces: поле `ProbeCursor.stream: Shuffled<TransmitIndices>` вместо `Peekable<Box<dyn Iterator<Item = (u64, u64)> +
  Send>>`; поле `blackrock` уходит внутрь `Shuffled`; `load_one` берёт готовую пару `(i, xXx после shuffle)`;
  `refresh_position` и `advance_pass` смотрят `stream.peek_index()` (сначала упреждение, потом индексы); `end` берётся из
  `stream.end()` — границы считаются один раз (`cursor_for_nic` и `advance_pass` больше не зовут `transmit_bounds` рядом с
  потоком). `advance_pass` строит новый `Shuffled` с `BlackRock(seed + repeats + 1)`. `ProbeCursor` остаётся `Send`, его
  `pub`-методы и `Debug` прежние.
- Ловушка: если `refresh_position`/`advance_pass` смотрят только на индексы, а не на упреждение, `position()`,
  `resume_base()` и `paused.conf` уезжают на 1–7 после отказа построителя или паузы. `tests/probe_cursor.rs` этого не
  заметит; ловят дайджесты `cursor1`/`cursor64` и тесты ниже.

- [ ] **Step 1: тесты.** `probe_cursor_is_send` (статическая проверка); в `tests/probe_cursor.rs`
  `pause_at_every_k_resumes_the_exact_suffix` (Review Focus 1): план CLI `198.18.0.0/27`, порты `80,443`, retries 2,
  shard 2/3, 2 адаптера, порты источника 40000–40015, адаптер 1; полный слив `full`; для каждого k в 0..=len:
  подтвердить k зондов пачками `preload(64)` + `advance_sent_n(min(64, k - отправлено))` → `position()` равен
  `full[k].index` (или `effective_end(1)` при k == len), `resume_base() == position() - nic_offset(1)`, курсор
  `cursor_for_nic(1, Some(resume_base()))` даёт хвост `full`, начиная с первого зонда этого индекса.
  `failure_position_matches_unbatched` (Review Focus 2): цели `198.18.0.0/28,2001:db8::/124`, адаптер без
  `source_ipv6`; с `preload(1)` и `preload(64)` зонды до отказа, `position()` после отказа и `build_error()` совпадают
  между собой и с дайджестом `v46_no_src6`.
  `advance_pass_refused_while_lookahead_holds_pairs` (Review Focus 3): `--infinite`, `/26` × p80; `preload(1)` +
  `advance_sent_n(1)` (в упреждении остались пары) → `advance_pass() == false`; после полного слива → `true`, проход 1
  совпадает с дайджестом `infinite`. Тесты закрепляют поведение базы и проходят до правки (кроме `probe_cursor_is_send`,
  которому всё равно); чувствительность после реализации — временно заставить `Shuffled::peek_index` смотреть только
  на индексы: первые два теста падают; вернуть.
- [ ] **Step 2:** реализация; **PASS** G-core (дайджесты `cursor1`/`cursor64`/`infinite`/`v46_no_src6`), G-ws (движок и
  CLI шлют через курсор).
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): ProbeCursor reads a concrete shuffled stream with lookahead`.
- [ ] **Step 4:** G-mac (`cursor_*` против задачи 2), G-bench (`OFFLINE_CURSOR` — главный); запись.

### Задача 6: ProbeCursor — буферы зондов и таблица доставки

**Files:**
- Modify: `src/probe.rs` (`ProbeCursor`, `load_one` :1049 и :1064, `advance_sent_n` :1180-1189, `PlanInner` :550-562,
  `ReadyPlan::build` :769-823)
- Test: `tests/probe_cursor.rs`

**Interfaces:**
- Produces: поле `ProbeCursor.spare: Vec<Probe>` — `advance_sent_n` переносит подтверждённые зонды туда, `load_one`
  берёт `spare.pop().unwrap_or_default()`; `fill`/`fill_v6` перезаписывают все девять полей `Probe` (`build_*` делают
  `out.clear()`), отказавший зонд возвращается в `spare`. Поле `PlanInner.destination_macs: Option<Box<[(u32, [u8;
  6])]>>`, отсортировано по адресу, строится из карты один раз; `load_one` ищет `binary_search_by_key` (покрытие
  гарантирует конструктор, как сейчас `destinations[&ip]`). Геттер `destinations() -> Option<&BTreeMap<u32, [u8; 6]>>`
  прежний.

- [ ] **Step 1: тесты.** `recycled_buffers_leave_no_stale_tail` (Review Focus 4): план CLI `198.18.0.0/28`, порты
  `80,U:53,U:161,U:9999,S:2905,I:0` (кадры 58, 42+DNS, 42+SNMP, 42, 66, 90 байт), циклы `preload(3)` +
  `advance_sent_n(3)` и `preload(64)` + `advance_sent_n(64)`: каждый `Probe` целиком (кадр включительно) равен зонду
  `for_each_probe_nic_with_payloads` на той же позиции. `mapped_plan_uses_each_targets_own_mac`: план Студии, 64 цели с
  разными MAC, `preload(64)`: `frame[..6] == map[ip]`, остальные байты равны плану без карты. Оба закрепляют поведение
  базы и проходят до правки; чувствительность после реализации — временно убрать `out.clear()` из `build_udp`: первый
  тест падает; вернуть.
- [ ] **Step 2:** реализация; **PASS** G-core, G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): ProbeCursor reuses probe buffers and a sorted delivery table`.
- [ ] **Step 4:** G-mac; G-bench; дополнительно `cargo bench --locked -p rmasscan-core` три раза на хосте стенда (дерево из
  `git archive`, тот же `CARGO_TARGET_DIR`) — строка `cursor_mapped` против задачи 2. Таблица доставки остаётся только при
  выигрыше на стенде (не меньше 1,02); иначе её часть откатывается отдельным коммитом, решение — в запись.

### Задача 7: `ip_header_checksum` срезом

**Files:**
- Modify: `src/checksum.rs:36-50`

**Interfaces:**
- `pub fn ip_header_checksum(px: &[u8], offset_ip: usize, max: usize) -> u16` — сигнатура та же. Правило C:
  `header_length = (px[offset_ip] & 0xF) * 4` (0 за концом); `end = min(max, offset_ip + header_length)`; слова с
  `offset_ip, offset_ip + 2, …` пока `i < end`; слово, которое начинается на `end - 1`, всё равно читает байт на `end`;
  любой байт за `px.len()` — 0. Реализация: срез `px[min(offset_ip, len) .. min(offset_ip + 2 * ceil((end - offset_ip)
  / 2), len)]`, `as_chunks::<2>()`, нечётный остаток — `b << 8`; сумма `u32` с `wrapping_add` и три свёртки, как сейчас.
- Ловушка: `chunks(2)` по `..max` неверен — первая такая версия разошлась с C на одном случае из двух миллионов.

- [ ] **Step 1:** тесты уже есть (задача 1: `ip_header_checksum_matches_reference`, `ip_header_checksum_edge_cases`);
  RED — временно обрезать срез по `max` и увидеть падение `edge_cases`.
- [ ] **Step 2:** реализация; **PASS** G-core (селфтест C в `checksum.rs`, `tests/receive.rs`, `tests/tcp_frames.rs`,
  корпус `receive`), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): IPv4 header checksum over a slice`.
- [ ] **Step 4:** G-mac, G-bench (`build_syn` пока зовёт её на каждом кадре); запись.

### Задача 8: сборщики кадров IPv4 — приращение суммы IP и общий код шаблонов

**Files:**
- Modify: `src/packet.rs` (`tcp_option_bytes` :87-113, `TcpSynTemplate` :124-263, `Tcp6SynTemplate::new_with_options`
  :327-368, `IcmpEchoTemplate` :430-512, `UdpTemplate` :518-596, `SctpTemplate` :611-678)

**Interfaces:**
- Produces (приватно): `struct TcpOptionBytes { buf: [u8; 20], len: usize }` + `fn as_slice(&self) -> &[u8]`,
  `fn tcp_option_bytes(o: &TcpHeaderOptions) -> TcpOptionBytes` (без `Vec` и цикла `while`);
  `fn relink(px: Vec<u8>, link: LinkType, offset_ip: usize, offset_l4: usize) -> (Vec<u8>, usize, usize)` — один
  «DATALINK KLUDGE» (templ-pkt.c:1342-1360) для четырёх шаблонов IPv4; одна запись заголовка IPv4 для четырёх
  `build_*`: длина, ID, адреса и сумма приращением:
  ```text
  base  = ip_header_checksum(шаблон) при нулевых ID, сумме и адресах   // у TCP это уже хранимый checksum_ip
          (у UDP ещё и при нулевой полной длине: длина зависит от нагрузки)
  sum   = base + [total_length, только UDP] + ip_id + ip_me>>16 + ip_me&0xFFFF + ip_them>>16 + ip_them&0xFFFF   (u64)
  поле  = !fold(sum)
  ```
  Равенство с полным пересчётом для любых входов: обе суммы положительны и равны по модулю 0xFFFF, а свёртка
  положительного числа даёт представителя в 1..=0xFFFF. Шаблоны ICMP, UDP и SCTP получают приватное поле `ip_base: u16`;
  `TcpSynTemplate::checksum_ip()` возвращает то же, что сейчас. Поля пишутся через `first_chunk_mut::<20>()` заголовков
  IP и L4. Нагрузка UDP: `out.extend_from_slice(&e.payload)`, затем `m.apply(&mut out[start..], seqno)` — без
  промежуточного `Vec`; `PayloadEntry::with_cookie` (pub) остаётся.

- [ ] **Step 1:** тесты уже есть (задача 1: `tcp_syn_matches_reference`, `ipv4_probe_builders_match_reference`);
  добавить `udp_length_term_covers_every_payload_length` в `tests/native_reference.rs`: своя запись без мутатора длиной
  0..=1472 × три канала, кадр равен `RefUdp`. RED — временно убрать слагаемое длины у UDP.
- [ ] **Step 2:** реализация; **PASS** G-core (тесты `packet.rs`: `syn_frame_matches_c_bytes`,
  `syn_checksums_validate_when_u64_sum_exceeds_2_pow_32`, `ttl_lands_in_every_link_type_with_a_valid_header_sum`,
  `null_and_raw_are_trimmed_ethernet_frames`, `tcp_options_layout_and_padding_match_c`,
  `all_tcp_options_and_badsum_keep_valid_ipv4_header`, `icmp_echo_frame_and_cookie_match_c`,
  `udp_frames_match_c_bytes_for_every_port`, `sctp_crc32c_matches_c_selftest_in_a_built_frame`; `udp_c_vectors`;
  дайджесты всех каналов), G-ws. `tests/probe_cursor.rs` строит ожидание из нового `build_syn` и здесь не доказателен.
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): incremental IPv4 header sum and one header writer for all
  probe templates`.
- [ ] **Step 4:** G-mac, G-bench; запись.

### Задача 9: SipHash одним вызовом

**Files:**
- Modify: `src/cookie.rs:7-15`

**Interfaces:**
- `pub fn siphash24(data: &[u8], k0: u64, k1: u64) -> u64` — сигнатура та же (её зовёт 4c); тело
  `SipHasher24::new_with_keys(k0, k1).hash(data)` (`siphasher` 1.0.4, тот же крейт, `Cargo.lock` прежний);
  `use std::hash::Hasher` уходит, если не нужен.

- [ ] **Step 1:** проверка 4c (Global Constraints). Тесты уже есть: `siphash24_reference_vectors` (64 вектора C),
  `syn_cookie_matches_c_values`, `syn_cookie_ipv6_matches_c_bytes`, `siphash_and_cookies_match_reference`.
- [ ] **Step 2:** правка; **PASS** G-core, G-ws (`rmasscan-proto` 4c и движок зовут cookie).
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): one-shot SipHash for cookies`.
- [ ] **Step 4:** G-mac (`cursor_16port`: две cookie на зонд), G-bench; запись.

### Задача 10: деления — только при выигрыше на хосте стенда

Три правки, у каждой свой коммит, свой G-bench и своя запись. Правка остаётся только при выигрыше (не меньше 1,02
предыдущей принятой строки) без регрессии второй строки; иначе `git revert --no-edit <sha>` и запись «нет выигрыша,
откат». Числа Mac здесь не решают ничего: на M4 аппаратное деление быстрое, на x86 стенда — медленное.

**Files:**
- Modify: `src/scan.rs` (`TransmitIndices::next` :170-187), `src/massip.rs` (`pick` :208-220), `src/blackrock.rs`,
  `src/scan.rs` (`Shuffled`)

**Interfaces:**
- 10a: приватная `fn reduce_mod(x: u64, range: u64) -> u64` в `scan.rs`: `x` при `x < range`; `x - range` при
  `x - range < range`; иначе `x % range`. Значение то же, что у `x %= range`, работа ограничена (цикл вычитания C растёт
  с retries).
- 10b: в `MassIp::pick` при `count_ports == 1` — `(ipv4.pick(index), ports.pick(0))` (индекс меньше порога
  `count_ipv4s * 1`, так что `%` и `/` дают `index` и 0); оба `assert!` прежние.
- 10c: деление на инвариантный делитель только на пути пачек. Приватно в `blackrock.rs`:
  `struct InvariantDiv { d: u64, magic: u64, shift: u32, kind: u8 }`, `fn new(d: u64) -> Self` (d ≥ 1),
  `fn div(&self, n: u64) -> u64`, `fn rem(&self, n: u64) -> u64`; `pub(crate) struct Divisors { a: InvariantDiv, b:
  InvariantDiv }`, `pub(crate) fn divisors(&self) -> Divisors`, `pub(crate) fn shuffle_batch_with<const K: usize>(&self,
  d: &Divisors, m: [u64; K]) -> [u64; K]`. `Shuffled` хранит `Divisors`, построенные в `Shuffled::new`; в `BlackRock`
  полей не прибавляется (размер и `Debug` прежние); cycle-walk дорожек остаётся на `%`. Метод (как `libdivide_u64_gen`):
  ```text
  d степень двойки:  q = n >> log2(d)
  иначе l = floor(log2 d), m = floor(2^(64+l) / d), rem = 2^(64+l) mod d (в u128)
    d - rem < 2^l:   magic = m + 1;                       q = mulhi(magic, n) >> l
    иначе:           magic = 2m + 1 (+1, если 2*rem >= d или 2*rem переполнилось);
                     t = mulhi(magic, n); q = (((n - t) >> 1) + t) >> l
  rem(n) = n - q * d
  ```

- [ ] **Step 1 (10a):** тест `reduce_mod_equals_modulo` (range ∈ {1, 2, 3, 40, 2^28, 2^63-1}; x ∈ {0, range-1, range,
  2·range-1, 2·range, u64::MAX} и 10 000 случайных) и `transmit_stream_with_wrapping_rate_term` (range 40, retries 2,
  rate 1.8e19: поток равен копии старого `next` в модуле тестов). FAIL → правка → PASS G-core (дайджесты `transmit/*`
  покрывают rate 1, 7, 40, 100 и 1e8), G-ws; G-frozen; **коммит** `perf(rmasscan-core): reduce the transmit index without
  a division when it is in range`; G-bench; решение и запись.
- [ ] **Step 2 (10b):** тест `single_port_pick_equals_division` (все индексы трёх диапазонов × 1 порт против `%`/`/`).
  FAIL → правка → PASS G-core (`pure_ipv4_pickers_agree`, `pick_*`, `tests/scan_golden.rs`), G-ws; G-frozen; **коммит**
  `perf(rmasscan-core): single-port pick without a division`; G-bench; решение и запись.
- [ ] **Step 3 (10c):** тест `invariant_div_is_exact` (юнит `blackrock.rs`): делители 1, 2, 3, 7, все `a` и `b`
  `BlackRock` для range 1..=1000 и {2^22, 2^28, 290112, 1000003, 2^63-1}, 20 000 случайных в 1..2^32 и 2000 в 1..u64::MAX;
  числители 0, 1, d-1, d, d+1, 2d-1, k·d для случайных k, u64::MAX-1, u64::MAX и 27 случайных → `div == n / d`,
  `rem == n % d`; плюс `shuffle_batch_with_equals_scalar` на наборах `shuffle_batch_equals_scalar`. FAIL → правка → PASS
  G-core, G-ws; G-frozen; **коммит** `perf(rmasscan-core): invariant-divisor rounds in the batched shuffle`; G-bench;
  решение и запись.

### Задача 11: разбор ответов и общие читатели

**Files:**
- Create: `src/bytes.rs`
- Modify: `src/lib.rs` (`mod bytes;`, не `pub`), `src/receive.rs` (флаги :54-55, читатели :170-181, `in_sorted_ranges`
  :357-363 и :523-529, статус по флагам :475-484 и :659-668, литералы `Reply {..}` :508, :685, :727, :851, :934, :1025,
  :1084, копии `is_my_port`/`is_my_ip` :829-832, :894-897, :1058-1061, `ok_or(t.clone())` :785-794, `expect` :597-598),
  `src/tcp_frame.rs` (флаги :35-36, импорт читателей), `src/arp.rs` (:54-60, :134-142), `src/ndp.rs` (:203-307),
  `src/payloads.rs` (:1161-1166), `src/ranges.rs` (`is_contains` :164-166, цикл по индексу в `exclude` :248)

**Interfaces:**
- Produces (`src/bytes.rs`, всё `pub(crate)`): `fn be16_at(b: &[u8], i: usize) -> Option<u16>`, `fn be32_at(..) ->
  Option<u32>`, `fn be128_at(..) -> Option<u128>`, `fn array_at<const N: usize>(b: &[u8], i: usize) -> Option<[u8; N]>`
  (через `b.get(i..)?.first_chunk::<N>().copied()`). Чтение «за концом — 0» остаётся только в `checksum.rs` (там его
  требует C).
- Produces (`receive.rs`, приватно или `pub(crate)`): `fn tcp_status(flags: u8) -> Option<PortStatus>`; конструкторы
  `Reply` для семи мест; один поиск по отсортированным диапазонам для IPv4 и IPv6; `pub(crate) const` номеров протоколов
  (1, 6, 17, 132) и флагов TCP (`0x04`, `0x12`), которые берёт и `tcp_frame.rs`; заголовки фиксированной длины —
  `first_chunk::<20>()` вместо проверок, которые не могут не пройти.
- Produces (`ranges.rs`): `is_contains` — двоичный поиск при `is_sorted`, линейный иначе; `exclude` — итератор вместо
  индекса. Если дифференциальный тест ниже найдёт отсортированный список, где они расходятся, двоичный поиск не вводится
  (остаётся линейный), причина — в сообщение коммита.

- [ ] **Step 1: тесты.** `readers_return_none_past_the_end` (юнит `bytes.rs`: длины 0..8, `i` 0..10 и `usize::MAX`);
  `is_contains_binary_equals_linear` (proptest, `ranges.rs`): списки из случайных `add_range` (иногда `begin > end`), с
  `sort_and_merge` и без, после `exclude` (включая исключение от `0.0.0.0`) — для каждого `begin`, `end`, ±1 и 64
  случайных значений ответ равен копии линейного поиска. FAIL (нет модуля).
- [ ] **Step 2:** реализация; **PASS** G-core (`tests/receive.rs`, `receive.rs` `tests_ipv6`, `tests/arp_replies.rs`,
  `ndp_tests.rs`, `tests/tcp_frames.rs`, корпуса `receive`, `ranges`), G-ws. Проверка 4c перед правкой `tcp_frame.rs`.
- [ ] **Step 3:** G-frozen; **коммит** `refactor(rmasscan-core): shared big-endian readers and one reply builder in
  receive`.

### Задача 12: `Builder::fill` по видам протокола

**Files:**
- Modify: `src/probe.rs` (`Builder::fill` :313-433)

**Interfaces:**
- Consumes: `targets::PortProto::from_raw(raw: u32) -> (PortProto, u16)` (pub, `targets.rs:471`; разбиение
  совпадает с нынешними ветками: `< 65536` TCP, UDP, SCTP, `TEMPL_ICMP_ECHO`, `TEMPL_ARP`, остальное `IcmpOther`/`Oproto`).
- Produces (приватно): `fn source(&self, i: u64, repeats: u64, xxx: u64) -> (u32, u32)` (main.c:379-384, `(ip_me,
  port_me)`), `fn split_u64(v: u64) -> (u32, u32)` (младшая и старшая половины для аргументов cookie). Порядок прежний:
  сначала `p.target`; затем `PortDoesNotFit { port_them, port_me }` для `port_me > 0xFFFF` в любом виде и для
  `IcmpOther`/`Oproto` (сейчас они падают в ветку TCP на `u16::try_from(port_them)`), до сборки кадра и до других полей;
  `seqno = syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, entropy) as u32` для всех видов; кадр по виду; поля
  присваиваются один раз; `port_them` зонда — 0 у ARP и ICMP Echo, младшие 16 бит у остальных.
- `port_me > 0xFFFF` через допустимый адаптер недостижим (`check_source_ports`: `first + (cookie & mask) <= last`),
  поэтому отказ проверяется через порт цели.

- [ ] **Step 1: тест** `fill_error_matches_base_for_each_kind` (юнит `probe.rs`): `new_cli_without_port_checks` с портами
  `80,O:6`, `80,I:1`, `80,I:600` → курсор останавливается с `ProbeBuild(PortDoesNotFit { port_them: <индекс>, port_me:
  40000 })` на той же позиции, что в дайджестах `bad_oproto`/`bad_icmp`; на базе проходит, RED — временно поменять порядок
  проверки и сборки.
- [ ] **Step 2:** реализация; **PASS** G-core (тесты планов ICMP, ARP, SCTP, UDP в `probe.rs`,
  `sticky_port_prefixes_and_oproto_live_refusal`, дайджесты; `tests/probe_cursor.rs` строит ожидание тем же кодом и здесь
  не доказателен), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `refactor(rmasscan-core): Builder::fill classifies the port index once`.
- [ ] **Step 4:** G-mac, G-bench (только «без регрессии»: `fill` идёт на каждый зонд); запись.

### Задача 13: кадры стека в готовый буфер

**Files:**
- Modify: `src/tcp_frame.rs` (`put` :156-163, `TcpFrameBuilder::build` :210-219, `build_v4`/`build_v6` :233-295)
- Test: `tests/tcp_frames.rs`

**Interfaces:**
- Produces: `pub fn build_into(&self, s: &SegmentOut, out: &mut Vec<u8>)` — очищает `out` и пишет кадр; кадра нет
  (длиннее 2040 байт или IPv6 без `source_ipv6`) — `out` пуст. `pub fn build(&self, s: &SegmentOut) -> Vec<u8>` —
  обёртка над `build_into`, сигнатура прежняя (вызовы движка переходят в фазе 2). Поля пишутся прямо в голову шаблона
  (она всегда содержит полные заголовки IP и TCP шаблона SYN); `put` уходит, если не нужен. `SegmentOut.window` живёт в
  `stack.rs` и не трогается.

- [ ] **Step 1:** проверка 4c. Тест `build_into_equals_build_and_reuses_the_buffer`: для каждого случая
  `tests/tcp_frames.rs` `build_into` в буфер, где раньше лежали 2040 байт `0xAA`, равен `build`; сегмент длиннее предела
  и IPv6 без источника оставляют буфер пустым. FAIL (нет метода).
- [ ] **Step 2:** реализация; **PASS** G-core (15 эталонов C в `tests/tcp_frames.rs`), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): TcpFrameBuilder::build_into writes into a reused buffer`.
  Замера нет: путь стека и вызовы движка меняются в фазе 2.

### Задача 14: мелкие идиомы

**Files:**
- Modify: `src/ranges.rs` (`pick` :217-238), `src/ranges6.rs` (`pick` :190-211, `format_ipv6_c` :280-318),
  `src/throttle.rs` (:55, :69, :116, :140, :150-155), `src/scan.rs` (кортежи границ :125-148, :190-216; `format_list_line*`
  :63-81), `src/probe.rs` (`Builder.payloads`, `for_each_probe_nic_with_payloads` :500-510)

**Interfaces:**
- `RangeList::pick`, `Range6List::pick`: `mid = picker.partition_point(|&p| u64::from(p) <= index) - 1` (`picker[0] == 0`)
  — тот же `mid` и для индексов за концом (последний диапазон, как сейчас).
- `Throttler`: `index: u8` с `wrapping_add(1)` (та же последовательность корзин, что `u32 & 0xFF`: 2^32 кратно 256);
  дробление сна `Option<NonZeroU64>` вместо `u64::MAX` в `next_batch_impl`; `SystemClock::now_micros` —
  `u64::try_from(..as_micros()).unwrap_or(u64::MAX)`.
- `scan.rs`: приватная `struct Bounds { start: u64, end: u64, increment: u64 }` у `list_bounds` и внутренней части
  `transmit_bounds`; pub `transmit_bounds` возвращает прежний кортеж.
- `Builder` без поля `payloads`; `fill(&self, payloads: &PayloadTable, ..)`; `for_each_probe_nic_with_payloads` отдаёт
  свою `&PayloadTable` без `Arc::new(payloads.clone())`, курсор — `&inner.payloads`.
- Аддитивно: `pub struct CIpv6(pub u128)` с `Display` (текст `format_ipv6_c`) в `ranges6.rs`; `pub struct ListLine { pub
  target: TargetIp, pub port: u32, pub single_port: bool }` с `Display` (текст `format_list_line_v46`) в `scan.rs`;
  старые функции зовут их, вызывающие (CLI, вывод движка) переходят в фазе 2.

- [ ] **Step 1: тесты.** `pick_partition_point_equals_old_search` (юнит `ranges.rs` и `ranges6.rs`, копия старого цикла):
  случайные списки 1..64 диапазонов, все индексы меньше суммы и ещё 3 за концом; `cipv6_display_equals_format_ipv6_c`
  (векторы тестов `ranges6.rs` и 10 000 случайных u128 против копии старой функции); `list_line_display_equals_format`.
  FAIL (нет `CIpv6`, `ListLine`).
- [ ] **Step 2:** реализация; **PASS** G-core (тесты `throttle.rs` с поддельными часами, `scan.rs`, дайджесты), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `refactor(rmasscan-core): partition_point picks, typed throttle state, Display
  wrappers`.
- [ ] **Step 4:** G-mac, G-bench (`pick` идёт дважды на зонд); запись.

### Задача 15: исключения IPv6 без квадратичной работы

**Files:**
- Modify: `src/ranges6.rs` (`remove_range` :220-260)

**Interfaces:**
- `Range6List::apply_excludes` (pub) прежняя. Приватная `remove_range` без `Vec::remove(i)` в цикле, с прежними правилами:
  сначала усечение, потом `add` верхней половины (она сливается с последним элементом списка или встаёт в конец и
  просматривается тем же проходом), пустая половина у `::` и у `ffff:…:ffff` не создаётся. Ловушка: «последний элемент»
  для `add` — последний живой элемент, а не удалённый, который ещё лежит в буфере при уплотнении.
- Если точная линейная версия не сходится с эталоном, правка не вводится: задача коммитит только тесты, решение — в
  сообщение коммита.

- [ ] **Step 1: тесты.** `remove_range_matches_reference` (proptest, юнит `ranges6.rs`, копия старых `remove_range` и
  `apply_excludes`): 1..200 целей (с `::` и `ffff:…:ffff` на краях), 1..300 исключений, в том числе перекрывающихся —
  содержимое списка и возвращённое число равны. `many_ipv6_excludes_time` (`#[ignore]`, только печать: 20 000 целей ×
  20 000 исключений, время).
- [ ] **Step 2:** реализация; **PASS** G-core (тесты `ranges6.rs`, `tests/selftest_parity.rs`, корпус `ranges6`),
  `many_ipv6_excludes_time` до и после — в сообщение коммита.
- [ ] **Step 3:** G-frozen; **коммит** `perf(rmasscan-core): IPv6 excludes in linear time`. Замера стенда нет: это
  время конфигурации.

### Задача 16: разбор нагрузок без курсоров C

**Files:**
- Modify: `src/payloads.rs` (`at`/`asn1_*` :85-155 и `snmp_set_cookie` :157-…, разбор файла `load_nmap_payloads_bytes`
  :886-946 и `trim` :1001-1007 с `Vec::drain` как курсором, `parse_ports_prefix` :1040 с `Result<_, ()>`)

**Interfaces:**
- Produces (приватно): `asn1_tag`, `asn1_length`, `asn1_integer` над срезом с возвратом `Option<(значение, смещение)>`
  вместо `&mut offset` и сторожа `0xFFFF_FFFF`. Сторож сейчас работает как число: `offset += community_len` уводит за
  конец, следующий тег читает 0, и функция выходит. С `Option` выход ранний в тех же точках — байты нагрузки после
  мутации те же. Курсоры по файлу — срезы (`split_at`, `strip_prefix`), а не `drain`; `parse_ports_prefix` возвращает
  `Option<(Vec<(u32, u32)>, usize)>`. Тексты `PayloadError` прежние.

- [ ] **Step 1:** тест `snmp_cookie_matches_old_helpers` (proptest, юнит `payloads.rs`, копия старых `asn1_*` и
  `snmp_set_cookie`): мутированные и обрезанные нагрузки 161 и случайные 0..64 байт × seqno → байты равны. RED — временно
  убрать один ранний выход.
- [ ] **Step 2:** реализация; **PASS** G-core (тесты `payloads.rs` с файлами nmap и pcap, векторы `udp_c_vectors.rs`,
  `tests/echo_golden.rs`, корпуса `nmap` и `snmp`), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `refactor(rmasscan-core): payload parsers on slices, ASN.1 helpers return Option`.

### Задача 17: один разборщик портов и разбор целей срезами

**Files:**
- Modify: `src/targets.rs` (разборщики :38-420, `strtoul0` :425, разбор портов :383-474 и `parse_ports_with` :502-600),
  `src/payloads.rs` (`parse_ports_prefix` :1040-1097 зовёт общий разборщик)

**Interfaces:**
- Produces (`pub(crate)` в `targets.rs`): `enum PortListEnd { StopAtNonPort, Error }` и
  `fn tokenize_ports(s: &[u8], end: PortListEnd) -> Result<(Vec<(u32, u32)>, usize), ParseError>` — одна реализация для
  `--nmap-payloads` (стоп на первом не-порте, возвращает длину разобранного) и `-p` (ошибка); оба документированных
  отличия от C сохраняются, в режиме `StopAtNonPort` отказы те же, что у нынешнего `parse_ports_prefix`.
  `fn strtoul0(s: &[u8]) -> (u64, &[u8])` (значение и остаток вместо `&mut pos`).
  `parse_ipv4(line: &[u8]) -> Option<(u32, &[u8])>`, `parse_range_at(buf: &[u8]) -> Result<(Range, &[u8]), ParseError>` —
  срезы вместо `while offset < max && line[offset] …`. Смещения в ошибках (`not_ipv4` и др.) считаются как
  `buf.len() - rest.len()` и совпадают с нынешними. Pub-функции (`range_parse_ipv4`, `add_target_string*`,
  `parse_ports*`, `add_top_ports`) прежние.

- [ ] **Step 1:** корпуса `targets`, `ports`, `nmap` (задача 0) — главный тест; плюс `tokenize_ports_modes_agree_on_ports`
  (proptest, юнит `targets.rs`): на строках только из портов оба режима дают одни и те же пары.
- [ ] **Step 2:** реализация; **PASS** G-core (`tests/echo_golden.rs`, `tests/scan_golden.rs`, `tests/selftest_parity.rs`,
  `tests/proptest_order.rs`, тесты `targets.rs` и `payloads.rs`, корпуса), G-ws.
- [ ] **Step 3:** G-frozen; **коммит** `refactor(rmasscan-core): one port tokenizer and slice-based target parsers`.

### Завершение ветки

- [ ] G-core, G-ws, G-frozen на вершине; `git diff --stat $BASE -- rmasscan/tests/golden` пуст; дайджесты задачи 0 без
  правок с момента записи (`git log --format=%h $BASE.. -- rmasscan/crates/rmasscan-core/tests/native_digests.rs` — один
  коммит); таблица `BENCHMARKS.md` содержит строку каждой задачи на скорость; `rmasscan/target` нет; свои процессы
  остановлены. Push и PR — по согласию пользователя.
