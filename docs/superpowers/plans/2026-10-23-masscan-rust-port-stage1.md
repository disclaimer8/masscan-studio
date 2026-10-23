# Порт masscan на Rust — этап 1 (ядро генерации) — план реализации

> **Для агентов-исполнителей:** ОБЯЗАТЕЛЬНЫЙ ПОД-НАВЫК: используйте
> superpowers:subagent-driven-development (рекомендуется) или
> superpowers:executing-plans. Шаги помечены чекбоксами (`- [ ]`). Коммиты
> исполнитель делает **только с согласия пользователя**. Этап 1 начинается
> после закрытия критерия выхода этапа 0 (см.
> `2026-10-23-masscan-rust-port-stage0.md`): workspace `rmasscan/`,
> правило «без C», golden-фикстуры готовы.

**Goal:** Реализовать чистое ядро генерации целей и пакетов (`rmasscan-core`)
и тонкий CLI (`rmasscan-cli`) так, чтобы `-sL` и `--echo` побайтово совпадали
с C masscan на матрице §7.2, а порядок transmit и байты SYN были покрыты
юнит-тестами по коду.

**Architecture:** `rmasscan-core` содержит модули `ranges`, `targets`,
`blackrock`, `siphash`, `cookie`, `checksum`, `packet`, `massip`, `scan`,
`throttle`, `config`. Всё — чистая логика без I/O и без сети,
`#![forbid(unsafe_code)]`. `rmasscan-cli` — clap-обёртка, реализующая
операции `-sL`, `--echo`, `--offline --packet-trace`. Проверка — перенос
C-selftests как `#[test]`, дифференциальная сверка с golden-фикстурами
(офлайн) и юнит-тесты transmit-формулы/байтов по коду.

**Tech Stack:** как в этапе 0. Добавляется prod-зависимость `siphasher
=1.0.4` в `rmasscan-core` (Задача 5); `proptest =1.12.0` и `criterion
=0.8.2` — dev.

**Spec:** `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`
(§3 карта, §4 инварианты, §7 проверка, §9 этап 1). Исходники masscan:
`/Users/denyskolomiiets/masscan`, HEAD `8e6b3b0`. **Ожидаемые значения в
тестах берутся из кода masscan и golden-фикстур этапа 0, не из памяти.**

## Global Constraints

Полностью наследуются из этапа 0 (три ОС; без C в графе; `forbid(unsafe_code)`
в core; точные версии; AGPL-3.0 + копирайт Graham в каждом модуле; без сети).
Дополнительно для этапа 1:

- Все целочисленные операции, где C полагается на переполнение `uint64_t`,
  используют `wrapping_*` явно (спека §4.2): иначе порядок целей разойдётся.
- Все тесты задают `--seed` явно; ветка энтропии при `seed == 0` (спека §4.1,
  syn-cookie.c:18) **не переносится** — studio всегда даёт seed.
- Пространство портов сохраняет смещения протоколов (`massip-port.h`: TCP 0,
  UDP +65536, SCTP +131072, ICMP 196608…) как константы, даже что в v1
  принимается только TCP (спека §4.1, §3): это нужно для будущей
  совместимости индексов.
- Источник-порт в тестах фиксируется (`--source-port`), чтобы исключить
  зависимость `40000 + time%20000` (main.c:1316).

## Review Focus

Классы входов, подразумеваемые спекой, но не покрытые happy-path; каждый
закрыт тестом в указанной задаче.

1. Переполнение в BlackRock: `L + READ` и `seed << r` в `uint64_t` (спека
   §4.2, crypto-blackrock.c:171,204). Без `wrapping_*` результат иной →
   весь порядок целей ломается (Задача 3, тест на большом range/seed +
   round-trip).
2. `-sL` считает `end += retries * max_rate`, а transmit — `+= retries *
   range` (спека §4.3; main-listscan.c:35 против main.c:273). Их легко
   перепутать (Задача 8, тест list-scan с `--retries 2`; Задача 9, тест
   transmit-формулы).
3. Исключения применяются **до** `optimize`, меняя `count_ipv4` и все
   индексы (спека §4.3; main.c:1673 до :1684). Применение в другом месте
   сдвинет весь порядок (Задача 2/8, differential с `--exclude`, режущим
   диапазон).
4. Пустой или нулевой range → в BlackRock `a=b=0` и деление на ноль
   (спека §4.2, crypto-blackrock.c:117). Порт обязан отклонять (Задача 10,
   тест валидации; Задача 3, тест `range==0`).
5. Порты с префиксами `U:`/`S:`/`O:`/`I:` и диапазоны >63 бит должны давать
   ошибку, а не молча просчитаться (спека §4.1, §3; main.c:1698). Также CLI
   обязан отклонять неподдерживаемые опции (Задача 2, тесты ошибок парсера;
   Задача 11, тест отклонения опции).

---

## Задача 1: `ranges` — списки диапазонов IPv4/портов

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/ranges.rs`
- Модуль подключить в `lib.rs` (`pub mod ranges;`)

**Interfaces:**
- Produces:
  - `pub struct Range { pub begin: u32, pub end: u32 }` (инклюзивный).
  - `pub struct RangeList { /* отсортированный, слитый список + picker */ }`
  - `RangeList::add_range(&mut self, begin: u32, end: u32)`
  - `RangeList::sort_and_merge(&mut self)` (= rangelist_sort,
    massip-rangesv4.c:258: qsort + слияние перекрытий)
  - `RangeList::count(&self) -> u64` (massip-rangesv4.c:798)
  - `RangeList::optimize(&mut self)` (строит префиксные суммы `picker`,
    massip-rangesv4.c:884)
  - `RangeList::pick(&self, index: u64) -> u32` (бинарный поиск по picker,
    massip-rangesv4.c:839; линейный fallback при отсутствии picker)
  - `RangeList::exclude(&mut self, excludes: &mut RangeList)`
    (massip-rangesv4.c:730; обе стороны сортируются, применяется
    `range_apply_exclude` с возможным split)
  - `RangeList::is_contains(&self, value: u32) -> bool`

Примечание: `end` хранится инклюзивно; `count` = Σ(end−begin+1) как u64,
чтобы 0.0.0.0/0 давал 0x1_0000_0000 (massip-rangesv4.c:804).

- [ ] **Шаг 1: Провальные тесты по C-selftests**

`ranges.rs` `#[cfg(test)]` — перенести утверждения `ranges_selftest`
(massip-rangesv4.c:1234) с теми же входами и ожиданиями:
```rust
#[test]
fn sort_merges_overlapping_ipv4() {
    let mut t = RangeList::new();
    for (b, e) in [(cidr("10.0.0.0/24")), range("10.0.1.10-10.0.1.19"),
                   range("10.0.1.20-10.0.1.30"), range("10.0.0.0-10.0.1.12")] {
        t.add_range(b, e);
    }
    t.sort_and_merge();
    assert_eq!(t.len(), 1);
    assert_eq!(t.get(0), Range { begin: 0x0a00_0000, end: 0x0a00_0100 + 30 });
}

#[test]
fn pick_reproduces_sorted_list() { /* regress_pick2, massip-rangesv4.c:931:
    случайные списки (LCG a=214013,c=2531011), optimize+pick воспроизводят
    отсортированный список */ }

#[test]
fn exclude_matches_reference_algorithm() { /* exclude_selftest,
    massip-rangesv4.c:1154: includes1/excludes из LCG seed 0 и 1,
    exclude() даёт тот же результат, что эталонный remove-range */ }
```
Хелперы `cidr(...)`/`range(...)` опираются на `targets::range_parse_ipv4`
(Задача 2); до неё — захардкодить `Range { begin, end }` числами из
C-теста (massip-rangesv4.c:1287–1298).

- [ ] **Шаг 2: Убедиться, что тесты падают** — `cargo test -p rmasscan-core ranges`, ожидается FAIL (нет реализации).

- [ ] **Шаг 3: Реализовать `ranges.rs`** по massip-rangesv4.c: `add_range`
  (:310 с авто-слиянием хвоста), `sort_and_merge` (:258), `count` (:798),
  `optimize` (:884), `pick`/линейный fallback (:839,:820),
  `range_apply_exclude` (:674) и `exclude` (:730), `is_contains`. Все
  арифметические переполнения на границе 0xFFFFFFFF считать в `u64` и
  сворачивать, как в C.

- [ ] **Шаг 4: Тесты проходят** — `cargo test -p rmasscan-core ranges`, PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): IPv4/port range lists (ranges.rs)`.

---

## Задача 2: `targets` — парсинг целей и портов из командной строки

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/targets.rs`

**Interfaces:**
- Consumes: `ranges::{Range, RangeList}`.
- Produces:
  - `pub fn range_parse_ipv4(line: &str) -> Result<Range, ParseError>`
    (massip-rangesv4.c:533: одиночный `a.b.c.d`, CIDR `.../N`, дефис-диапазон
    `a-b`; невалид → ошибка, не 0xFFFFFFFF-«badrange»)
  - `pub fn add_target_string(targets: &mut RangeList, s: &str) ->
    Result<(), ParseError>` (massip.c:72: IPv4-диапазоны через запятую/пробел;
    IPv6 → ошибка `Ipv6NotSupported`, спека §3 отложено)
  - `pub fn parse_ports(ports: &mut RangeList, s: &str) ->
    Result<(), ParseError>` (massip-rangesv4.c:993: `80`, `1000-2000`,
    `-1024`, `80-`; префикс `T:` или без префикса → TCP; `U:`/`S:`/`O:`/`I:`
    → ошибка `UnsupportedProtoPrefix`, спека §3/§4.1; диапазоны вне
    0..=65535 или end<begin → ошибка)
  - `pub enum ParseError { BadIpv4, BadPort, Ipv6NotSupported,
    UnsupportedProtoPrefix, ... }` (через `thiserror`)
  - Константы смещений протоколов `pub const TEMPL_TCP: u32 = 0;` …
    `TEMPL_UDP = 65536` … из `massip-port.h` (сохранить для будущего).

- [ ] **Шаг 1: Провальные тесты по C-selftest и коду парсера**

Перенести `selftest_massip_parse_range` (massip-parse.c:1112, IPv4-случаи):
```rust
#[test]
fn parse_ipv4_single_cidr_dash() {
    assert_eq!(range_parse_ipv4("192.168.1.3").unwrap(),
               Range { begin: 0xc0a8_0103, end: 0xc0a8_0103 });
    assert_eq!(range_parse_ipv4("10.0.1.2/16").unwrap(),
               Range { begin: 0x0a00_0000, end: 0x0a00_ffff });
    assert_eq!(range_parse_ipv4("10.0.0.20-10.0.0.30").unwrap(),
               Range { begin: 0x0a00_0000 + 20, end: 0x0a00_0000 + 30 });
    assert_eq!(range_parse_ipv4("0.0.0.0/0").unwrap(),
               Range { begin: 0, end: 0xffff_ffff });
}

#[test]
fn parse_ipv4_rejects_bad_octets() {
    for bad in ["75.748.86.91", "23.75.345.200", "192.1083.0.1", "0.0.0./0"] {
        assert!(range_parse_ipv4(bad).is_err());
    }
}

#[test]
fn parse_ports_tcp_and_rejects_other_protos() {
    let mut p = RangeList::new();
    parse_ports(&mut p, "80,1000-2000,1234,4444").unwrap();
    p.sort_and_merge();
    assert_eq!(p.len(), 3);
    assert_eq!(p.get(0), Range { begin: 80, end: 80 });
    assert_eq!(p.get(1), Range { begin: 1000, end: 2000 });
    // Review Focus №5: не-TCP префиксы отклоняются
    assert!(parse_ports(&mut RangeList::new(), "U:53").is_err());
    assert!(parse_ports(&mut RangeList::new(), "70000").is_err());
}
```
Также тест `add_target_string` на `"0.0.1.0/24,0.0.3.0-0.0.4.0"` →
две записи `{0x100,0x1ff}` и `{0x300,0x400}` (massip-parse.c:1121), и на
`"1::1"` → `Err(Ipv6NotSupported)`.

- [ ] **Шаг 2: Тесты падают** — `cargo test -p rmasscan-core targets`, FAIL.

- [ ] **Шаг 3: Реализовать `targets.rs`** по massip-rangesv4.c:470 (parse_ipv4),
  :533 (range_parse_ipv4), massip.c:72 (add_target_string, разделители
  запятая/пробел — massip.c:96), massip-rangesv4.c:993 (parse_ports, разбор
  префиксов :1016, nmap-стиль `-N`/`N-` :1044,:1056, проверка границ :1067).
  IPv6-ветки добавляются как `Err(Ipv6NotSupported)`.

- [ ] **Шаг 4: Тесты проходят** — `cargo test -p rmasscan-core targets`, PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): command-line target/port parsing (targets.rs)`.

---

## Задача 3: `blackrock` — перестановка Фейстеля

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/blackrock.rs`

**Interfaces:**
- Produces:
  - `pub struct BlackRock { a: u64, b: u64, rounds: u32, seed: u64, range: u64 }`
  - `pub fn BlackRock::new(range: u64, seed: u64, rounds: u32) -> BlackRock`
    (crypto-blackrock.c:108; табличные a,b для range ≤ 8 :116; иначе
    `a=floor(sqrt(range)-2)`, `b=floor(sqrt(range)+3)`, затем `while a*b<=range
    { b+=1 }` :146–151)
  - `pub fn BlackRock::shuffle(&self, m: u64) -> u64` (cycle-walking :268)
  - `pub fn BlackRock::unshuffle(&self, m: u64) -> u64` (:282)
  - Константа `SBOX: [u8; 256]` из crypto-blackrock.c:68.

Реализация внутренних `READ`/`ENCRYPT`/`UNENCRYPT` — приватные функции по
crypto-blackrock.c:164/192/220. Переполнения: `seed << r` и `seed >> (64−r)`,
`L + READ`, `r2<<23 ^ r3<<33` — через `wrapping_shl`/`wrapping_add`
(спека §4.2; Review Focus №1). `rounds >= 64` отклонять (паника/ошибка в
`new`). `range == 0` → `new` возвращает ошибку или паникует (Review Focus №4;
вызывающий код в §scan обязан не допускать пустой range).

- [ ] **Шаг 1: Провальные тесты по blackrock_selftest**

Перенести crypto-blackrock.c:373 с фиксированным seed (в C `time(0)`,
спека §7.4 требует фикс):
```rust
#[test]
fn shuffle_unshuffle_round_trip() {
    let br = BlackRock::new(1000, 0, 4);
    for i in 0..10u64 { assert_eq!(br.unshuffle(br.shuffle(i)), i); }
}

#[test]
fn shuffle_is_a_permutation() {
    // blackrock_verify, crypto-blackrock.c:298: каждый выход встречается ровно раз
    for seed in [1u64, 2, 42] {
        for &range in &[6056u64, 6074, 6094] { // (3015*3+10..)*2 как в :401
            let br = BlackRock::new(range, seed, 4);
            let mut seen = vec![0u8; range as usize];
            for i in 0..range { seen[br.shuffle(i) as usize] += 1; }
            assert!(seen.iter().all(|&c| c == 1));
        }
    }
}

#[test]
fn no_overflow_panic_on_large_range_and_rounds14() {
    // Review Focus №1: wrapping-арифметика не паникует и остаётся перестановкой
    let br = BlackRock::new(1_000_003, 0xdead_beef_cafe, 14);
    let x = br.shuffle(123_456);
    assert!(x < 1_000_003);
    assert_eq!(br.unshuffle(x), 123_456);
}
```

- [ ] **Шаг 2: Тесты падают** — `cargo test -p rmasscan-core blackrock`, FAIL.

- [ ] **Шаг 3: Реализовать `blackrock.rs`** дословно по crypto-blackrock.c
  (SBOX :68, new :108, READ :164, ENCRYPT :192, UNENCRYPT :220, shuffle :268,
  unshuffle :282), с явными `wrapping_*`.

- [ ] **Шаг 4: Тесты проходят** — PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): BlackRock permutation (blackrock.rs)`.

---

## Задача 4: `checksum` — контрольные суммы RFC 1071

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/checksum.rs`

**Interfaces:**
- Produces:
  - `pub fn ip_header_checksum(px: &[u8], offset_ip: usize, max: usize) -> u16`
    (частичная сумма без инверсии, templ-pkt.c:184)
  - `pub fn checksum_ipv4(ip_src: u32, ip_dst: u32, ip_proto: u8,
    payload: &[u8]) -> u16` (util-checksum.c:74, с псевдо-заголовком и
    вычетом текущего поля checksum по `ip_proto`)
  - `pub fn fold_and_invert(sum: u32) -> u16` (util-checksum.c:62)

- [ ] **Шаг 1: Провальные тесты по checksum_selftest (IPv4-векторы)**

util-checksum.c:165, три вектора (значения из кода, не из памяти):
```rust
#[test]
fn checksum_ipv4_reference_vectors() {
    // IGMP, proto 2
    assert_eq!(checksum_ipv4(0x0a14_1e01, 0xe000_0001, 2,
        &hex("1164ee9b00000000")), 0xee9b);
    // UDP, proto 17
    assert_eq!(checksum_ipv4(0x0a14_1ec9, 0xadc2_900a, 17,
        &hex("dc1301bb00296042 5bd6163ab1783d5d dd0e5a0535749291 574caac18576c00f 8d9e19a5cca28165be")), 0x6042);
    // TCP, proto 6
    assert_eq!(checksum_ipv4(0x0a14_1ec9, 0xa2fe_c14a, 6,
        &hex("7e7069951fb977c6 ee097b7250 1803fd 84b20000 1703030 ...")), 0x84b2);
}
```
(Полные буферы — из util-checksum.c:166–185; `hex()` — тест-хелпер.)

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать** по util-checksum.c:23 (`_checksum_calculate`),
  :62 (`_checksum_finish`), :74 (`checksum_ipv4`), templ-pkt.c:184
  (`ip_header_checksum`).

- [ ] **Шаг 4: Тесты проходят** — PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): RFC1071 checksums (checksum.rs)`.

---

## Задача 5: `siphash` и `cookie` — SYN-cookie

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/cookie.rs`
- Modify: `rmasscan/crates/rmasscan-core/Cargo.toml` (добавить `siphasher.workspace = true`)

**Interfaces:**
- Produces:
  - `pub fn siphash24(data: &[u8], k0: u64, k1: u64) -> u64` — через
    `siphasher::sip::SipHasher24::new_with_keys(k0, k1)` + `Hasher::write` +
    `finish` (API подтверждён по docs.rs/siphasher/1.0.2).
  - `pub fn syn_cookie_ipv4(ip_them: u32, port_them: u16, ip_me: u32,
    port_me: u16, entropy: u64) -> u64` (syn-cookie.c:135: `data = [ip_them,
    port_them, ip_me, port_me]` как 4×u32, ключ `[entropy, entropy]`).
  - Сериализация: каждое из 4 значений — `u32::to_le_bytes` (спека §4.4:
    порядок байтов хоста = LE на всех трёх целевых платформах, но пишется
    явно).

- [ ] **Шаг 1: Провальные тесты**

Векторы SipHash-2-4 (crypto-siphash24.c:151, значения из кода):
```rust
#[test]
fn siphash24_reference_vectors() {
    // k = 00 01 .. 0f  →  k0 = 0x0706050403020100, k1 = 0x0f0e0d0c0b0a0908
    let (k0, k1) = (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908);
    // in = "" → 31 0e 0e dd 47 db 6f 72 (LE) = 0x726f_db47_dd0e_0e31
    assert_eq!(siphash24(&[], k0, k1), 0x726f_db47_dd0e_0e31);
    // in = 00 (1 байт) → fd 67 dc 93 c5 39 f8 74 (LE)
    assert_eq!(siphash24(&[0x00], k0, k1), 0x74f8_39c5_93dc_67fd);
}

#[test]
fn syn_cookie_assembles_four_u32_le() {
    // Согласованность с siphasher над вручную собранными 16 байтами
    let (ip_them, port_them, ip_me, port_me, e) = (0x0102_0304u32, 80u16, 0x0a00_0001u32, 40000u16, 42u64);
    let mut buf = Vec::new();
    buf.extend_from_slice(&ip_them.to_le_bytes());
    buf.extend_from_slice(&(port_them as u32).to_le_bytes());
    buf.extend_from_slice(&ip_me.to_le_bytes());
    buf.extend_from_slice(&(port_me as u32).to_le_bytes());
    assert_eq!(syn_cookie_ipv4(ip_them, port_them, ip_me, port_me, e),
               siphash24(&buf, e, e));
}
```
(Второй вектор `0x74f8...` — перестановка байтов crypto-siphash24.c:154
в LE-u64; исполнитель проверяет по таблице vectors[].)

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать `cookie.rs`** через `siphasher`. Данные syn_cookie
  — `data[0]=ip_them, data[1]=port_them, data[2]=ip_me, data[3]=port_me` как
  `u32`, каждое `to_le_bytes` (syn-cookie.c:145). Усечение до `u32` при
  передаче в шаблон делает вызывающий код (Задача 7/9).

- [ ] **Шаг 4: Тесты проходят** — PASS. Прогнать `cargo deny check licenses`
  (siphasher MIT/Apache — должен пройти).

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): SipHash-2-4 and SYN cookie (cookie.rs)`.

---

## Задача 6: `massip` — объединение целей и портов, pick по индексу

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/massip.rs`

**Interfaces:**
- Consumes: `ranges::RangeList`.
- Produces:
  - `pub struct MassIp { pub ipv4: RangeList, pub ports: RangeList,
    count_ports: u64, count_ipv4s: u64, ipv4_index_threshold: u64 }`
    (IPv6-поля опущены — отложено, спека §3; смещение в счёте индексов
    сохраняется тем, что IPv6 count = 0)
  - `MassIp::apply_excludes(&mut self, exclude: &mut MassIp)` (massip.c:8:
    excludes к ipv4 и к ports) — **вызывается до optimize** (Review Focus №3)
  - `MassIp::optimize(&mut self)` (massip.c:15: sort+optimize ipv4 и ports,
    затем `count_ports`, `count_ipv4s`, `ipv4_index_threshold =
    count_ipv4s * count_ports`)
  - `MassIp::range(&self) -> u64` (= count_ipv4s * count_ports для v1;
    massip.h:36 / main.c:258 без IPv6)
  - `MassIp::pick(&self, index: u64) -> (u32 /*ipv4*/, u32 /*port*/)`
    (massip.c:27: `ip = ipv4.pick(index % count_ipv4s)`,
    `port = ports.pick(index / count_ipv4s)`)

- [ ] **Шаг 1: Провальный тест (IPv4-аналог massip_selftest)**

C-тест massip.c:112 использует IPv6; строим IPv4-эквивалент с ручным счётом:
```rust
#[test]
fn excludes_then_optimize_change_counts_and_pick() {
    let mut t = MassIp::new();
    targets::add_target_string(&mut t.ipv4, "10.0.0.0/30").unwrap(); // 4 адреса
    targets::parse_ports(&mut t.ports, "80,443").unwrap();           // 2 порта
    let mut ex = MassIp::new();
    targets::add_target_string(&mut ex.ipv4, "10.0.0.1-10.0.0.2").unwrap();
    t.apply_excludes(&mut ex);   // остаётся 10.0.0.0 и 10.0.0.3 → 2 адреса
    t.optimize();
    assert_eq!(t.range(), 2 * 2); // Review Focus №3: count_ipv4 изменился до 4-х pick
    // индекс 0 → (10.0.0.0, 80); индекс раскладывается ip=idx%2, port=idx/2
    let (ip, port) = t.pick(0);
    assert_eq!((ip, port), (0x0a00_0000, 80));
    let (ip3, _) = t.pick(1);
    assert_eq!(ip3, 0x0a00_0003);
}
```

- [ ] **Шаг 2: Тест падает** — FAIL.

- [ ] **Шаг 3: Реализовать `massip.rs`** по massip.c:8/15/27. `range()` без
  IPv6-слагаемого; порядок «apply_excludes → optimize» зафиксирован типом
  (optimize пересчитывает counts).

- [ ] **Шаг 4: Тест проходит** — PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): MassIp target space and pick (massip.rs)`.

---

## Задача 7: `packet` — шаблон TCP SYN и заполнение целей

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/packet.rs`

**Interfaces:**
- Consumes: `checksum`, `cookie`.
- Produces:
  - `pub enum LinkType { Ethernet, Null, Raw }` (DLT 1/0/12, спека §4.8)
  - `pub struct TcpSynTemplate { /* готовый шаблон + смещения + частичные суммы */ }`
  - `TcpSynTemplate::new(source_mac: [u8;6], router_mac: [u8;6],
    link: LinkType) -> Self` (templ-pkt.c:1218 `_template_init` для TCP;
    DLT_NULL/RAW-подрезка :1342; частичная IP-сумма :1293, частичная TCP
    :1319)
  - `TcpSynTemplate::build_syn(&self, ip_them: u32, port_them: u16,
    ip_me: u32, port_me: u16, seqno: u32, out: &mut Vec<u8>)`
    (templ-pkt.c:877 `template_set_target_ipv4`, ветка Proto_TCP:
    `ip_id = ip_them ^ port_them ^ seqno` :942; IP-checksum :988; TCP-порты,
    seqno :1000; инкрементальная TCP-сумма от `checksum_tcp` :1009)
  - Константа `DEFAULT_TCP_TEMPLATE: &[u8]` — байты templ-pkt.c:30
    (Ethernet 14 + IP 20 + TCP 20 + MSS-опция `02 04 05 b4`, итого 58).

- [ ] **Шаг 1: Провальные тесты байтов (спека §7.3) + template_selftest**

MAC как в template_selftest (templ-pkt.c:1541): source `00-11-22-33-44-55`,
router `66-55-44-33-22-11`.
```rust
#[test]
fn syn_frame_fixed_fields() {
    let t = TcpSynTemplate::new(hex6("001122334455"), hex6("665544332211"), LinkType::Ethernet);
    let mut f = Vec::new();
    t.build_syn(0x0a00_0001, 80, 0xc0a8_0101, 40000, 0x1234_5678, &mut f);
    assert_eq!(f.len(), 58);
    assert_eq!(&f[0..6], &hex6("665544332211"));   // dst mac = router
    assert_eq!(&f[6..12], &hex6("001122334455"));  // src mac
    assert_eq!(&f[12..14], &[0x08, 0x00]);         // ethertype IPv4
    assert_eq!(f[14], 0x45);                        // version/IHL
    assert_eq!(f[22], 0xff); assert_eq!(f[23], 0x06); // TTL=255, proto=TCP
    // ip_id = ip_them ^ port_them ^ seqno (усечённо до 16 бит в поле)
    let ip_id = (0x0a00_0001u32 ^ 80 ^ 0x1234_5678) as u16;
    assert_eq!(&f[18..20], &ip_id.to_be_bytes());
    // адреса, порты, seqno
    assert_eq!(&f[26..30], &0xc0a8_0101u32.to_be_bytes()); // src ip
    assert_eq!(&f[30..34], &0x0a00_0001u32.to_be_bytes()); // dst ip
    assert_eq!(&f[34..36], &40000u16.to_be_bytes());       // src port
    assert_eq!(&f[36..38], &80u16.to_be_bytes());          // dst port
    assert_eq!(&f[38..42], &0x1234_5678u32.to_be_bytes()); // seqno
    assert_eq!(f[46], 0x60); assert_eq!(f[47], 0x02);      // data offset, SYN
    assert_eq!(&f[48..50], &[0x04, 0x01]);                 // window 1024
    assert_eq!(&f[54..58], &[0x02, 0x04, 0x05, 0xb4]);     // MSS 1460
}

#[test]
fn syn_frame_checksums_validate() {
    // IP-заголовок суммируется в 0xFFFF, TCP-сумма валидна (независимый RFC1071)
    let t = TcpSynTemplate::new(hex6("001122334455"), hex6("665544332211"), LinkType::Ethernet);
    let mut f = Vec::new();
    t.build_syn(0x0808_0808, 443, 0x0a00_0002, 12345, 0xdead_beef, &mut f);
    assert_eq!(checksum::ip_header_checksum(&f, 14, 34) & 0xffff, 0xffff);
    // TCP: пересобрать сумму независимо и сверить с полем f[50..52]
    assert!(packet::tcp_checksum_is_valid(&f));
}

#[test]
fn template_proto_detection() {
    // template_selftest, templ-pkt.c:1524: TCP-шаблон распознан как TCP
    let t = TcpSynTemplate::new(hex6("001122334455"), hex6("665544332211"), LinkType::Ethernet);
    assert_eq!(t.proto_is_tcp(), true);
}
```

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать `packet.rs`** по templ-pkt.c: константа шаблона
  :30; `new` разбирает смещения (для TCP IPv4 они фиксированы: offset_ip=14,
  offset_tcp=34, offset_app=58 при Ethernet) и считает частичные суммы
  (:1293 ip, :1319 tcp через tcp_ipv4_checksum templ-pkt.c:243); `build_syn`
  :942–1021. DLT_NULL: 4-байтовый AF_INET-заголовок вместо Ethernet
  (:1342), offset_ip=4; DLT_RAW: без заголовка, offset_ip=0 (:1352).

- [ ] **Шаг 4: Тесты проходят** — PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): TCP SYN packet template (packet.rs)`.

---

## Задача 8: `scan` — генератор порядка (-sL и transmit)

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/scan.rs`

**Interfaces:**
- Consumes: `massip::MassIp`, `blackrock::BlackRock`.
- Produces:
  - `pub struct Shard { pub one: u32, pub of: u32 }` (по умолчанию 1/1)
  - `pub fn list_scan_indices(range: u64, shard: Shard, resume_index: u64,
    resume_count: Option<u64>, retries: u32, max_rate: u64) ->
    impl Iterator<Item = u64>` — **пред-shuffle** индексы `i` для `-sL`:
    `start = resume_index + (shard.one as u64 - 1)`, `end = range`, при
    `resume_count` `end = min(end, start+count)`, `end += retries * max_rate`
    (main-listscan.c:31–35), шаг `increment = shard.of` (main-listscan.c:14).
    (Review Focus №2.)
  - `pub fn transmit_index_stream(range: u64, shard: Shard, nic_count: u64,
    nic_index: u64, resume_index: u64, resume_count: Option<u64>,
    retries: u32, max_rate: u64) -> impl Iterator<Item = u64>` —
    **пред-shuffle** `xXx = (i + r*rate) mod range` для transmit: r бежит
    `retries+1 .. 1` на каждой позиции `i`, `i += shard.of*nic_count` после
    `r==0`; `start = resume_index + (shard.one-1)*nic_count + nic_index`,
    `end = range`, `+= retries*range` (main.c:269–334,:421). Понижение `mod`:
    если `rate > range` — `%`, иначе вычитание в цикле (main.c:329–333).
  - `pub fn list_scan<F: FnMut(u32,u32)>(massip: &MassIp, seed: u64,
    rounds: u32, shard: Shard, resume_index: u64, resume_count: Option<u64>,
    retries: u32, max_rate: u64, emit: F)` — для каждого индекса `i`:
    `xXx = blackrock.shuffle(i)`, `(ip, port) = massip.pick(xXx)`, `emit`.
    (main-listscan.c:42–63.)

Валидация: `range == 0` → ошибка до создания BlackRock (Review Focus №4).

- [ ] **Шаг 1: Провальные юнит-тесты transmit-формулы (спека §7.2 п2)**

Ручные значения на малых range (пред-shuffle, без BlackRock):
```rust
#[test]
fn transmit_stream_retries0_offsets_by_rate() {
    // range=10, rate=3, retries=0, shard 1/1, nic 1/0:
    // (i+3) mod 10 для i=0..9
    let got: Vec<u64> = transmit_index_stream(10, Shard{one:1,of:1}, 1, 0, 0, None, 0, 3).collect();
    assert_eq!(got, vec![3,4,5,6,7,8,9,0,1,2]);
}

#[test]
fn transmit_stream_retries2_three_offsets_per_index() {
    // range=10, rate=1, retries=2: на i эмитятся (i+3),(i+2),(i+1) mod 10;
    // end += retries*range = 10 + 20 = 30 позиций i, на каждой retries+1 = 3
    // отправки (r: 3→0, i += increment только при r == 0, main.c:213, :424–427),
    // итого 30 * 3 = 90 значений
    let got: Vec<u64> = transmit_index_stream(10, Shard{one:1,of:1}, 1, 0, 0, None, 2, 1).collect();
    assert_eq!(&got[0..3], &[3u64,2,1]);      // i=0
    assert_eq!(&got[3..6], &[4u64,3,2]);      // i=1
    assert_eq!(&got[87..90], &[2u64,1,0]);    // i=29: (29+3,29+2,29+1) mod 10
    assert_eq!(got.len(), 90);
}

#[test]
fn list_scan_indices_retries_use_max_rate_not_range() {
    // Review Focus №2: -sL end += retries*max_rate
    let n = list_scan_indices(10, Shard{one:1,of:1}, 0, None, 2, 5).count();
    assert_eq!(n, 10 + 2*5); // 20, НЕ 10+2*10
}

#[test]
fn shard_2_of_3_steps_by_three() {
    let got: Vec<u64> = list_scan_indices(9, Shard{one:2,of:3}, 0, None, 0, 100).collect();
    assert_eq!(got, vec![1,4,7]); // start = 0 + (2-1) = 1, шаг 3
}
```

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать `scan.rs`** по main-listscan.c и main.c:203–448.

- [ ] **Шаг 4: Тесты проходят** — PASS.

- [ ] **Шаг 5: Дифференциальный тест `-sL` против golden (спека §7.2 п1)**

Тест читает `tests/golden/manifest.json`, для каждой записи `mode == "-sL"`
прогоняет `list_scan` с теми же аргументами и сверяет построчно вывод с
`tests/golden/listscan/<file>`:
```rust
#[test]
fn list_scan_matches_c_oracle_fixtures() {
    let manifest = load_manifest("tests/golden/manifest.json"); // падает, если нет (Review Focus №3)
    for case in manifest.cases.iter().filter(|c| c.mode == "-sL") {
        let expected = std::fs::read_to_string(golden_path(&case.file)).unwrap();
        let got = run_list_scan_to_string(&case.args);
        assert_eq!(got, expected, "расхождение -sL на {:?}", case.args);
    }
}
```
Форматирование строки — через `cli` (Задача 11) или прямой хелпер `ip` /
`ip:port` (main-listscan.c:53–62): при одном порте печатается только IP.

- [ ] **Шаг 6 (коммит, с согласия):** `feat(core): scan ordering + differential -sL vs oracle (scan.rs)`.

---

## Задача 9: `throttle` — троттлер с инъецируемыми часами

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/throttle.rs`

**Interfaces:**
- Produces:
  - `pub trait Clock { fn now_micros(&self) -> u64; }` (для теста — фиктивные
    часы; в проде — обёртка `std::time::Instant`, спека §4.5)
  - `pub struct Throttler { buckets: [(u64,u64); 256], index: usize,
    batch_size: f64, max_rate: f64, current_rate: f64 }`
  - `Throttler::start(max_rate: f64, clock: &impl Clock) -> Self`
    (main-throttle.c:28: все корзины = now, batch_size=1)
  - `Throttler::next_batch(&mut self, packet_count: u64, clock: &impl Clock)
    -> u64` (main-throttle.c:58: корзина −256, разрыв >1с → batch_size=1 и
    повтор :90; при превышении — ожидание `0.1*(rate−max)/max` с потолком
    0.1с и `batch_size*=0.999` :109; иначе `*=1.005`, потолок 10000 :155).

Ожидание в тесте не «спит»: `Clock` подменяется, `next_batch` при
необходимости продвигает фиктивное время (сон заменяется продвижением
часов в тестовой реализации Clock).

- [ ] **Шаг 1: Провальные тесты с фиктивными часами**

```rust
#[test]
fn batch_size_is_one_at_low_rate() {
    let mut c = FakeClock::new();
    let mut t = Throttler::start(100.0, &c);
    c.advance_micros(10_000); // 10ms
    assert_eq!(t.next_batch(1, &c), 1);
}

#[test]
fn gap_over_one_second_resets_batch_to_one() {
    // main-throttle.c:90: timestamp - old > 1_000_000 → batch_size=1
    let mut c = FakeClock::new();
    let mut t = Throttler::start(1_000_000.0, &c);
    c.advance_micros(2_000_000);
    assert_eq!(t.next_batch(5_000_000, &c), 1);
}

#[test]
fn batch_size_grows_under_high_rate() {
    // при нагрузке >100k pps batch_size растёт выше 1 (main-throttle.c:155)
    // прогнать N итераций с продвижением часов пропорционально pps и
    // проверить, что next_batch в какой-то момент > 1 и ≤ 10000
}
```

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать `throttle.rs`** дословно по main-throttle.c:28/58.

- [ ] **Шаг 4: Тесты проходят** — PASS.

- [ ] **Шаг 5 (коммит, с согласия):** `feat(core): rate throttler with injectable clock (throttle.rs)`.

---

## Задача 10: `config` — ScanConfig, валидация, `--echo`-дамп

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/src/config.rs`

**Interfaces:**
- Consumes: `massip`, `targets`, `ranges`.
- Produces:
  - `pub struct ScanConfig { pub targets: MassIp, pub excludes: MassIp,
    pub seed: u64, pub max_rate: f64, pub retries: u32, pub shard: Shard,
    pub resume_index: u64, pub resume_count: Option<u64>,
    pub blackrock_rounds: u32, pub wait_secs: u32, pub adapter_ip: Option<u32>,
    pub adapter_mac: Option<[u8;6]>, pub router_mac: Option<[u8;6]>,
    pub source_port: Option<(u16,u16)> }` с дефолтами (main.c:1595:
    rounds=14, max_rate=100.0, wait=10, shard 1/1).
  - `pub fn validate(cfg: &ScanConfig) -> Result<EffectiveConfig, ConfigError>`
    — проверки: range != 0 (Review Focus №4; main.c:1720,1733), битность
    range ≤ 63 (main.c:1698), при >1e9 адресов нужен ≥1 exclude
    (main.c:1235). Применяет excludes и optimize в правильном порядке.
  - `pub fn echo(cfg: &ScanConfig, echo_all: bool, out: &mut String)` —
    канонический дамп `name = value` в формате `paused.conf`
    (main-conf.c:3636). Поддерживаемые ключи (из §7.1): `seed`
    (всегда, main-conf.c:2038), `rate` (main-conf.c:1872, целое или float),
    `retries` (если !=0 или echo_all), `shard = one/of` (main-conf.c:2067),
    `blackrock-rounds`, `adapter-ip`/`adapter-mac`/`router-mac-ipv4`
    (main-conf.c:293), `adapter-port` (main-conf.c:3668), `ports = ...`
    (main-conf.c:3681, TCP без префикса), `range = ...` CIDR/диапазоны
    (main-conf.c:3728), `resume-index`/`resume-count` (под комментарием
    `# resume information`).
  - `pub fn read_paused_conf(text: &str) -> Result<ScanConfig, ConfigError>`
    — парсер `name = value`, строки, начинающиеся с пунктуации,
    игнорируются (main-conf.c:3908).

- [ ] **Шаг 1: Провальные тесты валидации и round-trip echo**

```rust
#[test]
fn validate_rejects_empty_range() {
    let mut cfg = ScanConfig::default();
    // цели есть, портов нет → range 0 после optimize
    targets::add_target_string(&mut cfg.targets.ipv4, "10.0.0.0/24").unwrap();
    assert!(matches!(validate(&cfg), Err(ConfigError::EmptyPorts))); // main.c:1733
}

#[test]
fn validate_rejects_over_63_bits() { /* range битность > 63 → Err (main.c:1698) */ }

#[test]
fn echo_roundtrips_through_paused_conf() {
    let mut cfg = ScanConfig::default();
    cfg.seed = 1;
    targets::add_target_string(&mut cfg.targets.ipv4, "10.0.0.0/24").unwrap();
    targets::parse_ports(&mut cfg.targets.ports, "80,443").unwrap();
    let mut s = String::new();
    echo(&cfg, false, &mut s);
    let cfg2 = read_paused_conf(&s).unwrap();
    let mut s2 = String::new();
    echo(&cfg2, false, &mut s2);
    assert_eq!(s, s2); // эхо стабильно через запись/чтение
}
```

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать `config.rs`** по main.c:1595 (дефолты), :1673–1733
  (порядок excludes→optimize→проверки), main-conf.c:3636 (echo),
  :3883 (чтение).

- [ ] **Шаг 4: Тест чтения golden `paused.conf` (спека §7.2 п4)**

```rust
#[test]
fn reads_c_oracle_paused_conf_fixtures() {
    for f in golden_glob("tests/golden/paused/*.conf") {
        let cfg = read_paused_conf(&std::fs::read_to_string(&f).unwrap()).unwrap();
        // ключевые поля разобраны (seed, ports, range, resume-index)
        assert!(cfg.seed != 0 || cfg.resume_index != 0);
    }
}
```

- [ ] **Шаг 5: Тесты проходят** — PASS.

- [ ] **Шаг 6 (коммит, с согласия):** `feat(core): ScanConfig, validation and --echo (config.rs)`.

---

## Задача 11: `rmasscan-cli` — `-sL`, `--echo`, `--offline --packet-trace`

**Файлы:**
- Create: `rmasscan/crates/rmasscan-cli/src/args.rs`
- Modify: `rmasscan/crates/rmasscan-cli/src/main.rs`
- Test: `rmasscan/crates/rmasscan-cli/tests/differential.rs`

**Interfaces:**
- Consumes: весь `rmasscan-core`.
- Produces: clap-структура с подмножеством опций §7.1: `--seed`, `--rate`,
  `-p/--ports`, позиционные цели + `--range`, `--exclude`, `--excludefile`,
  `--resume-index`, `--resume-count`, `--shard`, `--retries`,
  `--blackrock-rounds`, `--adapter-ip`, `--adapter-mac`, `--router-mac`,
  `--source-port`, `--offline`, `--packet-trace`, `-sL/--list`, `--echo`,
  `--interface`, `--wait`. Любая другая опция → ошибка (Review Focus №5).
  Цели — `Vec<String>` с `ArgAction::Append` (подтверждено по docs clap:
  `#[arg(long)] name: Vec<String>`); для тестов — `Cli::try_parse_from`.

- [ ] **Шаг 1: Провальные тесты парсинга и операций**

```rust
#[test]
fn unsupported_option_errors() {
    assert!(Cli::try_parse_from(["rmasscan", "--banners", "10.0.0.0/24", "-p80"]).is_err());
}

#[test]
fn list_scan_single_port_prints_ip_only() {
    // main-listscan.c:53: при одном порте печатается только IP
    let out = run(["rmasscan", "-sL", "10.0.0.0/30", "-p80", "--seed", "1"]);
    assert!(out.lines().all(|l| !l.contains(':')));
    assert_eq!(out.lines().count(), 4);
}
```

- [ ] **Шаг 2: Тесты падают** — FAIL.

- [ ] **Шаг 3: Реализовать CLI**: отобразить аргументы в `ScanConfig`,
  операции: `-sL` → `scan::list_scan` + печать (ip или ip:port,
  main-listscan.c:59); `--echo` → `config::echo`; `--offline --packet-trace`
  → собрать кадры `scan` генератором и печатать трассу `SENT (t) TCP
  [ip]:port > [ip]:port SYN` (main-ptrace.c:94). Примечание (спека §4.8): в
  C `--offline` трасса пуста (DLT_NULL не распознаётся); наш CLI печатает
  рабочую трассу осознанно — она для собственной диагностики, не для сверки
  с C.

- [ ] **Шаг 4: Дифференциальные тесты `-sL` и `--echo` против golden**

`tests/differential.rs` — повторяет Задачу 8 шаг 5 на уровне бинарника
(через `assert_cmd`-подобный запуск собственного бинаря или вызов
библиотечной функции) и добавляет echo (спека §7.2 п3):
```rust
#[test]
fn echo_matches_oracle_as_set() {
    let manifest = load_manifest();
    for case in manifest.cases.iter().filter(|c| c.mode == "--echo") {
        let expected = parse_kv_set(&read_golden(&case.file)); // множество (ключ,значение)
        let got = parse_kv_set(&run_echo(&case.args));
        // сравнение как множеств по поддерживаемым ключам (спека §7.2 п3)
        assert_eq!(got, filter_supported(expected), "echo расходится на {:?}", case.args);
    }
}
```

- [ ] **Шаг 5: Тесты проходят** — `cd rmasscan && cargo test`, PASS на всех
  целевых ОС (в CI).

- [ ] **Шаг 6 (коммит, с согласия):** `feat(cli): -sL, --echo, --offline trace + differential tests`.

---

## Задача 12: Перенос оставшихся self-tests и бенчмарк генерации

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/benches/offline_gen.rs`
- Modify: `rmasscan/crates/rmasscan-core/Cargo.toml` (`[[bench]]`, criterion)

**Interfaces:**
- Consumes: `scan`, `massip`, `blackrock`.
- Produces: criterion-бенчмарк скорости генерации (пред-shuffle + shuffle +
  pick) без I/O, сопоставимый с офлайн-оракулом.

- [ ] **Шаг 1: Свести перенесённые self-tests (спека §9, §7.4)**

Проверить, что как `#[test]` присутствуют эквиваленты: `massip_selftest`
(Задача 6), `ranges_selftest` + `exclude_selftest` (Задача 1),
`massip_parse_selftest` IPv4-часть (Задача 2), `checksum_selftest` (Задача 4),
`siphash24_selftest` (Задача 5), `blackrock_selftest` (Задача 3),
`template_selftest` (Задача 7). Добавить сводный тест-перечень/документацию
соответствия C→Rust в `rmasscan-core/tests/selftest_parity.rs` (комментарий
со ссылками `файл:строка`). `rawsock_selftest` и `templ_tcp_selftest` —
**этап 2** (I/O и TCP-опции); отметить это в комментарии.

- [ ] **Шаг 2: Бенчмарк**

`benches/offline_gen.rs` — criterion измеряет пропускную способность
`list_scan`/`transmit_index_stream`+shuffle+pick на `0.0.0.0/4 -p80`-подобном
большом range (спека §7.6). Тест-проверка порога:
```rust
#[test]
fn offline_generation_meets_80pct_of_oracle() {
    let oracle_pps = load_manifest().offline_gen_pps; // из этапа 0, Задача 4 шаг 6
    let ours = measure_offline_gen_pps();
    assert!(ours >= 0.80 * oracle_pps, "{ours} < 80% от {oracle_pps}");
}
```
Если `offline_gen_pps` в манифесте отсутствует — тест помечается
`#[ignore]` с сообщением «нет оракул-числа; см. этап 0 Задача 4 шаг 6».

- [ ] **Шаг 3: Прогнать** — `cargo test -p rmasscan-core` (PASS),
  `cargo bench -p rmasscan-core` (записать достигнутый pps).

- [ ] **Шаг 4 (коммит, с согласия):** `test(core): selftest parity map + offline generation benchmark`.

---

## Задача 13: Property-тесты парсеров и порядка (proptest)

**Файлы:**
- Create: `rmasscan/crates/rmasscan-core/tests/proptest_order.rs`

**Interfaces:**
- Consumes: `scan`, `blackrock`, `massip`, `targets`.
- Produces: structural property-тесты (proptest, pure Rust; cargo-fuzz не
  используется на этапах 0–1, спека §12 вопрос 3).

- [ ] **Шаг 1: Провальные/проверочные property-тесты**

```rust
proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn blackrock_is_bijective_on_small_ranges(range in 9u64..2000, seed in any::<u64>()) {
        let br = BlackRock::new(range, seed, 14);
        let mut seen = vec![false; range as usize];
        for i in 0..range {
            let x = br.shuffle(i);
            prop_assert!(x < range);
            prop_assert!(!seen[x as usize]);
            seen[x as usize] = true;
        }
    }

    #[test]
    fn list_scan_visits_every_target_once(
        host_bits in 1u32..8, nports in 1u64..8, seed in any::<u64>())
    {
        // построить MassIp, прогнать list_scan, собрать (ip,port) в множество,
        // проверить, что их ровно range и все различны (перестановка целей)
    }

    #[test]
    fn parse_ports_never_panics(s in ".{0,40}") {
        let _ = targets::parse_ports(&mut RangeList::new(), &s); // не паникует
    }
}
```

- [ ] **Шаг 2: Прогнать** — `cargo test -p rmasscan-core --test proptest_order`, PASS.

- [ ] **Шаг 3 (коммит, с согласия):** `test(core): proptest for permutation invariants and parser robustness`.

---

## Задача 14: Go/No-Go этапа 1

**Файлы:** нет (контрольная задача; при необходимости — запись решения в
`rmasscan/README.md` или отчёт).

- [ ] **Шаг 1: Свести критерии выхода этапа 1 (спека §9)**

Подтвердить на всех трёх ОС (CI зелёный), приложив вывод команд:
1. **Побайтовое совпадение `-sL` с C** на всей матрице §7.2 — тест
   `list_scan_matches_c_oracle_fixtures` (Задача 8 шаг 5) зелёный на всех
   записях манифеста.
2. **`--echo` совпадает** как множество пар — `echo_matches_oracle_as_set`
   (Задача 11 шаг 4).
3. **Self-tests перенесены** — `selftest_parity.rs` и все тесты модулей
   (Задача 12 шаг 1).
4. **Transmit-формула и байты SYN покрыты тестами по коду** — Задача 8
   (шаги 1–4), Задача 7 (байты).
5. **Бенчмарк генерации ≥ 80% C** — `offline_generation_meets_80pct_of_oracle`
   (Задача 12 шаг 2), либо явно помечено «нет оракул-числа».
6. **`cargo deny` и `cargo tree -e build` без C** (наследие этапа 0) всё ещё
   зелёные после добавления siphasher.

- [ ] **Шаг 2: Проверить анти-критерий No-Go (спека §9)**

No-go, если обнаружен недетерминизм C, который нельзя воспроизвести
(например, зависимость от `time(0)` вне документированных мест §4.1/§4.4).
Если дифференциальные тесты падают из-за такого — зафиксировать находку,
остановить переход к этапу 2, вынести вопрос пользователю.

- [ ] **Шаг 3: Решение**

Если 1–6 выполнены и No-Go не сработал — этап 1 закрыт, можно планировать
этап 2 (raw I/O, golden pcap). Иначе — список незакрытых пунктов и причина.

---

## Самопроверка плана (этап 1)

**Покрытие критериев выхода §9 «этап 1»:**
- «Побайтовое совпадение `-sL` и `--echo` с C на матрице §7.2» → Задача 8
  шаг 5, Задача 11 шаг 4 (сверка с golden-фикстурами этапа 0).
- «selftests перенесены» → Задачи 1,2,3,4,5,6,7 + сводка в Задаче 12 шаг 1.
- «transmit-формула и байты SYN покрыты тестами по коду» → Задача 8
  (shaги 1–4, §7.2 п2), Задача 7 (§7.3).
- «бенчмарк генерации ≥ 80% C» → Задача 12 шаг 2.
- Отдельная go/no-go → Задача 14.

**Карта §3 (модули этапа 1):** `core::targets`→Задачи 1,2; `core::blackrock`
→3; `core::cookie`→5; `core::packet`→7; `core::throttle`→9; `core::config`+
`--echo`→10; CLI `-sL`/`--offline --packet-trace`→11; `core::scan`
(генератор)→8; `massip`→6; `checksum`→4.

**Инварианты §4:** §4.1 (дефолты, пространство индексов, 63-бита, seed) →
Задачи 10,8; §4.2 (BlackRock, wrapping) →3; §4.3 (порядок, формула transmit,
excludes до optimize) →6,8; §4.4 (байты, cookie, source-port) →5,7; §4.5
(троттлер, часы) →9; §4.6 (paused.conf, resume) →10; §4.8 (`-sL`,
`--offline`, `--echo`) →8,10,11. §4.7 (адаптер/ARP) — этап 2, вне плана.

**Review Focus:** №1→Задача 3; №2→Задачи 8; №3→Задачи 6,8; №4→Задачи 3,10;
№5→Задачи 2,11. Все пять имеют адресные тесты.

**Пропорция:** код в задачах дан сигнатурами, именами тестов и утверждениями
с точными значениями из кода masscan и golden-фикстур; тела алгоритмов не
переписаны, а привязаны к `файл:строка` в исходниках и спеке.

**IPv6:** всюду отложен (спека §3); парсеры возвращают `Ipv6NotSupported`,
`massip.range()` без IPv6-слагаемого, смещения индексов сохранены тем, что
IPv6-count = 0. Это сознательно сужает `massip_selftest` до IPv4-эквивалента.
