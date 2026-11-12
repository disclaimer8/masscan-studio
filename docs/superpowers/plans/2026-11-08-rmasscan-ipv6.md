# rmasscan: IPv6 — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development`. Шаги в чекбоксах (`- [ ]`).
> Цикл на каждую задачу: RED (тест) → FAIL → минимальная реализация со ссылкой на C `файл:строка` → PASS → коммит.

**Goal:** поведенческий паритет `rmasscan` с `masscan` (`8e6b3b0`) по IPv6: `Range6List` + `ipv6address_fmt`, смешанная
индексация v4+v6 без изменения порядка v4, 78-байтовый шаблон TCP SYN поверх IPv6 + `syn_cookie_ipv6`, автоопределение
source IPv6 на Linux/macOS/Windows, NDP (`135`/`136`), рендер IPv6 и записи `10`/`11` в форматах вывода и `--readscan`.

**Architecture:** `Range6List`, `ipv6address_fmt`, `syn_cookie_ipv6`, RFC 8200 чексумма, `Tcp6SynTemplate`, смешанная
выборка и приёмники IPv6/NS — в `rmasscan-core`; таблица маршрутов IPv6 ОС и NDP-резолвер — в `rmasscan-net`
(единственный `unsafe` крейт под `// SAFETY:`); `Record { ip: IpAddr }` и записи `10`/`11` в `rmasscan-cli`.

**Tech Stack:** Rust 1.99.1, Cargo workspace `rmasscan/`, без новых крейтов (`libc =0.2.191`, `windows-sys`).

**Spec:** [docs/superpowers/specs/2026-11-08-rmasscan-ipv6-design.md](../specs/2026-11-08-rmasscan-ipv6-design.md) (решения Р1–Р5).

## Global Constraints

- `#![forbid(unsafe_code)]` везде, кроме `rmasscan-net` (каждый `unsafe`-блок под `// SAFETY:`); ноль новых зависимостей
  (`Cargo.lock`/`deny.toml` без изменений); ноль файлов вне Rust/docs (`language-guard`); ноль живого трафика/NIC в
  офлайн-тестах; приватность публичного репо.
- **Контракт `Studio` заморожен:** структура `AdapterBinding` сохраняет свои 6 полей, `ReadyPlan::new(eff, binding)`
  сохраняет v1-контракт IPv4, `canonical_job_bytes` на чисто IPv4-заданиях не меняется ни на байт. Новые v6-поля в
  `NicBinding` / `ScanConfig` / `EffectiveConfig` обходят путь `Studio` без изменений его IPC.
- **Инвариант порядка v4:** когда `count_ipv6 == 0`, поток кадров и индексов IPv4 абсолютно тождествен предыдущим этапам
  (защищено явным регресс-тестом).
- Сборки и тесты на ноутбуке (Linux); **Windows/macOS clippy+тесты (включая `PF_ROUTE` / `GetBestRoute2`) ловит
  GitHub CI**.

## Review Focus

1. **Позиционные unbracketed `fd00::1`/`fe80::1`, сжатие первого нулевого блока `ipv6address_fmt` и `::/0`:** в C
   аргумент на `a`–`f` без скобок не распознавался (`main-conf.c:3594`), `::/0` даёт `2^128` в `count`
   (`massip-rangesv6.c:490`), а `Ipv6Addr::Display` не совпадает с `ipv6address_fmt` (`massip-addr.c:33–109`) — тесты
   `ipv6_parse_unbracketed_and_c_fmt_first_zero` (Задача 1) и `ipv6_full_space_and_63bit_limit` (Задачи 1 и 2).
2. **Смешанный v4+v6 скан vs неизменность чистого v4:** `range_ipv6` стоит внизу `0..range_ipv6`, но при `count_ipv6 == 0`
   байты и индексы v4 обязаны совпасть с эталоном предыдущих этапов — тест `pure_ipv4_sequence_unchanged_with_ipv6_support`
   (Задача 2).
3. **KAME `scope_id` в `fe80::/10` на macOS (`s6_addr[2..4]`), `utun`/VPN и ULA на Linux netns:** утекший индекс зоны в
   NDP-кадр или запрет `fd00::/8` срывает живое обнаружение — тесты `macos_kame_scope_id_is_stripped` и
   `route_selection_prefers_ula_and_ignores_vpn` (Задача 5).
4. **Таймаут NDP Neighbor Solicitation (`135`) без шлюза/соседа и прерывание по Ctrl-C:** NDP обязан уважать
   таймаут/отмену, как ARP, и возвращать читаемый отказ до запуска движка — тест `ndp_timeout_and_interrupt_abort_cleanly`
   (Задача 4).
5. **`-oB` записи `10`/`11` (28 байт) + фильтр IPv6 в `--readscan` + `hop_limit`:** смещение поля `version = 6` (байт 11),
   `len = 26`, `addrtype="ipv6"` в XML и фильтр `--readscan <v6-cidr> file.scan` — тест
   `readscan_v6_types_10_11_and_filter_match_c` (Задача 6).

---

### Задача 1: разбор, исключения и `ipv6address_fmt` для диапазонов IPv6 в `rmasscan-core`

**Files:**
- Create: `rmasscan/crates/rmasscan-core/src/ranges6.rs`
- Modify: `rmasscan/crates/rmasscan-core/src/{lib,massip,targets}.rs`
- Test: `#[cfg(test)]` в `ranges6.rs`, `targets.rs`

**Interfaces:**
- Produces:
  - `pub struct Ipv6AddrBytes(pub [u8; 16]);` / `Ipv6Range { pub begin: u128, pub end: u128 }` и `Range6List` с
    `add`, `optimize` (сортировка + слияние пересекающихся и смежных, `massip-rangesv6.c:219–242`), `apply_excludes`
    (`:408–485`), `count_u128` (`:490–507`), `picker` (`:554–582`) и `pick` бинарным поиском (`:513–543`).
  - `pub fn parse_ipv6_target(spec: &str) -> Result<Ipv6Range, ParseError>` (`massip-parse.c:274–763`: полная запись,
    одиночный `::`, `[addr]`, `/0..128`, `a-b`, отказ при `begin > end` и двойном `::`).
  - `pub fn format_ipv6_c(addr: u128) -> String` — точный порт `ipv6address_fmt` (`massip-addr.c:33–109`: сжатие первой
    нулевой серии 16-битных слов в `::`).

- [ ] **Шаг 1 — красный тест:**
  - `ipv6_parse_unbracketed_and_c_fmt_first_zero` (Review Focus 1):
    - `"2a03:9060:0:400:0:0:0:2"` парсится в число и форматируется `format_ipv6_c` строго в `"2a03:9060::400:0:0:0:2"`
      (не `"2a03:9060:0:400::2"`); `"fd00::/126"`, `"[2001:db8::1]-[2001:db8::5]"`, `"fe80::1"` (без скобок, на `a`–`f`)
      разбираются без ошибки; `"::2-::1"` и `"1::2::3"` отклоняются.
  - `ipv6_full_space_and_63bit_limit`: `"::/0"` не паникует и даёт полное покрытие `0..=u128::MAX`; `exclude` вырезает
    середину диапазона и сливает смежные участки по правилам C.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core ipv6_parse_unbracketed` — не компилируется.
- [ ] **Шаг 3 — реализация:** реализовать `ranges6.rs` и подключить к `MassIp` и `targets::add_target_string`
  (`~/masscan/src/massip-rangesv6.c`, `massip-parse.c:274–763`, `massip-addr.c:33–109`, плюс `-6` no-op в `args.rs`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core` — зелёный.
- [ ] **Шаг 5 — коммит:** `ranges6.rs`, `lib.rs`, `massip.rs`, `targets.rs`, `args.rs`.

### Задача 2: смешанная индексация v4 + v6, лимит 63 бита и `-sL` (`massip_pick` vs `transmit`)

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/{massip,scan,probe,config}.rs`
- Test: `#[cfg(test)]` в `scan.rs`, `probe.rs`, `config.rs`

**Interfaces:**
- Produces:
  - `MassIp::try_range(&self) -> Result<u64, ScanError>`: проверяет `bitcount((count_ipv4 + count_ipv6) * count_ports)
    <= 63` (`main.c:1698–1704`: иначе отказ `scan range too large, max is 63-bits`).
  - В `transmit_scan_flow` / `ReadyPlan::new_cli` (`main.c:258–260, 336–373`): `range_ipv6 = count_ipv6 * count_ports`;
    индексы `x < range_ipv6` → IPv6 `(ip6, port)`, индексы `x >= range_ipv6` → IPv4 `(ip4, port)` с вычетом
    `range_ipv6`.
  - В `list_scan` (`massip.c:24, 30–43`, `main-listscan.c:53–63`): при одновременном наличии v4 и v6 используется порядок
    `massip_pick` C (`v4` на `0..range_ipv4`, `v6` на `range_ipv4..range`), формат `[addr]:port\n` при `ports > 1` и
    `addr\n` при `1` порте; в `--echo` печатаются и `range = <v6>`.

- [ ] **Шаг 1 — красный тест:**
  - `pure_ipv4_sequence_unchanged_with_ipv6_support` (Review Focus 2): зафиксированный прогон чистого IPv4
    (`198.18.0.0/28`, порты `80,443`, `seed = 42`) выдаёт точный неизменный хэш/вектор зондов до и после задачи.
  - `mixed_v4_v6_transmit_puts_v6_in_low_indices_and_v4_after`: `count_ipv6 = 2, count_ipv4 = 3, ports = 2` → для
    `x ∈ 0..4` выдаётся `TargetIp::V6`, для `x ∈ 4..10` — `TargetIp::V4`, а `-sL` совпадает по строкам с C (`[addr]:port`).
  - `ipv6_slash_64_exceeds_63_bits_while_slash_66_succeeds` (Review Focus 1): `/64` при одном порте (64 бита) даёт ошибку
    63-битного предела, а `/66` (62 бита) проходит `validate`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core mixed_v4_v6_transmit` — падает.
- [ ] **Шаг 3 — реализация:** обновить `massip.rs`, `scan.rs`, `probe.rs` (`TargetIp { V4(u32), V6(u128) }`), `config.rs`
  (`echo` + снятие запрета только-v6 исключений из `main.c:1235`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core` — зелёный.
- [ ] **Шаг 5 — коммит:** `massip.rs`, `scan.rs`, `probe.rs`, `config.rs`.

### Задача 3: 78-байтовый шаблон TCP SYN поверх IPv6, `syn_cookie_ipv6`, чексумма RFC 8200 и приём

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/{checksum,cookie,packet,probe,receive}.rs`,
  `rmasscan/crates/rmasscan-engine/src/engine.rs`
- Test: `#[cfg(test)]` в `checksum.rs`, `cookie.rs`, `packet.rs`, `receive.rs`

**Interfaces:**
- Produces:
  - `cookie::syn_cookie_ipv6(ip_them: u128, port_them: u32, ip_me: u128, port_me: u32, entropy: u64) -> u64`
    (`syn-cookie.c:155–171`: SipHash-2-4 по 5 `u64` LE `[ip_them_hi, ip_them_lo, ip_me_hi, ip_me_lo,
    (port_them << 16) | port_me]`, `k0 = k1 = entropy`).
  - `checksum::tcp_ipv6_partial` / `checksum::checksum_ipv6` (`util-checksum.c:118–153`, RFC 8200: `src16 + dst16 +
    len_tcp32 + proto32(6)`).
  - `Tcp6SynTemplate` (`templ-pkt.c:718–803, 1110–1212`): 78 байт по умолчанию (поддержка `--ttl`, `--badsum`,
    `TcpHeaderOptions`, `LinkType::{Ethernet, Null, Raw}`); в `main.c:345–346` использует фиксированный `source_ipv6` и
    `source_ports.0`.
  - Приём в `receive.rs` и `DedupCache`: разбор `EtherType = 0x86DD`, обход `Hop-by-Hop (0)`, проверка TCP (`6`),
    валидация `syn_cookie_ipv6`, чтение реального `hop_limit = px[offset_ip + 7]` и 128-битный ключ дедупликации.

- [ ] **Шаг 1 — красный тест:**
  - `syn_cookie_ipv6_matches_c_bytes`: точные 64-битные значения `syn_cookie_ipv6` для фиксированных пар адрес/порт/seed
    против функции C `syn-cookie.c:155–171` (критична раскладка `hi/lo`);
  - `tcp6_syn_template_78_bytes_and_rfc8200_checksum`: все 78 байт `Tcp6SynTemplate` (`router_mac_ipv6`, `86 dd`,
    `60 00 00 00`, `payload_len = 00 18`, `next = 06`, `hop = ff`, `src`, `dst`, TCP SYN `win = 04 01`, MSS `02 04 05 b4`)
    и независимый верификатор чексуммы RFC 8200 `== 0xFFFF`;
  - `receive_v6_handles_hop_by_hop_extension_and_records_hop_limit`: синтетический SYN-ACK с Hop-by-Hop заголовком
    (`next = 0, len = 0 → +8 байт`) и `hop_limit = 59` распознаётся как `Open` с `ttl = 59` и точным `ackno - 1`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core tcp6_syn_template` — падает.
- [ ] **Шаг 3 — реализация:** `cookie.rs`, `checksum.rs`, `packet.rs`, `probe.rs`, `receive.rs`, `engine.rs` по
  `~/masscan/src/templ-pkt.c:718–803, 1110–1212`, `syn-cookie.c:155–171`, `proto-preprocess.c:215–332`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-engine` — зелёный.
- [ ] **Шаг 5 — коммит:** `checksum.rs`, `cookie.rs`, `packet.rs`, `probe.rs`, `receive.rs`, `engine.rs`.

### Задача 4: NDP (`ICMPv6 135/136`) резолв соседа/шлюза и ответчик на входящие NS

**Files:**
- Create: `rmasscan/crates/rmasscan-net/src/ndp.rs`, `rmasscan/crates/rmasscan-net/src/ndp_resolve.rs`
- Modify: `rmasscan/crates/rmasscan-net/src/lib.rs`, `rmasscan/crates/rmasscan-core/src/receive.rs`,
  `rmasscan/crates/rmasscan-engine/src/engine.rs`
- Test: `#[cfg(test)]` в `ndp.rs`, `ndp_resolve.rs`, `receive.rs`

**Interfaces:**
- Produces:
  - В `ndp.rs`: кодировщик 86-байтного `Neighbor Solicitation` (`dst_mac = [0x33, 0x33, 0xff, t[13], t[14], t[15]]`,
    `dst_ip = ff02::1:ffXX:XXXX`, `hop_limit = 255`, `payload_len = 32`, ICMPv6 `type 135`, Option `1` = `source_mac`,
    валидная ICMPv6-чексумма с псевдозаголовком `next_header = 58`) и декодер `Neighbor Advertisement` (`type 136`,
    `code 0`, `hop_limit == 255`, `target == wanted_ip`, Option `2` = Target Link-Layer Address).
  - В `ndp_resolve.rs`: `resolve_next_hop_v6_until(...) -> Result<Option<NdpReport>, NetError>` с контрактом, аналогичным
    `arp_resolve::resolve_next_hop_until` (повторы по политике, остановка по прерыванию, таймаут).
  - В `engine.rs` / `receive.rs`: обработчик входящего `Neighbor Solicitation (135)` на `source_ipv6` во время скана,
    отдающий в TX 86-байтный Neighbor Advertisement с `payload_length = 32` (`stack-ndpv6.c:95–182`, исправлена ошибка
    длины `:145`).

- [ ] **Шаг 1 — красный тест:**
  - `ndp_solicitation_86_bytes_and_advertisement_parse`: проверка всех 86 байт NS (solicited-node multicast MAC/IPv6,
    `hop_limit = 255`, Option `1`, ICMPv6-чексумма RFC 4443) и извлечение MAC из NA (`type 136`, Option `2`, игнор NA с
    `hop_limit != 255` по RFC 4861 §7.1.2);
  - `ndp_timeout_and_interrupt_abort_cleanly` (Review Focus 4): на фейковой паре при молчании пира `resolve_next_hop_v6_until`
    укладывается в `timeout` и возвращает понятную ошибку `NdpTimeout`, а при выставленном флаге прерывания немедленно
    возвращает `Ok(None)`;
  - `incoming_ns_during_scan_replies_with_32_byte_na`: входящий NS на `source_ipv6` в `engine` порождает корректный NA
    с `payload_len = 32`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-net ndp_` — не компилируется.
- [ ] **Шаг 3 — реализация:** `ndp.rs`, `ndp_resolve.rs`, интеграция в `receive.rs`/`engine.rs` по
  `~/masscan/src/stack-ndpv6.c:95–182` и RFC 4861.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-net -p rmasscan-engine -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `ndp.rs`, `ndp_resolve.rs`, `lib.rs`, `receive.rs`, `engine.rs`.

### Задача 5: автоопределение интерфейса, `source-ipv6` и next-hop по маршрутам ОС (Linux/macOS/Windows)

**Files:**
- Modify: `rmasscan/crates/rmasscan-net/src/discover.rs`, `rmasscan/crates/rmasscan-net/src/linux.rs`,
  `rmasscan/crates/rmasscan-net/src/macos.rs`, `rmasscan/crates/rmasscan-net/src/windows.rs`,
  `rmasscan/crates/rmasscan-net/src/lib.rs`, `rmasscan/crates/rmasscan-cli/src/{args,live,os_backend}.rs`
- Test: `#[cfg(test)]` в `discover.rs`, `linux.rs`, `macos.rs`, `windows.rs` (через фейковые таблицы и юниты парсеров)

**Interfaces:**
- Produces:
  - Расширение `Iface`, `RouteTable` / `RouteV6`, `Overrides` и `detect_v6` / `detect_mixed` в `discover.rs`:
    выбор интерфейса по маршруту к первой целевой подсети IPv6, извлечение `source_ipv6` и `next_hop_ipv6` (`::` →
    прямой сосед `target`, иначе шлюз), проверка ULA/Global (отказ только loopback/multicast/unspecified), поддержка
    `--adapter-ip <v6>`, `--router-ip <v6>` (`--router-ipv6`) и `--router-mac-ipv6`.
  - **Linux (`linux.rs`):** `AF_NETLINK` `RTM_GETROUTE` (`AF_INET6`, `RTA_DST`, `RTA_OIF`, `RTA_GATEWAY`, `RTA_PREFSRC`) +
    `RTM_GETADDR` (`AF_INET6`). Весь `unsafe` строго с `// SAFETY:`.
  - **macOS (`macos.rs`):** `PF_ROUTE` `RTM_GET` (`sockaddr_in6`) + `getifaddrs` (`AF_INET6`), с обязательным обнулением
    встроенного KAME `scope_id` (`bytes[2..4] = [0, 0]`) для `fe80::/10`. Весь `unsafe` строго с `// SAFETY:`.
  - **Windows (`windows.rs`):** `GetBestRoute2` (`AF_INET6`, `BestSourceAddress`, `NextHop`) + `GetAdaptersAddresses(AF_UNSPEC)`.
    Весь `unsafe` строго с `// SAFETY:`.

- [ ] **Шаг 1 — красный тест:**
  - `macos_kame_scope_id_is_stripped` (Review Focus 3): входной `sockaddr_in6` с `fe80:0004::1` (встроенный индекс зоны
    `4` в `s6_addr[2..4]`) преобразуется в чистый `Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)`;
  - `route_selection_prefers_ula_and_ignores_vpn` (Review Focus 3): на фейковых таблицах с дефолтным `utun` и
    конкретным ULA-маршрутом `fd00:198:18::/64` выбирает интерфейс стенда и `fd00:198:18::1`, а при расхождении
    интерфейсов v4 и v6 в одном смешанном скане даёт явный отказ `exit 1`;
  - кросс-тесты разбора Netlink/RTM_GET-буферов в `linux.rs` / `macos.rs`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-net route_selection_prefers_ula` — падает.
- [ ] **Шаг 3 — реализация:** расширить `linux.rs`, `macos.rs`, `windows.rs`, `discover.rs`, `live.rs` (печатая
  `[+] source-ip6 = ...`, `[+] router-mac-ipv6 = ...`) и `args.rs`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-net -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `discover.rs`, `linux.rs`, `macos.rs`, `windows.rs`, `lib.rs`, `args.rs`, `live.rs`, `os_backend.rs`.

### Задача 6: рендер IPv6 и бинарные записи типов `10`/`11` в форматах вывода и `--readscan`

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/receive.rs` (поддержка `IpAddr::V6` в `Reply` без поломки прежнего
  конструктора/полей для `Studio`), `rmasscan/crates/rmasscan-cli/src/output/{record,formats,grepable,pipeline}.rs`,
  `rmasscan/crates/rmasscan-cli/src/readscan.rs`, `rmasscan/crates/rmasscan-cli/examples/format_inputs.rs`,
  `rmasscan/crates/rmasscan-cli/tests/formats_golden.rs`, `rmasscan/tests/golden/formats/`
- Test: `#[cfg(test)]` в `formats.rs`, `readscan.rs`, `formats_golden.rs`

**Interfaces:**
- Produces:
  - В `record.rs`: адрес цели `IpAddr` (`V4` / `V6`), форматирование через `IpAddr::V4` стандартно и `format_ipv6_c` для
    `V6`; `Record` конвертируется из `Reply`.
  - В `formats.rs` (`Binary`, `Xml`, и др.) и `readscan.rs` (`out-binary.c:103–149`, `in-binary.c:228–276`):
    запись и чтение 28-байтовых записей `type = 10` (`Status::Open`, V6) и `type = 11` (`Status::Closed`, V6):
    `[0: 10|11, 1: 26, 2..5: ts BE4, 6: ip_proto, 7..8: port BE2, 9: reason, 10: ttl, 11: 6, 12..19: hi BE8, 20..27: lo BE8]`;
    в `Xml` при `V6` ставим `addrtype="ipv6"`; `ReadFilter::keeps` проверяет `targets.ipv6().contains(...)`.

- [ ] **Шаг 1 — красный тест:**
  - `binary_records_10_11_layout_is_exact_28_bytes`: запись и чтение `(2a03:9060:0:400::2, port 443, Open/Closed)`
    дают точные 28 байт (`len = 26`, байт 11 = `6`), XML содержит `addrtype="ipv6"`, list/json/ndjson/grepable/unicornscan
    используют `"2a03:9060::400:0:0:0:2"`;
  - `readscan_v6_types_10_11_and_filter_match_c` (Review Focus 5): чтение C-сгенерированного `ipv6.scan` во все форматы +
    фильтрация `--readscan 2a03:9060::/64` (входы от оракула `8e6b3b0` в `tests/golden/formats/`).
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli binary_records_10_11` — падает.
- [ ] **Шаг 3 — реализация:** расширить `Record`, форматтеры (`out-binary.c:103–149`, `out-xml.c:75`), `readscan.rs`
  (`in-binary.c:228–276`, `in-filter.c:10`), добавить `ipv6.scan` в `format_inputs.rs` и снять эталоны оракулом C
  на minipc.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-cli` (включая все эталоны `formats_golden`) — зелёный.
- [ ] **Шаг 5 — коммит:** `receive.rs`, `output/*`, `readscan.rs`, `format_inputs.rs`, `formats_golden.rs`,
  `tests/golden/formats/*`.

### Задача 7: живая приёмка (`--suite ipv6`) и документация

**Files:**
- Create: `rmasscan/crates/rmasscan-lab/src/{ipv6_suite,ipv6_verify}.rs`,
  `docs/experiments/2026-11-08-rmasscan-ipv6-acceptance.md`
- Modify: `rmasscan/crates/rmasscan-lab/src/{lib,main}.rs`, `rmasscan/scripts/wire-lab.sh` (`--suite ipv6` с включением
  IPv6 в netns без изменения прежнего `disable_ipv6=1` для старых наборов), `rmasscan/README.md`,
  `docs/experiments/2026-10-24-rmasscan-readiness.md`,
  `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`

**Interfaces:**
- Produces: подкоманды `rmasscan-lab ipv6-suite linux ...` и `ipv6-verify --dir DIR` с кодами `0` PASS / `1` FAIL / `2`
  INVALID (на базе ULA `fd00:198:18::/64` в запечатанном Linux netns).

- [x] **Шаг 1 — живое окно и верификатор (RED → GREEN):** добавить кейсы `v01_ndp_and_tcp6_syn` (автоопределение
  source IPv6, NDP, точные кадры SYN поверх IPv6, `-oJ`/`-oB`), `v02_mixed_v4_v6` (байты IPv4-зондов и карта индексов как у C: плана только IPv4 под смешанной перестановкой
  `x = shuffle((i + rate) mod range)`, `main.c:258–260, 325–331`; не буквальный порядок плана только IPv4, потому что C перемешивает
  весь смешанный диапазон),
  `v03_explicit_router_mac_ipv6`; прогнать `--suite ipv6` + полную регрессию `--suite autodetect`, `--suite output`,
  `--suite scan-control`, `--suite protocols` на Linux (minipc) и `windows-suite --plan autodetect` на Windows VM +
  `cargo xtask test` в `studio/`; выполнить privacy-grep. *(Сделано, кроме `cargo xtask test` в `studio/` и окон macOS и Windows
  IPv6: они NOT RUN, см. отчёт приёмки.)*
- [x] **Шаг 2 — документация и проверка CI:** обновить `rmasscan/README.md` («Отличия от masscan» по Р1–Р5), записать
  отчёт `docs/experiments/2026-11-08-rmasscan-ipv6-acceptance.md` и строку в `readiness.md`; убедиться в чистоте
  `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo fmt --check`,
  дождаться зелёного GitHub CI на всех 3 ОС (`rmasscan`, `Studio`, `language-guard`). *(Сделано, кроме зелёного CI на точном HEAD:
  PENDING, фиксирует контролёр при слиянии.)*

---

## Самопроверка

1. Покрытие спеки: Р1 → Задача 2; Р2 → Задачи 4, 5; Р3 → Задача 5; Р4 → Задача 1; Р5 → Задачи 3, 6; §6.2/§8 → Задача 7.
2. Каждый шаг даёт одну проверяемую вещь с точным именем теста и командой запуска.
3. Типы (`Ipv6Range`, `Range6List`, `Tcp6SynTemplate`, `TargetIp`, `Record { ip: IpAddr }`) согласованы; 6 полей
   `AdapterBinding` и `ReadyPlan::new` для `Studio` сохранены.
4. Все 5 пунктов Review Focus привязаны к явным тестам в задачах 1–6.
5. Порядок чистого IPv4 защищён явным регресс-тестом в Задаче 2 и живым набором в Задаче 7.
6. План соразмерен задаче и не содержит лишних абстракций или новых зависимостей.
