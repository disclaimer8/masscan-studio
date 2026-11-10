# rmasscan: протоколы IPv4 — план реализации

> **ОБЯЗАТЕЛЬНЫЙ САБ-СКИЛЛ:** `superpowers:subagent-driven-development`. Шаги в чекбоксах (`- [ ]`).
> Цикл на каждую задачу: RED (тест) → FAIL → минимальная реализация со ссылкой на C `файл:строка` → PASS → коммит.

**Goal:** поведенческий паритет `rmasscan` с `masscan` (`8e6b3b0`) по протоколам IPv4: грамматика префиксов `-p`
(`T:/U:/S:/I:/O:`, `--top-ports`), шаблоны и приём ICMP Echo (`--ping`), UDP (+ 28 встроенных AGPL-пейлоадов,
`--nmap-payloads`, `--pcap-payloads`, ICMP `3/3`), SCTP INIT (`CRC-32C`, `INIT-ACK`/`ABORT`), ARP-скан (`--arp`) и
рендер не-TCP записей во всех форматах вывода и `--readscan`.

**Architecture:** разбор портов, 28 пейлоадов, Castagnoli CRC-32C, шаблоны/приёмники ICMP/UDP/SCTP/ARP — в
`rmasscan-core`; учёт протокола в `DedupCache` и режим пропуска ARP шлюза при `--arp` — в `rmasscan-engine` и
`rmasscan-cli::live`; расширение `Record` / `ServiceNames` / форматтеров / `--readscan` — в `rmasscan-cli`.

**Tech Stack:** Rust 1.99.1, Cargo workspace `rmasscan/`, без новых крейтов.

**Spec:** [docs/superpowers/specs/2026-11-08-rmasscan-protocols-ipv4-design.md](../specs/2026-11-08-rmasscan-protocols-ipv4-design.md) (решения Р1–Р5).

## Global Constraints

- `#![forbid(unsafe_code)]` везде, кроме `rmasscan-net`; ноль новых зависимостей (`Cargo.lock`/`deny.toml` без изменений);
  ноль файлов вне Rust/docs (`language-guard`); никаких NPSL-файлов или баз из Nmap (спека порта §8.3).
- **Контракт `Studio` заморожен:** структура `AdapterBinding` сохраняет свои 6 полей, `ReadyPlan::new(eff, binding)`
  принимает только TCP для совместимости со `Studio`, `canonical_job_bytes` для TCP/IPv4 не меняется, а `Reply`
  сохраняет обратную совместимость (`tcp_flags`/`status`/`ip_proto`).
- Ноль живого трафика/NIC в офлайн-тестах; приватность публичного репо (без хостов, учёток и LAN-IP).
- Перед пушем: `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`,
  `cargo fmt --check` в `rmasscan/` и проверка `studio/`; Windows/macOS clippy+тесты подтверждает GitHub CI.

## Review Focus

1. **Смешанный список портов `-p U:53,T:80,S:2905,I:0` и отказ `O:`/`I:1+` при live/trace:** липкие префиксы не
   должны сбрасываться внутри списка или давать неинициализированную отправку на `O:` (`templ-pkt.c:932`) — тест
   `sticky_port_prefixes_and_oproto_live_refusal` (Задача 1).
2. **UDP-порт с 0-байтовым пейлоадом и без него, плюс ICMP Port Unreachable (`3/3`) на том же `(ip, port)`, что TCP:**
   UDP-порт не из таблицы обязан слать 0-байтовый UDP (42B кадр с валидной чексуммой `0xFFFF`, если получилось `0`), а
   `DedupCache` обязан различать `tcp` и `udp` и ICMP `3/3` (`Closed`) — тесты `udp_unknown_port_sends_empty_payload` и
   `dedup_cache_separates_protocols` (Задача 4).
3. **ARP-скан при нуле соседей или смешивании с `-p80`:** `--arp -p80` обязан падать с `FAIL: cannot arpscan and
   portscan at the same time`, `--arp` обязан пропускать резолв шлюза и в тихом сегменте завершаться с 0 записями и
   кодом `0` — тест `arp_scan_skips_gateway_arp_and_rejects_port_mix` (Задача 6).
4. **Чтение/запись не-TCP и ARP (`8`) в `-oB` и `--readscan`:** C-оракул обязан читать `-oB` с типами `6`/`7` для
   `ip_proto ∈ {1, 17, 132}`, а `rmasscan --readscan` обязан читать как эти файлы C, так и тип `8` (`arp`) и
   фильтровать по `-p U:53` — тест `readscan_handles_non_tcp_and_arp_type_8` (Задачи 2 и 7).
5. **UDP Port `53` / DNS `set_cookie` мутация id и Castagnoli CRC-32C для SCTP:** неправильный порядок байт CRC-32C
   (BE вместо LE) или несовпадение `port_me = 0` в ICMP Echo тихо срывает все ответы — тесты
   `sctp_crc32c_matches_c_selftest` (Задача 5) и `icmp_echo_cookie_uses_zero_source_port` (Задача 3).

---

### Задача 1: грамматика портов с префиксами `T:/U:/S:/I:/O:`, `--top-ports` и отказ `O:`/`I:1+`

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/targets.rs`, `rmasscan/crates/rmasscan-core/src/probe.rs`,
  `rmasscan/crates/rmasscan-core/src/config.rs`, `rmasscan/crates/rmasscan-cli/src/args.rs`
- Test: `#[cfg(test)]` в `targets.rs`, `probe.rs`, `args.rs`

**Interfaces:**
- Produces:
  - В `targets.rs`: снятие запрета на `U:`, `S:`, `I:`, `O:` в `parse_ports` (`massip-port.h:11–25`,
    `massip-rangesv4.c:992–1090`: липкий базовый сдвиг `TEMPL_TCP=0`, `TEMPL_UDP=65536`, `TEMPL_SCTP=131072`,
    `TEMPL_ICMP_ECHO=196608`, `TEMPL_OPROTO_FIRST=196864..=197119`), с проверкой границ `0..=65535` (TCP/UDP/SCTP),
    `0..=255` (Oproto) и разбором `top_ports(n, include_udp)` по встроенным массивам `top_tcp_ports[998]` и
    `top_udp_ports[31]` (`main-conf.c:896–1061`).
  - Хелпер `PortProto::from_raw(port: u32) -> (Proto, u16)` и валидация `ReadyPlan::new_cli` (отказ с `PlanError` при
    наличии `O:*` или `I:n` с `n != 0`, а также взаимный запрет `--arp` с портами, Р1).

- [ ] **Шаг 1 — красный тест:** добавить `sticky_port_prefixes_and_oproto_live_refusal` (Review Focus 1) в `targets.rs` и
  `probe.rs`:
  - `parse_ports("U:53,161,T:80-81,s:2905,I:0,o:47")` даёт точные сдвинутые диапазоны `[65589..=65589, 65697..=65697,
    80..=81, 133977..=133977, 196608..=196608, 196911..=196911]`; `O:256` и `U:65536` дают `Err`;
  - `--echo` с этими портами выводит `ports = 80-81,U:53,U:161,S:2905,I:0,O:47` (совпадает с уже готовым
    `echo_ports` в `config.rs:524–572`!);
  - `--top-ports 5` (только TCP) и `--top-ports 5 -sU` (TCP + UDP) совпадают со списками `main-conf.c:896–1061`;
  - `ReadyPlan::new_cli` отклоняет `O:47` и `I:1` с явной ошибкой, тогда как `I:0` и `ARP` принимаются.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core sticky_port_prefixes` — падает.
- [ ] **Шаг 3 — реализация:** обновить `targets.rs:420–499`, добавить флаги `-sU`, `--udp-ports`, `-sZ`, `--ping`,
  `--ping-sweep`, `--top-ports` в `args.rs` и проверку в `probe.rs` (`~/masscan/src/massip-rangesv4.c:992–1090`,
  `main-conf.c:896–1061, 3524–3550`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `targets.rs`, `probe.rs`, `config.rs`, `args.rs`.

### Задача 2: расширение `Record`, `ServiceNames`, форматтеров вывода и `--readscan` на `udp`/`sctp`/`icmp`/`arp`

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/receive.rs` (добавить `PortStatus::Arp`, поле `ip_proto: u8` и `mac:
  Option<[u8; 6]>` в `Reply`), `rmasscan/crates/rmasscan-cli/src/output/{mod,record,formats,grepable,services,pipeline}.rs`,
  `rmasscan/crates/rmasscan-cli/src/readscan.rs`
- Test: `#[cfg(test)]` в `formats.rs`, `grepable.rs`, `services.rs`, `readscan.rs`

**Interfaces:**
- Produces:
  - В `record.rs`: `pub enum Proto { Tcp = 6, Udp = 17, Sctp = 132, Icmp = 1, Arp = 0 }`, `Status::Arp` (`"up"`),
    `Record { timestamp, ip, port, proto, status, reason, ttl, mac: Option<[u8; 6]> }`, `proto_str(p: Proto) -> &'static str`
    (`"tcp"`, `"udp"`, `"sctp"`, `"icmp"`, `"arp"`, `out-text.c`/`output.c`).
  - В `services.rs`: поддержка `udp` в дополнение к `tcp` и маппинг имён протоколов из `/etc/protocols` (для ICMP/SCTP/ARP
    в `-oG`/`-oU`).
  - В `formats.rs` (`Binary`) и `readscan.rs`: `-oB` пишет тип `6`/`7` (`ip_proto ∈ {1, 6, 17, 132}`) и тип `8`
    (`Status::Arp`, `ip_proto = 0`); `--readscan` принимает типы `6`, `7` (`ip_proto ∈ {1, 6, 17, 132}`) и `8` (`ip_proto = 0`),
    а `ReadFilter` сравнивает `(r.proto, r.port)` со сдвинутым `targets.ports()`.

- [ ] **Шаг 1 — красный тест:**
  - `non_tcp_records_render_in_all_formats_like_c`: для записей `(Udp, Open, port 53, reason 0, ttl 64)`, `(Udp, Closed,
    port 5353, reason 0, ttl 64)`, `(Sctp, Open, port 2905)`, `(Icmp, Open, port 0)` и `(Arp, Arp, port 0, mac
    00:11:22:33:44:55)` проверяется точный вывод `-oL`, `-oJ`, `-oD`, `-oX`, `-oG`, `-oU`, `-oH`, `-oB` и интерактивной
    строки (`Discovered up port 0/arp on ... (00-11-22-33-44-55)` / формат С `xx:xx:xx:xx:xx:xx`).
  - `readscan_handles_non_tcp_and_arp_type_8` (Review Focus 4): бинарный буфер с типом `6` (`proto 17` и `proto 1`),
    типом `7` (`proto 132`) и типом `8` (`proto 0`) разбирается без ошибки, фильтруется `-p U:53` и сохраняет прежние
    тесты `formats_golden` (74 кейса TCP).
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli non_tcp_records` — падает.
- [ ] **Шаг 3 — реализация:** расширить `Record`, форматтеры (`~/masscan/src/out-{text,json,ndjson,xml,grepable,
  unicornscan,binary}.c`), `ServiceNames` и `readscan.rs` (`in-binary.c:583–634`), сохраняя 100% прежний вывод для
  чистых TCP-записей.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-cli` (включая `formats_golden` и `live_fake`) — зелёный.
- [ ] **Шаг 5 — коммит:** `receive.rs`, `output/*`, `readscan.rs`.

### Задача 3: шаблон ICMP Echo Request (`I:0`) и приём ICMP Echo Reply (`type 0`)

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/packet.rs`, `rmasscan/crates/rmasscan-core/src/probe.rs`,
  `rmasscan/crates/rmasscan-core/src/receive.rs`, `rmasscan/crates/rmasscan-core/src/checksum.rs`,
  `rmasscan/crates/rmasscan-engine/src/engine.rs`
- Test: `#[cfg(test)]` в `packet.rs`, `probe.rs`, `receive.rs`, `engine.rs`

**Interfaces:**
- Produces:
  - `DEFAULT_ICMP_PING_TEMPLATE` (90 байт: 14B Ethernet + 20B IPv4 `ip_len = 76`, `proto = 1`, `ttl = 255` + 8B ICMP
    `08 00` + 48B паттерн `0x08..=0x37`, `templ-pkt.c:105–136`) и метод `TemplateSet::build_icmp_echo(...)`
    (`templ-pkt.c:1065–1080`).
  - `icmp_echo_cookie = syn_cookie_ipv4(ip_them, Templ_ICMP_echo (196608), ip_me, 0, entropy) as u32` (`port_me = 0`,
    `main.c:997–1025`).

- [ ] **Шаг 1 — красный тест:**
  - `icmp_echo_frame_and_cookie_match_c`: зафиксированный 90-байтовый кадр ICMP Echo (включая `ip_id`, `ip_len = 0x004c`,
    валидную IP-чексумму, `[id|seq]`, валидную ICMP-чексумму over 56B, байты `0x08..=0x37`);
  - `icmp_echo_cookie_uses_zero_source_port` (Review Focus 5): при заданном `--source-port 41000` в `icmp_id|icmp_seq`
    подставляется cookie именно с `port_me = 0`, и `receive` принимает синтетический ответ `type 0, code 0` с тем же
    `[id|seq]`, выдавая `Reply { ip_proto: 1, remote_port: 0, status: Open, tcp_flags: 0, ttl }`, а ответ с неверным
    cookie отбрасывается.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core icmp_echo` — падает.
- [ ] **Шаг 3 — реализация:** реализовать ICMP Echo шаблон в `packet.rs`, ветку `TEMPL_ICMP_ECHO` в `probe.rs` и разбор
  ICMP Echo Reply в `receive.rs` + `engine.rs` (`~/masscan/src/templ-pkt.c:105–136, 1065–1080`, `proto-icmp.c:200–226`,
  `main.c:997–1025`).
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-engine` — зелёный.
- [ ] **Шаг 5 — коммит:** `packet.rs`, `probe.rs`, `receive.rs`, `checksum.rs`, `engine.rs`.

### Задача 4: шаблон UDP, 28 AGPL-пейлоадов, `--pcap-payloads`/`--nmap-payloads`, RX и ICMP `3/3`

**Files:**
- Create: `rmasscan/crates/rmasscan-core/src/payloads.rs`
- Modify: `rmasscan/crates/rmasscan-core/src/{lib,packet,probe,receive,checksum}.rs`,
  `rmasscan/crates/rmasscan-engine/src/engine.rs`, `rmasscan/crates/rmasscan-cli/src/args.rs`
- Test: `#[cfg(test)]` в `payloads.rs`, `probe.rs`, `receive.rs`, `engine.rs`

**Interfaces:**
- Produces:
  - `PayloadTable` в `payloads.rs`: 28 встроенных записей из `~/masscan/src/templ-payloads.c:66–472` +
    `set_cookie`-мутаторы для `53/111/137/2049` (DNS/ONCRPC/NBNS/NFS), `161` (SNMP), `5683` (CoAP), `11211` (Memcached),
    `500` (ISAKMP) и no-op `123` (NTP); плюс парсеры `PayloadTable::load_nmap_payloads(&str)` и
    `PayloadTable::load_pcap_payloads(&[u8])` (`templ-nmap-payloads.c:1–305`).
  - Построение UDP-кадра с чексуммой RFC 768 (`0x0000` → `0xFFFF`, `templ-pkt.c:278–303, 1023–1047`) и обработка в
    `receive.rs`:
    1. прямой UDP-ответ на `(ip_me, port_me)` (при активном скане UDP и прохождении `port_me` в диапазоне источника);
    2. ICMP Type 3 Code 3 (Port Unreachable) с разбором вложенного IPv4 + 8 байт L4 `(ip_me, port_me, ip_them, inner_proto,
       inner_port)` и проверкой cookie для TCP (`6`), UDP (`17`) или SCTP (`132`) (`proto-icmp.c:94–199`).
  - Расширение ключа `DedupCache` в `rmasscan-engine/src/engine.rs` на `ip_proto: u8` и `status`.

- [ ] **Шаг 1 — красный тест:**
  - `builtin_28_udp_payloads_match_c_bytes_and_cookies`: проверка всех 28 портов и точных байтов (включая подстановку
    `seqno` в DNS port 53 `txid`, SNMP `161`, ISAKMP `500`, CoAP `5683`, Memcached `11211`);
  - `udp_unknown_port_sends_empty_payload` (Review Focus 2): порт `59999` → 42-байтовый кадр (`ip_len = 28`, `udp_len = 8`,
    валидная UDP-чексумма RFC 768);
  - `nmap_and_pcap_payload_parsers_override_table`: разбор мини-фикстуры в синтаксисе `udp 53 "..."` и мини-`.pcap`
    заменяет пейлоад порта;
  - `icmp_port_unreachable_marks_closed_across_protocols` и `dedup_cache_separates_protocols` (Review Focus 2):
    ICMP `3/3` с вложенным UDP-зондом даёт `Reply { ip_proto: 17, status: Closed, reason: 0 }`; в `DedupCache` запись
    `(ip, 80, proto=6)` не подавляет `(ip, 80, proto=17)`.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core builtin_28_udp_payloads` — падает.
- [ ] **Шаг 3 — реализация:** перенести таблицу и `set_cookie` из `~/masscan/src/templ-payloads.c:66–472`, парсеры
  `templ-nmap-payloads.c:1–305`, UDP builder в `packet.rs`/`probe.rs` и приёмники UDP + ICMP `3/3` в `receive.rs`/`engine.rs`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-engine -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `payloads.rs`, `lib.rs`, `packet.rs`, `probe.rs`, `receive.rs`, `checksum.rs`, `engine.rs`, `args.rs`.

### Задача 5: шаблон SCTP INIT (`S:`), Castagnoli CRC-32C и приём `INIT-ACK` / `ABORT`

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/checksum.rs`, `rmasscan/crates/rmasscan-core/src/packet.rs`,
  `rmasscan/crates/rmasscan-core/src/probe.rs`, `rmasscan/crates/rmasscan-core/src/receive.rs`
- Test: `#[cfg(test)]` в `checksum.rs`, `packet.rs`, `receive.rs`

**Interfaces:**
- Produces:
  - `checksum::sctp_crc32c(bytes: &[u8]) -> u32` (табличный или побитовый Castagnoli CRC-32C с полиномом `0x1EDC6F41`,
    zeroed bytes `[8..12]`, LE output `to_le_bytes()`, `proto-sctp.c:9–131`).
  - 66-байтовый `DEFAULT_SCTP_INIT_TEMPLATE` (`templ-pkt.c:76–102`) + разбор ответов `proto = 132` (`proto-sctp.c:137–189`):
    `vtag == syn_cookie_ipv4(ip_them, Templ_SCTP + port, ip_me, port_me, entropy) as u32`, чанк `2` → `Open`, чанк `6` →
    `Closed` (`reason = 0`, `ip_proto = 132`).

- [ ] **Шаг 1 — красный тест:**
  - `sctp_crc32c_matches_c_selftest` (Review Focus 5): перенос тестового вектора `sctp_selftest` из
    `~/masscan/src/proto-sctp.c:195–208`, проверка точных 66 байт SCTP INIT (порт `2905`, `vtag = 0`, `initiate_tag =
    seqno`, `a_rwnd = 0x00008000`, `outbound = 10`, `inbound = 2048`, `initial_tsn = 0x461adf3d`, LE CRC-32C в `[42..46]`);
  - `sctp_rx_classifies_init_ack_and_abort`: пакеты с `vtag == cookie` и чанками `2` (`Open`) и `6` (`Closed`)
    принимаются, пакет с неверным `vtag` отбрасывается.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-core sctp_crc32c` — падает.
- [ ] **Шаг 3 — реализация:** реализовать `sctp_crc32c`, шаблон и TX/RX SCTP по `~/masscan/src/proto-sctp.c:9–208` и
  `templ-pkt.c:76–102, 1048–1064`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-engine` — зелёный.
- [ ] **Шаг 5 — коммит:** `checksum.rs`, `packet.rs`, `probe.rs`, `receive.rs`.

### Задача 6: ARP-скан локального сегмента (`--arp` / `--arpscan`)

**Files:**
- Modify: `rmasscan/crates/rmasscan-core/src/packet.rs`, `rmasscan/crates/rmasscan-core/src/probe.rs`,
  `rmasscan/crates/rmasscan-core/src/receive.rs`, `rmasscan/crates/rmasscan-cli/src/live.rs`,
  `rmasscan/crates/rmasscan-cli/src/args.rs`
- Test: `#[cfg(test)]` в `packet.rs`, `receive.rs`, `rmasscan/crates/rmasscan-cli/tests/live_fake.rs`

**Interfaces:**
- Produces:
  - 42-байтовый ARP-кадр `templ-pkt.c:162–176, 914–928`: `dst = ff:ff:ff:ff:ff:ff`, `ethertype = 0x0806`, `htype = 1`,
    `ptype = 0x0800`, `hlen = 6`, `plen = 4`, `op = 1`, `sha = source_mac`, `spa = ip_me`, `tha = 0`, `tpa = ip_them`.
  - В `live.rs`: при единственном типе `TEMPL_ARP` (флаг `--arp`) резолвер ARP шлюза перед сканом не запускается
    (`next_hop_mac = [0xFF; 6]`, `main-initadapter.c:170–189`); приём (`proto-arp.c:14–41`) принимает `op == 2`,
    `tpa ∈ source_ipv4_range`, `spa ∈ targets.ipv4`, выдавая `Reply { remote_ip: spa, remote_port: 0, ip_proto: 0,
    status: PortStatus::Arp, tcp_flags: 0, ttl: 0, mac: Some(sha) }`.

- [ ] **Шаг 1 — красный тест:**
  - `arp_probe_frame_matches_c_42_bytes`: проверка всех 42 байт широковещательного ARP who-has;
  - `arp_scan_skips_gateway_arp_and_rejects_port_mix` (Review Focus 3):
    1. `--arp -p80` падает до открытия адаптера с `FAIL: cannot arpscan and portscan at the same time`;
    2. на `FakeAdapter` с `--arp` шлюз не резолвится (в TX сразу 42B who-has на целевые IP), в ответный поток подаётся
       ARP Reply от `198.18.0.2` (`02:aa:bb:cc:dd:ee`) → `Discovered up port 0/arp on 198.18.0.2 (02:aa:bb:cc:dd:ee)`,
       а без ответов скан чисто завершается с кодом `0` и пустым файлом вывода.
- [ ] **Шаг 2 — запуск (FAIL):** `cargo test --locked -p rmasscan-cli --test live_fake arp_scan` — падает.
- [ ] **Шаг 3 — реализация:** `packet.rs`, `probe.rs`, `receive.rs`, `live.rs`, `args.rs` по `~/masscan/src/templ-pkt.c:162–176,
  914–928`, `main-initadapter.c:170–189`, `main.c:1224–1229`, `proto-arp.c:14–41`.
- [ ] **Шаг 4 — запуск (PASS):** `cargo test --locked -p rmasscan-core -p rmasscan-cli` — зелёный.
- [ ] **Шаг 5 — коммит:** `packet.rs`, `probe.rs`, `receive.rs`, `live.rs`, `args.rs`, `live_fake.rs`.

### Задача 7: golden `--readscan`, живая приёмка (`--suite protocols`) и документация

**Files:**
- Modify: `rmasscan/crates/rmasscan-cli/examples/format_inputs.rs`, `rmasscan/scripts/build-format-goldens.sh`,
  `rmasscan/crates/rmasscan-cli/tests/formats_golden.rs`, `rmasscan/tests/golden/formats/`,
  `rmasscan/crates/rmasscan-lab/src/{lib,main}.rs`, `rmasscan/scripts/wire-lab.sh`,
  `rmasscan/README.md`, `docs/experiments/2026-10-24-rmasscan-readiness.md`,
  `docs/superpowers/specs/2026-10-23-masscan-rust-port-design.md`
- Create: `rmasscan/crates/rmasscan-lab/src/{protocols_suite,protocols_verify}.rs`,
  `docs/experiments/2026-11-08-rmasscan-protocols-ipv4-acceptance.md`

**Interfaces:**
- Produces: расширение `tests/golden/formats/` входом `protocols.scan` (UDP/SCTP/ICMP, пропущенным через C-оракул
  `8e6b3b0 --readscan` в изолированном `unshare -n`), плюс подкоманды `rmasscan-lab protocols-suite linux ...` и
  `protocols-verify --dir DIR`.

- [ ] **Шаг 1 — golden через `--readscan`:** добавить `protocols.scan` в `format_inputs.rs`, снять эталоны через
  `build-format-goldens.sh` на minipc с оракулом `8e6b3b0` (без правки старых 74 эталонов), убедиться что
  `cargo test --locked -p rmasscan-cli --test formats_golden` проходит.
- [ ] **Шаг 2 — лаборатория и живое окно:** реализовать `protocols_suite.rs` / `protocols_verify.rs` (кейсы: `p01_ping`,
  `p02_udp_payloads_and_closed`, `p03_sctp_init_ack_abort`, `p04_arp_scan`, `p05_mixed_protos`), прогнать на запечатанном
  стенде Linux netns (`198.18.0.0/24`) плюс регрессию `autodetect`/`output`/`scan-control`, и `windows-suite --plan
  autodetect` на Windows VM + `cargo xtask test` в `studio/`; выполнить privacy-grep.
- [ ] **Шаг 3 — документация и проверка CI:** обновить `rmasscan/README.md` («Отличия от masscan» по Р1–Р5), записать
  `docs/experiments/2026-11-08-rmasscan-protocols-ipv4-acceptance.md` и строку в `readiness.md`; прогнать
  `cargo test --locked --workspace`, `cargo clippy --locked --workspace --all-targets -- -D warnings`, `cargo fmt --check`,
  дождаться зелёного GitHub CI на точном HEAD.

---

## Самопроверка

1. На каждый Р-номер есть задача: Р1 → Задача 1; Р2 → Задача 1; Р3 → Задача 4; Р4 → Задачи 3, 4, 5, 6; Р5 → Задача 2;
   §6.1/§6.2/§8 → Задача 7.
2. Каждый шаг даёт одну проверяемую вещь и точную команду `cargo test`.
3. Типы (`Proto`, `Record`, `Reply`, `PayloadTable`) согласованы, контракт `Studio` (`AdapterBinding`, `ReadyPlan::new`)
   не нарушен.
4. Все 5 пунктов Review Focus покрыты явными тестами в задачах 1–7.
5. План соразмерен задаче и не содержит NPSL-активов или внешних зависимостей.
